use std::net::{Ipv4Addr, Ipv6Addr};

use proptest::prelude::*;
use todoke_proto::discovery::{DiscoveryMode, Epoch};

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const LABEL: &str = "0ab10000000000ff";
const PORT: u16 = 47_000;

fn record() -> Result<DiscoveryRecord, Box<dyn std::error::Error>> {
    Ok(DiscoveryRecord::new(
        DiscoveryMode::Paired,
        Epoch::new(1_955_555)?,
        [0x3a, 0xbe, 0x80, 0x6d, 0x9b, 0x82, 0x1c, 0xfc],
    )?)
}

fn fullname(label: &str) -> String {
    format!("{label}.{MDNS_SERVICE}")
}

fn lan() -> Vec<(IpAddr, u32)> {
    vec![(IpAddr::from(Ipv4Addr::new(192, 168, 1, 20)), 3)]
}

fn check(
    name: &str,
    port: u16,
    addresses: Vec<(IpAddr, u32)>,
    txt: &[(&str, Option<&[u8]>)],
) -> Result<Sighting, Dropped> {
    Sighting::check(name, port, addresses, txt.iter().copied(), LanPolicy::new())
}

#[test]
fn a_well_formed_instance_is_kept() -> TestResult {
    let value = record()?.txt_value();
    let sighting = check(
        &fullname(LABEL),
        PORT,
        lan(),
        &[("v1", Some(value.as_bytes()))],
    )?;
    assert_eq!(sighting.label().as_str(), LABEL);
    assert_eq!(sighting.record(), &record()?);
    assert_eq!(
        sighting.addresses(),
        &[SocketAddr::from(([192, 168, 1, 20], PORT))]
    );
    Ok(())
}

/// Hostile and malformed answers: each is dropped for its own reason.
#[test]
fn malformed_instances_are_dropped() -> TestResult {
    let value = record()?.txt_value();
    let good: &[(&str, Option<&[u8]>)] = &[("v1", Some(value.as_bytes()))];
    // Names: another service, a device name, uppercase, extra labels.
    for name in [
        format!("{LABEL}._http._tcp.local."),
        fullname("Radus-MacBook-Pro"),
        fullname("0AB10000000000FF"),
        fullname("0ab10000000000f"),
        fullname("0000000000000000"),
        format!("x.{LABEL}.{MDNS_SERVICE}"),
        format!("{LABEL}{MDNS_SERVICE}"),
        String::new(),
        "é".repeat(20),
    ] {
        assert_eq!(
            check(&name, PORT, lan(), good).err(),
            Some(Dropped::Name),
            "{name}"
        );
    }
    // TXT: missing, extra strings, other keys, no value, wrong length,
    // uppercase hex, a bad record.
    let upper = value.to_uppercase();
    let mut bad_version = value.clone();
    bad_version.replace_range(..2, "02");
    let short = &value[..36];
    for txt in [
        &[][..],
        &[("v1", Some(value.as_bytes())), ("name", Some(&b"bob"[..]))][..],
        &[("name", Some(&b"bob"[..])), ("v1", Some(value.as_bytes()))][..],
        &[("V1", Some(value.as_bytes()))][..],
        &[("v2", Some(value.as_bytes()))][..],
        &[("v1", None)][..],
        &[("v1", Some(short.as_bytes()))][..],
        &[("v1", Some(upper.as_bytes()))][..],
        &[("v1", Some(bad_version.as_bytes()))][..],
    ] {
        assert_eq!(
            check(&fullname(LABEL), PORT, lan(), txt).err(),
            Some(Dropped::Txt),
            "{txt:?}"
        );
    }
    assert_eq!(
        check(&fullname(LABEL), 0, lan(), good).err(),
        Some(Dropped::Port)
    );
    Ok(())
}

/// Addresses outside the LAN policy are dropped one by one; an instance
/// with none left is dropped.
#[test]
fn only_allowed_addresses_are_kept() -> TestResult {
    let value = record()?.txt_value();
    let good: &[(&str, Option<&[u8]>)] = &[("v1", Some(value.as_bytes()))];
    let hostile = vec![
        (IpAddr::from(Ipv4Addr::new(8, 8, 8, 8)), 1),
        (IpAddr::from(Ipv4Addr::LOCALHOST), 1),
        (IpAddr::from(Ipv4Addr::new(169, 254, 169, 254)), 1),
        (IpAddr::from(Ipv4Addr::new(224, 0, 0, 251)), 1),
        (IpAddr::from(Ipv6Addr::LOCALHOST), 1),
        ("2001:4860::1".parse::<IpAddr>()?, 1),
    ];
    assert_eq!(
        check(&fullname(LABEL), PORT, hostile.clone(), good).err(),
        Some(Dropped::NoAddress)
    );
    // A privileged port makes every address unusable.
    assert_eq!(
        check(&fullname(LABEL), 80, lan(), good).err(),
        Some(Dropped::NoAddress)
    );
    let mut mixed = hostile;
    mixed.push((IpAddr::from(Ipv4Addr::new(10, 0, 0, 9)), 2));
    mixed.push(("fe80::1".parse::<IpAddr>()?, 7));
    mixed.push(("fd00::5".parse::<IpAddr>()?, 7));
    let sighting = check(&fullname(LABEL), PORT, mixed, good)?;
    let kept = sighting.addresses();
    assert_eq!(kept.len(), 3);
    assert!(kept.contains(&SocketAddr::from(([10, 0, 0, 9], PORT))));
    // Link-local IPv6 gets the receiving interface's scope; others none.
    assert!(kept.contains(&SocketAddr::V6(SocketAddrV6::new(
        "fe80::1".parse()?,
        PORT,
        0,
        7
    ))));
    assert!(kept.contains(&SocketAddr::V6(SocketAddrV6::new(
        "fd00::5".parse()?,
        PORT,
        0,
        0
    ))));
    // A link-local address seen without an interface is unusable.
    assert_eq!(
        check(
            &fullname(LABEL),
            PORT,
            vec![("fe80::1".parse::<IpAddr>()?, 0)],
            good
        )
        .err(),
        Some(Dropped::NoAddress)
    );
    Ok(())
}

#[test]
fn addresses_are_bounded_deduplicated_and_ordered() -> TestResult {
    let value = record()?.txt_value();
    let good: &[(&str, Option<&[u8]>)] = &[("v1", Some(value.as_bytes()))];
    let many: Vec<(IpAddr, u32)> = (1..=40)
        .rev()
        .flat_map(|n| {
            let ip = IpAddr::from(Ipv4Addr::new(192, 168, 1, n));
            [(ip, 1), (ip, 1)]
        })
        .collect();
    let sighting = check(&fullname(LABEL), PORT, many, good)?;
    assert_eq!(sighting.addresses().len(), MAX_ADDRESSES);
    let mut sorted = sighting.addresses().to_vec();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted, sighting.addresses());
    // The lowest four of all forty, not the first four listed.
    assert_eq!(
        sighting.addresses().first(),
        Some(&SocketAddr::from(([192, 168, 1, 1], PORT)))
    );
    Ok(())
}

/// R1: the order of the answer's addresses does not decide which are kept;
/// private IPv4 comes before unique-local and link-local IPv6.
#[test]
fn addresses_are_chosen_by_kind_not_by_answer_order() -> TestResult {
    let value = record()?.txt_value();
    let good: &[(&str, Option<&[u8]>)] = &[("v1", Some(value.as_bytes()))];
    let mut addresses: Vec<(IpAddr, u32)> = (1..=4)
        .map(|n| (IpAddr::from(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, n)), 3))
        .collect();
    addresses.push((IpAddr::from(Ipv4Addr::new(10, 1, 2, 3)), 1));
    addresses.push(("fd00::7".parse::<IpAddr>()?, 1));
    let forwards = check(&fullname(LABEL), PORT, addresses.clone(), good)?;
    addresses.reverse();
    let backwards = check(&fullname(LABEL), PORT, addresses, good)?;
    assert_eq!(forwards.addresses(), backwards.addresses());
    assert_eq!(
        forwards.addresses().first(),
        Some(&SocketAddr::from(([10, 1, 2, 3], PORT)))
    );
    assert_eq!(
        forwards.addresses().get(1),
        Some(&SocketAddr::V6(SocketAddrV6::new(
            "fd00::7".parse()?,
            PORT,
            0,
            0
        )))
    );
    Ok(())
}

#[test]
fn debug_output_hides_addresses_and_tokens() -> TestResult {
    let value = record()?.txt_value();
    let sighting = check(
        &fullname(LABEL),
        PORT,
        lan(),
        &[("v1", Some(value.as_bytes()))],
    )?;
    let shown = format!("{sighting:?}");
    assert!(!shown.contains("192.168"), "{shown}");
    assert!(!shown.contains("3abe806d"), "{shown}");
    assert!(!shown.contains(LABEL), "{shown}");
    Ok(())
}

proptest! {
    /// Arbitrary answers never panic, and a kept sighting always has the
    /// exact §9 shape.
    #[test]
    fn arbitrary_answers_are_kept_only_in_shape(
        name in "\\PC{0,64}",
        port in any::<u16>(),
        key in "\\PC{0,4}",
        value in proptest::option::of(proptest::collection::vec(any::<u8>(), 0..48)),
        extra in any::<bool>(),
        octets in proptest::collection::vec((any::<[u8; 4]>(), any::<u32>()), 0..6),
    ) {
        let addresses: Vec<(IpAddr, u32)> = octets
            .iter()
            .map(|(ip, scope)| (IpAddr::from(*ip), *scope))
            .collect();
        let mut txt: Vec<(&str, Option<&[u8]>)> = vec![(key.as_str(), value.as_deref())];
        if extra {
            txt.push(("v1", value.as_deref()));
        }
        if let Ok(sighting) = Sighting::check(&name, port, addresses, txt, LanPolicy::new()) {
            prop_assert_eq!(fullname(sighting.label().as_str()), name);
            prop_assert!(!extra);
            prop_assert_eq!(key.as_str(), "v1");
            prop_assert!(!sighting.addresses().is_empty());
            prop_assert!(sighting.addresses().len() <= MAX_ADDRESSES);
            for address in sighting.addresses() {
                prop_assert!(LanPolicy::new().check_peer(*address).is_ok());
            }
        }
    }
}
