use std::net::{SocketAddr, SocketAddrV6};

use proptest::prelude::*;

use super::*;

fn v4(text: &str, port: u16) -> Result<SocketAddr, std::net::AddrParseError> {
    Ok(SocketAddr::from((text.parse::<Ipv4Addr>()?, port)))
}

fn v6(text: &str, port: u16, scope: u32) -> Result<SocketAddr, std::net::AddrParseError> {
    Ok(SocketAddr::V6(SocketAddrV6::new(
        text.parse()?,
        port,
        0,
        scope,
    )))
}

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn private_and_link_local_peers_are_allowed() -> TestResult {
    let policy = LanPolicy::new();
    for address in [
        v4("10.0.0.7", 45_000)?,
        v4("172.16.4.2", 45_000)?,
        v4("172.31.255.254", 1024)?,
        v4("192.168.1.20", 65_535)?,
        v4("169.254.10.3", 45_000)?,
        v6("fd12:3456:789a::1", 45_000, 0)?,
        v6("fe80::1", 45_000, 3)?,
        v6("::ffff:192.168.1.20", 45_000, 0)?,
    ] {
        assert_eq!(policy.check_peer(address), Ok(()), "{address}");
    }
    Ok(())
}

/// The addresses a hostile mDNS record could point at instead of a peer.
#[test]
fn everything_else_is_refused() -> TestResult {
    let policy = LanPolicy::new();
    for address in [
        // The internet.
        v4("8.8.8.8", 45_000)?,
        v4("172.32.0.1", 45_000)?,
        v4("100.64.0.1", 45_000)?,
        v6("2001:4860:4860::8888", 45_000, 0)?,
        v6("::ffff:8.8.8.8", 45_000, 0)?,
        // This machine.
        v4("127.0.0.1", 45_000)?,
        v4("127.8.9.10", 45_000)?,
        v6("::1", 45_000, 0)?,
        v6("::ffff:127.0.0.1", 45_000, 0)?,
        // Nothing, everyone, or a group.
        v4("0.0.0.0", 45_000)?,
        v6("::", 45_000, 0)?,
        v4("255.255.255.255", 45_000)?,
        v4("224.0.0.251", 5353)?,
        v4("239.255.255.250", 45_000)?,
        v6("ff02::fb", 45_000, 1)?,
        // Cloud metadata services.
        v4("169.254.169.254", 45_000)?,
        v4("169.254.169.123", 45_000)?,
        v6("fd00:ec2::254", 45_000, 0)?,
        // Directed broadcast and network addresses.
        v4("192.168.1.255", 45_000)?,
        v4("10.0.0.255", 45_000)?,
        v4("169.254.255.255", 45_000)?,
        v4("192.168.1.0", 45_000)?,
        // Reserved and documentation ranges.
        v4("240.0.0.1", 45_000)?,
        v4("192.0.2.1", 45_000)?,
        v6("2001:db8::1", 45_000, 0)?,
    ] {
        assert_eq!(
            policy.check_peer(address),
            Err(Refusal::NotLocal),
            "{address}"
        );
    }
    Ok(())
}

#[test]
fn privileged_ports_and_unscoped_link_local_addresses_are_refused() -> TestResult {
    let policy = LanPolicy::new();
    for port in [0, 22, 80, 443, 1023] {
        assert_eq!(
            policy.check_peer(v4("192.168.1.1", port)?),
            Err(Refusal::PrivilegedPort)
        );
    }
    assert_eq!(
        policy.check_peer(v6("fe80::1", 45_000, 0)?),
        Err(Refusal::NoScope)
    );
    // An accepted connection's source port is the peer system's choice.
    assert_eq!(policy.check_source(v4("192.168.1.1", 80)?), Ok(()));
    assert_eq!(
        policy.check_source(v4("8.8.8.8", 45_000)?),
        Err(Refusal::NotLocal)
    );
    Ok(())
}

#[test]
fn loopback_needs_an_explicit_policy() -> TestResult {
    let policy = LanPolicy::new().with_loopback();
    assert_eq!(policy.check_peer(v4("127.0.0.1", 45_000)?), Ok(()));
    assert_eq!(policy.check_peer(v6("::1", 45_000, 0)?), Ok(()));
    assert_eq!(
        policy.check_peer(v4("127.0.0.1", 80)?),
        Err(Refusal::PrivilegedPort)
    );
    assert_eq!(
        policy.check_peer(v4("8.8.8.8", 45_000)?),
        Err(Refusal::NotLocal)
    );
    assert_ne!(LanPolicy::default(), policy);
    Ok(())
}

#[test]
fn local_network_interfaces_are_recognised() -> TestResult {
    assert!(is_local_network("192.168.1.2".parse()?));
    assert!(is_local_network("fe80::1".parse()?));
    assert!(!is_local_network("127.0.0.1".parse()?));
    assert!(!is_local_network("2001:4860::1".parse()?));
    Ok(())
}

proptest! {
    /// An allowed IPv4 peer is private or link-local, not loopback, on an
    /// unprivileged port; whatever the policy allows as a peer, it also
    /// allows as a source.
    #[test]
    fn allowed_v4_peers_are_local(octets in any::<[u8; 4]>(), port in any::<u16>()) {
        let ip = Ipv4Addr::from(octets);
        let address = SocketAddr::from((ip, port));
        if LanPolicy::new().check_peer(address).is_ok() {
            prop_assert!(ip.is_private() || ip.is_link_local());
            prop_assert!(!ip.is_loopback());
            prop_assert!(octets[3] != 255 && octets[3] != 0);
            prop_assert!(port >= MIN_PEER_PORT);
            prop_assert_eq!(LanPolicy::new().check_source(address), Ok(()));
        }
    }

    #[test]
    fn allowed_v6_peers_are_local(segments in any::<[u16; 8]>(), port in any::<u16>(), scope in any::<u32>()) {
        let ip = Ipv6Addr::from(segments);
        let address = SocketAddr::V6(SocketAddrV6::new(ip, port, 0, scope));
        if LanPolicy::new().check_peer(address).is_ok() {
            let mapped_private = ip
                .to_ipv4_mapped()
                .is_some_and(|v4| v4.is_private() || v4.is_link_local());
            prop_assert!(
                mapped_private
                    || ip.is_unique_local()
                    || (ip.is_unicast_link_local() && scope != 0)
            );
            prop_assert!(port >= MIN_PEER_PORT);
        }
    }
}
