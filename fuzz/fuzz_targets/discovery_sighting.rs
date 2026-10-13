//! The mDNS sighting check on arbitrary answers: instance name, port,
//! addresses with interface indices, and TXT strings, all fuzzer-chosen. A
//! kept sighting has exactly the §9 shape and only policy-approved
//! addresses.
#![no_main]

use std::net::IpAddr;

use libfuzzer_sys::fuzz_target;
use todoke_discovery::Sighting;
use todoke_discovery::sighting::MAX_ADDRESSES;
use todoke_proto::discovery::MDNS_SERVICE;
use todoke_transport::LanPolicy;

/// Splits off a length-prefixed field.
fn field<'a>(data: &mut &'a [u8]) -> &'a [u8] {
    let Some((&len, rest)) = data.split_first() else {
        return &[];
    };
    let len = usize::from(len).min(rest.len());
    let (field, rest) = rest.split_at(len);
    *data = rest;
    field
}

fuzz_target!(|data: &[u8]| {
    let mut data = data;
    let name = String::from_utf8_lossy(field(&mut data)).into_owned();
    let port = u16::from_be_bytes(
        field(&mut data)
            .get(..2)
            .and_then(|b| b.try_into().ok())
            .unwrap_or([0, 0]),
    );
    let mut addresses = Vec::new();
    for chunk in field(&mut data).chunks(21) {
        let scope = chunk.first().copied().map_or(0, u32::from);
        let ip = match chunk.get(1..) {
            Some(bytes) if bytes.len() >= 16 => {
                let octets: [u8; 16] = bytes[..16].try_into().unwrap_or([0; 16]);
                IpAddr::from(octets)
            }
            Some(bytes) if bytes.len() >= 4 => {
                let octets: [u8; 4] = bytes[..4].try_into().unwrap_or([0; 4]);
                IpAddr::from(octets)
            }
            _ => continue,
        };
        addresses.push((ip, scope));
    }
    let mut strings = Vec::new();
    while !data.is_empty() && strings.len() < 4 {
        let key = String::from_utf8_lossy(field(&mut data)).into_owned();
        let value = field(&mut data).to_vec();
        strings.push((key, value));
    }
    let txt = strings.iter().map(|(key, value)| {
        (
            key.as_str(),
            (!value.is_empty()).then_some(value.as_slice()),
        )
    });
    for policy in [LanPolicy::new(), LanPolicy::new().with_loopback()] {
        if let Ok(sighting) = Sighting::check(&name, port, addresses.clone(), txt.clone(), policy) {
            assert_eq!(
                format!("{}.{MDNS_SERVICE}", sighting.label().as_str()),
                name
            );
            assert_eq!(strings.len(), 1);
            assert!(!sighting.addresses().is_empty());
            assert!(sighting.addresses().len() <= MAX_ADDRESSES);
            for address in sighting.addresses() {
                assert!(policy.check_peer(*address).is_ok());
            }
        }
    }
});
