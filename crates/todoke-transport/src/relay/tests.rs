use super::*;

fn endpoint(name: &str) -> RelayEndpoint {
    RelayEndpoint {
        name: name.into(),
        address: "relay.example:4433".into(),
        server_name: "relay.example".into(),
        pin: None,
    }
}

fn token(byte: u8) -> RendezvousToken {
    RendezvousToken::new([byte; 32]).unwrap_or_else(|_| unreachable!())
}

#[test]
fn pins_parse_only_in_their_exact_form() {
    let hex = "ab".repeat(32);
    assert_eq!(parse_pin(&format!("spki-sha256:{hex}")), Some([0xab; 32]));
    assert_eq!(
        parse_pin(&format!("spki-sha256:{}", "AB".repeat(32))),
        Some([0xab; 32])
    );
    for bad in [
        hex.clone(),
        format!("sha256:{hex}"),
        format!("spki-sha256:{}", &hex[..62]),
        format!("spki-sha256:{hex}00"),
        format!("spki-sha256:{}zz", &hex[..62]),
        format!("spki-sha256: {}", &hex[..63]),
    ] {
        assert_eq!(parse_pin(&bad), None, "{bad}");
    }
}

/// Both peers pick the same relay for a token; tokens spread over the
/// list; a relay leaving the list moves only its own tokens.
#[test]
fn rendezvous_hashing_is_stable_and_spreads() {
    let list = [endpoint("a"), endpoint("b"), endpoint("c")];
    assert_eq!(choose(&[], &token(1)), None);
    let mut used = std::collections::BTreeSet::new();
    for byte in 1..=60 {
        let chosen = choose(&list, &token(byte)).map(|relay| relay.name.clone());
        assert_eq!(
            chosen,
            choose(&list, &token(byte)).map(|relay| relay.name.clone())
        );
        let without_b: Vec<RelayEndpoint> = list
            .iter()
            .filter(|relay| relay.name != "b")
            .cloned()
            .collect();
        if chosen.as_deref() != Some("b") {
            assert_eq!(
                choose(&without_b, &token(byte)).map(|relay| relay.name.clone()),
                chosen
            );
        }
        used.extend(chosen);
    }
    assert_eq!(used.len(), 3);
}

#[test]
fn relay_endpoints_hide_where_they_are() {
    let mut relay = endpoint("home");
    relay.pin = Some([1; 32]);
    let shown = format!("{relay:?}");
    assert!(!shown.contains("relay.example"), "{shown}");
    assert!(shown.contains("pinned: true"), "{shown}");
}
