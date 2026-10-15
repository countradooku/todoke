use zeroize::Zeroizing;

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const ID: [u8; OFFER_ID_LEN] = [7; OFFER_ID_LEN];

fn hotspot() -> Result<LinkOffer, DecodeError> {
    LinkOffer::new(
        ID,
        LinkKind::Hotspot,
        LinkSecurity::Wpa3,
        60,
        47_000,
        b"todoke-1a2b".to_vec(),
        Zeroizing::new(vec![b'A'; 63]),
    )
}

fn aware() -> Result<LinkOffer, DecodeError> {
    LinkOffer::new(
        ID,
        LinkKind::WifiAware,
        LinkSecurity::AwareSk256,
        120,
        1024,
        Vec::new(),
        Zeroizing::new(vec![0x5a; PMK_LEN]),
    )
}

/// The exact §10.2 layout: offer ID, kind, security, expiry, port (big
/// endian), SSID with its length, secret with its length.
#[test]
fn an_offer_has_the_exact_layout() -> TestResult {
    let offer = hotspot()?;
    let body = offer.encode();
    assert_eq!(body.len(), 23 + 11 + 63);
    assert_eq!(&body[..16], &ID);
    assert_eq!(&body[16..22], &[3, 1, 60, 0xb7, 0x98, 11]);
    assert_eq!(&body[22..33], b"todoke-1a2b");
    assert_eq!(body[33], 63);
    assert_eq!(LinkOffer::decode(&body)?, offer);
    let aware = aware()?;
    let body = aware.encode();
    assert_eq!(body.len(), 23 + 32);
    assert_eq!(&body[16..23], &[1, 4, 120, 0x04, 0x00, 0, 32]);
    assert_eq!(LinkOffer::decode(&body)?, aware);
    // The longest offer: a 32-byte SSID and a 63-byte passphrase.
    let longest = LinkOffer::new(
        ID,
        LinkKind::WifiDirect,
        LinkSecurity::Wpa2,
        10,
        u16::MAX,
        vec![b'D'; 32],
        Zeroizing::new(vec![b'~'; 63]),
    )?;
    assert_eq!(longest.encode().len(), 118);
    Ok(())
}

/// Every malformed offer is refused before it is used.
#[test]
fn malformed_offers_are_refused() -> TestResult {
    let good = hotspot()?.encode();
    let with = |at: usize, value: u8| {
        let mut body = good.to_vec();
        body[at] = value;
        LinkOffer::decode(&body)
    };
    assert_eq!(LinkOffer::decode(&[]), Err(DecodeError::Length));
    assert_eq!(LinkOffer::decode(&good[..22]), Err(DecodeError::Length));
    assert_eq!(
        LinkOffer::decode(&good[..good.len() - 1]),
        Err(DecodeError::Length)
    );
    assert_eq!(
        LinkOffer::decode(&[&good[..], &[0]].concat()),
        Err(DecodeError::Length)
    );
    // Kind and security.
    assert_eq!(with(16, 0), Err(DecodeError::UnknownEnum));
    assert_eq!(with(16, 4), Err(DecodeError::UnknownEnum));
    assert_eq!(with(17, 0), Err(DecodeError::UnknownEnum));
    assert_eq!(with(17, 6), Err(DecodeError::UnknownEnum));
    // Aware security on a hotspot.
    assert_eq!(with(17, 4), Err(DecodeError::UnknownEnum));
    // Expiry and port.
    assert_eq!(with(18, 9), Err(DecodeError::Range));
    assert_eq!(with(18, 121), Err(DecodeError::Range));
    let mut low_port = good.to_vec();
    low_port[19..21].copy_from_slice(&1023_u16.to_be_bytes());
    assert_eq!(LinkOffer::decode(&low_port), Err(DecodeError::Range));
    // A passphrase with a control character, or too short.
    assert_eq!(with(34, 0x0a), Err(DecodeError::Length));
    assert_eq!(with(34, 0x7f), Err(DecodeError::Length));
    let short = LinkOffer::new(
        ID,
        LinkKind::Hotspot,
        LinkSecurity::Wpa2,
        60,
        2000,
        b"x".to_vec(),
        Zeroizing::new(vec![b'a'; 7]),
    );
    assert_eq!(short, Err(DecodeError::Length));
    // An empty or too long SSID on a hotspot; any SSID on Wi-Fi Aware.
    let ssid = |kind, security, ssid: Vec<u8>, secret: Vec<u8>| {
        LinkOffer::new(ID, kind, security, 60, 2000, ssid, Zeroizing::new(secret))
    };
    assert_eq!(
        ssid(
            LinkKind::Hotspot,
            LinkSecurity::Wpa2,
            Vec::new(),
            vec![b'a'; 8]
        ),
        Err(DecodeError::Length)
    );
    assert_eq!(
        ssid(
            LinkKind::Hotspot,
            LinkSecurity::Wpa2,
            vec![b's'; 33],
            vec![b'a'; 8]
        ),
        Err(DecodeError::Length)
    );
    assert_eq!(
        ssid(
            LinkKind::WifiAware,
            LinkSecurity::AwareSk128,
            b"s".to_vec(),
            vec![1; 32]
        ),
        Err(DecodeError::Length)
    );
    assert_eq!(
        ssid(
            LinkKind::WifiAware,
            LinkSecurity::AwareSk128,
            Vec::new(),
            vec![1; 31]
        ),
        Err(DecodeError::Length)
    );
    // An all-zero offer ID.
    let mut zero = good.to_vec();
    zero[..16].fill(0);
    assert_eq!(LinkOffer::decode(&zero), Err(DecodeError::ZeroIdentifier));
    Ok(())
}

/// Debug output never shows the credential or the SSID.
#[test]
fn an_offer_never_prints_its_secret() -> TestResult {
    let offer = hotspot()?;
    let text = format!("{offer:?}");
    assert!(!text.contains("AAAA"), "{text}");
    assert!(!text.contains("todoke-1a2b"), "{text}");
    assert!(!text.contains("65, 65"), "{text}");
    Ok(())
}

/// Abilities are two masks of the three defined kinds.
#[test]
fn abilities_carry_two_masks() -> TestResult {
    let abilities = LinkAbilities::new(
        &[LinkKind::Hotspot],
        &[LinkKind::WifiAware, LinkKind::Hotspot],
    );
    assert_eq!(abilities.encode(), [0b100, 0b101]);
    assert_eq!(LinkAbilities::decode(&[0b100, 0b101])?, abilities);
    assert!(abilities.hosts(LinkKind::Hotspot) && !abilities.hosts(LinkKind::WifiAware));
    assert_eq!(
        LinkAbilities::decode(&[0b1000, 0]),
        Err(DecodeError::Reserved)
    );
    assert_eq!(
        LinkAbilities::decode(&[0, 0x80]),
        Err(DecodeError::Reserved)
    );
    assert_eq!(LinkAbilities::decode(&[0]), Err(DecodeError::Length));
    assert_eq!(LinkAbilities::decode(&[0, 0, 0]), Err(DecodeError::Length));
    assert_eq!(LinkAbilities::decode(&[0, 0])?, LinkAbilities::default());
    Ok(())
}

/// The §10.2 choice: the most preferred kind one can host and the other
/// join; the smaller key hosts when both can; nothing when nothing fits.
#[test]
fn the_link_and_its_host_are_chosen_by_rule() -> TestResult {
    let all = LinkAbilities::new(&LinkKind::ALL, &LinkKind::ALL);
    let none = LinkAbilities::default();
    assert_eq!(
        choose(all, all, true),
        Some((LinkKind::WifiAware, LinkRole::Host))
    );
    assert_eq!(
        choose(all, all, false),
        Some((LinkKind::WifiAware, LinkRole::Join))
    );
    assert_eq!(choose(all, none, true), None);
    assert_eq!(choose(none, none, true), None);
    // An iPhone joins hotspots only; an Android hosts everything.
    let iphone = LinkAbilities::new(&[], &[LinkKind::Hotspot]);
    let android = LinkAbilities::new(&LinkKind::ALL, &[LinkKind::WifiAware, LinkKind::WifiDirect]);
    assert_eq!(
        choose(android, iphone, false),
        Some((LinkKind::Hotspot, LinkRole::Host))
    );
    assert_eq!(
        choose(iphone, android, true),
        Some((LinkKind::Hotspot, LinkRole::Join))
    );
    // Both sides agree on the outcome.
    for own_smaller in [true, false] {
        for (a, b) in [(all, iphone), (android, android), (iphone, android)] {
            let mine = choose(a, b, own_smaller);
            let theirs = choose(b, a, !own_smaller);
            match (mine, theirs) {
                (None, None) => {}
                (Some((kind, role)), Some((other_kind, other_role))) => {
                    assert_eq!(kind, other_kind);
                    assert_ne!(role, other_role);
                }
                _ => return Err("the sides disagree".into()),
            }
        }
    }
    Ok(())
}

/// An answer is the offer ID and one of three results.
#[test]
fn answers_have_three_results() -> TestResult {
    for (code, result) in [
        (1, LinkResult::Joined),
        (2, LinkResult::Declined),
        (3, LinkResult::Failed),
    ] {
        let answer = LinkAnswer {
            offer_id: ID,
            result,
        };
        let body = answer.encode();
        assert_eq!(body[16], code);
        assert_eq!(LinkAnswer::decode(&body)?, answer);
    }
    let mut body = LinkAnswer {
        offer_id: ID,
        result: LinkResult::Joined,
    }
    .encode();
    body[16] = 4;
    assert_eq!(LinkAnswer::decode(&body), Err(DecodeError::UnknownEnum));
    body[16] = 0;
    assert_eq!(LinkAnswer::decode(&body), Err(DecodeError::UnknownEnum));
    assert_eq!(LinkAnswer::decode(&[1; 16]), Err(DecodeError::Length));
    assert_eq!(
        LinkAnswer::decode(&[0; 17]),
        Err(DecodeError::ZeroIdentifier)
    );
    Ok(())
}
