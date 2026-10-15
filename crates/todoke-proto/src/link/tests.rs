use zeroize::Zeroizing;

use super::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const ID: [u8; OFFER_ID_LEN] = [7; OFFER_ID_LEN];
const PASSPHRASE: &[u8; 63] = b"Ab0-_Ab0-_Ab0-_Ab0-_Ab0-_Ab0-_Ab0-_Ab0-_Ab0-_Ab0-_Ab0-_Ab0-_Ab0";
const HOTSPOT_SSID: &[u8; 23] = b"todoke-0123456789abcdef";
const DIRECT_SSID: &[u8; 30] = b"DIRECT-a9-tdk-0123456789abcdef";

fn offer(
    kind: LinkKind,
    security: LinkSecurity,
    ssid: &[u8],
    secret: &[u8],
) -> Result<LinkOffer, DecodeError> {
    LinkOffer::new(
        ID,
        kind,
        security,
        60,
        47_000,
        ssid.to_vec(),
        Zeroizing::new(secret.to_vec()),
    )
}

fn hotspot() -> Result<LinkOffer, DecodeError> {
    offer(
        LinkKind::Hotspot,
        LinkSecurity::Wpa3,
        HOTSPOT_SSID,
        PASSPHRASE,
    )
}

/// The exact §10.2 layout and sizes: 55 bytes for Wi-Fi Aware, 116 for
/// Wi-Fi Direct, 109 for a hotspot.
#[test]
fn offers_have_the_exact_layout() -> TestResult {
    let hotspot = hotspot()?;
    let body = hotspot.encode();
    assert_eq!(body.len(), 109);
    assert_eq!(&body[..16], &ID);
    assert_eq!(&body[16..22], &[3, 1, 60, 0xb7, 0x98, 23]);
    assert_eq!(&body[22..45], HOTSPOT_SSID);
    assert_eq!(body[45], 63);
    assert_eq!(LinkOffer::decode(&body)?, hotspot);
    let direct = offer(
        LinkKind::WifiDirect,
        LinkSecurity::Wpa3Transition,
        DIRECT_SSID,
        PASSPHRASE,
    )?;
    assert_eq!(direct.encode().len(), 116);
    assert_eq!(LinkOffer::decode(&direct.encode())?, direct);
    let aware = offer(
        LinkKind::WifiAware,
        LinkSecurity::AwareSk256,
        &[],
        &[0x5a; PMK_LEN],
    )?;
    let body = aware.encode();
    assert_eq!(body.len(), 55);
    assert_eq!(&body[16..23], &[1, 4, 60, 0xb7, 0x98, 0, 32]);
    assert_eq!(LinkOffer::decode(&body)?, aware);
    Ok(())
}

/// Only the exact SSID shapes are accepted: a hostile host cannot put its
/// own text in a system "join this network" dialog.
#[test]
fn ssids_have_one_shape_per_kind() {
    let hot = |ssid: &[u8]| offer(LinkKind::Hotspot, LinkSecurity::Wpa2, ssid, PASSPHRASE);
    let direct = |ssid: &[u8]| offer(LinkKind::WifiDirect, LinkSecurity::Wpa2, ssid, PASSPHRASE);
    assert!(hot(HOTSPOT_SSID).is_ok());
    assert!(direct(DIRECT_SSID).is_ok());
    for bad in [
        &b"todoke-0123456789ABCDEF"[..],
        b"todoke-0123456789abcdeg",
        b"todoke-0123456789abcde",
        b"todoke-0123456789abcdef0",
        b"Todoke-0123456789abcdef",
        b"Apple ID Verification!!",
        b"todoke-0123456789abcd\xe2\x80",
        DIRECT_SSID,
        b"",
    ] {
        assert_eq!(hot(bad), Err(DecodeError::Length), "{bad:?}");
    }
    for bad in [
        &b"DIRECT-A9-tdk-0123456789abcdef"[..],
        b"DIRECT-a9-TDK-0123456789abcdef",
        b"DIRECT-a9_tdk-0123456789abcdef",
        b"direct-a9-tdk-0123456789abcdef",
        b"DIRECT-a9-tdk-0123456789abcdeX",
        b"DIRECT-a9-tdk-0123456789abcde",
        HOTSPOT_SSID,
    ] {
        assert_eq!(direct(bad), Err(DecodeError::Length), "{bad:?}");
    }
}

/// A passphrase is exactly 63 characters from `A-Z a-z 0-9 - _`.
#[test]
fn passphrases_have_one_shape() {
    let with = |secret: &[u8]| offer(LinkKind::Hotspot, LinkSecurity::Wpa2, HOTSPOT_SSID, secret);
    assert!(with(PASSPHRASE).is_ok());
    let mut wrong = PASSPHRASE.to_vec();
    for byte in [b' ', b'!', b'~', b'.', 0x0a, 0x7f, 0xc3] {
        wrong[10] = byte;
        assert_eq!(with(&wrong), Err(DecodeError::Length), "{byte:#x}");
    }
    assert_eq!(with(&PASSPHRASE[..62]), Err(DecodeError::Length));
    assert_eq!(
        with(&[PASSPHRASE.as_slice(), b"A"].concat()),
        Err(DecodeError::Length)
    );
    assert_eq!(with(b"password"), Err(DecodeError::Length));
}

/// Every other malformed offer is refused before it is used.
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
    // Kind and security, and a security of another kind.
    assert_eq!(with(16, 0), Err(DecodeError::UnknownEnum));
    assert_eq!(with(16, 4), Err(DecodeError::UnknownEnum));
    assert_eq!(with(17, 0), Err(DecodeError::UnknownEnum));
    assert_eq!(with(17, 6), Err(DecodeError::UnknownEnum));
    assert_eq!(with(17, 4), Err(DecodeError::UnknownEnum));
    // Expiry and port.
    assert_eq!(with(18, 9), Err(DecodeError::Range));
    assert_eq!(with(18, 121), Err(DecodeError::Range));
    let mut low_port = good.to_vec();
    low_port[19..21].copy_from_slice(&1023_u16.to_be_bytes());
    assert_eq!(LinkOffer::decode(&low_port), Err(DecodeError::Range));
    // Wi-Fi Aware: no SSID, a 32-byte PMK.
    let aware = |ssid: &[u8], secret: &[u8]| {
        offer(LinkKind::WifiAware, LinkSecurity::AwareSk128, ssid, secret)
    };
    assert_eq!(aware(b"s", &[1; 32]), Err(DecodeError::Length));
    assert_eq!(aware(&[], &[1; 31]), Err(DecodeError::Length));
    assert_eq!(aware(&[], &[1; 33]), Err(DecodeError::Length));
    // An all-zero offer ID.
    let mut zero = good.to_vec();
    zero[..16].fill(0);
    assert_eq!(LinkOffer::decode(&zero), Err(DecodeError::ZeroIdentifier));
    Ok(())
}

/// Debug output never shows the credential or the SSID.
#[test]
fn an_offer_never_prints_its_secret() -> TestResult {
    let text = format!("{:?}", hotspot()?);
    assert!(!text.contains("Ab0"), "{text}");
    assert!(!text.contains("todoke-"), "{text}");
    assert!(!text.contains("65, 98"), "{text}");
    Ok(())
}

/// Abilities: two kind masks and a security mask, nothing else.
#[test]
fn abilities_carry_three_masks() -> TestResult {
    let abilities = LinkAbilities::new(
        &[LinkKind::Hotspot],
        &[LinkKind::WifiAware, LinkKind::Hotspot],
        &[LinkSecurity::Wpa2, LinkSecurity::AwareSk128],
    );
    assert_eq!(abilities.encode(), [0b100, 0b101, 0b1_0100]);
    assert_eq!(LinkAbilities::decode(&[0b100, 0b101, 0b1_0100])?, abilities);
    assert_eq!(
        abilities.strongest(LinkKind::Hotspot),
        Some(LinkSecurity::Wpa2)
    );
    assert_eq!(
        abilities.strongest(LinkKind::WifiAware),
        Some(LinkSecurity::AwareSk128)
    );
    assert_eq!(
        abilities.strongest(LinkKind::WifiDirect),
        Some(LinkSecurity::Wpa2)
    );
    assert_eq!(
        LinkAbilities::decode(&[0b1000, 0, 0]),
        Err(DecodeError::Reserved)
    );
    assert_eq!(
        LinkAbilities::decode(&[0, 0x80, 0]),
        Err(DecodeError::Reserved)
    );
    assert_eq!(
        LinkAbilities::decode(&[0, 0, 0b10_0000]),
        Err(DecodeError::Reserved)
    );
    assert_eq!(LinkAbilities::decode(&[0, 0]), Err(DecodeError::Length));
    assert_eq!(
        LinkAbilities::decode(&[0, 0, 0, 0]),
        Err(DecodeError::Length)
    );
    assert_eq!(LinkAbilities::decode(&[0, 0, 0])?, LinkAbilities::default());
    Ok(())
}

/// The §10.2 choice: the most preferred kind one can host and the other
/// can join with some security of it; the smaller key hosts when both
/// can; the strongest security the joiner supports; nothing when nothing
/// fits. Both ends come to the same choice.
#[test]
fn the_link_its_host_and_its_security_are_chosen_by_rule() -> TestResult {
    let every = LinkSecurity::ALL;
    let all = LinkAbilities::new(&LinkKind::ALL, &LinkKind::ALL, &every);
    let none = LinkAbilities::default();
    let chosen =
        |own, peer, smaller| choose(own, peer, smaller).map(|c| (c.kind, c.role, c.security));
    assert_eq!(
        chosen(all, all, true),
        Some((
            LinkKind::WifiAware,
            LinkRole::Host,
            LinkSecurity::AwareSk256
        ))
    );
    assert_eq!(
        chosen(all, all, false),
        Some((
            LinkKind::WifiAware,
            LinkRole::Join,
            LinkSecurity::AwareSk256
        ))
    );
    assert_eq!(chosen(all, none, true), None);
    // An iPhone joins hotspots with WPA2 only: an Android hosts one for it.
    let iphone = LinkAbilities::new(&[], &[LinkKind::Hotspot], &[LinkSecurity::Wpa2]);
    let android = LinkAbilities::new(&LinkKind::ALL, &[LinkKind::WifiAware], &every);
    assert_eq!(
        chosen(android, iphone, false),
        Some((LinkKind::Hotspot, LinkRole::Host, LinkSecurity::Wpa2))
    );
    // A joiner that can join a kind but with no security of it: not that kind.
    let no_wpa = LinkAbilities::new(&[], &[LinkKind::Hotspot], &[LinkSecurity::AwareSk256]);
    assert_eq!(chosen(android, no_wpa, true), None);
    for own_smaller in [true, false] {
        for (a, b) in [
            (all, iphone),
            (android, android),
            (iphone, android),
            (all, all),
        ] {
            let mine = choose(a, b, own_smaller);
            let theirs = choose(b, a, !own_smaller);
            match (mine, theirs) {
                (None, None) => {}
                (Some(mine), Some(theirs)) => {
                    assert_eq!((mine.kind, mine.security), (theirs.kind, theirs.security));
                    assert_ne!(mine.role, theirs.role);
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
