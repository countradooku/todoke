//! Link setup in the session (PROTOCOL §10.2): abilities once each, one
//! choice, one offer of exactly the chosen kind and security, one answer.

use todoke_proto::link::{
    LinkAbilities, LinkAnswer, LinkChoice, LinkKind, LinkOffer, LinkResult, LinkRole, LinkSecurity,
};
use todoke_proto::session::FrameType;
use zeroize::Zeroizing;

use super::basic::session_failure;
use super::support::{Link, TestResult, Which, config, fixture};
use crate::{FailureCode, LinkError, MemorySink, MemorySource, TransferEvent};

fn link(fixture: &super::support::Fixture) -> Result<Link<'_>, Box<dyn std::error::Error>> {
    let mut link = Link::new(
        fixture,
        Which::First,
        (MemorySource::new(), MemorySource::new()),
        (MemorySink::new(), MemorySink::new()),
        (config(4)?, config(4)?),
    )?;
    link.settle()?;
    Ok(link)
}

/// A hotspot offer with `security`.
fn hotspot(id: u8, security: LinkSecurity) -> Result<LinkOffer, Box<dyn std::error::Error>> {
    Ok(LinkOffer::new(
        [id; 16],
        LinkKind::Hotspot,
        security,
        60,
        40_000,
        b"todoke-0123456789abcdef".to_vec(),
        Zeroizing::new(vec![b'a'; 63]),
    )?)
}

fn chosen(events: &[TransferEvent]) -> Option<LinkChoice> {
    events.iter().find_map(|event| match event {
        TransferEvent::LinkChosen(choice) => Some(*choice),
        _ => None,
    })
}

/// Alice can host a hotspot; Bob can join one with every security. Alice
/// hosts and offers WPA3 (the strongest Bob can join); Bob gets the offer
/// and answers; Alice gets the answer.
#[test]
fn a_link_is_chosen_offered_and_answered() -> TestResult {
    let fixture = fixture()?;
    let mut link = link(&fixture)?;
    let all = [
        LinkSecurity::Wpa3,
        LinkSecurity::Wpa3Transition,
        LinkSecurity::Wpa2,
    ];
    link.a
        .send_link_abilities(LinkAbilities::new(&[LinkKind::Hotspot], &[], &[]))?;
    link.b
        .send_link_abilities(LinkAbilities::new(&[], &[LinkKind::Hotspot], &all))?;
    link.settle()?;
    let expected = |role| LinkChoice {
        kind: LinkKind::Hotspot,
        role,
        security: LinkSecurity::Wpa3,
    };
    assert_eq!(chosen(&link.a_events), Some(expected(LinkRole::Host)));
    assert_eq!(chosen(&link.b_events), Some(expected(LinkRole::Join)));
    // Only the chosen kind and security may be offered.
    assert_eq!(
        link.a.offer_link(&hotspot(1, LinkSecurity::Wpa2)?),
        Err(LinkError::WrongOffer)
    );
    // The joiner cannot offer; the host cannot answer.
    assert_eq!(
        link.b.offer_link(&hotspot(1, LinkSecurity::Wpa3)?),
        Err(LinkError::NotChosen)
    );
    assert_eq!(
        link.a.answer_link(&[1; 16], LinkResult::Joined),
        Err(LinkError::NoOffer)
    );
    let offer = hotspot(7, LinkSecurity::Wpa3)?;
    link.a.offer_link(&offer)?;
    assert_eq!(link.a.offer_link(&offer), Err(LinkError::Done));
    link.settle()?;
    let got = link.b_events.iter().find_map(|event| match event {
        TransferEvent::LinkOffered(offer) => Some(offer.clone()),
        _ => None,
    });
    assert_eq!(got.as_deref(), Some(&offer));
    // An answer to another offer is refused; then the right one, once.
    assert_eq!(
        link.b.answer_link(&[8; 16], LinkResult::Joined),
        Err(LinkError::NoOffer)
    );
    link.b.answer_link(&[7; 16], LinkResult::Joined)?;
    assert_eq!(
        link.b.answer_link(&[7; 16], LinkResult::Joined),
        Err(LinkError::Done)
    );
    link.settle()?;
    let answered = link.a_events.iter().find_map(|event| match event {
        TransferEvent::LinkAnswered(answer) => Some(*answer),
        _ => None,
    });
    assert_eq!(
        answered,
        Some(LinkAnswer {
            offer_id: [7; 16],
            result: LinkResult::Joined,
        })
    );
    Ok(())
}

/// Abilities go once, and only once the session is ready.
#[test]
fn abilities_go_once_after_capabilities() -> TestResult {
    let fixture = fixture()?;
    let mut fresh = Link::new(
        &fixture,
        Which::First,
        (MemorySource::new(), MemorySource::new()),
        (MemorySink::new(), MemorySink::new()),
        (config(4)?, config(4)?),
    )?;
    let none = LinkAbilities::new(&[], &[LinkKind::Hotspot], &[LinkSecurity::Wpa2]);
    // Capabilities not exchanged yet.
    assert_eq!(fresh.a.send_link_abilities(none), Err(LinkError::NotReady));
    fresh.settle()?;
    fresh.a.send_link_abilities(none)?;
    assert_eq!(
        fresh.a.send_link_abilities(none),
        Err(LinkError::AlreadySent)
    );
    fresh.settle()?;
    assert_eq!(fresh.delivered(true, FrameType::LINK_ABILITIES), 1);
    Ok(())
}

/// When both can host the kind, the smaller full device key hosts.
#[test]
fn the_smaller_key_hosts_when_both_can() -> TestResult {
    let fixture = fixture()?;
    let mut link = link(&fixture)?;
    let both = LinkAbilities::new(
        &[LinkKind::WifiDirect],
        &[LinkKind::WifiDirect],
        &[LinkSecurity::Wpa2],
    );
    link.a.send_link_abilities(both)?;
    link.b.send_link_abilities(both)?;
    link.settle()?;
    let alice_smaller = fixture.alice.key().as_bytes() < fixture.bob.key().as_bytes();
    let (a, b) = (chosen(&link.a_events), chosen(&link.b_events));
    let roles = (a.map(|choice| choice.role), b.map(|choice| choice.role));
    if alice_smaller {
        assert_eq!(roles, (Some(LinkRole::Host), Some(LinkRole::Join)));
    } else {
        assert_eq!(roles, (Some(LinkRole::Join), Some(LinkRole::Host)));
    }
    Ok(())
}

/// A peer that offers a weaker security than the strongest this side can
/// join, another kind, or a second offer, or answers what it was not
/// offered, ends the session (STATE): never passed on.
#[test]
fn offers_and_answers_out_of_line_are_state() -> TestResult {
    let fixture = fixture()?;
    let all = [
        LinkSecurity::Wpa3,
        LinkSecurity::Wpa3Transition,
        LinkSecurity::Wpa2,
    ];
    let setup = |link: &mut Link<'_>| -> TestResult {
        link.a
            .send_link_abilities(LinkAbilities::new(&[LinkKind::Hotspot], &[], &[]))?;
        link.b
            .send_link_abilities(LinkAbilities::new(&[], &[LinkKind::Hotspot], &all))?;
        link.settle()
    };
    // A downgrade: WPA2 when Bob joins WPA3.
    let mut weaker = link(&fixture)?;
    setup(&mut weaker)?;
    let body = hotspot(2, LinkSecurity::Wpa2)?.encode();
    let result = weaker
        .b
        .handle_frame(FrameType::LINK_OFFER, &body, weaker.now);
    assert_eq!(session_failure(result), Some(FailureCode::State));
    assert!(
        !weaker
            .b_events
            .iter()
            .any(|event| matches!(event, TransferEvent::LinkOffered(_)))
    );
    // Another kind (a Wi-Fi Direct group) than the chosen hotspot.
    let mut other = link(&fixture)?;
    setup(&mut other)?;
    let direct = LinkOffer::new(
        [3; 16],
        LinkKind::WifiDirect,
        LinkSecurity::Wpa3,
        60,
        40_000,
        b"DIRECT-ab-tdk-0123456789abcdef".to_vec(),
        Zeroizing::new(vec![b'a'; 63]),
    )?;
    let result = other
        .b
        .handle_frame(FrameType::LINK_OFFER, &direct.encode(), other.now);
    assert_eq!(session_failure(result), Some(FailureCode::State));
    // A second offer.
    let mut twice = link(&fixture)?;
    setup(&mut twice)?;
    let body = hotspot(4, LinkSecurity::Wpa3)?.encode();
    twice
        .b
        .handle_frame(FrameType::LINK_OFFER, &body, twice.now)?;
    let result = twice
        .b
        .handle_frame(FrameType::LINK_OFFER, &body, twice.now);
    assert_eq!(session_failure(result), Some(FailureCode::State));
    // An answer to an offer Alice never sent, and a second answer.
    let mut unasked = link(&fixture)?;
    setup(&mut unasked)?;
    let answer = LinkAnswer {
        offer_id: [5; 16],
        result: LinkResult::Joined,
    }
    .encode();
    let result = unasked
        .a
        .handle_frame(FrameType::LINK_ANSWER, &answer, unasked.now);
    assert_eq!(session_failure(result), Some(FailureCode::State));
    let mut again = link(&fixture)?;
    setup(&mut again)?;
    again.a.offer_link(&hotspot(6, LinkSecurity::Wpa3)?)?;
    again.settle()?;
    again.b.answer_link(&[6; 16], LinkResult::Declined)?;
    again.settle()?;
    let answer = LinkAnswer {
        offer_id: [6; 16],
        result: LinkResult::Joined,
    }
    .encode();
    let result = again
        .a
        .handle_frame(FrameType::LINK_ANSWER, &answer, again.now);
    assert_eq!(session_failure(result), Some(FailureCode::State));
    // A host's offer to a joiner that sent no abilities.
    let mut silent = link(&fixture)?;
    silent
        .a
        .send_link_abilities(LinkAbilities::new(&[LinkKind::Hotspot], &[], &[]))?;
    silent.settle()?;
    let body = hotspot(9, LinkSecurity::Wpa3)?.encode();
    let result = silent
        .b
        .handle_frame(FrameType::LINK_OFFER, &body, silent.now);
    assert_eq!(session_failure(result), Some(FailureCode::State));
    Ok(())
}
