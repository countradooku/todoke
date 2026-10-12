//! End-to-end human-code pairing (PROTOCOL §3.2) over the sans-IO session
//! harness: `CPace`, `XXpsk3`, identity, and the first ratchet; wrong codes
//! and the attempt budget; active attackers; malformed shares; expiry and
//! replay; and crashes at every point.

use core::time::Duration;

use proptest::prelude::*;
use todoke_proto::pairing::{
    CODE_OFFER_TRANSCRIPT_LEN, CodeOffer, CodeOfferRequest, CodeRole, CodeShare,
};
use todoke_proto::session::{Hello, PreludeKind, SessionMode, encode_prelude_record};
use todoke_proto::time::UnixTime;

use super::tests::{
    Auth, CLIENT_NONCE, MONO, RunResult, drain, empty_store, finish, side_journaled, view, wall,
};
use super::*;
use crate::identity::TrustOrigin;
use crate::identity::contacts::PairOutcome;
use crate::session::engine::Entropy;
use crate::session::establish::Phase;
use crate::session::handshake::HandshakeDriver;
use crate::session::tests::support::{
    AnyResult, Device, GATE, Harness, Side, Stage, Store, TestResult, reopen,
};
use crate::session::{ResponderPlan, Role, SessionError};

const CODE_GATE: UnauditedCodePairing = UnauditedCodePairing::acknowledge_not_production_ready();
const TOKEN: [u8; 8] = [0x5e; 8];

/// An entrant (Alice) and a displayer (Bob) with empty stores, Bob's live
/// code offer, and the public offer records Alice received for it.
struct CodePairing {
    entrant: Device,
    displayer: Device,
    entrant_store: Store,
    displayer_store: Store,
    offers: PairingOffers,
    /// What Bob shows.
    shown: HumanCode,
    request: CodeOfferRequest,
    offer: CodeOffer,
    /// Monotonic time of the next attempt (attempts are 2 s apart).
    mono: Duration,
}

impl CodePairing {
    fn new() -> AnyResult<Self> {
        let offers = PairingOffers::new();
        let shown = offers.create_code(wall()?, MONO)?;
        let request = CodeOfferRequest::new(TOKEN)?;
        let offer = offers.answer_code_request(&request, &TOKEN, wall()?, MONO)?;
        Ok(Self {
            entrant: Device::new()?,
            displayer: Device::new()?,
            entrant_store: empty_store()?,
            displayer_store: empty_store()?,
            offers,
            shown,
            request,
            offer,
            mono: MONO,
        })
    }

    fn code_offer(&self) -> [u8; CODE_OFFER_TRANSCRIPT_LEN] {
        let mut out = [0; CODE_OFFER_TRANSCRIPT_LEN];
        out[..10].copy_from_slice(&self.request.encode());
        out[10..].copy_from_slice(&self.offer.encode());
        out
    }

    fn hello(&self) -> AnyResult<Hello> {
        Ok(Hello::client(
            SessionMode::Code,
            0,
            *self.offer.pairing_id(),
            CLIENT_NONCE,
        )?)
    }

    fn wrong_code(&self) -> AnyResult<HumanCode> {
        let mut digits = self.shown.as_str().as_bytes().to_vec();
        digits[9] = if digits[9] == b'9' {
            b'0'
        } else {
            digits[9] + 1
        };
        Ok(HumanCode::parse(core::str::from_utf8(&digits)?)?)
    }
}

/// One code-pairing attempt with `entered` as Alice's code; `run` drives
/// the wire. Advances the attempt clock by the 2 s spacing.
fn code_run(
    p: &mut CodePairing,
    entered: &HumanCode,
    defer_ack: bool,
    run: impl FnOnce(&mut Harness<'_, Auth<'_>, Auth<'_>>),
) -> AnyResult<RunResult> {
    let entrant_local = p.entrant.local()?;
    let displayer_local = p.displayer.local()?;
    let hello = p.hello()?;
    let code_offer = p.code_offer();
    let (plan, entrant_authority) =
        p.entrant_store
            .begin_code_pairing(CODE_GATE, p.request, &p.offer, entered, wall()?)?;
    let reservation = p.offers.reserve(&hello, wall()?, p.mono)?;
    p.mono += CODE_ATTEMPT_SPACING;
    let (mut responder_plan, displayer_authority) =
        reservation.into_code_responder(CODE_GATE, &mut p.displayer_store)?;
    responder_plan.bind_code_offer(code_offer)?;
    let initiator = Side::initiator(entrant_local, entrant_authority);
    let mut responder = Side::responder(displayer_local, displayer_authority, responder_plan);
    responder.defer_ack = defer_ack;
    let mut harness = Harness::new(initiator, responder, plan)?;
    run(&mut harness);
    Ok(finish(&mut harness))
}

#[test]
fn code_pairing_creates_matching_contacts_on_both_sides() -> TestResult {
    let mut p = CodePairing::new()?;
    let entered = HumanCode::parse(p.shown.as_str())?;
    let result = code_run(&mut p, &entered, false, drain)?;
    let hash = result.scanner_open.ok_or("entrant not open")?;
    assert_eq!(result.displayer_open, Some(hash));
    assert_eq!(result.scanner_outcome, Some(PairOutcome::New));
    assert_eq!(result.displayer_outcome, Some(PairOutcome::New));
    let entrant = view(&p.entrant_store, &p.displayer.key())?.ok_or("entrant")?;
    let displayer = view(&p.displayer_store, &p.entrant.key())?.ok_or("displayer")?;
    assert_eq!(entrant, displayer);
    assert_eq!(entrant.0, 1);
    for (store, peer) in [
        (&p.entrant_store, p.displayer.key()),
        (&p.displayer_store, p.entrant.key()),
    ] {
        let contact = store.contact(&peer).ok_or("contact")?;
        assert_eq!(contact.origin(), TrustOrigin::CodePairing);
        assert!(store.pairing_burned(p.offer.pairing_id()));
        assert_eq!(view(&reopen(store)?, &peer)?, Some(entrant));
    }
    assert_eq!(p.offers.live(OfferKind::Code, wall()?, p.mono), 0);
    Ok(())
}

#[test]
fn wrong_codes_consume_the_attempt_budget_but_no_contact_state() -> TestResult {
    let mut p = CodePairing::new()?;
    let wrong = p.wrong_code()?;
    let id = *p.offer.pairing_id();
    for attempt in 1..=MAX_CODE_FAILURES {
        let result = code_run(&mut p, &wrong, false, drain)?;
        assert!(result.scanner_open.is_none() && result.displayer_open.is_none());
        // The displayer saw the Noise authentication fail; it sent nothing
        // that distinguishes a wrong code (§3.2).
        assert_eq!(result.displayer_error, Some(SessionError::Authentication));
        if attempt < MAX_CODE_FAILURES {
            assert_eq!(p.offers.failures(&id), Some(attempt));
        }
        assert!(!p.entrant_store.pairing_burned(&id));
        assert!(!p.displayer_store.pairing_burned(&id));
        assert!(p.entrant_store.contact(&p.displayer.key()).is_none());
    }
    // Exhausted: even the right code needs a new offer (§3.2).
    let right = HumanCode::parse(p.shown.as_str())?;
    assert_eq!(
        code_run(&mut p, &right, false, drain)
            .err()
            .map(|e| e.to_string()),
        Some(PairingError::UnknownOffer.to_string())
    );
    Ok(())
}

#[test]
fn attempts_too_close_together_are_refused() -> TestResult {
    let mut p = CodePairing::new()?;
    let wrong = p.wrong_code()?;
    code_run(&mut p, &wrong, false, drain)?;
    p.mono -= Duration::from_millis(1);
    let right = HumanCode::parse(p.shown.as_str())?;
    assert_eq!(
        code_run(&mut p, &right, false, drain)
            .err()
            .map(|e| e.to_string()),
        Some(PairingError::TooSoon.to_string())
    );
    p.mono += Duration::from_millis(1);
    let result = code_run(&mut p, &right, false, drain)?;
    assert!(result.scanner_open.is_some() && result.displayer_open.is_some());
    Ok(())
}

/// Mallory relays the public offer records but runs `CPace` herself with
/// each side, guessing the code: both runs fail, and the guess costs the
/// displayer one attempt.
#[test]
fn a_man_in_the_middle_with_a_guessed_code_fails_on_both_sides() -> TestResult {
    let mut p = CodePairing::new()?;
    let mallory = Device::new()?;
    let guess = p.wrong_code()?;
    // Mallory as the entrant towards Bob.
    let mut mallory_store = empty_store()?;
    let hello = p.hello()?;
    let code_offer = p.code_offer();
    let bob_local = p.displayer.local()?;
    let (plan, mallory_authority) =
        mallory_store.begin_code_pairing(CODE_GATE, p.request, &p.offer, &guess, wall()?)?;
    let reservation = p.offers.reserve(&hello, wall()?, p.mono)?;
    p.mono += CODE_ATTEMPT_SPACING;
    let (mut bob_plan, bob_authority) =
        reservation.into_code_responder(CODE_GATE, &mut p.displayer_store)?;
    bob_plan.bind_code_offer(code_offer)?;
    let mut towards_bob = Harness::new(
        Side::initiator(mallory.local()?, mallory_authority),
        Side::responder(bob_local, bob_authority, bob_plan),
        plan,
    )?;
    towards_bob.drain();
    let bob_side = finish(&mut towards_bob);
    assert!(bob_side.scanner_open.is_none() && bob_side.displayer_open.is_none());
    drop(towards_bob);
    assert_eq!(p.offers.failures(p.offer.pairing_id()), Some(1));
    // Mallory as the displayer towards Alice, with Bob's offer records.
    let right = HumanCode::parse(p.shown.as_str())?;
    let mallory_offers = PairingOffers::new();
    mallory_offers.create_code(wall()?, MONO)?;
    let mallory_id = mallory_offers.code_pairing_id().ok_or("offer")?;
    let reservation = mallory_offers.reserve(
        &Hello::client(SessionMode::Code, 0, mallory_id, CLIENT_NONCE)?,
        wall()?,
        MONO,
    )?;
    let mut mallory_store = empty_store()?;
    let (_, mallory_authority) = reservation.into_code_responder(CODE_GATE, &mut mallory_store)?;
    let mut mallory_plan = ResponderPlan::code_pairing(CODE_GATE, guess);
    mallory_plan.bind_code_offer(code_offer)?;
    let alice_local = p.entrant.local()?;
    let (plan, alice_authority) =
        p.entrant_store
            .begin_code_pairing(CODE_GATE, p.request, &p.offer, &right, wall()?)?;
    let mut towards_alice = Harness::new(
        Side::initiator(alice_local, alice_authority),
        Side::responder(mallory.local()?, mallory_authority, mallory_plan),
        plan,
    )?;
    towards_alice.drain();
    let alice_side = finish(&mut towards_alice);
    assert!(alice_side.scanner_open.is_none() && alice_side.displayer_open.is_none());
    drop(towards_alice);
    assert!(p.entrant_store.contact(&mallory.key()).is_none());
    assert!(!p.entrant_store.pairing_burned(p.offer.pairing_id()));
    // The honest pair still pairs with the same offer.
    let honest = code_run(&mut p, &right, false, drain)?;
    assert!(honest.scanner_open.is_some() && honest.displayer_open.is_some());
    Ok(())
}

/// The displayer withdraws its code and shows a new one while an attempt
/// with the old code is in flight, before or after it confirmed the
/// entrant's identity: the attempt stops before the displayer journals
/// anything, no contact is created, the displayer's store is unchanged,
/// and the new code is untouched. While the attempt holds the old code, a
/// new code is refused rather than silently replacing it.
#[test]
fn a_withdrawn_or_replaced_code_stops_an_attempt_in_flight() -> TestResult {
    for confirmed in [false, true] {
        let mut p = CodePairing::new()?;
        let right = HumanCode::parse(p.shown.as_str())?;
        let offers = p.offers.clone();
        let id = *p.offer.pairing_id();
        let before = p.displayer_store.storage().blob().map(<[u8]>::to_vec);
        let now = wall()?;
        let mut replace_while_held = None;
        let mut replacement = None;
        let mut was_confirmed = false;
        let result = code_run(&mut p, &right, false, |harness| {
            replace_while_held = Some(offers.create_code(now, MONO).map(|_| ()));
            if confirmed {
                while !matches!(&harness.responder.stage, Stage::Establish(e) if e.phase() == Phase::AwaitReady)
                {
                    if !(harness.deliver(true) || harness.deliver(false)) {
                        break;
                    }
                }
                was_confirmed = matches!(&harness.responder.stage, Stage::Establish(e) if e.phase() == Phase::AwaitReady);
            }
            offers.cancel_all();
            replacement = Some(offers.create_code(now, MONO).map(|_| ()));
            harness.drain();
        })?;
        let label = format!("confirmed {confirmed}");
        assert_eq!(was_confirmed, confirmed, "{label}");
        assert_eq!(
            replace_while_held,
            Some(Err(PairingError::OfferBusy)),
            "{label}"
        );
        assert_eq!(replacement, Some(Ok(())), "{label}");
        assert!(result.displayer_open.is_none(), "{label}");
        assert!(result.scanner_open.is_none(), "{label}");
        assert_eq!(
            result.displayer_error,
            Some(SessionError::Pairing(PairingError::UnknownOffer)),
            "{label}"
        );
        assert_eq!(result.displayer_outcome, None, "{label}");
        assert!(
            p.displayer_store.contact(&p.entrant.key()).is_none(),
            "{label}"
        );
        assert!(
            p.entrant_store.contact(&p.displayer.key()).is_none(),
            "{label}"
        );
        assert!(!p.displayer_store.pairing_pending(), "{label}");
        assert!(!p.displayer_store.pairing_burned(&id), "{label}");
        assert_eq!(
            p.displayer_store.storage().blob().map(<[u8]>::to_vec),
            before,
            "{label}"
        );
        // The new code is the only code offer, with no failure recorded.
        let fresh = p.offers.code_pairing_id().ok_or("new code")?;
        assert_ne!(fresh, id, "{label}");
        assert_eq!(p.offers.failures(&fresh), Some(0), "{label}");
        assert_eq!(p.offers.active_attempts(), 0, "{label}");
    }
    Ok(())
}

fn honest_record_count() -> AnyResult<usize> {
    let mut p = CodePairing::new()?;
    let right = HumanCode::parse(p.shown.as_str())?;
    let mut count = 0;
    code_run(&mut p, &right, false, |harness| {
        while harness.deliver(true) || harness.deliver(false) {
            count += 1;
        }
    })?;
    Ok(count)
}

/// A relay that alters any one record: never two divergent usable
/// contacts; before a journal, nothing is burned and the attempt counts
/// as one failure; after it, the offer is burned.
#[test]
fn a_relay_that_alters_any_record_never_pairs_divergently() -> TestResult {
    let steps = honest_record_count()?;
    // ClientHello, ServerHello, two shares, three Noise messages, then the
    // identity and ratchet records.
    assert!(steps >= 11, "{steps}");
    for target in 0..steps {
        let mut p = CodePairing::new()?;
        let right = HumanCode::parse(p.shown.as_str())?;
        let mut journaled = false;
        let result = code_run(&mut p, &right, false, |harness| {
            let mut index = 0;
            loop {
                let to_responder = !harness.to_responder.is_empty();
                let Some(mut record) = harness.queue(to_responder).pop_front() else {
                    break;
                };
                if index == target {
                    let last = record.len() - 1;
                    record[last] ^= 0x01;
                }
                index += 1;
                harness.deliver_bytes(to_responder, &record);
                journaled |= side_journaled(&harness.initiator.stage, Role::Initiator)
                    || side_journaled(&harness.responder.stage, Role::Responder);
            }
        })?;
        let label = format!("altered record {target}");
        assert!(
            result.scanner_open.is_none() || result.displayer_open.is_none(),
            "{label}"
        );
        let a = view(&reopen(&p.entrant_store)?, &p.displayer.key())?;
        let b = view(&reopen(&p.displayer_store)?, &p.entrant.key())?;
        if let (Some(a), Some(b)) = (a, b) {
            assert_eq!(a, b, "{label}: divergent");
        }
        let id = p.offer.pairing_id();
        if !journaled {
            assert!(!p.entrant_store.pairing_burned(id), "{label}");
            assert!(!p.displayer_store.pairing_burned(id), "{label}");
            assert_eq!(p.offers.failures(id), Some(1), "{label}");
        }
    }
    Ok(())
}

/// Shares that are malformed, from the wrong role, for another offer,
/// neutral, or noncanonical abort the responder before any Noise state.
#[test]
fn invalid_shares_abort_the_attempt() -> TestResult {
    let p = CodePairing::new()?;
    let hello = p.hello()?;
    let id = *p.offer.pairing_id();
    let mut canonical = [0; 32];
    // The Ristretto255 basepoint encoding (RFC 9496 §4.4).
    canonical.copy_from_slice(&hex::decode(
        "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76",
    )?);
    let mut negative = canonical;
    negative[0] |= 1;
    let share = |role: CodeRole, pairing_id: [u8; 16], element: [u8; 32]| -> AnyResult<Vec<u8>> {
        let body = CodeShare::new(pairing_id, role, element)?.encode();
        Ok(encode_prelude_record(
            if role == CodeRole::A {
                PreludeKind::CodeShareA
            } else {
                PreludeKind::CodeShareB
            },
            &body,
        )?)
    };
    let mut wrong_kind = share(CodeRole::A, id, canonical)?;
    wrong_kind[2] = PreludeKind::CodeShareB.to_u8();
    let mut truncated = share(CodeRole::A, id, canonical)?;
    truncated.pop();
    let cases: Vec<(&str, Vec<u8>)> = vec![
        ("role B", share(CodeRole::B, id, canonical)?),
        ("kind B with role A", wrong_kind),
        ("other offer", share(CodeRole::A, [0x77; 16], canonical)?),
        ("neutral", share(CodeRole::A, id, [0; 32])?),
        ("negative", share(CodeRole::A, id, negative)?),
        ("not a point", share(CodeRole::A, id, [0xff; 32])?),
        ("truncated", truncated),
    ];
    let device = Device::new()?;
    for (label, record) in cases {
        let mut plan = ResponderPlan::code_pairing(CODE_GATE, p.shown.clone());
        plan.bind_code_offer(p.code_offer())?;
        let (mut driver, _) = HandshakeDriver::responder(
            GATE,
            hello,
            plan,
            &device.noise,
            [0x5c; 16],
            Entropy::Os,
            MONO,
        )?;
        let body = &record[2..];
        assert!(driver.receive(body, MONO).is_err(), "{label}");
        // Poisoned: even a valid share is refused now.
        let valid = share(CodeRole::A, id, canonical)?;
        assert!(driver.receive(&valid[2..], MONO).is_err(), "{label}");
    }
    // The canonical basepoint is a valid share: the responder answers it
    // with its own share, once; a duplicate share A is refused.
    let mut plan = ResponderPlan::code_pairing(CODE_GATE, p.shown.clone());
    plan.bind_code_offer(p.code_offer())?;
    let (mut driver, _) = HandshakeDriver::responder(
        GATE,
        hello,
        plan,
        &device.noise,
        [0x5c; 16],
        Entropy::Os,
        MONO,
    )?;
    let valid = share(CodeRole::A, id, canonical)?;
    let replies = driver.receive(&valid[2..], MONO)?;
    assert_eq!(replies.len(), 1);
    assert_eq!(replies[0][2], PreludeKind::CodeShareB.to_u8());
    assert_eq!(replies[0].len(), 2 + 1 + 49);
    assert!(driver.receive(&valid[2..], MONO).is_err());
    Ok(())
}

#[test]
fn a_code_plan_needs_its_offer_records() -> TestResult {
    let p = CodePairing::new()?;
    let device = Device::new()?;
    let plan = ResponderPlan::code_pairing(CODE_GATE, p.shown.clone());
    assert_eq!(
        HandshakeDriver::responder(
            GATE,
            p.hello()?,
            plan,
            &device.noise,
            [0x5c; 16],
            Entropy::Os,
            MONO
        )
        .err(),
        Some(SessionError::Usage)
    );
    let mut bound = ResponderPlan::code_pairing(CODE_GATE, p.shown.clone());
    bound.bind_code_offer(p.code_offer())?;
    assert_eq!(
        bound.bind_code_offer(p.code_offer()),
        Err(SessionError::Usage)
    );
    let mut qr = ResponderPlan::qr(crate::session::PairingPsk::from_bytes(
        zeroize::Zeroizing::new([1; 32]),
    ));
    assert_eq!(qr.bind_code_offer(p.code_offer()), Err(SessionError::Usage));
    Ok(())
}

#[test]
fn expired_and_replayed_offers_are_refused() -> TestResult {
    let mut p = CodePairing::new()?;
    let right = HumanCode::parse(p.shown.as_str())?;
    let expires = p.offer.expires_at().seconds();
    let skew = crate::identity::CLOCK_SKEW_SECONDS;
    let late = UnixTime::new(expires + skew).ok_or("time")?;
    assert_eq!(
        p.entrant_store
            .begin_code_pairing(CODE_GATE, p.request, &p.offer, &right, late)
            .err(),
        Some(PairingError::Expired)
    );
    assert_eq!(
        p.offers
            .reserve(&p.hello()?, UnixTime::new(expires).ok_or("time")?, p.mono)
            .err(),
        Some(PairingError::Expired)
    );
    // Fresh offer, successful pairing, then replays.
    let mut p = CodePairing::new()?;
    let right = HumanCode::parse(p.shown.as_str())?;
    code_run(&mut p, &right, false, drain)?;
    assert_eq!(
        p.entrant_store
            .begin_code_pairing(CODE_GATE, p.request, &p.offer, &right, wall()?)
            .err(),
        Some(PairingError::Burned)
    );
    let mut restarted = reopen(&p.entrant_store)?;
    assert_eq!(
        restarted
            .begin_code_pairing(CODE_GATE, p.request, &p.offer, &right, wall()?)
            .err(),
        Some(PairingError::Burned)
    );
    assert_eq!(
        p.offers.reserve(&p.hello()?, wall()?, p.mono).err(),
        Some(PairingError::UnknownOffer)
    );
    Ok(())
}

/// Crash either side after every prefix of the honest run: no divergent
/// usable contacts, no surviving journal, and a side that journaled has
/// burned the offer.
#[test]
fn crash_at_every_point_burns_the_offer_once_journaled() -> TestResult {
    let steps = honest_record_count()? + 1;
    let mut seen = std::collections::BTreeSet::new();
    for crash_after in 0..=steps {
        for victim in [Role::Initiator, Role::Responder] {
            let mut p = CodePairing::new()?;
            let right = HumanCode::parse(p.shown.as_str())?;
            let mut journaled = (false, false);
            code_run(&mut p, &right, true, |harness| {
                let mut taken = 0;
                while taken < crash_after {
                    if harness.deliver(true) || harness.deliver(false) {
                        taken += 1;
                    } else if matches!(&harness.responder.stage, Stage::Establish(e) if e.phase() == Phase::AckPending)
                    {
                        harness.responder.confirm_ack(harness.now);
                        taken += 1;
                    } else {
                        break;
                    }
                    journaled.0 |= side_journaled(&harness.initiator.stage, Role::Initiator);
                    journaled.1 |= side_journaled(&harness.responder.stage, Role::Responder);
                }
                match victim {
                    Role::Initiator => harness.initiator.crash(),
                    Role::Responder => harness.responder.crash(),
                }
                harness.drain();
                harness.responder.confirm_ack(harness.now);
                harness.drain();
                journaled.0 |= side_journaled(&harness.initiator.stage, Role::Initiator);
                journaled.1 |= side_journaled(&harness.responder.stage, Role::Responder);
            })?;
            seen.insert(journaled);
            let label = format!("crash {victim:?} after {crash_after}");
            let entrant = reopen(&p.entrant_store)?;
            let displayer = reopen(&p.displayer_store)?;
            let a = view(&entrant, &p.displayer.key())?;
            let b = view(&displayer, &p.entrant.key())?;
            if let (Some(a), Some(b)) = (a, b) {
                assert_eq!(a, b, "{label}: divergent");
            }
            for (store, peer) in [(&entrant, p.displayer.key()), (&displayer, p.entrant.key())] {
                assert!(!store.pairing_pending(), "{label}");
                if let Some(contact) = store.contact(&peer) {
                    assert!(!contact.ratchet_pending(), "{label}");
                    assert_eq!(contact.generation(), 1, "{label}");
                    assert_eq!(contact.origin(), TrustOrigin::CodePairing, "{label}");
                }
            }
            let id = p.offer.pairing_id();
            assert_eq!(entrant.pairing_burned(id), journaled.0, "{label}");
            assert_eq!(displayer.pairing_burned(id), journaled.1, "{label}");
            if journaled.1 {
                assert_eq!(p.offers.failures(id), None, "{label}: offer not burned");
            }
        }
    }
    assert_eq!(
        seen.into_iter().collect::<Vec<_>>(),
        [(false, false), (true, false), (true, true)]
    );
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum WireOp {
    Deliver(bool),
    Flip(bool),
    Drop(bool),
    Duplicate(bool),
    Crash(bool),
}

fn wire_op() -> impl Strategy<Value = WireOp> {
    prop_oneof![
        8 => any::<bool>().prop_map(WireOp::Deliver),
        1 => any::<bool>().prop_map(WireOp::Flip),
        1 => any::<bool>().prop_map(WireOp::Drop),
        1 => any::<bool>().prop_map(WireOp::Duplicate),
        1 => any::<bool>().prop_map(WireOp::Crash),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(32))]

    /// The code-pairing flow under an adversarial wire with crashes and an
    /// optionally wrong code: after a restart, contacts never diverge,
    /// journals never survive, a side that journaled has burned the offer,
    /// a wrong code never pairs, and an attempt that did not reach the
    /// displayer's journal costs exactly one failure on the offer.
    #[test]
    fn code_pairing_flow_state_machine(
        ops in proptest::collection::vec(wire_op(), 1..48),
        wrong in any::<bool>(),
    ) {
        let fail = |error: &dyn std::fmt::Display| TestCaseError::fail(error.to_string());
        let mut p = CodePairing::new().map_err(|e| fail(&*e))?;
        let entered = if wrong { p.wrong_code() } else { HumanCode::parse(p.shown.as_str()).map_err(Into::into) }
            .map_err(|e| fail(&*e))?;
        let mut journaled = (false, false);
        let result = code_run(&mut p, &entered, false, |harness| {
            for op in &ops {
                match *op {
                    WireOp::Deliver(to_responder) => {
                        harness.deliver(to_responder);
                    }
                    WireOp::Flip(to_responder) => {
                        if let Some(mut record) = harness.queue(to_responder).pop_front() {
                            let last = record.len() - 1;
                            record[last] ^= 0x80;
                            harness.deliver_bytes(to_responder, &record);
                        }
                    }
                    WireOp::Drop(to_responder) => {
                        harness.queue(to_responder).pop_front();
                    }
                    WireOp::Duplicate(to_responder) => {
                        if let Some(record) = harness.queue(to_responder).front().cloned() {
                            harness.deliver_bytes(to_responder, &record);
                        }
                    }
                    WireOp::Crash(initiator) => {
                        if initiator {
                            harness.initiator.crash();
                        } else {
                            harness.responder.crash();
                        }
                    }
                }
                journaled.0 |= side_journaled(&harness.initiator.stage, Role::Initiator);
                journaled.1 |= side_journaled(&harness.responder.stage, Role::Responder);
            }
        }).map_err(|e| fail(&*e))?;
        if wrong {
            prop_assert!(result.scanner_open.is_none() && result.displayer_open.is_none());
            prop_assert!(!journaled.0 && !journaled.1);
        }
        let entrant = reopen(&p.entrant_store).map_err(|e| fail(&*e))?;
        let displayer = reopen(&p.displayer_store).map_err(|e| fail(&*e))?;
        let a = view(&entrant, &p.displayer.key()).map_err(|e| fail(&*e))?;
        let b = view(&displayer, &p.entrant.key()).map_err(|e| fail(&*e))?;
        if let (Some(a), Some(b)) = (a, b) {
            prop_assert_eq!(a, b);
        }
        for store in [&entrant, &displayer] {
            prop_assert!(!store.pairing_pending());
        }
        let id = p.offer.pairing_id();
        prop_assert_eq!(entrant.pairing_burned(id), journaled.0);
        prop_assert_eq!(displayer.pairing_burned(id), journaled.1);
        if !journaled.1 {
            prop_assert_eq!(p.offers.failures(id), Some(1));
        }
    }
}
