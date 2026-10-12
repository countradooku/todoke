//! End-to-end QR pairing over the sans-IO session harness: contact
//! creation, replay, expiry, active attackers on the wire, and crashes at
//! every point of the transaction. Code pairing reuses these helpers in
//! `code_tests`.

use core::time::Duration;

use proptest::prelude::*;
use todoke_proto::session::{Hello, SessionMode};
use todoke_proto::time::UnixTime;

use super::*;
use crate::identity::contacts::PairOutcome;
use crate::identity::test_support::{T0, request};
use crate::identity::{
    Ed25519PublicKey, IdentityError, TrustOrigin, VerificationState, issue_device_binding,
};
use crate::session::establish::Phase;
use crate::session::tests::support::{
    AnyResult, Device, Harness, Side, Stage, Store, TestResult, WALL, reopen, usable,
};
use crate::session::{LocalIdentity, PairingPsk, ResponderPlan, Role, SessionError, WallClock};

/// Monotonic time at which offers are created.
pub(super) const MONO: Duration = Duration::from_secs(5_000);
/// The client nonce the harness's initiator uses.
pub(super) const CLIENT_NONCE: [u8; 16] = [0xc1; 16];

pub(super) fn wall() -> AnyResult<UnixTime> {
    Ok(UnixTime::new(WALL).ok_or("time")?)
}

pub(super) fn empty_store() -> AnyResult<Store> {
    Ok(crate::identity::ContactStore::open(
        crate::identity::test_support::sealer(9),
        crate::identity::MemoryStorage::new(),
    )?)
}

/// A scanner (Alice) and a displayer (Bob) with empty contact stores and
/// one QR offer from Bob.
struct Pairing {
    scanner: Device,
    displayer: Device,
    scanner_store: Store,
    displayer_store: Store,
    offers: PairingOffers,
    payload: QrPayload,
}

impl Pairing {
    fn new() -> AnyResult<Self> {
        let scanner = Device::new()?;
        let displayer = Device::new()?;
        let offers = PairingOffers::new();
        let shown = offers.create_qr(&displayer.local()?, wall()?, MONO)?;
        // What the scanner's camera reads.
        let payload = QrPayload::from_text(&shown.to_text(), wall()?)?;
        Ok(Self {
            scanner,
            displayer,
            scanner_store: empty_store()?,
            displayer_store: empty_store()?,
            offers,
            payload,
        })
    }

    fn hello(&self) -> AnyResult<Hello> {
        Ok(Hello::client(
            SessionMode::Qr,
            0,
            *self.payload.pairing_id(),
            CLIENT_NONCE,
        )?)
    }
}

pub(super) type Auth<'a> =
    PairingAuthority<'a, crate::identity::SoftwareSealer, crate::identity::MemoryStorage>;

/// The handshake hash each side opened with, and each authority's outcome.
#[derive(Debug, Default)]
pub(super) struct RunResult {
    pub(super) scanner_open: Option<[u8; 32]>,
    pub(super) displayer_open: Option<[u8; 32]>,
    pub(super) displayer_error: Option<SessionError>,
    pub(super) scanner_outcome: Option<PairOutcome>,
    pub(super) displayer_outcome: Option<PairOutcome>,
}

/// Runs one QR pairing attempt: the scanner begins from its payload, the
/// displayer reserves its offer for the scanner's Hello, and `run` drives
/// the wire.
fn qr_run(
    p: &mut Pairing,
    defer_ack: bool,
    run: impl FnOnce(&mut Harness<'_, Auth<'_>, Auth<'_>>),
) -> AnyResult<RunResult> {
    let scanner_local = p.scanner.local()?;
    let displayer_local = p.displayer.local()?;
    let hello = p.hello()?;
    let (plan, scanner_authority) = p.scanner_store.begin_qr_pairing(&p.payload, wall()?)?;
    let reservation = p.offers.reserve(&hello, wall()?, MONO)?;
    let (responder_plan, displayer_authority) =
        reservation.into_qr_responder(&mut p.displayer_store)?;
    let initiator = Side::initiator(scanner_local, scanner_authority);
    let mut responder = Side::responder(displayer_local, displayer_authority, responder_plan);
    responder.defer_ack = defer_ack;
    let mut harness = Harness::new(initiator, responder, plan)?;
    run(&mut harness);
    Ok(finish(&mut harness))
}

/// Ends a run: deadlines fire on anything unfinished; collects the result.
pub(super) fn finish(harness: &mut Harness<'_, Auth<'_>, Auth<'_>>) -> RunResult {
    harness.finish();
    let hash = |core: Option<&mut crate::session::transport::SessionCore>| {
        core.map(|core| core.info().handshake_hash)
    };
    RunResult {
        scanner_open: hash(harness.initiator.core()),
        displayer_open: hash(harness.responder.core()),
        displayer_error: harness.responder.error(),
        scanner_outcome: harness.initiator.authority.outcome(),
        displayer_outcome: harness.responder.authority.outcome(),
    }
}

pub(super) fn drain(harness: &mut Harness<'_, Auth<'_>, Auth<'_>>) {
    harness.drain();
}

/// `(generation, psk)` of `peer` in `store`, if usable now.
pub(super) fn view(store: &Store, peer: &Ed25519PublicKey) -> AnyResult<Option<(u64, [u8; 32])>> {
    match store.contact(peer) {
        None => Ok(None),
        Some(_) => usable(store, peer),
    }
}

#[test]
fn qr_pairing_creates_matching_contacts_on_both_sides() -> TestResult {
    let mut p = Pairing::new()?;
    let result = qr_run(&mut p, false, drain)?;
    let hash = result.scanner_open.ok_or("scanner not open")?;
    assert_eq!(result.displayer_open, Some(hash));
    assert_eq!(result.scanner_outcome, Some(PairOutcome::New));
    assert_eq!(result.displayer_outcome, Some(PairOutcome::New));
    let scanner_view = view(&p.scanner_store, &p.displayer.key())?.ok_or("scanner")?;
    let displayer_view = view(&p.displayer_store, &p.scanner.key())?.ok_or("displayer")?;
    assert_eq!(scanner_view, displayer_view);
    assert_eq!(scanner_view.0, 1);
    let expected = crate::session::kdf::psk_next(&hash, p.payload.psk()).map_err(|_| "kdf")?;
    assert_eq!(scanner_view.1, *expected);
    // The QR PSK itself is never stored.
    assert_ne!(scanner_view.1, **p.payload.psk());
    for (store, peer) in [
        (&p.scanner_store, p.displayer.key()),
        (&p.displayer_store, p.scanner.key()),
    ] {
        let contact = store.contact(&peer).ok_or("contact")?;
        assert_eq!(contact.origin(), TrustOrigin::QrPairing);
        assert_eq!(contact.state(), VerificationState::Verified);
        assert!(store.pairing_burned(p.payload.pairing_id()));
        // Durable as well.
        let durable = reopen(store)?;
        assert_eq!(view(&durable, &peer)?, Some(scanner_view));
    }
    // The scanner pinned exactly the displayer's keys from the QR.
    let pinned = p
        .scanner_store
        .contact(&p.displayer.key())
        .ok_or("contact")?
        .pinned();
    assert_eq!(pinned.device_public(), p.payload.device_public());
    assert_eq!(pinned.noise_static(), p.payload.noise_static());
    assert_eq!(pinned.kem_static(), p.payload.kem_static());
    assert_eq!(p.offers.live(OfferKind::Qr, wall()?, MONO), 0);
    Ok(())
}

#[test]
fn paired_devices_then_run_a_contact_session() -> TestResult {
    let mut p = Pairing::new()?;
    qr_run(&mut p, false, drain)?;
    let initiator_authority = p.scanner_store.session_authority(&p.displayer.key())?;
    let plan = initiator_authority.initiator_plan([0xb7; 16])?;
    let responder_authority = p.displayer_store.session_authority(&p.scanner.key())?;
    let hello = Hello::client(SessionMode::Contact, 1, [0xb7; 16], CLIENT_NONCE)?;
    let responder_plan = responder_authority.responder_plan(&hello)?;
    let mut harness = Harness::new(
        Side::initiator(p.scanner.local()?, initiator_authority),
        Side::responder(p.displayer.local()?, responder_authority, responder_plan),
        plan,
    )?;
    harness.drain();
    assert!(harness.initiator.is_open() && harness.responder.is_open());
    drop(harness);
    let scanner = view(&p.scanner_store, &p.displayer.key())?.ok_or("scanner")?;
    let displayer = view(&p.displayer_store, &p.scanner.key())?.ok_or("displayer")?;
    assert_eq!(scanner, displayer);
    assert_eq!(scanner.0, 2);
    Ok(())
}

#[test]
fn replayed_qr_is_refused_on_both_sides_including_after_restart() -> TestResult {
    let mut p = Pairing::new()?;
    qr_run(&mut p, false, drain)?;
    // The scanner refuses to use the same QR again, before and after a
    // restart.
    assert_eq!(
        p.scanner_store.begin_qr_pairing(&p.payload, wall()?).err(),
        Some(PairingError::Burned)
    );
    let mut restarted = reopen(&p.scanner_store)?;
    assert_eq!(
        restarted.begin_qr_pairing(&p.payload, wall()?).err(),
        Some(PairingError::Burned)
    );
    // The displayer's offer is gone, and a restarted displayer has none.
    assert_eq!(
        p.offers.reserve(&p.hello()?, wall()?, MONO).err(),
        Some(PairingError::UnknownOffer)
    );
    assert_eq!(
        PairingOffers::new()
            .reserve(&p.hello()?, wall()?, MONO)
            .err(),
        Some(PairingError::UnknownOffer)
    );
    // A fresh scanner store still cannot get past the displayer: the
    // offer was burned, so the attempt never starts.
    p.scanner_store = empty_store()?;
    let error = qr_run(&mut p, false, drain).err();
    assert_eq!(
        error.map(|error| error.to_string()),
        Some(PairingError::UnknownOffer.to_string())
    );
    Ok(())
}

#[test]
fn expired_qr_is_refused_everywhere() -> TestResult {
    let mut p = Pairing::new()?;
    let expires = p.payload.expires_at().seconds();
    let skew = crate::identity::CLOCK_SKEW_SECONDS;
    let at = |seconds: u64| UnixTime::new(seconds).ok_or("time");
    // Scanner: decoding and beginning use the §1 skew.
    let text = {
        let shown = p.offers.create_qr(&p.displayer.local()?, wall()?, MONO)?;
        shown.to_text()
    };
    assert_eq!(
        QrPayload::from_text(&text, at(expires + skew)?).err(),
        Some(QrError::Expired)
    );
    assert_eq!(
        p.scanner_store
            .begin_qr_pairing(&p.payload, at(expires + skew)?)
            .err(),
        Some(PairingError::Qr(QrError::Expired))
    );
    // Displayer: its own clock, no skew.
    assert_eq!(
        p.offers.reserve(&p.hello()?, at(expires)?, MONO).err(),
        Some(PairingError::Expired)
    );
    Ok(())
}

#[test]
fn an_offer_that_expires_during_the_attempt_fails_before_any_journal() -> TestResult {
    let mut p = Pairing::new()?;
    let expires = p.payload.expires_at();
    let result = qr_run(&mut p, false, |harness| {
        // The displayer's clock is at the expiry by the time the peer's
        // Identity arrives.
        harness.responder.wall = WallClock::new(expires, harness.now);
        harness.drain();
    })?;
    assert_eq!(
        result.displayer_error,
        Some(SessionError::Pairing(PairingError::Expired))
    );
    assert!(result.scanner_open.is_none());
    assert!(!p.displayer_store.pairing_burned(p.payload.pairing_id()));
    assert!(!p.scanner_store.pairing_burned(p.payload.pairing_id()));
    Ok(())
}

/// The displayer's sealed blob (`None` before the first write).
fn blob(store: &Store) -> Option<Vec<u8>> {
    store.storage().blob().map(<[u8]>::to_vec)
}

/// Runs until the displayer has confirmed the scanner's identity but has
/// not journaled yet.
fn until_displayer_confirmed(harness: &mut Harness<'_, Auth<'_>, Auth<'_>>) {
    while !matches!(&harness.responder.stage, Stage::Establish(e) if e.phase() == Phase::AwaitReady)
    {
        if !(harness.deliver(true) || harness.deliver(false)) {
            break;
        }
    }
}

/// The displayer withdraws its offers (closes the pairing screen) while an
/// attempt is in flight, before or after it confirmed the scanner's
/// identity: the attempt stops before the displayer journals anything, no
/// contact is created, and the displayer's store is unchanged.
#[test]
fn a_withdrawn_offer_stops_an_attempt_in_flight() -> TestResult {
    for confirmed in [false, true] {
        let mut p = Pairing::new()?;
        let offers = p.offers.clone();
        let id = *p.payload.pairing_id();
        let before = blob(&p.displayer_store);
        let mut was_confirmed = false;
        let result = qr_run(&mut p, false, |harness| {
            if confirmed {
                until_displayer_confirmed(harness);
                was_confirmed = matches!(&harness.responder.stage, Stage::Establish(e) if e.phase() == Phase::AwaitReady);
            }
            offers.cancel_all();
            harness.drain();
        })?;
        let label = format!("confirmed {confirmed}");
        assert_eq!(was_confirmed, confirmed, "{label}");
        assert!(result.displayer_open.is_none(), "{label}");
        assert!(result.scanner_open.is_none(), "{label}");
        assert_eq!(
            result.displayer_error,
            Some(SessionError::Pairing(PairingError::UnknownOffer)),
            "{label}"
        );
        assert_eq!(result.displayer_outcome, None, "{label}");
        assert_eq!(result.scanner_outcome, None, "{label}");
        assert!(
            p.displayer_store.contact(&p.scanner.key()).is_none(),
            "{label}"
        );
        assert!(
            p.scanner_store.contact(&p.displayer.key()).is_none(),
            "{label}"
        );
        assert!(!p.displayer_store.pairing_pending(), "{label}");
        assert!(!p.displayer_store.pairing_burned(&id), "{label}");
        assert_eq!(blob(&p.displayer_store), before, "{label}");
        assert_eq!(p.offers.active_attempts(), 0, "{label}");
    }
    Ok(())
}

/// Mallory answers the scanner in place of the displayer, with her own
/// device keys, either guessing the PSK or knowing it (she saw the QR).
#[test]
fn a_man_in_the_middle_cannot_impersonate_the_displayer() -> TestResult {
    for knows_psk in [false, true] {
        let mut p = Pairing::new()?;
        let mallory = Device::new()?;
        let mut mallory_store = empty_store()?;
        let mallory_offers = PairingOffers::new();
        // Mallory's own offer under the scanner's pairing ID is impossible
        // (IDs are random), so she answers with a plan of her own.
        let psk = if knows_psk {
            p.payload.psk().clone()
        } else {
            zeroize::Zeroizing::new([0x99; 32])
        };
        let mallory_payload = mallory_offers.create_qr(&mallory.local()?, wall()?, MONO)?;
        let reservation = mallory_offers.reserve(
            &Hello::client(
                SessionMode::Qr,
                0,
                *mallory_payload.pairing_id(),
                CLIENT_NONCE,
            )?,
            wall()?,
            MONO,
        )?;
        let (_, mallory_authority) = reservation.into_qr_responder(&mut mallory_store)?;
        let (plan, scanner_authority) = p.scanner_store.begin_qr_pairing(&p.payload, wall()?)?;
        let mut harness = Harness::new(
            Side::initiator(p.scanner.local()?, scanner_authority),
            Side::responder(
                mallory.local()?,
                mallory_authority,
                ResponderPlan::qr(PairingPsk::from_bytes(psk)),
            ),
            plan,
        )?;
        harness.drain();
        harness.finish();
        assert!(!harness.initiator.is_open(), "knows_psk {knows_psk}");
        assert!(!harness.responder.is_open(), "knows_psk {knows_psk}");
        drop(harness);
        // Nothing was journaled: the scanner may still use the real QR.
        assert!(!p.scanner_store.pairing_burned(p.payload.pairing_id()));
        assert!(p.scanner_store.contact(&mallory.key()).is_none());
        assert!(mallory_store.contact(&p.scanner.key()).is_none());
        let honest = qr_run(&mut p, false, drain)?;
        assert!(honest.scanner_open.is_some() && honest.displayer_open.is_some());
    }
    Ok(())
}

/// Mallory relays every record but alters one of them. Before the journal
/// the attempt fails and consumes nothing: the same QR then pairs. After
/// the journal both sides fail closed and the QR is burned.
#[test]
fn a_relay_that_alters_any_record_fails_and_never_pairs_divergently() -> TestResult {
    let steps = honest_record_count()?;
    for target in 0..steps {
        let mut p = Pairing::new()?;
        let mut journaled = false;
        let result = qr_run(&mut p, false, |harness| {
            let mut index = 0;
            loop {
                let to_responder = !harness.to_responder.is_empty();
                let Some(mut record) = harness.queue(to_responder).pop_front() else {
                    break;
                };
                if index == target {
                    // Flip a bit near the end: inside every record's body.
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
            "{label}: both opened"
        );
        let scanner_view = view(&reopen(&p.scanner_store)?, &p.displayer.key())?;
        let displayer_view = view(&reopen(&p.displayer_store)?, &p.scanner.key())?;
        if let (Some(a), Some(b)) = (scanner_view, displayer_view) {
            assert_eq!(a, b, "{label}: divergent");
        }
        let burned = p.scanner_store.pairing_burned(p.payload.pairing_id())
            || p.displayer_store.pairing_burned(p.payload.pairing_id());
        if burned {
            assert!(journaled, "{label}: burned without a journal");
        } else {
            // Unauthenticated failures consume neither side's offer.
            let retry = qr_run(&mut p, false, drain)?;
            assert!(
                retry.scanner_open.is_some() && retry.displayer_open.is_some(),
                "{label}: retry failed"
            );
        }
    }
    Ok(())
}

fn honest_record_count() -> AnyResult<usize> {
    let mut p = Pairing::new()?;
    let mut count = 0;
    qr_run(&mut p, false, |harness| {
        loop {
            if harness.deliver(true) || harness.deliver(false) {
                count += 1;
            } else {
                break;
            }
        }
    })?;
    Ok(count)
}

/// The displayer presents a binding certifying a different ML-KEM
/// credential than its QR: the scanner refuses before any journal (§3.1
/// pins all three keys).
#[test]
fn a_binding_that_differs_from_the_qr_keys_is_refused() -> TestResult {
    let mut p = Pairing::new()?;
    let mut other = request(0x33, 0x45, 2, T0, T0 + 30 * 86_400)?;
    other.noise_static = *p.displayer.noise.public_key();
    let enrolled = &p.displayer.enrolled;
    let swapped = issue_device_binding(&enrolled.store, &enrolled.root, &enrolled.device, other)?;
    let swapped_local = LocalIdentity::new(
        &enrolled.store,
        enrolled.device,
        &swapped,
        &p.displayer.noise,
        wall()?,
    )?;
    let hello = p.hello()?;
    let (plan, scanner_authority) = p.scanner_store.begin_qr_pairing(&p.payload, wall()?)?;
    let reservation = p.offers.reserve(&hello, wall()?, MONO)?;
    let (responder_plan, displayer_authority) =
        reservation.into_qr_responder(&mut p.displayer_store)?;
    let mut harness = Harness::new(
        Side::initiator(p.scanner.local()?, scanner_authority),
        Side::responder(swapped_local, displayer_authority, responder_plan),
        plan,
    )?;
    harness.drain();
    harness.finish();
    assert_eq!(
        harness.initiator.error(),
        Some(SessionError::Identity(IdentityError::AuthenticationFailed))
    );
    assert!(!harness.responder.is_open());
    drop(harness);
    assert!(!p.scanner_store.pairing_burned(p.payload.pairing_id()));
    assert!(p.scanner_store.contact(&p.displayer.key()).is_none());
    Ok(())
}

/// Crash either side after every prefix of the honest run, let the other
/// time out, restart both, and check: no divergent usable contacts, a
/// journal never survives a restart, every side that journaled has burned
/// the QR, and a QR that neither side journaled is still usable.
#[test]
fn crash_at_every_point_burns_the_offer_once_journaled() -> TestResult {
    let steps = honest_record_count()? + 1;
    let mut seen = std::collections::BTreeSet::new();
    for crash_after in 0..=steps {
        for victim in [Role::Initiator, Role::Responder] {
            let mut p = Pairing::new()?;
            let mut journaled = (false, false);
            qr_run(&mut p, true, |harness| {
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
            let label = format!("crash {victim:?} after {crash_after}");
            seen.insert(journaled);
            let scanner = reopen(&p.scanner_store)?;
            let displayer = reopen(&p.displayer_store)?;
            let a = view(&scanner, &p.displayer.key())?;
            let b = view(&displayer, &p.scanner.key())?;
            if let (Some(a), Some(b)) = (a, b) {
                assert_eq!(a, b, "{label}: divergent");
            }
            for (store, peer) in [(&scanner, p.displayer.key()), (&displayer, p.scanner.key())] {
                assert!(!store.pairing_pending(), "{label}");
                if let Some(contact) = store.contact(&peer) {
                    assert!(!contact.ratchet_pending(), "{label}");
                    assert_eq!(contact.generation(), 1, "{label}");
                }
            }
            let id = p.payload.pairing_id();
            assert_eq!(scanner.pairing_burned(id), journaled.0, "{label}: scanner");
            assert_eq!(
                displayer.pairing_burned(id),
                journaled.1,
                "{label}: displayer"
            );
            if !journaled.0 && !journaled.1 {
                // Restarted displayer has no offers; a still-running one
                // (the scanner crashed) keeps its unconsumed offer.
                if victim == Role::Initiator {
                    p.scanner_store = scanner;
                    let retry = qr_run(&mut p, false, drain)?;
                    assert!(retry.scanner_open.is_some(), "{label}: retry");
                }
            } else {
                let mut scanner = scanner;
                assert_eq!(
                    scanner.begin_qr_pairing(&p.payload, wall()?).err(),
                    if journaled.0 {
                        Some(PairingError::Burned)
                    } else {
                        None
                    },
                    "{label}"
                );
            }
        }
    }
    // Crashes before any journal, after only the scanner's, and after both.
    assert_eq!(
        seen.into_iter().collect::<Vec<_>>(),
        [(false, false), (true, false), (true, true)]
    );
    Ok(())
}

/// Whether a side has passed its §4.4 journal step.
pub(super) fn side_journaled(stage: &Stage, role: Role) -> bool {
    match stage {
        Stage::Establish(establishment) => match role {
            Role::Initiator => !matches!(establishment.phase(), Phase::AwaitIdentity),
            Role::Responder => !matches!(
                establishment.phase(),
                Phase::AwaitIdentity | Phase::AwaitReady
            ),
        },
        Stage::Open(_) => true,
        _ => false,
    }
}

/// A full burned ledger refuses the journal before changing anything: an
/// existing contact for the same device stays usable, and the QR is not
/// burned (nothing was journaled).
#[test]
fn a_full_ledger_refuses_the_journal_without_side_effects() -> TestResult {
    let mut p = Pairing::new()?;
    // Bob is already a contact of Alice, and Alice's ledger is full.
    let mut old = qr_run(&mut p, false, drain)?;
    assert!(old.scanner_open.take().is_some());
    let before = view(&p.scanner_store, &p.displayer.key())?.ok_or("contact")?;
    let filler = Device::new()?;
    for index in 0..crate::identity::contacts::MAX_BURNED_PAIRINGS - 1 {
        let mut id = [0xb0; 16];
        id[15] = u8::try_from(index)?;
        p.scanner_store.journal_pairing(
            &crate::identity::contacts::PairingJournal {
                pairing_id: id,
                expires_at: wall()?,
                origin: TrustOrigin::QrPairing,
                peer: &filler.binding,
                handshake_hash: &[1; 32],
                psk_next: &[2; 32],
            },
            wall()?,
        )?;
        p.scanner_store.abandon_pairing(&id, &filler.key())?;
    }
    // A fresh QR from Bob.
    let shown = p.offers.create_qr(&p.displayer.local()?, wall()?, MONO)?;
    p.payload = QrPayload::from_text(&shown.to_text(), wall()?)?;
    let result = qr_run(&mut p, false, drain)?;
    assert!(result.scanner_open.is_none() && result.displayer_open.is_none());
    assert_eq!(view(&p.scanner_store, &p.displayer.key())?, Some(before));
    assert!(!p.scanner_store.pairing_burned(p.payload.pairing_id()));
    Ok(())
}

#[test]
fn errors_and_debug_output() -> TestResult {
    let mut p = Pairing::new()?;
    let (_, authority) = p.scanner_store.begin_qr_pairing(&p.payload, wall()?)?;
    let debug = format!("{authority:?}");
    assert!(debug.starts_with("PairingAuthority { mode: Qr, role: \"initiator\", expires_at: "));
    assert!(debug.ends_with("outcome: None, .. }"));
    assert_eq!(authority.mode(), SessionMode::Qr);
    drop(authority);
    let messages: Vec<String> = [
        PairingError::Qr(QrError::Expired),
        PairingError::UnknownOffer,
        PairingError::Expired,
        PairingError::Mode,
        PairingError::OfferBusy,
        PairingError::TooSoon,
        PairingError::RateLimited,
        PairingError::TooManyOffers,
        PairingError::Burned,
        PairingError::PairingInProgress,
        PairingError::LocalIdentity,
        PairingError::Random,
        PairingError::Unavailable,
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    crate::identity::test_support::assert_distinct_messages(&messages);
    assert_eq!(
        PairingError::from(QrError::Length),
        PairingError::Qr(QrError::Length)
    );
    assert_eq!(
        SessionError::Pairing(PairingError::Burned).to_string(),
        "pairing refused: pairing offer already used; create a new one"
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
    #![proptest_config(ProptestConfig::with_cases(48))]

    /// The pairing flow under an adversarial wire with crashes: after a
    /// restart of both sides, contacts never diverge, journals never
    /// survive, generation is 1, a side that journaled has burned the QR,
    /// and a side that did not can pair again with a fresh offer.
    #[test]
    fn pairing_flow_state_machine(ops in proptest::collection::vec(wire_op(), 1..40)) {
        let fail = |error: &dyn std::fmt::Display| TestCaseError::fail(error.to_string());
        let mut p = Pairing::new().map_err(|e| fail(&*e))?;
        let mut journaled = (false, false);
        qr_run(&mut p, false, |harness| {
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
        let scanner = reopen(&p.scanner_store).map_err(|e| fail(&*e))?;
        let displayer = reopen(&p.displayer_store).map_err(|e| fail(&*e))?;
        let a = view(&scanner, &p.displayer.key()).map_err(|e| fail(&*e))?;
        let b = view(&displayer, &p.scanner.key()).map_err(|e| fail(&*e))?;
        if let (Some(a), Some(b)) = (a, b) {
            prop_assert_eq!(a, b);
        }
        for (store, peer) in [(&scanner, p.displayer.key()), (&displayer, p.scanner.key())] {
            prop_assert!(!store.pairing_pending());
            if let Some(contact) = store.contact(&peer) {
                prop_assert!(!contact.ratchet_pending());
                prop_assert_eq!(contact.generation(), 1);
            }
        }
        let id = p.payload.pairing_id();
        prop_assert_eq!(scanner.pairing_burned(id), journaled.0);
        prop_assert_eq!(displayer.pairing_burned(id), journaled.1);
    }
}
