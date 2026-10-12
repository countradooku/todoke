use std::collections::BTreeMap;

use proptest::prelude::*;
use todoke_proto::session::Hello;

use super::*;
use crate::identity::test_support::T0;
use crate::pairing::QrPayload;
use crate::session::tests::support::{AnyResult, Device, TestResult};

const MONO: Duration = Duration::from_secs(1_000);
const CODE_GATE: UnauditedCodePairing = UnauditedCodePairing::acknowledge_not_production_ready();

fn now() -> AnyResult<UnixTime> {
    Ok(UnixTime::new(T0 + 60).ok_or("time")?)
}

fn later(seconds: u64) -> AnyResult<UnixTime> {
    Ok(UnixTime::new(T0 + 60 + seconds).ok_or("time")?)
}

fn hello(mode: SessionMode, pairing_id: [u8; 16]) -> AnyResult<Hello> {
    Ok(Hello::client(mode, 0, pairing_id, [0xc1; 16])?)
}

fn qr_offer(offers: &PairingOffers, device: &Device) -> AnyResult<QrPayload> {
    Ok(offers.create_qr(&device.local()?, now()?, MONO)?)
}

#[test]
fn qr_offers_carry_the_local_keys_and_round_trip() -> TestResult {
    let device = Device::new()?;
    let offers = PairingOffers::new();
    let payload = qr_offer(&offers, &device)?;
    assert_eq!(payload.device_public(), device.binding.device_public());
    assert_eq!(payload.noise_static(), device.noise.public_key());
    assert_eq!(payload.kem_static(), device.binding.kem_static());
    assert_eq!(
        payload.expires_at().seconds(),
        now()?.seconds() + OFFER_LIFETIME_SECONDS
    );
    assert_ne!(payload.pairing_id(), &[0; 16]);
    let scanned = QrPayload::from_text(&payload.to_text(), now()?)?;
    assert_eq!(scanned.encode(), payload.encode());
    assert_eq!(offers.live(OfferKind::Qr, now()?, MONO), 1);
    assert_eq!(offers.live(OfferKind::Code, now()?, MONO), 0);
    // Two offers never share an ID or PSK.
    let other = qr_offer(&offers, &device)?;
    assert_ne!(other.pairing_id(), payload.pairing_id());
    assert_ne!(other.psk().as_slice(), payload.psk().as_slice());
    Ok(())
}

#[test]
fn qr_offer_requires_a_valid_local_binding() -> TestResult {
    let device = Device::valid_until(T0 + 120)?;
    let offers = PairingOffers::new();
    let local = device.local_at(T0 + 60)?;
    let late = UnixTime::new(T0 + 120 + 121).ok_or("time")?;
    assert_eq!(
        offers.create_qr(&local, late, MONO).err(),
        Some(PairingError::LocalIdentity)
    );
    Ok(())
}

#[test]
fn reservations_are_exclusive_and_qr_failures_do_not_consume() -> TestResult {
    let device = Device::new()?;
    let offers = PairingOffers::new();
    let payload = qr_offer(&offers, &device)?;
    let id = *payload.pairing_id();
    let first = offers.reserve(&hello(SessionMode::Qr, id)?, now()?, MONO)?;
    assert_eq!(first.kind(), OfferKind::Qr);
    assert_eq!(first.pairing_id(), &id);
    assert_eq!(first.expires_at(), payload.expires_at());
    assert_eq!(offers.active_attempts(), 1);
    assert_eq!(
        offers
            .reserve(&hello(SessionMode::Qr, id)?, now()?, MONO)
            .err(),
        Some(PairingError::OfferBusy)
    );
    drop(first);
    assert_eq!(offers.active_attempts(), 0);
    // Any number of failed attempts leave a QR offer usable.
    for _ in 0..10 {
        drop(offers.reserve(&hello(SessionMode::Qr, id)?, now()?, MONO)?);
    }
    assert_eq!(offers.failures(&id), Some(0));
    let mut burned = offers.reserve(&hello(SessionMode::Qr, id)?, now()?, MONO)?;
    burned.authenticated();
    assert_eq!(offers.active_attempts(), 0);
    assert!(burned.still_offered());
    assert_eq!(burned.burn(), Ok(()));
    assert!(!burned.still_offered());
    // Burning twice is a no-op.
    assert_eq!(burned.burn(), Ok(()));
    drop(burned);
    assert_eq!(
        offers
            .reserve(&hello(SessionMode::Qr, id)?, now()?, MONO)
            .err(),
        Some(PairingError::UnknownOffer)
    );
    Ok(())
}

#[test]
fn reserve_checks_id_mode_and_expiry() -> TestResult {
    let device = Device::new()?;
    let offers = PairingOffers::new();
    let id = *qr_offer(&offers, &device)?.pairing_id();
    assert_eq!(
        offers
            .reserve(&hello(SessionMode::Qr, [0x99; 16])?, now()?, MONO)
            .err(),
        Some(PairingError::UnknownOffer)
    );
    assert_eq!(
        offers
            .reserve(&hello(SessionMode::Code, id)?, now()?, MONO)
            .err(),
        Some(PairingError::Mode)
    );
    let contact = Hello::client(SessionMode::Contact, 3, id, [1; 16])?;
    assert_eq!(
        offers.reserve(&contact, now()?, MONO).err(),
        Some(PairingError::Mode)
    );
    // Wall clock: the offer is valid strictly before its expiry.
    assert!(
        offers
            .reserve(&hello(SessionMode::Qr, id)?, later(299)?, MONO)
            .is_ok()
    );
    assert_eq!(
        offers
            .reserve(&hello(SessionMode::Qr, id)?, later(300)?, MONO)
            .err(),
        Some(PairingError::Expired)
    );
    // Monotonic clock: 300 s after creation even if the wall clock lags.
    let second = *qr_offer(&offers, &device)?.pairing_id();
    assert_eq!(
        offers
            .reserve(
                &hello(SessionMode::Qr, second)?,
                now()?,
                MONO + OFFER_LIFETIME
            )
            .err(),
        Some(PairingError::Expired)
    );
    assert_eq!(offers.live(OfferKind::Qr, now()?, MONO), 0);
    Ok(())
}

#[test]
fn code_offers_count_failures_and_space_attempts() -> TestResult {
    let offers = PairingOffers::new();
    let code = offers.create_code(CODE_GATE, now()?, MONO)?;
    assert_eq!(code.as_str().len(), 10);
    let id = offers.code_pairing_id().ok_or("code offer")?;
    let mut mono = MONO;
    for failure in 1..=MAX_CODE_FAILURES {
        let reservation = offers.reserve(&hello(SessionMode::Code, id)?, now()?, mono)?;
        assert_eq!(reservation.kind(), OfferKind::Code);
        assert_eq!(
            offers
                .reserve(&hello(SessionMode::Code, id)?, now()?, mono)
                .err(),
            Some(PairingError::OfferBusy)
        );
        drop(reservation);
        if failure < MAX_CODE_FAILURES {
            assert_eq!(offers.failures(&id), Some(failure));
            // Less than 2 s after the previous attempt.
            assert_eq!(
                offers
                    .reserve(
                        &hello(SessionMode::Code, id)?,
                        now()?,
                        mono + CODE_ATTEMPT_SPACING.saturating_sub(Duration::from_millis(1))
                    )
                    .err(),
                Some(PairingError::TooSoon)
            );
        }
        mono += CODE_ATTEMPT_SPACING;
    }
    // Exhausted: a new code and local action are required (§3.2).
    assert_eq!(offers.failures(&id), None);
    assert_eq!(
        offers
            .reserve(&hello(SessionMode::Code, id)?, now()?, mono)
            .err(),
        Some(PairingError::UnknownOffer)
    );
    let fresh = offers.create_code(CODE_GATE, now()?, mono)?;
    let fresh_id = offers.code_pairing_id().ok_or("code offer")?;
    assert_ne!(fresh_id, id);
    assert_ne!(fresh.as_str(), "");
    Ok(())
}

#[test]
fn a_new_code_replaces_the_old_one() -> TestResult {
    let offers = PairingOffers::new();
    offers.create_code(CODE_GATE, now()?, MONO)?;
    let first = offers.code_pairing_id().ok_or("first")?;
    // While an attempt holds the code, a new code is refused instead of
    // silently replacing it, and the attempt keeps its offer.
    let held = offers.reserve(&hello(SessionMode::Code, first)?, now()?, MONO)?;
    assert_eq!(
        offers.create_code(CODE_GATE, now()?, MONO).err(),
        Some(PairingError::OfferBusy)
    );
    assert_eq!(offers.code_pairing_id(), Some(first));
    assert!(held.still_offered());
    drop(held);
    assert_eq!(offers.failures(&first), Some(1));
    // Free again: the new code replaces it.
    offers.create_code(CODE_GATE, now()?, MONO)?;
    let second = offers.code_pairing_id().ok_or("second")?;
    assert_ne!(first, second);
    assert_eq!(offers.live(OfferKind::Code, now()?, MONO), 1);
    assert_eq!(
        offers
            .reserve(
                &hello(SessionMode::Code, first)?,
                now()?,
                MONO + CODE_ATTEMPT_SPACING
            )
            .err(),
        Some(PairingError::UnknownOffer)
    );
    // Withdrawing the code stops an attempt on it; a new code may then be
    // shown, and the old attempt can neither burn it nor count against it.
    let mut stale = offers.reserve(
        &hello(SessionMode::Code, second)?,
        now()?,
        MONO + CODE_ATTEMPT_SPACING,
    )?;
    offers.cancel_all();
    offers.create_code(CODE_GATE, now()?, MONO + CODE_ATTEMPT_SPACING)?;
    let third = offers.code_pairing_id().ok_or("third")?;
    assert_ne!(third, second);
    assert!(!stale.still_offered());
    assert_eq!(stale.burn(), Err(PairingError::UnknownOffer));
    drop(stale);
    assert_eq!(offers.failures(&third), Some(0));
    assert_eq!(offers.active_attempts(), 0);
    Ok(())
}

/// §3.2: only a stream that exchanged the offer records may attempt a
/// code offer. Code-mode Hellos without it are refused before anything is
/// checked or counted: any number of them leave the offer's five attempts,
/// its spacing, and the §13 budget untouched.
#[test]
fn code_hellos_without_the_offer_exchange_never_reserve() -> TestResult {
    let offers = PairingOffers::new();
    offers.create_code(CODE_GATE, now()?, MONO)?;
    let id = offers.code_pairing_id().ok_or("code offer")?;
    let bare = hello(SessionMode::Code, id)?;
    for attempt in 0..u32::from(MAX_CODE_FAILURES) * 5 {
        let mono = MONO + CODE_ATTEMPT_SPACING * attempt;
        assert_eq!(
            offers
                .reserve_attempt(&bare, false, &mut None, now()?, mono)
                .err(),
            Some(PairingError::NoOfferExchange)
        );
    }
    // Also for an unknown pairing ID: nothing is looked up.
    assert_eq!(
        offers
            .reserve_attempt(
                &hello(SessionMode::Code, [0x99; 16])?,
                false,
                &mut None,
                now()?,
                MONO
            )
            .err(),
        Some(PairingError::NoOfferExchange)
    );
    assert_eq!(offers.failures(&id), Some(0));
    assert_eq!(offers.active_attempts(), 0);
    // An exchanged stream may still attempt it at once (no spacing used).
    let reservation = offers.reserve_attempt(&bare, true, &mut None, now()?, MONO)?;
    assert_eq!(reservation.kind(), OfferKind::Code);
    // QR attempts never had an exchange to make.
    let device = Device::new()?;
    let qr = *qr_offer(&offers, &device)?.pairing_id();
    assert!(
        offers
            .reserve_attempt(&hello(SessionMode::Qr, qr)?, false, &mut None, now()?, MONO)
            .is_ok()
    );
    Ok(())
}

#[test]
fn code_requests_need_the_advertised_token_and_never_reserve() -> TestResult {
    let offers = PairingOffers::new();
    let request = CodeOfferRequest::new([0x5e; 8])?;
    assert_eq!(
        offers
            .answer_code_request(CODE_GATE, &request, &[0x5e; 8], now()?, MONO)
            .err(),
        Some(PairingError::UnknownOffer)
    );
    offers.create_code(CODE_GATE, now()?, MONO)?;
    let id = offers.code_pairing_id().ok_or("code offer")?;
    assert_eq!(
        offers
            .answer_code_request(CODE_GATE, &request, &[0x5f; 8], now()?, MONO)
            .err(),
        Some(PairingError::UnknownOffer)
    );
    let _held = offers.reserve(&hello(SessionMode::Code, id)?, now()?, MONO)?;
    // Concurrent requests still receive the public offer.
    for _ in 0..3 {
        let offer = offers.answer_code_request(CODE_GATE, &request, &[0x5e; 8], now()?, MONO)?;
        assert_eq!(offer.pairing_id(), &id);
        assert_eq!(offer.stranger_token(), &[0x5e; 8]);
        assert_eq!(
            offer.expires_at().seconds(),
            now()?.seconds() + OFFER_LIFETIME_SECONDS
        );
    }
    assert_eq!(
        offers
            .answer_code_request(CODE_GATE, &request, &[0x5e; 8], later(300)?, MONO)
            .err(),
        Some(PairingError::UnknownOffer)
    );
    Ok(())
}

#[test]
fn global_budget_limits_concurrency_and_rate() -> TestResult {
    let device = Device::new()?;
    let offers = PairingOffers::new();
    let ids: Vec<[u8; 16]> = (0..MAX_OFFERS)
        .map(|_| qr_offer(&offers, &device).map(|payload| *payload.pairing_id()))
        .collect::<Result<_, _>>()?;
    assert_eq!(
        qr_offer(&offers, &device).err().map(|e| e.to_string()),
        Some(PairingError::TooManyOffers.to_string())
    );
    // Four concurrent unauthenticated attempts at most.
    let held: Vec<OfferReservation> = ids
        .iter()
        .map(|id| -> AnyResult<OfferReservation> {
            Ok(offers.reserve(&hello(SessionMode::Qr, *id)?, now()?, MONO)?)
        })
        .collect::<Result<_, _>>()?;
    assert_eq!(offers.active_attempts(), MAX_CONCURRENT_ATTEMPTS);
    drop(held);
    // Twenty starts within one minute at most; four happened at MONO.
    let mut mono = MONO;
    for start in MAX_CONCURRENT_ATTEMPTS..MAX_ATTEMPT_STARTS_PER_MINUTE {
        let id = ids[start % ids.len()];
        drop(offers.reserve(&hello(SessionMode::Qr, id)?, now()?, mono)?);
        mono += Duration::from_millis(100);
    }
    assert_eq!(
        offers
            .reserve(&hello(SessionMode::Qr, ids[0])?, now()?, mono)
            .err(),
        Some(PairingError::RateLimited)
    );
    assert!(
        offers
            .reserve(&hello(SessionMode::Qr, ids[0])?, now()?, MONO + MINUTE * 2)
            .is_ok()
    );
    Ok(())
}

#[test]
fn authenticated_attempts_leave_the_unauthenticated_budget() -> TestResult {
    let device = Device::new()?;
    let offers = PairingOffers::new();
    let ids: Vec<[u8; 16]> = (0..MAX_OFFERS)
        .map(|_| qr_offer(&offers, &device).map(|payload| *payload.pairing_id()))
        .collect::<Result<_, _>>()?;
    let mut first = offers.reserve(&hello(SessionMode::Qr, ids[0])?, now()?, MONO)?;
    first.authenticated();
    first.authenticated();
    assert_eq!(offers.active_attempts(), 0);
    drop(first);
    assert_eq!(offers.active_attempts(), 0);
    Ok(())
}

#[test]
fn cancel_all_withdraws_offers() -> TestResult {
    let device = Device::new()?;
    let offers = PairingOffers::new();
    let id = *qr_offer(&offers, &device)?.pairing_id();
    let other = *qr_offer(&offers, &device)?.pairing_id();
    let mut reservation = offers.reserve(&hello(SessionMode::Qr, id)?, now()?, MONO)?;
    let mut confirmed = offers.reserve(&hello(SessionMode::Qr, other)?, now()?, MONO)?;
    confirmed.authenticated();
    assert!(reservation.still_offered() && confirmed.still_offered());
    offers.cancel_all();
    // Attempts in flight lose their offers: neither can burn it, whether
    // or not the peer was authenticated already.
    assert!(!reservation.still_offered());
    assert!(!confirmed.still_offered());
    assert_eq!(reservation.burn(), Err(PairingError::UnknownOffer));
    assert_eq!(confirmed.burn(), Err(PairingError::UnknownOffer));
    // The unauthenticated attempt holds its §13 slot until it ends.
    assert_eq!(offers.active_attempts(), 1);
    drop(reservation);
    drop(confirmed);
    assert_eq!(offers.active_attempts(), 0);
    assert_eq!(
        offers
            .reserve(&hello(SessionMode::Qr, id)?, now()?, MONO)
            .err(),
        Some(PairingError::UnknownOffer)
    );
    Ok(())
}

#[test]
fn debug_shows_no_secrets() -> TestResult {
    let device = Device::new()?;
    let offers = PairingOffers::new();
    let payload = qr_offer(&offers, &device)?;
    let reservation = offers.reserve(
        &hello(SessionMode::Qr, *payload.pairing_id())?,
        now()?,
        MONO,
    )?;
    assert_eq!(
        format!("{offers:?}"),
        "PairingOffers { offers: 1, active_attempts: 1 }"
    );
    let debug = format!("{reservation:?}");
    assert!(debug.starts_with("OfferReservation { kind: Qr, expires_at: UnixTime("));
    assert!(debug.ends_with("state: Unauthenticated, .. }"));
    Ok(())
}

/// Offer-registry operations, including a process restart.
#[derive(Clone, Debug)]
enum Op {
    CreateQr,
    CreateCode,
    /// Reserve offer number `n` (modulo the offers created so far) in its
    /// own mode, or in the other mode.
    Reserve(usize, bool),
    Authenticate(usize),
    Burn(usize),
    Release(usize),
    /// Withdraw every offer.
    CancelAll,
    /// A code-mode Hello for offer number `n` on a stream without the
    /// offer exchange.
    BareCodeHello(usize),
    /// Let monotonic and wall time pass.
    Advance(u16),
    /// The process restarts: every offer and reservation is gone.
    Restart,
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        2 => Just(Op::CreateQr),
        1 => Just(Op::CreateCode),
        5 => (0..8_usize, any::<bool>()).prop_map(|(n, same)| Op::Reserve(n, same)),
        2 => (0..8_usize).prop_map(Op::Authenticate),
        2 => (0..8_usize).prop_map(Op::Burn),
        3 => (0..8_usize).prop_map(Op::Release),
        1 => Just(Op::CancelAll),
        1 => (0..8_usize).prop_map(Op::BareCodeHello),
        2 => (0..4000_u16).prop_map(Op::Advance),
        1 => Just(Op::Restart),
    ]
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[expect(clippy::struct_excessive_bools, reason = "a flat test model")]
struct ModelOffer {
    code: bool,
    created_ms: u64,
    reserved: bool,
    /// Burned, replaced, or withdrawn: the slot is gone.
    burned: bool,
    failures: u8,
    last_attempt_ms: Option<u64>,
    restarted: bool,
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// The registry against a model: an offer is never held twice, a QR
    /// offer survives any number of failed attempts, a code offer allows at
    /// most five failed attempts spaced at least 2 s apart, burned and
    /// expired offers never reserve again, a restart forgets every offer,
    /// a held code is never replaced, a withdrawn offer can no longer be
    /// burned by the attempt that held it, and the §13 budget counts
    /// exactly the unauthenticated reservations.
    #[test]
    fn registry_matches_the_model(ops in proptest::collection::vec(op(), 1..60)) {
        let device = Device::new().map_err(|e| TestCaseError::fail(e.to_string()))?;
        let local = device.local().map_err(|e| TestCaseError::fail(e.to_string()))?;
        let base = now().map_err(|e| TestCaseError::fail(e.to_string()))?;
        let mut offers = PairingOffers::new();
        let mut ids: Vec<[u8; 16]> = Vec::new();
        let mut model: BTreeMap<[u8; 16], ModelOffer> = BTreeMap::new();
        let mut held: BTreeMap<[u8; 16], (OfferReservation, bool)> = BTreeMap::new();
        let mut starts: Vec<u64> = Vec::new();
        let mut elapsed_ms: u64 = 0;
        for op in ops {
            let mono = MONO + Duration::from_millis(elapsed_ms);
            let wall = UnixTime::new(base.seconds() + elapsed_ms / 1000).ok_or_else(|| TestCaseError::fail("time"))?;
            let at = elapsed_ms;
            let live = |m: &ModelOffer| !m.burned && !m.restarted && at < m.created_ms + 300_000 && m.failures < MAX_CODE_FAILURES;
            match op {
                Op::CreateQr | Op::CreateCode => {
                    let code = matches!(op, Op::CreateCode);
                    let busy = code && model.values().any(|m| m.code && m.reserved && !m.burned && !m.restarted);
                    if code && !busy {
                        for entry in model.values_mut() {
                            if entry.code { entry.burned = true; }
                        }
                    }
                    let count = model.values().filter(|m| live(m) || (m.reserved && !m.burned && !m.restarted)).count();
                    let result = if code {
                        offers.create_code(CODE_GATE, wall, mono).map(|_| offers.code_pairing_id())
                    } else {
                        offers.create_qr(&local, wall, mono).map(|payload| Some(*payload.pairing_id()))
                    };
                    if busy {
                        prop_assert_eq!(result.err(), Some(PairingError::OfferBusy));
                    } else if count >= MAX_OFFERS {
                        prop_assert_eq!(result.err(), Some(PairingError::TooManyOffers));
                    } else {
                        let id = result.map_err(|e| TestCaseError::fail(e.to_string()))?.ok_or_else(|| TestCaseError::fail("id"))?;
                        ids.push(id);
                        model.insert(id, ModelOffer { code, created_ms: elapsed_ms, reserved: false, burned: false, failures: 0, last_attempt_ms: None, restarted: false });
                    }
                }
                Op::Reserve(n, same) => {
                    if ids.is_empty() { continue; }
                    let id = ids[n % ids.len()];
                    let entry = model[&id];
                    let mode = if entry.code == same { SessionMode::Code } else { SessionMode::Qr };
                    let hello = hello(mode, id).map_err(|e| TestCaseError::fail(e.to_string()))?;
                    let result = offers.reserve(&hello, wall, mono);
                    starts.retain(|&start| elapsed_ms.saturating_sub(start) < 60_000);
                    let unauthenticated = held.values().filter(|(_, auth)| !auth).count();
                    let too_soon = entry.code && entry.last_attempt_ms.is_some_and(|last| elapsed_ms < last + 2_000);
                    let expected_ok = same && !entry.reserved && live(&entry) && !too_soon
                        && unauthenticated < MAX_CONCURRENT_ATTEMPTS && starts.len() < MAX_ATTEMPT_STARTS_PER_MINUTE;
                    prop_assert_eq!(result.is_ok(), expected_ok, "{:?} {:?}", entry, result.as_ref().err());
                    if let Ok(reservation) = result {
                        starts.push(elapsed_ms);
                        let entry = model.get_mut(&id).ok_or_else(|| TestCaseError::fail("model"))?;
                        entry.reserved = true;
                        entry.last_attempt_ms = Some(elapsed_ms);
                        held.insert(id, (reservation, false));
                    }
                }
                Op::Authenticate(n) => {
                    if let Some(id) = held.keys().nth(n % held.len().max(1)).copied()
                        && let Some((reservation, auth)) = held.get_mut(&id)
                    {
                        reservation.authenticated();
                        *auth = true;
                    }
                }
                Op::Burn(n) | Op::Release(n) => {
                    if let Some(id) = held.keys().nth(n % held.len().max(1)).copied() {
                        let (mut reservation, _) = held.remove(&id).ok_or_else(|| TestCaseError::fail("held"))?;
                        let entry = model.get_mut(&id).ok_or_else(|| TestCaseError::fail("model"))?;
                        entry.reserved = false;
                        if matches!(op, Op::Burn(_)) {
                            // Only an offer that is still there can burn.
                            prop_assert_eq!(reservation.burn().is_ok(), !entry.burned);
                            prop_assert!(!reservation.still_offered());
                            entry.burned = true;
                        } else if entry.code && !entry.burned {
                            entry.failures += 1;
                        }
                        drop(reservation);
                    }
                }
                Op::BareCodeHello(n) => {
                    if ids.is_empty() { continue; }
                    let id = ids[n % ids.len()];
                    let bare = hello(SessionMode::Code, id).map_err(|e| TestCaseError::fail(e.to_string()))?;
                    prop_assert_eq!(offers.reserve_attempt(&bare, false, &mut None, wall, mono).err(), Some(PairingError::NoOfferExchange));
                }
                Op::CancelAll => {
                    offers.cancel_all();
                    for entry in model.values_mut() {
                        entry.burned = true;
                    }
                    for (reservation, _) in held.values() {
                        prop_assert!(!reservation.still_offered());
                    }
                }
                Op::Advance(ms) => elapsed_ms += u64::from(ms),
                Op::Restart => {
                    held.clear();
                    offers = PairingOffers::new();
                    for entry in model.values_mut() {
                        entry.restarted = true;
                        entry.reserved = false;
                    }
                    starts.clear();
                }
            }
            let unauthenticated = held.values().filter(|(_, auth)| !auth).count();
            prop_assert_eq!(offers.active_attempts(), unauthenticated);
            for (id, entry) in &model {
                if entry.code && !entry.burned && !entry.restarted && entry.failures < MAX_CODE_FAILURES
                    && let Some(failures) = offers.failures(id)
                {
                    prop_assert_eq!(failures, entry.failures);
                }
                prop_assert!(entry.failures <= MAX_CODE_FAILURES);
            }
        }
    }
}
