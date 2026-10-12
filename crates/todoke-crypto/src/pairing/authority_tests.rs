//! The pairing authority called directly (PROTOCOL §3.1, §3.2, §4.3,
//! §4.4): the three QR key pins one at a time, the offer-expiry boundary
//! on each side, the §13 budget at identity confirmation, and the refusals
//! of the begin, journal, commit, and clear steps.

use todoke_proto::session::{Hello, SessionMode};
use todoke_proto::time::UnixTime;
use zeroize::Zeroizing;

use super::tests::{CLIENT_NONCE, MONO, empty_store, wall};
use super::*;
use crate::identity::contacts::{PairOutcome, PairPsk, PairingJournal, Unavailable};
use crate::identity::test_support::{DAY, Enrolled, SwitchableStorage, T0, nz, request, sealer};
use crate::identity::{
    BindingError, CLOCK_SKEW_SECONDS, ContactError, ContactStore, IdentityError, RevocationRequest,
    TrustOrigin, VerifiedDeviceBinding, issue_device_binding, issue_revocation,
};
use crate::session::tests::support::{AnyResult, Device, TestResult};
use crate::session::{
    NoiseStaticKey, PeerAuthority, PeerPresentation, PendingRatchet, Role, SessionError,
};
use todoke_proto::identity::RevocationReason;

const HASH: [u8; 32] = [0x4a; 32];
const PSK_NEXT: [u8; 32] = [0x6b; 32];
const CODE_GATE: UnauditedCodePairing = UnauditedCodePairing::acknowledge_not_production_ready();

fn at(seconds: u64) -> AnyResult<UnixTime> {
    Ok(UnixTime::new(seconds).ok_or("time")?)
}

fn present(
    mode: SessionMode,
    binding: &VerifiedDeviceBinding,
    now: UnixTime,
) -> PeerPresentation<'_> {
    PeerPresentation {
        mode,
        noise_static: binding.noise_static(),
        binding: binding.binding(),
        now,
    }
}

fn pending(peer: &VerifiedDeviceBinding, generation_next: u64, hash: [u8; 32]) -> PendingRatchet {
    PendingRatchet {
        role: Role::Initiator,
        generation_next,
        handshake_hash: hash,
        psk_next: Zeroizing::new(PSK_NEXT),
        peer: peer.clone(),
    }
}

/// A displayer with one live QR offer, as the scanner received it.
struct Offer {
    displayer: Device,
    offers: PairingOffers,
    payload: QrPayload,
}

impl Offer {
    fn new() -> AnyResult<Self> {
        let displayer = Device::new()?;
        let offers = PairingOffers::new();
        let payload = offers.create_qr(&displayer.local()?, wall()?, MONO)?;
        Ok(Self {
            displayer,
            offers,
            payload,
        })
    }

    fn reserve(&self) -> AnyResult<OfferReservation> {
        let hello = Hello::client(SessionMode::Qr, 0, *self.payload.pairing_id(), CLIENT_NONCE)?;
        Ok(self.offers.reserve(&hello, wall()?, MONO)?)
    }
}

/// §3.1: each of the three keys from the QR is checked on its own. Every
/// presented binding below is validly signed and differs from the QR in
/// exactly one key; a code entrant, which pins nothing, accepts them all.
#[test]
fn the_scanner_pins_each_qr_key() -> TestResult {
    let offer = Offer::new()?;
    let displayer = &offer.displayer;
    let now = wall()?;
    let noise = *displayer.noise.public_key();
    // Another device and person certifying the displayer's Noise and
    // ML-KEM keys.
    let other_device = Enrolled::new()?.bind_noise(1, noise)?;
    // The displayer's device certifying another Noise key.
    let other_noise = displayer
        .enrolled
        .bind_noise(2, *NoiseStaticKey::generate()?.public_key())?;
    // The displayer's device certifying another ML-KEM credential.
    let mut kem_request = request(0x33, 0x45, 3, T0, T0 + 30 * DAY)?;
    kem_request.noise_static = noise;
    let enrolled = &displayer.enrolled;
    let other_kem = issue_device_binding(
        &enrolled.store,
        &enrolled.root,
        &enrolled.device,
        kem_request,
    )?;
    assert_eq!(
        other_device.noise_static(),
        displayer.binding.noise_static()
    );
    assert_eq!(other_device.kem_static(), displayer.binding.kem_static());
    assert_eq!(
        other_noise.device_public(),
        displayer.binding.device_public()
    );
    assert_eq!(other_noise.kem_static(), displayer.binding.kem_static());
    assert_eq!(other_kem.device_public(), displayer.binding.device_public());
    assert_eq!(other_kem.noise_static(), displayer.binding.noise_static());
    for (label, binding) in [
        ("device", &other_device),
        ("noise", &other_noise),
        ("kem", &other_kem),
    ] {
        let mut store = empty_store()?;
        let (_, mut authority) = store.begin_qr_pairing(&offer.payload, now)?;
        assert_eq!(
            authority
                .confirm_peer(&present(SessionMode::Qr, binding, now))
                .err(),
            Some(SessionError::Identity(IdentityError::AuthenticationFailed)),
            "{label}"
        );
        // The code entrant has no pins (§4.2).
        let mut store = empty_store()?;
        let request = todoke_proto::pairing::CodeOfferRequest::new([0x5e; 8])?;
        let code_offer = todoke_proto::pairing::CodeOffer::new(
            &request,
            *offer.payload.pairing_id(),
            offer.payload.expires_at(),
        )?;
        let code = HumanCode::parse("0123456789")?;
        let (_, mut authority) =
            store.begin_code_pairing(CODE_GATE, request, &code_offer, &code, now)?;
        assert!(
            authority
                .confirm_peer(&present(SessionMode::Code, binding, now))
                .is_ok(),
            "{label}"
        );
    }
    let mut store = empty_store()?;
    let (_, mut authority) = store.begin_qr_pairing(&offer.payload, now)?;
    let verified = authority.confirm_peer(&present(SessionMode::Qr, &displayer.binding, now))?;
    assert_eq!(verified.device_public(), displayer.binding.device_public());
    Ok(())
}

/// §1/§3: the scanner allows the clock skew around the QR's expiry, the
/// displayer compares its own clock with none. Confirmation after either
/// boundary fails before the binding is even verified.
#[test]
fn offer_expiry_boundaries_at_confirmation() -> TestResult {
    let offer = Offer::new()?;
    let binding = &offer.displayer.binding;
    let expires = offer.payload.expires_at().seconds();
    let scanner = |seconds: u64| -> AnyResult<Result<(), SessionError>> {
        let mut store = empty_store()?;
        let (_, mut authority) = store.begin_qr_pairing(&offer.payload, wall()?)?;
        Ok(authority
            .confirm_peer(&present(SessionMode::Qr, binding, at(seconds)?))
            .map(drop))
    };
    assert_eq!(scanner(expires + CLOCK_SKEW_SECONDS - 1)?, Ok(()));
    assert_eq!(
        scanner(expires + CLOCK_SKEW_SECONDS)?,
        Err(SessionError::Pairing(PairingError::Expired))
    );
    // A displayer clock far ahead of the scanner's: the expiry lies more
    // than 300 s plus the skew ahead.
    assert_eq!(
        scanner(expires - OFFER_LIFETIME_SECONDS - CLOCK_SKEW_SECONDS - 1)?,
        Err(SessionError::Pairing(PairingError::Expired))
    );
    let scanner_binding = Device::new()?.binding;
    let displayer = |seconds: u64| -> AnyResult<Result<(), SessionError>> {
        let mut store = empty_store()?;
        let (_, mut authority) = offer.reserve()?.into_qr_responder(&mut store)?;
        Ok(authority
            .confirm_peer(&present(SessionMode::Qr, &scanner_binding, at(seconds)?))
            .map(drop))
    };
    assert_eq!(displayer(expires - 1)?, Ok(()));
    assert_eq!(
        displayer(expires)?,
        Err(SessionError::Pairing(PairingError::Expired))
    );
    Ok(())
}

/// §13: the displayer's attempt leaves the unauthenticated budget when the
/// scanner's identity is confirmed, not only when the offer is burned.
#[test]
fn confirmation_leaves_the_unauthenticated_budget() -> TestResult {
    let offer = Offer::new()?;
    let scanner = Device::new()?;
    let mut store = empty_store()?;
    let (_, mut authority) = offer.reserve()?.into_qr_responder(&mut store)?;
    assert_eq!(offer.offers.active_attempts(), 1);
    authority.confirm_peer(&present(SessionMode::Qr, &scanner.binding, wall()?))?;
    assert_eq!(offer.offers.active_attempts(), 0);
    assert!(format!("{authority:?}").contains("role: \"responder\""));
    drop(authority);
    // Dropped before the journal: the QR offer is free again.
    assert_eq!(offer.offers.live(OfferKind::Qr, wall()?, MONO), 1);
    assert_eq!(offer.offers.active_attempts(), 0);
    Ok(())
}

#[test]
fn confirmation_requires_the_authority_mode() -> TestResult {
    let offer = Offer::new()?;
    let mut store = empty_store()?;
    let (_, mut authority) = store.begin_qr_pairing(&offer.payload, wall()?)?;
    for mode in [SessionMode::Code, SessionMode::Contact] {
        assert_eq!(
            authority
                .confirm_peer(&present(mode, &offer.displayer.binding, wall()?))
                .err(),
            Some(SessionError::Usage),
            "{mode:?}"
        );
    }
    Ok(())
}

/// §4.4: a new pairing journals only after the peer was confirmed and only
/// generation 1 (from 0). Refusals journal and burn nothing; a second
/// journal of the same offer is refused as burned.
#[test]
fn journal_needs_a_confirmed_peer_at_generation_one() -> TestResult {
    let offer = Offer::new()?;
    let binding = &offer.displayer.binding;
    let id = *offer.payload.pairing_id();
    let mut store = empty_store()?;
    {
        let (_, mut authority) = store.begin_qr_pairing(&offer.payload, wall()?)?;
        assert_eq!(
            authority.journal(&pending(binding, 1, HASH)),
            Err(SessionError::Usage)
        );
        authority.confirm_peer(&present(SessionMode::Qr, binding, wall()?))?;
        for generation in [0, 2, u64::MAX] {
            assert_eq!(
                authority.journal(&pending(binding, generation, HASH)),
                Err(SessionError::RatchetUncertain),
                "{generation}"
            );
        }
    }
    assert!(!store.pairing_burned(&id));
    assert!(!store.pairing_pending());
    let (_, mut authority) = store.begin_qr_pairing(&offer.payload, wall()?)?;
    authority.confirm_peer(&present(SessionMode::Qr, binding, wall()?))?;
    authority.journal(&pending(binding, 1, HASH))?;
    assert_eq!(
        authority.journal(&pending(binding, 1, HASH)),
        Err(SessionError::Pairing(PairingError::Burned))
    );
    drop(authority);
    assert!(store.pairing_burned(&id));
    assert!(store.pairing_pending());
    Ok(())
}

/// One new pairing at a time per store, on both sides (§4.4), and the right
/// kind of offer for each responder.
#[test]
fn begin_refuses_a_pending_pairing_and_the_wrong_offer_kind() -> TestResult {
    let offer = Offer::new()?;
    let other = Device::new()?;
    let mut store = empty_store()?;
    store.journal_pairing(
        &PairingJournal {
            pairing_id: [0x77; 16],
            expires_at: wall()?,
            origin: TrustOrigin::QrPairing,
            peer: &other.binding,
            handshake_hash: &HASH,
            psk_next: &PSK_NEXT,
        },
        wall()?,
    )?;
    assert_eq!(
        store.begin_qr_pairing(&offer.payload, wall()?).err(),
        Some(PairingError::PairingInProgress)
    );
    assert_eq!(
        offer.reserve()?.into_qr_responder(&mut store).err(),
        Some(PairingError::PairingInProgress)
    );
    // The offer's own ID, burned by an earlier journal of this store.
    store.abandon_pairing(&[0x77; 16], other.binding.device_public())?;
    store.journal_pairing(
        &PairingJournal {
            pairing_id: *offer.payload.pairing_id(),
            expires_at: offer.payload.expires_at(),
            origin: TrustOrigin::QrPairing,
            peer: &other.binding,
            handshake_hash: &HASH,
            psk_next: &PSK_NEXT,
        },
        wall()?,
    )?;
    store.abandon_pairing(offer.payload.pairing_id(), other.binding.device_public())?;
    assert_eq!(
        offer.reserve()?.into_qr_responder(&mut store).err(),
        Some(PairingError::Burned)
    );
    let mut fresh = empty_store()?;
    assert_eq!(
        offer
            .reserve()?
            .into_code_responder(CODE_GATE, &mut fresh)
            .err(),
        Some(PairingError::Mode)
    );
    let codes = PairingOffers::new();
    codes.create_code(CODE_GATE, wall()?, MONO)?;
    let id = codes.code_pairing_id().ok_or("code offer")?;
    let reservation = codes.reserve(
        &Hello::client(SessionMode::Code, 0, id, CLIENT_NONCE)?,
        wall()?,
        MONO,
    )?;
    assert_eq!(
        reservation.into_qr_responder(&mut fresh).err(),
        Some(PairingError::Mode)
    );
    Ok(())
}

/// The journal refuses a device whose existing contact is mid-ratchet
/// (§4.4: one transaction per device pair) before burning or recording
/// anything on the scanner.
#[test]
fn journal_refuses_a_device_with_a_ratchet_in_progress() -> TestResult {
    let offer = Offer::new()?;
    let binding = &offer.displayer.binding;
    let mut store = empty_store()?;
    store.pair(
        binding,
        TrustOrigin::QrPairing,
        PairPsk::new([0x77; 32]),
        3,
        wall()?,
    )?;
    store.journal_ratchet(binding.device_public(), 4, &[1; 32], &[2; 32])?;
    let (_, mut authority) = store.begin_qr_pairing(&offer.payload, wall()?)?;
    authority.confirm_peer(&present(SessionMode::Qr, binding, wall()?))?;
    assert_eq!(
        authority.journal(&pending(binding, 1, HASH)),
        Err(SessionError::Pairing(PairingError::PairingInProgress))
    );
    drop(authority);
    assert!(!store.pairing_burned(offer.payload.pairing_id()));
    assert!(!store.pairing_pending());
    Ok(())
}

/// A journal write that fails leaves its durability uncertain: the
/// pairing is dropped in memory so it does not block later pairings, the
/// offer stays burned on both sides, and an existing contact for the
/// device is blocked (§3.2, §4.4).
#[test]
fn a_failed_journal_write_drops_the_pairing_and_keeps_the_burn() -> TestResult {
    let offer = Offer::new()?;
    let binding = &offer.displayer.binding;
    let (storage, failing) = SwitchableStorage::new();
    let mut store = ContactStore::open(sealer(9), storage)?;
    store.pair(
        binding,
        TrustOrigin::QrPairing,
        PairPsk::new([0x77; 32]),
        3,
        wall()?,
    )?;
    let (_, mut authority) = store.begin_qr_pairing(&offer.payload, wall()?)?;
    authority.confirm_peer(&present(SessionMode::Qr, binding, wall()?))?;
    failing.set(true);
    assert!(matches!(
        authority.journal(&pending(binding, 1, HASH)),
        Err(SessionError::Storage(ContactError::Storage(_)))
    ));
    drop(authority);
    assert!(!store.pairing_pending());
    assert!(store.pairing_burned(offer.payload.pairing_id()));
    assert_eq!(
        store.availability(binding.device_public())?.err(),
        Some(Unavailable::RatchetUncertain)
    );
    // The displayer burns its offer before the write.
    let scanner = Device::new()?;
    let (storage, failing) = SwitchableStorage::new();
    let mut store = ContactStore::open(sealer(9), storage)?;
    let (_, mut authority) = offer.reserve()?.into_qr_responder(&mut store)?;
    authority.confirm_peer(&present(SessionMode::Qr, &scanner.binding, wall()?))?;
    failing.set(true);
    assert!(
        authority
            .journal(&pending(&scanner.binding, 1, HASH))
            .is_err()
    );
    drop(authority);
    assert!(!store.pairing_pending());
    assert_eq!(offer.offers.live(OfferKind::Qr, wall()?, MONO), 0);
    Ok(())
}

/// Commit and clear accept only the journaled transaction, after the
/// peer's confirmation, and report storage failures as such.
#[test]
fn commit_and_clear_refuse_anything_but_the_journaled_transaction() -> TestResult {
    let offer = Offer::new()?;
    let binding = &offer.displayer.binding;
    let mut store = empty_store()?;
    let (_, mut authority) = store.begin_qr_pairing(&offer.payload, wall()?)?;
    assert_eq!(
        authority.commit(&pending(binding, 1, HASH)),
        Err(SessionError::Usage)
    );
    authority.confirm_peer(&present(SessionMode::Qr, binding, wall()?))?;
    authority.journal(&pending(binding, 1, HASH))?;
    assert_eq!(
        authority.commit(&pending(binding, 1, [0x4b; 32])),
        Err(SessionError::RatchetUncertain)
    );
    assert_eq!(authority.outcome(), None);
    authority.commit(&pending(binding, 1, HASH))?;
    assert_eq!(authority.outcome(), Some(PairOutcome::New));
    assert_eq!(
        authority.clear(&pending(binding, 1, [0x4b; 32])),
        Err(SessionError::RatchetUncertain)
    );
    authority.clear(&pending(binding, 1, HASH))?;
    drop(authority);
    assert!(
        store
            .availability(binding.device_public())?
            .is_ok_and(|contact| contact.generation() == 1)
    );

    // Storage failures of commit and of clear.
    for fail_at_clear in [false, true] {
        let offer = Offer::new()?;
        let binding = &offer.displayer.binding;
        let (storage, failing) = SwitchableStorage::new();
        let mut store = ContactStore::open(sealer(9), storage)?;
        let (_, mut authority) = store.begin_qr_pairing(&offer.payload, wall()?)?;
        authority.confirm_peer(&present(SessionMode::Qr, binding, wall()?))?;
        authority.journal(&pending(binding, 1, HASH))?;
        if fail_at_clear {
            authority.commit(&pending(binding, 1, HASH))?;
        }
        failing.set(true);
        let result = if fail_at_clear {
            authority.clear(&pending(binding, 1, HASH))
        } else {
            authority.commit(&pending(binding, 1, HASH))
        };
        assert!(
            matches!(result, Err(SessionError::Storage(ContactError::Storage(_)))),
            "{fail_at_clear}"
        );
    }
    Ok(())
}

/// A binding the store has revoked cannot be paired again at the commit,
/// even if it was journaled (§2): the refusal is an identity error.
#[test]
fn commit_refuses_a_revoked_binding() -> TestResult {
    let offer = Offer::new()?;
    let binding = &offer.displayer.binding;
    let revoked = Enrolled::new()?;
    let revoked_binding = revoked.bind(1)?;
    let mut store = empty_store()?;
    // Revocations apply only under a root the store already trusts.
    store.pair(
        &revoked_binding,
        TrustOrigin::QrPairing,
        PairPsk::new([0x77; 32]),
        3,
        wall()?,
    )?;
    let revocation = issue_revocation(
        &revoked.store,
        &revoked.root,
        RevocationRequest {
            device_public: *revoked_binding.device_public(),
            sequence: nz(1)?,
            issued_at: at(T0)?,
            through_serial: nz(1)?,
            reason: RevocationReason::Lost,
        },
    )?;
    store.apply_revocation(revocation.record().clone())?;
    let (_, mut authority) = store.begin_qr_pairing(&offer.payload, wall()?)?;
    authority.confirm_peer(&present(SessionMode::Qr, binding, wall()?))?;
    authority.journal(&pending(&revoked_binding, 1, HASH))?;
    assert_eq!(
        authority.commit(&pending(&revoked_binding, 1, HASH)),
        Err(SessionError::Identity(IdentityError::Binding(
            BindingError::Revoked
        )))
    );
    drop(authority);
    assert!(!store.pairing_pending());
    assert!(
        store
            .availability(revoked_binding.device_public())?
            .is_err()
    );
    Ok(())
}
