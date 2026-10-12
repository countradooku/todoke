//! Forged Identity and ratchet records under the real session keys.

use super::*;
use crate::identity::test_support::{DAY, T0, request, time};
use crate::identity::{BindingError, VerificationState};
use crate::identity::{IdentityError, MemoryStorage, SoftwareSealer, issue_device_binding};
use crate::session::ContactAuthority;
use crate::session::NoiseStaticKey;
use crate::session::authority::testing::{Journal, PairingAuthority, Substituting};
use crate::session::handshake::{HandshakeDriver, InitiatorPlan, ResponderPlan, read_client_hello};
use crate::session::tests::support::*;
use todoke_proto::session::ErrorScope;

const GENERATION: u64 = 3;
const LOCATOR: [u8; 16] = [0x4c; 16];

fn record_body(record: &[u8]) -> &[u8] {
    &record[2..]
}

/// Runs the KK handshake between `alice` (initiator) and `bob` and returns
/// both establishment phases, before either sent anything.
fn established_pair(alice: &Device, bob: &Device) -> AnyResult<(Establishment, Establishment)> {
    established_pair_at(alice, bob, WALL)
}

/// [`established_pair`] with both sides' trusted wall clock at `wall`
/// (Unix seconds) at monotonic `START`.
fn established_pair_at(
    alice: &Device,
    bob: &Device,
    wall: u64,
) -> AnyResult<(Establishment, Establishment)> {
    let (mut initiator, client_hello) = HandshakeDriver::initiator(
        GATE,
        InitiatorPlan::contact(
            GENERATION,
            LOCATOR,
            Zeroizing::new(OLD_PSK),
            *bob.noise.public_key(),
        ),
        &alice.noise,
        [1; 16],
        Entropy::Os,
        START,
    )?;
    let hello = read_client_hello(record_body(&client_hello))?;
    let (mut responder, server_hello) = HandshakeDriver::responder(
        GATE,
        hello,
        ResponderPlan::contact(
            GENERATION,
            Zeroizing::new(OLD_PSK),
            *alice.noise.public_key(),
        ),
        &bob.noise,
        [2; 16],
        Entropy::Os,
        START,
    )?;
    let first = initiator.receive(record_body(&server_hello), START)?;
    let second = responder.receive(record_body(&first[0]), START)?;
    initiator.receive(record_body(&second[0]), START)?;
    let wall = crate::session::WallClock::new(time(wall)?, START);
    Ok((
        Establishment::new(initiator.finish()?, START, wall, Limits::SPEC),
        Establishment::new(responder.finish()?, START, wall, Limits::SPEC),
    ))
}

type Authority<'a> = ContactAuthority<'a, SoftwareSealer, MemoryStorage>;

/// Signs an `Identity` body for arbitrary inputs with `signer`'s device key.
fn forged_identity(
    signer: &crate::identity::test_support::Enrolled,
    binding: &VerifiedDeviceBinding,
    hash: &[u8; 32],
    role: Role,
) -> AnyResult<Vec<u8>> {
    let message = kdf::identity_message(hash, role, &binding.encode());
    let signature = signer
        .store
        .sign(&signer.device, SigningDomain::Identity, &message)?;
    Ok(Identity::new(binding.binding().clone(), *hash, signature.to_bytes()).encode())
}

fn seal(
    establishment: &mut Establishment,
    frame_type: FrameType,
    body: &[u8],
) -> AnyResult<Vec<u8>> {
    let mut records = establishment
        .transport_mut()
        .seal(frame_type, body, START)?;
    records.pop().ok_or_else(|| "no record".into())
}

/// The responder's view of a forged first record from the initiator.
fn responder_rejects(
    forge: impl Fn(&Device, &Device, &mut Establishment) -> AnyResult<Vec<u8>>,
) -> AnyResult<(SessionError, Store, Device)> {
    let alice = Device::new()?;
    let bob = Device::new()?;
    let mut bob_store = store_pairing(&alice, GENERATION)?;
    let (mut initiator, mut responder) = established_pair(&alice, &bob)?;
    let record = forge(&alice, &bob, &mut initiator)?;
    let bob_local = bob.local()?;
    let alice_key = alice.key();
    let error = {
        let mut authority: Authority<'_> = bob_store.session_authority(&alice_key)?;
        let result = responder.receive(record_body(&record), &bob_local, &mut authority, START);
        result.err().ok_or("forged record accepted")?
    };
    assert_eq!(responder.phase(), Phase::Failed);
    Ok((error, bob_store, alice))
}

#[test]
fn forged_identities_fail_before_any_journal() -> TestResult {
    // Wrong handshake hash, correctly signed.
    let (error, store, alice) = responder_rejects(|alice, _, initiator| {
        let mut hash = initiator.handshake_hash;
        hash[0] ^= 1;
        let body = forged_identity(&alice.enrolled, &alice.binding, &hash, Role::Initiator)?;
        seal(initiator, FrameType::IDENTITY, &body)
    })?;
    assert_eq!(error, SessionError::Authentication);
    assert_eq!(usable(&store, &alice.key())?, Some((GENERATION, OLD_PSK)));
    // The responder's role byte instead of the initiator's.
    let (error, store, alice) = responder_rejects(|alice, _, initiator| {
        let hash = initiator.handshake_hash;
        let body = forged_identity(&alice.enrolled, &alice.binding, &hash, Role::Responder)?;
        seal(initiator, FrameType::IDENTITY, &body)
    })?;
    assert_eq!(error, SessionError::Authentication);
    assert_eq!(usable(&store, &alice.key())?, Some((GENERATION, OLD_PSK)));
    // Alice's binding signed by Bob's device key.
    let (error, _, _) = responder_rejects(|alice, bob, initiator| {
        let hash = initiator.handshake_hash;
        let body = forged_identity(&bob.enrolled, &alice.binding, &hash, Role::Initiator)?;
        seal(initiator, FrameType::IDENTITY, &body)
    })?;
    assert_eq!(error, SessionError::Authentication);
    // A valid binding of Alice's that certifies another Noise key.
    let (error, store, alice) = responder_rejects(|alice, _, initiator| {
        let hash = initiator.handshake_hash;
        let other = alice.enrolled.bind(2)?;
        let body = forged_identity(&alice.enrolled, &other, &hash, Role::Initiator)?;
        seal(initiator, FrameType::IDENTITY, &body)
    })?;
    assert_eq!(error, SessionError::Authentication);
    assert_eq!(usable(&store, &alice.key())?, Some((GENERATION, OLD_PSK)));
    // Malformed body.
    let (error, _, _) =
        responder_rejects(|_, _, initiator| seal(initiator, FrameType::IDENTITY, &[0; 10]))?;
    assert_eq!(error, SessionError::Protocol(ErrorCode::MALFORMED));
    Ok(())
}

/// §4.3: a validly signed binding with different keys for the pinned
/// Noise static key is an unknown identity change: the contact is blocked.
#[test]
fn identity_change_blocks_the_contact() -> TestResult {
    let (error, store, alice) = responder_rejects(|alice, _, initiator| {
        let impostor = crate::identity::test_support::Enrolled::new()?;
        let binding = impostor.bind_noise(1, *alice.noise.public_key())?;
        let hash = initiator.handshake_hash;
        let body = forged_identity(&impostor, &binding, &hash, Role::Initiator)?;
        seal(initiator, FrameType::IDENTITY, &body)
    })?;
    assert!(matches!(
        error,
        SessionError::Identity(IdentityError::KeyChanged(_))
    ));
    let contact = store.contact(&alice.key()).ok_or("contact")?;
    assert_eq!(contact.state(), VerificationState::KeyChanged);
    assert_eq!(usable(&store, &alice.key())?, None);
    Ok(())
}

/// Revocation and expiry checks precede identity confirmation (§4.3).
#[test]
fn expired_peer_binding_is_rejected() -> TestResult {
    let enrolled = crate::identity::test_support::Enrolled::new()?;
    let noise = NoiseStaticKey::generate()?;
    let mut short = request(0x33, 0x44, 1, T0, T0 + DAY)?;
    short.noise_static = *noise.public_key();
    let binding = issue_device_binding(&enrolled.store, &enrolled.root, &enrolled.device, short)?;
    let alice = Device {
        enrolled,
        noise,
        binding,
    };
    let bob = Device::new()?;
    let mut bob_store = store_pairing(&alice, GENERATION)?;
    // The session starts after Alice's one-day binding expired.
    let (mut initiator, mut responder) = established_pair_at(&alice, &bob, T0 + 2 * DAY)?;
    let alice_local = alice.local()?;
    let records = initiator.start(&alice_local, START)?;
    let bob_local = bob.local_at(T0 + 2 * DAY)?;
    let alice_key = alice.key();
    let mut authority: Authority<'_> = bob_store.session_authority(&alice_key)?;
    assert_eq!(
        responder
            .receive(record_body(&records[0]), &bob_local, &mut authority, START)
            .map(|_| ()),
        Err(SessionError::Identity(IdentityError::Binding(
            BindingError::Expired
        )))
    );
    Ok(())
}

/// Forged ratchet records from the initiator, before the responder
/// journaled: the responder fails and its pairing stays usable.
#[test]
#[allow(clippy::too_many_lines, reason = "one table of forgeries")]
fn forged_ready_from_the_initiator_leaves_the_responder_usable() -> TestResult {
    type Forge = fn(&mut Establishment, &[u8; 32], [u8; 32]) -> AnyResult<Vec<u8>>;
    let cases: [(Forge, SessionError); 7] = [
        // Wrong MAC.
        (
            |e, _, id| {
                seal(
                    e,
                    FrameType::RATCHET_READY,
                    &Ratchet::new(id, GENERATION + 1, [9; 32])?.encode(),
                )
            },
            SessionError::Authentication,
        ),
        // Correct MAC for a skipped generation.
        (
            |e, next, id| {
                let mac = kdf::ratchet_confirmation(
                    next,
                    FrameType::RATCHET_READY,
                    Role::Initiator,
                    &id,
                    GENERATION + 2,
                );
                seal(
                    e,
                    FrameType::RATCHET_READY,
                    &Ratchet::new(id, GENERATION + 2, mac)?.encode(),
                )
            },
            SessionError::GenerationMismatch,
        ),
        // Another session's ID.
        (
            |e, next, mut id| {
                id[0] ^= 1;
                let mac = kdf::ratchet_confirmation(
                    next,
                    FrameType::RATCHET_READY,
                    Role::Initiator,
                    &id,
                    GENERATION + 1,
                );
                seal(
                    e,
                    FrameType::RATCHET_READY,
                    &Ratchet::new(id, GENERATION + 1, mac)?.encode(),
                )
            },
            SessionError::Authentication,
        ),
        // The responder's own role in the MAC (a reflected Ready).
        (
            |e, next, id| {
                let mac = kdf::ratchet_confirmation(
                    next,
                    FrameType::RATCHET_READY,
                    Role::Responder,
                    &id,
                    GENERATION + 1,
                );
                seal(
                    e,
                    FrameType::RATCHET_READY,
                    &Ratchet::new(id, GENERATION + 1, mac)?.encode(),
                )
            },
            SessionError::Authentication,
        ),
        // Commit before Ready, even with a valid MAC.
        (
            |e, next, id| {
                let mac = kdf::ratchet_confirmation(
                    next,
                    FrameType::RATCHET_COMMIT,
                    Role::Initiator,
                    &id,
                    GENERATION + 1,
                );
                seal(
                    e,
                    FrameType::RATCHET_COMMIT,
                    &Ratchet::new(id, GENERATION + 1, mac)?.encode(),
                )
            },
            SessionError::Protocol(ErrorCode::STATE),
        ),
        // KeyUpdate before the ratchet committed.
        (
            |e, _, _| seal(e, FrameType::KEY_UPDATE, &1_u64.to_be_bytes()),
            SessionError::Protocol(ErrorCode::STATE),
        ),
        // An authenticated Error closes.
        (
            |e, _, _| {
                seal(
                    e,
                    FrameType::ERROR,
                    &ErrorRecord::new(ErrorScope::Session, ErrorCode::STORAGE)?.encode(),
                )
            },
            SessionError::PeerError(ErrorCode::STORAGE),
        ),
    ];
    for (index, (forge, expected)) in cases.into_iter().enumerate() {
        let alice = Device::new()?;
        let bob = Device::new()?;
        let mut bob_store = store_pairing(&alice, GENERATION)?;
        let (mut initiator, mut responder) = established_pair(&alice, &bob)?;
        let alice_local = alice.local()?;
        let bob_local = bob.local()?;
        let alice_key = alice.key();
        let identity = initiator.start(&alice_local, START)?;
        let psk_next = kdf::psk_next(&initiator.handshake_hash, &OLD_PSK).map_err(|_| "kdf")?;
        let session_id = initiator.session_id;
        {
            let mut authority: Authority<'_> = bob_store.session_authority(&alice_key)?;
            responder.receive(record_body(&identity[0]), &bob_local, &mut authority, START)?;
            let forged = forge(&mut initiator, &psk_next, session_id)?;
            assert_eq!(
                responder
                    .receive(record_body(&forged), &bob_local, &mut authority, START)
                    .map(|_| ()),
                Err(expected),
                "case {index}"
            );
        }
        assert_eq!(
            usable(&bob_store, &alice_key)?,
            Some((GENERATION, OLD_PSK)),
            "case {index}"
        );
    }
    Ok(())
}

/// A forged `RatchetReady` from the responder reaches an initiator that
/// already journaled: it fails closed and must re-pair (§4.4).
#[test]
fn forged_ready_after_the_initiator_journaled_blocks_it() -> TestResult {
    let alice = Device::new()?;
    let bob = Device::new()?;
    let mut alice_store = store_pairing(&bob, GENERATION)?;
    let mut bob_store = store_pairing(&alice, GENERATION)?;
    let (mut initiator, mut responder) = established_pair(&alice, &bob)?;
    let (alice_local, bob_local) = (alice.local()?, bob.local()?);
    let (alice_key, bob_key) = (alice.key(), bob.key());
    let identity = initiator.start(&alice_local, START)?;
    let reply = {
        let mut authority: Authority<'_> = bob_store.session_authority(&alice_key)?;
        responder.receive(record_body(&identity[0]), &bob_local, &mut authority, START)?
    };
    let session_id = responder.session_id;
    {
        let mut authority: Authority<'_> = alice_store.session_authority(&bob_key)?;
        let ready =
            initiator.receive(record_body(&reply[0]), &alice_local, &mut authority, START)?;
        assert_eq!(ready.len(), 1);
        let forged = seal(
            &mut responder,
            FrameType::RATCHET_READY,
            &Ratchet::new(session_id, GENERATION + 1, [7; 32])?.encode(),
        )?;
        assert_eq!(
            initiator
                .receive(record_body(&forged), &alice_local, &mut authority, START)
                .map(|_| ()),
            Err(SessionError::RatchetUncertain)
        );
    }
    assert_eq!(usable(&alice_store, &bob_key)?, None);
    // Abandoned, not merely interrupted: the block is recorded now and the
    // journaled next PSK is dropped rather than kept until a restart.
    let contact = alice_store.contact(&bob_key).ok_or("contact")?;
    assert_eq!(contact.state(), VerificationState::RatchetUncertain);
    assert!(!contact.ratchet_pending());
    let restarted = reopen(&alice_store)?;
    let contact = restarted.contact(&bob_key).ok_or("contact")?;
    assert_eq!(contact.state(), VerificationState::RatchetUncertain);
    assert_eq!(
        contact.generation(),
        GENERATION,
        "the old PSK is not restored as usable"
    );
    // Bob never journaled.
    assert_eq!(usable(&bob_store, &alice_key)?, Some((GENERATION, OLD_PSK)));
    Ok(())
}

/// Runs the honest establishment between pairing authorities to the open
/// gate on both sides.
fn open_pair(
    alice: &Device,
    bob: &Device,
) -> AnyResult<(
    Establishment,
    Establishment,
    PairingAuthority,
    PairingAuthority,
)> {
    let (mut initiator, mut responder) = established_pair(alice, bob)?;
    let (alice_local, bob_local) = (alice.local()?, bob.local()?);
    let mut alice_authority = PairingAuthority::new(Some(bob.key()));
    let mut bob_authority = PairingAuthority::new(None);
    let mut to_responder = initiator.start(&alice_local, START)?;
    while let Some(record) = to_responder.pop() {
        for reply in
            responder.receive(record_body(&record), &bob_local, &mut bob_authority, START)?
        {
            if responder.phase() == Phase::AckPending {
                responder.ack_queued(&mut bob_authority)?;
            }
            to_responder.extend(initiator.receive(
                record_body(&reply),
                &alice_local,
                &mut alice_authority,
                START,
            )?);
        }
    }
    Ok((initiator, responder, alice_authority, bob_authority))
}

/// The phase guards: `ack_queued` only after the responder queued its Ack,
/// `into_core` only once the gate is open, and a failure reported after the
/// gate opened neither blocks the committed pairing nor hides the error.
#[test]
fn phase_guards_around_the_open_gate() -> TestResult {
    let alice = Device::new()?;
    let bob = Device::new()?;
    let (mut initiator, _) = established_pair(&alice, &bob)?;
    let mut authority = PairingAuthority::new(None);
    assert_eq!(initiator.ack_queued(&mut authority), Err(state()));
    assert_eq!(
        initiator
            .into_core(&alice.local()?, Entropy::Os, START)
            .map(|_| ()),
        Err(state())
    );
    let (mut initiator, mut responder, mut alice_authority, mut bob_authority) =
        open_pair(&alice, &bob)?;
    assert_eq!(
        (initiator.phase(), responder.phase()),
        (Phase::Open, Phase::Open)
    );
    assert_eq!(responder.ack_queued(&mut bob_authority), Err(state()));
    for (establishment, authority) in [
        (&mut initiator, &mut alice_authority),
        (&mut responder, &mut bob_authority),
    ] {
        assert_eq!(
            establishment.failure(SessionError::Timeout, authority),
            SessionError::Timeout
        );
        assert_eq!(establishment.phase(), Phase::Open);
        assert_eq!(authority.journal, Journal::Cleared);
        assert_eq!(authority.committed_generation, Some(GENERATION + 1));
    }
    let core = responder.into_core(&bob.local()?, Entropy::Os, START)?;
    assert_eq!(core.info().role, Role::Responder);
    Ok(())
}

/// §4.3: the authority must confirm exactly the presented binding; one that
/// answers with another binding is treated as an authentication failure
/// before anything is journaled.
#[test]
fn an_authority_that_confirms_other_keys_is_refused() -> TestResult {
    let alice = Device::new()?;
    let bob = Device::new()?;
    let (mut initiator, mut responder) = established_pair(&alice, &bob)?;
    let records = initiator.start(&alice.local()?, START)?;
    let mut authority = Substituting {
        inner: PairingAuthority::new(None),
        substitute: alice.enrolled.bind_noise(2, *alice.noise.public_key())?,
    };
    assert_eq!(
        responder
            .receive(
                record_body(&records[0]),
                &bob.local()?,
                &mut authority,
                START
            )
            .map(|_| ()),
        Err(SessionError::Authentication)
    );
    assert_eq!(responder.phase(), Phase::Failed);
    assert_eq!(authority.inner.journal, Journal::Clean);
    Ok(())
}

#[test]
fn identity_twice_and_late_records_are_rejected() -> TestResult {
    let (error, _, _) = responder_rejects(|alice, _, initiator| {
        let local = alice.local()?;
        drop(initiator.start(&local, START)?);
        let hash = initiator.handshake_hash;
        let body = forged_identity(&alice.enrolled, &alice.binding, &hash, Role::Initiator)?;
        seal(initiator, FrameType::IDENTITY, &body)
    })?;
    // The responder sees the second Identity first: nonce 1 vs expected 0.
    assert_eq!(error, SessionError::Authentication);
    // A record after the 10-second deadline.
    let alice = Device::new()?;
    let bob = Device::new()?;
    let mut bob_store = store_pairing(&alice, GENERATION)?;
    let (mut initiator, mut responder) = established_pair(&alice, &bob)?;
    let records = initiator.start(&alice.local()?, START)?;
    let bob_local = bob.local()?;
    let alice_key = alice.key();
    let mut authority: Authority<'_> = bob_store.session_authority(&alice_key)?;
    assert_eq!(responder.deadline(), START + ESTABLISH_TIMEOUT);
    assert_eq!(
        responder
            .receive(
                record_body(&records[0]),
                &bob_local,
                &mut authority,
                START + ESTABLISH_TIMEOUT
            )
            .map(|_| ()),
        Err(SessionError::Timeout)
    );
    assert_eq!(
        responder
            .receive(record_body(&records[0]), &bob_local, &mut authority, START)
            .map(|_| ()),
        Err(SessionError::Closed)
    );
    Ok(())
}

#[test]
fn generation_exhaustion_requires_new_pairing() -> TestResult {
    let alice = Device::new()?;
    let bob = Device::new()?;
    let (mut initiator, _) = established_pair(&alice, &bob)?;
    initiator.generation = u64::MAX;
    initiator.peer = Some(bob.binding.clone());
    let mut authority = crate::session::authority::testing::PairingAuthority::new(None);
    assert_eq!(
        initiator.begin_ratchet(&mut authority),
        Err(SessionError::GenerationExhausted)
    );
    assert!(format!("{initiator:?}").contains("journaled: false"));
    Ok(())
}

/// HMAC-SHA-256 from `RustCrypto`, independent of the libcrux code under test.
fn reference_hmac(key: &[u8], message: &[u8]) -> AnyResult<[u8; 32]> {
    use hmac::{KeyInit as _, Mac as _};
    let mut mac = hmac::Hmac::<sha2::Sha256>::new_from_slice(key).map_err(|_| "hmac key")?;
    mac.update(message);
    Ok(mac.finalize().into_bytes().into())
}

/// §4.3, built literally from the spec table: the `Identity` signature input
/// is `"todoke/v1/identity\0" || h || role:u8 || B3(binding)`, checked with
/// libcrux's Ed25519 verifier rather than the code under test.
#[test]
fn identity_signature_covers_the_spec_byte_layout() -> TestResult {
    let alice = Device::new()?;
    let local = alice.local()?;
    let hash = [0x6d; 32];
    let device_public = *alice.key().as_bytes();
    let binding = alice.binding.encode();
    assert_eq!(binding.len(), 1438);
    for (role, role_byte) in [(Role::Initiator, 0_u8), (Role::Responder, 1)] {
        let identity = local.sign_identity(&hash, role)?;
        let mut signed = Vec::new();
        signed.extend_from_slice(b"todoke/v1/identity\x00");
        signed.extend_from_slice(&hash);
        signed.push(role_byte);
        signed.extend_from_slice(blake3::hash(&binding).as_bytes());
        assert_eq!(signed.len(), 19 + 32 + 1 + 32);
        libcrux_ed25519::verify(&signed, &device_public, identity.signature())
            .map_err(|_| format!("{role:?}: signature does not cover the spec layout"))?;
        // A different role byte must not verify.
        signed[19 + 32] ^= 1;
        assert!(libcrux_ed25519::verify(&signed, &device_public, identity.signature()).is_err());
        // The 1536-byte record: binding_len || binding || h || signature.
        let encoded = identity.encode();
        assert_eq!(encoded.len(), 1536);
        assert_eq!(&encoded[..2], &1438_u16.to_be_bytes());
        assert_eq!(&encoded[2..1440], binding.as_slice());
        assert_eq!(&encoded[1440..1472], &hash);
        assert_eq!(&encoded[1472..], identity.signature());
    }
    Ok(())
}

/// §4.4, built literally from the spec: `psk_next = HKDF(h, psk,
/// "todoke/v1/psk-ratchet\0", 32)` and `confirmation = HMAC-SHA256(psk_next,
/// "todoke/v1/ratchet-confirm\0" || type:u16 || role:u8 || session_id ||
/// generation_next:u64)`, recomputed with `RustCrypto` HMAC. Checks the
/// confirmation function for every type and role, and the actual
/// `RatchetReady` body an initiator sends.
#[test]
fn ratchet_confirmation_covers_the_spec_byte_layout() -> TestResult {
    let alice = Device::new()?;
    let bob = Device::new()?;
    let mut alice_store = store_pairing(&bob, GENERATION)?;
    let mut bob_store = store_pairing(&alice, GENERATION)?;
    let (alice_local, bob_local) = (alice.local()?, bob.local()?);
    let (alice_key, bob_key) = (alice.key(), bob.key());
    let (mut initiator, mut responder) = established_pair(&alice, &bob)?;
    let hash = initiator.handshake_hash;
    // session_id = B3("todoke/v1/session\0" || h) (§4.2.6).
    let mut session_input = b"todoke/v1/session\x00".to_vec();
    session_input.extend_from_slice(&hash);
    let session_id = *blake3::hash(&session_input).as_bytes();
    assert_eq!(initiator.session_id, session_id);
    // HKDF-SHA-256 Extract then Expand to 32 bytes (one block, RFC 5869).
    let prk = reference_hmac(&hash, &OLD_PSK)?;
    let psk_next = reference_hmac(&prk, b"todoke/v1/psk-ratchet\x00\x01")?;
    let generation_next = GENERATION + 1;
    let confirmation = |frame_type: u16, role: u8| -> AnyResult<[u8; 32]> {
        let mut message = b"todoke/v1/ratchet-confirm\x00".to_vec();
        message.extend_from_slice(&frame_type.to_be_bytes());
        message.push(role);
        message.extend_from_slice(&session_id);
        message.extend_from_slice(&generation_next.to_be_bytes());
        assert_eq!(message.len(), 26 + 2 + 1 + 32 + 8);
        reference_hmac(&psk_next, &message)
    };
    for (frame_type, raw_type) in [
        (FrameType::RATCHET_READY, 0x0002),
        (FrameType::RATCHET_COMMIT, 0x0003),
        (FrameType::RATCHET_ACK, 0x0004),
    ] {
        for (role, role_byte) in [(Role::Initiator, 0), (Role::Responder, 1)] {
            let next = Zeroizing::new(psk_next);
            assert_eq!(
                kdf::ratchet_confirmation(&next, frame_type, role, &session_id, generation_next),
                confirmation(raw_type, role_byte)?,
                "{frame_type:?} {role:?}"
            );
        }
    }
    // The initiator's real RatchetReady, opened under the session keys.
    let identity = initiator.start(&alice_local, START)?;
    let reply = {
        let mut authority: Authority<'_> = bob_store.session_authority(&alice_key)?;
        responder.receive(record_body(&identity[0]), &bob_local, &mut authority, START)?
    };
    let ready = {
        let mut authority: Authority<'_> = alice_store.session_authority(&bob_key)?;
        initiator.receive(record_body(&reply[0]), &alice_local, &mut authority, START)?
    };
    let Opened::Frame(frame_type, body) = responder
        .transport_mut()
        .open(record_body(&ready[0]), START)?
    else {
        return Err("expected a frame".into());
    };
    assert_eq!(frame_type, FrameType::RATCHET_READY);
    let mut expected = session_id.to_vec();
    expected.extend_from_slice(&generation_next.to_be_bytes());
    expected.extend_from_slice(&confirmation(0x0002, 0)?);
    assert_eq!(body.as_slice(), expected.as_slice());
    Ok(())
}
