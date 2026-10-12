//! Forged Identity and ratchet records under the real session keys.

use super::*;
use crate::identity::test_support::{DAY, T0, request, time};
use crate::identity::{BindingError, VerificationState};
use crate::identity::{IdentityError, MemoryStorage, SoftwareSealer, issue_device_binding};
use crate::session::ContactAuthority;
use crate::session::NoiseStaticKey;
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
