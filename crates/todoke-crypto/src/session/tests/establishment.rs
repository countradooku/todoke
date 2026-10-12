//! End-to-end establishment through the sans-IO layers, and the §4.4
//! crash policy at every point of the transaction.

use super::support::*;
use crate::identity::VerificationState;
use crate::identity::contacts::Unavailable;
use crate::identity::{MemoryStorage, SoftwareSealer};
use crate::session::authority::testing::{Journal, Recording, ScriptedAuthority};
use crate::session::establish::Phase;
use crate::session::handshake::{CODE_OFFER_LEN, CODE_SHARE_LEN};
use crate::session::{
    CodeTranscript, ContactAuthority, FrameType, InitiatorPlan, PairingPsk, PeerAuthority,
    ResponderPlan, Role, SessionError, SessionMode, kdf,
};
use zeroize::Zeroizing;

const GENERATION: u64 = 7;
const LOCATOR: [u8; 16] = [0xb7; 16];

struct Contacts {
    alice: Device,
    bob: Device,
    /// Alice's store, pinning Bob.
    alice_store: Store,
    /// Bob's store, pinning Alice.
    bob_store: Store,
}

fn contacts() -> AnyResult<Contacts> {
    let alice = Device::new()?;
    let bob = Device::new()?;
    let alice_store = store_pairing(&bob, GENERATION)?;
    let bob_store = store_pairing(&alice, GENERATION)?;
    Ok(Contacts {
        alice,
        bob,
        alice_store,
        bob_store,
    })
}

type ContactAuth<'a> = ContactAuthority<'a, SoftwareSealer, MemoryStorage>;
type ContactHarness<'h, 'a, 'b> = Harness<'h, ContactAuth<'a>, ContactAuth<'b>>;

/// The handshake hash of each side whose gate opened.
type OpenHashes = (Option<[u8; 32]>, Option<[u8; 32]>);

fn drain_all(harness: &mut ContactHarness<'_, '_, '_>) {
    harness.drain();
}

/// Whether `side` holds a queued-but-unconfirmed `RatchetAck`.
fn ack_pending<A: PeerAuthority>(side: &Side<'_, A>) -> bool {
    matches!(&side.stage, Stage::Establish(establishment) if establishment.phase() == Phase::AckPending)
}

/// Alice initiates a contact session to Bob over the harness and `run`
/// drives it; returns `(alice_open_hash, bob_open_hash)`.
fn contact_run(
    c: &mut Contacts,
    defer_ack: bool,
    run: impl FnOnce(&mut ContactHarness<'_, '_, '_>),
) -> AnyResult<OpenHashes> {
    let alice_local = c.alice.local()?;
    let bob_local = c.bob.local()?;
    let bob_key = c.bob.key();
    let alice_key = c.alice.key();
    let generation = c
        .alice_store
        .contact(&bob_key)
        .ok_or("contact")?
        .generation();
    let initiator_authority = c.alice_store.session_authority(&bob_key)?;
    let plan = initiator_authority.initiator_plan(LOCATOR)?;
    let responder_authority = c.bob_store.session_authority(&alice_key)?;
    let hello =
        todoke_proto::session::Hello::client(SessionMode::Contact, generation, LOCATOR, [1; 16])?;
    let responder_plan = responder_authority.responder_plan(&hello)?;
    let initiator = Side::initiator(alice_local, initiator_authority);
    let mut responder = Side::responder(bob_local, responder_authority, responder_plan);
    responder.defer_ack = defer_ack;
    let mut harness = Harness::new(initiator, responder, plan)?;
    run(&mut harness);
    harness.finish();
    let hash = |core: Option<&mut crate::session::transport::SessionCore>| {
        core.map(|core| core.info().handshake_hash)
    };
    Ok((
        hash(harness.initiator.core()),
        hash(harness.responder.core()),
    ))
}

#[test]
fn contact_session_commits_the_same_ratchet_on_both_sides() -> TestResult {
    let mut c = contacts()?;
    let (alice, bob) = contact_run(&mut c, false, drain_all)?;
    let hash = alice.ok_or("initiator not open")?;
    assert_eq!(bob, Some(hash));
    let psk_next = kdf::psk_next(&hash, &OLD_PSK).map_err(|_| "kdf")?;
    for (store, peer) in [(&c.alice_store, c.bob.key()), (&c.bob_store, c.alice.key())] {
        assert_eq!(usable(store, &peer)?, Some((GENERATION + 1, *psk_next)));
        // Durable too: a restart loads the committed state.
        assert_eq!(
            usable(&reopen(store)?, &peer)?,
            Some((GENERATION + 1, *psk_next))
        );
        assert!(!store.contact(&peer).ok_or("contact")?.ratchet_pending());
    }
    // The next session uses the new generation and PSK and ratchets again.
    let (alice, bob) = contact_run(&mut c, false, drain_all)?;
    let second = alice.ok_or("second session")?;
    assert_eq!(bob, Some(second));
    assert_ne!(second, hash);
    let psk_third = kdf::psk_next(&second, &psk_next).map_err(|_| "kdf")?;
    assert_eq!(
        usable(&c.alice_store, &c.bob.key())?,
        Some((GENERATION + 2, *psk_third))
    );
    Ok(())
}

#[test]
fn application_frames_flow_once_the_gate_is_open() -> TestResult {
    let mut c = contacts()?;
    let alice_local = c.alice.local()?;
    let bob_local = c.bob.local()?;
    let (bob_key, alice_key) = (c.bob.key(), c.alice.key());
    let initiator_authority = c.alice_store.session_authority(&bob_key)?;
    let plan = initiator_authority.initiator_plan(LOCATOR)?;
    let responder_authority = c.bob_store.session_authority(&alice_key)?;
    let hello =
        todoke_proto::session::Hello::client(SessionMode::Contact, GENERATION, LOCATOR, [1; 16])?;
    let responder_plan = responder_authority.responder_plan(&hello)?;
    let mut harness = Harness::new(
        Side::initiator(alice_local, initiator_authority),
        Side::responder(bob_local, responder_authority, responder_plan),
        plan,
    )?;
    harness.drain();
    let now = harness.now;
    let core = harness.initiator.core().ok_or("open")?;
    assert_eq!(core.info().role, Role::Initiator);
    assert_eq!(core.info().peer_binding.device_public(), &bob_key);
    core.send(FrameType::CAPABILITIES, b"caps", now)?;
    let records: Vec<_> = core::iter::from_fn(|| core.pop_outgoing()).collect();
    let responder = harness.responder.core().ok_or("open")?;
    let frame = responder
        .receive(&records[0][2..], now)?
        .ok_or("no frame")?;
    assert_eq!(frame.body(), b"caps");
    Ok(())
}

fn transcript() -> CodeTranscript {
    CodeTranscript::new(
        [1; CODE_OFFER_LEN],
        [2; CODE_SHARE_LEN],
        [3; CODE_SHARE_LEN],
    )
}

#[test]
fn qr_and_code_sessions_complete_with_pairing_authorities() -> TestResult {
    let alice = Device::new()?;
    let bob = Device::new()?;
    let psk = || PairingPsk::from_bytes(Zeroizing::new([0x9a; 32]));
    for mode in [SessionMode::Qr, SessionMode::Code] {
        let (plan, responder_plan) = match mode {
            SessionMode::Qr => (
                InitiatorPlan::qr(LOCATOR, *bob.noise.public_key(), psk()),
                ResponderPlan::qr(psk()),
            ),
            _ => (
                InitiatorPlan::code_with_psk(LOCATOR, psk(), transcript()),
                ResponderPlan::code_with_psk(psk(), transcript()),
            ),
        };
        // The QR scanner pins the displayer's device key; the displayer and
        // both code parties rely on the PSK alone.
        let pin = (mode == SessionMode::Qr).then(|| bob.key());
        let mut harness = Harness::new(
            Side::initiator(alice.local()?, ScriptedAuthority::new(pin)),
            Side::responder(bob.local()?, ScriptedAuthority::new(None), responder_plan),
            plan,
        )?;
        harness.drain();
        assert!(
            harness.initiator.is_open() && harness.responder.is_open(),
            "{mode:?}"
        );
        let hash = harness
            .initiator
            .core()
            .ok_or("open")?
            .info()
            .handshake_hash;
        let psk_next = kdf::psk_next(&hash, &[0x9a; 32]).map_err(|_| "kdf")?;
        for authority in [&harness.initiator.authority, &harness.responder.authority] {
            assert_eq!(authority.journal, Journal::Cleared);
            assert_eq!(authority.committed_generation, Some(1));
            assert_eq!(authority.committed_psk.as_deref(), Some(&*psk_next));
        }
        assert_eq!(
            harness
                .responder
                .core()
                .ok_or("open")?
                .info()
                .peer_binding
                .device_public(),
            &alice.key()
        );
    }
    Ok(())
}

/// Each authority is shown exactly the authenticated peer and the §4.4
/// transaction (its own role, generation + 1, this session's `h`, the
/// verified peer), and neither view prints the next PSK.
#[test]
fn authorities_see_the_presented_peer_and_the_journaled_transaction() -> TestResult {
    let alice = Device::new()?;
    let bob = Device::new()?;
    let psk = || PairingPsk::from_bytes(Zeroizing::new([0x9a; 32]));
    let mut harness = Harness::new(
        Side::initiator(
            alice.local()?,
            Recording::new(ScriptedAuthority::new(Some(bob.key()))),
        ),
        Side::responder(
            bob.local()?,
            Recording::new(ScriptedAuthority::new(None)),
            ResponderPlan::qr(psk()),
        ),
        InitiatorPlan::qr(LOCATOR, *bob.noise.public_key(), psk()),
    )?;
    harness.drain();
    let hash = harness
        .initiator
        .core()
        .ok_or("initiator not open")?
        .info()
        .handshake_hash;
    assert!(harness.responder.is_open());
    let psk_next = kdf::psk_next(&hash, &[0x9a; 32]).map_err(|_| "kdf")?;
    for (authority, role, peer) in [
        (&harness.initiator.authority, Role::Initiator, &bob),
        (&harness.responder.authority, Role::Responder, &alice),
    ] {
        let presented = authority.presented.as_ref().ok_or("nothing presented")?;
        assert_eq!(presented.mode, SessionMode::Qr);
        assert_eq!(&presented.binding, peer.binding.binding());
        assert!(
            presented
                .debug
                .starts_with("PeerPresentation { mode: Qr, binding: ")
        );
        let journaled = authority.journaled.as_ref().ok_or("nothing journaled")?;
        assert_eq!(
            (
                journaled.role,
                journaled.generation_next,
                journaled.handshake_hash,
                journaled.peer
            ),
            (role, 1, hash, peer.key())
        );
        assert!(journaled.debug.starts_with(&format!(
            "PendingRatchet {{ role: {role:?}, generation_next: 1, peer: "
        )));
        for debug in [&presented.debug, &journaled.debug] {
            assert!(!debug.contains("psk"), "{debug}");
            assert!(!debug.contains(&format!("{:?}", &psk_next[..8])), "{debug}");
        }
    }
    Ok(())
}

/// A contact authority confirms peers of contact sessions only: used for a
/// QR attempt it refuses the peer, and the contact is left untouched.
#[test]
fn contact_authority_refuses_peers_of_pairing_sessions() -> TestResult {
    let mut c = contacts()?;
    let bob_key = c.bob.key();
    let psk = || PairingPsk::from_bytes(Zeroizing::new([0x9a; 32]));
    let alice_local = c.alice.local()?;
    let mut harness = Harness::new(
        Side::initiator(alice_local, c.alice_store.session_authority(&bob_key)?),
        Side::responder(
            c.bob.local()?,
            ScriptedAuthority::new(None),
            ResponderPlan::qr(psk()),
        ),
        InitiatorPlan::qr(LOCATOR, *c.bob.noise.public_key(), psk()),
    )?;
    harness.drain();
    harness.finish();
    assert_eq!(harness.initiator.error(), Some(SessionError::Usage));
    assert_eq!(harness.responder.authority.journal, Journal::Clean);
    drop(harness);
    assert_eq!(
        usable(&c.alice_store, &bob_key)?,
        Some((GENERATION, OLD_PSK))
    );
    assert!(
        !c.alice_store
            .contact(&bob_key)
            .ok_or("contact")?
            .ratchet_pending()
    );
    Ok(())
}

/// `Debug` of the local identity and of a contact authority is structural
/// and prints no secret key or PSK.
#[test]
fn identity_and_authority_debug_output_is_structural() -> TestResult {
    let mut c = contacts()?;
    let bob_key = c.bob.key();
    let local = c.alice.local()?;
    let debug = format!("{local:?}");
    assert!(debug.starts_with("LocalIdentity { device_key: "), "{debug}");
    assert!(
        debug.contains(&format!("device: {:?}", c.alice.key())),
        "{debug}"
    );
    assert!(debug.contains(&format!("checked_at: {:?}", local.checked_at())));
    assert!(
        !debug.contains(&format!("{:?}", c.alice.noise.secret())),
        "{debug}"
    );
    let authority = c.alice_store.session_authority(&bob_key)?;
    assert_eq!(authority.device(), &bob_key);
    let debug = format!("{authority:?}");
    assert_eq!(
        debug,
        format!("ContactAuthority {{ device: {bob_key:?}, .. }}")
    );
    Ok(())
}

#[test]
fn qr_pin_mismatch_fails_before_any_journal() -> TestResult {
    let alice = Device::new()?;
    let bob = Device::new()?;
    let psk = || PairingPsk::from_bytes(Zeroizing::new([0x9a; 32]));
    let mut harness = Harness::new(
        Side::initiator(alice.local()?, ScriptedAuthority::new(Some(alice.key()))),
        Side::responder(
            bob.local()?,
            ScriptedAuthority::new(None),
            ResponderPlan::qr(psk()),
        ),
        InitiatorPlan::qr(LOCATOR, *bob.noise.public_key(), psk()),
    )?;
    harness.drain();
    harness.finish();
    assert!(matches!(
        harness.initiator.error(),
        Some(SessionError::Identity(_))
    ));
    assert_eq!(harness.initiator.authority.journal, Journal::Clean);
    // The responder never got a Ready: its timeout leaves nothing journaled.
    assert_eq!(harness.responder.error(), Some(SessionError::Timeout));
    assert_eq!(harness.responder.authority.journal, Journal::Clean);
    Ok(())
}

/// A failing persistence step at the authority: before the journal the
/// pairing stays usable; from the journal on it is blocked.
#[test]
fn persistence_failure_at_each_step() -> TestResult {
    let alice = Device::new()?;
    let bob = Device::new()?;
    let psk = || PairingPsk::from_bytes(Zeroizing::new([0x9a; 32]));
    for (failing_side, step) in [(0, 1), (1, 1), (0, 2), (1, 2), (0, 3), (1, 3)] {
        let mut initiator_authority = ScriptedAuthority::new(None);
        let mut responder_authority = ScriptedAuthority::new(None);
        if failing_side == 0 {
            initiator_authority.fail_step = Some(step);
        } else {
            responder_authority.fail_step = Some(step);
        }
        let mut harness = Harness::new(
            Side::initiator(alice.local()?, initiator_authority),
            Side::responder(bob.local()?, responder_authority, ResponderPlan::qr(psk())),
            InitiatorPlan::qr(LOCATOR, *bob.noise.public_key(), psk()),
        )?;
        harness.drain();
        harness.finish();
        let (failed, other) = if failing_side == 0 {
            (&harness.initiator, &harness.responder)
        } else {
            (&harness.responder, &harness.initiator)
        };
        let label = format!("side {failing_side} step {step}");
        assert!(!failed.is_open(), "{label}");
        if step == 1 {
            // The journal write itself failed: nothing to abandon.
            assert!(
                matches!(failed.error(), Some(SessionError::Storage(_))),
                "{label}"
            );
            assert_eq!(failed.authority.journal, Journal::Clean, "{label}");
        } else {
            assert_eq!(
                failed.error(),
                Some(SessionError::RatchetUncertain),
                "{label}"
            );
            assert_eq!(failed.authority.journal, Journal::Abandoned, "{label}");
        }
        // The other side never ends usable with a commit its peer lacks,
        // except the responder, which opens once its Ack is queued.
        if other.is_open() {
            assert_eq!((failing_side, step), (0, 3), "{label}");
            assert_eq!(other.role, Role::Responder);
        }
    }
    Ok(())
}

/// Wrong generation in the Hello: reported locally, nothing retried, and
/// the stored pairing is unchanged on both sides.
#[test]
fn divergent_generation_is_reported_and_changes_nothing() -> TestResult {
    let mut c = contacts()?;
    let bob_key = c.bob.key();
    let alice_key = c.alice.key();
    let authority = c.bob_store.session_authority(&alice_key)?;
    let stale = todoke_proto::session::Hello::client(
        SessionMode::Contact,
        GENERATION - 1,
        LOCATOR,
        [1; 16],
    )?;
    assert_eq!(
        authority.responder_plan(&stale).map(|_| ()),
        Err(SessionError::GenerationMismatch)
    );
    let qr = todoke_proto::session::Hello::client(SessionMode::Qr, 0, LOCATOR, [1; 16])?;
    assert_eq!(
        authority.responder_plan(&qr).map(|_| ()),
        Err(SessionError::Usage)
    );
    assert_eq!(
        usable(&c.bob_store, &alice_key)?,
        Some((GENERATION, OLD_PSK))
    );
    assert_eq!(
        usable(&c.alice_store, &bob_key)?,
        Some((GENERATION, OLD_PSK))
    );
    Ok(())
}

#[test]
fn blocked_contacts_cannot_start_a_session() -> TestResult {
    let mut c = contacts()?;
    let bob_key = c.bob.key();
    c.alice_store.mark_ratchet_uncertain(&bob_key)?;
    assert_eq!(
        c.alice_store.session_authority(&bob_key).map(|_| ()).err(),
        Some(SessionError::Unavailable(Unavailable::RatchetUncertain))
    );
    let unknown = Device::new()?;
    assert!(matches!(
        c.alice_store.session_authority(&unknown.key()).map(|_| ()),
        Err(SessionError::Storage(_))
    ));
    Ok(())
}

/// How many records an honest contact run exchanges, in delivery order:
/// `(to_responder, …)` for each step of [`Harness::drain`]'s alternation.
fn honest_steps() -> AnyResult<Vec<bool>> {
    let mut c = contacts()?;
    let mut steps = Vec::new();
    contact_run(&mut c, true, |harness| {
        loop {
            if harness.deliver(true) {
                steps.push(true);
            } else if harness.deliver(false) {
                steps.push(false);
            } else if ack_pending(&harness.responder) {
                // The deferred "Ack queued" step counts as one step.
                harness.responder.confirm_ack(harness.now);
                steps.push(true);
            } else {
                break;
            }
        }
    })?;
    Ok(steps)
}

/// Crash either side after every prefix of the honest run (including
/// between the responder's Ack being queued and its marker being cleared),
/// let the survivor time out, restart both from durable state, and check
/// the §4.4 policy.
#[test]
fn crash_at_every_point_never_leaves_divergent_usable_pairings() -> TestResult {
    let steps = honest_steps()?;
    assert!(steps.len() >= 10, "{steps:?}");
    for crash_after in 0..=steps.len() {
        for victim in [Role::Initiator, Role::Responder] {
            let mut c = contacts()?;
            let (alice_open, bob_open) = contact_run(&mut c, true, |harness| {
                let mut taken = 0;
                while taken < crash_after {
                    if harness.deliver(true) || harness.deliver(false) {
                        taken += 1;
                    } else if ack_pending(&harness.responder) {
                        harness.responder.confirm_ack(harness.now);
                        taken += 1;
                    } else {
                        break;
                    }
                }
                match victim {
                    Role::Initiator => harness.initiator.crash(),
                    Role::Responder => harness.responder.crash(),
                }
                harness.drain();
                harness.responder.confirm_ack(harness.now);
                harness.drain();
            })?;
            let label = format!("crash {victim:?} after {crash_after}");
            check_policy(&c, alice_open.is_some(), bob_open.is_some(), &label)?;
        }
    }
    Ok(())
}

/// The §4.4 safety properties over both durable stores.
#[allow(clippy::too_many_arguments)]
pub(super) fn check_policy_stores(
    generation: u64,
    alice_store: &Store,
    bob_store: &Store,
    alice_key: &crate::identity::Ed25519PublicKey,
    bob_key: &crate::identity::Ed25519PublicKey,
    alice_open: bool,
    bob_open: bool,
    label: &str,
) -> TestResult {
    let alice_durable = reopen(alice_store)?;
    let bob_durable = reopen(bob_store)?;
    let alice_view = usable(&alice_durable, bob_key)?;
    let bob_view = usable(&bob_durable, alice_key)?;
    // Never two usable pairings that disagree, and never an old PSK next
    // to a new one: either both match, or at most one side is usable.
    if let (Some(a), Some(b)) = (alice_view, bob_view) {
        assert_eq!(a, b, "{label}: divergent usable pairings");
    }
    for (view, durable, peer, open) in [
        (alice_view, &alice_durable, bob_key, alice_open),
        (bob_view, &bob_durable, alice_key, bob_open),
    ] {
        let contact = durable.contact(peer).ok_or("contact")?;
        if let Some((stored, psk)) = view {
            assert!(
                (stored == generation && psk == OLD_PSK) || stored == generation + 1,
                "{label}: unexpected usable state"
            );
            if open {
                assert_eq!(stored, generation + 1, "{label}: open side not committed");
            }
        } else {
            assert_eq!(
                contact.state(),
                VerificationState::RatchetUncertain,
                "{label}"
            );
            assert!(!open || contact.generation() == generation + 1, "{label}");
        }
        assert!(
            !contact.ratchet_pending(),
            "{label}: journal survives a restart"
        );
    }
    Ok(())
}

fn check_policy(c: &Contacts, alice_open: bool, bob_open: bool, label: &str) -> TestResult {
    check_policy_stores(
        GENERATION,
        &c.alice_store,
        &c.bob_store,
        &c.alice.key(),
        &c.bob.key(),
        alice_open,
        bob_open,
        label,
    )
}

/// Dropping the honest `RatchetAck`: the responder is committed and open,
/// the initiator is uncertain and must re-pair (deliberately fail-closed).
#[test]
fn lost_ack_blocks_only_the_initiator() -> TestResult {
    let mut c = contacts()?;
    let (alice, bob) = contact_run(&mut c, false, |harness| {
        loop {
            // Deliver everything except the final record to the initiator
            // once the responder has opened.
            if harness.responder.is_open() {
                harness.to_initiator.clear();
                break;
            }
            if !(harness.deliver(true) || harness.deliver(false)) {
                break;
            }
        }
    })?;
    assert!(alice.is_none() && bob.is_some());
    let (alice_key, bob_key) = (c.alice.key(), c.bob.key());
    assert_eq!(usable(&c.alice_store, &bob_key)?, None);
    let restarted = reopen(&c.alice_store)?;
    assert_eq!(
        restarted.contact(&bob_key).ok_or("contact")?.state(),
        VerificationState::RatchetUncertain
    );
    assert_eq!(
        usable(&c.bob_store, &alice_key)?.map(|(generation, _)| generation),
        Some(GENERATION + 1)
    );
    check_policy(&c, false, true, "lost ack")
}

#[test]
fn error_frames_and_codes_are_not_sent_before_the_gate() -> TestResult {
    // A responder that fails identity checks closes silently: nothing goes
    // back to the initiator.
    let mut c = contacts()?;
    let (alice, bob) = contact_run(&mut c, false, |harness| {
        harness.deliver(true); // ClientHello
        harness.deliver(false); // ServerHello
        harness.deliver(true); // message 1
        harness.deliver(false); // message 2
        let identity = harness.to_responder.pop_front();
        if let Some(mut identity) = identity {
            let last = identity.len() - 1;
            identity[last] ^= 1;
            harness.deliver_bytes(true, &identity);
        }
        assert!(harness.to_initiator.is_empty(), "nothing is sent back");
    })?;
    assert!(alice.is_none() && bob.is_none());
    assert_eq!(
        usable(&c.bob_store, &c.alice.key())?,
        Some((GENERATION, OLD_PSK))
    );
    assert_eq!(
        usable(&c.alice_store, &c.bob.key())?,
        Some((GENERATION, OLD_PSK))
    );
    Ok(())
}

/// The session lifetime ends when the earlier binding expires, measured
/// from the time the session started, not from when the long-lived
/// `LocalIdentity` was built (§2).
#[test]
fn session_lifetime_is_computed_from_the_session_start_time() -> TestResult {
    use crate::identity::binding::CLOCK_SKEW_SECONDS;
    use crate::identity::test_support::{DAY, T0, time};
    use crate::session::WallClock;
    let alice = Device::valid_until(T0 + 300 * DAY)?;
    let bob = Device::new()?;
    let mut alice_store = store_pairing(&bob, GENERATION)?;
    let mut bob_store = store_pairing(&alice, GENERATION)?;
    let (alice_key, bob_key) = (alice.key(), bob.key());
    // 100 seconds before Bob's binding expires.
    let bob_expiry = T0 + 30 * DAY;
    let started = WallClock::new(time(bob_expiry - 100)?, START);
    let initiator_authority = alice_store.session_authority(&bob_key)?;
    let plan = initiator_authority.initiator_plan(LOCATOR)?;
    let responder_authority = bob_store.session_authority(&alice_key)?;
    let hello =
        todoke_proto::session::Hello::client(SessionMode::Contact, GENERATION, LOCATOR, [1; 16])?;
    let responder_plan = responder_authority.responder_plan(&hello)?;
    // Both identities were built long ago, at WALL.
    let mut initiator = Side::initiator(alice.local()?, initiator_authority);
    let mut responder = Side::responder(bob.local()?, responder_authority, responder_plan);
    initiator.wall = started;
    responder.wall = started;
    let mut harness = Harness::new(initiator, responder, plan)?;
    harness.drain();
    let expected = START + core::time::Duration::from_secs(100 + CLOCK_SKEW_SECONDS);
    for side in [
        harness
            .initiator
            .core()
            .ok_or("initiator open")?
            .hard_deadline(),
        harness
            .responder
            .core()
            .ok_or("responder open")?
            .hard_deadline(),
    ] {
        assert_eq!(side, expected);
    }
    Ok(())
}

/// §4.4: generation overflow requires a new pairing. A contact whose
/// generation reached `u64::MAX` is blocked before any handshake, durably
/// (the block survives a restart), until it is explicitly re-paired.
#[test]
fn exhausted_generation_blocks_the_contact_until_re_pairing() -> TestResult {
    let alice = Device::new()?;
    let bob = Device::new()?;
    let mut c = Contacts {
        alice_store: store_pairing(&bob, u64::MAX - 1)?,
        bob_store: store_pairing(&alice, u64::MAX - 1)?,
        alice,
        bob,
    };
    // The last possible ratchet commits u64::MAX on both sides.
    let (alice_open, bob_open) = contact_run(&mut c, false, drain_all)?;
    assert!(alice_open.is_some() && bob_open.is_some());
    let (alice_key, bob_key) = (c.alice.key(), c.bob.key());
    for (store, peer) in [
        (&mut c.alice_store, &bob_key),
        (&mut c.bob_store, &alice_key),
    ] {
        assert_eq!(store.contact(peer).ok_or("contact")?.generation(), u64::MAX);
        // No further session can start, as initiator or responder.
        assert_eq!(
            store.session_authority(peer).map(|_| ()).err(),
            Some(SessionError::GenerationExhausted)
        );
        assert_eq!(
            store.availability(peer)?.map(|_| ()).err(),
            Some(Unavailable::GenerationExhausted)
        );
        // Durable: a restart loads the same block.
        let restarted = reopen(store)?;
        assert_eq!(
            restarted.availability(peer)?.map(|_| ()).err(),
            Some(Unavailable::GenerationExhausted)
        );
    }
    // Explicit re-pairing starts a new generation and unblocks it.
    c.alice_store.pair(
        &c.bob.binding,
        crate::identity::TrustOrigin::QrPairing,
        crate::identity::contacts::PairPsk::new([0x42; 32]),
        0,
        crate::identity::test_support::time(WALL)?,
    )?;
    assert_eq!(usable(&c.alice_store, &bob_key)?, Some((0, [0x42; 32])));
    Ok(())
}

/// Blob storage that fails every write once switched.
#[derive(Default)]
struct Flaky {
    blob: Option<Vec<u8>>,
    fail: std::rc::Rc<std::cell::Cell<bool>>,
}

impl crate::identity::BlobStorage for Flaky {
    fn load(
        &self,
        max_len: usize,
    ) -> Result<Option<Vec<u8>>, crate::identity::storage::StorageError> {
        Ok(self.blob.clone().filter(|blob| blob.len() <= max_len))
    }

    fn store(&mut self, bytes: &[u8]) -> Result<(), crate::identity::storage::StorageError> {
        if self.fail.get() {
            return Err(crate::identity::storage::StorageError::Io(
                std::io::ErrorKind::Other,
            ));
        }
        self.blob = Some(bytes.to_vec());
        Ok(())
    }
}

/// A contact store whose writes fail during the session: a failed identity
/// update (a renewed peer binding) or a failed journal write surfaces as
/// [`SessionError::Storage`], nothing is journaled durably, and the durable
/// pairing stays at the old generation and PSK.
#[test]
fn contact_store_write_failures_surface_as_storage_errors() -> TestResult {
    for renewed in [true, false] {
        let alice = Device::new()?;
        let bob = Device::new()?;
        let fail = std::rc::Rc::new(std::cell::Cell::new(false));
        let mut alice_store = crate::identity::ContactStore::open(
            crate::identity::test_support::sealer(9),
            Flaky {
                blob: None,
                fail: std::rc::Rc::clone(&fail),
            },
        )?;
        alice_store.pair(
            &bob.binding,
            crate::identity::TrustOrigin::QrPairing,
            crate::identity::contacts::PairPsk::new(OLD_PSK),
            GENERATION,
            crate::identity::test_support::time(crate::identity::test_support::T0)?,
        )?;
        let mut bob_store = store_pairing(&alice, GENERATION)?;
        // A renewed binding of Bob's (serial 2) makes Alice's store record
        // the newer serial, which is a write.
        let bob_binding = if renewed {
            bob.enrolled.bind_noise(2, *bob.noise.public_key())?
        } else {
            bob.binding.clone()
        };
        let bob_local = crate::session::LocalIdentity::new(
            &bob.enrolled.store,
            bob.enrolled.device,
            &bob_binding,
            &bob.noise,
            todoke_proto::time::UnixTime::new(WALL).ok_or("time")?,
        )?;
        let (bob_key, alice_key) = (bob.key(), alice.key());
        let initiator_authority = alice_store.session_authority(&bob_key)?;
        let plan = initiator_authority.initiator_plan(LOCATOR)?;
        let responder_authority = bob_store.session_authority(&alice_key)?;
        let hello = todoke_proto::session::Hello::client(
            SessionMode::Contact,
            GENERATION,
            LOCATOR,
            [1; 16],
        )?;
        let responder_plan = responder_authority.responder_plan(&hello)?;
        let mut harness = Harness::new(
            Side::initiator(alice.local()?, initiator_authority),
            Side::responder(bob_local, responder_authority, responder_plan),
            plan,
        )?;
        fail.set(true);
        harness.drain();
        harness.finish();
        assert!(
            matches!(harness.initiator.error(), Some(SessionError::Storage(_))),
            "renewed {renewed}: {:?}",
            harness.initiator.error()
        );
        drop(harness);
        // Durable state: still the old pairing, no journal.
        let mut storage = MemoryStorage::new();
        storage.set_blob(alice_store.storage().blob.clone());
        let durable =
            crate::identity::ContactStore::open(crate::identity::test_support::sealer(9), storage)?;
        assert_eq!(
            usable(&durable, &bob_key)?,
            Some((GENERATION, OLD_PSK)),
            "renewed {renewed}"
        );
        assert_eq!(usable(&bob_store, &alice_key)?, Some((GENERATION, OLD_PSK)));
    }
    Ok(())
}
