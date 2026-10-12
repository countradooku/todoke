//! The async adapter over an in-memory duplex pipe, with a minimal
//! executor and controllable timers (no runtime dependency).

use core::future::Future;
use core::pin::{Pin, pin};
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};
use std::task::Wake;

use futures_io::{AsyncRead, AsyncWrite};
use zeroize::Zeroizing;

use super::support::*;
use crate::identity::contacts::PairOutcome;
use crate::identity::contacts::Unavailable;
use crate::pairing::{PairingOffers, QrPayload};
use crate::session::authority::testing::ScriptedAuthority;
use crate::session::{
    ErrorCode, ErrorRecord, ErrorScope, FrameType, IncomingSession, InitiatorPlan, PairingPsk,
    ResponderPlan, Role, Session, SessionError, SessionMode, Timer, UnauditedSuite0001,
};

const GENERATION: u64 = 2;
const LOCATOR: [u8; 16] = [0xa7; 16];
const GATE: UnauditedSuite0001 = UnauditedSuite0001::acknowledge_not_production_ready();

#[derive(Default)]
struct Shared {
    buffer: VecDeque<u8>,
    reader: Option<Waker>,
    writer: Option<Waker>,
    closed: bool,
}

/// One direction of the pipe, with a bounded buffer.
#[derive(Clone)]
struct Channel {
    shared: Arc<Mutex<Shared>>,
    capacity: usize,
}

impl Channel {
    fn new(capacity: usize) -> Self {
        Self {
            shared: Arc::default(),
            capacity,
        }
    }

    fn lock(&self) -> io::Result<std::sync::MutexGuard<'_, Shared>> {
        self.shared.lock().map_err(|_| io::Error::other("poisoned"))
    }
}

/// One end of an in-memory duplex byte pipe.
struct End {
    incoming: Channel,
    outgoing: Channel,
}

fn duplex(capacity: usize) -> (End, End) {
    let a = Channel::new(capacity);
    let b = Channel::new(capacity);
    (
        End {
            incoming: a.clone(),
            outgoing: b.clone(),
        },
        End {
            incoming: b,
            outgoing: a,
        },
    )
}

impl AsyncRead for End {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let mut shared = self.incoming.lock()?;
        if shared.buffer.is_empty() {
            if shared.closed {
                return Poll::Ready(Ok(0));
            }
            shared.reader = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let count = buf.len().min(shared.buffer.len());
        for (slot, byte) in buf.iter_mut().zip(shared.buffer.drain(..count)) {
            *slot = byte;
        }
        if let Some(writer) = shared.writer.take() {
            writer.wake();
        }
        Poll::Ready(Ok(count))
    }
}

impl AsyncWrite for End {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let capacity = self.outgoing.capacity;
        let mut shared = self.outgoing.lock()?;
        if shared.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let room = capacity.saturating_sub(shared.buffer.len());
        if room == 0 {
            shared.writer = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let count = room.min(buf.len());
        shared.buffer.extend(&buf[..count]);
        if let Some(reader) = shared.reader.take() {
            reader.wake();
        }
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl Drop for End {
    fn drop(&mut self) {
        for channel in [&self.incoming, &self.outgoing] {
            if let Ok(mut shared) = channel.lock() {
                shared.closed = true;
                for waker in [shared.reader.take(), shared.writer.take()]
                    .into_iter()
                    .flatten()
                {
                    waker.wake();
                }
            }
        }
    }
}

/// A clock that only moves when told to; sleeps complete once it passes
/// their deadline (the executor re-polls periodically).
#[derive(Clone, Default)]
struct ManualTimer(Arc<Mutex<Duration>>);

impl ManualTimer {
    fn at(start: Duration) -> Self {
        Self(Arc::new(Mutex::new(start)))
    }

    fn advance(&self, by: Duration) {
        if let Ok(mut now) = self.0.lock() {
            *now += by;
        }
    }
}

struct ManualSleep {
    timer: ManualTimer,
    deadline: Duration,
}

impl Future for ManualSleep {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        if self.timer.now() >= self.deadline {
            Poll::Ready(())
        } else {
            Poll::Pending
        }
    }
}

impl Timer for ManualTimer {
    type Sleep = ManualSleep;

    fn now(&self) -> Duration {
        self.0.lock().map_or(Duration::ZERO, |now| *now)
    }

    fn sleep_until(&self, deadline: Duration) -> ManualSleep {
        ManualSleep {
            timer: self.clone(),
            deadline,
        }
    }
}

/// A clock that jumps straight to any deadline a sleep waits for: every
/// wait times out at once, which exercises each deadline path quickly.
#[derive(Clone, Default)]
struct JumpingTimer(ManualTimer);

struct JumpingSleep(ManualSleep);

impl Future for JumpingSleep {
    type Output = ();
    fn poll(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<()> {
        if let Ok(mut now) = self.0.timer.0.lock() {
            *now = (*now).max(self.0.deadline);
        }
        Poll::Ready(())
    }
}

impl Timer for JumpingTimer {
    type Sleep = JumpingSleep;

    fn now(&self) -> Duration {
        self.0.now()
    }

    fn sleep_until(&self, deadline: Duration) -> JumpingSleep {
        JumpingSleep(self.0.sleep_until(deadline))
    }
}

struct Unpark(std::thread::Thread);

impl Wake for Unpark {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
}

/// Polls two futures to completion on this thread.
fn join<A: Future, B: Future>(a: A, b: B) -> AnyResult<(A::Output, B::Output)> {
    let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    let (mut a, mut b) = (pin!(a), pin!(b));
    let (mut a_out, mut b_out) = (None, None);
    for _ in 0..200_000 {
        if a_out.is_none()
            && let Poll::Ready(value) = a.as_mut().poll(&mut cx)
        {
            a_out = Some(value);
        }
        if b_out.is_none()
            && let Poll::Ready(value) = b.as_mut().poll(&mut cx)
        {
            b_out = Some(value);
        }
        if let (Some(_), Some(_)) = (&a_out, &b_out) {
            return Ok((a_out.ok_or("a")?, b_out.ok_or("b")?));
        }
        std::thread::park_timeout(Duration::from_micros(200));
    }
    Err("futures did not complete".into())
}

fn block_on<F: Future>(future: F) -> AnyResult<F::Output> {
    Ok(join(future, async {})?.0)
}

fn contacts() -> AnyResult<(Device, Device, Store, Store)> {
    let alice = Device::new()?;
    let bob = Device::new()?;
    let alice_store = store_pairing(&bob, GENERATION)?;
    let bob_store = store_pairing(&alice, GENERATION)?;
    Ok((alice, bob, alice_store, bob_store))
}

type Established<T> = (Session<End, T>, Session<End, T>);

/// Runs a full contact session over the pipe with `timer`.
fn contact_sessions<T: Timer + Clone>(
    alice: &Device,
    bob: &Device,
    alice_store: &mut Store,
    bob_store: &mut Store,
    timer: &T,
) -> AnyResult<Established<T>> {
    contact_sessions_with(alice, bob, alice_store, bob_store, timer, 1 << 20)
}

fn contact_sessions_with<T: Timer + Clone>(
    alice: &Device,
    bob: &Device,
    alice_store: &mut Store,
    bob_store: &mut Store,
    timer: &T,
    capacity: usize,
) -> AnyResult<Established<T>> {
    let wall = crate::identity::test_support::time(WALL)?;
    let (alice_end, bob_end) = duplex(capacity);
    let (alice_local, bob_local) = (alice.local()?, bob.local()?);
    let (alice_key, bob_key) = (alice.key(), bob.key());
    let mut initiator_authority = alice_store.session_authority(&bob_key)?;
    let plan = initiator_authority.initiator_plan(LOCATOR)?;
    let initiator = Session::initiate(
        alice_end,
        timer.clone(),
        GATE,
        &alice_local,
        wall,
        plan,
        &mut initiator_authority,
    );
    let responder = async {
        let incoming = IncomingSession::accept(bob_end, timer.clone(), GATE).await?;
        assert_eq!(incoming.client_hello().mode(), SessionMode::Contact);
        assert_eq!(incoming.client_hello().locator(), &LOCATOR);
        let mut authority = bob_store.session_authority(&alice_key)?;
        let plan = authority.responder_plan(incoming.client_hello())?;
        incoming
            .respond(&bob_local, wall, plan, &mut authority)
            .await
    };
    let (initiator, responder) = join(initiator, responder)?;
    Ok((initiator?, responder?))
}

#[test]
fn contact_session_over_a_byte_pipe() -> TestResult {
    let (alice, bob, mut alice_store, mut bob_store) = contacts()?;
    let timer = ManualTimer::at(START);
    let (mut a, mut b) = contact_sessions(&alice, &bob, &mut alice_store, &mut bob_store, &timer)?;
    assert_eq!(a.role(), Role::Initiator);
    assert_eq!(b.role(), Role::Responder);
    assert_eq!(a.mode(), SessionMode::Contact);
    assert_eq!(a.handshake_hash(), b.handshake_hash());
    assert_eq!(a.session_id(), b.session_id());
    // session_id = B3("todoke/v1/session\0" || h) (§4.2.6).
    let mut session_input = b"todoke/v1/session\x00".to_vec();
    session_input.extend_from_slice(a.handshake_hash());
    assert_eq!(a.session_id(), blake3::hash(&session_input).as_bytes());
    assert_eq!(a.peer_static(), bob.noise.public_key());
    assert_eq!(b.peer_static(), alice.noise.public_key());
    assert_eq!(a.peer_binding().device_public(), &bob.key());
    assert!(!a.is_closed());
    // Both stores committed the same next generation and PSK.
    let next = crate::session::kdf::psk_next(a.handshake_hash(), &OLD_PSK).map_err(|_| "kdf")?;
    assert_eq!(
        usable(&alice_store, &bob.key())?,
        Some((GENERATION + 1, *next))
    );
    assert_eq!(
        usable(&bob_store, &alice.key())?,
        Some((GENERATION + 1, *next))
    );
    // Frames both ways, an explicit rekey, and frames after it.
    block_on(a.send(FrameType::CAPABILITIES, b"alice caps"))??;
    let frame = block_on(b.recv())??;
    assert_eq!(
        (frame.frame_type(), frame.body()),
        (FrameType::CAPABILITIES, &b"alice caps"[..])
    );
    block_on(b.send(FrameType::CAPABILITIES, b"bob caps"))??;
    assert_eq!(block_on(a.recv())??.body(), b"bob caps");
    block_on(a.rekey())??;
    assert_eq!(block_on(a.rekey())?, Err(SessionError::RekeyTooSoon));
    let big = vec![0x5a; todoke_proto::session::MAX_BODY_LEN];
    block_on(a.send(FrameType::new(0x0016), &big))??;
    assert_eq!(block_on(b.recv())??.body(), big.as_slice());
    assert_eq!(
        block_on(a.send(FrameType::PING, b"")).map_err(|e| e.to_string())?,
        Err(SessionError::Usage)
    );
    // A transfer-scoped Error passes through; a session-scoped one closes.
    let transfer = ErrorRecord::new(ErrorScope::Transfer([1; 16]), ErrorCode::STORAGE)?;
    block_on(b.send_error(transfer))??;
    assert_eq!(ErrorRecord::decode(block_on(a.recv())??.body())?, transfer);
    block_on(b.send_error(ErrorRecord::new(ErrorScope::Session, ErrorCode::STATE)?))??;
    assert!(b.is_closed());
    assert_eq!(
        block_on(a.recv())?.map(|_| ()),
        Err(SessionError::PeerError(ErrorCode::STATE))
    );
    assert!(a.is_closed());
    assert_eq!(
        block_on(a.send(FrameType::CAPABILITIES, b"")).map_err(|e| e.to_string())?,
        Err(SessionError::Closed)
    );
    assert!(format!("{a:?}").contains("Session"));
    Ok(())
}

/// Real QR pairing over the pipe: the displayer offers, the scanner reads
/// the QR text, the displayer reserves its offer for the incoming Hello,
/// and both create the contact.
#[test]
fn qr_pairing_over_a_byte_pipe() -> TestResult {
    let wall = crate::identity::test_support::time(WALL)?;
    let alice = Device::new()?;
    let bob = Device::new()?;
    let mut alice_store = empty_store()?;
    let mut bob_store = empty_store()?;
    let timer = ManualTimer::at(START);
    let offers = PairingOffers::new();
    let text = offers
        .create_qr(&bob.local()?, wall, timer.now())?
        .to_text();
    let payload = QrPayload::from_text(&text, wall)?;
    let (alice_end, bob_end) = duplex(4096);
    let (alice_local, bob_local) = (alice.local()?, bob.local()?);
    let (plan, mut initiator_authority) = alice_store.begin_qr_pairing(&payload, wall)?;
    let initiator = Session::initiate(
        alice_end,
        timer.clone(),
        GATE,
        &alice_local,
        wall,
        plan,
        &mut initiator_authority,
    );
    let responder = async {
        let incoming = IncomingSession::accept(bob_end, timer.clone(), GATE).await?;
        let reservation = offers.reserve(incoming.client_hello(), wall, timer.now())?;
        let (plan, mut authority) = reservation.into_qr_responder(&mut bob_store)?;
        let session = incoming
            .respond(&bob_local, wall, plan, &mut authority)
            .await?;
        Ok::<_, Box<dyn std::error::Error>>((session, authority.outcome()))
    };
    let (a, b) = join(initiator, responder)?;
    let (a, (b, outcome)) = (a?, b?);
    assert_eq!(a.mode(), SessionMode::Qr);
    assert_eq!(a.handshake_hash(), b.handshake_hash());
    assert_eq!(b.peer_binding().device_public(), &alice.key());
    assert_eq!(outcome, Some(PairOutcome::New));
    assert_eq!(initiator_authority.outcome(), Some(PairOutcome::New));
    drop(initiator_authority);
    let next =
        crate::session::kdf::psk_next(a.handshake_hash(), payload.psk()).map_err(|_| "kdf")?;
    assert_eq!(usable(&alice_store, &bob.key())?, Some((1, *next)));
    assert_eq!(usable(&bob_store, &alice.key())?, Some((1, *next)));
    Ok(())
}

/// The code-mode handshake over the pipe with a synthetic transcript and
/// PSK, through the scripted authority (no `CPace`).
#[test]
fn synthetic_code_session_over_a_byte_pipe() -> TestResult {
    let wall = crate::identity::test_support::time(WALL)?;
    let alice = Device::new()?;
    let bob = Device::new()?;
    let psk = || PairingPsk::from_bytes(Zeroizing::new([0x6b; 32]));
    let transcript = || {
        crate::session::CodeTranscript::new(
            [1; crate::session::handshake::CODE_OFFER_LEN],
            [2; crate::session::handshake::CODE_SHARE_LEN],
            [3; crate::session::handshake::CODE_SHARE_LEN],
        )
    };
    let timer = ManualTimer::at(START);
    let (alice_end, bob_end) = duplex(4096);
    let (alice_local, bob_local) = (alice.local()?, bob.local()?);
    let plan = InitiatorPlan::code_with_psk(LOCATOR, psk(), transcript());
    let mut initiator_authority = ScriptedAuthority::new(Some(bob.key()));
    let mut responder_authority = ScriptedAuthority::new(None);
    let initiator = Session::initiate(
        alice_end,
        timer.clone(),
        GATE,
        &alice_local,
        wall,
        plan,
        &mut initiator_authority,
    );
    let responder = async {
        let incoming = IncomingSession::accept(bob_end, timer.clone(), GATE).await?;
        let plan = ResponderPlan::code_with_psk(psk(), transcript());
        incoming
            .respond(&bob_local, wall, plan, &mut responder_authority)
            .await
    };
    let (a, b) = join(initiator, responder)?;
    let (a, b) = (a?, b?);
    assert_eq!(a.mode(), SessionMode::Code);
    assert_eq!(a.handshake_hash(), b.handshake_hash());
    assert_eq!(b.peer_binding().device_public(), &alice.key());
    assert_eq!(initiator_authority.committed_generation, Some(1));
    assert_eq!(responder_authority.committed_generation, Some(1));
    Ok(())
}

fn empty_store() -> AnyResult<Store> {
    Ok(crate::identity::ContactStore::open(
        crate::identity::test_support::sealer(9),
        crate::identity::MemoryStorage::new(),
    )?)
}

#[test]
fn rejected_or_mismatched_attempts_change_nothing() -> TestResult {
    let wall = crate::identity::test_support::time(WALL)?;
    let (alice, bob, mut alice_store, mut bob_store) = contacts()?;
    // Bob's store is one generation behind: Bob reports it locally and
    // drops the stream; Alice sees the stream close.
    bob_store.mark_ratchet_uncertain(&alice.key())?;
    let timer = ManualTimer::at(START);
    let (alice_end, bob_end) = duplex(4096);
    let alice_local = alice.local()?;
    let bob_key = bob.key();
    let alice_key = alice.key();
    let mut authority = alice_store.session_authority(&bob_key)?;
    let plan = authority.initiator_plan(LOCATOR)?;
    let initiator = Session::initiate(
        alice_end,
        timer.clone(),
        GATE,
        &alice_local,
        wall,
        plan,
        &mut authority,
    );
    let responder = async {
        let incoming = IncomingSession::accept(bob_end, timer.clone(), GATE).await?;
        let refusal = bob_store.session_authority(&alice_key).map(|_| ());
        drop(incoming.reject());
        refusal
    };
    let (initiator, responder) = join(initiator, responder)?;
    assert_eq!(
        responder,
        Err(SessionError::Unavailable(Unavailable::RatchetUncertain))
    );
    assert_eq!(initiator.map(|_| ()), Err(SessionError::Closed));
    assert_eq!(usable(&alice_store, &bob_key)?, Some((GENERATION, OLD_PSK)));
    Ok(())
}

#[test]
fn deadlines_fire_through_the_timer() -> TestResult {
    let wall = crate::identity::test_support::time(WALL)?;
    let (alice, bob, mut alice_store, _) = contacts()?;
    // Nobody answers: the handshake times out after 30 seconds.
    let timer = JumpingTimer::default();
    let (alice_end, _silent) = duplex(4096);
    let alice_local = alice.local()?;
    let bob_key = bob.key();
    let mut authority = alice_store.session_authority(&bob_key)?;
    let plan = authority.initiator_plan(LOCATOR)?;
    let result = block_on(Session::initiate(
        alice_end,
        timer.clone(),
        GATE,
        &alice_local,
        wall,
        plan,
        &mut authority,
    ))?;
    assert_eq!(result.map(|_| ()), Err(SessionError::Timeout));
    assert_eq!(timer.now(), crate::session::HANDSHAKE_TIMEOUT);
    // A listener without a ClientHello gives up too.
    let (listener_end, _quiet) = duplex(4096);
    let accepted = block_on(IncomingSession::accept(
        listener_end,
        JumpingTimer::default(),
        GATE,
    ))?;
    assert_eq!(accepted.map(|_| ()).err(), Some(SessionError::Timeout));
    Ok(())
}

#[test]
fn idle_peer_is_pinged_then_timed_out() -> TestResult {
    let (alice, bob, mut alice_store, mut bob_store) = contacts()?;
    let manual = ManualTimer::at(START);
    let (mut a, mut b) = contact_sessions(&alice, &bob, &mut alice_store, &mut bob_store, &manual)?;
    // Bob stays silent; Alice's recv sends a Ping at 30 s and gives up 10 s
    // later, telling Bob why.
    manual.advance(crate::session::PING_AFTER);
    let alice_recv = a.recv();
    let advance = async {
        // Let Alice send the Ping, then move past the Pong deadline.
        for _ in 0..3 {
            futures_yield().await;
        }
        manual.advance(crate::session::PONG_TIMEOUT);
    };
    let (received, ()) = join(alice_recv, advance)?;
    assert_eq!(received.map(|_| ()), Err(SessionError::Timeout));
    // Bob answers the Ping automatically and then sees Alice's Error.
    assert_eq!(
        block_on(b.recv())?.map(|_| ()),
        Err(SessionError::PeerError(ErrorCode::TIMEOUT))
    );
    Ok(())
}

/// Yields once to the executor.
async fn futures_yield() {
    let mut yielded = false;
    std::future::poll_fn(|cx| {
        if yielded {
            Poll::Ready(())
        } else {
            yielded = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    })
    .await;
}

/// A write cancelled midway leaves the session unusable (§5): a partial
/// record must not be followed by another on the same cipher state.
#[test]
fn cancelled_write_closes_the_session() -> TestResult {
    let (alice, bob, mut alice_store, mut bob_store) = contacts()?;
    let timer = ManualTimer::at(START);
    let (mut a, _b) =
        contact_sessions_with(&alice, &bob, &mut alice_store, &mut bob_store, &timer, 8192)?;
    // The pipe holds 8 KiB, so a 64 KiB frame cannot be written completely.
    let big = vec![1; todoke_proto::session::MAX_BODY_LEN];
    {
        let mut send = pin!(a.send(FrameType::new(0x0016), &big));
        let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
        let mut cx = Context::from_waker(&waker);
        assert!(
            send.as_mut().poll(&mut cx).is_pending(),
            "the pipe applies back-pressure"
        );
    }
    assert_eq!(
        block_on(a.send(FrameType::CAPABILITIES, b"x"))?,
        Err(SessionError::Closed)
    );
    assert!(a.is_closed());
    Ok(())
}

#[test]
fn local_identity_must_be_consistent_and_current() -> TestResult {
    let alice = Device::new()?;
    let bob = Device::new()?;
    let check = |device: &crate::identity::KeyId, binding, noise, wall| {
        crate::session::LocalIdentity::new(
            &alice.enrolled.store,
            *device,
            binding,
            noise,
            todoke_proto::time::UnixTime::new(wall).ok_or(SessionError::Usage)?,
        )
        .map(|_| ())
    };
    assert!(check(&alice.enrolled.device, &alice.binding, &alice.noise, WALL).is_ok());
    assert_eq!(
        check(&alice.enrolled.device, &alice.binding, &bob.noise, WALL),
        Err(SessionError::LocalIdentity)
    );
    assert_eq!(
        check(&alice.enrolled.device, &bob.binding, &bob.noise, WALL),
        Err(SessionError::LocalIdentity)
    );
    assert_eq!(
        check(&alice.enrolled.root, &alice.binding, &alice.noise, WALL),
        Err(SessionError::LocalIdentity)
    );
    let expired = crate::identity::test_support::T0 + 40 * crate::identity::test_support::DAY;
    assert_eq!(
        check(
            &alice.enrolled.device,
            &alice.binding,
            &alice.noise,
            expired
        ),
        Err(SessionError::LocalIdentity)
    );
    let local = alice.local()?;
    assert!(!format!("{local:?}").contains("noise"));
    Ok(())
}

/// A daemon keeps one `LocalIdentity` for a long time. A session started
/// later must check the local binding, and verify the peer's, at the time it
/// is given, not at the time the identity was built (§2).
#[test]
fn sessions_use_the_current_time_not_the_identity_build_time() -> TestResult {
    use crate::identity::test_support::{DAY, T0, time};
    // Alice's binding lasts 300 days, Bob's 30. Both identities are built
    // at WALL, one minute after T0; the sessions run 40 days later.
    let alice = Device::valid_until(T0 + 300 * DAY)?;
    let bob = Device::new()?;
    let mut alice_store = store_pairing(&bob, GENERATION)?;
    let mut bob_store = store_pairing(&alice, GENERATION)?;
    let (alice_local, bob_local) = (alice.local()?, bob.local()?);
    let (alice_key, bob_key) = (alice.key(), bob.key());
    let later = time(T0 + 40 * DAY)?;

    // Bob's own binding has expired by then: nothing is sent.
    let (bob_end, mut alice_end) = duplex(4096);
    let mut authority = bob_store.session_authority(&alice_key)?;
    let plan = authority.initiator_plan(LOCATOR)?;
    let refused = block_on(Session::initiate(
        bob_end,
        ManualTimer::at(START),
        GATE,
        &bob_local,
        later,
        plan,
        &mut authority,
    ))?;
    assert_eq!(refused.map(|_| ()).err(), Some(SessionError::LocalIdentity));
    let mut byte = [0; 1];
    let read =
        Pin::new(&mut alice_end).poll_read(&mut Context::from_waker(Waker::noop()), &mut byte);
    assert!(matches!(read, Poll::Ready(Ok(0))), "nothing was written");

    // Alice's binding is still valid, but Bob's (presented by a peer whose
    // clock is behind) expired: Alice must reject it before any journal.
    let timer = ManualTimer::at(START);
    let (alice_end, bob_end) = duplex(1 << 20);
    let wall = time(WALL)?;
    let mut initiator_authority = alice_store.session_authority(&bob_key)?;
    let plan = initiator_authority.initiator_plan(LOCATOR)?;
    let initiator = Session::initiate(
        alice_end,
        timer.clone(),
        GATE,
        &alice_local,
        later,
        plan,
        &mut initiator_authority,
    );
    let responder = async {
        let incoming = IncomingSession::accept(bob_end, timer.clone(), GATE).await?;
        let mut authority = bob_store.session_authority(&alice_key)?;
        let plan = authority.responder_plan(incoming.client_hello())?;
        incoming
            .respond(&bob_local, wall, plan, &mut authority)
            .await
    };
    let (initiator, responder) = join(initiator, responder)?;
    assert!(
        matches!(
            initiator.map(|_| ()),
            Err(SessionError::Identity(
                crate::identity::IdentityError::Binding(_)
            ))
        ),
        "an expired peer binding must not authenticate"
    );
    assert!(responder.is_err());
    assert_eq!(usable(&alice_store, &bob_key)?, Some((GENERATION, OLD_PSK)));
    Ok(())
}

#[test]
fn session_errors_render_without_detail() {
    let all = [
        SessionError::Authentication,
        SessionError::Protocol(ErrorCode::STATE),
        SessionError::PeerError(ErrorCode::TIMEOUT),
        SessionError::GenerationMismatch,
        SessionError::GenerationExhausted,
        SessionError::RatchetUncertain,
        SessionError::Unavailable(Unavailable::Revoked),
        SessionError::Timeout,
        SessionError::Closed,
        SessionError::Io(io::ErrorKind::BrokenPipe),
        SessionError::LocalIdentity,
        SessionError::Random,
        SessionError::Usage,
        SessionError::RekeyTooSoon,
        SessionError::Identity(crate::identity::IdentityError::AuthenticationFailed),
        SessionError::KeyStore(crate::identity::KeyStoreError::UnknownKey),
        SessionError::Storage(crate::identity::ContactError::UnknownContact),
    ];
    let messages: Vec<String> = all.iter().map(ToString::to_string).collect();
    for (index, message) in messages.iter().enumerate() {
        assert_ne!(message, "");
        assert!(!messages[..index].contains(message), "{message}");
    }
    // Engine failures map without detail (§4.2.6).
    assert_eq!(
        [
            crate::session::engine::NoiseError::Authentication,
            crate::session::engine::NoiseError::Random,
            crate::session::engine::NoiseError::State
        ]
        .map(SessionError::from),
        [
            SessionError::Authentication,
            SessionError::Random,
            SessionError::Protocol(ErrorCode::STATE)
        ]
    );
    assert_eq!(GATE, UnauditedSuite0001::acknowledge_not_production_ready());
    assert_eq!(Role::Initiator.peer(), Role::Responder);
    assert_eq!(Role::Responder.to_u8(), 1);
}

/// A pipe end whose writer stops making progress once `writes` successful
/// `poll_write` calls are used up: every later write stays pending forever
/// (a peer that stopped reading). `None` means unlimited.
struct Stalling {
    end: End,
    state: Arc<Mutex<StallState>>,
}

#[derive(Default)]
struct StallState {
    writes: Option<usize>,
    stalled: bool,
    /// Successful `poll_write` calls so far.
    written: usize,
}

impl Stalling {
    fn new(end: End, writes: Option<usize>) -> (Self, Arc<Mutex<StallState>>) {
        let state = Arc::new(Mutex::new(StallState {
            writes,
            ..StallState::default()
        }));
        (
            Self {
                end,
                state: Arc::clone(&state),
            },
            state,
        )
    }
}

fn stalled(state: &Mutex<StallState>) -> bool {
    state.lock().is_ok_and(|state| state.stalled)
}

fn stall_now(state: &Mutex<StallState>) {
    if let Ok(mut state) = state.lock() {
        state.writes = Some(0);
    }
}

impl AsyncRead for Stalling {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.end).poll_read(cx, buf)
    }
}

impl AsyncWrite for Stalling {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        {
            let mut state = self
                .state
                .lock()
                .map_err(|_| io::Error::other("poisoned"))?;
            match state.writes {
                Some(0) => {
                    // Never woken: the peer stopped reading for good.
                    state.stalled = true;
                    return Poll::Pending;
                }
                Some(ref mut left) => *left -= 1,
                None => {}
            }
            state.written += 1;
        }
        Pin::new(&mut self.end).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.end).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.end).poll_close(cx)
    }
}

/// Polls both futures concurrently inside one task.
async fn both<A: Future, B: Future>(a: A, b: B) -> (A::Output, B::Output) {
    let (mut a, mut b) = (pin!(a), pin!(b));
    let (mut a_out, mut b_out) = (None, None);
    std::future::poll_fn(|cx| {
        if a_out.is_none()
            && let Poll::Ready(value) = a.as_mut().poll(cx)
        {
            a_out = Some(value);
        }
        if b_out.is_none()
            && let Poll::Ready(value) = b.as_mut().poll(cx)
        {
            b_out = Some(value);
        }
        match (a_out.take(), b_out.take()) {
            (Some(a), Some(b)) => Poll::Ready((a, b)),
            (a, b) => {
                (a_out, b_out) = (a, b);
                Poll::Pending
            }
        }
    })
    .await
}

/// Waits until a write is stuck on `state`, then moves `timer` by `by`.
async fn advance_once_stalled(state: &Mutex<StallState>, timer: &ManualTimer, by: Duration) {
    while !stalled(state) {
        futures_yield().await;
    }
    timer.advance(by);
}

/// Both sides' results and stores, and both devices.
type StalledAttempt = (
    Result<(), SessionError>,
    Result<(), SessionError>,
    Store,
    Store,
    Device,
    Device,
);

/// A contact session attempt over stalling pipe ends, with a clock that
/// jumps by `advance` once `watch` (0 Alice, 1 Bob) has a write stuck.
fn stalled_contact_attempt(
    alice_writes: Option<usize>,
    bob_writes: Option<usize>,
    watch: usize,
    advance: Duration,
) -> AnyResult<StalledAttempt> {
    let (alice, bob, mut alice_store, mut bob_store) = contacts()?;
    let wall = crate::identity::test_support::time(WALL)?;
    let timer = ManualTimer::at(START);
    let (alice_end, bob_end) = duplex(1 << 20);
    let (alice_io, alice_state) = Stalling::new(alice_end, alice_writes);
    let (bob_io, bob_state) = Stalling::new(bob_end, bob_writes);
    let watched = if watch == 0 { alice_state } else { bob_state };
    let (alice_local, bob_local) = (alice.local()?, bob.local()?);
    let (alice_key, bob_key) = (alice.key(), bob.key());
    let (initiator, responder) = {
        let mut initiator_authority = alice_store.session_authority(&bob_key)?;
        let plan = initiator_authority.initiator_plan(LOCATOR)?;
        let initiator = async {
            Session::initiate(
                alice_io,
                timer.clone(),
                GATE,
                &alice_local,
                wall,
                plan,
                &mut initiator_authority,
            )
            .await
            .map(|_| ())
        };
        let responder = async {
            let incoming = IncomingSession::accept(bob_io, timer.clone(), GATE).await?;
            let mut authority = bob_store.session_authority(&alice_key)?;
            let plan = authority.responder_plan(incoming.client_hello())?;
            incoming
                .respond(&bob_local, wall, plan, &mut authority)
                .await
                .map(|_| ())
        };
        let clock = advance_once_stalled(&watched, &timer, advance);
        join(initiator, both(responder, clock))?
    };
    Ok((initiator, responder.0, alice_store, bob_store, alice, bob))
}

/// §13: the handshake deadline also bounds writes. A peer that never reads
/// the `ClientHello` makes the attempt time out, not hang.
#[test]
fn stalled_handshake_write_times_out() -> TestResult {
    let (alice, bob, mut alice_store, _) = contacts()?;
    let timer = JumpingTimer::default();
    let (alice_end, _peer) = duplex(4096);
    let (alice_io, state) = Stalling::new(alice_end, Some(0));
    let alice_local = alice.local()?;
    let bob_key = bob.key();
    let mut authority = alice_store.session_authority(&bob_key)?;
    let plan = authority.initiator_plan(LOCATOR)?;
    let result = block_on(Session::initiate(
        alice_io,
        timer.clone(),
        GATE,
        &alice_local,
        crate::identity::test_support::time(WALL)?,
        plan,
        &mut authority,
    ))?;
    assert!(stalled(&state));
    assert_eq!(result.map(|_| ()).err(), Some(SessionError::Timeout));
    assert_eq!(timer.now(), crate::session::HANDSHAKE_TIMEOUT);
    Ok(())
}

/// §13: identity and ratchet writes are bounded by the 10-second
/// establishment deadline. Before a journal the pairing stays usable.
#[test]
fn stalled_identity_write_times_out_before_the_journal() -> TestResult {
    // Alice writes ClientHello and Noise message 1, then her Identity
    // write never completes.
    let (alice, bob, alice_store, bob_store, alice_device, bob_device) =
        stalled_contact_attempt(Some(2), None, 0, crate::session::ESTABLISH_TIMEOUT)?;
    assert_eq!(alice, Err(SessionError::Timeout));
    assert!(bob.is_err());
    assert_eq!(
        usable(&alice_store, &bob_device.key())?,
        Some((GENERATION, OLD_PSK))
    );
    assert_eq!(
        usable(&bob_store, &alice_device.key())?,
        Some((GENERATION, OLD_PSK))
    );
    Ok(())
}

/// A stalled write after the journal is a fatal close through the §4.4
/// failure path: the pairing is blocked until re-pairing.
#[test]
fn stalled_ratchet_write_after_the_journal_blocks_the_pairing() -> TestResult {
    // Bob writes ServerHello, Noise message 2, and his Identity; his
    // RatchetReady (sent after journaling) never completes.
    let (alice, bob, alice_store, bob_store, alice_device, bob_device) =
        stalled_contact_attempt(None, Some(3), 1, crate::session::ESTABLISH_TIMEOUT)?;
    assert_eq!(bob, Err(SessionError::RatchetUncertain));
    assert_eq!(alice, Err(SessionError::RatchetUncertain));
    assert_eq!(usable(&bob_store, &alice_device.key())?, None);
    assert_eq!(usable(&alice_store, &bob_device.key())?, None);
    Ok(())
}

/// §5, §13: on an established session a peer that stops reading cannot
/// block `send` past the idle deadline.
#[test]
fn stalled_session_write_times_out_at_the_idle_deadline() -> TestResult {
    let (alice, bob, mut alice_store, mut bob_store) = contacts()?;
    let wall = crate::identity::test_support::time(WALL)?;
    let timer = ManualTimer::at(START);
    let (alice_end, bob_end) = duplex(1 << 20);
    let (alice_io, state) = Stalling::new(alice_end, None);
    let (bob_io, _) = Stalling::new(bob_end, None);
    let (alice_local, bob_local) = (alice.local()?, bob.local()?);
    let (alice_key, bob_key) = (alice.key(), bob.key());
    let mut initiator_authority = alice_store.session_authority(&bob_key)?;
    let plan = initiator_authority.initiator_plan(LOCATOR)?;
    let initiator = Session::initiate(
        alice_io,
        timer.clone(),
        GATE,
        &alice_local,
        wall,
        plan,
        &mut initiator_authority,
    );
    let responder = async {
        let incoming = IncomingSession::accept(bob_io, timer.clone(), GATE).await?;
        let mut authority = bob_store.session_authority(&alice_key)?;
        let plan = authority.responder_plan(incoming.client_hello())?;
        incoming
            .respond(&bob_local, wall, plan, &mut authority)
            .await
    };
    let (a, b) = join(initiator, responder)?;
    let (mut a, _b) = (a?, b?);
    stall_now(&state);
    let (sent, ()) = join(
        a.send(FrameType::CAPABILITIES, b"caps"),
        advance_once_stalled(&state, &timer, crate::session::IDLE_TIMEOUT),
    )?;
    assert_eq!(sent, Err(SessionError::Timeout));
    assert!(a.is_closed());
    assert_eq!(
        block_on(a.send(FrameType::CAPABILITIES, b"x"))?,
        Err(SessionError::Closed)
    );
    Ok(())
}

fn writes_so_far(state: &Mutex<StallState>) -> usize {
    state.lock().map_or(0, |state| state.written)
}

/// §13: durable I/O counts against the 10-second establishment budget. An
/// authority step that takes longer must not be followed by a send: the
/// attempt fails (closed, through the §4.4 failure path) without the next
/// ratchet record going out.
#[test]
fn slow_authority_steps_count_against_the_establishment_deadline() -> TestResult {
    use crate::session::authority::testing::Delayed;
    // (slow side: 0 Alice/initiator, 1 Bob/responder; slow step: 1 journal,
    // 2 commit). Each step is followed by a send on that side.
    for (side, step) in [(0, 1), (0, 2), (1, 1), (1, 2)] {
        let label = format!("side {side} step {step}");
        let (alice, bob, mut alice_store, mut bob_store) = contacts()?;
        let wall = crate::identity::test_support::time(WALL)?;
        let timer = ManualTimer::at(START);
        let (alice_end, bob_end) = duplex(1 << 20);
        let (alice_io, alice_state) = Stalling::new(alice_end, None);
        let (bob_io, bob_state) = Stalling::new(bob_end, None);
        let (alice_local, bob_local) = (alice.local()?, bob.local()?);
        let (alice_key, bob_key) = (alice.key(), bob.key());
        let slow_state = if side == 0 {
            Arc::clone(&alice_state)
        } else {
            Arc::clone(&bob_state)
        };
        let at_step = Arc::new(Mutex::new(None));
        let hook = {
            let (timer, slow_state, at_step) =
                (timer.clone(), Arc::clone(&slow_state), Arc::clone(&at_step));
            move || {
                if let Ok(mut at_step) = at_step.lock() {
                    *at_step = Some(writes_so_far(&slow_state));
                }
                timer.advance(crate::session::ESTABLISH_TIMEOUT + Duration::from_secs(1));
            }
        };
        let mut hook: Option<Box<dyn FnMut()>> = Some(Box::new(hook));
        let mut slow = |wanted: usize| -> (Option<u8>, Box<dyn FnMut()>) {
            match (wanted == side).then(|| hook.take()).flatten() {
                Some(hook) => (Some(step), hook),
                None => (None, Box::new(|| {})),
            }
        };
        let (initiator, responder) = {
            let inner = alice_store.session_authority(&bob_key)?;
            let plan = inner.initiator_plan(LOCATOR)?;
            let (alice_step, alice_after) = slow(0);
            let mut initiator_authority = Delayed {
                inner,
                step: alice_step,
                after: alice_after,
            };
            let (bob_step, bob_after) = slow(1);
            let initiator = Session::initiate(
                alice_io,
                timer.clone(),
                GATE,
                &alice_local,
                wall,
                plan,
                &mut initiator_authority,
            );
            let responder = async {
                let incoming = IncomingSession::accept(bob_io, timer.clone(), GATE).await?;
                let inner = bob_store.session_authority(&alice_key)?;
                let plan = inner.responder_plan(incoming.client_hello())?;
                let mut authority = Delayed {
                    inner,
                    step: bob_step,
                    after: bob_after,
                };
                incoming
                    .respond(&bob_local, wall, plan, &mut authority)
                    .await
            };
            join(initiator, responder)?
        };
        let (slow_result, other_result) = if side == 0 {
            (initiator.map(|_| ()), responder.map(|_| ()))
        } else {
            (responder.map(|_| ()), initiator.map(|_| ()))
        };
        let recorded = at_step
            .lock()
            .map_err(|_| "poisoned")?
            .ok_or_else(|| format!("{label}: step not reached"))?;
        assert_eq!(
            writes_so_far(&slow_state),
            recorded,
            "{label}: nothing is sent after an overdue step"
        );
        // The step journaled (or committed), so the failure blocks the
        // pairing on the slow side; the other side never opens.
        assert_eq!(slow_result, Err(SessionError::RatchetUncertain), "{label}");
        assert!(other_result.is_err(), "{label}");
        let slow_store_view = if side == 0 {
            usable(&alice_store, &bob_key)?
        } else {
            usable(&bob_store, &alice_key)?
        };
        assert_eq!(slow_store_view, None, "{label}");
    }
    Ok(())
}

/// §14.2: an accepted attempt's `Debug` does not print the contact locator.
#[test]
fn incoming_session_debug_redacts_the_locator() -> TestResult {
    use todoke_proto::session::{Hello, PreludeKind, encode_prelude_record};
    let (mut peer, listener) = duplex(4096);
    let hello = Hello::client(SessionMode::Contact, GENERATION, LOCATOR, [0xc4; 16])?;
    let record = encode_prelude_record(PreludeKind::ClientHello, &hello.encode())?;
    let written = Pin::new(&mut peer).poll_write(&mut Context::from_waker(Waker::noop()), &record);
    assert!(matches!(written, Poll::Ready(Ok(n)) if n == record.len()));
    let incoming = block_on(IncomingSession::accept(
        listener,
        ManualTimer::at(START),
        GATE,
    ))??;
    assert_eq!(incoming.client_hello().locator(), &LOCATOR);
    let debug = format!("{incoming:?}");
    for needle in ["a7a7", "167", "c4c4", "196"] {
        assert!(!debug.contains(needle), "{debug}");
    }
    assert!(debug.contains("IncomingSession") && debug.contains("[16 bytes]"));
    Ok(())
}

/// Local refusals before anything is sent: an initiator plan with a zero
/// locator and a responder plan for another mode are usage errors, and the
/// peer only sees the stream end. A session whose peer went away stays
/// closed for every later call.
#[test]
fn refused_plans_send_nothing_and_a_dead_pipe_stays_closed() -> TestResult {
    let wall = crate::identity::test_support::time(WALL)?;
    let (alice, bob, mut alice_store, mut bob_store) = contacts()?;
    let alice_local = alice.local()?;
    let bob_local = bob.local()?;
    let psk = || PairingPsk::from_bytes(Zeroizing::new([0x9a; 32]));
    let (alice_end, bob_end) = duplex(4096);
    let mut authority = ScriptedAuthority::new(None);
    let result = block_on(Session::initiate(
        alice_end,
        ManualTimer::at(START),
        GATE,
        &alice_local,
        wall,
        InitiatorPlan::qr([0; 16], *bob.noise.public_key(), psk()),
        &mut authority,
    ))?;
    assert_eq!(result.map(|_| ()), Err(SessionError::Usage));
    let listener = block_on(IncomingSession::accept(
        bob_end,
        ManualTimer::at(START),
        GATE,
    ))?;
    assert_eq!(listener.map(|_| ()), Err(SessionError::Closed));
    // A contact Hello answered with a QR plan.
    let timer = ManualTimer::at(START);
    let (alice_end, bob_end) = duplex(4096);
    let bob_key = bob.key();
    let mut alice_authority = alice_store.session_authority(&bob_key)?;
    let plan = alice_authority.initiator_plan(LOCATOR)?;
    let initiator = Session::initiate(
        alice_end,
        timer.clone(),
        GATE,
        &alice_local,
        wall,
        plan,
        &mut alice_authority,
    );
    let responder = async {
        let incoming = IncomingSession::accept(bob_end, timer.clone(), GATE).await?;
        let mut authority = ScriptedAuthority::new(None);
        incoming
            .respond(&bob_local, wall, ResponderPlan::qr(psk()), &mut authority)
            .await
            .map(|_| ())
    };
    let (initiator, responder) = join(initiator, responder)?;
    assert_eq!(responder, Err(SessionError::Usage));
    assert_eq!(initiator.map(|_| ()), Err(SessionError::Closed));
    assert_eq!(usable(&alice_store, &bob_key)?, Some((GENERATION, OLD_PSK)));
    // An established session whose peer went away.
    let (mut a, b) = contact_sessions(
        &alice,
        &bob,
        &mut alice_store,
        &mut bob_store,
        &ManualTimer::at(START),
    )?;
    drop(b);
    assert_eq!(block_on(a.recv())?.map(|_| ()), Err(SessionError::Closed));
    assert!(a.is_closed());
    assert_eq!(
        block_on(a.send(FrameType::CAPABILITIES, b"late"))?,
        Err(SessionError::Closed)
    );
    Ok(())
}
