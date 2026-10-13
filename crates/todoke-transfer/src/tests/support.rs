//! Shared fixtures: devices with real keys, real suite 0x0001 sessions over
//! an in-memory pipe (QR pairing, then contact sessions), a minimal
//! executor, and a sans-IO link that connects two engines frame by frame.

use core::future::Future;
use core::pin::{Pin, pin};
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use std::cell::RefCell;
use std::collections::VecDeque;
use std::io;
use std::sync::{Arc, Mutex};
use std::task::Wake;

use futures_io::{AsyncRead, AsyncWrite};
use todoke_crypto::consent::SessionBinding;
use todoke_crypto::content::{ContentSuite, ContentSuites};
use todoke_crypto::identity::{
    BindingRequest, ContactStore, Ed25519PublicKey, ExportPolicy, KeyId, KeyRole, KeyStore,
    MemoryStorage, SoftwareKeyStore, SoftwareSealer, StorageKey, VerifiedDeviceBinding,
    issue_device_binding,
};
use todoke_crypto::pairing::{PairingOffers, QrPayload};
use todoke_crypto::session::{
    Accepted, IncomingSession, LocalIdentity, NoiseStaticKey, Session, Timer, UnauditedSuite0001,
};
use todoke_proto::session::{ErrorRecord, ErrorScope, FrameType};
use todoke_proto::time::UnixTime;
use todoke_proto::transfer::{Capabilities, ManifestLimits, TransferId};
use zeroize::Zeroizing;

use crate::{
    Clock, EngineConfig, Failure, FailureCode, LocalCapabilities, ManifestBuilder, MemorySink,
    MemorySource, OutgoingFrame, OutgoingOffer, TransferEngine, TransferEvent, storage::MemoryFile,
};

pub(crate) type AnyResult<T> = Result<T, Box<dyn std::error::Error>>;
pub(crate) type TestResult = AnyResult<()>;
pub(crate) type Keys = SoftwareKeyStore<MemoryStorage>;
pub(crate) type Store = ContactStore<SoftwareSealer, MemoryStorage>;
pub(crate) type Engine<'k> = TransferEngine<'k, Keys, MemorySource, MemorySink>;

/// Every session's wall-clock time: one minute into the bindings' validity.
pub(crate) const T0: u64 = 1_760_000_000;
pub(crate) const WALL: u64 = T0 + 60;
/// Monotonic start of every run.
pub(crate) const START: Duration = Duration::from_secs(10_000);
pub(crate) const GATE: UnauditedSuite0001 = UnauditedSuite0001::acknowledge_not_production_ready();

pub(crate) fn time(seconds: u64) -> Result<UnixTime, &'static str> {
    UnixTime::new(seconds).ok_or("time")
}

fn sealer(byte: u8) -> SoftwareSealer {
    SoftwareSealer::new(StorageKey::from_bytes(Zeroizing::new([byte; 32])))
}

/// A device: person root and device key, a real Noise static key, and a
/// binding valid for 30 days from `T0`.
pub(crate) struct Device {
    pub(crate) keys: Keys,
    pub(crate) signing_key: KeyId,
    pub(crate) noise: NoiseStaticKey,
    pub(crate) binding: VerifiedDeviceBinding,
}

impl Device {
    pub(crate) fn new(kem_seed: u8) -> AnyResult<Self> {
        let mut keys = SoftwareKeyStore::open(sealer(1), MemoryStorage::new())?;
        let root = keys.generate(KeyRole::PersonRoot, ExportPolicy::NonExportable)?;
        let device = keys.generate(KeyRole::Device, ExportPolicy::NonExportable)?;
        let noise = NoiseStaticKey::generate()?;
        let pair = libcrux_ml_kem::mlkem768::generate_key_pair([kem_seed; 64]);
        let kem_static: [u8; 1184] = *pair.public_key().as_slice();
        let request = BindingRequest {
            noise_static: *noise.public_key(),
            kem_static: Box::new(kem_static),
            serial: core::num::NonZeroU64::new(1).ok_or("serial")?,
            not_before: time(T0)?,
            not_after: time(T0 + 30 * 86_400)?,
        };
        let binding = issue_device_binding(&keys, &root, &device, request)?;
        Ok(Self {
            keys,
            signing_key: device,
            noise,
            binding,
        })
    }

    pub(crate) fn local(&self) -> AnyResult<LocalIdentity<'_, Keys>> {
        Ok(LocalIdentity::new(
            &self.keys,
            self.signing_key,
            &self.binding,
            &self.noise,
            time(WALL)?,
        )?)
    }

    pub(crate) fn key(&self) -> Ed25519PublicKey {
        *self.binding.device_public()
    }
}

#[derive(Default)]
struct Shared {
    buffer: VecDeque<u8>,
    reader: Option<Waker>,
    writer: Option<Waker>,
    closed: bool,
}

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

/// One end of an in-memory duplex byte pipe with bounded buffers.
pub(crate) struct End {
    incoming: Channel,
    outgoing: Channel,
}

pub(crate) fn duplex(capacity: usize) -> (End, End) {
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

/// A clock that only moves when told to.
#[derive(Clone, Default)]
pub(crate) struct ManualTimer(Arc<Mutex<Duration>>);

impl ManualTimer {
    pub(crate) fn at(start: Duration) -> Self {
        Self(Arc::new(Mutex::new(start)))
    }
}

pub(crate) struct ManualSleep {
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

struct Unpark(std::thread::Thread);

impl Wake for Unpark {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }
}

/// Polls two futures to completion on this thread.
pub(crate) fn join<A: Future, B: Future>(a: A, b: B) -> AnyResult<(A::Output, B::Output)> {
    let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
    let mut cx = Context::from_waker(&waker);
    let (mut a, mut b) = (pin!(a), pin!(b));
    let (mut a_out, mut b_out) = (None, None);
    for _ in 0..400_000 {
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
        std::thread::park_timeout(Duration::from_micros(100));
    }
    Err("futures did not complete".into())
}

pub(crate) type Established = (Session<End, ManualTimer>, Session<End, ManualTimer>);

/// Two devices, paired by QR, with their contact stores.
pub(crate) struct Pair {
    pub(crate) alice: Device,
    pub(crate) bob: Device,
    pub(crate) alice_store: Store,
    pub(crate) bob_store: Store,
}

impl Pair {
    /// QR pairing over the pipe (Alice scans, Bob displays). Returns the
    /// pairing session, Alice's end first.
    pub(crate) fn new(timer: &ManualTimer) -> AnyResult<(Self, Established)> {
        let wall = time(WALL)?;
        let alice = Device::new(0x41)?;
        let bob = Device::new(0x42)?;
        let mut alice_store = ContactStore::open(sealer(9), MemoryStorage::new())?;
        let mut bob_store = ContactStore::open(sealer(8), MemoryStorage::new())?;
        let offers = PairingOffers::new();
        let text = offers
            .create_qr(&bob.local()?, wall, timer.now())?
            .to_text();
        let payload = QrPayload::from_text(&text, wall)?;
        let (alice_end, bob_end) = duplex(1 << 18);
        let (alice_local, bob_local) = (alice.local()?, bob.local()?);
        let sessions = {
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
                let Accepted::Hello(mut incoming) =
                    IncomingSession::accept_any(bob_end, timer.clone(), GATE, &offers).await?
                else {
                    return Err::<_, Box<dyn std::error::Error>>("expected a ClientHello".into());
                };
                let reservation = incoming.reserve_offer(&offers, wall)?;
                let (plan, mut authority) = reservation.into_qr_responder(&mut bob_store)?;
                Ok(incoming
                    .respond(&bob_local, wall, plan, &mut authority)
                    .await?)
            };
            let (a, b) = join(initiator, responder)?;
            (a?, b?)
        };
        Ok((
            Self {
                alice,
                bob,
                alice_store,
                bob_store,
            },
            sessions,
        ))
    }

    /// A fresh contact session (`KKpsk2`, Alice initiates).
    pub(crate) fn contact_session(&mut self, timer: &ManualTimer) -> AnyResult<Established> {
        let wall = time(WALL)?;
        let (alice_end, bob_end) = duplex(1 << 18);
        let (alice_local, bob_local) = (self.alice.local()?, self.bob.local()?);
        let (alice_key, bob_key) = (self.alice.key(), self.bob.key());
        let mut initiator_authority = self.alice_store.session_authority(&bob_key)?;
        let plan = initiator_authority.initiator_plan([0xa7; 16])?;
        let initiator = Session::initiate(
            alice_end,
            timer.clone(),
            GATE,
            &alice_local,
            wall,
            plan,
            &mut initiator_authority,
        );
        let bob_store = &mut self.bob_store;
        let responder = async {
            let incoming = IncomingSession::accept(bob_end, timer.clone(), GATE).await?;
            let mut authority = bob_store.session_authority(&alice_key)?;
            let plan = authority.responder_plan(incoming.client_hello())?;
            Ok::<_, Box<dyn std::error::Error>>(
                incoming
                    .respond(&bob_local, wall, plan, &mut authority)
                    .await?,
            )
        };
        let (a, b) = join(initiator, responder)?;
        Ok((a?, b?))
    }
}

/// Two devices and the transfer bindings of two independent sessions
/// between them, for sans-IO tests. Built once per test thread: the
/// handshakes are the expensive part.
pub(crate) struct Fixture {
    pub(crate) alice: Device,
    pub(crate) bob: Device,
    /// Session 1 (QR pairing), Alice's view and Bob's view.
    pub(crate) first: (SessionBinding, SessionBinding),
    /// Session 2 (contact), for resume and wrong-session tests.
    pub(crate) second: (SessionBinding, SessionBinding),
}

thread_local! {
    static FIXTURE: RefCell<Option<std::rc::Rc<Fixture>>> = const { RefCell::new(None) };
}

pub(crate) fn fixture() -> AnyResult<std::rc::Rc<Fixture>> {
    if let Some(fixture) = FIXTURE.with(|cell| cell.borrow().clone()) {
        return Ok(fixture);
    }
    let timer = ManualTimer::at(START);
    let (mut pair, (a1, b1)) = Pair::new(&timer)?;
    let first = (a1.transfer_binding(), b1.transfer_binding());
    drop((a1, b1));
    let (a2, b2) = pair.contact_session(&timer)?;
    let second = (a2.transfer_binding(), b2.transfer_binding());
    drop((a2, b2));
    let fixture = std::rc::Rc::new(Fixture {
        alice: pair.alice,
        bob: pair.bob,
        first,
        second,
    });
    FIXTURE.with(|cell| *cell.borrow_mut() = Some(fixture.clone()));
    Ok(fixture)
}

/// Deterministic test content of `len` bytes.
pub(crate) fn content(len: usize, salt: u8) -> Vec<u8> {
    (0..len)
        .map(|i| {
            let bytes = (i as u64).to_le_bytes();
            bytes[0] ^ bytes[1].rotate_left(3) ^ salt
        })
        .collect()
}

/// A file to offer: name, parent index in the builder, content.
pub(crate) struct Spec {
    pub(crate) name: &'static str,
    pub(crate) parent: u32,
    pub(crate) content: Option<Vec<u8>>,
}

pub(crate) fn file(name: &'static str, parent: u32, len: usize, salt: u8) -> Spec {
    Spec {
        name,
        parent,
        content: Some(content(len, salt)),
    }
}

pub(crate) fn dir(name: &'static str, parent: u32) -> Spec {
    Spec {
        name,
        parent,
        content: None,
    }
}

/// Builds an offer from `sender` to `recipient` with `specs` and stores
/// its files in `source`.
pub(crate) fn build_offer(
    sender: &Ed25519PublicKey,
    recipient: &Ed25519PublicKey,
    specs: &[Spec],
    source: &mut MemorySource,
    lifetime: u64,
) -> AnyResult<OutgoingOffer> {
    let suite = ContentSuites::local()
        .select(ContentSuites::local())
        .ok_or("suite")?;
    build_offer_with_suite(sender, recipient, specs, source, lifetime, suite)
}

/// As [`build_offer`], every file using `suite`.
pub(crate) fn build_offer_with_suite(
    sender: &Ed25519PublicKey,
    recipient: &Ed25519PublicKey,
    specs: &[Spec],
    source: &mut MemorySource,
    lifetime: u64,
    suite: ContentSuite,
) -> AnyResult<OutgoingOffer> {
    let mut builder = ManifestBuilder::new(sender, recipient, time(WALL)?, time(WALL + lifetime)?)?;
    let mut files = Vec::new();
    for spec in specs {
        match &spec.content {
            None => {
                builder.add_directory(spec.parent, spec.name);
            }
            Some(bytes) => {
                let memory = MemoryFile::new(bytes.clone());
                let id = builder.add_file(
                    spec.parent,
                    spec.name,
                    "application/octet-stream",
                    memory.size(),
                    *memory.root(),
                );
                files.push((id, memory));
            }
        }
    }
    let manifest = builder.build(suite, &ManifestLimits::SPEC)?;
    for (id, memory) in files {
        source.insert(*manifest.transfer_id(), id, memory);
    }
    Ok(OutgoingOffer::new(manifest)?)
}

/// Engine configuration with a request budget of `outstanding`.
pub(crate) fn config(outstanding: u16) -> AnyResult<EngineConfig> {
    config_with_suites(outstanding, ContentSuites::local())
}

/// As [`config`], advertising `suites` (a subset of this device's).
pub(crate) fn config_with_suites(
    outstanding: u16,
    suites: ContentSuites,
) -> AnyResult<EngineConfig> {
    let maximums = Capabilities::PROTOCOL_MAXIMUMS;
    let record = Capabilities::new(
        suites.bits(),
        maximums.max_manifest_bytes(),
        maximums.max_entries(),
        maximums.max_file_bytes(),
        maximums.max_transfer_bytes(),
        outstanding,
    )?;
    Ok(EngineConfig {
        capabilities: LocalCapabilities::new(record)?,
        transport: "test-pipe",
    })
}

/// Which session of the fixture an engine runs on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Which {
    First,
    Second,
}

/// Two engines joined frame by frame, Alice (`a`) and Bob (`b`).
pub(crate) struct Link<'k> {
    pub(crate) a: Engine<'k>,
    pub(crate) b: Engine<'k>,
    pub(crate) to_b: VecDeque<OutgoingFrame>,
    pub(crate) to_a: VecDeque<OutgoingFrame>,
    pub(crate) now: Duration,
    pub(crate) a_events: Vec<TransferEvent>,
    pub(crate) b_events: Vec<TransferEvent>,
    /// Every delivered frame: toward Bob, and its type.
    pub(crate) log: Vec<(bool, FrameType)>,
    /// Every frame each engine emitted, in order.
    pub(crate) emitted_a: Vec<OutgoingFrame>,
    pub(crate) emitted_b: Vec<OutgoingFrame>,
}

impl<'k> Link<'k> {
    /// How many frames of `frame_type` were delivered toward Bob
    /// (`to_bob`) or Alice.
    pub(crate) fn delivered(&self, to_bob: bool, frame_type: FrameType) -> usize {
        self.log
            .iter()
            .filter(|&&(toward, kind)| toward == to_bob && kind == frame_type)
            .count()
    }

    pub(crate) fn new(
        fixture: &'k Fixture,
        which: Which,
        sources: (MemorySource, MemorySource),
        sinks: (MemorySink, MemorySink),
        configs: (EngineConfig, EngineConfig),
    ) -> AnyResult<Self> {
        let (a_binding, b_binding) = match which {
            Which::First => fixture.first,
            Which::Second => fixture.second,
        };
        let clock = Clock::new(time(WALL)?, START);
        let a = TransferEngine::new(
            a_binding,
            &fixture.alice.keys,
            fixture.alice.signing_key,
            sources.0,
            sinks.0,
            configs.0,
            clock,
            START,
        )?;
        let b = TransferEngine::new(
            b_binding,
            &fixture.bob.keys,
            fixture.bob.signing_key,
            sources.1,
            sinks.1,
            configs.1,
            clock,
            START,
        )?;
        Ok(Self {
            a,
            b,
            to_b: VecDeque::new(),
            to_a: VecDeque::new(),
            now: START,
            a_events: Vec::new(),
            b_events: Vec::new(),
            log: Vec::new(),
            emitted_a: Vec::new(),
            emitted_b: Vec::new(),
        })
    }

    /// Moves queued frames from both engines onto the wires.
    pub(crate) fn collect(&mut self) {
        while let Some(frame) = self.a.pop_frame() {
            self.emitted_a.push(frame.clone());
            self.to_b.push_back(frame);
        }
        while let Some(frame) = self.b.pop_frame() {
            self.emitted_b.push(frame.clone());
            self.to_a.push_back(frame);
        }
        while let Some(event) = self.a.pop_event() {
            self.a_events.push(event);
        }
        while let Some(event) = self.b.pop_event() {
            self.b_events.push(event);
        }
    }

    /// Delivers the next frame toward Bob (`to_bob`) or Alice.
    pub(crate) fn deliver(&mut self, to_bob: bool) -> Option<Result<(), crate::EngineError>> {
        self.collect();
        let frame = if to_bob {
            self.to_b.pop_front()
        } else {
            self.to_a.pop_front()
        }?;
        self.log.push((to_bob, raw(&frame).0));
        let engine = if to_bob { &mut self.b } else { &mut self.a };
        let result = deliver_to(engine, frame, self.now);
        self.collect();
        Some(result)
    }

    /// Delivers everything both ways until both wires are empty.
    pub(crate) fn settle(&mut self) -> TestResult {
        for _ in 0..1_000_000 {
            self.collect();
            if self.to_b.is_empty() && self.to_a.is_empty() {
                return Ok(());
            }
            if !self.to_b.is_empty()
                && let Some(Err(error)) = self.deliver(true)
            {
                return Err(format!("bob: {error}").into());
            }
            if !self.to_a.is_empty()
                && let Some(Err(error)) = self.deliver(false)
            {
                return Err(format!("alice: {error}").into());
            }
        }
        Err("link did not settle".into())
    }

    /// Advances the clock and runs both engines' timers.
    pub(crate) fn advance(
        &mut self,
        by: Duration,
    ) -> (
        Result<(), crate::EngineError>,
        Result<(), crate::EngineError>,
    ) {
        self.now += by;
        let a = if self.a.is_closed() {
            Ok(())
        } else {
            self.a.poll(self.now)
        };
        let b = if self.b.is_closed() {
            Ok(())
        } else {
            self.b.poll(self.now)
        };
        self.collect();
        (a, b)
    }

    pub(crate) fn transfer_id_of_offer(&self) -> Option<TransferId> {
        self.b_events.iter().find_map(|event| match event {
            TransferEvent::OfferReceived(view) => Some(view.transfer_id),
            _ => None,
        })
    }
}

/// Hands one frame to an engine as the session layer would: a
/// session-scoped `Error` closes the session; anything else is a frame.
pub(crate) fn deliver_to<K: KeyStore, S: crate::SendSource, R: crate::ReceiveSink>(
    engine: &mut TransferEngine<'_, K, S, R>,
    frame: OutgoingFrame,
    now: Duration,
) -> Result<(), crate::EngineError> {
    if engine.is_closed() {
        return Ok(());
    }
    match frame {
        OutgoingFrame::Frame { frame_type, body } => engine.handle_frame(frame_type, &body, now),
        OutgoingFrame::Error(record) => {
            if record.scope() == ErrorScope::Session {
                engine.close(Some(Failure {
                    code: FailureCode::from_error_code(record.code()),
                    by: crate::Party::Peer,
                }));
                Ok(())
            } else {
                engine.handle_frame(FrameType::ERROR, &record.encode(), now)
            }
        }
    }
}

/// The raw frame type and body of an outgoing frame (errors encoded).
pub(crate) fn raw(frame: &OutgoingFrame) -> (FrameType, Vec<u8>) {
    match frame {
        OutgoingFrame::Frame { frame_type, body } => (*frame_type, body.to_vec()),
        OutgoingFrame::Error(record) => (FrameType::ERROR, record.encode().to_vec()),
    }
}

/// A transfer-scoped `Error` record body.
pub(crate) fn transfer_error(
    transfer_id: TransferId,
    code: todoke_proto::session::ErrorCode,
) -> AnyResult<Vec<u8>> {
    Ok(ErrorRecord::new(ErrorScope::Transfer(transfer_id), code)?
        .encode()
        .to_vec())
}
