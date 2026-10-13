//! Real suite 0x0001 sessions between two test devices (QR pairing, then a
//! contact session) over an in-memory pipe, for the session bindings that
//! verified Accepts need, and helpers that seal and open real content.
//! Trimmed from todoke-transfer's test support.

use core::future::Future;
use core::pin::{Pin, pin};
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use std::cell::RefCell;
use std::collections::{BTreeMap, VecDeque};
use std::io::{self, Cursor};
use std::sync::{Arc, Mutex};
use std::task::Wake;

use futures_io::{AsyncRead, AsyncWrite};
use todoke_crypto::consent::{
    CanonicalManifest, SessionBinding, VerifiedAccept, sign_accept, verify_accept,
};
use todoke_crypto::content::{
    ContentOpener, ContentSealer, ContentSuite, ContentSuites, FileMaster, VerifiedSegment,
    outboard,
};
use todoke_crypto::identity::{
    BindingRequest, ContactStore, Ed25519PublicKey, ExportPolicy, KeyId, KeyRole, KeyStore,
    MemoryStorage, SoftwareKeyStore, SoftwareSealer, StorageKey, VerifiedDeviceBinding,
    issue_device_binding,
};
use todoke_crypto::pairing::{PairingOffers, QrPayload};
use todoke_crypto::session::{
    Accepted, IncomingSession, LocalIdentity, NoiseStaticKey, Session, Timer, UnauditedSuite0001,
};
use todoke_proto::time::UnixTime;
use todoke_proto::transfer::{ManifestLimits, TransferId};
use todoke_transfer::ManifestBuilder;
use zeroize::Zeroizing;

use super::AnyResult;

pub(crate) type Keys = SoftwareKeyStore<MemoryStorage>;
type Store = ContactStore<SoftwareSealer, MemoryStorage>;

/// Every session's wall-clock time: one minute into the bindings' validity.
pub(crate) const T0: u64 = 1_760_000_000;
pub(crate) const WALL: u64 = T0 + 60;
/// Monotonic start of every run.
pub(crate) const START: Duration = Duration::from_secs(10_000);
const GATE: UnauditedSuite0001 = UnauditedSuite0001::acknowledge_not_production_ready();

pub(crate) fn time(seconds: u64) -> Result<UnixTime, &'static str> {
    UnixTime::new(seconds).ok_or("time")
}

pub(crate) fn sealer(byte: u8) -> SoftwareSealer {
    SoftwareSealer::new(StorageKey::from_bytes(Zeroizing::new([byte; 32])))
}

/// A device with real keys and a binding valid for 30 days from `T0`.
pub(crate) struct Device {
    pub(crate) keys: Keys,
    pub(crate) signing_key: KeyId,
    noise: NoiseStaticKey,
    binding: VerifiedDeviceBinding,
}

impl Device {
    fn new(kem_seed: u8) -> AnyResult<Self> {
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

    fn local(&self) -> AnyResult<LocalIdentity<'_, Keys>> {
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
struct Channel(Arc<Mutex<Shared>>);

impl Channel {
    fn lock(&self) -> io::Result<std::sync::MutexGuard<'_, Shared>> {
        self.0.lock().map_err(|_| io::Error::other("poisoned"))
    }
}

/// One end of an in-memory duplex byte pipe.
pub(crate) struct End {
    incoming: Channel,
    outgoing: Channel,
}

fn duplex() -> (End, End) {
    let a = Channel(Arc::default());
    let b = Channel(Arc::default());
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
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut shared = self.outgoing.lock()?;
        if shared.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        shared.buffer.extend(buf);
        if let Some(reader) = shared.reader.take() {
            reader.wake();
        }
        Poll::Ready(Ok(buf.len()))
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
#[derive(Clone)]
struct ManualTimer(Arc<Mutex<Duration>>);

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

/// Two devices and the transfer bindings of two independent sessions
/// between them (Alice's view, Bob's view). Built once per test thread.
pub(crate) struct Fixture {
    pub(crate) alice: Device,
    pub(crate) bob: Device,
    pub(crate) first: (SessionBinding, SessionBinding),
    pub(crate) second: (SessionBinding, SessionBinding),
}

thread_local! {
    static FIXTURE: RefCell<Option<std::rc::Rc<Fixture>>> = const { RefCell::new(None) };
}

pub(crate) fn fixture() -> AnyResult<std::rc::Rc<Fixture>> {
    if let Some(fixture) = FIXTURE.with(|cell| cell.borrow().clone()) {
        return Ok(fixture);
    }
    let timer = ManualTimer(Arc::new(Mutex::new(START)));
    let wall = time(WALL)?;
    let alice = Device::new(0x41)?;
    let bob = Device::new(0x42)?;
    let mut alice_store: Store = ContactStore::open(sealer(9), MemoryStorage::new())?;
    let mut bob_store: Store = ContactStore::open(sealer(8), MemoryStorage::new())?;
    // QR pairing (Alice scans Bob's code): the first session.
    let offers = PairingOffers::new();
    let text = offers
        .create_qr(&bob.local()?, wall, timer.now())?
        .to_text();
    let payload = QrPayload::from_text(&text, wall)?;
    let first = {
        let (alice_end, bob_end) = duplex();
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
        (a?.transfer_binding(), b?.transfer_binding())
    };
    // A contact session (KKpsk2): the second.
    let second = {
        let (alice_end, bob_end) = duplex();
        let (alice_local, bob_local) = (alice.local()?, bob.local()?);
        let (alice_key, bob_key) = (alice.key(), bob.key());
        let mut initiator_authority = alice_store.session_authority(&bob_key)?;
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
        let bob_store = &mut bob_store;
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
        (a?.transfer_binding(), b?.transfer_binding())
    };
    let fixture = std::rc::Rc::new(Fixture {
        alice,
        bob,
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
            bytes[0] ^ bytes[1].rotate_left(3) ^ bytes[2].rotate_left(5) ^ salt
        })
        .collect()
}

/// An entry of an offer: a directory (no content) or a file.
pub(crate) struct Entry {
    pub(crate) name: String,
    pub(crate) parent: u32,
    pub(crate) content: Option<Vec<u8>>,
}

pub(crate) fn dir_entry(name: &str, parent: u32) -> Entry {
    Entry {
        name: name.to_owned(),
        parent,
        content: None,
    }
}

pub(crate) fn file_entry(name: &str, parent: u32, content: Vec<u8>) -> Entry {
    Entry {
        name: name.to_owned(),
        parent,
        content: Some(content),
    }
}

/// The content suite both test devices use.
pub(crate) fn suite() -> AnyResult<ContentSuite> {
    Ok(ContentSuites::local()
        .select(ContentSuites::local())
        .ok_or("suite")?)
}

/// A manifest from Alice to Bob, valid for `lifetime` seconds from `WALL`.
pub(crate) fn build_manifest(
    fixture: &Fixture,
    transfer_id: TransferId,
    entries: &[Entry],
    lifetime: u64,
) -> AnyResult<CanonicalManifest> {
    let mut builder = ManifestBuilder::with_transfer_id(
        transfer_id,
        &fixture.alice.key(),
        &fixture.bob.key(),
        time(WALL)?,
        time(WALL + lifetime)?,
    );
    for entry in entries {
        match &entry.content {
            None => {
                builder.add_directory(entry.parent, &entry.name);
            }
            Some(bytes) => {
                builder.add_file(
                    entry.parent,
                    &entry.name,
                    "application/octet-stream",
                    bytes.len() as u64,
                    *blake3::hash(bytes).as_bytes(),
                );
            }
        }
    }
    Ok(builder.build(suite()?, &ManifestLimits::SPEC)?)
}

/// One transfer, consented in one session: Bob's verified Accept and
/// Alice's view of it, the content, and the file masters.
pub(crate) struct Consented {
    pub(crate) manifest: CanonicalManifest,
    pub(crate) accept: VerifiedAccept,
    pub(crate) sender_accept: VerifiedAccept,
    pub(crate) contents: BTreeMap<u32, Vec<u8>>,
    pub(crate) masters: BTreeMap<u32, [u8; 32]>,
}

impl Consented {
    /// Bob accepts `selection` of `manifest` in session `second` (or the
    /// first), with fixed masters derived from `master_seed`.
    pub(crate) fn new(
        fixture: &Fixture,
        manifest: &CanonicalManifest,
        entries: &[Entry],
        selection: &[u32],
        second: bool,
        master_seed: u8,
    ) -> AnyResult<Self> {
        let (alice_binding, bob_binding) = if second {
            fixture.second
        } else {
            fixture.first
        };
        let now = time(WALL)?;
        let expires = manifest.expires_at().min(time(WALL + 86_000)?);
        let accept = sign_accept(
            &fixture.bob.keys,
            &fixture.bob.signing_key,
            &bob_binding,
            manifest,
            selection.to_vec(),
            expires,
            now,
        )?;
        let sender_accept = verify_accept(accept.encoded(), &alice_binding, manifest, now)?;
        let mut contents = BTreeMap::new();
        let mut masters = BTreeMap::new();
        for (index, entry) in entries.iter().enumerate() {
            let id = u32::try_from(index + 1)?;
            if let Some(bytes) = &entry.content {
                contents.insert(id, bytes.clone());
                masters.insert(id, [master_seed ^ u8::try_from(id % 251)?; 32]);
            }
        }
        Ok(Self {
            manifest: manifest.clone(),
            accept,
            sender_accept,
            contents,
            masters,
        })
    }

    pub(crate) fn master(&self, file_id: u32) -> AnyResult<FileMaster> {
        let bytes = *self.masters.get(&file_id).ok_or("master")?;
        Ok(FileMaster::from_secret(Zeroizing::new(bytes)))
    }

    /// The sender's sealed content ciphertext of segment `index`.
    pub(crate) fn ciphertext(&self, file_id: u32, index: u32) -> AnyResult<Vec<u8>> {
        let file = self.sender_accept.file(file_id).ok_or("not selected")?;
        let data = self.contents.get(&file_id).ok_or("content")?;
        let (tree, _) = outboard(data);
        let sealer = ContentSealer::new(&file, &self.master(file_id)?)?;
        Ok(sealer.seal_segment(
            index,
            Cursor::new(data.as_slice()),
            Cursor::new(tree.as_slice()),
        )?)
    }

    /// The receiver's verified segment for `ciphertext`.
    pub(crate) fn verified(
        &self,
        file_id: u32,
        index: u32,
        ciphertext: &[u8],
    ) -> AnyResult<VerifiedSegment> {
        let file = self.accept.file(file_id).ok_or("not selected")?;
        let opener = ContentOpener::new(&file, &self.master(file_id)?)?;
        Ok(opener.open_segment(index, ciphertext)?)
    }

    /// The segment count of file `file_id`.
    pub(crate) fn count(&self, file_id: u32) -> AnyResult<u32> {
        Ok(self.manifest.file(file_id).ok_or("file")?.layout().count())
    }
}
