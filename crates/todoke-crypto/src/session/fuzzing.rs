//! Entry points for `cargo fuzz` harnesses; compiled only with `--cfg fuzzing`.
//!
//! Every input is parsed by the real prelude reader and handshake driver,
//! set up deterministically from the public §4.2 fixture inputs
//! (`spec/test-vectors/handshake-*.json`), so a fuzzer can start from the
//! committed transcripts and mutate them.
//!
//! The establishment and transport harnesses run the sans-IO layers after a
//! deterministic contact (`KKpsk2`) handshake between two fixed public test
//! identities. The fuzzer controls the wire: each input byte selects an
//! operation such as delivering the honest peer's next record, a corrupted
//! or replayed one, raw bytes, or a clock jump, so inputs reach every phase
//! without precomputed ciphertexts.
//!
//! The record-stream harness runs the async adapter's incremental record
//! reader over arbitrary bytes delivered in short reads.

use core::num::NonZeroU64;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use std::collections::VecDeque;
use std::sync::OnceLock;

use futures_io::AsyncRead;
use todoke_proto::session::{
    ErrorCode, FrameType, Hello, SessionMode, ciphertext_len, prelude_record_len,
};
use todoke_proto::time::UnixTime;
use zeroize::Zeroizing;

use super::authority::ContactAuthority;
use super::engine::Entropy;
use super::establish::{Establishment, Phase};
use super::handshake::{
    CODE_OFFER_LEN, CODE_SHARE_LEN, CodeTranscript, HandshakeDriver, InitiatorPlan, ResponderPlan,
    Split, read_client_hello,
};
use super::io::{Framing, RecordReader};
use super::keys::{NoiseStaticKey, PairingPsk};
use super::transport::{FrameTransport, Limits, MAX_SESSION_DURATION, SessionCore, SessionInfo};
use super::{LocalIdentity, SessionError, UnauditedSuite0001, WallClock};
use crate::identity::contacts::PairPsk;
use crate::identity::{
    BindingRequest, ContactStore, KeyId, KeyRole, MemoryStorage, SoftwareKeyStore, SoftwareSealer,
    StorageKey, TrustOrigin, VerifiedDeviceBinding, issue_device_binding,
};

const START: Duration = Duration::from_secs(1);
/// Fuzz builds enable the `unaudited-suite-0001` feature (`fuzz/Cargo.toml`).
const GATE: UnauditedSuite0001 = UnauditedSuite0001::acknowledge_not_production_ready();
const INIT_STATIC: [u8; 32] = [0x11; 32];
const RESP_STATIC: [u8; 32] = [0x33; 32];
const PSK: [u8; 32] = [0x55; 32];

/// Splits `data` into prelude records (`kind || body`), stopping at the
/// first invalid prefix or incomplete record.
fn records(mut data: &[u8]) -> Vec<&[u8]> {
    let mut out = Vec::new();
    while let Some((prefix, rest)) = data.split_first_chunk::<2>() {
        let Ok(length) = prelude_record_len(*prefix) else {
            break;
        };
        let Some(record) = rest.get(..length) else {
            break;
        };
        out.push(record);
        data = &rest[length..];
    }
    out
}

fn mode(selector: u8) -> SessionMode {
    match selector % 3 {
        0 => SessionMode::Qr,
        1 => SessionMode::Code,
        _ => SessionMode::Contact,
    }
}

fn key(secret: [u8; 32]) -> Option<NoiseStaticKey> {
    NoiseStaticKey::from_secret(Zeroizing::new(secret)).ok()
}

fn psk() -> PairingPsk {
    PairingPsk::from_bytes(Zeroizing::new(PSK))
}

fn transcript() -> CodeTranscript {
    CodeTranscript::new(
        [0x31; CODE_OFFER_LEN],
        [0x32; CODE_SHARE_LEN],
        [0x33; CODE_SHARE_LEN],
    )
}

/// The fixture `ClientHello` for `mode` (generation 7 for contacts).
fn client_hello(mode: SessionMode) -> Option<Hello> {
    let generation = if mode == SessionMode::Contact { 7 } else { 0 };
    Hello::client(mode, generation, [0xa1; 16], [0xa5; 16]).ok()
}

/// Handshake input parsing. The first byte selects the mode (`% 3`) and
/// the role (`& 4`: responder when clear); the rest is a stream of prelude
/// records fed to the driver until it fails or completes. The responder
/// also parses the first record as a `ClientHello`.
pub fn handshake_records(data: &[u8]) {
    let Some((&selector, stream)) = data.split_first() else {
        return;
    };
    let mode = mode(selector);
    let (Some(initiator_static), Some(responder_static)) = (key(INIT_STATIC), key(RESP_STATIC))
    else {
        return;
    };
    let Some(hello) = client_hello(mode) else {
        return;
    };
    let inputs = records(stream);
    if let Some(first) = inputs.first() {
        let _ = read_client_hello(first);
    }
    let driver = if selector & 4 == 0 {
        let plan = match mode {
            SessionMode::Qr => ResponderPlan::qr(psk()),
            SessionMode::Code => ResponderPlan::code_with_psk(psk(), transcript()),
            SessionMode::Contact => {
                ResponderPlan::contact(7, Zeroizing::new(PSK), *initiator_static.public_key())
            }
        };
        let entropy = Entropy::scripted(vec![vec![0x62; 32], vec![0x64; 32]]);
        HandshakeDriver::responder(
            GATE,
            hello,
            plan,
            &responder_static,
            [0xa6; 16],
            entropy,
            START,
        )
        .map(|(driver, _)| driver)
    } else {
        let plan = match mode {
            SessionMode::Qr => InitiatorPlan::qr([0xa1; 16], *responder_static.public_key(), psk()),
            SessionMode::Code => InitiatorPlan::code_with_psk([0xa1; 16], psk(), transcript()),
            SessionMode::Contact => InitiatorPlan::contact(
                7,
                [0xa1; 16],
                Zeroizing::new(PSK),
                *responder_static.public_key(),
            ),
        };
        let entropy = Entropy::scripted(vec![vec![0x61; 32], vec![0x63; 64]]);
        HandshakeDriver::initiator(GATE, plan, &initiator_static, [0xa5; 16], entropy, START)
            .map(|(driver, _)| driver)
    };
    let Ok(mut driver) = driver else {
        return;
    };
    for record in inputs {
        if driver.receive(record, START).is_err() {
            return;
        }
        if driver.is_done() {
            let _ = driver.finish();
            return;
        }
    }
}

// ---------------------------------------------------------------------------
// Deterministic contact session setup for the sans-IO harnesses.

/// Binding validity start; the sessions run one minute later.
const T0: u64 = 1_760_000_000;
const WALL: u64 = T0 + 60;
const GENERATION: u64 = 7;
const LOCATOR: [u8; 16] = [0xa1; 16];

type Keys = SoftwareKeyStore<MemoryStorage>;
type Store = ContactStore<SoftwareSealer, MemoryStorage>;

/// A fixed public test identity: root and device keys from public seeds,
/// the fixture Noise static key, and a 30-day binding.
struct Party {
    keys: Keys,
    device: KeyId,
    binding: VerifiedDeviceBinding,
    noise: NoiseStaticKey,
}

fn sealer(byte: u8) -> SoftwareSealer {
    SoftwareSealer::new(StorageKey::from_bytes(Zeroizing::new([byte; 32])))
}

fn party(seed: u8, noise_secret: [u8; 32]) -> Option<Party> {
    let mut keys = SoftwareKeyStore::open(sealer(seed), MemoryStorage::new()).ok()?;
    let root = keys
        .insert_fixed_seed(KeyRole::PersonRoot, [seed; 32])
        .ok()?;
    let device = keys.insert_fixed_seed(KeyRole::Device, [!seed; 32]).ok()?;
    let noise = key(noise_secret)?;
    let kem = libcrux_ml_kem::mlkem768::generate_key_pair([seed; 64]);
    let request = BindingRequest {
        noise_static: *noise.public_key(),
        kem_static: Box::new(*kem.public_key().as_slice()),
        serial: NonZeroU64::new(1)?,
        not_before: UnixTime::new(T0)?,
        not_after: UnixTime::new(T0 + 30 * 86_400)?,
    };
    let binding = issue_device_binding(&keys, &root, &device, request).ok()?;
    Some(Party {
        keys,
        device,
        binding,
        noise,
    })
}

/// The initiator and responder identities, built once per process.
fn parties() -> Option<&'static (Party, Party)> {
    static PARTIES: OnceLock<Option<(Party, Party)>> = OnceLock::new();
    PARTIES
        .get_or_init(|| Some((party(0x41, INIT_STATIC)?, party(0x42, RESP_STATIC)?)))
        .as_ref()
}

/// A complete, deterministic `KKpsk2` handshake: both `Split`s.
fn splits(initiator: &Party, responder: &Party) -> Option<(Split, Split)> {
    let plan = InitiatorPlan::contact(
        GENERATION,
        LOCATOR,
        Zeroizing::new(PSK),
        *responder.noise.public_key(),
    );
    let entropy = Entropy::scripted(vec![vec![0x61; 32], vec![0x63; 64]]);
    let (mut client, hello) =
        HandshakeDriver::initiator(GATE, plan, &initiator.noise, [0xa5; 16], entropy, START)
            .ok()?;
    let hello = read_client_hello(hello.get(2..)?).ok()?;
    let plan = ResponderPlan::contact(
        GENERATION,
        Zeroizing::new(PSK),
        *initiator.noise.public_key(),
    );
    let entropy = Entropy::scripted(vec![vec![0x62; 32], vec![0x64; 32]]);
    let (mut server, server_hello) = HandshakeDriver::responder(
        GATE,
        hello,
        plan,
        &responder.noise,
        [0xa6; 16],
        entropy,
        START,
    )
    .ok()?;
    let first = client.receive(server_hello.get(2..)?, START).ok()?;
    let second = server.receive(first.first()?.get(2..)?, START).ok()?;
    client.receive(second.first()?.get(2..)?, START).ok()?;
    Some((client.finish().ok()?, server.finish().ok()?))
}

/// A contact store pinning `peer` at [`GENERATION`] with the fixture PSK.
fn store(peer: &Party) -> Option<Store> {
    let mut store = ContactStore::open(sealer(0x5c), MemoryStorage::new()).ok()?;
    store
        .pair(
            &peer.binding,
            TrustOrigin::QrPairing,
            PairPsk::from_secret(&PSK),
            GENERATION,
            UnixTime::new(T0)?,
        )
        .ok()?;
    Some(store)
}

fn local(party: &Party) -> Option<LocalIdentity<'_, Keys>> {
    LocalIdentity::new(
        &party.keys,
        party.device,
        &party.binding,
        &party.noise,
        UnixTime::new(WALL)?,
    )
    .ok()
}

/// The ciphertext after a record's two-byte length prefix.
fn ciphertext(record: &[u8]) -> &[u8] {
    record.get(2..).unwrap_or_default()
}

/// Takes the next `n` input bytes, or what is left.
fn take<'a>(ops: &mut &'a [u8], n: usize) -> &'a [u8] {
    let (taken, rest) = ops.split_at(n.min(ops.len()));
    *ops = rest;
    taken
}

fn take_u8(ops: &mut &[u8]) -> u8 {
    take(ops, 1).first().copied().unwrap_or(0)
}

/// One side of the establishment phase with its authority.
struct EstablishSide<'a> {
    establishment: Establishment,
    local: LocalIdentity<'a, Keys>,
    authority: ContactAuthority<'a, SoftwareSealer, MemoryStorage>,
}

impl EstablishSide<'_> {
    /// Feeds one record; on success returns the replies, after the
    /// responder's "Ack queued" step.
    fn receive(&mut self, record: &[u8], now: Duration) -> Result<Vec<Vec<u8>>, SessionError> {
        let replies = self
            .establishment
            .receive(record, &self.local, &mut self.authority, now)?;
        if self.establishment.phase() == Phase::AckPending {
            self.establishment.ack_queued(&mut self.authority)?;
        }
        Ok(replies)
    }
}

/// What one establishment-harness operation asks the fuzzed side to do.
enum WireOp {
    /// Receive these records (possibly none).
    Deliver(Vec<Vec<u8>>),
    /// Run the deadline check.
    CheckDeadline,
}

/// Applies one wire operation of [`establishment_records`] to the queue of
/// honest peer records.
fn wire_op(
    op: u8,
    ops: &mut &[u8],
    to_target: &mut VecDeque<Vec<u8>>,
    now: &mut Duration,
) -> WireOp {
    let records = match op % 8 {
        0 => to_target.pop_front().into_iter().collect(),
        1 => {
            let position = usize::from(u16::from_be_bytes([take_u8(ops), take_u8(ops)]));
            let bit = take_u8(ops) % 8;
            to_target
                .pop_front()
                .map(|mut record| {
                    let index = position % record.len().max(1);
                    if let Some(byte) = record.get_mut(index) {
                        *byte ^= 1 << bit;
                    }
                    record
                })
                .into_iter()
                .collect()
        }
        2 => vec![raw_record(ops)],
        3 => {
            to_target.pop_front();
            Vec::new()
        }
        4 => {
            *now = now.saturating_add(Duration::from_secs(u64::from(take_u8(ops))));
            Vec::new()
        }
        5 => to_target
            .pop_front()
            .map(|record| vec![record.clone(), record])
            .unwrap_or_default(),
        6 => return WireOp::CheckDeadline,
        _ => {
            if to_target.len() >= 2 {
                to_target.swap(0, 1);
            }
            Vec::new()
        }
    };
    WireOp::Deliver(records)
}

/// A record of raw input bytes (next byte: length), behind a dummy prefix.
fn raw_record(ops: &mut &[u8]) -> Vec<u8> {
    let length = usize::from(take_u8(ops));
    let mut record = vec![0; 2];
    record.extend_from_slice(take(ops, length));
    record
}

/// `Establishment::receive` (§4.3, §4.4) on the side selected by the first
/// byte (`& 1`: responder when set), against an honest peer. Each later byte
/// is an operation on the record stream toward the fuzzed side:
///
/// | Op (`% 8`) | Action |
/// | --- | --- |
/// | 0 | deliver the peer's next record |
/// | 1 | deliver it with one bit flipped (next 3 bytes: position, bit) |
/// | 2 | deliver raw bytes (next byte: length, then the bytes) |
/// | 3 | drop the peer's next record |
/// | 4 | advance the clock (next byte: seconds) |
/// | 5 | deliver the peer's next record twice |
/// | 6 | deadline check with the current clock |
/// | 7 | swap the next two peer records |
///
/// Once the fuzzed side's gate opens it builds the session core and stops.
pub fn establishment_records(data: &[u8]) {
    let Some((&selector, mut ops)) = data.split_first() else {
        return;
    };
    let Some((initiator, responder)) = parties() else {
        return;
    };
    let Some((split_i, split_r)) = splits(initiator, responder) else {
        return;
    };
    let (Some(mut store_i), Some(mut store_r)) = (store(responder), store(initiator)) else {
        return;
    };
    let (Some(local_i), Some(local_r), Some(wall)) =
        (local(initiator), local(responder), UnixTime::new(WALL))
    else {
        return;
    };
    let wall = WallClock::new(wall, START);
    let (Ok(authority_i), Ok(authority_r)) = (
        store_i.session_authority(responder.binding.device_public()),
        store_r.session_authority(initiator.binding.device_public()),
    ) else {
        return;
    };
    let side_i = EstablishSide {
        establishment: Establishment::new(split_i, START, wall, Limits::SPEC),
        local: local_i,
        authority: authority_i,
    };
    let side_r = EstablishSide {
        establishment: Establishment::new(split_r, START, wall, Limits::SPEC),
        local: local_r,
        authority: authority_r,
    };
    let (mut target, mut peer) = if selector & 1 == 0 {
        (side_i, side_r)
    } else {
        (side_r, side_i)
    };
    let mut now = START;
    let mut to_target: VecDeque<Vec<u8>> = VecDeque::new();
    let Ok(first) = target.establishment.start(&target.local, now) else {
        return;
    };
    let mut to_peer: Vec<Vec<u8>> = first;
    if let Ok(records) = peer.establishment.start(&peer.local, now) {
        to_target.extend(records);
    }
    loop {
        // The honest peer answers everything the fuzzed side sent.
        for record in core::mem::take(&mut to_peer) {
            if let Ok(replies) = peer.receive(ciphertext(&record), now) {
                to_target.extend(replies);
            }
        }
        let Some(&op) = ops.first() else {
            return;
        };
        ops = &ops[1..];
        let delivered = match wire_op(op, &mut ops, &mut to_target, &mut now) {
            WireOp::Deliver(records) => records,
            WireOp::CheckDeadline => {
                if target
                    .establishment
                    .check_deadline(now, &mut target.authority)
                    .is_err()
                {
                    return;
                }
                Vec::new()
            }
        };
        for record in delivered {
            match target.receive(ciphertext(&record), now) {
                Ok(replies) => to_peer.extend(replies),
                Err(_) => return,
            }
            if target.establishment.phase() == Phase::Open {
                let EstablishSide {
                    establishment,
                    local,
                    ..
                } = target;
                let _ = establishment.into_core(&local, Entropy::scripted(Vec::new()), now);
                return;
            }
        }
    }
}

/// What the honest peer of [`transport_records`] sends for one operation.
fn peer_records(op: u8, ops: &mut &[u8], peer: &mut FrameTransport, now: Duration) -> Vec<Vec<u8>> {
    match op {
        0 | 6 => {
            let frame_type = FrameType::new(u16::from_be_bytes([take_u8(ops), take_u8(ops)]));
            let length = usize::from(take_u8(ops));
            let body = take(ops, length).to_vec();
            let mut records = peer.seal(frame_type, &body, now).unwrap_or_default();
            if op == 6 {
                let position = usize::from(u16::from_be_bytes([take_u8(ops), take_u8(ops)]));
                let bit = take_u8(ops) % 8;
                if let Some(record) = records.last_mut() {
                    let index = position % record.len().max(1);
                    if let Some(byte) = record.get_mut(index) {
                        *byte ^= 1 << bit;
                    }
                }
            }
            records
        }
        1 => peer.key_update(now).into_iter().collect(),
        2 | 3 => {
            let frame_type = if op == 2 {
                FrameType::PING
            } else {
                FrameType::PONG
            };
            let nonce = take(ops, 8).to_vec();
            peer.seal(frame_type, &nonce, now).unwrap_or_default()
        }
        4 => {
            let body = take(ops, 19).to_vec();
            peer.seal(FrameType::ERROR, &body, now).unwrap_or_default()
        }
        5 => vec![raw_record(ops)],
        _ => {
            let epoch = take(ops, 8).to_vec();
            peer.seal(FrameType::KEY_UPDATE, &epoch, now)
                .unwrap_or_default()
        }
    }
}

/// `SessionCore::receive` and its timers (§5, §12, §13) on an established
/// session, after a deterministic handshake. The first byte selects the
/// role (`& 1`) and a small byte budget (`& 2`, to reach rekey limits).
/// Each later byte is an operation; the peer encrypts with the real
/// transport framing, so records authenticate unless corrupted:
///
/// | Op (`% 10`) | Action |
/// | --- | --- |
/// | 0 | peer sends a frame (next 2 bytes: type; next byte: body length, then the body) |
/// | 1 | peer sends `KeyUpdate` |
/// | 2 | peer sends `Ping` (next 8 bytes: nonce) |
/// | 3 | peer sends `Pong` (next 8 bytes: nonce) |
/// | 4 | peer sends `Error` (next 19 bytes: body) |
/// | 5 | raw bytes as a ciphertext (next byte: length, then the bytes) |
/// | 6 | peer sends a frame with one bit flipped (next 3 bytes: position, bit) |
/// | 7 | advance the clock (next byte: seconds) and run the timers |
/// | 8 | the fuzzed side sends a frame or requests a rekey |
/// | 9 | peer sends a crafted `KeyUpdate` (next 8 bytes: epoch) |
pub fn transport_records(data: &[u8]) {
    let Some((&selector, mut ops)) = data.split_first() else {
        return;
    };
    let Some((initiator, responder)) = parties() else {
        return;
    };
    let Some((split_i, split_r)) = splits(initiator, responder) else {
        return;
    };
    let limits = if selector & 2 == 0 {
        Limits::SPEC
    } else {
        Limits { byte_budget: 4096 }
    };
    let (target_split, peer_split, peer_party) = if selector & 1 == 0 {
        (split_i, split_r, responder)
    } else {
        (split_r, split_i, initiator)
    };
    let info = SessionInfo {
        role: target_split.role,
        mode: target_split.mode,
        handshake_hash: target_split.handshake_hash,
        session_id: target_split.session_id,
        peer_static: target_split.peer_static,
        peer_binding: peer_party.binding.clone(),
    };
    let mut now = START;
    let mut target = SessionCore::new(
        FrameTransport::new(target_split.transport, now, limits),
        info,
        Entropy::scripted(vec![vec![0x5a; 8]; 16]),
        now,
        MAX_SESSION_DURATION,
    );
    let mut peer = FrameTransport::new(peer_split.transport, now, limits);
    peer.allow_updates();
    while let Some(&op) = ops.first() {
        ops = &ops[1..];
        let sealed = match op % 10 {
            7 => {
                now = now.saturating_add(Duration::from_secs(u64::from(take_u8(&mut ops))));
                let _ = target.poll(now);
                Vec::new()
            }
            8 => {
                let _ = if take_u8(&mut ops).is_multiple_of(2) {
                    target.send(FrameType::CAPABILITIES, b"fuzz", now)
                } else {
                    target.request_rekey(now)
                };
                Vec::new()
            }
            other => peer_records(other, &mut ops, &mut peer, now),
        };
        for record in sealed {
            let _ = target.receive(ciphertext(&record), now);
        }
        // What the fuzzed side would send is not fed back.
        while target.pop_outgoing().is_some() {}
    }
}

/// A pipe that returns `Pending` before every read and then at most `chunk`
/// bytes, so record boundaries fall anywhere and progress must survive.
struct ChunkedPipe<'a> {
    stream: &'a [u8],
    chunk: usize,
    pending: bool,
}

impl AsyncRead for ChunkedPipe<'_> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        self.pending = !self.pending;
        if self.pending {
            return Poll::Pending;
        }
        let count = buf.len().min(self.chunk).min(self.stream.len());
        let (head, rest) = self.stream.split_at(count);
        buf[..count].copy_from_slice(head);
        self.stream = rest;
        Poll::Ready(Ok(count))
    }
}

/// The incremental length-prefixed record reader of the async adapter
/// (PROTOCOL §4.1, §5, §13) on an arbitrary byte stream.
///
/// The first byte selects the framing (bit 0: prelude or transport) and the
/// largest read (bits 1..7: 1 to 128 bytes); the rest is the stream. The
/// reader's records must equal a direct split of the same bytes, and it must
/// stop exactly at the first out-of-range prefix (`MALFORMED`) or at the end
/// of the stream (`Closed`), never returning a partial record.
pub fn record_stream(data: &[u8]) {
    let Some((&control, stream)) = data.split_first() else {
        return;
    };
    let framing = if control & 1 == 0 {
        Framing::Prelude
    } else {
        Framing::Transport
    };
    let mut pipe = ChunkedPipe {
        stream,
        chunk: usize::from(control >> 1) + 1,
        pending: false,
    };
    let mut reader = RecordReader::new();
    let mut cx = Context::from_waker(Waker::noop());
    let mut records = Vec::new();
    let error = loop {
        match reader.poll_record(&mut pipe, framing, &mut cx) {
            Poll::Ready(Ok(record)) => records.push(record),
            Poll::Ready(Err(error)) => break error,
            Poll::Pending => {}
        }
    };
    let mut expected = Vec::new();
    let mut rest = stream;
    let expected_error = loop {
        let Some((prefix, after)) = rest.split_first_chunk::<2>() else {
            break SessionError::Closed;
        };
        let length = match framing {
            Framing::Prelude => prelude_record_len(*prefix),
            Framing::Transport => ciphertext_len(*prefix),
        };
        let Ok(length) = length else {
            break SessionError::Protocol(ErrorCode::MALFORMED);
        };
        let Some(record) = after.get(..length) else {
            break SessionError::Closed;
        };
        expected.push(record.to_vec());
        rest = &after[length..];
    };
    assert_eq!(records, expected);
    assert_eq!(error, expected_error);
}
