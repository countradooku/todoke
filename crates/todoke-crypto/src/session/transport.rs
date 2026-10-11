//! Sans-IO Noise transport framing, rekey, keepalive, and Error handling
//! (PROTOCOL §5, §12, §13).
//!
//! Each record on the pipe is `ciphertext_len:u16 || ciphertext`; the
//! plaintext is `type:u16 || flags:u16 || body`. Every directional
//! `CipherState` belongs to Snow; nonces are its counters and never wrap.

use core::fmt;
use core::time::Duration;
use std::collections::VecDeque;

use todoke_proto::session::{
    CIPHERTEXT_PREFIX_LEN, ERROR_LEN, ErrorCode, ErrorRecord, ErrorScope, FrameClass, FrameType,
    MAX_CIPHERTEXT_LEN, MAX_NONCRITICAL_BODY_LEN, MIN_CIPHERTEXT_LEN, TAG_LEN, decode_frame,
    decode_key_update, decode_ping, encode_frame_into,
};
use zeroize::Zeroizing;

use super::engine::{Entropy, NoiseTransport};
use super::{Role, SessionError};
use crate::identity::VerifiedDeviceBinding;
use todoke_proto::session::SessionMode;

/// Ordinary ciphertext bytes per directional key before a `KeyUpdate` is
/// mandatory: 2^30 (§5).
pub const BYTE_BUDGET: u64 = 1 << 30;
/// Longest a directional key may stay in use: 120 seconds (§5).
pub const MAX_KEY_AGE: Duration = Duration::from_secs(120);
/// When this implementation schedules its time-based `KeyUpdate`: early
/// enough that a late timer wake-up still meets [`MAX_KEY_AGE`].
pub const LOCAL_REKEY_INTERVAL: Duration = Duration::from_secs(100);
/// Earliest repeat of a `KeyUpdate` absent byte-budget exhaustion (§5).
pub const MIN_REKEY_INTERVAL: Duration = Duration::from_secs(1);
/// Send `Ping` after this long without authenticated traffic (§13).
pub const PING_AFTER: Duration = Duration::from_secs(30);
/// `Pong` must arrive within this (§13).
pub const PONG_TIMEOUT: Duration = Duration::from_secs(10);
/// No authenticated traffic for this long closes the session (§5, §13).
pub const IDLE_TIMEOUT: Duration = Duration::from_secs(135);
/// Longest session (§13).
pub const MAX_SESSION_DURATION: Duration = Duration::from_secs(24 * 60 * 60);

/// `KeyUpdate` ciphertext: 4-byte header, 8-byte epoch, 16-byte tag.
const KEY_UPDATE_CIPHERTEXT_LEN: usize = 28;
/// Unknown noncritical frames per session (§13).
const MAX_NONCRITICAL_FRAMES: u8 = 32;

/// Tunable bounds; production always uses [`Limits::SPEC`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Limits {
    pub(crate) byte_budget: u64,
}

impl Limits {
    pub(crate) const SPEC: Self = Self {
        byte_budget: BYTE_BUDGET,
    };
}

#[derive(Clone, Copy, Debug)]
struct Direction {
    /// 0 for the Split key; each `KeyUpdate` announces the next value.
    epoch: u64,
    /// Ordinary ciphertext bytes under the current key.
    bytes: u64,
    key_since: Duration,
}

impl Direction {
    const fn new(now: Duration) -> Self {
        Self {
            epoch: 0,
            bytes: 0,
            key_since: now,
        }
    }
}

/// A decrypted frame delivered to the caller. The body is zeroized on drop:
/// later frame types carry keys and file content.
pub struct Frame {
    frame_type: FrameType,
    body: Zeroizing<Vec<u8>>,
}

impl Frame {
    /// The frame type.
    #[must_use]
    pub fn frame_type(&self) -> FrameType {
        self.frame_type
    }

    /// The body, authenticated but not yet validated against its layout.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

impl fmt::Debug for Frame {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Frame")
            .field("frame_type", &self.frame_type)
            .field("body", &format_args!("[{} bytes]", self.body.len()))
            .finish()
    }
}

pub(crate) enum Opened {
    Frame(FrameType, Zeroizing<Vec<u8>>),
    KeyUpdated,
}

/// The encrypted framing over a `NoiseTransport`, with §5 rekey rules.
pub(crate) struct FrameTransport {
    noise: NoiseTransport,
    limits: Limits,
    send: Direction,
    recv: Direction,
    last_update_sent: Option<Duration>,
    updates_allowed: bool,
    closed: bool,
}

fn prefixed(ciphertext: &[u8]) -> Result<Vec<u8>, SessionError> {
    let length = u16::try_from(ciphertext.len()).map_err(|_| SessionError::Usage)?;
    let mut record = Vec::with_capacity(CIPHERTEXT_PREFIX_LEN + ciphertext.len());
    record.extend_from_slice(&length.to_be_bytes());
    record.extend_from_slice(ciphertext);
    Ok(record)
}

const fn protocol(code: ErrorCode) -> SessionError {
    SessionError::Protocol(code)
}

impl FrameTransport {
    pub(crate) fn new(noise: NoiseTransport, now: Duration, limits: Limits) -> Self {
        Self {
            noise,
            limits,
            send: Direction::new(now),
            recv: Direction::new(now),
            last_update_sent: None,
            updates_allowed: false,
            closed: false,
        }
    }

    /// `KeyUpdate` is valid only once the ratchet committed (§11).
    pub(crate) fn allow_updates(&mut self) {
        self.updates_allowed = true;
    }

    pub(crate) fn close(&mut self) {
        self.closed = true;
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.closed
    }

    fn encrypt(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, SessionError> {
        if let Ok(ciphertext) = self.noise.encrypt(plaintext) {
            prefixed(&ciphertext)
        } else {
            // An exhausted nonce or internal failure: the CipherState must
            // not be used again (§5).
            self.closed = true;
            Err(SessionError::Closed)
        }
    }

    /// Encrypts one frame. If it would push the sending key past the byte
    /// budget, a `KeyUpdate` is emitted first under the old key (§5).
    pub(crate) fn seal(
        &mut self,
        frame_type: FrameType,
        body: &[u8],
        now: Duration,
    ) -> Result<Vec<Vec<u8>>, SessionError> {
        if self.closed {
            return Err(SessionError::Closed);
        }
        let mut plaintext = Zeroizing::new(Vec::new());
        encode_frame_into(frame_type, body, &mut plaintext).map_err(|_| SessionError::Usage)?;
        let length = u64::try_from(plaintext.len() + TAG_LEN).unwrap_or(u64::MAX);
        let mut records = Vec::with_capacity(2);
        if self.send.bytes.saturating_add(length) > self.limits.byte_budget {
            if !self.updates_allowed {
                return Err(protocol(ErrorCode::LIMIT));
            }
            records.push(self.key_update(now)?);
        }
        records.push(self.encrypt(&plaintext)?);
        self.send.bytes += length;
        Ok(records)
    }

    /// Sends `KeyUpdate` under the current key, then applies Noise `REKEY`
    /// to the sending direction. Its bytes count toward neither epoch.
    pub(crate) fn key_update(&mut self, now: Duration) -> Result<Vec<u8>, SessionError> {
        if self.closed {
            return Err(SessionError::Closed);
        }
        if !self.updates_allowed {
            return Err(SessionError::Usage);
        }
        let Some(epoch) = self.send.epoch.checked_add(1) else {
            self.closed = true;
            return Err(protocol(ErrorCode::LIMIT));
        };
        let mut plaintext = Zeroizing::new(Vec::new());
        encode_frame_into(FrameType::KEY_UPDATE, &epoch.to_be_bytes(), &mut plaintext)
            .map_err(|_| SessionError::Usage)?;
        let record = self.encrypt(&plaintext)?;
        self.noise.rekey_outgoing();
        self.send = Direction {
            epoch,
            bytes: 0,
            key_since: now,
        };
        self.last_update_sent = Some(now);
        Ok(record)
    }

    /// An explicit early update: at most one per [`MIN_REKEY_INTERVAL`].
    pub(crate) fn requested_key_update(&mut self, now: Duration) -> Result<Vec<u8>, SessionError> {
        if self
            .last_update_sent
            .is_some_and(|last| now < last.saturating_add(MIN_REKEY_INTERVAL))
        {
            return Err(SessionError::RekeyTooSoon);
        }
        self.key_update(now)
    }

    /// When the time-based update is due.
    pub(crate) fn rekey_deadline(&self) -> Duration {
        self.send.key_since.saturating_add(LOCAL_REKEY_INTERVAL)
    }

    /// Decrypts and parses one record body (after the length prefix).
    /// `KeyUpdate` is consumed here. Any failure is fatal.
    pub(crate) fn open(
        &mut self,
        ciphertext: &[u8],
        now: Duration,
    ) -> Result<Opened, SessionError> {
        if self.closed {
            return Err(SessionError::Closed);
        }
        let result = self.open_inner(ciphertext, now);
        if result.is_err() {
            self.closed = true;
        }
        result
    }

    fn open_inner(&mut self, ciphertext: &[u8], now: Duration) -> Result<Opened, SessionError> {
        if !(MIN_CIPHERTEXT_LEN..=MAX_CIPHERTEXT_LEN).contains(&ciphertext.len()) {
            return Err(protocol(ErrorCode::MALFORMED));
        }
        // Failed decryption closes immediately and reveals nothing (§5).
        let mut plaintext = self
            .noise
            .decrypt(ciphertext)
            .map_err(|_| SessionError::Authentication)?;
        let (frame_type, body) =
            decode_frame(&plaintext).map_err(|_| protocol(ErrorCode::MALFORMED))?;
        if frame_type == FrameType::KEY_UPDATE {
            if !self.updates_allowed {
                return Err(protocol(ErrorCode::STATE));
            }
            if ciphertext.len() != KEY_UPDATE_CIPHERTEXT_LEN {
                return Err(protocol(ErrorCode::MALFORMED));
            }
            let epoch = decode_key_update(body).map_err(|_| protocol(ErrorCode::MALFORMED))?;
            // Duplicate, skipped, or wrapped epochs are fatal (§5).
            if self.recv.epoch.checked_add(1) != Some(epoch) {
                return Err(protocol(ErrorCode::STATE));
            }
            self.noise.rekey_incoming();
            self.recv = Direction {
                epoch,
                bytes: 0,
                key_since: now,
            };
            return Ok(Opened::KeyUpdated);
        }
        self.recv.bytes = self
            .recv
            .bytes
            .saturating_add(u64::try_from(ciphertext.len()).unwrap_or(u64::MAX));
        if self.recv.bytes > self.limits.byte_budget {
            return Err(protocol(ErrorCode::LIMIT));
        }
        plaintext.drain(..todoke_proto::session::FRAME_HEADER_LEN);
        Ok(Opened::Frame(frame_type, plaintext))
    }

    #[cfg(test)]
    pub(crate) fn epochs(&self) -> (u64, u64) {
        (self.send.epoch, self.recv.epoch)
    }
}

impl fmt::Debug for FrameTransport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FrameTransport")
            .field("send_epoch", &self.send.epoch)
            .field("recv_epoch", &self.recv.epoch)
            .field("closed", &self.closed)
            .finish_non_exhaustive()
    }
}

/// Public facts about an established session.
#[derive(Clone, Debug)]
pub(crate) struct SessionInfo {
    pub(crate) role: Role,
    pub(crate) mode: SessionMode,
    pub(crate) handshake_hash: [u8; 32],
    pub(crate) session_id: [u8; 32],
    pub(crate) peer_static: [u8; 32],
    pub(crate) peer_binding: VerifiedDeviceBinding,
}

/// The established session after the ratchet gate opened (§11 "Ratchet
/// committed" and "Ready").
pub(crate) struct SessionCore {
    transport: FrameTransport,
    info: SessionInfo,
    entropy: Entropy,
    last_received: Duration,
    ping: Option<(u64, Duration)>,
    hard_deadline: Duration,
    deadline_is_expiry: bool,
    noncritical_frames: u8,
    peer_capabilities_seen: bool,
    outgoing: VecDeque<Vec<u8>>,
}

impl SessionCore {
    /// `binding_lifetime` is how long both bindings remain valid from `now`
    /// (§2: an active session closes on binding expiry).
    pub(crate) fn new(
        mut transport: FrameTransport,
        info: SessionInfo,
        entropy: Entropy,
        now: Duration,
        binding_lifetime: Duration,
    ) -> Self {
        transport.allow_updates();
        let deadline_is_expiry = binding_lifetime < MAX_SESSION_DURATION;
        Self {
            transport,
            info,
            entropy,
            last_received: now,
            ping: None,
            hard_deadline: now.saturating_add(binding_lifetime.min(MAX_SESSION_DURATION)),
            deadline_is_expiry,
            noncritical_frames: 0,
            peer_capabilities_seen: false,
            outgoing: VecDeque::new(),
        }
    }

    pub(crate) fn info(&self) -> &SessionInfo {
        &self.info
    }

    pub(crate) fn is_closed(&self) -> bool {
        self.transport.is_closed()
    }

    pub(crate) fn pop_outgoing(&mut self) -> Option<Vec<u8>> {
        self.outgoing.pop_front()
    }

    /// Closes with `error`. A protocol error is reported to the peer once
    /// (§12), unless it answers an `Error` or the cipher is unusable.
    fn fail(&mut self, error: SessionError, now: Duration) -> SessionError {
        let code = match error {
            SessionError::Protocol(code) => Some(code),
            SessionError::Timeout if self.deadline_is_expiry && now >= self.hard_deadline => {
                Some(ErrorCode::EXPIRED)
            }
            SessionError::Timeout => Some(ErrorCode::TIMEOUT),
            _ => None,
        };
        if let Some(code) = code {
            if !self.transport.is_closed() {
                if let Ok(record) = ErrorRecord::new(ErrorScope::Session, code) {
                    if let Ok(records) =
                        self.transport.seal(FrameType::ERROR, &record.encode(), now)
                    {
                        self.outgoing.extend(records);
                    }
                }
            }
        }
        self.transport.close();
        error
    }

    /// Queues an application frame. Session-layer and unassigned types are
    /// refused: Identity, ratchet, `KeyUpdate`, Ping/Pong, and Error belong
    /// to this layer, and v1 enables no extension types (§5, §6).
    pub(crate) fn send(
        &mut self,
        frame_type: FrameType,
        body: &[u8],
        now: Duration,
    ) -> Result<(), SessionError> {
        self.poll(now)?;
        if frame_type.class() != FrameClass::Application {
            return Err(SessionError::Usage);
        }
        match self.transport.seal(frame_type, body, now) {
            Ok(records) => {
                self.outgoing.extend(records);
                Ok(())
            }
            Err(SessionError::Usage) => Err(SessionError::Usage),
            Err(error) => Err(self.fail(error, now)),
        }
    }

    /// Queues an `Error`; a session-scoped one closes the session (§12).
    pub(crate) fn send_error(
        &mut self,
        record: ErrorRecord,
        now: Duration,
    ) -> Result<(), SessionError> {
        self.poll(now)?;
        let records = self
            .transport
            .seal(FrameType::ERROR, &record.encode(), now)
            .map_err(|error| self.fail(error, now))?;
        self.outgoing.extend(records);
        if record.scope() == ErrorScope::Session {
            self.transport.close();
        }
        Ok(())
    }

    pub(crate) fn request_rekey(&mut self, now: Duration) -> Result<(), SessionError> {
        self.poll(now)?;
        match self.transport.requested_key_update(now) {
            Ok(record) => {
                self.outgoing.push_back(record);
                Ok(())
            }
            Err(SessionError::RekeyTooSoon) => Err(SessionError::RekeyTooSoon),
            Err(error) => Err(self.fail(error, now)),
        }
    }

    /// Handles one received record body. Returns a frame for the caller, or
    /// `None` for one this layer consumed.
    pub(crate) fn receive(
        &mut self,
        ciphertext: &[u8],
        now: Duration,
    ) -> Result<Option<Frame>, SessionError> {
        if self.transport.is_closed() {
            return Err(SessionError::Closed);
        }
        match self.receive_inner(ciphertext, now) {
            Ok(frame) => Ok(frame),
            Err(error) => Err(self.fail(error, now)),
        }
    }

    fn receive_inner(
        &mut self,
        ciphertext: &[u8],
        now: Duration,
    ) -> Result<Option<Frame>, SessionError> {
        let opened = self.transport.open(ciphertext, now)?;
        self.last_received = now;
        let (frame_type, body) = match opened {
            Opened::KeyUpdated => return Ok(None),
            Opened::Frame(frame_type, body) => (frame_type, body),
        };
        match frame_type.class() {
            FrameClass::Session => self.session_frame(frame_type, body, now),
            FrameClass::Application => {
                if frame_type == FrameType::CAPABILITIES {
                    self.peer_capabilities_seen = true;
                }
                Ok(Some(Frame { frame_type, body }))
            }
            // v1 enables no extension: every noncritical frame is unknown
            // and skipped within the §13 budget, after Capabilities.
            FrameClass::Noncritical => {
                if !self.peer_capabilities_seen {
                    return Err(protocol(ErrorCode::STATE));
                }
                self.noncritical_frames += 1;
                if body.len() > MAX_NONCRITICAL_BODY_LEN
                    || self.noncritical_frames > MAX_NONCRITICAL_FRAMES
                {
                    return Err(protocol(ErrorCode::LIMIT));
                }
                Ok(None)
            }
            FrameClass::UnsupportedCritical | FrameClass::Experimental => {
                Err(protocol(ErrorCode::UNSUPPORTED))
            }
        }
    }

    fn session_frame(
        &mut self,
        frame_type: FrameType,
        body: Zeroizing<Vec<u8>>,
        now: Duration,
    ) -> Result<Option<Frame>, SessionError> {
        match frame_type {
            FrameType::PING => {
                let nonce = decode_ping(&body).map_err(|_| protocol(ErrorCode::MALFORMED))?;
                let records = self
                    .transport
                    .seal(FrameType::PONG, &nonce.to_be_bytes(), now)?;
                self.outgoing.extend(records);
                Ok(None)
            }
            FrameType::PONG => {
                let nonce = decode_ping(&body).map_err(|_| protocol(ErrorCode::MALFORMED))?;
                match self.ping {
                    Some((expected, _)) if expected == nonce => {
                        self.ping = None;
                        Ok(None)
                    }
                    _ => Err(protocol(ErrorCode::STATE)),
                }
            }
            FrameType::ERROR => {
                if body.len() != ERROR_LEN {
                    // Never answer an Error with an Error (§12).
                    self.transport.close();
                    return Err(SessionError::PeerError(ErrorCode::MALFORMED));
                }
                match ErrorRecord::decode(&body) {
                    Ok(record) if record.scope() == ErrorScope::Session => {
                        self.transport.close();
                        Err(SessionError::PeerError(record.code()))
                    }
                    Ok(_) => Ok(Some(Frame { frame_type, body })),
                    Err(_) => {
                        self.transport.close();
                        Err(SessionError::PeerError(ErrorCode::MALFORMED))
                    }
                }
            }
            // Identity and the ratchet records are over; KeyUpdate was
            // consumed by the transport.
            _ => Err(protocol(ErrorCode::STATE)),
        }
    }

    /// Runs timers: hard deadline, idle close, Pong deadline, Ping, and the
    /// time-based `KeyUpdate`.
    pub(crate) fn poll(&mut self, now: Duration) -> Result<(), SessionError> {
        if self.transport.is_closed() {
            return Err(SessionError::Closed);
        }
        let expired = now >= self.hard_deadline
            || now >= self.last_received.saturating_add(IDLE_TIMEOUT)
            || self
                .ping
                .is_some_and(|(_, sent)| now >= sent.saturating_add(PONG_TIMEOUT));
        if expired {
            return Err(self.fail(SessionError::Timeout, now));
        }
        if self.ping.is_none() && now >= self.last_received.saturating_add(PING_AFTER) {
            let mut nonce = [0; 8];
            loop {
                self.entropy
                    .fill(&mut nonce)
                    .map_err(|_| SessionError::Random)?;
                if nonce != [0; 8] {
                    break;
                }
            }
            match self.transport.seal(FrameType::PING, &nonce, now) {
                Ok(records) => self.outgoing.extend(records),
                Err(error) => return Err(self.fail(error, now)),
            }
            self.ping = Some((u64::from_be_bytes(nonce), now));
        }
        if now >= self.transport.rekey_deadline() {
            match self.transport.key_update(now) {
                Ok(record) => self.outgoing.push_back(record),
                Err(error) => return Err(self.fail(error, now)),
            }
        }
        Ok(())
    }

    /// The next instant [`Self::poll`] has work to do.
    pub(crate) fn next_deadline(&self) -> Duration {
        let keepalive = match self.ping {
            Some((_, sent)) => sent.saturating_add(PONG_TIMEOUT),
            None => self.last_received.saturating_add(PING_AFTER),
        };
        self.hard_deadline
            .min(self.last_received.saturating_add(IDLE_TIMEOUT))
            .min(keepalive)
            .min(self.transport.rekey_deadline())
    }

    #[cfg(test)]
    pub(crate) fn transport(&self) -> &FrameTransport {
        &self.transport
    }
}

impl fmt::Debug for SessionCore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SessionCore")
            .field("role", &self.info.role)
            .field("mode", &self.info.mode)
            .field("transport", &self.transport)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests;
