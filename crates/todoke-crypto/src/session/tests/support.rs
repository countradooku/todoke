//! Shared fixtures: devices with real Noise keys, paired contact stores,
//! and a sans-IO two-party harness whose wire an adversary controls.

use core::time::Duration;
use std::collections::VecDeque;

use todoke_proto::session::{CIPHERTEXT_PREFIX_LEN, ciphertext_len, prelude_record_len};
use todoke_proto::time::UnixTime;

use crate::identity::contacts::PairPsk;
use crate::identity::test_support::{Enrolled, T0, sealer, time};
use crate::identity::{
    ContactStore, Ed25519PublicKey, MemoryStorage, SoftwareKeyStore, SoftwareSealer, TrustOrigin,
    VerifiedDeviceBinding,
};
use crate::session::authority::PeerAuthority;
use crate::session::engine::Entropy;
use crate::session::establish::{Establishment, Phase};
use crate::session::handshake::{self, HandshakeDriver, InitiatorPlan, ResponderPlan};
use crate::session::transport::{Limits, SessionCore};
use crate::session::{LocalIdentity, NoiseStaticKey, Role, SessionError};

pub(crate) type AnyResult<T> = Result<T, Box<dyn std::error::Error>>;
pub(crate) type TestResult = AnyResult<()>;
pub(crate) type Keys = SoftwareKeyStore<MemoryStorage>;
pub(crate) type Store = ContactStore<SoftwareSealer, MemoryStorage>;

/// Wall-clock time of every test session: one minute into the bindings'
/// 30-day validity.
pub(crate) const WALL: u64 = T0 + 60;
/// Monotonic start of every harness run.
pub(crate) const START: Duration = Duration::from_secs(10_000);
/// The PSK both stores hold before a session.
pub(crate) const OLD_PSK: [u8; 32] = [0x77; 32];

/// A device: a person root and device key, a real X25519 Noise static key,
/// and a binding certifying it.
pub(crate) struct Device {
    pub(crate) enrolled: Enrolled,
    pub(crate) noise: NoiseStaticKey,
    pub(crate) binding: VerifiedDeviceBinding,
}

impl Device {
    pub(crate) fn new() -> AnyResult<Self> {
        let enrolled = Enrolled::new()?;
        let noise = NoiseStaticKey::generate()?;
        let binding = enrolled.bind_noise(1, *noise.public_key())?;
        Ok(Self {
            enrolled,
            noise,
            binding,
        })
    }

    pub(crate) fn local(&self) -> AnyResult<LocalIdentity<'_, Keys>> {
        self.local_at(WALL)
    }

    pub(crate) fn local_at(&self, wall: u64) -> AnyResult<LocalIdentity<'_, Keys>> {
        Ok(LocalIdentity::new(
            &self.enrolled.store,
            self.enrolled.device,
            &self.binding,
            &self.noise,
            UnixTime::new(wall).ok_or("time")?,
        )?)
    }

    pub(crate) fn key(&self) -> Ed25519PublicKey {
        *self.binding.device_public()
    }
}

/// A store in which `owner` has paired `peer` at `generation` with
/// [`OLD_PSK`].
pub(crate) fn store_pairing(peer: &Device, generation: u64) -> AnyResult<Store> {
    let mut store = ContactStore::open(sealer(9), MemoryStorage::new())?;
    store.pair(
        &peer.binding,
        TrustOrigin::QrPairing,
        PairPsk::new(OLD_PSK),
        generation,
        time(T0)?,
    )?;
    Ok(store)
}

/// What a restart would load: the store reopened from its durable blob.
pub(crate) fn reopen(store: &Store) -> AnyResult<Store> {
    let mut storage = MemoryStorage::new();
    storage.set_blob(store.storage().blob().map(<[u8]>::to_vec));
    Ok(ContactStore::open(sealer(9), storage)?)
}

/// `(generation, psk)` if the contact is usable now, else `None`.
pub(crate) fn usable(
    store: &Store,
    device: &Ed25519PublicKey,
) -> AnyResult<Option<(u64, [u8; 32])>> {
    Ok(match store.availability(device)? {
        Ok(contact) => Some((contact.generation(), *contact.psk().expose())),
        Err(_) => None,
    })
}

#[derive(Debug)]
pub(crate) enum Stage {
    AwaitClientHello(Option<Box<ResponderPlan>>),
    Handshake(Box<HandshakeDriver>),
    Establish(Box<Establishment>),
    Open(Box<SessionCore>),
    Failed(SessionError),
    Crashed,
}

/// One party of the harness.
pub(crate) struct Side<'l, A: PeerAuthority> {
    pub(crate) role: Role,
    pub(crate) local: LocalIdentity<'l, Keys>,
    pub(crate) authority: A,
    pub(crate) stage: Stage,
    inbound: Vec<u8>,
    /// Hold the responder's Ack-queued confirmation for an explicit step.
    pub(crate) defer_ack: bool,
}

impl<'l, A: PeerAuthority> Side<'l, A> {
    pub(crate) fn initiator(local: LocalIdentity<'l, Keys>, authority: A) -> Self {
        Self {
            role: Role::Initiator,
            local,
            authority,
            stage: Stage::Failed(SessionError::Closed),
            inbound: Vec::new(),
            defer_ack: false,
        }
    }

    pub(crate) fn responder(
        local: LocalIdentity<'l, Keys>,
        authority: A,
        plan: ResponderPlan,
    ) -> Self {
        Self {
            role: Role::Responder,
            local,
            authority,
            stage: Stage::AwaitClientHello(Some(Box::new(plan))),
            inbound: Vec::new(),
            defer_ack: false,
        }
    }

    pub(crate) fn is_open(&self) -> bool {
        matches!(self.stage, Stage::Open(_))
    }

    pub(crate) fn core(&mut self) -> Option<&mut SessionCore> {
        match &mut self.stage {
            Stage::Open(core) => Some(core),
            _ => None,
        }
    }

    pub(crate) fn error(&self) -> Option<SessionError> {
        match self.stage {
            Stage::Failed(error) => Some(error),
            _ => None,
        }
    }

    fn prelude_framing(&self) -> bool {
        matches!(self.stage, Stage::AwaitClientHello(_) | Stage::Handshake(_))
    }

    /// Feeds stream bytes and processes every complete record.
    fn feed(&mut self, bytes: &[u8], now: Duration) -> Vec<Vec<u8>> {
        if matches!(self.stage, Stage::Failed(_) | Stage::Crashed) {
            return Vec::new();
        }
        self.inbound.extend_from_slice(bytes);
        let mut out = Vec::new();
        while let Some(prefix) = self.inbound.first_chunk::<CIPHERTEXT_PREFIX_LEN>().copied() {
            let length = if self.prelude_framing() {
                prelude_record_len(prefix)
            } else {
                ciphertext_len(prefix)
            };
            let Ok(length) = length else {
                self.fail(SessionError::Protocol(
                    todoke_proto::session::ErrorCode::MALFORMED,
                ));
                break;
            };
            if self.inbound.len() < CIPHERTEXT_PREFIX_LEN + length {
                break;
            }
            let body: Vec<u8> = self
                .inbound
                .drain(..CIPHERTEXT_PREFIX_LEN + length)
                .skip(2)
                .collect();
            match self.step(&body, now) {
                Ok(records) => out.extend(records),
                Err(error) => {
                    self.fail(error);
                    break;
                }
            }
            if matches!(self.stage, Stage::Failed(_)) {
                break;
            }
        }
        out
    }

    /// Records a failure; after a journal the authority blocks the pairing.
    pub(crate) fn fail(&mut self, error: SessionError) {
        let error = match &mut self.stage {
            Stage::Establish(establishment) => establishment.failure(error, &mut self.authority),
            Stage::Open(core) => {
                core.close_for_tests();
                error
            }
            _ => error,
        };
        self.stage = Stage::Failed(error);
    }

    fn step(&mut self, body: &[u8], now: Duration) -> Result<Vec<Vec<u8>>, SessionError> {
        let stage = core::mem::replace(&mut self.stage, Stage::Failed(SessionError::Closed));
        let (stage, out) = self.advance(stage, body, now)?;
        self.stage = stage;
        Ok(out)
    }

    fn advance(
        &mut self,
        stage: Stage,
        body: &[u8],
        now: Duration,
    ) -> Result<(Stage, Vec<Vec<u8>>), SessionError> {
        match stage {
            Stage::AwaitClientHello(plan) => {
                let hello = handshake::read_client_hello(body)?;
                let plan = plan.ok_or(SessionError::Usage)?;
                let (driver, record) = HandshakeDriver::responder(
                    hello,
                    *plan,
                    self.local.noise_static(),
                    [0x5c; 16],
                    Entropy::Os,
                    now,
                )?;
                Ok((Stage::Handshake(Box::new(driver)), vec![record]))
            }
            Stage::Handshake(mut driver) => {
                let mut out = driver.receive(body, now)?;
                if !driver.is_done() {
                    return Ok((Stage::Handshake(driver), out));
                }
                let mut establishment =
                    Box::new(Establishment::new(driver.finish()?, now, Limits::SPEC));
                match establishment.start(&self.local, now) {
                    Ok(records) => out.extend(records),
                    Err(error) => return Err(establishment.failure(error, &mut self.authority)),
                }
                Ok((Stage::Establish(establishment), out))
            }
            Stage::Establish(mut establishment) => {
                let out = establishment.receive(body, &self.local, &mut self.authority, now)?;
                let stage = self.settle(establishment, now)?;
                Ok((stage, out))
            }
            Stage::Open(mut core) => {
                let mut out = Vec::new();
                let result = core.receive(body, now);
                out.extend(core::iter::from_fn(|| core.pop_outgoing()));
                result?;
                Ok((Stage::Open(core), out))
            }
            other => Ok((other, Vec::new())),
        }
    }

    /// Applies the Ack-queued step unless deferred, and opens the gate.
    fn settle(
        &mut self,
        mut establishment: Box<Establishment>,
        now: Duration,
    ) -> Result<Stage, SessionError> {
        if establishment.phase() == Phase::AckPending && !self.defer_ack {
            establishment.ack_queued(&mut self.authority)?;
        }
        if establishment.phase() == Phase::Open {
            let core = establishment.into_core(&self.local, Entropy::Os, now)?;
            return Ok(Stage::Open(Box::new(core)));
        }
        Ok(Stage::Establish(establishment))
    }

    /// The deferred responder step: "Ack queued".
    pub(crate) fn confirm_ack(&mut self, now: Duration) {
        let stage = core::mem::replace(&mut self.stage, Stage::Failed(SessionError::Closed));
        self.stage = match stage {
            Stage::Establish(establishment) if establishment.phase() == Phase::AckPending => {
                let defer = self.defer_ack;
                self.defer_ack = false;
                let result = self.settle(establishment, now);
                self.defer_ack = defer;
                match result {
                    Ok(stage) => stage,
                    Err(error) => Stage::Failed(error),
                }
            }
            other => other,
        };
    }

    /// The process dies: memory is lost, durable state remains.
    pub(crate) fn crash(&mut self) {
        self.stage = Stage::Crashed;
    }

    /// A deadline fires on whatever is still in progress.
    pub(crate) fn time_out(&mut self) {
        if !matches!(
            self.stage,
            Stage::Open(_) | Stage::Failed(_) | Stage::Crashed
        ) {
            self.fail(SessionError::Timeout);
        }
    }
}

/// Two sides and the wire between them.
pub(crate) struct Harness<'l, A: PeerAuthority, B: PeerAuthority> {
    pub(crate) initiator: Side<'l, A>,
    pub(crate) responder: Side<'l, B>,
    pub(crate) to_responder: VecDeque<Vec<u8>>,
    pub(crate) to_initiator: VecDeque<Vec<u8>>,
    pub(crate) now: Duration,
}

impl<'l, A: PeerAuthority, B: PeerAuthority> Harness<'l, A, B> {
    pub(crate) fn new(
        mut initiator: Side<'l, A>,
        responder: Side<'l, B>,
        plan: InitiatorPlan,
    ) -> AnyResult<Self> {
        let (driver, client_hello) = HandshakeDriver::initiator(
            plan,
            initiator.local.noise_static(),
            [0xc1; 16],
            Entropy::Os,
            START,
        )?;
        initiator.stage = Stage::Handshake(Box::new(driver));
        Ok(Self {
            initiator,
            responder,
            to_responder: VecDeque::from([client_hello]),
            to_initiator: VecDeque::new(),
            now: START,
        })
    }

    pub(crate) fn queue(&mut self, to_responder: bool) -> &mut VecDeque<Vec<u8>> {
        if to_responder {
            &mut self.to_responder
        } else {
            &mut self.to_initiator
        }
    }

    /// Delivers the next record in one direction (possibly altered bytes).
    pub(crate) fn deliver_bytes(&mut self, to_responder: bool, bytes: &[u8]) {
        let now = self.now;
        if to_responder {
            let out = self.responder.feed(bytes, now);
            self.to_initiator.extend(out);
        } else {
            let out = self.initiator.feed(bytes, now);
            self.to_responder.extend(out);
        }
    }

    pub(crate) fn deliver(&mut self, to_responder: bool) -> bool {
        match self.queue(to_responder).pop_front() {
            Some(record) => {
                self.deliver_bytes(to_responder, &record);
                true
            }
            None => false,
        }
    }

    /// Delivers everything honestly until both queues are empty.
    pub(crate) fn drain(&mut self) {
        loop {
            let a = self.deliver(true);
            let b = self.deliver(false);
            if !a && !b {
                break;
            }
        }
    }

    /// Ends the run: deadlines fire on anything unfinished.
    pub(crate) fn finish(&mut self) {
        self.initiator.time_out();
        self.responder.time_out();
    }
}
