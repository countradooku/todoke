//! Contact sessions over links: one attempt and one session per device
//! pair (PROTOCOL §4), connection racing, and migration to a new link.
//!
//! # Steps
//!
//! Outgoing: [`TransportManager::claim_outgoing`] reserves the peer's slot,
//! [`OutgoingClaim::connect`] races the candidates ([`crate::race`]), and
//! [`Connected::initiate`] runs the one handshake (`KKpsk2`, identity
//! confirmation, PSK ratchet) on the winner.
//!
//! Incoming: [`TransportManager::accept`] reads the `ClientHello` within
//! the §13 unauthenticated-attempt budget, [`IncomingContact::claim`]
//! resolves its locator against the current [`DiscoveryTable`] and reserves
//! the slot, and [`ClaimedIncoming::respond`] runs the handshake.
//!
//! The contact store is needed only for the handshake steps, so a caller
//! that guards it with a lock holds that lock only while a handshake runs,
//! and conflicting attempts are settled before either waits for it.
//!
//! # Simultaneous attempts
//!
//! A slot is held from the claim until the [`Established`] session is
//! dropped. When both devices connect to each other at once, the device
//! with the lexicographically smaller full device key keeps its outgoing
//! attempt and the larger keeps its incoming one (§4): the smaller refuses
//! the incoming attempt, and the larger accepts it, so both keep the same
//! connection. The larger device's own outgoing attempt is then refused by
//! the smaller at its `ClientHello`, before either side journals anything,
//! so the pairing stays usable. An outgoing attempt superseded this way
//! that completes anyway (a peer that does not follow the rule) is closed.
//!
//! # Migration
//!
//! A session never moves to another link (§5). Migrating means closing the
//! current session and starting a fresh one on the new link, after which
//! an unfinished transfer resumes only with a **new signed Accept** from
//! the receiver (§7.5), which the core creates only from local user intent
//! (§7.2). [`MigrationPolicy`] decides whether a new link is worth that;
//! the slot rule forbids keeping both sessions, so the old session is
//! closed first (break before make).

use core::fmt;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard};

use todoke_crypto::discovery::DiscoveryTable;
use todoke_crypto::identity::{BlobStorage, ContactStore, Ed25519PublicKey, KeyStore, Sealer};
use todoke_crypto::pairing::PairingOffers;
use todoke_crypto::session::{
    Accepted, IncomingCodeRequest, IncomingSession, LocalIdentity, Session, SessionError,
    SessionMode, UnauditedSuite0001,
};
use todoke_proto::time::UnixTime;

use crate::link::{Link, LinkInfo};
use crate::race::{Candidate, Connector, RaceConfig, RaceError, race};
use crate::timer::TokioTimer;

/// Why a contact session was not established.
#[derive(Debug)]
pub enum ConnectError {
    /// Another attempt or session with this device exists (§4).
    Busy,
    /// The device is not an available contact in the discovery table (not
    /// paired, revoked, blocked, or ratchet-uncertain).
    UnknownPeer,
    /// No link could be opened.
    Race(RaceError),
    /// The session failed.
    Session(SessionError),
    /// The attempt lost to a simultaneous one and was closed (§4).
    Superseded,
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Busy => f.write_str("another session with this device is in progress"),
            Self::UnknownPeer => f.write_str("not an available contact"),
            Self::Race(error) => write!(f, "{error}"),
            Self::Session(error) => write!(f, "session failed: {error}"),
            Self::Superseded => f.write_str("a simultaneous session with this device won"),
        }
    }
}

impl std::error::Error for ConnectError {}

impl From<SessionError> for ConnectError {
    fn from(error: SessionError) -> Self {
        Self::Session(error)
    }
}

impl From<RaceError> for ConnectError {
    fn from(error: RaceError) -> Self {
        Self::Race(error)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Direction {
    Outgoing,
    Incoming,
}

#[derive(Clone, Copy, Debug)]
struct Slot {
    id: u64,
    direction: Direction,
    active: bool,
}

#[derive(Debug, Default)]
struct Slots {
    by_peer: BTreeMap<Ed25519PublicKey, Slot>,
    /// Outgoing attempts that lost to an incoming one (§4); closed if they
    /// complete.
    superseded: Vec<u64>,
    next_id: u64,
}

type Shared = Arc<Mutex<Slots>>;

fn lock(slots: &Shared) -> MutexGuard<'_, Slots> {
    // The table holds no invariant a panicking holder could break halfway:
    // recover it rather than refuse every session from then on.
    slots
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// A device pair's slot, from claim to the end of its session. Dropping it
/// frees the slot.
#[derive(Debug)]
pub struct SlotGuard {
    slots: Shared,
    peer: Ed25519PublicKey,
    id: u64,
}

impl SlotGuard {
    fn activate(&self) -> Result<(), ConnectError> {
        let mut slots = lock(&self.slots);
        if slots.superseded.contains(&self.id) {
            return Err(ConnectError::Superseded);
        }
        match slots.by_peer.get_mut(&self.peer) {
            Some(slot) if slot.id == self.id => {
                slot.active = true;
                Ok(())
            }
            _ => Err(ConnectError::Superseded),
        }
    }
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        let mut slots = lock(&self.slots);
        slots.superseded.retain(|id| *id != self.id);
        if slots
            .by_peer
            .get(&self.peer)
            .is_some_and(|slot| slot.id == self.id)
        {
            slots.by_peer.remove(&self.peer);
        }
    }
}

/// An authenticated contact session on a link, holding the device pair's
/// slot. Peer authentication only: not consent to anything (§7).
pub struct Established<L: Link> {
    session: Session<L, TokioTimer>,
    peer: Ed25519PublicKey,
    link: LinkInfo,
    slot: SlotGuard,
}

impl<L: Link> Established<L> {
    /// The session.
    pub fn session(&mut self) -> &mut Session<L, TokioTimer> {
        &mut self.session
    }

    /// The authenticated peer device.
    #[must_use]
    pub const fn peer(&self) -> &Ed25519PublicKey {
        &self.peer
    }

    /// The link the session runs over.
    #[must_use]
    pub const fn link(&self) -> &LinkInfo {
        &self.link
    }

    /// The session and the slot; the slot must live as long as the session
    /// (dropping it lets another session with this device start).
    #[must_use]
    pub fn into_parts(self) -> (Session<L, TokioTimer>, SlotGuard) {
        (self.session, self.slot)
    }
}

impl<L: Link> fmt::Debug for Established<L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Established")
            .field("link", &self.link)
            .finish_non_exhaustive()
    }
}

/// Starts and accepts contact sessions over links.
#[derive(Clone)]
pub struct TransportManager {
    gate: UnauditedSuite0001,
    local_device: Ed25519PublicKey,
    offers: PairingOffers,
    race: RaceConfig,
    slots: Shared,
}

impl fmt::Debug for TransportManager {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TransportManager")
            .field("race", &self.race)
            .finish_non_exhaustive()
    }
}

impl TransportManager {
    /// A manager for the local device `local_device`. `offers` is the
    /// device's one pairing-offer table, which also holds the §13
    /// unauthenticated-attempt budget every incoming link counts against.
    #[must_use]
    pub fn new(
        gate: UnauditedSuite0001,
        local_device: Ed25519PublicKey,
        offers: PairingOffers,
    ) -> Self {
        Self {
            gate,
            local_device,
            offers,
            race: RaceConfig::default(),
            slots: Shared::default(),
        }
    }

    /// With other race timing.
    #[must_use]
    pub const fn with_race(mut self, race: RaceConfig) -> Self {
        self.race = race;
        self
    }

    /// Whether a session or attempt with `peer` exists.
    #[must_use]
    pub fn is_busy(&self, peer: &Ed25519PublicKey) -> bool {
        lock(&self.slots).by_peer.contains_key(peer)
    }

    fn claim(
        &self,
        peer: Ed25519PublicKey,
        direction: Direction,
    ) -> Result<SlotGuard, ConnectError> {
        let mut slots = lock(&self.slots);
        let id = slots.next_id;
        if let Some(existing) = slots.by_peer.get(&peer).copied() {
            // The only exception: an incoming attempt while our own outgoing
            // one is still unestablished, and we hold the larger key (§4).
            let keep_incoming = direction == Direction::Incoming
                && existing.direction == Direction::Outgoing
                && !existing.active
                && self.local_device > peer;
            if !keep_incoming {
                return Err(ConnectError::Busy);
            }
            slots.superseded.push(existing.id);
        }
        slots.next_id = id.wrapping_add(1);
        slots.by_peer.insert(
            peer,
            Slot {
                id,
                direction,
                active: false,
            },
        );
        Ok(SlotGuard {
            slots: Arc::clone(&self.slots),
            peer,
            id,
        })
    }

    /// Reserves the slot for a session with `peer`.
    ///
    /// # Errors
    ///
    /// [`ConnectError::Busy`] if an attempt or session with `peer` exists.
    pub fn claim_outgoing(
        &self,
        peer: Ed25519PublicKey,
    ) -> Result<OutgoingClaim<'_>, ConnectError> {
        let slot = self.claim(peer, Direction::Outgoing)?;
        Ok(OutgoingClaim {
            manager: self,
            peer,
            slot,
        })
    }

    /// Reads an incoming link's first prelude record, within the §13
    /// unauthenticated-attempt budget (at most 4 at once and 20 starts a
    /// minute; refused links are closed).
    ///
    /// # Errors
    ///
    /// [`SessionError`]: a timeout, a malformed record, or
    /// [`SessionError::Pairing`] when the budget is spent.
    pub async fn accept<L: Link>(&self, link: L) -> Result<Incoming<'_, L>, SessionError> {
        let info = *link.info();
        let accepted =
            IncomingSession::accept_any(link, TokioTimer::new(), self.gate, &self.offers).await?;
        Ok(match accepted {
            Accepted::CodeOfferRequest(request) => Incoming::CodeOfferRequest(request),
            Accepted::Hello(incoming) if incoming.client_hello().mode() == SessionMode::Contact => {
                Incoming::Contact(IncomingContact {
                    manager: self,
                    incoming,
                    link: info,
                })
            }
            Accepted::Hello(incoming) => Incoming::Pairing(incoming),
        })
    }
}

/// An outgoing attempt holding its slot.
#[derive(Debug)]
pub struct OutgoingClaim<'m> {
    manager: &'m TransportManager,
    peer: Ed25519PublicKey,
    slot: SlotGuard,
}

impl<'m> OutgoingClaim<'m> {
    /// Races `candidates` and keeps the first link that connects.
    ///
    /// # Errors
    ///
    /// [`ConnectError::Race`].
    pub async fn connect<C: Connector + Sync>(
        self,
        connector: &C,
        candidates: &[Candidate],
    ) -> Result<Connected<'m, C::Link>, ConnectError> {
        let link = race(connector, candidates, &self.manager.race).await?;
        Ok(Connected { claim: self, link })
    }

    /// Uses a link the caller opened.
    #[must_use]
    pub fn with_link<L: Link>(self, link: L) -> Connected<'m, L> {
        Connected { claim: self, link }
    }
}

/// An outgoing attempt with its link, before the handshake.
pub struct Connected<'m, L: Link> {
    claim: OutgoingClaim<'m>,
    link: L,
}

impl<L: Link> fmt::Debug for Connected<'_, L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connected")
            .field("link", self.link.info())
            .finish_non_exhaustive()
    }
}

impl<L: Link> Connected<'_, L> {
    /// What is known about the link.
    #[must_use]
    pub fn link(&self) -> &LinkInfo {
        self.link.info()
    }

    /// Runs the contact handshake as initiator: the Hello locator for the
    /// table's epoch, `KKpsk2` with the stored PSK, identity confirmation,
    /// and the ratchet. `table` must be current (rebuilt at each epoch and
    /// after each committed session).
    ///
    /// # Errors
    ///
    /// [`ConnectError::UnknownPeer`] if the peer is not in `table`;
    /// [`ConnectError::Session`]; [`ConnectError::Superseded`] if a
    /// simultaneous incoming attempt won meanwhile (the session is closed).
    pub async fn initiate<K: KeyStore, S: Sealer, B: BlobStorage>(
        self,
        table: &DiscoveryTable,
        store: &mut ContactStore<S, B>,
        local: &LocalIdentity<'_, K>,
        now: UnixTime,
    ) -> Result<Established<L>, ConnectError> {
        let Self { claim, link } = self;
        let peer = claim.peer;
        let locator = table.locator(&peer).ok_or(ConnectError::UnknownPeer)?;
        let info = *link.info();
        let mut authority = store.session_authority(&peer)?;
        let plan = authority.initiator_plan(locator)?;
        let session = Session::initiate(
            link,
            TokioTimer::new(),
            claim.manager.gate,
            local,
            now,
            plan,
            &mut authority,
        )
        .await?;
        claim.slot.activate()?;
        Ok(Established {
            session,
            peer,
            link: info,
            slot: claim.slot,
        })
    }
}

/// An incoming link after its first prelude record.
pub enum Incoming<'m, L: Link> {
    /// A contact `ClientHello`.
    Contact(IncomingContact<'m, L>),
    /// A QR or human-code pairing `ClientHello`, for the pairing flow (§3).
    Pairing(IncomingSession<L, TokioTimer>),
    /// A human-code `CodeOfferRequest`, for the pairing flow (§3.2).
    CodeOfferRequest(IncomingCodeRequest<L, TokioTimer>),
}

impl<L: Link> fmt::Debug for Incoming<'_, L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Contact(_) => "Incoming::Contact",
            Self::Pairing(_) => "Incoming::Pairing",
            Self::CodeOfferRequest(_) => "Incoming::CodeOfferRequest",
        })
    }
}

/// An incoming contact attempt whose peer is not resolved yet.
pub struct IncomingContact<'m, L: Link> {
    manager: &'m TransportManager,
    incoming: IncomingSession<L, TokioTimer>,
    link: LinkInfo,
}

impl<L: Link> fmt::Debug for IncomingContact<'_, L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("IncomingContact")
            .field("link", &self.link)
            .finish_non_exhaustive()
    }
}

impl<L: Link> IncomingContact<'_, L> {
    /// Resolves the Hello's locator to one contact in `table` (the local
    /// epoch or a neighbour, §4.1) and reserves that device pair's slot.
    /// The locator is an unauthenticated hint; the handshake decides.
    ///
    /// # Errors
    ///
    /// [`ConnectError::UnknownPeer`] for a locator that names no available
    /// contact, or more than one; [`ConnectError::Busy`] (§4).
    pub fn claim(self, table: &DiscoveryTable) -> Result<ClaimedIncoming<L>, ConnectError> {
        let [peer] = table.resolve_locator(self.incoming.client_hello().locator()) else {
            return Err(ConnectError::UnknownPeer);
        };
        let peer = *peer;
        let slot = self.manager.claim(peer, Direction::Incoming)?;
        Ok(ClaimedIncoming {
            incoming: self.incoming,
            peer,
            link: self.link,
            slot,
        })
    }
}

/// An incoming contact attempt holding its slot.
pub struct ClaimedIncoming<L: Link> {
    incoming: IncomingSession<L, TokioTimer>,
    peer: Ed25519PublicKey,
    link: LinkInfo,
    slot: SlotGuard,
}

impl<L: Link> fmt::Debug for ClaimedIncoming<L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClaimedIncoming")
            .field("link", &self.link)
            .finish_non_exhaustive()
    }
}

impl<L: Link> ClaimedIncoming<L> {
    /// Runs the contact handshake as responder.
    ///
    /// # Errors
    ///
    /// [`ConnectError::Session`], including
    /// [`SessionError::GenerationMismatch`] (reported locally only, §4.4).
    pub async fn respond<K: KeyStore, S: Sealer, B: BlobStorage>(
        self,
        store: &mut ContactStore<S, B>,
        local: &LocalIdentity<'_, K>,
        now: UnixTime,
    ) -> Result<Established<L>, ConnectError> {
        let Self {
            incoming,
            peer,
            link,
            slot,
        } = self;
        let mut authority = store.session_authority(&peer)?;
        let plan = authority.responder_plan(incoming.client_hello())?;
        let session = incoming.respond(local, now, plan, &mut authority).await?;
        slot.activate()?;
        Ok(Established {
            session,
            peer,
            link,
            slot,
        })
    }
}

/// When a newly found link is worth a fresh session (and, for an unfinished
/// transfer, asking the receiver to accept again, §7.5).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MigrationPolicy {
    /// How many times lower the new link's latency must be, for links of
    /// the same rank.
    pub latency_ratio: u32,
}

impl Default for MigrationPolicy {
    fn default() -> Self {
        Self { latency_ratio: 4 }
    }
}

impl MigrationPolicy {
    /// Whether to move from `current` to `candidate`: a higher-ranked kind,
    /// or the same rank with a measured latency at least
    /// [`Self::latency_ratio`] times lower. Unknown metrics never justify
    /// a migration.
    #[must_use]
    pub fn should_migrate(&self, current: &LinkInfo, candidate: &LinkInfo) -> bool {
        let (current_rank, candidate_rank) = (current.kind().rank(), candidate.kind().rank());
        if candidate_rank != current_rank {
            return candidate_rank > current_rank;
        }
        match (current.latency(), candidate.latency()) {
            (Some(current), Some(candidate)) => {
                candidate.saturating_mul(self.latency_ratio.max(2)) <= current
            }
            _ => false,
        }
    }
}

#[cfg(test)]
mod tests;
