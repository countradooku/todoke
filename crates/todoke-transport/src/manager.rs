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
//! # Clock
//!
//! The manager keeps one monotonic clock ([`TransportManager::timer`]) for
//! every session it starts or accepts and for the §13 attempt budget in
//! its [`PairingOffers`]; pairing offers created for this manager must use
//! the same clock (`PairingOffers` compares times across calls).
//!
//! # Simultaneous attempts
//!
//! A slot is held from the claim until the [`Established`] session is
//! dropped. When both devices connect to each other at once, the device
//! with the lexicographically smaller full device key keeps its outgoing
//! attempt and the larger keeps its incoming one (§4).
//!
//! An incoming `ClientHello` is not authenticated: its locator can be
//! replayed by anyone who saw it. So an incoming attempt never displaces
//! anything. On the smaller device it is refused while an outgoing attempt
//! to the same peer exists. On the larger device it **waits** (at most
//! [`SIMULTANEOUS_WAIT`]) for the outgoing attempt's outcome: in a real
//! simultaneous attempt the smaller device refuses that outgoing attempt at
//! its Hello, before anything is journaled, and the incoming attempt then
//! takes the slot; if the outgoing attempt succeeds instead (the incoming
//! one was a replay, or the peer did not try at once), the incoming one is
//! refused. Only one incoming attempt waits per peer.
//!
//! # Migration
//!
//! A session never moves to another link (§5). [`TransportManager::migrate`]
//! closes the current session and reserves the slot for a fresh one on the
//! new link, after which an unfinished transfer resumes only with a **new
//! signed Accept** from the receiver (§7.5), which the core creates only
//! from local user intent (§7.2). [`MigrationPolicy`] decides whether a new
//! link is worth that; the slot rule forbids keeping both sessions, so the
//! old session is closed first (break before make).

use core::fmt;
use core::time::Duration;
use std::collections::BTreeMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard};

use todoke_crypto::discovery::DiscoveryTable;
use todoke_crypto::identity::{BlobStorage, ContactStore, Ed25519PublicKey, KeyStore, Sealer};
use todoke_crypto::pairing::PairingOffers;
use todoke_crypto::session::{
    Accepted, IncomingCodeRequest, IncomingSession, LocalIdentity, Session, SessionError,
    SessionMode, UnauditedSuite0001,
};
use todoke_proto::time::UnixTime;
use tokio::sync::Notify;

use crate::link::{Link, LinkInfo};
use crate::race::{Candidate, Connector, RaceConfig, RaceError, race};
use crate::timer::TokioTimer;

/// How long an incoming link may take to send its first prelude record. A
/// local quota below §13's 30-second handshake bound (§13 allows smaller
/// ones): an idle connection holds one of only four unauthenticated slots.
pub const FIRST_RECORD_TIMEOUT: Duration = Duration::from_secs(5);
/// Unauthenticated incoming attempts allowed at once from one source
/// address, so that one host cannot take all four (§13).
pub const MAX_ATTEMPTS_PER_SOURCE: usize = 2;
/// How long an incoming attempt on the larger-key device waits for its own
/// outgoing attempt to the same peer to succeed or fail (see the module
/// notes).
pub const SIMULTANEOUS_WAIT: Duration = Duration::from_secs(10);

/// Why a contact session was not established.
#[derive(Debug)]
pub enum ConnectError {
    /// Another attempt or session with this device exists (§4).
    Busy,
    /// The device is not an available contact in the discovery table (not
    /// paired, revoked, blocked, or ratchet-uncertain).
    UnknownPeer,
    /// The discovery table is for another epoch or an earlier pair
    /// generation than the store's: rebuild it (§9).
    StaleTable,
    /// Too many unauthenticated attempts from this source address.
    SourceBusy,
    /// No link could be opened.
    Race(RaceError),
    /// The session failed.
    Session(SessionError),
}

impl fmt::Display for ConnectError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Busy => f.write_str("another session with this device is in progress"),
            Self::UnknownPeer => f.write_str("not an available contact"),
            Self::StaleTable => f.write_str("the discovery table is out of date"),
            Self::SourceBusy => f.write_str("too many attempts from one address"),
            Self::Race(error) => write!(f, "{error}"),
            Self::Session(error) => write!(f, "session failed: {error}"),
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

#[derive(Clone, Copy)]
struct Slot {
    id: u64,
    direction: Direction,
    active: bool,
    /// An incoming attempt is waiting for this (outgoing) attempt's outcome.
    waiter: bool,
}

#[derive(Default)]
struct Slots {
    by_peer: BTreeMap<Ed25519PublicKey, Slot>,
    /// Unauthenticated incoming attempts per source address.
    sources: BTreeMap<IpAddr, usize>,
    next_id: u64,
}

/// Device keys and addresses are left out (§14.2).
impl fmt::Debug for Slots {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Slots")
            .field("peers", &self.by_peer.len())
            .field("sources", &self.sources.len())
            .finish_non_exhaustive()
    }
}

#[derive(Default)]
struct State {
    slots: Mutex<Slots>,
    /// Woken whenever a slot is activated or freed.
    changed: Notify,
}

type Shared = Arc<State>;

fn lock(state: &State) -> MutexGuard<'_, Slots> {
    // The table holds no invariant a panicking holder could break halfway:
    // recover it rather than refuse every session from then on.
    state
        .slots
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// What a claim found.
enum Claim {
    Taken(SlotGuard),
    /// Wait for the outgoing attempt (with this ID) to end.
    Wait(u64),
}

/// A device pair's slot, from claim to the end of its session. Dropping it
/// frees the slot.
pub struct SlotGuard {
    state: Shared,
    peer: Ed25519PublicKey,
    id: u64,
}

impl fmt::Debug for SlotGuard {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SlotGuard")
    }
}

impl SlotGuard {
    fn activate(&self) -> Result<(), ConnectError> {
        let activated = match lock(&self.state).by_peer.get_mut(&self.peer) {
            Some(slot) if slot.id == self.id => {
                slot.active = true;
                true
            }
            _ => false,
        };
        self.state.changed.notify_waiters();
        if activated {
            Ok(())
        } else {
            Err(ConnectError::Busy)
        }
    }
}

impl Drop for SlotGuard {
    fn drop(&mut self) {
        {
            let mut slots = lock(&self.state);
            if slots
                .by_peer
                .get(&self.peer)
                .is_some_and(|slot| slot.id == self.id)
            {
                slots.by_peer.remove(&self.peer);
            }
        }
        self.state.changed.notify_waiters();
    }
}

/// One unauthenticated incoming attempt from a source address, counted
/// against [`MAX_ATTEMPTS_PER_SOURCE`] until dropped.
struct SourceGuard {
    state: Shared,
    source: Option<IpAddr>,
}

impl Drop for SourceGuard {
    fn drop(&mut self) {
        if let Some(source) = self.source {
            let mut slots = lock(&self.state);
            if let Some(count) = slots.sources.get_mut(&source) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    slots.sources.remove(&source);
                }
            }
        }
    }
}

/// An authenticated contact session on a link, holding the device pair's
/// slot for as long as it lives. Peer authentication only: not consent to
/// anything (§7).
pub struct Established<L: Link> {
    session: Session<L, TokioTimer>,
    peer: Ed25519PublicKey,
    link: LinkInfo,
    /// Held for its `Drop`: the slot is freed when the session ends.
    #[expect(dead_code, reason = "held only for its Drop")]
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
    timer: TokioTimer,
    race: RaceConfig,
    state: Shared,
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
    /// unauthenticated-attempt budget every incoming link counts against;
    /// offers in it must be created with [`Self::timer`]'s clock.
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
            timer: TokioTimer::new(),
            race: RaceConfig::default(),
            state: Shared::default(),
        }
    }

    /// With other race timing.
    #[must_use]
    pub const fn with_race(mut self, race: RaceConfig) -> Self {
        self.race = race;
        self
    }

    /// The manager's monotonic clock, shared by every session and attempt
    /// budget it uses; pass its `now()` to [`PairingOffers`] calls.
    #[must_use]
    pub const fn timer(&self) -> TokioTimer {
        self.timer
    }

    /// Whether a session or attempt with `peer` exists.
    #[must_use]
    pub fn is_busy(&self, peer: &Ed25519PublicKey) -> bool {
        lock(&self.state).by_peer.contains_key(peer)
    }

    fn claim(&self, peer: Ed25519PublicKey, direction: Direction) -> Result<Claim, ConnectError> {
        let mut slots = lock(&self.state);
        if let Some(existing) = slots.by_peer.get_mut(&peer) {
            // The larger device keeps its incoming attempt (§4), but only once
            // its own outgoing attempt has failed: an unauthenticated Hello
            // never displaces anything.
            let may_wait = direction == Direction::Incoming
                && existing.direction == Direction::Outgoing
                && !existing.active
                && !existing.waiter
                && self.local_device > peer;
            if !may_wait {
                return Err(ConnectError::Busy);
            }
            existing.waiter = true;
            return Ok(Claim::Wait(existing.id));
        }
        let id = slots.next_id;
        slots.next_id = id.wrapping_add(1);
        slots.by_peer.insert(
            peer,
            Slot {
                id,
                direction,
                active: false,
                waiter: false,
            },
        );
        Ok(Claim::Taken(SlotGuard {
            state: Arc::clone(&self.state),
            peer,
            id,
        }))
    }

    /// Ends a wait on outgoing attempt `id`, if it still holds the slot.
    fn stop_waiting(&self, peer: &Ed25519PublicKey, id: u64) {
        if let Some(slot) = lock(&self.state).by_peer.get_mut(peer)
            && slot.id == id
        {
            slot.waiter = false;
        }
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
        match self.claim(peer, Direction::Outgoing)? {
            Claim::Taken(slot) => Ok(OutgoingClaim {
                manager: self,
                peer,
                slot,
            }),
            Claim::Wait(_) => Err(ConnectError::Busy),
        }
    }

    /// Closes `current` and reserves the slot for a fresh session with the
    /// same peer (break before make, §5). Connect and initiate the returned
    /// claim on the new link; an unfinished transfer then needs a new Accept
    /// from the receiver (§7.5).
    ///
    /// # Errors
    ///
    /// [`ConnectError::Busy`] if another attempt with the peer started in
    /// between.
    pub fn migrate<L: Link>(
        &self,
        current: Established<L>,
    ) -> Result<OutgoingClaim<'_>, ConnectError> {
        let peer = current.peer;
        drop(current);
        self.claim_outgoing(peer)
    }

    /// Reads an incoming link's first prelude record within
    /// [`FIRST_RECORD_TIMEOUT`], counting it against the §13
    /// unauthenticated-attempt budget (at most 4 at once and 20 starts a
    /// minute) and [`MAX_ATTEMPTS_PER_SOURCE`]; refused links are closed.
    ///
    /// # Errors
    ///
    /// [`ConnectError::SourceBusy`];
    /// [`ConnectError::Session`] with [`SessionError::Timeout`], a malformed
    /// record, or [`SessionError::Pairing`] when the budget is spent.
    pub async fn accept<L: Link>(&self, link: L) -> Result<Incoming<'_, L>, ConnectError> {
        let info = *link.info();
        let source = self.source(info.remote().map(|address| address.ip()))?;
        let accepted = tokio::time::timeout(
            FIRST_RECORD_TIMEOUT,
            IncomingSession::accept_any(link, self.timer, self.gate, &self.offers),
        )
        .await
        .map_err(|_| ConnectError::Session(SessionError::Timeout))??;
        Ok(match accepted {
            Accepted::CodeOfferRequest(request) => Incoming::CodeOfferRequest(request),
            Accepted::Hello(incoming) if incoming.client_hello().mode() == SessionMode::Contact => {
                Incoming::Contact(IncomingContact {
                    manager: self,
                    incoming,
                    link: info,
                    source,
                })
            }
            Accepted::Hello(incoming) => Incoming::Pairing(incoming),
        })
    }

    fn source(&self, source: Option<IpAddr>) -> Result<SourceGuard, ConnectError> {
        if let Some(source) = source {
            let mut slots = lock(&self.state);
            let count = slots.sources.entry(source).or_default();
            if *count >= MAX_ATTEMPTS_PER_SOURCE {
                return Err(ConnectError::SourceBusy);
            }
            *count += 1;
        }
        Ok(SourceGuard {
            state: Arc::clone(&self.state),
            source,
        })
    }
}

/// Refuses a table built for another epoch than `now`'s, or at another pair
/// generation for `peer` than the store's (§9: discovery state from earlier
/// generations must not stay in use). The Hello names no generation (§4.1):
/// the table's, matched here, is what ties the claimed locator to the PSK
/// the handshake uses. A re-pairing restarts at generation 1, so a table
/// kept across one could pass this check with the new PSK; the handshake
/// then fails authentication, and the runtime rebuilds its table on every
/// pairing anyway.
fn check_table<S: Sealer, B: BlobStorage>(
    table: &DiscoveryTable,
    store: &ContactStore<S, B>,
    peer: &Ed25519PublicKey,
    now: UnixTime,
) -> Result<(), ConnectError> {
    if table.is_stale(now) {
        return Err(ConnectError::StaleTable);
    }
    let stored = store
        .contact(peer)
        .map(todoke_crypto::identity::Contact::generation);
    match (table.generation(peer), stored) {
        (Some(table), Some(stored)) if table == stored => Ok(()),
        (None, _) | (_, None) => Err(ConnectError::UnknownPeer),
        _ => Err(ConnectError::StaleTable),
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
    /// and the ratchet. `table` must be current: built for `now`'s epoch and
    /// the store's pair generation (rebuild it at each epoch and after each
    /// committed session).
    ///
    /// # Errors
    ///
    /// [`ConnectError::UnknownPeer`] if the peer is not in `table` or the
    /// store; [`ConnectError::StaleTable`]; [`ConnectError::Session`].
    pub async fn initiate<K: KeyStore, S: Sealer, B: BlobStorage>(
        self,
        table: &DiscoveryTable,
        store: &mut ContactStore<S, B>,
        local: &LocalIdentity<'_, K>,
        now: UnixTime,
    ) -> Result<Established<L>, ConnectError> {
        let Self { claim, link } = self;
        let peer = claim.peer;
        check_table(table, store, &peer, now)?;
        let locator = table.locator(&peer).ok_or(ConnectError::UnknownPeer)?;
        let info = *link.info();
        let mut authority = store.session_authority(&peer)?;
        let plan = authority.initiator_plan(locator)?;
        let session = Session::initiate(
            link,
            claim.manager.timer,
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
    source: SourceGuard,
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
    /// epoch or a neighbour, §4.1) and reserves that device pair's slot,
    /// waiting for this device's own outgoing attempt to the peer if the
    /// §4 key order says so (see the module notes). The locator is an
    /// unauthenticated hint; the handshake decides.
    ///
    /// # Errors
    ///
    /// [`ConnectError::StaleTable`] for a table not built for `now`'s
    /// epoch; [`ConnectError::UnknownPeer`] for a locator that names no
    /// available contact, or more than one; [`ConnectError::Busy`] (§4).
    pub async fn claim(
        self,
        table: &DiscoveryTable,
        now: UnixTime,
    ) -> Result<ClaimedIncoming<L>, ConnectError> {
        if table.is_stale(now) {
            return Err(ConnectError::StaleTable);
        }
        let [peer] = table.resolve_locator(self.incoming.client_hello().locator()) else {
            return Err(ConnectError::UnknownPeer);
        };
        let peer = *peer;
        let manager = self.manager;
        let deadline = tokio::time::Instant::now() + SIMULTANEOUS_WAIT;
        let mut waited_on = None;
        let slot = loop {
            let changed = manager.state.changed.notified();
            let mut changed = core::pin::pin!(changed);
            changed.as_mut().enable();
            match manager.claim(peer, Direction::Incoming) {
                Ok(Claim::Taken(slot)) => break slot,
                Ok(Claim::Wait(id)) => {
                    waited_on = Some(id);
                    let woken = tokio::time::timeout_at(deadline, changed).await;
                    manager.stop_waiting(&peer, id);
                    if woken.is_err() {
                        return Err(ConnectError::Busy);
                    }
                }
                Err(error) => {
                    if let Some(id) = waited_on {
                        manager.stop_waiting(&peer, id);
                    }
                    return Err(error);
                }
            }
        };
        Ok(ClaimedIncoming {
            incoming: self.incoming,
            peer,
            link: self.link,
            slot,
            source: self.source,
        })
    }
}

/// An incoming contact attempt holding its slot.
pub struct ClaimedIncoming<L: Link> {
    incoming: IncomingSession<L, TokioTimer>,
    peer: Ed25519PublicKey,
    link: LinkInfo,
    slot: SlotGuard,
    source: SourceGuard,
}

impl<L: Link> fmt::Debug for ClaimedIncoming<L> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ClaimedIncoming")
            .field("link", &self.link)
            .finish_non_exhaustive()
    }
}

impl<L: Link> ClaimedIncoming<L> {
    /// The contact the Hello's locator named: unauthenticated until the
    /// handshake, which must prove it.
    #[must_use]
    pub const fn peer(&self) -> &Ed25519PublicKey {
        &self.peer
    }

    /// Runs the contact handshake as responder. `table` must be the one the
    /// claim used, still current for the store's pair generation.
    ///
    /// # Errors
    ///
    /// [`ConnectError::StaleTable`] or [`ConnectError::Session`].
    pub async fn respond<K: KeyStore, S: Sealer, B: BlobStorage>(
        self,
        table: &DiscoveryTable,
        store: &mut ContactStore<S, B>,
        local: &LocalIdentity<'_, K>,
        now: UnixTime,
    ) -> Result<Established<L>, ConnectError> {
        let Self {
            incoming,
            peer,
            link,
            slot,
            source,
        } = self;
        check_table(table, store, &peer, now)?;
        let mut authority = store.session_authority(&peer)?;
        let plan = authority.responder_plan(incoming.client_hello())?;
        let session = incoming.respond(local, now, plan, &mut authority).await?;
        // Authenticated now: no longer counted against its source.
        drop(source);
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
