//! The core's state and its loop (see the parent module).

use core::cell::{Cell, RefCell};
use core::time::Duration;
use std::collections::{BTreeMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::rc::Rc;

use todoke_crypto::discovery::DiscoveryTable;
use todoke_crypto::identity::{Ed25519PublicKey, SoftwareSealer, StorageKey};
use todoke_crypto::pairing::{HumanCode, PairingOffers, QrPayload, UnauditedCodePairing};
use todoke_crypto::session::{Session, SessionMode, Timer as _, UnauditedSuite0001};
use todoke_discovery::{Advertiser, Directory, OsRandom};

use crate::discovery::Mdns;
use todoke_fs::dest::DirDestination;
use todoke_fs::{FsSink, FsSource, Preparer, SharedSink, SinkConfig};
use todoke_proto::discovery::DISCOVERY_TOKEN_LEN;
use todoke_proto::time::UnixTime;
use todoke_proto::transfer::TransferId;
use todoke_transfer::OutgoingOffer;
use todoke_transport::{
    Candidate, ConnectError, Connected, Incoming, LanListener, LanPolicy, Link, LinkKind,
    TcpConnector, TokioTimer, TransportManager,
};
use tokio::sync::{broadcast, mpsc, oneshot};
use zeroize::Zeroizing;

use super::relay::Role;
use super::session::{self, SessionCommand};
use super::{Command, Envelope, StartError};
use crate::api::{
    ContactInfo, ErrorCode, Event, HISTORY_NAMES, HistoryEntry, MIN_PREFIX, OfferInfo, ReceiptInfo,
    Request, Response, Route, StatusInfo, StrangerInfo, TransferInfo, TransferState, Way, hex,
};
use crate::config::{CoreConfig, MAX_HISTORY_DAYS};
use crate::discovery::Backend;
use crate::history::History;
use crate::profile::{Contacts, Identity, Profile};
use crate::send;
use crate::storage_key::StorageKeySource;

pub(super) const GATE: UnauditedSuite0001 = UnauditedSuite0001::acknowledge_not_production_ready();
pub(super) const CODE_GATE: UnauditedCodePairing =
    UnauditedCodePairing::acknowledge_not_production_ready();

/// The quarantine sink every session shares.
pub(super) type Sink = SharedSink<DirDestination, SoftwareSealer>;

/// How often discovery, tables, and reconnection are looked after.
const TICK: Duration = Duration::from_millis(500);
/// How long stranger browsing stays on after a `Strangers` request.
const STRANGER_BROWSING: Duration = Duration::from_secs(300);
/// Reconnection back-off: first and longest wait.
const RETRY_FIRST: Duration = Duration::from_secs(2);
const RETRY_MAX: Duration = Duration::from_secs(60);
/// A session at least this long resets the back-off.
const SESSION_LASTED: Duration = Duration::from_secs(30);
/// How long the core waits after a failed accept before the next.
const ACCEPT_PAUSE: Duration = Duration::from_millis(100);
/// How long a QR scan looks among the nearby strangers for the device
/// showing its QR before it turns to the relay.
const QR_SCAN_WINDOW: Duration = Duration::from_secs(10);
/// How many dials one QR scan makes at most to advertisements carrying
/// its QR's stranger token: more than one only if the token was copied.
const MAX_QR_TARGETS: usize = 4;
/// Entries listed by one `Offers` answer: four offers of §13's 10000.
const MAX_LISTED_ENTRIES: usize = 40_000;
/// Finished transfers remembered for `Transfers`.
const MAX_FINISHED: usize = 256;

/// The trusted wall clock.
pub(super) fn wall() -> UnixTime {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs());
    let clamped = seconds.min(todoke_proto::time::MAX_UNIX_TIME);
    // In range by construction.
    UnixTime::new(clamped).unwrap_or_else(|| wall_fallback(clamped))
}

#[expect(
    clippy::unwrap_used,
    reason = "never called: the clamped value is in range"
)]
fn wall_fallback(_: u64) -> UnixTime {
    UnixTime::new(0).unwrap()
}

/// Offers waiting for a session with one peer, and the source that serves
/// them (kept across sessions so an interrupted transfer can resume).
pub(super) struct PeerQueue {
    pub(super) source: FsSource,
    /// New transfers, built into offers once a session negotiated (§6).
    pub(super) prepared: Vec<send::Prepared>,
    /// Built offers waiting for a session, resumable ones included.
    pub(super) offers: Vec<OutgoingOffer>,
}

impl PeerQueue {
    /// Drops the offers past their lifetime at `now` and stops serving
    /// their files; returns their IDs.
    pub(super) fn expire(&mut self, now: UnixTime) -> Vec<TransferId> {
        let mut gone = Vec::new();
        self.prepared.retain(|prepared| {
            let live = prepared
                .created_at()
                .seconds()
                .saturating_add(send::OFFER_LIFETIME)
                > now.seconds();
            if !live {
                gone.push(*prepared.transfer_id());
            }
            live
        });
        self.offers.retain(|offer| {
            let live = offer.manifest().manifest().header().expires_at > now;
            if !live {
                gone.push(*offer.transfer_id());
            }
            live
        });
        for id in &gone {
            self.source.remove_transfer(id);
        }
        gone
    }
}

/// Which transfers are idle (finished or interrupted), oldest first; past
/// [`MAX_FINISHED`] the oldest are forgotten.
#[derive(Default)]
pub(super) struct Idle {
    order: VecDeque<TransferId>,
}

impl Idle {
    /// `id` went from `was` to `now` (`true`: idle); returns the transfers
    /// to forget.
    pub(super) fn update(&mut self, id: TransferId, was: bool, now: bool) -> Vec<TransferId> {
        if !now {
            self.order.retain(|old| *old != id);
            return Vec::new();
        }
        if was && self.order.contains(&id) {
            return Vec::new();
        }
        self.order.push_back(id);
        let excess = self.order.len().saturating_sub(MAX_FINISHED);
        self.order.drain(..excess).collect()
    }

    /// `id` was recorded afresh (a resumed offer): not idle.
    pub(super) fn forget(&mut self, id: &TransferId) {
        self.order.retain(|old| old != id);
    }
}

/// The history entry of a transfer that just finished at `now`.
fn history_entry(id: &TransferId, record: &TransferRecord, now: UnixTime) -> HistoryEntry {
    HistoryEntry {
        transfer: hex(id),
        peer: hex(record.peer.as_bytes()),
        way: record.way,
        state: record.state,
        detail: record.detail.clone(),
        finished_at: now.seconds(),
        files: record.files,
        bytes: record.total,
        names: record.names.clone(),
        manifest_hash: record.manifest_hash.map(hex),
        receipt: record.receipt.map(|(id, completed_at)| ReceiptInfo {
            id: hex(id),
            completed_at: completed_at.seconds(),
        }),
    }
}

/// Offers to list, in order, at most [`MAX_LISTED_ENTRIES`] entries in all
/// but never none when one waits.
pub(super) fn capped<'a>(offers: impl Iterator<Item = &'a OfferInfo>) -> Vec<OfferInfo> {
    let mut entries = 0;
    let mut listed = Vec::new();
    for offer in offers {
        entries += offer.entries.len();
        if entries > MAX_LISTED_ENTRIES && !listed.is_empty() {
            break;
        }
        listed.push(offer.clone());
    }
    listed
}

/// What the core knows about one transfer.
#[derive(Clone)]
pub(super) struct TransferRecord {
    pub(super) peer: Ed25519PublicKey,
    pub(super) way: Way,
    pub(super) state: TransferState,
    pub(super) detail: Option<String>,
    pub(super) done: u64,
    pub(super) total: u64,
    /// For the history: files offered, then selected.
    pub(super) files: u32,
    /// For the history: the first top-level names.
    pub(super) names: Vec<String>,
    /// The manifest's hash, once the offer was sent or received.
    pub(super) manifest_hash: Option<[u8; 32]>,
    /// The signed receipt's ID and completion time (§7.7).
    pub(super) receipt: Option<([u8; 16], UnixTime)>,
}

/// Where an accepted link came from, and so what it may carry.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Origin {
    /// The LAN listener: contacts and every kind of pairing.
    Lan,
    /// A relay tunnel opened for this contact: its session only.
    RelayContact(Ed25519PublicKey),
    /// A relay tunnel opened for a shown QR offer: QR pairing only.
    RelayQr,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Pairing {
    Qr,
    Code,
}

/// The core's state, shared by its tasks on the core thread.
pub(super) struct State {
    pub(super) config: CoreConfig,
    pub(super) identity: Identity,
    pub(super) contacts: tokio::sync::Mutex<Contacts>,
    pub(super) offers: PairingOffers,
    pub(super) manager: TransportManager,
    connector: TcpConnector,
    listener: Option<LanListener>,
    pub(super) sink: Sink,
    /// Meeting contacts and QR scanners through relays (§10), if any are
    /// configured.
    pub(super) relay: Option<super::relay::Relays>,
    /// Hashes files for new offers on the blocking pool.
    preparer: Preparer,
    pub(super) events: broadcast::Sender<Event>,
    pub(super) table: RefCell<DiscoveryTable>,
    pub(super) directory: RefCell<Directory>,
    advertiser: RefCell<Advertiser>,
    backend: RefCell<Backend>,
    pub(super) sessions: RefCell<BTreeMap<Ed25519PublicKey, mpsc::Sender<SessionCommand>>>,
    /// How each open session reaches its contact.
    pub(super) routes: RefCell<BTreeMap<Ed25519PublicKey, Route>>,
    pub(super) queues: RefCell<BTreeMap<Ed25519PublicKey, PeerQueue>>,
    pub(super) transfers: RefCell<BTreeMap<TransferId, TransferRecord>>,
    /// Received offers, until they are decided or end.
    pub(super) received: RefCell<BTreeMap<TransferId, OfferInfo>>,
    /// Idle transfers, oldest first.
    finished: RefCell<Idle>,
    /// Addresses each contact was last reached at (its own listener's).
    pub(super) last_known: RefCell<BTreeMap<Ed25519PublicKey, Vec<SocketAddr>>>,
    retry: RefCell<BTreeMap<Ed25519PublicKey, (Duration, Duration)>>,
    pub(super) pairing: Cell<Option<Pairing>>,
    strangers_until: Cell<Duration>,
    /// Hidden from contacts: no paired advertisement, no relay presence.
    pub(super) hidden: Cell<bool>,
    /// Finished transfers, sealed at rest.
    history: RefCell<History<SoftwareSealer>>,
    /// What protects the storage key.
    key_protection: crate::api::KeyProtection,
}

impl State {
    /// Opens the profile, quarantine, listener, and discovery.
    pub(super) fn open(
        config: CoreConfig,
        key_source: &dyn StorageKeySource,
        events: broadcast::Sender<Event>,
    ) -> Result<Rc<Self>, StartError> {
        let now = wall();
        // The private state directory first: a key file goes in it.
        crate::profile::private_dir(&config.state_dir).map_err(StartError::Profile)?;
        // Asked once: a platform store may cost a round trip (or a prompt).
        let key = key_source.storage_key().map_err(|error| {
            StartError::Profile(crate::profile::ProfileError::storage_key(&error))
        })?;
        let key_protection = key_source.protection();
        let fetched = crate::storage_key::Fetched(Zeroizing::new(*key));
        let profile =
            Profile::open(&config.state_dir, &fetched, now).map_err(StartError::Profile)?;
        let (identity, contacts) = profile.into_parts();
        let sealer = SoftwareSealer::new(StorageKey::from_bytes(Zeroizing::new(*key)));
        if config.history_days > MAX_HISTORY_DAYS {
            return Err(StartError::Io(std::io::ErrorKind::InvalidInput));
        }
        let history = History::open(
            &config.state_dir,
            SoftwareSealer::new(StorageKey::from_bytes(Zeroizing::new(*key))),
            config.history_days,
            now,
        );
        std::fs::create_dir_all(&config.downloads_dir)
            .map_err(|error| StartError::Io(error.kind()))?;
        let destination = DirDestination::open(&config.downloads_dir)
            .map_err(|_| StartError::Io(std::io::ErrorKind::PermissionDenied))?;
        let sink = FsSink::open(
            &config.state_dir.join("quarantine"),
            destination,
            sealer,
            SinkConfig::default(),
            now,
        )
        .map_err(|error| StartError::Quarantine(error.to_string()))?;
        let preparer = Preparer::new(&config.state_dir.join("prepared"))
            .map_err(|error| StartError::Io(error.kind()))?;
        let relay = super::relay::Relays::new(&config.relays, config.relay_presence_seconds)?;
        let mut policy = LanPolicy::new();
        if config.lan.allow_loopback {
            policy = policy.with_loopback();
        }
        let offers = PairingOffers::new();
        let manager =
            TransportManager::new(GATE, *identity.binding().device_public(), offers.clone());
        let listener = if config.lan.enabled {
            Some(
                LanListener::bind(config.lan.port, policy)
                    .map_err(|error| StartError::Io(error.kind()))?,
            )
        } else {
            None
        };
        let port = listener.as_ref().and_then(|listener| listener.port().ok());
        let backend = match (port, &config.discovery_folder) {
            (Some(port), Some(folder)) => Backend::Folder(
                crate::discovery::Folder::new(folder.clone(), port, policy)
                    .map_err(|error| StartError::Io(error.kind()))?,
            ),
            (Some(port), None) => Mdns::start(port, policy).map_or(Backend::Off, Backend::Mdns),
            (None, _) => Backend::Off,
        };
        let table = contacts
            .discovery_table(now)
            .map_err(|_| StartError::Io(std::io::ErrorKind::Other))?;
        let hidden = config.hidden;
        Ok(Rc::new(Self {
            config,
            identity,
            contacts: tokio::sync::Mutex::new(contacts),
            offers,
            manager,
            connector: TcpConnector::new(policy),
            listener,
            sink: SharedSink::new(sink),
            relay,
            preparer,
            events,
            table: RefCell::new(table),
            directory: RefCell::new(Directory::new()),
            advertiser: RefCell::new(Advertiser::new()),
            backend: RefCell::new(backend),
            sessions: RefCell::new(BTreeMap::new()),
            routes: RefCell::new(BTreeMap::new()),
            queues: RefCell::new(BTreeMap::new()),
            transfers: RefCell::new(BTreeMap::new()),
            received: RefCell::new(BTreeMap::new()),
            finished: RefCell::new(Idle::default()),
            last_known: RefCell::new(BTreeMap::new()),
            retry: RefCell::new(BTreeMap::new()),
            pairing: Cell::new(None),
            strangers_until: Cell::new(Duration::ZERO),
            hidden: Cell::new(hidden),
            history: RefCell::new(history),
            key_protection,
        }))
    }

    pub(super) fn mono(&self) -> Duration {
        self.manager.timer().now()
    }

    pub(super) fn emit(&self, event: Event) {
        let _ = self.events.send(event);
    }

    /// Rebuilds the discovery table from the contact store (after a
    /// committed session, a pairing, or at an epoch boundary).
    pub(super) async fn refresh_table(&self) {
        let contacts = self.contacts.lock().await;
        if let Ok(table) = contacts.discovery_table(wall()) {
            *self.table.borrow_mut() = table;
        }
    }

    /// One discovery and reconnection step.
    fn tick(self: &Rc<Self>) {
        let now = wall();
        let mono = self.mono();
        // Never waits on a handshake holding the contacts: the next tick
        // tries again.
        if self.table.borrow().is_stale(now)
            && let Ok(contacts) = self.contacts.try_lock()
            && let Ok(table) = contacts.discovery_table(now)
        {
            *self.table.borrow_mut() = table;
        }
        self.expire_queued(now);
        {
            let table = self.table.borrow();
            let mut directory = self.directory.borrow_mut();
            directory.set_stranger_browsing(mono < self.strangers_until.get());
            let mut plan = self
                .advertiser
                .borrow_mut()
                .plan(&table, now, mono, &mut OsRandom);
            if self.hidden.get() {
                plan.paired = None;
            }
            if self.pairing.get().is_some() && plan.stranger.is_none() {
                // The stranger advertisement expired with the offer.
                self.pairing.set(None);
            }
            directory.set_own(plan.labels());
            let mut backend = self.backend.borrow_mut();
            backend.apply(&plan);
            backend.drain(&mut directory, &table, mono);
            directory.expire(&table, mono);
        }
        self.reconnect(mono);
        self.relay_tick(now);
    }

    /// Starts a session with every contact that has offers waiting, is
    /// reachable, and is not waiting out its back-off.
    fn reconnect(self: &Rc<Self>, mono: Duration) {
        let waiting: Vec<Ed25519PublicKey> = self
            .queues
            .borrow()
            .iter()
            .filter(|(_, queue)| !queue.offers.is_empty() || !queue.prepared.is_empty())
            .map(|(peer, _)| *peer)
            .collect();
        for peer in waiting {
            if self.sessions.borrow().contains_key(&peer) || self.manager.is_busy(&peer) {
                continue;
            }
            let due = self
                .retry
                .borrow()
                .get(&peer)
                .is_none_or(|(next, _)| mono >= *next);
            if !due {
                continue;
            }
            let candidates = self.candidates(&peer, mono);
            if candidates.is_empty() {
                continue;
            }
            let backoff = self
                .retry
                .borrow()
                .get(&peer)
                .map_or(RETRY_FIRST, |(_, backoff)| (*backoff * 2).min(RETRY_MAX));
            self.retry
                .borrow_mut()
                .insert(peer, (mono + backoff, backoff));
            let state = Rc::clone(self);
            tokio::task::spawn_local(async move {
                let _ = state.connect(peer, candidates).await;
            });
        }
    }

    /// Where `peer` may be: discovered addresses, then where it was last
    /// reached. Untrusted hints; the handshake authenticates.
    fn candidates(&self, peer: &Ed25519PublicKey, mono: Duration) -> Vec<Candidate> {
        let mut candidates = self
            .directory
            .borrow()
            .contact(peer, mono)
            .map(|reachable| reachable.candidates())
            .unwrap_or_default();
        if let Some(addresses) = self.last_known.borrow().get(peer) {
            for address in addresses {
                let candidate = Candidate::new(LinkKind::Lan, *address);
                if !candidates.contains(&candidate) {
                    candidates.push(candidate);
                }
            }
        }
        candidates
    }

    /// Connects to `peer` and runs a session with it.
    async fn connect(
        self: &Rc<Self>,
        peer: Ed25519PublicKey,
        candidates: Vec<Candidate>,
    ) -> Result<(), ConnectError> {
        let connected = self
            .manager
            .claim_outgoing(peer)?
            .connect(&self.connector, &candidates)
            .await?;
        self.initiate_on(peer, connected).await
    }

    /// Runs the initiator's handshake on `connected` and then the session
    /// (§4: the side that opened the link, or the smaller device key on a
    /// relay tunnel).
    pub(super) async fn initiate_on<L: Link>(
        self: &Rc<Self>,
        peer: Ed25519PublicKey,
        connected: Connected<'_, L>,
    ) -> Result<(), ConnectError> {
        let table = self.table.borrow().clone();
        let now = wall();
        let local = self
            .identity
            .local(now)
            .map_err(|_| ConnectError::UnknownPeer)?;
        let established = {
            let mut contacts = self.contacts.lock().await;
            connected
                .initiate(&table, &mut contacts, &local, now)
                .await?
        };
        self.refresh_table().await;
        // Its listener's address, for reconnecting without discovery.
        if established.link().kind() == LinkKind::Lan
            && let Some(remote) = established.link().remote()
        {
            self.last_known.borrow_mut().insert(peer, vec![remote]);
        }
        let started = self.mono();
        session::run(Rc::clone(self), established).await;
        // The back-off restarts only after a session that lasted: one that
        // ends at once is retried no faster than before.
        if self.mono().saturating_sub(started) >= SESSION_LASTED {
            self.retry.borrow_mut().remove(&peer);
        }
        Ok(())
    }

    /// Handles one accepted link: only what `origin` allows (a relay
    /// tunnel is accepted only for what it was opened for, and human-code
    /// pairing only on the LAN, §10 and §16 O8). Returns whether a session
    /// ran or a pairing committed.
    pub(super) async fn incoming<L: Link>(self: &Rc<Self>, link: L, origin: Origin) -> bool {
        let Ok(incoming) = self.manager.accept(link).await else {
            return false;
        };
        let now = wall();
        match incoming {
            Incoming::Contact(contact) if origin != Origin::RelayQr => {
                let table = self.table.borrow().clone();
                let Ok(claimed) = contact.claim(&table, now).await else {
                    return false;
                };
                // A tunnel opened for one contact carries no other's
                // session (whoever registered on its token).
                if let Origin::RelayContact(expected) = origin
                    && *claimed.peer() != expected
                {
                    return false;
                }
                let Ok(local) = self.identity.local(now) else {
                    return false;
                };
                let established = {
                    let mut contacts = self.contacts.lock().await;
                    claimed.respond(&table, &mut contacts, &local, now).await
                };
                let Ok(established) = established else {
                    return false;
                };
                self.refresh_table().await;
                session::run(Rc::clone(self), established).await;
                true
            }
            Incoming::Pairing(incoming) if !matches!(origin, Origin::RelayContact(_)) => {
                let mode = incoming.client_hello().mode();
                if origin == Origin::RelayQr && mode != SessionMode::Qr {
                    return false;
                }
                self.pairing_responder(incoming).await
            }
            Incoming::CodeOfferRequest(request) if origin == Origin::Lan => {
                let Some(token) = self.stranger_token() else {
                    return false;
                };
                if self.pairing.get() != Some(Pairing::Code) {
                    return false;
                }
                match request.answer(CODE_GATE, &self.offers, &token, now).await {
                    Ok(incoming) => self.pairing_responder(incoming).await,
                    Err(_) => false,
                }
            }
            _ => false,
        }
    }

    /// The stranger token this device advertises now.
    pub(super) fn stranger_token(&self) -> Option<[u8; DISCOVERY_TOKEN_LEN]> {
        let table = self.table.borrow();
        let plan = self
            .advertiser
            .borrow_mut()
            .plan(&table, wall(), self.mono(), &mut OsRandom);
        plan.stranger
            .map(|advertisement| *advertisement.record.token())
    }

    /// The displayer's side of QR or code pairing.
    async fn pairing_responder<L: Link>(
        self: &Rc<Self>,
        mut incoming: todoke_crypto::session::IncomingSession<L, TokioTimer>,
    ) -> bool {
        let now = wall();
        let mode = incoming.client_hello().mode();
        let shown = match mode {
            SessionMode::Qr => Pairing::Qr,
            SessionMode::Code => Pairing::Code,
            SessionMode::Contact => return false,
        };
        if self.pairing.get() != Some(shown) {
            return false;
        }
        let Ok(reservation) = incoming.reserve_offer(&self.offers, now) else {
            return false;
        };
        let Ok(local) = self.identity.local(now) else {
            return false;
        };
        let paired = {
            let mut contacts = self.contacts.lock().await;
            let planned = match mode {
                SessionMode::Qr => reservation.into_qr_responder(&mut contacts),
                SessionMode::Code => reservation.into_code_responder(CODE_GATE, &mut contacts),
                SessionMode::Contact => return false,
            };
            let Ok((plan, mut authority)) = planned else {
                return false;
            };
            incoming
                .respond(&local, now, plan, &mut authority)
                .await
                .map(|session| *session.peer_binding().device_public())
        };
        if let Ok(peer) = paired {
            self.paired(peer).await;
            return true;
        }
        false
    }

    /// A pairing committed: stop showing the offer and tell the user.
    async fn paired(&self, peer: Ed25519PublicKey) {
        self.stop_pairing();
        self.refresh_table().await;
        self.emit(Event::Paired {
            contact: hex(peer.as_bytes()),
        });
    }

    /// Withdraws every pairing offer shown and stops advertising it: a QR
    /// code or code seen before can no longer pair.
    fn stop_pairing(&self) {
        self.offers.cancel_all();
        self.stop_qr_relay();
        self.pairing.set(None);
        self.advertiser.borrow_mut().disable_stranger();
    }

    /// Handles a request.
    pub(super) async fn handle(self: &Rc<Self>, request: Request) -> Response {
        match request {
            Request::Status => Response::Status(self.status()),
            Request::Contacts => Response::Contacts(self.contact_list().await),
            Request::Transfers => Response::Transfers(self.transfer_list()),
            Request::Offers => Response::Offers(self.offers_waiting()),
            Request::PairShowQr => self.show_qr(),
            Request::PairShowCode => self.show_code(),
            Request::StopPairing => {
                self.stop_pairing();
                Response::Done
            }
            Request::Strangers => {
                self.strangers_until.set(self.mono() + STRANGER_BROWSING);
                self.directory.borrow_mut().set_stranger_browsing(true);
                let strangers = self
                    .directory
                    .borrow()
                    .strangers(self.mono())
                    .into_iter()
                    .map(|(token, _)| StrangerInfo {
                        stranger: hex(token),
                    })
                    .collect();
                Response::Strangers(strangers)
            }
            Request::PairScanQr { text } => self.scan_qr(&Zeroizing::new(text)).await,
            Request::PairEnterCode { code, stranger } => {
                self.enter_code(&Zeroizing::new(code), &stranger).await
            }
            Request::Send { contact, paths } => self.send(&contact, &paths).await,
            Request::Accept { transfer, files } => {
                self.to_session(&transfer, |id| SessionCommand::Accept(id, files))
                    .await
            }
            Request::Decline { transfer } => {
                self.to_session(&transfer, SessionCommand::Decline).await
            }
            Request::Cancel { transfer } => self.cancel(&transfer).await,
            Request::SetHidden { hidden } => {
                self.hidden.set(hidden);
                Response::Done
            }
            Request::History => Response::History(self.history.borrow().list(wall())),
            Request::ClearHistory => {
                if self.history.borrow_mut().clear() {
                    Response::Done
                } else {
                    Response::error(ErrorCode::Internal, "the history could not be deleted")
                }
            }
        }
    }

    fn status(&self) -> StatusInfo {
        StatusInfo {
            device: hex(self.identity.binding().device_public().as_bytes()),
            sessions_enabled: true,
            port: self
                .listener
                .as_ref()
                .and_then(|listener| listener.port().ok()),
            contacts: self.table.borrow().len(),
            sessions: self.sessions.borrow().len(),
            pairing: self.pairing.get().is_some(),
            hidden: self.hidden.get(),
            history_days: self.history.borrow().days(),
            key_protection: self.key_protection,
        }
    }

    async fn contact_list(&self) -> Vec<ContactInfo> {
        let contacts = self.contacts.lock().await;
        let mono = self.mono();
        let directory = self.directory.borrow();
        let sessions = self.sessions.borrow();
        let routes = self.routes.borrow();
        contacts
            .contacts()
            .map(|contact| {
                let device = *contact.pinned().device_public();
                ContactInfo {
                    device: hex(device.as_bytes()),
                    person: hex(contact.pinned().person_root().as_bytes()),
                    available: matches!(contacts.availability(&device), Ok(Ok(_))),
                    nearby: directory.contact(&device, mono).is_some(),
                    connected: sessions.contains_key(&device),
                    route: routes.get(&device).copied(),
                }
            })
            .collect()
    }

    fn transfer_list(&self) -> Vec<TransferInfo> {
        self.transfers
            .borrow()
            .iter()
            .map(|(id, record)| TransferInfo {
                transfer: hex(id),
                peer: hex(record.peer.as_bytes()),
                way: record.way,
                state: record.state,
                detail: record.detail.clone(),
                bytes_done: record.done,
                bytes_total: record.total,
            })
            .collect()
    }

    /// Records a new transfer.
    pub(super) fn remember(&self, id: TransferId, record: TransferRecord) {
        self.transfers.borrow_mut().insert(id, record);
        self.finished.borrow_mut().forget(&id);
    }

    /// Moves a transfer to `next`; a received offer leaves the list of
    /// those awaiting a decision. Beyond [`MAX_FINISHED`] transfers that
    /// are finished or interrupted, the oldest are forgotten.
    pub(super) fn set_state(&self, id: &TransferId, next: TransferState) {
        if next != TransferState::AwaitingDecision {
            self.received.borrow_mut().remove(id);
        }
        let idle =
            |state: TransferState| state.is_finished() || state == TransferState::Interrupted;
        let mut transfers = self.transfers.borrow_mut();
        let Some(record) = transfers.get_mut(id) else {
            return;
        };
        let was = idle(record.state);
        let finished = !record.state.is_finished() && next.is_finished();
        record.state = next;
        if finished {
            let now = wall();
            let entry = history_entry(id, record, now);
            self.history.borrow_mut().record(entry, now);
        }
        for old in self.finished.borrow_mut().update(*id, was, idle(next)) {
            transfers.remove(&old);
        }
    }

    /// A session with `peer` ended: what was moving or awaiting a decision
    /// in it can only resume in the next one (§7.5).
    pub(super) fn interrupt(&self, peer: &Ed25519PublicKey) {
        let open: Vec<TransferId> = self
            .transfers
            .borrow()
            .iter()
            .filter(|(_, record)| {
                record.peer == *peer
                    && matches!(
                        record.state,
                        TransferState::AwaitingDecision
                            | TransferState::Accepted
                            | TransferState::Transferring
                    )
            })
            .map(|(id, _)| *id)
            .collect();
        for id in open {
            self.set_state(&id, TransferState::Interrupted);
        }
    }

    /// Received offers still awaiting a decision, at most
    /// [`MAX_LISTED_ENTRIES`] entries in all (the rest are listed once these
    /// are decided), so the answer fits one IPC message.
    fn offers_waiting(&self) -> Vec<OfferInfo> {
        let transfers = self.transfers.borrow();
        let received = self.received.borrow();
        capped(received.iter().filter_map(|(id, offer)| {
            transfers
                .get(id)
                .is_some_and(|record| record.state == TransferState::AwaitingDecision)
                .then_some(offer)
        }))
    }

    fn show_qr(self: &Rc<Self>) -> Response {
        // One offer at a time: a new one replaces any shown before.
        self.stop_pairing();
        let now = wall();
        let Ok(local) = self.identity.local(now) else {
            return Response::error(ErrorCode::Internal, "the device binding is not valid");
        };
        let Ok(payload) = self.offers.create_qr(&local, now, self.mono()) else {
            return Response::error(ErrorCode::Pairing, "no pairing offer could be created");
        };
        // Its scanner recognises it by the QR's stranger tokens (§9).
        let Ok(tokens) = payload
            .stranger_key()
            .and_then(|key| key.schedule(now, payload.expires_at()))
        else {
            self.offers.cancel_all();
            return Response::error(ErrorCode::Internal, "no pairing offer could be created");
        };
        if !self
            .advertiser
            .borrow_mut()
            .enable_qr_stranger(tokens, now, self.mono(), &mut OsRandom)
        {
            self.offers.cancel_all();
            return Response::error(ErrorCode::Internal, "OS randomness is unavailable");
        }
        self.pairing.set(Some(Pairing::Qr));
        self.display_qr_relay(&payload);
        Response::Qr {
            text: payload.to_text().to_string(),
            expires_at: payload.expires_at().seconds(),
        }
    }

    fn show_code(&self) -> Response {
        self.stop_pairing();
        let now = wall();
        let Ok(code) = self.offers.create_code(CODE_GATE, now, self.mono()) else {
            return Response::error(ErrorCode::Pairing, "no pairing offer could be created");
        };
        if !self
            .advertiser
            .borrow_mut()
            .enable_stranger(now, self.mono(), &mut OsRandom)
        {
            return Response::error(ErrorCode::Internal, "OS randomness is unavailable");
        }
        self.pairing.set(Some(Pairing::Code));
        Response::Code {
            code: code.as_str().to_owned(),
            expires_at: now.seconds().saturating_add(300),
        }
    }

    /// The scanner's side of QR pairing: tries the nearby strangers, then
    /// the relay (§10: the offer's rendezvous capability).
    async fn scan_qr(self: &Rc<Self>, text: &str) -> Response {
        let now = wall();
        let Ok(payload) = QrPayload::from_text(text, now) else {
            return Response::error(ErrorCode::Pairing, "not a valid, unexpired pairing code");
        };
        self.strangers_until.set(self.mono() + STRANGER_BROWSING);
        // Without the LAN there is nobody nearby to look for.
        if self.listener.is_some() {
            match self.scan_nearby(&payload).await {
                Ok(peer) => return self.paired_with(peer).await,
                Err(Some(response)) => return response,
                Err(None) => {}
            }
        }
        if let Some(link) = self.relay_for_qr(&payload, Role::Scanner).await {
            match self.scan_on(link, &payload).await {
                Ok(peer) => return self.paired_with(peer).await,
                Err(Some(response)) => return response,
                Err(None) => {}
            }
        }
        Response::error(ErrorCode::Pairing, "no device accepted the offer")
    }

    /// QR pairing with the nearby strangers: only advertisements carrying
    /// the QR's stranger token (§9) get its `ClientHello`, so pairings shown
    /// side by side never reach each other's displayers (§3.1). The scan
    /// looks for [`QR_SCAN_WINDOW`], since the displayer may not be seen
    /// yet. A token is a candidate filter, not authentication: anyone can
    /// copy it, so each address under it is dialed once (the handshake
    /// pins the QR's keys), at most [`MAX_QR_TARGETS`] times in all.
    async fn scan_nearby(
        self: &Rc<Self>,
        payload: &QrPayload,
    ) -> Result<Ed25519PublicKey, Option<Response>> {
        let Ok(key) = payload.stranger_key() else {
            return Err(None);
        };
        let deadline = self.mono() + QR_SCAN_WINDOW;
        let mut dialed = HashSet::new();
        let mut dials = 0;
        loop {
            let now = wall();
            for (token, candidates) in self.strangers() {
                if !key.matches(&token, now) {
                    continue;
                }
                let fresh: Vec<Candidate> = candidates
                    .into_iter()
                    .filter(|candidate| !dialed.contains(candidate))
                    .collect();
                if fresh.is_empty() {
                    continue;
                }
                if dials >= MAX_QR_TARGETS {
                    return Err(None);
                }
                dials += 1;
                let Ok(link) = todoke_transport::race::race(
                    &self.connector,
                    &fresh,
                    &todoke_transport::RaceConfig::default(),
                )
                .await
                else {
                    dialed.extend(fresh);
                    continue;
                };
                // Only the address that answered is done: under a copied
                // token, the others get a dial of their own.
                let remote = link.info().remote();
                if let Some(answered) = fresh
                    .iter()
                    .find(|candidate| Some(candidate.address()) == remote)
                {
                    dialed.insert(*answered);
                } else {
                    dialed.extend(fresh);
                }
                match self.scan_on(link, payload).await {
                    Err(None) => {}
                    done => return done,
                }
            }
            if self.mono() >= deadline {
                return Err(None);
            }
            self.tick();
            tokio::time::sleep(TICK).await;
        }
    }

    /// QR pairing as the scanner (the initiator, §4) on `link`: the new
    /// contact, or `Some` response for an offer that cannot be used.
    async fn scan_on<L: Link>(
        &self,
        link: L,
        payload: &QrPayload,
    ) -> Result<Ed25519PublicKey, Option<Response>> {
        let now = wall();
        let local = self.identity.local(now).map_err(|_| None)?;
        let mut contacts = self.contacts.lock().await;
        let Ok((plan, mut authority)) = contacts.begin_qr_pairing(payload, now) else {
            return Err(Some(Response::error(
                ErrorCode::Pairing,
                "this offer cannot be used",
            )));
        };
        Session::initiate(
            link,
            self.manager.timer(),
            GATE,
            &local,
            now,
            plan,
            &mut authority,
        )
        .await
        .map(|session| *session.peer_binding().device_public())
        .map_err(|_| None)
    }

    async fn paired_with(&self, peer: Ed25519PublicKey) -> Response {
        self.paired(peer).await;
        Response::Paired {
            contact: hex(peer.as_bytes()),
        }
    }

    /// The entrant's side of code pairing.
    async fn enter_code(self: &Rc<Self>, code: &str, stranger: &str) -> Response {
        let Ok(code) = HumanCode::parse(code) else {
            return Response::error(ErrorCode::Invalid, "a code is ten digits");
        };
        let Some(token) = parse_token(stranger) else {
            return Response::error(ErrorCode::Invalid, "unknown stranger");
        };
        self.strangers_until.set(self.mono() + STRANGER_BROWSING);
        let Some(candidates) = self
            .wait_for_strangers()
            .await
            .into_iter()
            .find_map(|(seen, candidates)| (seen == token).then_some(candidates))
        else {
            return Response::error(ErrorCode::Unreachable, "that device is no longer nearby");
        };
        let Ok(link) = todoke_transport::race::race(
            &self.connector,
            &candidates,
            &todoke_transport::RaceConfig::default(),
        )
        .await
        else {
            return Response::error(ErrorCode::Unreachable, "that device did not answer");
        };
        let now = wall();
        let Ok(local) = self.identity.local(now) else {
            return Response::error(ErrorCode::Internal, "the device binding is not valid");
        };
        let paired = {
            let mut contacts = self.contacts.lock().await;
            Session::initiate_code_pairing(
                link,
                self.manager.timer(),
                GATE,
                CODE_GATE,
                &local,
                now,
                token,
                &code,
                &mut contacts,
            )
            .await
            .map(|(session, _)| *session.peer_binding().device_public())
        };
        match paired {
            Ok(peer) => {
                self.paired(peer).await;
                Response::Paired {
                    contact: hex(peer.as_bytes()),
                }
            }
            Err(_) => Response::error(
                ErrorCode::Pairing,
                "pairing failed (wrong or expired code?)",
            ),
        }
    }

    /// The strangers seen now and where to reach them.
    fn strangers(&self) -> Vec<([u8; DISCOVERY_TOKEN_LEN], Vec<Candidate>)> {
        self.directory
            .borrow()
            .strangers(self.mono())
            .into_iter()
            .map(|(token, reachable)| (token, reachable.candidates()))
            .collect()
    }

    /// The strangers seen, waiting a few ticks for answers if none yet.
    async fn wait_for_strangers(
        self: &Rc<Self>,
    ) -> Vec<([u8; DISCOVERY_TOKEN_LEN], Vec<Candidate>)> {
        for _ in 0..20 {
            let found = self.strangers();
            if !found.is_empty() {
                return found;
            }
            self.tick();
            tokio::time::sleep(TICK).await;
        }
        Vec::new()
    }

    /// Offers `paths` to `contact`: walked and hashed on the blocking pool
    /// (the core keeps serving meanwhile), then handed to the session with
    /// that contact or queued for the next one.
    async fn send(self: &Rc<Self>, contact: &str, paths: &[std::path::PathBuf]) -> Response {
        let paths = paths.to_vec();
        self.send_with(contact, move || send::walk(&paths)).await
    }

    /// Offers what `walk` finds (paths walked, or files handed over open)
    /// to `contact`: walked and hashed on the blocking pool.
    pub(super) async fn send_with(
        self: &Rc<Self>,
        contact: &str,
        walk: impl FnOnce() -> Result<send::Walked, send::SendError> + Send + 'static,
    ) -> Response {
        let peer = match self.resolve_contact(contact).await {
            Ok(peer) => peer,
            Err(response) => return response,
        };
        let (hasher, now) = (self.preparer.clone(), wall());
        let outcome = tokio::task::spawn_blocking(move || {
            let walked = walk()?;
            send::check_open_files(walked.files())?;
            send::prepare(&walked, now, &hasher).map(|prepared| (prepared, walked.skipped))
        })
        .await;
        let (prepared, skipped) = match outcome {
            Ok(Ok(done)) => done,
            Ok(Err(error)) => return Response::error(ErrorCode::Source, error.to_string()),
            Err(_) => return Response::error(ErrorCode::Internal, "preparing the files failed"),
        };
        let transfer_id = *prepared.transfer_id();
        self.remember(
            transfer_id,
            TransferRecord {
                peer,
                way: Way::Outgoing,
                state: TransferState::Offered,
                detail: None,
                done: 0,
                total: prepared.total_bytes(),
                files: prepared.files(),
                names: prepared.top_names(HISTORY_NAMES),
                manifest_hash: None,
                receipt: None,
            },
        );
        if let Err(response) = self.queue(peer, prepared).await {
            self.set_state(&transfer_id, TransferState::Failed);
            return response;
        }
        self.retry.borrow_mut().remove(&peer);
        self.reconnect(self.mono());
        Response::Offered {
            transfer: hex(transfer_id),
            skipped,
        }
    }

    /// Hands `prepared` to the session with `peer`, whose engine's source
    /// then serves its files, or, with no session, to `peer`'s queue.
    async fn queue(
        &self,
        peer: Ed25519PublicKey,
        prepared: send::Prepared,
    ) -> Result<(), Response> {
        let session = self.sessions.borrow().get(&peer).cloned();
        let mut prepared = match session {
            Some(session) => match session
                .send(SessionCommand::Offer(Box::new(prepared)))
                .await
            {
                Ok(()) => return Ok(()),
                // The session ended meanwhile; its queue is back in place.
                Err(mpsc::error::SendError(SessionCommand::Offer(prepared))) => *prepared,
                Err(_) => return Err(Response::error(ErrorCode::Internal, "the offer was lost")),
            },
            None => prepared,
        };
        // No await from here on: no session can start for `peer` and take
        // the queue in between.
        let Ok(mut queue) = self.take_queue(&peer) else {
            return Err(Response::error(
                ErrorCode::Internal,
                "the state directory is unusable",
            ));
        };
        prepared.install(&mut queue.source);
        queue.prepared.push(prepared);
        self.queues.borrow_mut().insert(peer, queue);
        Ok(())
    }

    /// Cancels `transfer`: through its session, or, for an outgoing offer
    /// still waiting for one, here.
    async fn cancel(&self, transfer: &str) -> Response {
        let (id, peer) = match self.find_transfer(transfer) {
            Ok(found) => found,
            Err(response) => return response,
        };
        if self.sessions.borrow().contains_key(&peer) {
            return self.to_session(transfer, SessionCommand::Cancel).await;
        }
        let mut queues = self.queues.borrow_mut();
        let Some(queue) = queues.get_mut(&peer) else {
            return Response::error(ErrorCode::Unreachable, "the peer is not connected");
        };
        let before = queue.prepared.len() + queue.offers.len();
        queue
            .prepared
            .retain(|prepared| *prepared.transfer_id() != id);
        queue.offers.retain(|offer| *offer.transfer_id() != id);
        if queue.prepared.len() + queue.offers.len() == before {
            return Response::error(ErrorCode::Unreachable, "the peer is not connected");
        }
        queue.source.remove_transfer(&id);
        drop(queues);
        session::end(
            self,
            &id,
            TransferState::Cancelled,
            "the transfer was cancelled",
        );
        Response::Done
    }

    /// Drops queued offers past their lifetime (§7.5: they cannot resume).
    fn expire_queued(&self, now: UnixTime) {
        let expired: Vec<TransferId> = self
            .queues
            .borrow_mut()
            .values_mut()
            .flat_map(|queue| queue.expire(now))
            .collect();
        for id in expired {
            session::end(self, &id, TransferState::Failed, "expired");
        }
    }

    /// The queue for `peer`, created if missing (with its own outboard
    /// directory).
    ///
    /// # Errors
    ///
    /// The I/O error if the outboard directory cannot be prepared.
    pub(super) fn take_queue(&self, peer: &Ed25519PublicKey) -> std::io::Result<PeerQueue> {
        if let Some(queue) = self.queues.borrow_mut().remove(peer) {
            return Ok(queue);
        }
        let dir = self
            .config
            .state_dir
            .join("sources")
            .join(hex(&peer.as_bytes()[..8]));
        Ok(PeerQueue {
            source: FsSource::new(&dir)?,
            prepared: Vec::new(),
            offers: Vec::new(),
        })
    }

    /// The contact `prefix` names, if this device may still exchange files
    /// with it (not blocked or revoked).
    async fn resolve_contact(&self, prefix: &str) -> Result<Ed25519PublicKey, Response> {
        let prefix = prefix.to_ascii_lowercase();
        if prefix.len() < MIN_PREFIX {
            return Err(Response::error(
                ErrorCode::Invalid,
                "name a contact by at least 8 hex digits",
            ));
        }
        let contacts = self.contacts.lock().await;
        let mut matches = contacts
            .contacts()
            .map(|contact| *contact.pinned().device_public())
            .filter(|device| hex(device.as_bytes()).starts_with(&prefix));
        match (matches.next(), matches.next()) {
            (Some(device), None) if !matches!(contacts.availability(&device), Ok(Ok(_))) => Err(
                Response::error(ErrorCode::State, "that contact is blocked or revoked"),
            ),
            (Some(device), None) => Ok(device),
            (Some(_), Some(_)) => Err(Response::error(
                ErrorCode::Ambiguous,
                "more than one contact matches",
            )),
            (None, _) => Err(Response::error(ErrorCode::Invalid, "no such contact")),
        }
    }

    /// The transfer `prefix` names, and its peer.
    fn find_transfer(&self, prefix: &str) -> Result<(TransferId, Ed25519PublicKey), Response> {
        let prefix = prefix.to_ascii_lowercase();
        if prefix.len() < MIN_PREFIX {
            return Err(Response::error(
                ErrorCode::Invalid,
                "name a transfer by at least 8 hex digits",
            ));
        }
        let found: Vec<(TransferId, Ed25519PublicKey)> = self
            .transfers
            .borrow()
            .iter()
            .filter(|(id, _)| hex(id).starts_with(&prefix))
            .map(|(id, record)| (*id, record.peer))
            .collect();
        match found.as_slice() {
            [one] => Ok(*one),
            [] => Err(Response::error(ErrorCode::Invalid, "no such transfer")),
            _ => Err(Response::error(
                ErrorCode::Ambiguous,
                "more than one transfer matches",
            )),
        }
    }

    /// Routes a decision to the session carrying `transfer`.
    async fn to_session(
        &self,
        transfer: &str,
        command: impl FnOnce(TransferId) -> SessionCommand,
    ) -> Response {
        let (id, peer) = match self.find_transfer(transfer) {
            Ok(found) => found,
            Err(response) => return response,
        };
        let session = self.sessions.borrow().get(&peer).cloned();
        let Some(session) = session else {
            return Response::error(ErrorCode::Unreachable, "the peer is not connected");
        };
        let (reply, answer) = oneshot::channel();
        if session
            .send(SessionCommand::with_reply(command(id), reply))
            .await
            .is_err()
        {
            return Response::error(ErrorCode::Unreachable, "the session ended");
        }
        answer
            .await
            .unwrap_or_else(|_| Response::error(ErrorCode::Unreachable, "the session ended"))
    }
}

fn parse_token(text: &str) -> Option<[u8; DISCOVERY_TOKEN_LEN]> {
    let bytes = text.as_bytes();
    if bytes.len() != DISCOVERY_TOKEN_LEN * 2 {
        return None;
    }
    let mut out = [0; DISCOVERY_TOKEN_LEN];
    let digit = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    for ([high, low], byte) in bytes.as_chunks::<2>().0.iter().zip(out.iter_mut()) {
        *byte = (digit(*high)? << 4) | digit(*low)?;
    }
    Some(out)
}

/// The core loop: requests, incoming links, and the tick.
pub(super) async fn run(
    state: Rc<State>,
    mut requests: mpsc::Receiver<Envelope>,
    mut stop: oneshot::Receiver<()>,
) {
    let mut tick = tokio::time::interval(TICK);
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        // The next paired record change, on time rather than at the tick
        // after it (docs/adr/0013-private-discovery.md).
        let rotation = {
            let next = state.advertiser.borrow().next_change(state.mono());
            let timer = state.manager.timer();
            async move {
                match next {
                    Some(at) => timer.sleep_until(at).await,
                    None => core::future::pending().await,
                }
            }
        };
        let accept = async {
            match &state.listener {
                Some(listener) => listener.accept().await,
                None => core::future::pending().await,
            }
        };
        tokio::select! {
            _ = &mut stop => break,
            envelope = requests.recv() => {
                let Some((command, reply)) = envelope else { break };
                let state = Rc::clone(&state);
                tokio::task::spawn_local(async move {
                    let response = match command {
                        Command::Api(request) => state.handle(request).await,
                        Command::SendFiles { contact, files } => {
                            state
                                .send_with(&contact, move || send::walk_open(files))
                                .await
                        }
                    };
                    let _ = reply.send(response);
                });
            }
            accepted = accept => {
                if let Ok(link) = accepted {
                    let state = Rc::clone(&state);
                    tokio::task::spawn_local(async move {
                        state.incoming(link, Origin::Lan).await;
                    });
                } else {
                    // Out of descriptors, say: never spin on it.
                    tokio::time::sleep(ACCEPT_PAUSE).await;
                }
            }
            _ = tick.tick() => state.tick(),
            () = rotation => state.tick(),
        }
    }
}
