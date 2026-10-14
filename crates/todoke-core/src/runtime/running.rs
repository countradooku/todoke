//! The core's state and its loop (see the parent module).

use core::cell::{Cell, RefCell};
use core::time::Duration;
use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::rc::Rc;

use todoke_crypto::discovery::DiscoveryTable;
use todoke_crypto::identity::{Ed25519PublicKey, SoftwareSealer, StorageKey};
use todoke_crypto::pairing::{HumanCode, PairingOffers, QrPayload, UnauditedCodePairing};
use todoke_crypto::session::{Session, SessionMode, Timer as _, UnauditedSuite0001};
use todoke_discovery::{Advertiser, Directory, Mdns, OsRandom};
use todoke_fs::dest::DirDestination;
use todoke_fs::{FsSink, FsSource, SharedSink, SinkConfig};
use todoke_proto::discovery::DISCOVERY_TOKEN_LEN;
use todoke_proto::time::UnixTime;
use todoke_proto::transfer::TransferId;
use todoke_transfer::OutgoingOffer;
use todoke_transport::{
    Candidate, ConnectError, Incoming, LanListener, LanPolicy, LinkKind, TcpConnector, TcpLink,
    TokioTimer, TransportManager,
};
use tokio::sync::{broadcast, mpsc, oneshot};
use zeroize::Zeroizing;

use super::session::{self, SessionCommand};
use super::{Envelope, StartError};
use crate::api::{
    ContactInfo, ErrorCode, Event, MIN_PREFIX, OfferInfo, Request, Response, StatusInfo,
    StrangerInfo, TransferInfo, TransferState, Way, hex,
};
use crate::config::CoreConfig;
use crate::discovery::Backend;
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
/// How many stranger devices a QR scan tries.
const MAX_QR_TARGETS: usize = 4;
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

/// What the core knows about one transfer.
#[derive(Clone)]
pub(super) struct TransferRecord {
    pub(super) peer: Ed25519PublicKey,
    pub(super) way: Way,
    pub(super) state: TransferState,
    pub(super) detail: Option<String>,
    pub(super) done: u64,
    pub(super) total: u64,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Pairing {
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
    pub(super) events: broadcast::Sender<Event>,
    pub(super) table: RefCell<DiscoveryTable>,
    directory: RefCell<Directory>,
    advertiser: RefCell<Advertiser>,
    backend: RefCell<Backend>,
    pub(super) sessions: RefCell<BTreeMap<Ed25519PublicKey, mpsc::Sender<SessionCommand>>>,
    pub(super) queues: RefCell<BTreeMap<Ed25519PublicKey, PeerQueue>>,
    pub(super) transfers: RefCell<BTreeMap<TransferId, TransferRecord>>,
    /// The file IDs of each offer received, for "accept all".
    /// Received offers, until they are decided or end.
    pub(super) received: RefCell<BTreeMap<TransferId, OfferInfo>>,
    /// Finished transfers, oldest first.
    finished: RefCell<VecDeque<TransferId>>,
    /// Addresses each contact was last reached at (its own listener's).
    pub(super) last_known: RefCell<BTreeMap<Ed25519PublicKey, Vec<SocketAddr>>>,
    retry: RefCell<BTreeMap<Ed25519PublicKey, (Duration, Duration)>>,
    pairing: Cell<Option<Pairing>>,
    strangers_until: Cell<Duration>,
}

impl State {
    /// Opens the profile, quarantine, listener, and discovery.
    pub(super) fn open(
        config: CoreConfig,
        key_source: &dyn StorageKeySource,
        events: broadcast::Sender<Event>,
    ) -> Result<Rc<Self>, StartError> {
        let now = wall();
        let profile =
            Profile::open(&config.state_dir, key_source, now).map_err(StartError::Profile)?;
        let (identity, contacts) = profile.into_parts();
        let key = key_source
            .storage_key()
            .map_err(|error| StartError::Io(error.kind()))?;
        let sealer = SoftwareSealer::new(StorageKey::from_bytes(Zeroizing::new(*key)));
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
        .map_err(|_| StartError::Io(std::io::ErrorKind::Other))?;
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
        Ok(Rc::new(Self {
            config,
            identity,
            contacts: tokio::sync::Mutex::new(contacts),
            offers,
            manager,
            connector: TcpConnector::new(policy),
            listener,
            sink: SharedSink::new(sink),
            events,
            table: RefCell::new(table),
            directory: RefCell::new(Directory::new()),
            advertiser: RefCell::new(Advertiser::new()),
            backend: RefCell::new(backend),
            sessions: RefCell::new(BTreeMap::new()),
            queues: RefCell::new(BTreeMap::new()),
            transfers: RefCell::new(BTreeMap::new()),
            received: RefCell::new(BTreeMap::new()),
            finished: RefCell::new(VecDeque::new()),
            last_known: RefCell::new(BTreeMap::new()),
            retry: RefCell::new(BTreeMap::new()),
            pairing: Cell::new(None),
            strangers_until: Cell::new(Duration::ZERO),
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
    async fn tick(self: &Rc<Self>) {
        let now = wall();
        let mono = self.mono();
        if self.table.borrow().is_stale(now) {
            self.refresh_table().await;
        }
        {
            let table = self.table.borrow();
            let mut directory = self.directory.borrow_mut();
            directory.set_stranger_browsing(mono < self.strangers_until.get());
            let plan = self
                .advertiser
                .borrow_mut()
                .plan(&table, None, now, mono, &mut OsRandom);
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
        self.retry.borrow_mut().remove(&peer);
        // Its listener's address, for reconnecting without discovery.
        if let Some(remote) = established.link().remote() {
            self.last_known.borrow_mut().insert(peer, vec![remote]);
        }
        session::run(Rc::clone(self), established).await;
        Ok(())
    }

    /// Handles one accepted link.
    async fn incoming(self: &Rc<Self>, link: TcpLink) {
        let Ok(incoming) = self.manager.accept(link).await else {
            return;
        };
        let now = wall();
        match incoming {
            Incoming::Contact(contact) => {
                let table = self.table.borrow().clone();
                let Ok(claimed) = contact.claim(&table, now).await else {
                    return;
                };
                let Ok(local) = self.identity.local(now) else {
                    return;
                };
                let established = {
                    let mut contacts = self.contacts.lock().await;
                    claimed.respond(&table, &mut contacts, &local, now).await
                };
                if let Ok(established) = established {
                    self.refresh_table().await;
                    session::run(Rc::clone(self), established).await;
                }
            }
            Incoming::Pairing(incoming) => self.pairing_responder(incoming).await,
            Incoming::CodeOfferRequest(request) => {
                let Some(token) = self.stranger_token() else {
                    return;
                };
                if self.pairing.get() != Some(Pairing::Code) {
                    return;
                }
                if let Ok(incoming) = request.answer(CODE_GATE, &self.offers, &token, now).await {
                    self.pairing_responder(incoming).await;
                }
            }
        }
    }

    /// The stranger token this device advertises now.
    fn stranger_token(&self) -> Option<[u8; DISCOVERY_TOKEN_LEN]> {
        let table = self.table.borrow();
        let plan =
            self.advertiser
                .borrow_mut()
                .plan(&table, None, wall(), self.mono(), &mut OsRandom);
        plan.stranger
            .map(|advertisement| *advertisement.record.token())
    }

    /// The displayer's side of QR or code pairing.
    async fn pairing_responder(
        self: &Rc<Self>,
        mut incoming: todoke_crypto::session::IncomingSession<TcpLink, TokioTimer>,
    ) {
        let now = wall();
        let mode = incoming.client_hello().mode();
        let Ok(reservation) = incoming.reserve_offer(&self.offers, now) else {
            return;
        };
        let Ok(local) = self.identity.local(now) else {
            return;
        };
        let paired = {
            let mut contacts = self.contacts.lock().await;
            let planned = match mode {
                SessionMode::Qr => reservation.into_qr_responder(&mut contacts),
                SessionMode::Code => reservation.into_code_responder(CODE_GATE, &mut contacts),
                SessionMode::Contact => return,
            };
            let Ok((plan, mut authority)) = planned else {
                return;
            };
            incoming
                .respond(&local, now, plan, &mut authority)
                .await
                .map(|session| *session.peer_binding().device_public())
        };
        if let Ok(peer) = paired {
            self.paired(peer).await;
        }
    }

    /// A pairing committed: stop showing the offer and tell the user.
    async fn paired(&self, peer: Ed25519PublicKey) {
        self.pairing.set(None);
        self.advertiser.borrow_mut().disable_stranger();
        self.refresh_table().await;
        self.emit(Event::Paired {
            contact: hex(peer.as_bytes()),
        });
    }

    /// Handles a request.
    async fn handle(self: &Rc<Self>, request: Request) -> Response {
        match request {
            Request::Status => Response::Status(self.status()),
            Request::Contacts => Response::Contacts(self.contact_list().await),
            Request::Transfers => Response::Transfers(self.transfer_list()),
            Request::Offers => Response::Offers(self.offers_waiting()),
            Request::PairShowQr => self.show_qr(),
            Request::PairShowCode => self.show_code(),
            Request::StopPairing => {
                self.pairing.set(None);
                self.advertiser.borrow_mut().disable_stranger();
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
            Request::Cancel { transfer } => {
                self.to_session(&transfer, SessionCommand::Cancel).await
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
        }
    }

    async fn contact_list(&self) -> Vec<ContactInfo> {
        let contacts = self.contacts.lock().await;
        let mono = self.mono();
        let directory = self.directory.borrow();
        let sessions = self.sessions.borrow();
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
        self.finished.borrow_mut().retain(|old| *old != id);
    }

    /// Moves a transfer to `next`; a received offer leaves the list of
    /// those awaiting a decision. Beyond [`MAX_FINISHED`] finished
    /// transfers, the oldest are forgotten.
    pub(super) fn set_state(&self, id: &TransferId, next: TransferState) {
        if next != TransferState::AwaitingDecision {
            self.received.borrow_mut().remove(id);
        }
        let mut transfers = self.transfers.borrow_mut();
        let Some(record) = transfers.get_mut(id) else {
            return;
        };
        let newly_finished = !record.state.is_finished() && next.is_finished();
        record.state = next;
        if newly_finished {
            let mut finished = self.finished.borrow_mut();
            finished.push_back(*id);
            while finished.len() > MAX_FINISHED {
                if let Some(old) = finished.pop_front() {
                    transfers.remove(&old);
                }
            }
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

    /// Received offers still awaiting a decision.
    fn offers_waiting(&self) -> Vec<OfferInfo> {
        let transfers = self.transfers.borrow();
        self.received
            .borrow()
            .iter()
            .filter(|(id, _)| {
                transfers
                    .get(*id)
                    .is_some_and(|record| record.state == TransferState::AwaitingDecision)
            })
            .map(|(_, offer)| offer.clone())
            .collect()
    }

    fn show_qr(&self) -> Response {
        let now = wall();
        let Ok(local) = self.identity.local(now) else {
            return Response::error(ErrorCode::Internal, "the device binding is not valid");
        };
        let Ok(payload) = self.offers.create_qr(&local, now, self.mono()) else {
            return Response::error(ErrorCode::Pairing, "no pairing offer could be created");
        };
        if !self
            .advertiser
            .borrow_mut()
            .enable_stranger(now, self.mono(), &mut OsRandom)
        {
            return Response::error(ErrorCode::Internal, "OS randomness is unavailable");
        }
        self.pairing.set(Some(Pairing::Qr));
        Response::Qr {
            text: payload.to_text().to_string(),
            expires_at: payload.expires_at().seconds(),
        }
    }

    fn show_code(&self) -> Response {
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

    /// The scanner's side of QR pairing: tries the nearby strangers.
    async fn scan_qr(self: &Rc<Self>, text: &str) -> Response {
        let now = wall();
        let Ok(payload) = QrPayload::from_text(text, now) else {
            return Response::error(ErrorCode::Pairing, "not a valid, unexpired pairing code");
        };
        self.strangers_until.set(self.mono() + STRANGER_BROWSING);
        let targets = self.wait_for_strangers().await;
        for (_, candidates) in targets.into_iter().take(MAX_QR_TARGETS) {
            let Ok(link) = todoke_transport::race::race(
                &self.connector,
                &candidates,
                &todoke_transport::RaceConfig::default(),
            )
            .await
            else {
                continue;
            };
            let Ok(local) = self.identity.local(now) else {
                break;
            };
            let paired = {
                let mut contacts = self.contacts.lock().await;
                let Ok((plan, mut authority)) = contacts.begin_qr_pairing(&payload, now) else {
                    return Response::error(ErrorCode::Pairing, "this offer cannot be used");
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
            };
            if let Ok(peer) = paired {
                self.paired(peer).await;
                return Response::Paired {
                    contact: hex(peer.as_bytes()),
                };
            }
        }
        Response::error(ErrorCode::Pairing, "no nearby device accepted the offer")
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

    /// The strangers seen, waiting a few ticks for answers if none yet.
    async fn wait_for_strangers(
        self: &Rc<Self>,
    ) -> Vec<([u8; DISCOVERY_TOKEN_LEN], Vec<Candidate>)> {
        for _ in 0..20 {
            let found: Vec<_> = self
                .directory
                .borrow()
                .strangers(self.mono())
                .into_iter()
                .map(|(token, reachable)| (token, reachable.candidates()))
                .collect();
            if !found.is_empty() {
                return found;
            }
            self.tick().await;
            tokio::time::sleep(TICK).await;
        }
        Vec::new()
    }

    /// Queues an offer of `paths` to `contact`.
    async fn send(self: &Rc<Self>, contact: &str, paths: &[std::path::PathBuf]) -> Response {
        let peer = match self.resolve_contact(contact).await {
            Ok(peer) => peer,
            Err(response) => return response,
        };
        let walked = match send::walk(paths) {
            Ok(walked) => walked,
            Err(error) => return Response::error(ErrorCode::Source, error.to_string()),
        };
        let Ok(mut queue) = self.take_queue(&peer) else {
            return Response::error(ErrorCode::Internal, "the state directory is unusable");
        };
        let response = match send::prepare(&walked, wall(), &mut queue.source) {
            Ok(prepared) => {
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
                    },
                );
                let session = self.sessions.borrow().get(&peer).cloned();
                match session {
                    Some(session) => {
                        if let Err(mpsc::error::SendError(SessionCommand::Offer(prepared))) =
                            session
                                .send(SessionCommand::Offer(Box::new(prepared)))
                                .await
                        {
                            queue.prepared.push(*prepared);
                        }
                    }
                    None => queue.prepared.push(prepared),
                }
                self.retry.borrow_mut().remove(&peer);
                Response::Offered {
                    transfer: hex(transfer_id),
                }
            }
            Err(error) => Response::error(ErrorCode::Source, error.to_string()),
        };
        self.queues.borrow_mut().insert(peer, queue);
        self.reconnect(self.mono());
        response
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
            (Some(device), None) => Ok(device),
            (Some(_), Some(_)) => Err(Response::error(
                ErrorCode::Ambiguous,
                "more than one contact matches",
            )),
            (None, _) => Err(Response::error(ErrorCode::Invalid, "no such contact")),
        }
    }

    /// Routes a decision to the session carrying `transfer`.
    async fn to_session(
        &self,
        transfer: &str,
        command: impl FnOnce(TransferId) -> SessionCommand,
    ) -> Response {
        let prefix = transfer.to_ascii_lowercase();
        if prefix.len() < MIN_PREFIX {
            return Response::error(
                ErrorCode::Invalid,
                "name a transfer by at least 8 hex digits",
            );
        }
        let found: Vec<(TransferId, Ed25519PublicKey)> = self
            .transfers
            .borrow()
            .iter()
            .filter(|(id, _)| hex(id).starts_with(&prefix))
            .map(|(id, record)| (*id, record.peer))
            .collect();
        let [(id, peer)] = found.as_slice() else {
            return if found.is_empty() {
                Response::error(ErrorCode::Invalid, "no such transfer")
            } else {
                Response::error(ErrorCode::Ambiguous, "more than one transfer matches")
            };
        };
        let session = self.sessions.borrow().get(peer).cloned();
        let Some(session) = session else {
            return Response::error(ErrorCode::Unreachable, "the peer is not connected");
        };
        let (reply, answer) = oneshot::channel();
        if session
            .send(SessionCommand::with_reply(command(*id), reply))
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
        let accept = async {
            match &state.listener {
                Some(listener) => listener.accept().await,
                None => core::future::pending().await,
            }
        };
        tokio::select! {
            _ = &mut stop => break,
            envelope = requests.recv() => {
                let Some((request, reply)) = envelope else { break };
                let state = Rc::clone(&state);
                tokio::task::spawn_local(async move {
                    let _ = reply.send(state.handle(request).await);
                });
            }
            accepted = accept => {
                if let Ok(link) = accepted {
                    let state = Rc::clone(&state);
                    tokio::task::spawn_local(async move { state.incoming(link).await });
                }
            }
            _ = tick.tick() => state.tick().await,
        }
    }
}
