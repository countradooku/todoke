//! Moving a session onto a direct Wi-Fi link (PROTOCOL §10.2).
//!
//! In a session that may take part (a platform that can, the configured
//! policy, not already on a direct link, and no recent failed attempt with
//! this contact), this device sends its abilities once the session is
//! ready. The engine checks and reports the choice. Link setup waits for a
//! transfer with the contact that this device's user started or accepted
//! and that the receiver has accepted (pending or running): before that
//! there is nothing to move, and the joiner would have to decline. The
//! chosen host brings the link up (off the core thread; one hosted link
//! at a time), listens on its address on the link only, and offers fresh
//! credentials. The joiner answers `joining` before it joins (one radio
//! cannot keep the session's network and join another), or declines.
//!
//! Then both close the session: the joiner joins, connects to the host's
//! address on the link from its own, and the host accepts that one
//! connection from that contact before the offer expires. The session runs
//! again there with a full handshake. Transfers resume (§7.5); the
//! receiver's fresh Accept repeats the consent its user gave before the
//! move, for the same contact, manifest, and selection, without asking
//! again. Each side tears the link down (off the core thread) when that
//! session ends, when the offer expires, or when the move fails; a failed
//! or refused attempt is not repeated with that contact for a while, and
//! the devices reconnect however they can.

use core::time::Duration;
use std::net::{IpAddr, SocketAddr, SocketAddrV6};
use std::rc::Rc;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use todoke_crypto::identity::Ed25519PublicKey;
use todoke_proto::link::{
    LinkChoice, LinkOffer, LinkResult, LinkRole, MAX_OFFER_SECONDS, OFFER_ID_LEN,
};
use todoke_transfer::{TransferEvent, TransferId};
use todoke_transport::{LanListener, LinkKind};
use tokio::task::JoinHandle;
use zeroize::Zeroizing;

use super::running::{Origin, State};
use crate::api::{TransferState, Way};
use crate::link::{DirectLinks, HostRequest, JoinRequest, LinkLease, LinkPlatform, credentials};

/// How long an offer stands (§10.2: 10..120 seconds).
#[cfg(not(test))]
const OFFER_SECONDS: u8 = 60;
#[cfg(test)]
const OFFER_SECONDS: u8 = 10;
/// How long consent is kept across a move: the offer's life, a handshake,
/// and the new session's offers. Never extended.
const RETAIN: Duration = Duration::from_secs(MAX_OFFER_SECONDS as u64 + 60);
/// After a link setup with a contact failed, was refused, or expired: no
/// other attempt with it for this long.
const BACKOFF: Duration = Duration::from_mins(30);
/// Between connection attempts to the host over a new link (its address
/// may take a moment to answer).
const RETRY: Duration = Duration::from_millis(500);

type Engine<'k> = super::session::Engine<'k>;

/// A link lease whose teardown (which may block on the operating system)
/// runs off the core thread.
pub(super) struct Held(Option<LinkLease>);

impl Drop for Held {
    fn drop(&mut self) {
        if let Some(lease) = self.0.take() {
            match tokio::runtime::Handle::try_current() {
                Ok(runtime) => drop(runtime.spawn_blocking(move || drop(lease))),
                Err(_) => drop(lease),
            }
        }
    }
}

/// Sets its flag when dropped: the platform stops what it is doing.
struct Cancel(Arc<AtomicBool>);

impl Drop for Cancel {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}

/// The device's one hosted link (§13: one at a time), released when
/// dropped.
pub(super) struct HostSlot(Rc<State>);

impl HostSlot {
    fn take(state: &Rc<State>) -> Option<Self> {
        (!state.hosting.replace(true)).then(|| Self(Rc::clone(state)))
    }
}

impl Drop for HostSlot {
    fn drop(&mut self) {
        self.0.hosting.set(false);
    }
}

/// How a session leaves for a direct link.
pub(super) enum Move {
    /// Join the offer, then connect from the link to the host on `port`.
    Join {
        platform: Arc<dyn LinkPlatform>,
        request: JoinRequest,
        port: u16,
        until: Duration,
    },
    /// Accept one connection from the contact on `listener`.
    Host {
        lease: Held,
        listener: LanListener,
        until: Duration,
        slot: HostSlot,
    },
}

enum Hosting {
    Idle,
    /// Chosen to host; waiting for a transfer that qualifies.
    Chosen(LinkChoice),
    /// The platform is bringing the link up.
    Starting {
        task: JoinHandle<std::io::Result<LinkLease>>,
        choice: LinkChoice,
        offer_id: [u8; OFFER_ID_LEN],
        ssid: String,
        secret: Zeroizing<Vec<u8>>,
        cancel: Cancel,
        slot: HostSlot,
    },
    /// Offered; the answer is awaited until `until`.
    Offered {
        lease: Held,
        listener: LanListener,
        until: Duration,
        slot: HostSlot,
    },
    Done,
}

/// One session's part in link setup.
pub(super) struct SessionLink {
    state: Rc<State>,
    peer: Ed25519PublicKey,
    platform: Option<Arc<dyn LinkPlatform>>,
    hosting: Hosting,
    answered: bool,
    /// Set once the session should end and move.
    leaving: Option<Move>,
}

impl SessionLink {
    /// For a session over `kind` with `peer`: whether it may take part.
    pub(super) fn new(state: &Rc<State>, peer: Ed25519PublicKey, kind: LinkKind) -> Self {
        let allowed = match state.config.direct_links {
            DirectLinks::Off => false,
            DirectLinks::FromRelay => kind == LinkKind::Relay,
            DirectLinks::Always => kind != LinkKind::Direct,
        } && !state.backing_off(&peer);
        Self {
            state: Rc::clone(state),
            peer,
            platform: state.links.get().filter(|_| allowed).cloned(),
            hosting: Hosting::Idle,
            answered: false,
            leaving: None,
        }
    }

    /// The session is ready: send this device's abilities, if it has any.
    pub(super) fn ready(&self, engine: &mut Engine<'_>) {
        if let Some(platform) = &self.platform {
            let abilities = platform.abilities();
            if abilities != crate::link::LinkAbilities::new(&[], &[], &[]) {
                let _ = engine.send_link_abilities(abilities);
            }
        }
    }

    /// Takes the link events from the engine; returns the others.
    pub(super) fn event(
        &mut self,
        engine: &mut Engine<'_>,
        event: TransferEvent,
        now: Duration,
    ) -> Option<TransferEvent> {
        match event {
            TransferEvent::LinkChosen(choice) => {
                if choice.role == LinkRole::Host {
                    self.hosting = Hosting::Chosen(choice);
                }
                None
            }
            TransferEvent::LinkOffered(offer) => {
                self.join(engine, &offer, now);
                None
            }
            TransferEvent::LinkAnswered(answer) => {
                let hosting = core::mem::replace(&mut self.hosting, Hosting::Done);
                match hosting {
                    Hosting::Offered {
                        lease,
                        listener,
                        until,
                        slot,
                    } if answer.result == LinkResult::Joining => {
                        self.leave(
                            Move::Host {
                                lease,
                                listener,
                                until,
                                slot,
                            },
                            until,
                        );
                    }
                    // Declined or failed: the link goes, and no other
                    // attempt with this contact for a while.
                    _ => self.state.back_off(self.peer),
                }
                None
            }
            other => Some(other),
        }
    }

    /// The joiner's side: only for a transfer that qualifies, answered
    /// before joining (the join happens once the session is closed).
    fn join(&mut self, engine: &mut Engine<'_>, offer: &LinkOffer, now: Duration) {
        let id = *offer.offer_id();
        let platform = match &self.platform {
            Some(platform) if !self.answered && qualifies(&self.state, &self.peer) => {
                Arc::clone(platform)
            }
            _ => {
                let _ = engine.answer_link(&id, LinkResult::Declined);
                self.answered = true;
                self.state.back_off(self.peer);
                return;
            }
        };
        self.answered = true;
        let within = Duration::from_secs(offer.expires_in().into());
        let mut service_info = [0; 8];
        service_info.copy_from_slice(&id[..8]);
        let request = JoinRequest {
            kind: offer.kind(),
            security: offer.security(),
            ssid: String::from_utf8_lossy(offer.ssid()).into_owned(),
            secret: Zeroizing::new(offer.secret().to_vec()),
            service_info,
            within,
            cancel: Arc::default(),
        };
        if engine.answer_link(&id, LinkResult::Joining).is_ok() {
            let until = now + within;
            self.leave(
                Move::Join {
                    platform,
                    request,
                    port: offer.port(),
                    until,
                },
                until,
            );
        }
    }

    /// The move, if an event set one up (when the session ended anyway).
    pub(super) const fn take_leaving(&mut self) -> Option<Move> {
        self.leaving.take()
    }

    /// Advances hosting; returns the move once the session should end for
    /// it.
    pub(super) async fn step(&mut self, engine: &mut Engine<'_>, now: Duration) -> Option<Move> {
        if let Some(leaving) = self.leaving.take() {
            return Some(leaving);
        }
        match &mut self.hosting {
            Hosting::Chosen(choice) if qualifies(&self.state, &self.peer) => {
                let choice = *choice;
                self.start_hosting(choice);
            }
            Hosting::Starting { task, .. } if task.is_finished() => {
                self.offer(engine, now).await;
            }
            Hosting::Offered { until, .. } if now >= *until => {
                // Unanswered in time: the link goes.
                self.hosting = Hosting::Done;
                self.state.back_off(self.peer);
            }
            _ => {}
        }
        None
    }

    fn start_hosting(&mut self, choice: LinkChoice) {
        let Some(platform) = self.platform.clone() else {
            self.hosting = Hosting::Done;
            return;
        };
        // Another link is hosted now: wait for it to go.
        let Some(slot) = HostSlot::take(&self.state) else {
            return;
        };
        let (Ok((ssid, secret)), Some(offer_id)) = (credentials(choice.kind), offer_id()) else {
            self.hosting = Hosting::Done;
            return;
        };
        let mut service_info = [0; 8];
        service_info.copy_from_slice(&offer_id[..8]);
        let cancel = Arc::new(AtomicBool::new(false));
        let request = HostRequest {
            kind: choice.kind,
            security: choice.security,
            ssid: ssid.clone(),
            secret: secret.clone(),
            service_info,
            cancel: Arc::clone(&cancel),
        };
        let task = tokio::task::spawn_blocking(move || platform.host(&request));
        self.hosting = Hosting::Starting {
            task,
            choice,
            offer_id,
            ssid,
            secret,
            cancel: Cancel(cancel),
            slot,
        };
    }

    /// The link is up (or not): listen on it and offer it.
    async fn offer(&mut self, engine: &mut Engine<'_>, now: Duration) {
        let Hosting::Starting {
            task,
            choice,
            offer_id,
            ssid,
            secret,
            cancel,
            slot,
        } = core::mem::replace(&mut self.hosting, Hosting::Done)
        else {
            return;
        };
        let Ok(Ok(lease)) = task.await else {
            self.state.back_off(self.peer);
            return;
        };
        let lease = Held(Some(lease));
        drop(cancel);
        let Some(local) = lease
            .0
            .as_ref()
            .map(|lease| scoped(lease.local, 0, lease.interface))
            .filter(|local| usable(&self.state, local.ip()))
        else {
            return;
        };
        let Ok(listener) = LanListener::bind_direct(local, self.state.lan_policy()) else {
            return;
        };
        let Ok(port) = listener.port() else {
            return;
        };
        let offer = LinkOffer::new(
            offer_id,
            choice.kind,
            choice.security,
            OFFER_SECONDS,
            port,
            ssid.into_bytes(),
            secret,
        );
        if let Ok(offer) = offer
            && engine.offer_link(&offer).is_ok()
        {
            self.hosting = Hosting::Offered {
                lease,
                listener,
                until: now + Duration::from_secs(OFFER_SECONDS.into()),
                slot,
            };
        }
    }

    /// The session ends at its next turn (after the answer is sent) and
    /// moves: nothing else connects to the contact until `until`, and the
    /// consent given for its incoming transfers is kept for the new
    /// session (once: never extended).
    fn leave(&mut self, to: Move, until: Duration) {
        let state = &self.state;
        state.moving.borrow_mut().insert(self.peer, until);
        let keep = until + RETAIN;
        let mut retained = state.retained.borrow_mut();
        for (id, record) in state.transfers.borrow().iter() {
            if record.peer == self.peer
                && record.way == Way::Incoming
                && matches!(
                    record.state,
                    TransferState::Accepted | TransferState::Transferring
                )
                && let (Some(selection), Some(manifest_hash)) =
                    (&record.selection, record.manifest_hash)
            {
                retained.entry(*id).or_insert_with(|| Retained {
                    peer: self.peer,
                    manifest_hash,
                    selection: selection.clone(),
                    until: keep,
                });
            }
        }
        self.leaving = Some(to);
    }
}

/// Consent kept across a move for one incoming transfer.
pub(super) struct Retained {
    peer: Ed25519PublicKey,
    manifest_hash: [u8; 32],
    selection: Vec<u32>,
    until: Duration,
}

/// Whether a transfer with `peer` that this device's user started or
/// accepted has been accepted by its receiver and is pending or running
/// (§10.2): the only time there is something to move, so both sides agree.
fn qualifies(state: &State, peer: &Ed25519PublicKey) -> bool {
    state.transfers.borrow().values().any(|record| {
        record.peer == *peer
            && matches!(
                record.state,
                TransferState::Accepted | TransferState::Transferring
            )
            && (record.way == Way::Outgoing || record.selection.is_some())
    })
}

/// Whether `ip` may be a link address: a unicast address the LAN policy
/// accepts (never an unspecified one, which would listen everywhere).
fn usable(state: &State, ip: IpAddr) -> bool {
    !ip.is_unspecified()
        && !ip.is_multicast()
        && state
            .lan_policy()
            .check_peer(SocketAddr::new(ip, 49_152))
            .is_ok()
}

/// A fresh offer ID (never all zero).
fn offer_id() -> Option<[u8; OFFER_ID_LEN]> {
    let mut id = [0; OFFER_ID_LEN];
    getrandom::fill(&mut id).ok()?;
    (id != [0; OFFER_ID_LEN]).then_some(id)
}

/// `ip` on `port`, a link-local IPv6 address scoped to `interface`.
fn scoped(ip: IpAddr, port: u16, interface: u32) -> SocketAddr {
    match ip {
        IpAddr::V6(v6) if v6.is_unicast_link_local() => {
            SocketAddr::V6(SocketAddrV6::new(v6, port, 0, interface))
        }
        ip => SocketAddr::new(ip, port),
    }
}

impl State {
    /// The selection whose consent was kept for `id` across a move with
    /// `peer`, for the manifest `manifest_hash`, if it still holds; used
    /// once.
    pub(super) fn take_retained(
        &self,
        id: &TransferId,
        peer: &Ed25519PublicKey,
        manifest_hash: &[u8; 32],
    ) -> Option<Vec<u32>> {
        let now = self.mono();
        let kept = self.retained.borrow_mut().remove(id)?;
        (kept.peer == *peer && kept.manifest_hash == *manifest_hash && now < kept.until)
            .then_some(kept.selection)
    }

    /// Forgets the consent kept for `id` (the user cancelled it).
    pub(super) fn forget_retained(&self, id: &TransferId) {
        self.retained.borrow_mut().remove(id);
    }

    /// Whether `peer`'s session is moving onto a direct link now.
    pub(super) fn is_moving(&self, peer: &Ed25519PublicKey) -> bool {
        let now = self.mono();
        self.moving
            .borrow()
            .get(peer)
            .is_some_and(|until| now < *until)
    }

    /// Whether link setup with `peer` is paused after a failed attempt.
    fn backing_off(&self, peer: &Ed25519PublicKey) -> bool {
        let now = self.mono();
        self.link_backoff
            .borrow()
            .get(peer)
            .is_some_and(|until| now < *until)
    }

    /// No link setup with `peer` for a while.
    fn back_off(&self, peer: Ed25519PublicKey) {
        let until = self.mono() + BACKOFF;
        self.link_backoff.borrow_mut().insert(peer, until);
    }

    /// Drops what expired: kept consent, moves, and pauses.
    pub(super) fn prune_links(&self) {
        let now = self.mono();
        self.retained
            .borrow_mut()
            .retain(|_, kept| now < kept.until);
        self.moving.borrow_mut().retain(|_, until| now < *until);
        self.link_backoff
            .borrow_mut()
            .retain(|_, until| now < *until);
    }

    /// Runs the session again over the direct link (after the old one
    /// ended), then tears the link down. A move that fails leaves the
    /// devices to reconnect however they can, and pauses link setup with
    /// the contact.
    pub(super) async fn move_to(self: Rc<Self>, peer: Ed25519PublicKey, to: Move) {
        let moved = match to {
            Move::Join {
                platform,
                request,
                port,
                until,
            } => {
                self.join_and_connect(peer, platform, request, port, until)
                    .await
            }
            Move::Host {
                lease,
                listener,
                until,
                slot,
            } => {
                let wait = until.saturating_sub(self.mono());
                // One connection, from this contact, before the offer
                // expires; the move lasts until its session ends.
                let moved = match tokio::time::timeout(wait, listener.accept()).await {
                    Ok(Ok(link)) => {
                        drop(listener);
                        self.incoming(link, Origin::Direct(peer)).await
                    }
                    _ => false,
                };
                drop(lease);
                drop(slot);
                moved
            }
        };
        self.moving.borrow_mut().remove(&peer);
        if !moved {
            self.back_off(peer);
        }
    }

    /// The joiner's move: join (off the core thread), connect over the
    /// link, run the session; whether a session ran there.
    async fn join_and_connect(
        self: &Rc<Self>,
        peer: Ed25519PublicKey,
        platform: Arc<dyn LinkPlatform>,
        request: JoinRequest,
        port: u16,
        until: Duration,
    ) -> bool {
        let cancel = Cancel(Arc::clone(&request.cancel));
        let joined = tokio::task::spawn_blocking(move || platform.join(&request)).await;
        let Ok(Ok(lease)) = joined else {
            return false;
        };
        let lease = Held(Some(lease));
        let Some((local, host)) = lease.0.as_ref().and_then(|lease| {
            let host = lease.host?;
            usable(self, lease.local).then(|| (lease.local, scoped(host, port, lease.interface)))
        }) else {
            return false;
        };
        let moved = loop {
            match self.connector().connect_direct(local, host).await {
                Ok(link) => {
                    let Ok(claim) = self.manager.claim_outgoing(peer) else {
                        break false;
                    };
                    break self.initiate_on(peer, claim.with_link(link)).await.is_ok();
                }
                Err(_) if self.mono() + RETRY < until => tokio::time::sleep(RETRY).await,
                Err(_) => break false,
            }
        };
        drop(cancel);
        drop(lease);
        moved
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::runtime::running::TransferRecord;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// A state on loopback (no LAN listener, no discovery); nothing is sent.
    fn state(scratch: &std::path::Path) -> Result<Rc<State>, Box<dyn std::error::Error>> {
        let mut config =
            crate::config::CoreConfig::new(scratch.join("state"), scratch.join("downloads"));
        config.lan.enabled = false;
        config.lan.allow_loopback = true;
        let key = crate::storage_key::KeyFile::new(scratch.join("storage.key"));
        let (events, _) = tokio::sync::broadcast::channel(4);
        Ok(State::open(config, &key, events)?)
    }

    /// The Ed25519 base point: a valid public key for a contact.
    fn contact() -> Result<Ed25519PublicKey, Box<dyn std::error::Error>> {
        let mut bytes = [0x66; 32];
        bytes[0] = 0x58;
        Ok(Ed25519PublicKey::from_bytes(&bytes)?)
    }

    /// Another valid key: this device's own.
    fn other(state: &State) -> Ed25519PublicKey {
        *state.identity.binding().device_public()
    }

    fn record(
        peer: Ed25519PublicKey,
        way: Way,
        state: TransferState,
        selection: Option<Vec<u32>>,
    ) -> TransferRecord {
        TransferRecord {
            peer,
            way,
            state,
            detail: None,
            done: 0,
            total: 1,
            files: 1,
            names: Vec::new(),
            manifest_hash: Some([7; 32]),
            receipt: None,
            selection,
        }
    }

    /// Kept consent is used once, only for the same contact and manifest,
    /// and only until it expires.
    #[tokio::test(flavor = "current_thread")]
    async fn kept_consent_is_bound_and_used_once() -> TestResult {
        let scratch = crate::profile::tests::Scratch::new("retained")?;
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async move {
                let state = state(&scratch.0)?;
                let (alice, mallory) = (contact()?, other(&state));
                let keep = |id: u8, until: Duration| {
                    state.retained.borrow_mut().insert(
                        [id; 16],
                        Retained {
                            peer: alice,
                            manifest_hash: [7; 32],
                            selection: vec![1, 3],
                            until,
                        },
                    );
                };
                let later = state.mono() + Duration::from_secs(60);
                keep(1, later);
                assert_eq!(state.take_retained(&[1; 16], &mallory, &[7; 32]), None);
                keep(1, later);
                assert_eq!(state.take_retained(&[1; 16], &alice, &[8; 32]), None);
                keep(1, later);
                assert_eq!(
                    state.take_retained(&[1; 16], &alice, &[7; 32]),
                    Some(vec![1, 3])
                );
                assert_eq!(state.take_retained(&[1; 16], &alice, &[7; 32]), None);
                keep(2, state.mono());
                assert_eq!(state.take_retained(&[2; 16], &alice, &[7; 32]), None);
                // Cancelling drops it.
                keep(3, later);
                state.forget_retained(&[3; 16]);
                assert_eq!(state.take_retained(&[3; 16], &alice, &[7; 32]), None);
                Ok(())
            })
            .await
    }

    /// Link setup waits for the receiver's decision: an incoming transfer
    /// still awaiting it, or an outgoing one not yet accepted, does not
    /// qualify; accepted ones (with this user's selection) do.
    #[tokio::test(flavor = "current_thread")]
    async fn only_accepted_transfers_qualify() -> TestResult {
        let scratch = crate::profile::tests::Scratch::new("qualifies")?;
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async move {
                let state = state(&scratch.0)?;
                let peer = contact()?;
                let cases = [
                    (Way::Incoming, TransferState::AwaitingDecision, None, false),
                    (Way::Outgoing, TransferState::Offered, None, false),
                    (Way::Incoming, TransferState::Accepted, None, false),
                    (Way::Incoming, TransferState::Accepted, Some(vec![1]), true),
                    (
                        Way::Incoming,
                        TransferState::Transferring,
                        Some(vec![1]),
                        true,
                    ),
                    (Way::Outgoing, TransferState::Accepted, None, true),
                    (Way::Outgoing, TransferState::Received, None, false),
                ];
                for (way, transfer_state, selection, expected) in cases {
                    state.transfers.borrow_mut().clear();
                    state.remember(
                        [1; 16],
                        record(peer, way, transfer_state, selection.clone()),
                    );
                    assert_eq!(
                        qualifies(&state, &peer),
                        expected,
                        "{way:?} {transfer_state:?} {selection:?}"
                    );
                    assert!(!qualifies(&state, &other(&state)), "another contact's");
                }
                // Never an unspecified address, which would listen
                // everywhere.
                assert!(!usable(&state, IpAddr::from([0, 0, 0, 0])));
                assert!(!usable(&state, IpAddr::from([224, 0, 0, 1])));
                assert!(usable(&state, IpAddr::from([192, 168, 49, 1])));
                Ok(())
            })
            .await
    }

    /// The host accepts one connection for the offer: a stranger who
    /// connects first takes it (and fails the handshake), the listener
    /// closes, the move fails, and link setup with the contact pauses.
    #[tokio::test(flavor = "current_thread")]
    async fn the_host_accepts_one_connection() -> TestResult {
        let scratch = crate::profile::tests::Scratch::new("one-accept")?;
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async move {
                let state = state(&scratch.0)?;
                let peer = contact()?;
                let listener = LanListener::bind_direct(
                    SocketAddr::from(([127, 0, 0, 1], 0)),
                    state.lan_policy(),
                )?;
                let port = listener.port()?;
                let slot = HostSlot::take(&state).ok_or("no slot")?;
                assert!(HostSlot::take(&state).is_none(), "one hosted link");
                let until = state.mono() + Duration::from_secs(5);
                state.moving.borrow_mut().insert(peer, until);
                let lease = Held(Some(LinkLease::new(
                    IpAddr::from([127, 0, 0, 1]),
                    None,
                    0,
                    (),
                )));
                let moving = tokio::task::spawn_local(Rc::clone(&state).move_to(
                    peer,
                    Move::Host {
                        lease,
                        listener,
                        until,
                        slot,
                    },
                ));
                // A stranger connects first and says nothing useful.
                let mut stranger = tokio::net::TcpStream::connect(("127.0.0.1", port)).await?;
                tokio::io::AsyncWriteExt::write_all(&mut stranger, &[0; 64]).await?;
                drop(stranger);
                tokio::time::timeout(Duration::from_secs(30), moving).await??;
                assert!(state.backing_off(&peer));
                assert!(!state.is_moving(&peer));
                assert!(!state.hosting.get(), "the slot is released");
                assert!(
                    tokio::net::TcpStream::connect(("127.0.0.1", port))
                        .await
                        .is_err(),
                    "the listener is closed"
                );
                Ok(())
            })
            .await
    }
}
