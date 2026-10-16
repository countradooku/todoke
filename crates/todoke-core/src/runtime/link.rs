//! Moving a session onto a direct Wi-Fi link (PROTOCOL §10.2).
//!
//! In a session that may take part (a platform that can, the configured
//! policy, and not already on a direct link), this device sends its
//! abilities once the session is ready. The engine checks and reports the
//! choice. The chosen host brings the link up (off the core thread) only
//! while a transfer this device's user started or accepted with the peer
//! is pending or running, listens on its address on the link only, and
//! offers fresh credentials. The joiner joins only for such a transfer too
//! (otherwise it declines) and answers. After `joined` both close the
//! session: the joiner connects to the host's address on the link from
//! its own, the host accepts that one connection from that contact before
//! the offer expires, and the session runs again there with a full
//! handshake. Transfers resume (§7.5); the receiver's fresh Accept repeats
//! the consent its user gave before the move without asking again. Each
//! side tears the link down when that session ends, when the offer
//! expires, or when the move fails, and the devices then reconnect however
//! they can.

use core::time::Duration;
use std::net::{IpAddr, SocketAddr, SocketAddrV6};
use std::rc::Rc;
use std::sync::Arc;

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
const OFFER_SECONDS: u8 = 60;
/// How long consent is kept across a move: the offer's life, a handshake,
/// and the new session's offers.
const RETAIN: Duration = Duration::from_secs(MAX_OFFER_SECONDS as u64 + 60);
/// Between connection attempts to the host over a new link (its address
/// may take a moment to answer).
const RETRY: Duration = Duration::from_millis(500);

type Engine<'k> = super::session::Engine<'k>;

/// How a session leaves for a direct link.
pub(super) enum Move {
    /// Connect from the lease's address to the host's, on `port`.
    Join {
        lease: LinkLease,
        port: u16,
        until: Duration,
    },
    /// Accept one connection from the contact on `listener`.
    Host {
        lease: LinkLease,
        listener: LanListener,
        until: Duration,
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
    },
    /// Offered; the answer is awaited until `until`.
    Offered {
        lease: LinkLease,
        listener: LanListener,
        until: Duration,
    },
    Done,
}

enum Joining {
    Idle,
    /// The platform is joining the offer.
    Starting {
        task: JoinHandle<std::io::Result<LinkLease>>,
        offer_id: [u8; OFFER_ID_LEN],
        port: u16,
        until: Duration,
    },
    Done,
}

/// One session's part in link setup.
pub(super) struct SessionLink {
    platform: Option<Arc<dyn LinkPlatform>>,
    hosting: Hosting,
    joining: Joining,
    /// Set once the session should end and move.
    leaving: Option<Move>,
}

impl SessionLink {
    /// For a session over `kind` with `peer`: whether it may take part.
    pub(super) fn new(state: &State, kind: LinkKind) -> Self {
        let allowed = match state.config.direct_links {
            DirectLinks::Off => false,
            DirectLinks::FromRelay => kind == LinkKind::Relay,
            DirectLinks::Always => kind != LinkKind::Direct,
        };
        Self {
            platform: state.links.get().filter(|_| allowed).cloned(),
            hosting: Hosting::Idle,
            joining: Joining::Idle,
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
        state: &State,
        peer: Ed25519PublicKey,
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
                self.join(state, peer, engine, &offer, now);
                None
            }
            TransferEvent::LinkAnswered(answer) => {
                let hosting = core::mem::replace(&mut self.hosting, Hosting::Done);
                if answer.result == LinkResult::Joined
                    && let Hosting::Offered {
                        lease,
                        listener,
                        until,
                    } = hosting
                {
                    self.leave(
                        state,
                        peer,
                        Move::Host {
                            lease,
                            listener,
                            until,
                        },
                        until,
                    );
                }
                // Declined or failed: the lease drops, the link goes.
                None
            }
            other => Some(other),
        }
    }

    /// The joiner's side: join only for a transfer this user started or
    /// accepted with the peer, else decline.
    fn join(
        &mut self,
        state: &State,
        peer: Ed25519PublicKey,
        engine: &mut Engine<'_>,
        offer: &LinkOffer,
        now: Duration,
    ) {
        let id = *offer.offer_id();
        let platform = match (&self.platform, &self.joining) {
            (Some(platform), Joining::Idle) if qualifies(state, &peer) => Arc::clone(platform),
            _ => {
                let _ = engine.answer_link(&id, LinkResult::Declined);
                self.joining = Joining::Done;
                return;
            }
        };
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
        };
        let task = tokio::task::spawn_blocking(move || platform.join(&request));
        self.joining = Joining::Starting {
            task,
            offer_id: id,
            port: offer.port(),
            until: now + within,
        };
    }

    /// Advances hosting and joining; returns the move once the session
    /// should end for it.
    pub(super) async fn step(
        &mut self,
        state: &State,
        peer: Ed25519PublicKey,
        engine: &mut Engine<'_>,
        now: Duration,
    ) -> Option<Move> {
        if let Some(leaving) = self.leaving.take() {
            return Some(leaving);
        }
        self.step_hosting(state, peer, engine, now).await;
        self.step_joining(state, peer, engine, now).await;
        None
    }

    async fn step_hosting(
        &mut self,
        state: &State,
        peer: Ed25519PublicKey,
        engine: &mut Engine<'_>,
        now: Duration,
    ) {
        match &mut self.hosting {
            Hosting::Chosen(choice) if qualifies(state, &peer) => {
                let choice = *choice;
                let Some(platform) = self.platform.clone() else {
                    self.hosting = Hosting::Done;
                    return;
                };
                let (Ok((ssid, secret)), Some(offer_id)) = (credentials(choice.kind), offer_id())
                else {
                    self.hosting = Hosting::Done;
                    return;
                };
                let mut service_info = [0; 8];
                service_info.copy_from_slice(&offer_id[..8]);
                let request = HostRequest {
                    kind: choice.kind,
                    security: choice.security,
                    ssid: ssid.clone(),
                    secret: secret.clone(),
                    service_info,
                };
                let task = tokio::task::spawn_blocking(move || platform.host(&request));
                self.hosting = Hosting::Starting {
                    task,
                    choice,
                    offer_id,
                    ssid,
                    secret,
                };
            }
            Hosting::Starting { task, .. } if task.is_finished() => {
                let Hosting::Starting {
                    task,
                    choice,
                    offer_id,
                    ssid,
                    secret,
                } = core::mem::replace(&mut self.hosting, Hosting::Done)
                else {
                    return;
                };
                let Ok(Ok(lease)) = task.await else {
                    return;
                };
                let at = scoped(lease.local, 0, lease.interface);
                let Ok(listener) = LanListener::bind_direct(at, state.lan_policy()) else {
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
                    };
                }
            }
            Hosting::Offered { until, .. } if now >= *until => {
                // Unanswered in time: the link goes.
                self.hosting = Hosting::Done;
            }
            _ => {}
        }
    }

    async fn step_joining(
        &mut self,
        state: &State,
        peer: Ed25519PublicKey,
        engine: &mut Engine<'_>,
        now: Duration,
    ) {
        let Joining::Starting { task, .. } = &self.joining else {
            return;
        };
        if !task.is_finished() {
            return;
        }
        let Joining::Starting {
            task,
            offer_id,
            port,
            until,
        } = core::mem::replace(&mut self.joining, Joining::Done)
        else {
            return;
        };
        match task.await {
            Ok(Ok(lease)) if now < until && lease.host.is_some() => {
                if engine.answer_link(&offer_id, LinkResult::Joined).is_ok() {
                    self.leave(state, peer, Move::Join { lease, port, until }, until);
                }
            }
            _ => {
                let _ = engine.answer_link(&offer_id, LinkResult::Failed);
            }
        }
    }

    /// The session ends at its next turn (after the answer is sent) and
    /// moves: nothing else connects to `peer` until `until`, and the
    /// consent given for its incoming transfers is kept for the new
    /// session.
    fn leave(&mut self, state: &State, peer: Ed25519PublicKey, to: Move, until: Duration) {
        state.moving.borrow_mut().insert(peer, until);
        let keep = until + RETAIN;
        let mut retained = state.retained.borrow_mut();
        for (id, record) in state.transfers.borrow().iter() {
            if record.peer == peer
                && record.way == Way::Incoming
                && matches!(
                    record.state,
                    TransferState::Accepted | TransferState::Transferring
                )
                && let Some(selection) = &record.selection
            {
                retained.insert(*id, (selection.clone(), keep));
            }
        }
        self.leaving = Some(to);
    }
}

/// Whether a transfer this device's user started or accepted with `peer`
/// is pending or running (§10.2).
fn qualifies(state: &State, peer: &Ed25519PublicKey) -> bool {
    state.transfers.borrow().values().any(|record| {
        record.peer == *peer
            && match record.way {
                Way::Outgoing => matches!(
                    record.state,
                    TransferState::Offered | TransferState::Accepted | TransferState::Transferring
                ),
                Way::Incoming => matches!(
                    record.state,
                    TransferState::Accepted | TransferState::Transferring
                ),
            }
    })
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
    /// The selection whose consent was kept for `id` across a move, if it
    /// still holds; it is used once.
    pub(super) fn take_retained(&self, id: &TransferId) -> Option<Vec<u32>> {
        let now = self.mono();
        self.retained
            .borrow_mut()
            .remove(id)
            .and_then(|(selection, until)| (now < until).then_some(selection))
    }

    /// Whether `peer`'s session is moving onto a direct link now.
    pub(super) fn is_moving(&self, peer: &Ed25519PublicKey) -> bool {
        let now = self.mono();
        let mut moving = self.moving.borrow_mut();
        moving.retain(|_, until| now < *until);
        moving.contains_key(peer)
    }

    /// Runs the session again over the direct link (after the old one
    /// ended), then tears the link down. A move that fails leaves the
    /// devices to reconnect however they can.
    pub(super) async fn move_to(self: Rc<Self>, peer: Ed25519PublicKey, to: Move) {
        match to {
            Move::Join { lease, port, until } => {
                if let Some(host) = lease.host {
                    let host = scoped(host, port, lease.interface);
                    loop {
                        let attempt = self.connector().connect_direct(lease.local, host).await;
                        match attempt {
                            Ok(link) => {
                                if let Ok(claim) = self.manager.claim_outgoing(peer) {
                                    let _ = self.initiate_on(peer, claim.with_link(link)).await;
                                }
                                break;
                            }
                            Err(_) if self.mono() + RETRY < until => {
                                tokio::time::sleep(RETRY).await;
                            }
                            Err(_) => break,
                        }
                    }
                }
                drop(lease);
            }
            Move::Host {
                lease,
                listener,
                until,
            } => {
                let wait = until.saturating_sub(self.mono());
                // One connection, from this contact, before the offer
                // expires.
                if let Ok(Ok(link)) = tokio::time::timeout(wait, listener.accept()).await {
                    drop(listener);
                    self.moving.borrow_mut().remove(&peer);
                    self.incoming(link, Origin::Direct(peer)).await;
                }
                drop(lease);
            }
        }
        self.moving.borrow_mut().remove(&peer);
    }
}
