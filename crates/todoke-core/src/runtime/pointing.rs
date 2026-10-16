//! Pointing at nearby contacts with ultra-wideband (PROTOCOL §10.4).
//!
//! The app ranges; the core carries the parameters inside sessions. Every
//! UWB address serves one ranging (platforms allocate one per ranging
//! session), so addresses come from the app per ranging. A device that can
//! be pointed at says so (`Request::SetRangingReady`), and every session
//! tells its peer once. A device that points (`Request::PointStart`, with a
//! pool of controllers the platform prepared) opens sessions to the
//! contacts on the local network and, in each session on a local link
//! whose peer can be pointed at, starts one ranging with the next unused
//! controller and a fresh session ID and key. The peer's app gets
//! `Event::RangingRequested` and answers with a fresh controlee address
//! (`Request::RangingAnswer`); the pointing device then gets
//! `Event::PointTarget`. Pointing ends with `Request::PointStop`, after
//! 120 seconds, or with the session; every end is reported. Ranging is an
//! interface hint only: nothing here authenticates, picks a link, or
//! consents to anything.

use core::time::Duration;
use std::rc::Rc;

use todoke_crypto::identity::Ed25519PublicKey;
use todoke_proto::ranging::{
    MAX_RANGING_SECONDS, MAX_STARTS, RangingReady, RangingStart, STS_KEY_LEN,
};
use todoke_transfer::TransferEvent;
use todoke_transport::LinkKind;
use zeroize::Zeroizing;

use super::running::State;
use super::session::SessionCommand;
use crate::api::{
    ErrorCode, Event, PeerRangingInfo, Ranging, RangingAbility, Response, UwbController, hex,
};
use todoke_proto::ranging::{
    CONFIG_APPLE_PEER, CONFIG_PROVISIONED_DS_TWR, MAX_TOKEN_LEN, PeerRanging,
};

type Engine<'k> = super::session::Engine<'k>;

/// Between attempts to open a session to a contact while pointing.
const DIAL_PAUSE: Duration = Duration::from_secs(5);

/// This device pointing now.
#[derive(Debug)]
pub(super) struct Pointer {
    /// The `FiRa` controllers the app prepared, each used for one ranging.
    controllers: Vec<UwbController>,
    /// The first unused one.
    next: usize,
    /// The Apple Nearby Interaction tokens the app prepared, each used for
    /// one ranging.
    tokens: Vec<Vec<u8>>,
    /// The first unused one.
    next_token: usize,
    /// Which `PointStart` this is: a session ranges once per pointing.
    epoch: u64,
    until: Duration,
}

impl State {
    /// `Request::SetRangingReady`: sessions tell their peers from now on.
    pub(super) fn set_ranging_ready(&self, ready: Option<RangingAbility>) -> Response {
        let ready = match ready {
            None => None,
            Some(ability) => {
                // Checked as the record will be.
                let ready = RangingReady {
                    configs: ability.configs,
                };
                if RangingReady::decode(&ready.encode()).is_err() {
                    return Response::error(ErrorCode::Invalid, "not a UWB configuration");
                }
                Some(ready)
            }
        };
        self.ranging_ready.set(ready);
        Response::Done
    }

    /// `Request::PointStart`: point for 120 seconds; sessions open to the
    /// contacts on the local network.
    pub(super) fn point_start(
        self: &Rc<Self>,
        controllers: Vec<UwbController>,
        peer_tokens: &[String],
    ) -> Response {
        let tokens: Option<Vec<Vec<u8>>> = peer_tokens.iter().map(|token| unhex(token)).collect();
        let Some(tokens) = tokens.filter(|tokens| {
            let mut distinct = tokens.clone();
            distinct.sort_unstable();
            distinct.dedup();
            distinct.len() == tokens.len()
                && tokens
                    .iter()
                    .all(|token| (1..=MAX_TOKEN_LEN).contains(&token.len()))
        }) else {
            return Response::error(
                ErrorCode::Invalid,
                "not distinct discovery tokens of 1 to 1024 bytes",
            );
        };
        let valid = |controller: &UwbController| {
            controller.address != 0
                && controller.address != u16::MAX
                && matches!(controller.channel, 5 | 9)
                && matches!(controller.preamble, 9..=12 | 25..=32)
        };
        let mut addresses: Vec<u16> = controllers.iter().map(|c| c.address).collect();
        addresses.sort_unstable();
        addresses.dedup();
        let total = controllers.len() + tokens.len();
        if total == 0
            || total > usize::from(MAX_STARTS)
            || addresses.len() != controllers.len()
            || !controllers.iter().all(valid)
        {
            return Response::error(
                ErrorCode::Invalid,
                "not 1 to 8 UWB controllers and tokens, controllers with distinct addresses, channels 5 or 9, and preambles 9 to 12 or 25 to 32",
            );
        }
        let epoch = self.point_epoch.get() + 1;
        self.point_epoch.set(epoch);
        *self.pointer.borrow_mut() = Some(Pointer {
            controllers,
            next: 0,
            tokens,
            next_token: 0,
            epoch,
            until: self.mono() + Duration::from_secs(MAX_RANGING_SECONDS),
        });
        self.connect_nearby();
        Response::Done
    }

    /// `Request::PointStop`.
    pub(super) fn point_stop(&self) -> Response {
        self.pointer.borrow_mut().take();
        Response::Done
    }

    /// `Request::RangingAnswer`: to the session with `contact`.
    pub(super) async fn ranging_answer(
        &self,
        contact: &str,
        session_id: u32,
        controlee: Option<u16>,
    ) -> Response {
        let answer = controlee.map_or(Answer::Refuse, Answer::Fira);
        self.answer(contact, session_id, answer).await
    }

    /// `Request::PeerRangingAccept`: to the session with `contact`.
    pub(super) async fn peer_ranging_accept(
        &self,
        contact: &str,
        session_id: u32,
        token: &str,
    ) -> Response {
        let Some(token) = unhex(token) else {
            return Response::error(ErrorCode::Invalid, "not a discovery token");
        };
        self.answer(contact, session_id, Answer::Peer(token)).await
    }

    async fn answer(&self, contact: &str, session_id: u32, answer: Answer) -> Response {
        let peer = match self.resolve_contact(contact).await {
            Ok(peer) => peer,
            Err(response) => return response,
        };
        let session = self.sessions.borrow().get(&peer).cloned();
        let Some(session) = session else {
            return Response::error(ErrorCode::Unreachable, "the contact is not connected");
        };
        let (reply, outcome) = tokio::sync::oneshot::channel();
        let command = SessionCommand::Ranging { session_id, answer };
        if session
            .send(SessionCommand::with_reply(command, reply))
            .await
            .is_err()
        {
            return Response::error(ErrorCode::Unreachable, "the session ended");
        }
        outcome
            .await
            .unwrap_or_else(|_| Response::error(ErrorCode::Unreachable, "the session ended"))
    }

    /// The pointing epoch now, if pointing has not run out.
    pub(super) fn pointing(&self) -> Option<u64> {
        let mut pointer = self.pointer.borrow_mut();
        let epoch = pointer.as_ref()?.epoch;
        if pointer
            .as_ref()
            .is_some_and(|pointer| self.mono() >= pointer.until)
        {
            *pointer = None;
            return None;
        }
        Some(epoch)
    }

    /// How to range with a peer announcing `configs`: the next unused
    /// controller (`FiRa`, preferred) or token (Apple), taken.
    fn take_method(&self, configs: u8) -> Option<Method> {
        let mut pointer = self.pointer.borrow_mut();
        let pointer = pointer.as_mut()?;
        if configs & CONFIG_PROVISIONED_DS_TWR != 0
            && let Some(controller) = pointer.controllers.get(pointer.next).copied()
        {
            pointer.next += 1;
            return Some(Method::Fira(controller));
        }
        if configs & CONFIG_APPLE_PEER != 0
            && let Some(token) = pointer.tokens.get(pointer.next_token).cloned()
        {
            pointer.next_token += 1;
            return Some(Method::Peer(token));
        }
        None
    }

    /// Opens a session to every contact on the local network that has
    /// none (where pointing can reach it).
    pub(super) fn connect_nearby(self: &Rc<Self>) {
        let mono = self.mono();
        let nearby = self.directory.borrow().contacts(mono);
        for (peer, reachable) in nearby {
            // One attempt at a time per contact, then a pause (a session
            // that lasts clears it): never a dial per tick.
            let due = self
                .retry
                .borrow()
                .get(&peer)
                .is_none_or(|(next, _)| mono >= *next);
            if !due
                || self.sessions.borrow().contains_key(&peer)
                || self.manager.is_busy(&peer)
                || self.is_moving(&peer)
            {
                continue;
            }
            self.retry
                .borrow_mut()
                .insert(peer, (mono + DIAL_PAUSE, DIAL_PAUSE));
            let candidates = reachable.candidates();
            let state = Rc::clone(self);
            tokio::task::spawn_local(async move {
                let _ = state.connect(peer, candidates).await;
            });
        }
    }
}

/// How this device ranges as the controller with one contact.
enum Method {
    Fira(UwbController),
    /// Apple peer ranging with this token.
    Peer(Vec<u8>),
}

/// The app's answer to a ranging request.
pub(super) enum Answer {
    /// Range (`FiRa`) at this controlee address.
    Fira(u16),
    /// Range (Apple) with this token.
    Peer(Vec<u8>),
    Refuse,
}

/// What a controller keeps of its start until the peer accepts it (then
/// reported as the target).
enum Started {
    Fira(RangingStart),
    /// This device's token.
    Peer(Vec<u8>),
}

/// The ranging running in a session.
struct Running {
    session_id: u32,
    /// This side started it.
    controller: bool,
    start: Option<Started>,
}

/// One session's part in pointing.
pub(super) struct SessionPointing {
    peer: Ed25519PublicKey,
    /// The session runs on a local link (the LAN or a direct one).
    local: bool,
    sent_ready: bool,
    peer_ready: Option<RangingReady>,
    /// The pointing epoch this session ranged for.
    ranged: Option<u64>,
    running: Option<Running>,
}

impl SessionPointing {
    pub(super) fn new(peer: Ed25519PublicKey, kind: LinkKind) -> Self {
        Self {
            peer,
            local: matches!(kind, LinkKind::Lan | LinkKind::Direct),
            sent_ready: false,
            peer_ready: None,
            ranged: None,
            running: None,
        }
    }

    fn stopped(&mut self, state: &State, session_id: u32) {
        self.running = None;
        state.emit(Event::RangingStopped {
            contact: hex(self.peer.as_bytes()),
            session_id,
        });
    }

    /// Takes the pointing events from the engine; returns the others.
    pub(super) fn event(
        &mut self,
        state: &State,
        engine: &mut Engine<'_>,
        event: TransferEvent,
    ) -> Option<TransferEvent> {
        match event {
            TransferEvent::RangingReady(ready) => {
                self.peer_ready = Some(ready);
                None
            }
            TransferEvent::RangingRequested(start) => {
                // No longer pointable (UWB off, app in the background): the
                // start is refused at once (§10.4).
                if !self.pointable(state, CONFIG_PROVISIONED_DS_TWR) {
                    let _ = engine.stop_ranging(start.session_id);
                    return None;
                }
                self.requested(start.session_id);
                state.emit(Event::RangingRequested(ranging(self.peer, &start, None)));
                None
            }
            TransferEvent::PeerRangingRequested(start) => {
                if !self.pointable(state, CONFIG_APPLE_PEER) {
                    let _ = engine.stop_ranging(start.session_id);
                    return None;
                }
                self.requested(start.session_id);
                state.emit(Event::PeerRangingRequested(PeerRangingInfo {
                    contact: hex(self.peer.as_bytes()),
                    session_id: start.session_id,
                    peer_token: hex(&start.token),
                    local_token: None,
                }));
                None
            }
            TransferEvent::RangingAccepted(accept) => {
                if let Some(Started::Fira(start)) = self.accepted(accept.session_id) {
                    state.emit(Event::PointTarget(ranging(
                        self.peer,
                        &start,
                        Some(accept.controlee),
                    )));
                }
                None
            }
            TransferEvent::PeerRangingAccepted(accept) => {
                if let Some(Started::Peer(local)) = self.accepted(accept.session_id) {
                    state.emit(Event::PeerPointTarget(PeerRangingInfo {
                        contact: hex(self.peer.as_bytes()),
                        session_id: accept.session_id,
                        peer_token: hex(&accept.token),
                        local_token: Some(hex(&local)),
                    }));
                }
                None
            }
            TransferEvent::RangingStopped { session_id } => {
                if self
                    .running
                    .as_ref()
                    .is_some_and(|running| running.session_id == session_id)
                {
                    self.running = None;
                }
                state.emit(Event::RangingStopped {
                    contact: hex(self.peer.as_bytes()),
                    session_id,
                });
                None
            }
            other => Some(other),
        }
    }

    /// Takes the app's answer to a ranging request; returns other commands.
    pub(super) fn command(
        &mut self,
        state: &State,
        engine: &mut Engine<'_>,
        command: SessionCommand,
    ) -> Option<SessionCommand> {
        let (session_id, answer, reply) = match command {
            SessionCommand::Ranging { session_id, answer } => (session_id, answer, None),
            SessionCommand::Reply(command, reply) => match *command {
                SessionCommand::Ranging { session_id, answer } => (session_id, answer, Some(reply)),
                other => return Some(SessionCommand::with_reply(other, reply)),
            },
            other => return Some(other),
        };
        let mine = self
            .running
            .as_ref()
            .is_some_and(|running| running.session_id == session_id && !running.controller);
        let outcome = if mine {
            match answer {
                Answer::Fira(controlee) => engine.accept_ranging(session_id, controlee),
                Answer::Peer(token) => engine.accept_peer_ranging(session_id, token),
                Answer::Refuse => {
                    let stopped = engine.stop_ranging(session_id);
                    if stopped.is_ok() {
                        self.stopped(state, session_id);
                    }
                    stopped
                }
            }
        } else {
            Err(todoke_transfer::RangingError::NotRunning)
        };
        if let Some(reply) = reply {
            let _ = reply.send(match outcome {
                Ok(()) => Response::Done,
                Err(todoke_transfer::RangingError::Address) => Response::error(
                    ErrorCode::Invalid,
                    "not a UWB address or token for this ranging",
                ),
                Err(error) => Response::error(ErrorCode::State, error.to_string()),
            });
        }
        None
    }

    /// Advances pointing: tells the peer this side can be pointed at,
    /// starts ranging for a new pointing, stops what no longer stands
    /// (pointing ended, or this side no longer pointable).
    pub(super) fn step(&mut self, state: &State, engine: &mut Engine<'_>, now: Duration) {
        if !self.sent_ready
            && let Some(ready) = state.ranging_ready.get()
            && engine.send_ranging_ready(ready).is_ok()
        {
            self.sent_ready = true;
        }
        let epoch = state.pointing();
        if let Some(running) = &self.running {
            let session_id = running.session_id;
            let stands = if running.controller {
                epoch.is_some() && epoch == self.ranged
            } else {
                state.ranging_ready.get().is_some()
            };
            if !stands {
                let _ = engine.stop_ranging(session_id);
                self.stopped(state, session_id);
            }
        }
        let (Some(epoch), Some(peer)) = (epoch, self.peer_ready) else {
            return;
        };
        if !self.local || self.running.is_some() || self.ranged == Some(epoch) {
            return;
        }
        let Some(method) = state.take_method(peer.configs) else {
            return;
        };
        self.ranged = Some(epoch);
        let Some(session_id) = fresh_session_id() else {
            return;
        };
        let started = match method {
            Method::Fira(controller) => {
                let Some(start) = fresh_start(session_id, controller) else {
                    return;
                };
                engine
                    .start_ranging(&start, now)
                    .is_ok()
                    .then_some(Started::Fira(start))
            }
            Method::Peer(token) => {
                let start = PeerRanging {
                    session_id,
                    token: token.clone(),
                };
                engine
                    .start_peer_ranging(&start, now)
                    .is_ok()
                    .then_some(Started::Peer(token))
            }
        };
        if let Some(started) = started {
            self.running = Some(Running {
                session_id,
                controller: true,
                start: Some(started),
            });
        }
    }

    /// Whether this side can be pointed at now with `config`, on a local
    /// link.
    fn pointable(&self, state: &State, config: u8) -> bool {
        self.local
            && state
                .ranging_ready
                .get()
                .is_some_and(|ready| ready.configs & config != 0)
    }

    /// The peer started a ranging with this side as the controlee.
    fn requested(&mut self, session_id: u32) {
        self.running = Some(Running {
            session_id,
            controller: false,
            start: None,
        });
    }

    /// The peer accepted the ranging this side started: its start, once.
    fn accepted(&mut self, session_id: u32) -> Option<Started> {
        self.running
            .as_mut()
            .filter(|running| running.session_id == session_id)?
            .start
            .take()
    }

    /// The session ends: a ranging still running ends with it.
    pub(super) fn end(&mut self, state: &State) {
        if let Some(running) = self.running.take() {
            self.stopped(state, running.session_id);
        }
    }
}

/// A fresh ranging session ID (never zero).
fn fresh_session_id() -> Option<u32> {
    let mut id = [0_u8; 4];
    getrandom::fill(&mut id).ok()?;
    Some(u32::from_be_bytes(id)).filter(|&id| id != 0)
}

/// A `FiRa` start with `controller` and a fresh key (provisioned-STS
/// DS-TWR).
fn fresh_start(session_id: u32, controller: UwbController) -> Option<RangingStart> {
    let mut sts_key = Zeroizing::new([0_u8; STS_KEY_LEN]);
    getrandom::fill(&mut *sts_key).ok()?;
    Some(RangingStart {
        session_id,
        controller: controller.address,
        channel: controller.channel,
        preamble: controller.preamble,
        config: CONFIG_PROVISIONED_DS_TWR,
        sts_key,
    })
}

/// Hexadecimal text as bytes.
fn unhex(text: &str) -> Option<Vec<u8>> {
    let digit = |byte: u8| {
        char::from(byte)
            .to_digit(16)
            .and_then(|d| u8::try_from(d).ok())
    };
    let (pairs, []) = text.as_bytes().as_chunks::<2>() else {
        return None;
    };
    pairs
        .iter()
        .map(|pair| Some((digit(pair[0])? << 4) | digit(pair[1])?))
        .collect()
}

fn ranging(peer: Ed25519PublicKey, start: &RangingStart, controlee: Option<u16>) -> Ranging {
    Ranging {
        contact: hex(peer.as_bytes()),
        session_id: start.session_id,
        controller: start.controller,
        controlee,
        channel: start.channel,
        preamble: start.preamble,
        config: start.config,
        sts_key: hex(*start.sts_key),
    }
}
