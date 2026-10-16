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
use crate::api::{ErrorCode, Event, Ranging, RangingAbility, Response, UwbController, hex};

type Engine<'k> = super::session::Engine<'k>;

/// Between attempts to open a session to a contact while pointing.
const DIAL_PAUSE: Duration = Duration::from_secs(5);

/// This device pointing now.
#[derive(Debug)]
pub(super) struct Pointer {
    /// The controllers the app prepared, each used for one ranging.
    controllers: Vec<UwbController>,
    /// The first unused one.
    next: usize,
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
    pub(super) fn point_start(self: &Rc<Self>, controllers: Vec<UwbController>) -> Response {
        let valid = |controller: &UwbController| {
            controller.address != 0
                && controller.address != u16::MAX
                && matches!(controller.channel, 5 | 9)
                && matches!(controller.preamble, 9..=12 | 25..=32)
        };
        let mut addresses: Vec<u16> = controllers.iter().map(|c| c.address).collect();
        addresses.sort_unstable();
        addresses.dedup();
        if controllers.is_empty()
            || controllers.len() > usize::from(MAX_STARTS)
            || addresses.len() != controllers.len()
            || !controllers.iter().all(valid)
        {
            return Response::error(
                ErrorCode::Invalid,
                "not 1 to 8 UWB controllers with distinct addresses, channels 5 or 9, and preambles 9 to 12 or 25 to 32",
            );
        }
        let epoch = self.point_epoch.get() + 1;
        self.point_epoch.set(epoch);
        *self.pointer.borrow_mut() = Some(Pointer {
            controllers,
            next: 0,
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
        let peer = match self.resolve_contact(contact).await {
            Ok(peer) => peer,
            Err(response) => return response,
        };
        let session = self.sessions.borrow().get(&peer).cloned();
        let Some(session) = session else {
            return Response::error(ErrorCode::Unreachable, "the contact is not connected");
        };
        let (reply, answer) = tokio::sync::oneshot::channel();
        let command = SessionCommand::Ranging {
            session_id,
            controlee,
        };
        if session
            .send(SessionCommand::with_reply(command, reply))
            .await
            .is_err()
        {
            return Response::error(ErrorCode::Unreachable, "the session ended");
        }
        answer
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

    /// The next unused controller of the pointing, taken.
    fn take_controller(&self) -> Option<UwbController> {
        let mut pointer = self.pointer.borrow_mut();
        let pointer = pointer.as_mut()?;
        let controller = pointer.controllers.get(pointer.next).copied()?;
        pointer.next += 1;
        Some(controller)
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

/// The ranging running in a session.
struct Running {
    session_id: u32,
    /// This side started it.
    controller: bool,
    /// The controller's start, kept until the peer accepts it (then
    /// reported as the target).
    start: Option<RangingStart>,
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
                if state.ranging_ready.get().is_none() || !self.local {
                    let _ = engine.stop_ranging(start.session_id);
                    return None;
                }
                self.running = Some(Running {
                    session_id: start.session_id,
                    controller: false,
                    start: None,
                });
                state.emit(Event::RangingRequested(ranging(self.peer, &start, None)));
                None
            }
            TransferEvent::RangingAccepted(accept) => {
                if let Some(running) = self.running.as_mut()
                    && running.session_id == accept.session_id
                    && let Some(start) = running.start.take()
                {
                    state.emit(Event::PointTarget(ranging(
                        self.peer,
                        &start,
                        Some(accept.controlee),
                    )));
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
        let (session_id, controlee, reply) = match command {
            SessionCommand::Ranging {
                session_id,
                controlee,
            } => (session_id, controlee, None),
            SessionCommand::Reply(command, reply) => match *command {
                SessionCommand::Ranging {
                    session_id,
                    controlee,
                } => (session_id, controlee, Some(reply)),
                other => return Some(SessionCommand::with_reply(other, reply)),
            },
            other => return Some(other),
        };
        let mine = self
            .running
            .as_ref()
            .is_some_and(|running| running.session_id == session_id && !running.controller);
        let outcome = if !mine {
            Err(todoke_transfer::RangingError::NotRunning)
        } else if let Some(controlee) = controlee {
            engine.accept_ranging(session_id, controlee)
        } else {
            let stopped = engine.stop_ranging(session_id);
            if stopped.is_ok() {
                self.stopped(state, session_id);
            }
            stopped
        };
        if let Some(reply) = reply {
            let _ = reply.send(match outcome {
                Ok(()) => Response::Done,
                Err(todoke_transfer::RangingError::Address) => {
                    Response::error(ErrorCode::Invalid, "not a UWB address for this ranging")
                }
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
        let Some(controller) = state.take_controller() else {
            return;
        };
        self.ranged = Some(epoch);
        let Some(start) = fresh_start(controller, peer) else {
            return;
        };
        if engine.start_ranging(&start, now).is_ok() {
            self.running = Some(Running {
                session_id: start.session_id,
                controller: true,
                start: Some(start),
            });
        }
    }

    /// The session ends: a ranging still running ends with it.
    pub(super) fn end(&mut self, state: &State) {
        if let Some(running) = self.running.take() {
            self.stopped(state, running.session_id);
        }
    }
}

/// A start with `controller`, a fresh session ID and key, and the
/// configuration the peer announced (provisioned-STS DS-TWR).
fn fresh_start(controller: UwbController, peer: RangingReady) -> Option<RangingStart> {
    let mut id = [0_u8; 4];
    let mut sts_key = Zeroizing::new([0_u8; STS_KEY_LEN]);
    getrandom::fill(&mut id).ok()?;
    getrandom::fill(&mut *sts_key).ok()?;
    let session_id = u32::from_be_bytes(id);
    let config = peer.configs & peer.configs.wrapping_neg();
    (session_id != 0 && config != 0).then_some(RangingStart {
        session_id,
        controller: controller.address,
        channel: controller.channel,
        preamble: controller.preamble,
        config,
        sts_key,
    })
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
