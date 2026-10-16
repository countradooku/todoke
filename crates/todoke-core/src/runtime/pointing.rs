//! Pointing at nearby contacts with ultra-wideband (PROTOCOL §10.4).
//!
//! The app ranges; the core carries the parameters inside sessions. A
//! device that can be pointed at says so (`Request::SetRangingReady`), and
//! every session tells its peer once. A device that points
//! (`Request::PointStart`) opens sessions to the contacts on the local
//! network and, in each session on a local link whose peer can be pointed
//! at, starts one ranging with a fresh session ID and key, reported as
//! `Event::PointTarget`; the peer's app gets `Event::RangingRequested`.
//! Pointing ends with `Request::PointStop`, after 120 seconds, or with the
//! session; every end is reported. Ranging is an interface hint only:
//! nothing here authenticates, picks a link, or consents to anything.

use core::time::Duration;
use std::rc::Rc;

use todoke_crypto::identity::Ed25519PublicKey;
use todoke_proto::ranging::{MAX_RANGING_SECONDS, RangingReady, RangingStart, STS_KEY_LEN};
use todoke_transfer::TransferEvent;
use todoke_transport::LinkKind;
use zeroize::Zeroizing;

use super::running::State;
use crate::api::{ErrorCode, Event, Ranging, RangingAbility, Response, hex};

type Engine<'k> = super::session::Engine<'k>;

/// Between attempts to open a session to a contact while pointing.
const DIAL_PAUSE: Duration = Duration::from_secs(5);

/// This device pointing now.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Pointer {
    controller: u16,
    channel: u8,
    preamble: u8,
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
                    address: ability.address,
                    configs: ability.configs,
                };
                if RangingReady::decode(&ready.encode()).is_err() {
                    return Response::error(
                        ErrorCode::Invalid,
                        "not a UWB address and configuration",
                    );
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
        controller: u16,
        channel: u8,
        preamble: u8,
    ) -> Response {
        let valid = controller != 0
            && controller != u16::MAX
            && matches!(channel, 5 | 9)
            && matches!(preamble, 9..=12 | 25..=32);
        if !valid {
            return Response::error(
                ErrorCode::Invalid,
                "not a UWB address, channel, and preamble",
            );
        }
        let epoch = self.pointer.get().map_or(1, |pointer| pointer.epoch + 1);
        self.pointer.set(Some(Pointer {
            controller,
            channel,
            preamble,
            epoch,
            until: self.mono() + Duration::from_secs(MAX_RANGING_SECONDS),
        }));
        self.connect_nearby();
        Response::Done
    }

    /// `Request::PointStop`.
    pub(super) fn point_stop(&self) -> Response {
        self.pointer.set(None);
        Response::Done
    }

    /// Pointing now, if it has not run out.
    pub(super) fn pointing(&self) -> Option<Pointer> {
        let pointer = self.pointer.get()?;
        if self.mono() >= pointer.until {
            self.pointer.set(None);
            return None;
        }
        Some(pointer)
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

/// One session's part in pointing.
pub(super) struct SessionPointing {
    peer: Ed25519PublicKey,
    /// The session runs on a local link (the LAN or a direct one).
    local: bool,
    sent_ready: bool,
    peer_ready: Option<RangingReady>,
    /// The pointing epoch this session ranged for.
    ranged: Option<u64>,
    /// The ranging running now, and whether this side is its controller.
    running: Option<(u32, bool)>,
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
                let controlee = state.ranging_ready.get().map_or(0, |ready| ready.address);
                self.running = Some((start.session_id, false));
                state.emit(Event::RangingRequested(ranging(
                    self.peer, &start, controlee,
                )));
                None
            }
            TransferEvent::RangingStopped { session_id } => {
                if self.running.is_some_and(|(id, _)| id == session_id) {
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

    /// Advances pointing: tells the peer this side can be pointed at,
    /// starts ranging for a new pointing, stops it once pointing ends.
    pub(super) fn step(&mut self, state: &State, engine: &mut Engine<'_>, now: Duration) {
        if !self.sent_ready
            && let Some(ready) = state.ranging_ready.get()
            && engine.send_ranging_ready(ready).is_ok()
        {
            self.sent_ready = true;
        }
        let pointer = state.pointing();
        if let Some((session_id, true)) = self.running
            && pointer.is_none_or(|pointer| Some(pointer.epoch) != self.ranged)
        {
            if engine.stop_ranging(session_id).is_ok() {
                state.emit(Event::RangingStopped {
                    contact: hex(self.peer.as_bytes()),
                    session_id,
                });
            }
            self.running = None;
        }
        let (Some(pointer), Some(peer)) = (pointer, self.peer_ready) else {
            return;
        };
        if !self.local || self.running.is_some() || self.ranged == Some(pointer.epoch) {
            return;
        }
        let Some(start) = fresh_start(pointer, peer) else {
            return;
        };
        self.ranged = Some(pointer.epoch);
        if engine.start_ranging(&start, now).is_ok() {
            self.running = Some((start.session_id, true));
            state.emit(Event::PointTarget(ranging(self.peer, &start, peer.address)));
        }
    }

    /// The session ends: a ranging still running ends with it.
    pub(super) fn end(&mut self, state: &State) {
        if let Some((session_id, _)) = self.running.take() {
            state.emit(Event::RangingStopped {
                contact: hex(self.peer.as_bytes()),
                session_id,
            });
        }
    }
}

/// A start with a fresh session ID and key, with the configuration the
/// peer announced (provisioned-STS DS-TWR).
fn fresh_start(pointer: Pointer, peer: RangingReady) -> Option<RangingStart> {
    let mut id = [0_u8; 4];
    let mut sts_key = Zeroizing::new([0_u8; STS_KEY_LEN]);
    getrandom::fill(&mut id).ok()?;
    getrandom::fill(&mut *sts_key).ok()?;
    let session_id = u32::from_be_bytes(id);
    let config = peer.configs & peer.configs.wrapping_neg();
    (session_id != 0 && config != 0).then_some(RangingStart {
        session_id,
        controller: pointer.controller,
        channel: pointer.channel,
        preamble: pointer.preamble,
        config,
        sts_key,
    })
}

fn ranging(peer: Ed25519PublicKey, start: &RangingStart, controlee: u16) -> Ranging {
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
