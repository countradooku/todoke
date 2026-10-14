//! The room table (§10): which tokens are waiting, who joined each room,
//! and what each member is told. No I/O: each member's stream task asks
//! the table and receives [`RoomEvent`]s on its channel.
//!
//! A room holds at most two members of one token. The first member's room
//! is created by its `Register`; the second matches it, and both are told
//! `PeerReady`. Each member may send one `Candidates` (forwarded once to
//! the other; when both have, both get a `Punch`) and then `Forward`; once
//! both have forwarded, the second hands both streams to the tunnel and
//! the room is gone. Every room is gone after its TTL, a closure, or a
//! member leaving. Nothing about a room outlives it.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use todoke_proto::relay::{
    Candidate, CloseCode, MAX_ROOM_SECONDS, MAX_WAIT_SECONDS, Nonce, Random16, RendezvousToken,
    RoomId,
};
use tokio::sync::mpsc;

/// What the table tells one member's stream task.
#[derive(Debug)]
pub(crate) enum RoomEvent {
    /// The other endpoint joined.
    PeerReady(Nonce),
    /// The other endpoint's candidates, to pass on once.
    Candidates(Vec<Candidate>),
    /// Both sent candidates: when to try them.
    Punch { delay_ms: u16, nonce: Nonce },
    /// The room closed; tell the client why.
    Closed(CloseCode),
}

/// Which member of a room.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Slot {
    First,
    Second,
}

impl Slot {
    const fn index(self) -> usize {
        match self {
            Self::First => 0,
            Self::Second => 1,
        }
    }

    const fn other(self) -> Self {
        match self {
            Self::First => Self::Second,
            Self::Second => Self::First,
        }
    }
}

/// A member's place in a room.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Ticket {
    pub(crate) room: RoomId,
    pub(crate) slot: Slot,
}

/// What a `Register` got.
#[derive(Debug)]
pub(crate) struct Joined {
    pub(crate) ticket: Ticket,
    /// Seconds left of the room, at most the TTL asked for.
    pub(crate) expires_in: u16,
    /// When the room expires.
    pub(crate) expires: Instant,
    /// When the wait for the other endpoint ends (the room's expiry if
    /// sooner).
    pub(crate) wait_until: Instant,
    /// The other endpoint's nonce, if it was already waiting.
    pub(crate) peer: Option<Nonce>,
}

/// What `Forward` led to.
#[derive(Debug)]
pub(crate) enum Forwarded<S> {
    /// The other endpoint has not forwarded yet: this member's streams wait
    /// in the room.
    Waiting,
    /// Both forwarded: this member's streams and the other's, for the
    /// tunnel. The room is gone.
    Tunnel {
        /// This member's.
        mine: S,
        /// The other member's.
        theirs: S,
    },
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
enum Step {
    #[default]
    Registered,
    Ready,
    Candidates,
    Forwarded,
}

struct Member<S> {
    endpoint: u64,
    nonce: Nonce,
    events: mpsc::Sender<RoomEvent>,
    step: Step,
    candidates: bool,
    streams: Option<S>,
}

struct Room<S> {
    token: [u8; 32],
    expires: Instant,
    members: [Option<Member<S>>; 2],
}

/// Limits a table enforces.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Limits {
    /// Rooms open at once on this node.
    pub(crate) max_rooms: usize,
}

/// The rooms of one relay node, keyed by room ID and by token. `S` is a
/// member's stream pair, handed over for the tunnel.
pub(crate) struct Rooms<S> {
    open: HashMap<RoomId, Room<S>>,
    by_token: HashMap<[u8; 32], RoomId>,
    limits: Limits,
}

impl<S> Rooms<S> {
    pub(crate) fn new(limits: Limits) -> Self {
        Self {
            open: HashMap::new(),
            by_token: HashMap::new(),
            limits,
        }
    }

    /// Rooms open.
    pub(crate) fn len(&self) -> usize {
        self.open.len()
    }

    /// `Register` from `endpoint` (a connection) at `now`.
    ///
    /// # Errors
    ///
    /// The code to close with: [`CloseCode::Full`] for a token with two
    /// members or one of this endpoint, [`CloseCode::Malformed`] for a
    /// nonce equal to the waiting member's, [`CloseCode::Unavailable`] at
    /// the room limit or without randomness.
    pub(crate) fn register(
        &mut self,
        token: &RendezvousToken,
        nonce: Nonce,
        ttl_seconds: u16,
        endpoint: u64,
        events: mpsc::Sender<RoomEvent>,
        now: Instant,
    ) -> Result<Joined, CloseCode> {
        let token = *token.as_bytes();
        // An expired room for this token is closed now; others are left to
        // the periodic `expire`, so a Register never scans the table.
        if let Some(id) = self.by_token.get(&token).copied()
            && self.open.get(&id).is_some_and(|room| room.expires <= now)
            && let Some(room) = self.remove(id)
        {
            for member in room.members.iter().flatten() {
                let _ = member
                    .events
                    .try_send(RoomEvent::Closed(CloseCode::Expired));
            }
        }
        let member = Member {
            endpoint,
            nonce,
            events,
            step: Step::Registered,
            candidates: false,
            streams: None,
        };
        if let Some(id) = self.by_token.get(&token).copied()
            && let Some(room) = self.open.get_mut(&id)
        {
            let [Some(first), None] = &room.members else {
                return Err(CloseCode::Full);
            };
            if first.endpoint == endpoint {
                return Err(CloseCode::Full);
            }
            if first.nonce == nonce {
                return Err(CloseCode::Malformed);
            }
            let (first_nonce, first_events) = (first.nonce, first.events.clone());
            room.members[1] = Some(Member {
                step: Step::Ready,
                ..member
            });
            if let Some(Some(first)) = room.members.first_mut() {
                first.step = Step::Ready;
            }
            // The first member learns now; a full channel means it is not
            // reading, and its room closes when it is next looked at.
            let _ = first_events.try_send(RoomEvent::PeerReady(nonce));
            let left = room.expires.saturating_duration_since(now);
            return Ok(Joined {
                ticket: Ticket {
                    room: id,
                    slot: Slot::Second,
                },
                expires_in: seconds(left).min(ttl_seconds).max(1),
                expires: room.expires,
                wait_until: room.expires,
                peer: Some(first_nonce),
            });
        }
        if self.open.len() >= self.limits.max_rooms {
            return Err(CloseCode::Unavailable);
        }
        let id = fresh_room().ok_or(CloseCode::Unavailable)?;
        let ttl = ttl_seconds.clamp(1, MAX_ROOM_SECONDS);
        let expires = now + Duration::from_secs(u64::from(ttl));
        let wait_until = (now + Duration::from_secs(u64::from(MAX_WAIT_SECONDS))).min(expires);
        self.open.insert(
            id,
            Room {
                token,
                expires,
                members: [Some(member), None],
            },
        );
        self.by_token.insert(token, id);
        Ok(Joined {
            ticket: Ticket {
                room: id,
                slot: Slot::First,
            },
            expires_in: ttl,
            expires,
            wait_until,
            peer: None,
        })
    }

    /// `Candidates` from a member: passed on to the other once; when both
    /// sent theirs, both are told to punch.
    ///
    /// # Errors
    ///
    /// [`CloseCode::Malformed`] for candidates before `PeerReady`, after
    /// `Forward`, a second time, or for another room; the room is closed.
    pub(crate) fn candidates(
        &mut self,
        ticket: Ticket,
        room: RoomId,
        candidates: Vec<Candidate>,
    ) -> Result<(), CloseCode> {
        let valid = ticket.room == room
            && self
                .member(ticket)
                .is_some_and(|member| member.step == Step::Ready && !member.candidates);
        if !valid {
            self.close(ticket, CloseCode::Malformed);
            return Err(CloseCode::Malformed);
        }
        if let Some(member) = self.member_mut(ticket) {
            member.candidates = true;
            member.step = Step::Candidates;
        }
        let both = self
            .member(Ticket {
                slot: ticket.slot.other(),
                ..ticket
            })
            .is_some_and(|peer| peer.candidates);
        if let Some(peer) = self.member(Ticket {
            slot: ticket.slot.other(),
            ..ticket
        }) {
            let _ = peer.events.try_send(RoomEvent::Candidates(candidates));
        }
        if both && let Some(nonce) = fresh_room() {
            for slot in [Slot::First, Slot::Second] {
                if let Some(member) = self.member(Ticket { slot, ..ticket }) {
                    let _ = member
                        .events
                        .try_send(RoomEvent::Punch { delay_ms: 0, nonce });
                }
            }
        }
        Ok(())
    }

    /// `Forward` from a member, with its `streams`.
    ///
    /// # Errors
    ///
    /// [`CloseCode::Malformed`] for a `Forward` before `PeerReady`, a
    /// second time, or for another room; the room is closed. The streams
    /// come back with the error so the caller can say so.
    pub(crate) fn forward(
        &mut self,
        ticket: Ticket,
        room: RoomId,
        streams: S,
    ) -> Result<Forwarded<S>, (CloseCode, S)> {
        let valid = ticket.room == room
            && self
                .member(ticket)
                .is_some_and(|member| matches!(member.step, Step::Ready | Step::Candidates));
        if !valid {
            self.close(ticket, CloseCode::Malformed);
            return Err((CloseCode::Malformed, streams));
        }
        let peer_forwarded = self
            .member(Ticket {
                slot: ticket.slot.other(),
                ..ticket
            })
            .is_some_and(|peer| peer.step == Step::Forwarded);
        if !peer_forwarded {
            if let Some(member) = self.member_mut(ticket) {
                member.step = Step::Forwarded;
                member.streams = Some(streams);
            }
            return Ok(Forwarded::Waiting);
        }
        // Both forwarded: the tunnel replaces the room.
        let Some(mut room) = self.remove(ticket.room) else {
            return Err((CloseCode::Unavailable, streams));
        };
        let theirs = room.members[ticket.slot.other().index()]
            .as_mut()
            .and_then(|peer| peer.streams.take());
        match theirs {
            Some(theirs) => Ok(Forwarded::Tunnel {
                mine: streams,
                theirs,
            }),
            None => Err((CloseCode::Unavailable, streams)),
        }
    }

    /// Takes back a waiting member's streams (it is leaving, or its room
    /// expired); `None` if the tunnel took them first. The room closes.
    pub(crate) fn withdraw(&mut self, ticket: Ticket, code: CloseCode) -> Option<S> {
        let streams = self
            .member_mut(ticket)
            .and_then(|member| member.streams.take());
        self.close(ticket, code);
        streams
    }

    /// Closes the room of `ticket`: the other member is told `code`.
    pub(crate) fn close(&mut self, ticket: Ticket, code: CloseCode) {
        let Some(room) = self.remove(ticket.room) else {
            return;
        };
        if let Some(Some(peer)) = room.members.get(ticket.slot.other().index()) {
            let _ = peer.events.try_send(RoomEvent::Closed(code));
        }
    }

    /// Closes every room past its TTL at `now`, telling its members.
    pub(crate) fn expire(&mut self, now: Instant) {
        let expired: Vec<RoomId> = self
            .open
            .iter()
            .filter(|(_, room)| room.expires <= now)
            .map(|(id, _)| *id)
            .collect();
        for id in expired {
            if let Some(room) = self.remove(id) {
                for member in room.members.iter().flatten() {
                    let _ = member
                        .events
                        .try_send(RoomEvent::Closed(CloseCode::Expired));
                }
            }
        }
    }

    fn remove(&mut self, id: RoomId) -> Option<Room<S>> {
        let room = self.open.remove(&id)?;
        if self.by_token.get(&room.token) == Some(&id) {
            self.by_token.remove(&room.token);
        }
        Some(room)
    }

    fn member(&self, ticket: Ticket) -> Option<&Member<S>> {
        self.open.get(&ticket.room)?.members[ticket.slot.index()].as_ref()
    }

    fn member_mut(&mut self, ticket: Ticket) -> Option<&mut Member<S>> {
        self.open.get_mut(&ticket.room)?.members[ticket.slot.index()].as_mut()
    }
}

/// Whole seconds in `duration`, at most `u16::MAX`.
fn seconds(duration: Duration) -> u16 {
    u16::try_from(duration.as_secs()).unwrap_or(u16::MAX)
}

/// A fresh random room ID (or punch nonce) from the OS CSPRNG.
fn fresh_room() -> Option<RoomId> {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).ok()?;
    Random16::new(bytes).ok()
}

#[cfg(test)]
mod tests;
