//! Meeting contacts and QR scanners through relays (PROTOCOL §10).
//!
//! Both devices of a pair register the pair's rendezvous token for the
//! current epoch (§9) at the same relay: the one with the highest
//! rendezvous hash in the shared relay list. Once the relay joins them,
//! the tunnel carries an ordinary session, with §4's roles: the smaller
//! full device key initiates; for QR pairing the scanner initiates.
//!
//! When to register is this device's policy, inside §10's limits (two
//! rooms at once, a 30-second wait):
//!
//! - A contact with offers waiting and not reachable on the LAN is tried
//!   back to back.
//! - Every available contact is also met at a presence window: 30 seconds
//!   every five minutes, at an offset both devices derive from the pair's
//!   token, so two idle devices show up at the same moment and a sender
//!   reaches a receiver within five minutes.
//! - A shown QR offer waits at the relay until it is used, stopped, or
//!   expires; a scanner tries the relay after the nearby devices.
//!
//! Human-code pairing never uses a relay (§10, §16 O8).

use core::cell::{Cell, RefCell};
use core::time::Duration;
use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;

use todoke_crypto::identity::Ed25519PublicKey;
use todoke_crypto::pairing::QrPayload;
use todoke_proto::relay::{MAX_ROOMS_PER_ENDPOINT, MAX_WAIT_SECONDS, RendezvousToken};
use todoke_proto::time::UnixTime;
use todoke_transport::relay::{
    RelayClient, RelayEndpoint, RelayError, RelayLink, choose, parse_pin,
};

use super::StartError;
use super::running::{Pairing, State, wall};
use crate::config::RelayConfig;

/// The shortest presence period allowed.
const MIN_PRESENCE: u64 = 10;
/// How long a registration waits for the other device (§10's maximum).
const WAIT: Duration = Duration::from_secs(MAX_WAIT_SECONDS as u64);
/// After a relay error (not a missing peer), how long before trying that
/// contact again.
const ERROR_PAUSE: Duration = Duration::from_secs(30);
/// After a failed QR registration, how long before the next.
const QR_PAUSE: Duration = Duration::from_secs(5);

/// Which side of QR pairing this device is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Role {
    /// It scanned the code and initiates (§4).
    Scanner,
}

/// The relays this device uses, and what it is doing at them.
pub(super) struct Relays {
    client: RelayClient,
    endpoints: Vec<RelayEndpoint>,
    /// Rooms open now (at most two, §10).
    rooms: Cell<usize>,
    /// Contacts with a registration in progress.
    busy: RefCell<BTreeSet<Ed25519PublicKey>>,
    /// Contacts not to try before this monotonic time.
    paused: RefCell<BTreeMap<Ed25519PublicKey, Duration>>,
    /// The presence window last used for each contact.
    presence: RefCell<BTreeMap<Ed25519PublicKey, u64>>,
    /// Bumped whenever the QR offer shown changes or stops.
    qr_generation: Cell<u64>,
    /// How often an idle pair meets, in seconds.
    period: u64,
}

impl Relays {
    /// The relays of `configs`; `None` if there are none.
    ///
    /// # Errors
    ///
    /// [`StartError::Io`] with `InvalidInput` for a malformed pin or a name
    /// used twice; the I/O error if no UDP socket can be bound.
    pub(super) fn new(configs: &[RelayConfig], period: u32) -> Result<Option<Self>, StartError> {
        if configs.is_empty() {
            return Ok(None);
        }
        let invalid = || StartError::Io(std::io::ErrorKind::InvalidInput);
        let mut endpoints = Vec::with_capacity(configs.len());
        for config in configs {
            if endpoints
                .iter()
                .any(|known: &RelayEndpoint| known.name == config.name)
            {
                return Err(invalid());
            }
            let pin = match &config.pin {
                Some(pin) => Some(parse_pin(pin).ok_or_else(invalid)?),
                None => None,
            };
            endpoints.push(RelayEndpoint {
                name: config.name.clone(),
                address: config.address.clone(),
                server_name: config.server_name.clone(),
                pin,
            });
        }
        let client = RelayClient::new().map_err(|error| StartError::Io(error.kind()))?;
        Ok(Some(Self {
            client,
            endpoints,
            rooms: Cell::new(0),
            busy: RefCell::new(BTreeSet::new()),
            paused: RefCell::new(BTreeMap::new()),
            presence: RefCell::new(BTreeMap::new()),
            qr_generation: Cell::new(0),
            period: u64::from(period).max(MIN_PRESENCE),
        }))
    }

    /// A room, if fewer than two are open.
    fn take_room(&self) -> Option<RoomSlot<'_>> {
        let open = self.rooms.get();
        (open < MAX_ROOMS_PER_ENDPOINT).then(|| {
            self.rooms.set(open + 1);
            RoomSlot(&self.rooms)
        })
    }

    /// Meets the other holder of `token`.
    async fn meet(&self, token: RendezvousToken, wait: Duration) -> Result<RelayLink, RelayError> {
        let endpoint = choose(&self.endpoints, &token).ok_or(RelayError::Closed(
            todoke_proto::relay::CloseCode::Unavailable,
        ))?;
        self.client.rendezvous(endpoint, token, wait).await
    }
}

/// An open room, given back when dropped.
struct RoomSlot<'a>(&'a Cell<usize>);

impl Drop for RoomSlot<'_> {
    fn drop(&mut self) {
        self.0.set(self.0.get().saturating_sub(1));
    }
}

/// The presence window of a pair whose token is `token` at `now`, every
/// `period` seconds: its number, and the seconds left in it; `None`
/// outside it. A window lasts half the period, at most §10's 30-second
/// wait.
fn presence_window(token: &RendezvousToken, now: UnixTime, period: u64) -> Option<(u64, u64)> {
    let mut first = [0; 8];
    first.copy_from_slice(&token.as_bytes()[..8]);
    let offset = u64::from_be_bytes(first) % period;
    let shifted = now.seconds().saturating_add(period - offset);
    let phase = shifted % period;
    let window = u64::from(MAX_WAIT_SECONDS).min(period / 2);
    (phase < window).then(|| (shifted / period, window - phase))
}

impl State {
    /// Starts relay registrations for contacts that need one (see the
    /// module docs), at most two rooms at once.
    pub(super) fn relay_tick(self: &Rc<Self>, now: UnixTime) {
        let Some(relays) = &self.relay else {
            return;
        };
        let mono = self.mono();
        relays.paused.borrow_mut().retain(|_, until| *until > mono);
        let mut urgent = Vec::new();
        let mut present = Vec::new();
        {
            let table = self.table.borrow();
            let sessions = self.sessions.borrow();
            let queues = self.queues.borrow();
            let directory = self.directory.borrow();
            let busy = relays.busy.borrow();
            let paused = relays.paused.borrow();
            let presence = relays.presence.borrow();
            for peer in table.contacts() {
                if sessions.contains_key(peer)
                    || self.manager.is_busy(peer)
                    || busy.contains(peer)
                    || paused.contains_key(peer)
                {
                    continue;
                }
                let Some(token) = table
                    .rendezvous_token(peer)
                    .and_then(|token| RendezvousToken::new(*token).ok())
                else {
                    continue;
                };
                let waiting = queues
                    .get(peer)
                    .is_some_and(|queue| !queue.offers.is_empty() || !queue.prepared.is_empty());
                if waiting && directory.contact(peer, mono).is_none() {
                    urgent.push((*peer, token, WAIT, None));
                } else if let Some((window, left)) = presence_window(&token, now, relays.period)
                    && presence.get(peer) != Some(&window)
                {
                    present.push((*peer, token, Duration::from_secs(left), Some(window)));
                }
            }
        }
        for (peer, token, wait, window) in urgent.into_iter().chain(present) {
            if relays.rooms.get() >= MAX_ROOMS_PER_ENDPOINT {
                break;
            }
            if let Some(window) = window {
                relays.presence.borrow_mut().insert(peer, window);
            }
            relays.busy.borrow_mut().insert(peer);
            let state = Rc::clone(self);
            tokio::task::spawn_local(async move {
                state.meet_contact(peer, token, wait).await;
            });
        }
    }

    /// One registration for `peer`, and the session if it comes.
    async fn meet_contact(
        self: Rc<Self>,
        peer: Ed25519PublicKey,
        token: RendezvousToken,
        wait: Duration,
    ) {
        let Some(relays) = &self.relay else {
            return;
        };
        let met = match relays.take_room() {
            Some(_room) => relays.meet(token, wait).await,
            None => Err(RelayError::Closed(todoke_proto::relay::CloseCode::Full)),
        };
        relays.busy.borrow_mut().remove(&peer);
        match met {
            Ok(link) => self.contact_tunnel(peer, link).await,
            Err(RelayError::NoPeer) => {}
            Err(_) => {
                relays
                    .paused
                    .borrow_mut()
                    .insert(peer, self.mono() + ERROR_PAUSE);
            }
        }
    }

    /// A session with `peer` on a relay tunnel, in §4's roles: the smaller
    /// full device key initiates, the larger responds.
    async fn contact_tunnel(self: &Rc<Self>, peer: Ed25519PublicKey, link: RelayLink) {
        let ours = *self.identity.binding().device_public();
        if ours.as_bytes() < peer.as_bytes() {
            if let Ok(claim) = self.manager.claim_outgoing(peer) {
                let _ = self.initiate_on(peer, claim.with_link(link)).await;
            }
        } else {
            self.incoming(link).await;
        }
    }

    /// While the QR offer `payload` is shown, waits at the relay for its
    /// scanner and answers it (the displayer responds, §4).
    pub(super) fn display_qr_relay(self: &Rc<Self>, payload: &QrPayload) {
        let Some(relays) = &self.relay else {
            return;
        };
        let generation = relays.qr_generation.get().wrapping_add(1);
        relays.qr_generation.set(generation);
        let Some(token) = payload
            .rendezvous_token()
            .ok()
            .and_then(|token| RendezvousToken::new(*token.as_bytes()).ok())
        else {
            return;
        };
        let expires = payload.expires_at();
        let state = Rc::clone(self);
        tokio::task::spawn_local(async move {
            let Some(relays) = &state.relay else {
                return;
            };
            let shown = || {
                relays.qr_generation.get() == generation
                    && state.pairing.get() == Some(Pairing::Qr)
                    && wall() < expires
            };
            while shown() {
                let met = match relays.take_room() {
                    Some(_room) => relays.meet(token, WAIT).await,
                    None => Err(RelayError::Closed(todoke_proto::relay::CloseCode::Full)),
                };
                match met {
                    Ok(link) if shown() => state.incoming(link).await,
                    Ok(_) | Err(RelayError::NoPeer) => {}
                    Err(_) => tokio::time::sleep(QR_PAUSE).await,
                }
            }
        });
    }

    /// The QR offer is no longer shown: its relay wait stops.
    pub(super) fn stop_qr_relay(&self) {
        if let Some(relays) = &self.relay {
            relays
                .qr_generation
                .set(relays.qr_generation.get().wrapping_add(1));
        }
    }

    /// A tunnel to the displayer of `payload`, if relays are configured and
    /// it is waiting there.
    pub(super) async fn relay_for_qr(&self, payload: &QrPayload, role: Role) -> Option<RelayLink> {
        let Role::Scanner = role;
        let relays = self.relay.as_ref()?;
        let token = payload.rendezvous_token().ok()?;
        let token = RendezvousToken::new(*token.as_bytes()).ok()?;
        let _room = relays.take_room()?;
        relays.meet(token, WAIT).await.ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn token(first: u64) -> RendezvousToken {
        let mut bytes = [1; 32];
        bytes[..8].copy_from_slice(&first.to_be_bytes());
        RendezvousToken::new(bytes).unwrap_or_else(|_| unreachable!())
    }

    fn at(seconds: u64) -> UnixTime {
        UnixTime::new(seconds).unwrap_or_else(|| unreachable!())
    }

    /// Both devices of a pair find the same 30-second window every five
    /// minutes, at the offset of their token.
    #[test]
    fn presence_windows_follow_the_token() {
        const PERIOD: u64 = 300;
        let pair = token(1_000_000_007);
        let offset = 1_000_000_007 % PERIOD;
        let base = 1_800_000_000 - 1_800_000_000 % PERIOD;
        let start = base + offset;
        let window = |seconds| presence_window(&pair, at(seconds), PERIOD);
        assert_eq!(window(start).map(|(_, left)| left), Some(30));
        assert_eq!(window(start + 29).map(|(_, left)| left), Some(1));
        assert_eq!(window(start + 30), None);
        assert_eq!(window(start - 1), None);
        let (one, _) = window(start).unwrap_or_default();
        let (next, _) = window(start + PERIOD).unwrap_or_default();
        assert_eq!(next, one + 1);
        // Another pair's window is elsewhere.
        let other = token(1_000_000_007 + 100);
        assert_eq!(presence_window(&other, at(start), PERIOD), None);
        // A short period has a window of half of it.
        let short = presence_window(&pair, at(1_800_000_000), 10);
        assert!(short.is_none_or(|(_, left)| left <= 5));
    }
}
