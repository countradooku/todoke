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
//! - Every available contact is also met at a presence window: half of
//!   the presence period (300 seconds by default), at most 30 seconds, at
//!   an offset both devices derive from the pair's token, so two idle
//!   devices show up at the same moment and a sender reaches a receiver
//!   within one period.
//! - A shown QR offer waits at the relay until it is used, stopped (which
//!   ends the wait at once), or expires; a scanner tries the relay after
//!   the nearby devices. While either is going on, contacts leave one room
//!   free for it.
//! - A tunnel that did not lead to a session (a relay answering for a
//!   peer that is not there) pauses that contact, doubling up to 16
//!   minutes; a relay error pauses it 30 seconds.
//!
//! A tunnel is accepted only for what it was opened for: a contact's
//! session, or QR pairing. Human-code pairing never uses a relay (§10,
//! §16 O8).

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
use super::running::{Origin, Pairing, State, wall};
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
/// The longest pause after tunnels that led to no session.
const MAX_FAILURE_PAUSE: Duration = Duration::from_mins(16);
/// How often a scanner looks for a free room.
const ROOM_POLL: Duration = Duration::from_millis(200);

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
    /// Of those, rooms held by contact registrations.
    contact_rooms: Cell<usize>,
    /// Contacts with a registration in progress.
    busy: RefCell<BTreeSet<Ed25519PublicKey>>,
    /// Contacts not to try before this monotonic time.
    paused: RefCell<BTreeMap<Ed25519PublicKey, Duration>>,
    /// Tunnels in a row that led to no session, by contact.
    failures: RefCell<BTreeMap<Ed25519PublicKey, u32>>,
    /// The presence window last used for each contact.
    presence: RefCell<BTreeMap<Ed25519PublicKey, u64>>,
    /// Bumped whenever the QR offer shown changes or stops.
    qr_generation: Cell<u64>,
    /// Wakes a QR wait when its offer stops.
    qr_cancel: tokio::sync::Notify,
    /// Ends the presence waits (hidden, or in the background).
    presence_cancel: tokio::sync::Notify,
    /// A scanner is waiting for a room.
    scanning: Cell<bool>,
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
            contact_rooms: Cell::new(0),
            busy: RefCell::new(BTreeSet::new()),
            paused: RefCell::new(BTreeMap::new()),
            failures: RefCell::new(BTreeMap::new()),
            presence: RefCell::new(BTreeMap::new()),
            qr_generation: Cell::new(0),
            qr_cancel: tokio::sync::Notify::new(),
            presence_cancel: tokio::sync::Notify::new(),
            scanning: Cell::new(false),
            period: u64::from(period).max(MIN_PRESENCE),
        }))
    }

    /// Meets the other holder of `token`.
    async fn meet(&self, token: RendezvousToken, wait: Duration) -> Result<RelayLink, RelayError> {
        let endpoint = choose(&self.endpoints, &token).ok_or(RelayError::Closed(
            todoke_proto::relay::CloseCode::Unavailable,
        ))?;
        self.client.rendezvous(endpoint, token, wait).await
    }
}

/// An open room, and for a contact its busy mark: both given back when
/// dropped, however the registration ends.
struct Claim {
    state: Rc<State>,
    peer: Option<Ed25519PublicKey>,
}

impl Drop for Claim {
    fn drop(&mut self) {
        if let Some(relays) = &self.state.relay {
            relays.rooms.set(relays.rooms.get().saturating_sub(1));
            if let Some(peer) = &self.peer {
                relays
                    .contact_rooms
                    .set(relays.contact_rooms.get().saturating_sub(1));
                relays.busy.borrow_mut().remove(peer);
            }
        }
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

/// The pause after `failures` tunnels in a row that led to no session.
fn failure_pause(failures: u32) -> Duration {
    ERROR_PAUSE
        .saturating_mul(1 << failures.min(6))
        .min(MAX_FAILURE_PAUSE)
}

impl State {
    /// A room for a registration, if one of §10's two is free; for a
    /// contact, also one of the `limit` contacts may hold, and its busy
    /// mark.
    fn claim_room(self: &Rc<Self>, peer: Option<Ed25519PublicKey>, limit: usize) -> Option<Claim> {
        let relays = self.relay.as_ref()?;
        if relays.rooms.get() >= MAX_ROOMS_PER_ENDPOINT
            || (peer.is_some() && relays.contact_rooms.get() >= limit)
        {
            return None;
        }
        relays.rooms.set(relays.rooms.get() + 1);
        if let Some(peer) = peer {
            relays.contact_rooms.set(relays.contact_rooms.get() + 1);
            relays.busy.borrow_mut().insert(peer);
        }
        Some(Claim {
            state: Rc::clone(self),
            peer,
        })
    }

    /// Rooms contacts may use now: one is kept free while a QR offer is
    /// shown or a scanner waits.
    fn contact_rooms(&self) -> usize {
        let qr = self.pairing.get() == Some(Pairing::Qr)
            || self
                .relay
                .as_ref()
                .is_some_and(|relays| relays.scanning.get());
        MAX_ROOMS_PER_ENDPOINT - usize::from(qr)
    }

    /// Starts relay registrations for contacts that need one (see the
    /// module docs), each holding one of at most two rooms from the start.
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
            // A table from another epoch has another epoch's tokens.
            if table.is_stale(now) {
                return;
            }
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
                } else if !self.hidden.get()
                    && !self.background.get()
                    && let Some((window, left)) = presence_window(&token, now, relays.period)
                    && presence.get(peer) != Some(&window)
                {
                    present.push((*peer, token, Duration::from_secs(left), Some(window)));
                }
            }
        }
        let limit = self.contact_rooms();
        for (peer, token, wait, window) in urgent.into_iter().chain(present) {
            // The room is taken now, so one tick never starts more
            // registrations than there are rooms.
            let Some(claim) = self.claim_room(Some(peer), limit) else {
                break;
            };
            if let Some(window) = window {
                relays.presence.borrow_mut().insert(peer, window);
            }
            let state = Rc::clone(self);
            let presence = window.is_some();
            tokio::task::spawn_local(async move {
                state.meet_contact(claim, peer, token, wait, presence).await;
            });
        }
    }

    /// One registration for `peer` (its room held by `claim`), and the
    /// session if it comes.
    async fn meet_contact(
        self: Rc<Self>,
        claim: Claim,
        peer: Ed25519PublicKey,
        token: RendezvousToken,
        wait: Duration,
        presence: bool,
    ) {
        let Some(relays) = &self.relay else {
            return;
        };
        let met = if presence {
            tokio::select! {
                met = relays.meet(token, wait) => met,
                () = relays.presence_cancel.notified() => return,
            }
        } else {
            relays.meet(token, wait).await
        };
        drop(claim);
        match met {
            Ok(link) => {
                let pause = if self.contact_tunnel(peer, link).await {
                    relays.failures.borrow_mut().remove(&peer);
                    None
                } else {
                    let mut failures = relays.failures.borrow_mut();
                    let count = failures.entry(peer).or_insert(0);
                    *count = count.saturating_add(1);
                    Some(failure_pause(*count))
                };
                if let Some(pause) = pause {
                    relays.paused.borrow_mut().insert(peer, self.mono() + pause);
                }
            }
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
    /// full device key initiates, the larger responds. Whether a session
    /// ran.
    async fn contact_tunnel(self: &Rc<Self>, peer: Ed25519PublicKey, link: RelayLink) -> bool {
        let ours = *self.identity.binding().device_public();
        if ours.as_bytes() < peer.as_bytes() {
            match self.manager.claim_outgoing(peer) {
                Ok(claim) => self.initiate_on(peer, claim.with_link(link)).await.is_ok(),
                Err(_) => false,
            }
        } else {
            self.incoming(link, Origin::RelayContact(peer)).await
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
                let Some(claim) = state.claim_room(None, MAX_ROOMS_PER_ENDPOINT) else {
                    tokio::time::sleep(ROOM_POLL).await;
                    continue;
                };
                let met = tokio::select! {
                    met = relays.meet(token, WAIT) => met,
                    () = relays.qr_cancel.notified() => break,
                };
                drop(claim);
                match met {
                    Ok(link) if shown() => {
                        if !state.incoming(link, Origin::RelayQr).await {
                            tokio::time::sleep(QR_PAUSE).await;
                        }
                    }
                    Ok(_) | Err(RelayError::NoPeer) => {}
                    Err(_) => tokio::time::sleep(QR_PAUSE).await,
                }
            }
        });
    }

    /// No more presence (hidden, or in the background): the presence waits
    /// at the relay end now; waits for contacts with sends waiting go on.
    pub(super) fn stop_presence(&self) {
        if let Some(relays) = &self.relay {
            relays.presence_cancel.notify_waiters();
        }
    }

    /// The QR offer is no longer shown: its relay wait ends now.
    pub(super) fn stop_qr_relay(&self) {
        if let Some(relays) = &self.relay {
            relays
                .qr_generation
                .set(relays.qr_generation.get().wrapping_add(1));
            relays.qr_cancel.notify_waiters();
        }
    }

    /// A tunnel to the displayer of `payload`, if relays are configured and
    /// it is waiting there. Waits for a room (contacts leave one free
    /// meanwhile) at most one registration's wait.
    pub(super) async fn relay_for_qr(
        self: &Rc<Self>,
        payload: &QrPayload,
        role: Role,
    ) -> Option<RelayLink> {
        let Role::Scanner = role;
        let relays = self.relay.as_ref()?;
        let token = payload.rendezvous_token().ok()?;
        let token = RendezvousToken::new(*token.as_bytes()).ok()?;
        relays.scanning.set(true);
        let deadline = tokio::time::Instant::now() + WAIT;
        let claim = loop {
            if let Some(claim) = self.claim_room(None, MAX_ROOMS_PER_ENDPOINT) {
                break Some(claim);
            }
            if tokio::time::Instant::now() >= deadline {
                break None;
            }
            tokio::time::sleep(ROOM_POLL).await;
        };
        relays.scanning.set(false);
        let _claim = claim?;
        // A connection that did not come up (a lost handshake) is tried
        // again while the displayer still waits.
        for _ in 0..3 {
            match relays.meet(token, WAIT).await {
                Ok(link) => return Some(link),
                Err(RelayError::Unreachable(_)) => {}
                Err(_) => return None,
            }
        }
        None
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

    /// Tunnels that lead to no session back off, doubling, to 16 minutes.
    #[test]
    fn failed_tunnels_back_off() {
        assert_eq!(failure_pause(1), Duration::from_mins(1));
        assert_eq!(failure_pause(2), Duration::from_mins(2));
        assert_eq!(failure_pause(5), Duration::from_mins(16));
        assert_eq!(failure_pause(40), MAX_FAILURE_PAUSE);
    }

    /// A state with one (unreachable) relay configured; nothing is sent.
    fn state(scratch: &std::path::Path) -> Result<Rc<State>, Box<dyn std::error::Error>> {
        let mut config =
            crate::config::CoreConfig::new(scratch.join("state"), scratch.join("downloads"));
        config.lan.enabled = false;
        config.relays = vec![RelayConfig {
            name: "none".into(),
            address: "127.0.0.1:9".into(),
            server_name: "relay.test".into(),
            pin: None,
        }];
        let key = crate::storage_key::KeyFile::new(scratch.join("storage.key"));
        let (events, _) = tokio::sync::broadcast::channel(4);
        Ok(State::open(config, &key, events)?)
    }

    /// §10: two rooms at once. While a QR offer is shown, contacts leave
    /// one room free for it, so a contact and the offer can wait together.
    #[tokio::test(flavor = "current_thread")]
    async fn a_shown_offer_and_one_contact_can_wait_together()
    -> Result<(), Box<dyn std::error::Error>> {
        let scratch = crate::profile::tests::Scratch::new("rooms-unit")?;
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async move {
                let state = state(&scratch.0)?;
                let own = *state.identity.binding().device_public();
                // No offer shown: contacts take two rooms, never a third.
                let one = state.claim_room(Some(own), state.contact_rooms());
                let two = state.claim_room(Some(own), state.contact_rooms());
                let three = state.claim_room(Some(own), state.contact_rooms());
                assert!(one.is_some() && two.is_some() && three.is_none());
                drop((one, two));
                // The offer is registered first, then a contact asks.
                state.pairing.set(Some(Pairing::Qr));
                let offer = state.claim_room(None, MAX_ROOMS_PER_ENDPOINT);
                let contact_room = state.claim_room(Some(own), state.contact_rooms());
                assert!(offer.is_some());
                assert!(
                    contact_room.is_some(),
                    "the offer's room starved the contact"
                );
                Ok(())
            })
            .await
    }

    fn config(name: &str, pin: Option<&str>) -> RelayConfig {
        RelayConfig {
            name: name.into(),
            address: "127.0.0.1:9".into(),
            server_name: "relay.test".into(),
            pin: pin.map(str::to_owned),
        }
    }

    /// The relay list is checked when the core starts: a name used twice
    /// (it is the rendezvous-hashing key, so two would split a pair) and a
    /// pin that is not exactly `spki-sha256:` and 64 hex digits are refused;
    /// and a presence period below 10 seconds is raised to 10.
    #[tokio::test(flavor = "current_thread")]
    async fn the_relay_list_is_validated() {
        let invalid = |result: Result<Option<Relays>, StartError>| {
            matches!(
                result,
                Err(StartError::Io(std::io::ErrorKind::InvalidInput))
            )
        };
        let pin = format!("spki-sha256:{}", "ab".repeat(32));
        assert!(matches!(Relays::new(&[], 300), Ok(None)));
        assert!(invalid(Relays::new(
            &[config("a", None), config("a", Some(&pin))],
            300
        )));
        for bad in ["spki-sha256:abcd", "sha256:00", &pin[..pin.len() - 1], ""] {
            assert!(
                invalid(Relays::new(&[config("a", Some(bad))], 300)),
                "{bad}"
            );
        }
        let list = [config("a", None), config("b", Some(&pin))];
        let relays = Relays::new(&list, 1);
        assert!(
            matches!(&relays, Ok(Some(relays)) if relays.period == MIN_PRESENCE
            && relays.endpoints.len() == 2 && relays.endpoints[1].pin == Some([0xab; 32]))
        );
    }

    /// A shown QR offer waits at the relay, and stopping it ends that wait
    /// at once, giving its room back (not after the 30-second wait).
    #[tokio::test(flavor = "current_thread")]
    async fn stopping_the_offer_ends_its_wait_at_the_relay()
    -> Result<(), Box<dyn std::error::Error>> {
        use crate::api::{Request, Response};
        let (identity, _, _) = todoke_relay::Identity::self_signed(vec!["relay.test".into()])?;
        let node = todoke_relay::Relay::bind(
            todoke_relay::Config::new(([127, 0, 0, 1], 0).into()),
            &identity,
        )?;
        let (counters, address) = (node.metrics(), node.local_addr()?);
        tokio::spawn(node.run(std::sync::Arc::new(tokio::sync::Notify::new())));
        let scratch = crate::profile::tests::Scratch::new("qr-stop")?;
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async move {
                let mut config = crate::config::CoreConfig::new(
                    scratch.0.join("state"),
                    scratch.0.join("downloads"),
                );
                config.lan.enabled = false;
                config.relays = vec![RelayConfig {
                    name: "node".into(),
                    address: address.to_string(),
                    server_name: "relay.test".into(),
                    pin: Some(todoke_relay::format_pin(&identity.pin()?)),
                }];
                let key = crate::storage_key::KeyFile::new(scratch.0.join("storage.key"));
                let (events, _) = tokio::sync::broadcast::channel(4);
                let state = State::open(config, &key, events)?;
                let rooms = || state.relay.as_ref().map_or(99, |relays| relays.rooms.get());
                assert!(matches!(
                    state.handle(Request::PairShowQr).await,
                    Response::Qr { .. }
                ));
                let waiting = async {
                    while counters
                        .registers
                        .load(std::sync::atomic::Ordering::Relaxed)
                        == 0
                    {
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                };
                tokio::time::timeout(Duration::from_secs(5), waiting).await?;
                assert_eq!(rooms(), 1);
                assert_eq!(state.handle(Request::StopPairing).await, Response::Done);
                let freed = async {
                    while rooms() != 0 {
                        tokio::time::sleep(Duration::from_millis(20)).await;
                    }
                };
                tokio::time::timeout(Duration::from_secs(1), freed).await?;
                Ok(())
            })
            .await
    }

    type Counters = std::sync::Arc<todoke_relay::Metrics>;

    /// A relay node on loopback and a LAN-less core using it.
    fn with_relay(
        scratch: &std::path::Path,
    ) -> Result<(Rc<State>, Counters), Box<dyn std::error::Error>> {
        let (identity, _, _) = todoke_relay::Identity::self_signed(vec!["relay.test".into()])?;
        let node = todoke_relay::Relay::bind(
            todoke_relay::Config::new(([127, 0, 0, 1], 0).into()),
            &identity,
        )?;
        let (counters, address) = (node.metrics(), node.local_addr()?);
        tokio::spawn(node.run(std::sync::Arc::new(tokio::sync::Notify::new())));
        let mut config =
            crate::config::CoreConfig::new(scratch.join("state"), scratch.join("downloads"));
        config.lan.enabled = false;
        config.relays = vec![RelayConfig {
            name: "node".into(),
            address: address.to_string(),
            server_name: "relay.test".into(),
            pin: Some(todoke_relay::format_pin(&identity.pin()?)),
        }];
        let key = crate::storage_key::KeyFile::new(scratch.join("storage.key"));
        let (events, _) = tokio::sync::broadcast::channel(4);
        Ok((State::open(config, &key, events)?, counters))
    }

    /// Waits up to `limit` for `done`.
    async fn until(limit: Duration, done: impl Fn() -> bool) -> bool {
        tokio::time::timeout(limit, async {
            while !done() {
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .is_ok()
    }

    /// In the background (§10.3) a shown QR offer's wait at the relay ends
    /// at once, and pairing is refused until the app is back.
    #[tokio::test(flavor = "current_thread")]
    async fn the_background_ends_the_qr_wait_at_the_relay() -> Result<(), Box<dyn std::error::Error>>
    {
        use crate::api::{ErrorCode, Request, Response};
        let scratch = crate::profile::tests::Scratch::new("qr-background")?;
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async move {
                let (state, counters) = with_relay(&scratch.0)?;
                let rooms = || state.relay.as_ref().map_or(99, |relays| relays.rooms.get());
                assert!(matches!(
                    state.handle(Request::PairShowQr).await,
                    Response::Qr { .. }
                ));
                let registered = || {
                    counters
                        .registers
                        .load(std::sync::atomic::Ordering::Relaxed)
                        > 0
                };
                assert!(until(Duration::from_secs(5), registered).await);
                assert_eq!(rooms(), 1);
                assert_eq!(
                    state
                        .handle(Request::SetBackground { background: true })
                        .await,
                    Response::Done
                );
                assert!(until(Duration::from_secs(1), || rooms() == 0).await);
                assert!(matches!(
                    state.handle(Request::PairShowQr).await,
                    Response::Error {
                        code: ErrorCode::Pairing,
                        ..
                    }
                ));
                assert_eq!(
                    state
                        .handle(Request::SetBackground { background: false })
                        .await,
                    Response::Done
                );
                assert!(matches!(
                    state.handle(Request::PairShowQr).await,
                    Response::Qr { .. }
                ));
                Ok(())
            })
            .await
    }

    /// Ending presence (hidden, or the background) ends a presence wait at
    /// the relay at once, giving its room back; a wait for a contact with
    /// sends waiting goes on.
    #[tokio::test(flavor = "current_thread")]
    async fn ending_presence_ends_only_presence_waits() -> Result<(), Box<dyn std::error::Error>> {
        let scratch = crate::profile::tests::Scratch::new("presence-stop")?;
        let local = tokio::task::LocalSet::new();
        local
            .run_until(async move {
                let (state, counters) = with_relay(&scratch.0)?;
                let rooms = || state.relay.as_ref().map_or(99, |relays| relays.rooms.get());
                let registers = || {
                    counters
                        .registers
                        .load(std::sync::atomic::Ordering::Relaxed)
                };
                let peer = *state.identity.binding().device_public();
                for (presence, first) in [(true, 1), (false, 2)] {
                    let before = registers();
                    let claim = state.claim_room(Some(peer), 2).ok_or("no room")?;
                    tokio::task::spawn_local(Rc::clone(&state).meet_contact(
                        claim,
                        peer,
                        token(first),
                        WAIT,
                        presence,
                    ));
                    assert!(until(Duration::from_secs(5), || registers() > before).await);
                    assert_eq!(rooms(), 1);
                    state.stop_presence();
                    let freed = until(Duration::from_secs(1), || rooms() == 0).await;
                    assert_eq!(freed, presence, "presence {presence}");
                    if !presence {
                        // The urgent wait is left to run out (30 s): the
                        // test ends here, dropping it.
                        break;
                    }
                }
                Ok(())
            })
            .await
    }
}
