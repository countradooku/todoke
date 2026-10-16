//! The app's state: what the core last said, driven by its event stream and
//! its answers. Pure (no window, no I/O); the views only read it, and every
//! change goes through [`Model::apply`] or [`Model::answer`].

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use todoke_core::api::{
    ContactInfo, Event, HistoryEntry, OfferInfo, Response, Route, StatusInfo, StrangerInfo,
    TransferInfo, TransferState, Way,
};
use zeroize::Zeroizing;

use crate::format;

/// How the app reaches the core.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Connection {
    /// Opening the profile or looking for a daemon.
    Starting,
    /// This app runs the core and serves it to the CLI.
    Hosted,
    /// A daemon runs the core; this app is its window.
    Attached,
    /// Sessions are disabled in this build (PROTOCOL §16 gates).
    Disabled,
    /// The core could not start: why, for people.
    Failed(String),
    /// The core stopped (`todoke daemon stop`, or the daemon went away).
    Stopped,
}

impl Connection {
    /// Whether requests can be made.
    #[must_use]
    pub const fn is_up(&self) -> bool {
        matches!(self, Self::Hosted | Self::Attached)
    }
}

/// How near a contact is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Proximity {
    /// On this network: transfers go directly.
    Direct,
    /// Reachable through a relay.
    Remote,
    /// Not seen, and no relay to meet at.
    Offline,
    /// Revoked, blocked, or uncertain: no session may start.
    Blocked,
}

impl Proximity {
    /// Its name for people.
    #[must_use]
    pub const fn label(self) -> &'static str {
        match self {
            Self::Direct => "Nearby",
            Self::Remote => "Through relay",
            Self::Offline => "Offline",
            Self::Blocked => "Blocked",
        }
    }
}

/// A pairing offer this device shows. `Debug` never prints the secret.
#[derive(Clone, Default, PartialEq, Eq)]
pub enum Pairing {
    /// None.
    #[default]
    Idle,
    /// Asked the core for one.
    Requested,
    /// A QR offer: its text is secret until used or expired (§3.1).
    Qr {
        /// The QR text.
        text: Zeroizing<String>,
        /// Unix seconds.
        expires_at: u64,
    },
    /// A code offer: secret until used or expired (§3.2).
    Code {
        /// The ten digits.
        code: Zeroizing<String>,
        /// Unix seconds.
        expires_at: u64,
    },
}

impl core::fmt::Debug for Pairing {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Idle => f.write_str("Idle"),
            Self::Requested => f.write_str("Requested"),
            Self::Qr { expires_at, .. } => {
                write!(f, "Qr {{ text: <redacted>, expires_at: {expires_at} }}")
            }
            Self::Code { expires_at, .. } => {
                write!(f, "Code {{ code: <redacted>, expires_at: {expires_at} }}")
            }
        }
    }
}

impl Pairing {
    /// When the offer shown expires, Unix seconds.
    #[must_use]
    pub const fn expires_at(&self) -> Option<u64> {
        match self {
            Self::Qr { expires_at, .. } | Self::Code { expires_at, .. } => Some(*expires_at),
            Self::Idle | Self::Requested => None,
        }
    }
}

/// How a notice reads.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Level {
    /// Something happened.
    Info,
    /// Something finished well.
    Success,
    /// Something failed.
    Error,
}

/// A short message for the user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Notice {
    /// Unique, for dismissing.
    pub id: u64,
    /// How it reads.
    pub level: Level,
    /// The text (never a secret or a raw peer-chosen string).
    pub text: String,
}

/// What to ask the core for after an event.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Fetch {
    /// The status.
    Status,
    /// The contacts.
    Contacts,
    /// The transfers.
    Transfers,
    /// Offers awaiting a decision.
    Offers,
    /// The history.
    History,
}

/// Everything, for a fresh start or after missed events.
pub const EVERYTHING: [Fetch; 5] = [
    Fetch::Status,
    Fetch::Contacts,
    Fetch::Transfers,
    Fetch::Offers,
    Fetch::History,
];

/// The most notices shown at once.
const MAX_NOTICES: usize = 4;

/// The app's state.
#[derive(Debug)]
pub struct Model {
    /// How the core is reached.
    pub connection: Connection,
    /// The core's status.
    pub status: Option<StatusInfo>,
    /// Paired devices.
    pub contacts: Vec<ContactInfo>,
    /// Whether any relay is configured (contacts away may be remote).
    pub relays: bool,
    /// Transfers by ID: active ones and the core's recent finished ones.
    pub transfers: BTreeMap<String, TransferInfo>,
    /// The last throughput of each moving transfer.
    pub speeds: BTreeMap<String, u64>,
    /// Received offers awaiting a decision, oldest first.
    pub offers: Vec<OfferInfo>,
    /// Finished transfers, newest first.
    pub history: Vec<HistoryEntry>,
    /// Nearby devices in stranger mode, for code pairing.
    pub strangers: Vec<StrangerInfo>,
    /// The pairing offer shown.
    pub pairing: Pairing,
    /// Notices, oldest first.
    pub notices: VecDeque<Notice>,
    /// Contacts selected for sending, by device key.
    pub selected: BTreeSet<String>,
    next_notice: u64,
}

impl Default for Model {
    fn default() -> Self {
        Self::new()
    }
}

impl Model {
    /// A model before the core answered.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            connection: Connection::Starting,
            status: None,
            contacts: Vec::new(),
            relays: false,
            transfers: BTreeMap::new(),
            speeds: BTreeMap::new(),
            offers: Vec::new(),
            history: Vec::new(),
            strangers: Vec::new(),
            pairing: Pairing::Idle,
            notices: VecDeque::new(),
            selected: BTreeSet::new(),
            next_notice: 0,
        }
    }

    /// Applies an event; returns what to fetch again.
    pub fn apply(&mut self, event: Event) -> Vec<Fetch> {
        match event {
            Event::Paired { contact } => {
                self.pairing = Pairing::Idle;
                let text = format!("Paired with {}", format::device(&contact));
                self.notify(Level::Success, text);
                vec![Fetch::Contacts, Fetch::Status]
            }
            Event::OfferReceived(offer) => {
                self.transfers.insert(
                    offer.transfer.clone(),
                    TransferInfo {
                        transfer: offer.transfer.clone(),
                        peer: offer.from.clone(),
                        way: Way::Incoming,
                        state: TransferState::AwaitingDecision,
                        detail: None,
                        bytes_done: 0,
                        bytes_total: offer.total_bytes,
                    },
                );
                self.offers.retain(|old| old.transfer != offer.transfer);
                self.offers.push(offer);
                Vec::new()
            }
            Event::Progress {
                transfer,
                way,
                done,
                total,
                bytes_per_second,
            } => {
                let entry =
                    self.transfers
                        .entry(transfer.clone())
                        .or_insert_with(|| TransferInfo {
                            transfer: transfer.clone(),
                            peer: String::new(),
                            way,
                            state: TransferState::Transferring,
                            detail: None,
                            bytes_done: 0,
                            bytes_total: total,
                        });
                entry.state = TransferState::Transferring;
                entry.bytes_done = done;
                entry.bytes_total = total;
                self.speeds.insert(transfer, bytes_per_second);
                // A transfer first seen here has no peer yet.
                if entry.peer.is_empty() {
                    vec![Fetch::Transfers]
                } else {
                    Vec::new()
                }
            }
            Event::Completed { transfer } => {
                let text = self.finish(&transfer, TransferState::Received, None);
                self.notify(Level::Success, text);
                vec![Fetch::History]
            }
            Event::Delivered { transfer } => {
                let text = self.finish(&transfer, TransferState::Delivered, None);
                self.notify(Level::Success, text);
                vec![Fetch::History]
            }
            Event::Ended {
                transfer,
                reason,
                message,
            } => {
                let text = self.finish(&transfer, reason, Some(&message));
                let level = if reason == TransferState::Failed {
                    Level::Error
                } else {
                    Level::Info
                };
                self.notify(level, text);
                vec![Fetch::History, Fetch::Transfers]
            }
            Event::Missed { .. } => EVERYTHING.to_vec(),
            // Pointing is for phones with UWB.
            Event::PointTarget(_) | Event::RangingRequested(_) | Event::RangingStopped { .. } => {
                Vec::new()
            }
        }
    }

    /// Records a transfer's end; returns the notice text.
    fn finish(&mut self, id: &str, state: TransferState, detail: Option<&str>) -> String {
        self.offers.retain(|offer| offer.transfer != id);
        self.speeds.remove(id);
        let peer = match self.transfers.get_mut(id) {
            Some(transfer) => {
                transfer.state = state;
                if state == TransferState::Received || state == TransferState::Delivered {
                    transfer.bytes_done = transfer.bytes_total;
                }
                if let Some(detail) = detail {
                    transfer.detail = Some(detail.to_owned());
                }
                format::device(&transfer.peer)
            }
            None => "a contact".to_owned(),
        };
        match state {
            TransferState::Received => format!("Received files from {peer}"),
            TransferState::Delivered => format!("Delivered to {peer}, receipt verified"),
            TransferState::Unconfirmed => format!("Sent to {peer}; delivery is unconfirmed"),
            TransferState::Rejected => format!("{peer} declined the transfer"),
            TransferState::Cancelled => format!("The transfer with {peer} was cancelled"),
            TransferState::Interrupted => {
                format!("The transfer with {peer} paused; it resumes when you reconnect")
            }
            _ => format!("The transfer with {peer} failed"),
        }
    }

    /// Takes in an answer to a fetch.
    pub fn answer(&mut self, response: Response) {
        match response {
            Response::Status(status) => self.status = Some(status),
            Response::Contacts(contacts) => {
                let known: BTreeSet<&String> = contacts.iter().map(|c| &c.device).collect();
                self.selected.retain(|device| known.contains(device));
                self.contacts = contacts;
            }
            Response::Transfers(transfers) => {
                self.transfers = transfers
                    .into_iter()
                    .map(|transfer| (transfer.transfer.clone(), transfer))
                    .collect();
                let moving: BTreeSet<&String> = self
                    .transfers
                    .values()
                    .filter(|t| t.state == TransferState::Transferring)
                    .map(|t| &t.transfer)
                    .collect();
                self.speeds.retain(|id, _| moving.contains(id));
            }
            Response::Offers(offers) => self.offers = offers,
            Response::History(history) => self.history = history,
            Response::Strangers(strangers) => self.strangers = strangers,
            Response::Qr { text, expires_at } => {
                self.pairing = Pairing::Qr {
                    text: Zeroizing::new(text),
                    expires_at,
                };
            }
            Response::Code { code, expires_at } => {
                self.pairing = Pairing::Code {
                    code: Zeroizing::new(code),
                    expires_at,
                };
            }
            // Errors may quote local file names: escaped like peer text.
            Response::Error { message, .. } => self.notify(Level::Error, format::name(&message)),
            Response::Done | Response::Paired { .. } | Response::Offered { .. } => {}
        }
    }

    /// Adds a notice; the oldest go past [`MAX_NOTICES`].
    pub fn notify(&mut self, level: Level, text: impl Into<String>) {
        self.next_notice += 1;
        self.notices.push_back(Notice {
            id: self.next_notice,
            level,
            text: text.into(),
        });
        while self.notices.len() > MAX_NOTICES {
            self.notices.pop_front();
        }
    }

    /// Dismisses a notice.
    pub fn dismiss(&mut self, id: u64) {
        self.notices.retain(|notice| notice.id != id);
    }

    /// How near `contact` is.
    #[must_use]
    pub const fn proximity(&self, contact: &ContactInfo) -> Proximity {
        if !contact.available {
            return Proximity::Blocked;
        }
        match contact.route {
            Some(Route::Lan | Route::Direct) => Proximity::Direct,
            Some(Route::Relay) => Proximity::Remote,
            None if contact.nearby => Proximity::Direct,
            None if self.relays => Proximity::Remote,
            None => Proximity::Offline,
        }
    }

    /// How the session with `peer` runs, if one is open.
    #[must_use]
    pub fn route_of(&self, peer: &str) -> Option<Route> {
        self.contacts
            .iter()
            .find(|contact| contact.device == peer)
            .and_then(|contact| contact.route)
    }

    /// Transfers not finished (an interrupted one resumes), newest IDs last.
    #[must_use]
    pub fn active(&self) -> Vec<&TransferInfo> {
        self.transfers
            .values()
            .filter(|t| !t.state.is_finished() && t.state != TransferState::AwaitingDecision)
            .collect()
    }

    /// The throughput of a moving transfer.
    #[must_use]
    pub fn speed(&self, id: &str) -> u64 {
        self.speeds.get(id).copied().unwrap_or(0)
    }

    /// Selects or deselects a contact for sending.
    pub fn toggle(&mut self, device: &str) {
        if !self.selected.remove(device) {
            self.selected.insert(device.to_owned());
        }
    }

    /// History entries matching `query` (case-insensitive) in a name, the
    /// peer, the transfer, the manifest hash, the receipt, or the state.
    #[must_use]
    pub fn search(&self, query: &str) -> Vec<&HistoryEntry> {
        let query = query.trim().to_lowercase();
        let compact: String = query.chars().filter(|c| !c.is_whitespace()).collect();
        self.history
            .iter()
            .filter(|entry| {
                if query.is_empty() {
                    return true;
                }
                let hexes = [
                    Some(entry.peer.as_str()),
                    Some(entry.transfer.as_str()),
                    entry.manifest_hash.as_deref(),
                    entry.receipt.as_ref().map(|receipt| receipt.id.as_str()),
                ];
                entry
                    .names
                    .iter()
                    .any(|name| format::name(name).to_lowercase().contains(&query))
                    || entry.state.as_str().contains(&query)
                    || (!compact.is_empty()
                        && hexes
                            .into_iter()
                            .flatten()
                            .any(|hex| hex.contains(&compact)))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use todoke_core::api::{EntryInfo, ReceiptInfo};

    use super::*;

    fn contact(device: &str, available: bool, nearby: bool, route: Option<Route>) -> ContactInfo {
        ContactInfo {
            device: device.into(),
            person: "pp".into(),
            available,
            nearby,
            connected: route.is_some(),
            route,
        }
    }

    fn offer(transfer: &str) -> OfferInfo {
        OfferInfo {
            transfer: transfer.into(),
            from: "aa11".into(),
            entries: vec![EntryInfo {
                id: 1,
                parent: 0,
                directory: false,
                name: "a.txt".into(),
                mime: "text/plain".into(),
                size: 10,
            }],
            total_bytes: 10,
            resume: None,
        }
    }

    #[test]
    fn proximity_follows_the_route_then_discovery_then_relays() {
        let mut model = Model::new();
        assert_eq!(
            model.proximity(&contact("a", true, false, Some(Route::Lan))),
            Proximity::Direct
        );
        assert_eq!(
            model.proximity(&contact("a", true, true, Some(Route::Relay))),
            Proximity::Remote
        );
        assert_eq!(
            model.proximity(&contact("a", true, true, None)),
            Proximity::Direct
        );
        assert_eq!(
            model.proximity(&contact("a", true, false, None)),
            Proximity::Offline
        );
        model.relays = true;
        assert_eq!(
            model.proximity(&contact("a", true, false, None)),
            Proximity::Remote
        );
        assert_eq!(
            model.proximity(&contact("a", false, true, Some(Route::Lan))),
            Proximity::Blocked
        );
    }

    #[test]
    fn an_offer_waits_until_it_ends() {
        let mut model = Model::new();
        assert_eq!(model.apply(Event::OfferReceived(offer("t1"))).len(), 0);
        model.apply(Event::OfferReceived(offer("t1")));
        assert_eq!(model.offers.len(), 1);
        assert_eq!(
            model.transfers.get("t1").map(|t| t.state),
            Some(TransferState::AwaitingDecision)
        );
        assert_eq!(model.active().len(), 0);
        let fetch = model.apply(Event::Ended {
            transfer: "t1".into(),
            reason: TransferState::Rejected,
            message: "declined".into(),
        });
        assert_eq!(fetch, [Fetch::History, Fetch::Transfers]);
        assert_eq!(model.offers.len(), 0);
        assert_eq!(
            model.notices.back().map(|n| n.text.as_str()),
            Some("Device AA11 declined the transfer")
        );
    }

    #[test]
    fn progress_moves_a_transfer_and_completion_clears_its_speed() {
        let mut model = Model::new();
        model.apply(Event::OfferReceived(offer("t1")));
        let fetch = model.apply(Event::Progress {
            transfer: "t1".into(),
            way: Way::Incoming,
            done: 4,
            total: 10,
            bytes_per_second: 2,
        });
        assert_eq!(fetch.len(), 0);
        assert_eq!(model.active().len(), 1);
        assert_eq!(model.speed("t1"), 2);
        // Unknown transfers are fetched for their peer.
        let unknown = model.apply(Event::Progress {
            transfer: "t2".into(),
            way: Way::Outgoing,
            done: 1,
            total: 2,
            bytes_per_second: 1,
        });
        assert_eq!(unknown, [Fetch::Transfers]);
        assert_eq!(
            model.apply(Event::Completed {
                transfer: "t1".into()
            }),
            [Fetch::History]
        );
        assert_eq!(model.speed("t1"), 0);
        assert_eq!(
            model.transfers.get("t1").map(|t| (t.state, t.bytes_done)),
            Some((TransferState::Received, 10))
        );
        assert_eq!(model.notices.back().map(|n| n.level), Some(Level::Success));
    }

    /// An interrupted transfer is not finished: it keeps its progress and
    /// stays listed as active, says why quietly, and moves again when it
    /// resumes. A failure is an error; an end for a transfer never seen
    /// still says something.
    #[test]
    fn an_interrupted_transfer_pauses_and_resumes() {
        let mut model = Model::new();
        model.apply(Event::OfferReceived(offer("t1")));
        let progress = |done| Event::Progress {
            transfer: "t1".into(),
            way: Way::Incoming,
            done,
            total: 10,
            bytes_per_second: 5,
        };
        model.apply(progress(4));
        let fetch = model.apply(Event::Ended {
            transfer: "t1".into(),
            reason: TransferState::Interrupted,
            message: "the connection dropped".into(),
        });
        assert_eq!(fetch, [Fetch::History, Fetch::Transfers]);
        assert_eq!(model.speed("t1"), 0);
        let paused = model.transfers.get("t1");
        assert_eq!(paused.map(|t| t.state), Some(TransferState::Interrupted));
        assert_eq!(paused.map(|t| t.bytes_done), Some(4), "progress is kept");
        assert_eq!(
            paused.and_then(|t| t.detail.as_deref()),
            Some("the connection dropped")
        );
        assert_eq!(model.active().len(), 1, "a paused transfer resumes");
        let notice = model.notices.back();
        assert_eq!(notice.map(|n| n.level), Some(Level::Info));
        assert!(
            notice.is_some_and(|n| n.text.contains("paused")),
            "{notice:?}"
        );
        model.apply(progress(6));
        assert_eq!(
            model.transfers.get("t1").map(|t| (t.state, t.bytes_done)),
            Some((TransferState::Transferring, 6))
        );
        assert_eq!(model.speed("t1"), 5);
        // A failure is an error, and its transfer leaves the active list.
        model.apply(Event::Ended {
            transfer: "t1".into(),
            reason: TransferState::Failed,
            message: "hash mismatch".into(),
        });
        assert_eq!(model.notices.back().map(|n| n.level), Some(Level::Error));
        assert_eq!(model.active().len(), 0);
        assert_eq!(model.speed("t1"), 0);
        // Never seen here: still reported, without inventing a transfer.
        model.apply(Event::Ended {
            transfer: "other".into(),
            reason: TransferState::Cancelled,
            message: String::new(),
        });
        assert_eq!(
            model.notices.back().map(|n| n.text.as_str()),
            Some("The transfer with a contact was cancelled")
        );
        assert!(!model.transfers.contains_key("other"));
    }

    #[test]
    fn missed_events_refetch_everything_and_notices_are_bounded() {
        let mut model = Model::new();
        assert_eq!(
            model.apply(Event::Missed { events: 3 }),
            EVERYTHING.to_vec()
        );
        for n in 0..10 {
            model.notify(Level::Info, format!("n{n}"));
        }
        assert_eq!(model.notices.len(), MAX_NOTICES);
        let first = model.notices.front().map(|n| n.id).unwrap_or_default();
        model.dismiss(first);
        assert_eq!(model.notices.len(), MAX_NOTICES - 1);
    }

    #[test]
    fn answers_replace_state_and_drop_stale_selections() {
        let mut model = Model::new();
        model.toggle("gone");
        model.toggle("kept");
        model.answer(Response::Contacts(vec![contact("kept", true, true, None)]));
        assert_eq!(model.selected.iter().collect::<Vec<_>>(), ["kept"]);
        model.toggle("kept");
        assert_eq!(model.selected.len(), 0);
        model.answer(Response::Code {
            code: "0123456789".into(),
            expires_at: 5,
        });
        assert!(matches!(model.pairing, Pairing::Code { expires_at: 5, .. }));
        // Pairing ends with the Paired event.
        model.apply(Event::Paired {
            contact: "beef".into(),
        });
        assert_eq!(model.pairing, Pairing::Idle);
        model.answer(Response::error(todoke_core::api::ErrorCode::State, "nope"));
        assert_eq!(model.notices.back().map(|n| n.level), Some(Level::Error));
    }

    #[test]
    fn pairing_secrets_never_reach_debug_output() {
        let mut model = Model::new();
        model.answer(Response::Qr {
            text: "TODOKE:SECRET".into(),
            expires_at: 9,
        });
        assert!(!format!("{model:?}").contains("SECRET"));
        model.answer(Response::Code {
            code: "0123456789".into(),
            expires_at: 9,
        });
        assert!(!format!("{model:?}").contains("0123456789"));
        assert_eq!(model.pairing.expires_at(), Some(9));
    }

    #[test]
    fn history_search_matches_names_hashes_and_states() {
        let mut model = Model::new();
        model.history = vec![HistoryEntry {
            transfer: "0011".into(),
            peer: "aabb".into(),
            way: Way::Incoming,
            state: TransferState::Received,
            detail: None,
            finished_at: 1,
            files: 1,
            bytes: 1,
            names: vec!["Holiday.JPG".into(), "evil\u{202e}gpj.exe".into()],
            manifest_hash: Some("c0ffee".into()),
            receipt: Some(ReceiptInfo {
                id: "deadbeef".into(),
                completed_at: 1,
            }),
        }];
        for query in ["holiday", "C0FF EE", "dead", "received", "aabb", "", "202e"] {
            assert_eq!(model.search(query).len(), 1, "{query}");
        }
        // Blank queries show everything; a partial state name matches.
        for query in ["   ", "\t", "rece"] {
            assert_eq!(model.search(query).len(), 1, "{query:?}");
        }
        for query in ["nothing", "delivered", "\u{202e}"] {
            assert_eq!(model.search(query).len(), 0, "{query}");
        }
    }
}
