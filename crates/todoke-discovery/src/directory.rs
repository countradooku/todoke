//! What discovery has seen recently, bounded against a hostile network.
//!
//! Each [`Sighting`] is matched against the current [`DiscoveryTable`]
//! when it arrives: a paired-mode record that matches no available contact
//! is dropped at once and never stored, so a flood of fake instances cannot
//! push real peers out. A matching sighting is kept per contact (at most
//! [`MAX_INSTANCES_PER_CONTACT`], least recently seen first out), and a
//! stranger-mode sighting only while stranger browsing is on, in a pool of
//! [`MAX_STRANGERS`]. Every entry expires [`CACHE_LIFETIME`] after it was
//! last seen (§9: cached data MUST expire within 120 seconds), and
//! sightings beyond [`MAX_SIGHTINGS_PER_SECOND`] are dropped unmatched
//! (§9: matching is rate-limited).
//!
//! A match is a candidate filter, not authentication (§9): every candidate
//! goes through a full authenticated session.

use core::time::Duration;
use std::collections::{BTreeMap, VecDeque};

use todoke_crypto::discovery::DiscoveryTable;
use todoke_crypto::identity::Ed25519PublicKey;
use todoke_proto::discovery::{DISCOVERY_TOKEN_LEN, DiscoveryMode, InstanceLabel};

use crate::sighting::Sighting;

/// How long an entry lives after it was last seen (§9).
pub const CACHE_LIFETIME: Duration = Duration::from_secs(120);
/// Instances kept per contact.
pub const MAX_INSTANCES_PER_CONTACT: usize = 4;
/// Stranger-mode instances kept while stranger browsing is on.
pub const MAX_STRANGERS: usize = 32;
/// Sightings matched per second; the rest are dropped.
pub const MAX_SIGHTINGS_PER_SECOND: u32 = 64;

/// What happened to a sighting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Observed {
    /// It matches a contact (or, for a stranger record, stranger browsing
    /// is on) and was stored or refreshed.
    Kept,
    /// It is one of this device's own advertisements.
    Own,
    /// A paired record that matches no available contact, or a stranger
    /// record while stranger browsing is off.
    Unmatched,
    /// Over the per-second matching budget.
    RateLimited,
}

#[derive(Clone, Debug)]
struct Entry {
    sighting: Sighting,
    seen: Duration,
}

/// A candidate peer: a contact or stranger token with its untrusted
/// addresses, most recently seen first.
#[derive(Clone, PartialEq, Eq)]
pub struct Reachable {
    addresses: Vec<std::net::SocketAddr>,
}

impl Reachable {
    /// The addresses, as LAN candidates for the transport race.
    #[cfg(not(target_family = "wasm"))]
    #[must_use]
    pub fn candidates(&self) -> Vec<todoke_transport::Candidate> {
        self.addresses
            .iter()
            .map(|address| {
                todoke_transport::Candidate::new(todoke_transport::LinkKind::Lan, *address)
            })
            .collect()
    }

    /// The addresses; untrusted.
    #[must_use]
    pub fn addresses(&self) -> &[std::net::SocketAddr] {
        &self.addresses
    }
}

impl core::fmt::Debug for Reachable {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Reachable")
            .field("addresses", &self.addresses.len())
            .finish()
    }
}

/// Recent sightings, bounded (see the module notes). Times are a monotonic
/// clock the caller keeps.
#[derive(Debug, Default)]
pub struct Directory {
    contacts: BTreeMap<Ed25519PublicKey, VecDeque<Entry>>,
    strangers: VecDeque<Entry>,
    stranger_browsing: bool,
    own: Vec<InstanceLabel>,
    window: Duration,
    in_window: u32,
}

impl Directory {
    /// An empty directory, stranger browsing off.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Turns stranger browsing on (while the user looks for a device to pair
    /// with) or off (dropping what it found).
    pub fn set_stranger_browsing(&mut self, on: bool) {
        self.stranger_browsing = on;
        if !on {
            self.strangers.clear();
        }
    }

    /// This device's own instance labels, which are never matched.
    pub fn set_own(&mut self, labels: Vec<InstanceLabel>) {
        self.contacts
            .values_mut()
            .for_each(|entries| entries.retain(|entry| !labels.contains(entry.sighting.label())));
        self.strangers
            .retain(|entry| !labels.contains(entry.sighting.label()));
        self.own = labels;
    }

    fn admit(&mut self, now: Duration) -> bool {
        let second = Duration::from_secs(now.as_secs());
        if second != self.window {
            self.window = second;
            self.in_window = 0;
        }
        if self.in_window >= MAX_SIGHTINGS_PER_SECOND {
            return false;
        }
        self.in_window += 1;
        true
    }

    /// Matches `sighting` against `table` and stores it if it is useful.
    pub fn observe(
        &mut self,
        sighting: Sighting,
        table: &DiscoveryTable,
        now: Duration,
    ) -> Observed {
        if self.own.contains(sighting.label()) {
            return Observed::Own;
        }
        if !self.admit(now) {
            return Observed::RateLimited;
        }
        let entry = |sighting| Entry {
            sighting,
            seen: now,
        };
        match sighting.record().mode() {
            DiscoveryMode::Paired => {
                let devices = table.candidates(sighting.record());
                if devices.is_empty() {
                    return Observed::Unmatched;
                }
                for device in devices {
                    let entries = self.contacts.entry(device).or_default();
                    replace(entries, entry(sighting.clone()), MAX_INSTANCES_PER_CONTACT);
                }
                Observed::Kept
            }
            DiscoveryMode::Stranger => {
                if !self.stranger_browsing {
                    return Observed::Unmatched;
                }
                replace(&mut self.strangers, entry(sighting), MAX_STRANGERS);
                Observed::Kept
            }
        }
    }

    /// Forgets an instance that said goodbye.
    pub fn remove(&mut self, label: &InstanceLabel) {
        for entries in self.contacts.values_mut() {
            entries.retain(|entry| entry.sighting.label() != label);
        }
        self.contacts.retain(|_, entries| !entries.is_empty());
        self.strangers
            .retain(|entry| entry.sighting.label() != label);
    }

    /// Drops entries last seen [`CACHE_LIFETIME`] ago or more, and contacts
    /// no longer in `table` (revoked, blocked, or re-paired).
    pub fn expire(&mut self, table: &DiscoveryTable, now: Duration) {
        let live = |entry: &Entry| now.saturating_sub(entry.seen) < CACHE_LIFETIME;
        let contacts: Vec<&Ed25519PublicKey> = table.contacts().collect();
        self.contacts.retain(|device, entries| {
            entries.retain(live);
            !entries.is_empty() && contacts.contains(&device)
        });
        self.strangers.retain(live);
    }

    /// Where `device` was seen, if it was recently.
    #[must_use]
    pub fn contact(&self, device: &Ed25519PublicKey, now: Duration) -> Option<Reachable> {
        reachable(self.contacts.get(device)?.iter(), now)
    }

    /// Every contact seen recently.
    #[must_use]
    pub fn contacts(&self, now: Duration) -> Vec<(Ed25519PublicKey, Reachable)> {
        self.contacts
            .iter()
            .filter_map(|(device, entries)| Some((*device, reachable(entries.iter(), now)?)))
            .collect()
    }

    /// Stranger-mode advertisements seen recently, by token, while stranger
    /// browsing is on. A token identifies nobody and authorizes nothing: it
    /// only selects whom to send a code-pairing request to (§3.2).
    #[must_use]
    pub fn strangers(&self, now: Duration) -> Vec<([u8; DISCOVERY_TOKEN_LEN], Reachable)> {
        let mut by_token: BTreeMap<[u8; DISCOVERY_TOKEN_LEN], Vec<&Entry>> = BTreeMap::new();
        for entry in &self.strangers {
            by_token
                .entry(*entry.sighting.record().token())
                .or_default()
                .push(entry);
        }
        by_token
            .into_iter()
            .filter_map(|(token, entries)| Some((token, reachable(entries.into_iter(), now)?)))
            .collect()
    }
}

/// Inserts `entry`, replacing an entry with the same label, evicting the
/// least recently seen beyond `max`.
fn replace(entries: &mut VecDeque<Entry>, entry: Entry, max: usize) {
    entries.retain(|existing| existing.sighting.label() != entry.sighting.label());
    entries.push_front(entry);
    entries.truncate(max);
}

/// The addresses of the live entries, most recently seen first, without
/// duplicates.
fn reachable<'a>(entries: impl Iterator<Item = &'a Entry>, now: Duration) -> Option<Reachable> {
    let mut live: Vec<&Entry> = entries
        .filter(|entry| now.saturating_sub(entry.seen) < CACHE_LIFETIME)
        .collect();
    live.sort_by_key(|entry| core::cmp::Reverse(entry.seen));
    let mut addresses = Vec::new();
    for entry in live {
        for address in entry.sighting.addresses() {
            if !addresses.contains(address) {
                addresses.push(*address);
            }
        }
    }
    (!addresses.is_empty()).then_some(Reachable { addresses })
}

#[cfg(all(test, not(target_family = "wasm")))]
mod tests;
