//! What discovery has seen recently, bounded against a hostile network.
//!
//! Each [`Sighting`] is matched against the current [`DiscoveryTable`]
//! when it arrives: a paired-mode record that matches no available contact
//! is dropped at once and never stored, so random fake instances cannot
//! push real peers out. A matching sighting is kept per contact, at most
//! [`MAX_INSTANCES_PER_CONTACT`]: the longest-known live instances stay and
//! a newcomer is dropped while they are full, and candidates come out
//! longest-known first. A pair token is public within its epoch, so anyone
//! can copy a contact's record under other addresses; an instance that was
//! there first is not displaced by copies that come later, and the
//! authenticated session rejects whatever answers at a copied address.
//! Stranger-mode sightings are kept only while stranger browsing is on, in
//! a pool of [`MAX_STRANGERS`] (newest first: a device that just started
//! pairing is new). Every entry expires [`CACHE_LIFETIME`] after it was last
//! seen (§9: cached data MUST expire within 120 seconds). At most
//! [`MAX_SIGHTINGS_PER_SECOND`] matching sightings are stored or refreshed
//! each second (§9: matching is rate-limited); records that match nothing
//! cost one table lookup and use none of that budget.
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
/// Matching sightings stored or refreshed per second; the rest are dropped.
pub const MAX_SIGHTINGS_PER_SECOND: u32 = 64;

/// What happened to a sighting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Observed {
    /// It matches a contact (or, for a stranger record, stranger browsing
    /// is on) and was stored or refreshed.
    Kept,
    /// It matches a contact whose instances are full of longer-known ones.
    Full,
    /// It is one of this device's own advertisements.
    Own,
    /// A paired record that matches no available contact, or a stranger
    /// record while stranger browsing is off.
    Unmatched,
    /// Over the per-second matching budget.
    RateLimited,
}

#[derive(Clone)]
struct Entry {
    sighting: Sighting,
    /// When this label was first seen (it stays while it is refreshed).
    first: Duration,
    /// When it was last seen.
    seen: Duration,
}

/// A candidate peer: a contact or stranger token with its untrusted
/// addresses, longest known first.
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
#[derive(Default)]
pub struct Directory {
    contacts: BTreeMap<Ed25519PublicKey, VecDeque<Entry>>,
    strangers: VecDeque<Entry>,
    stranger_browsing: bool,
    own: Vec<InstanceLabel>,
    window: Duration,
    in_window: u32,
}

/// Devices, labels, and addresses are left out (§14.2).
impl core::fmt::Debug for Directory {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Directory")
            .field("contacts", &self.contacts.len())
            .field("strangers", &self.strangers.len())
            .field("stranger_browsing", &self.stranger_browsing)
            .finish_non_exhaustive()
    }
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
        match sighting.record().mode() {
            DiscoveryMode::Paired => {
                let devices = table.candidates(sighting.record());
                if devices.is_empty() {
                    return Observed::Unmatched;
                }
                if !self.admit(now) {
                    return Observed::RateLimited;
                }
                let mut outcome = Observed::Full;
                for device in devices {
                    let entries = self.contacts.entry(device).or_default();
                    if keep_oldest(entries, &sighting, now) {
                        outcome = Observed::Kept;
                    }
                }
                self.contacts.retain(|_, entries| !entries.is_empty());
                outcome
            }
            DiscoveryMode::Stranger => {
                if !self.stranger_browsing {
                    return Observed::Unmatched;
                }
                if !self.admit(now) {
                    return Observed::RateLimited;
                }
                keep_newest(&mut self.strangers, sighting, now, MAX_STRANGERS);
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

/// Refreshes `sighting`'s entry if its label is known; otherwise adds it
/// if there is room after dropping expired entries. Returns whether it is
/// stored. Live entries are never displaced by a newcomer.
fn keep_oldest(entries: &mut VecDeque<Entry>, sighting: &Sighting, now: Duration) -> bool {
    entries.retain(|entry| now.saturating_sub(entry.seen) < CACHE_LIFETIME);
    if let Some(entry) = entries
        .iter_mut()
        .find(|entry| entry.sighting.label() == sighting.label())
    {
        entry.sighting = sighting.clone();
        entry.seen = now;
        return true;
    }
    if entries.len() >= MAX_INSTANCES_PER_CONTACT {
        return false;
    }
    entries.push_back(Entry {
        sighting: sighting.clone(),
        first: now,
        seen: now,
    });
    true
}

/// Inserts `sighting`, replacing an entry with the same label (keeping when
/// it was first seen), evicting the least recently seen beyond `max`.
fn keep_newest(entries: &mut VecDeque<Entry>, sighting: Sighting, now: Duration, max: usize) {
    let first = entries
        .iter()
        .find(|entry| entry.sighting.label() == sighting.label())
        .map_or(now, |entry| entry.first);
    entries.retain(|existing| existing.sighting.label() != sighting.label());
    entries.push_front(Entry {
        sighting,
        first,
        seen: now,
    });
    entries.truncate(max);
}

/// The addresses of the live entries, longest known first, without
/// duplicates.
fn reachable<'a>(entries: impl Iterator<Item = &'a Entry>, now: Duration) -> Option<Reachable> {
    let mut live: Vec<&Entry> = entries
        .filter(|entry| now.saturating_sub(entry.seen) < CACHE_LIFETIME)
        .collect();
    live.sort_by_key(|entry| entry.first);
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
