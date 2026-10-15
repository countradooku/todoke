//! Discovery state derived from committed pairings (PROTOCOL §4.4, §9).
//!
//! For each available contact, from its committed pair PSK:
//!
//! ```text
//! pair_secret      = HKDF(empty, psk, "todoke/v1/pair-secret\0", 32)
//! pair_key         = HKDF(empty, pair_secret, "todoke/v1/discovery-key\0", 32)
//! token            = HMAC-BLAKE3(pair_key, epoch:u64)[..8]
//! rendezvous_token = HKDF(epoch:u64, pair_secret, "todoke/v1/rendezvous\0", 32)
//! locator          = rendezvous_token[..16]   (contact Hello, §4.1)
//! ```
//!
//! A [`DiscoveryTable`] holds, for the current epoch and its neighbours,
//! only the derived tokens and locators, never `pair_secret`, `pair_key`,
//! or the PSK. It is derived afresh from the store's committed state, so
//! state from an earlier ratchet generation is gone as soon as a new table
//! is built after the commit (§9): callers rebuild it at every epoch
//! boundary and after every committed session.
//!
//! A match is a candidate filter, not authentication: the 64-bit token can
//! collide or be replayed within its epoch, so every candidate goes through
//! the full authenticated session (§9).
//!
//! # Secret residue (O6)
//!
//! `pair_secret` and `pair_key` live in `Zeroizing` buffers. The HMAC comes
//! from `RustCrypto`'s `hmac` 0.13 (`SimpleHmac`), which keeps `pair_key`
//! XOR opad and a BLAKE3 state absorbed with `pair_key` XOR ipad in fields
//! it does not wipe on drop; the HKDF has the libcrux stack residue noted
//! in `session::kdf`. These are recorded with the suite's other unwiped
//! temporaries under PROTOCOL §16 O6 rather than worked around with a
//! hand-written HMAC. Exposure is bounded: `pair_key` serves only discovery
//! (whoever holds it can recognise and forge the pair's tokens, which
//! authorize nothing) and is replaced at every committed session.

use core::fmt;
use std::collections::BTreeMap;

use hmac::{KeyInit as _, Mac as _, SimpleHmac};
use todoke_proto::discovery::{DISCOVERY_TOKEN_LEN, DiscoveryMode, DiscoveryRecord, Epoch};
use todoke_proto::time::UnixTime;
use zeroize::Zeroizing;

use crate::identity::{BlobStorage, ContactStore, Ed25519PublicKey, Sealer};
use crate::session::kdf::{self, KdfError};

/// Length of a contact locator, the rendezvous-token prefix carried in a
/// contact Hello (§4.1, §9).
pub const LOCATOR_LEN: usize = 16;

const RENDEZVOUS_INFO: &[u8] = b"todoke/v1/rendezvous\0";

/// A derivation failed inside libcrux or the HMAC; unreachable for these
/// fixed lengths, and fails closed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DiscoveryError;

impl fmt::Display for DiscoveryError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("discovery state derivation failed")
    }
}

impl std::error::Error for DiscoveryError {}

impl From<KdfError> for DiscoveryError {
    fn from(_: KdfError) -> Self {
        Self
    }
}

/// `HMAC-BLAKE3(key, counter:u64)[..8]`: RFC 2104 HMAC over unkeyed
/// BLAKE3 (64-byte block, 32-byte output), not BLAKE3 keyed mode (§1).
/// The paired token (§9, `counter` the epoch) and the QR stranger token
/// (`counter` the minute).
pub(crate) fn hmac_blake3_token(
    key: &[u8; 32],
    counter: u64,
) -> Result<[u8; DISCOVERY_TOKEN_LEN], DiscoveryError> {
    let mut mac = SimpleHmac::<blake3::Hasher>::new_from_slice(key).map_err(|_| DiscoveryError)?;
    mac.update(&counter.to_be_bytes());
    let tag = Zeroizing::new(<[u8; 32]>::from(mac.finalize().into_bytes()));
    let mut token = [0; DISCOVERY_TOKEN_LEN];
    token.copy_from_slice(&tag[..DISCOVERY_TOKEN_LEN]);
    Ok(token)
}

/// One contact's discovery keys, held only while a table is built.
struct PairKeys {
    pair_secret: Zeroizing<[u8; 32]>,
    pair_key: Zeroizing<[u8; 32]>,
}

impl PairKeys {
    fn derive(committed_psk: &[u8; 32]) -> Result<Self, DiscoveryError> {
        let pair_secret = kdf::pair_secret(committed_psk)?;
        let pair_key = kdf::discovery_key(&pair_secret)?;
        Ok(Self {
            pair_secret,
            pair_key,
        })
    }

    /// `HMAC-BLAKE3(pair_key, epoch:u64)[..8]`.
    fn token(&self, epoch: Epoch) -> Result<[u8; DISCOVERY_TOKEN_LEN], DiscoveryError> {
        hmac_blake3_token(&self.pair_key, epoch.get())
    }

    /// `HKDF(epoch:u64, pair_secret, "todoke/v1/rendezvous\0", 32)`.
    fn rendezvous_token(&self, epoch: Epoch) -> Result<Zeroizing<[u8; 32]>, DiscoveryError> {
        Ok(kdf::hkdf_sha256(
            &epoch.get().to_be_bytes(),
            self.pair_secret.as_slice(),
            RENDEZVOUS_INFO,
        )?)
    }

    fn locator(&self, epoch: Epoch) -> Result<[u8; LOCATOR_LEN], DiscoveryError> {
        let token = self.rendezvous_token(epoch)?;
        let mut locator = [0; LOCATOR_LEN];
        locator.copy_from_slice(&token[..LOCATOR_LEN]);
        Ok(locator)
    }
}

/// One contact's tokens and locators for the table's epochs.
#[derive(Clone, PartialEq, Eq)]
struct ContactEntry {
    /// The pair generation the entries were derived at (§4.4).
    generation: u64,
    /// `(epoch, token)` for the previous, current, and next epochs.
    tokens: Vec<(Epoch, [u8; DISCOVERY_TOKEN_LEN])>,
    /// `(epoch, locator)` for the same epochs.
    locators: Vec<(Epoch, [u8; LOCATOR_LEN])>,
    /// The rendezvous token of the table's own epoch (§10).
    rendezvous: Zeroizing<[u8; 32]>,
}

/// Discovery tokens and contact locators of every available contact, for
/// one local epoch and its neighbours (§9), and each contact's rendezvous
/// token for that epoch (§10). Holds no key material: the tokens are what
/// relays and the network may see.
#[derive(Clone, PartialEq, Eq)]
pub struct DiscoveryTable {
    epoch: Epoch,
    contacts: BTreeMap<Ed25519PublicKey, ContactEntry>,
    /// Token to the contacts whose token it is in some table epoch; more
    /// than one only on a collision.
    by_token: BTreeMap<[u8; DISCOVERY_TOKEN_LEN], Vec<(Epoch, Ed25519PublicKey)>>,
    by_locator: BTreeMap<[u8; LOCATOR_LEN], Vec<Ed25519PublicKey>>,
}

impl DiscoveryTable {
    fn build<'a>(
        now: UnixTime,
        contacts: impl Iterator<Item = (Ed25519PublicKey, &'a [u8; 32], u64)>,
    ) -> Result<Self, DiscoveryError> {
        let epoch = Epoch::of(now);
        let mut table = Self {
            epoch,
            contacts: BTreeMap::new(),
            by_token: BTreeMap::new(),
            by_locator: BTreeMap::new(),
        };
        for (device, psk, generation) in contacts {
            let keys = PairKeys::derive(psk)?;
            let mut entry = ContactEntry {
                generation,
                tokens: Vec::with_capacity(3),
                locators: Vec::with_capacity(3),
                rendezvous: keys.rendezvous_token(epoch)?,
            };
            for at in epoch.adjacent() {
                let token = keys.token(at)?;
                let locator = keys.locator(at)?;
                entry.tokens.push((at, token));
                entry.locators.push((at, locator));
                table.by_token.entry(token).or_default().push((at, device));
                let owners = table.by_locator.entry(locator).or_default();
                if !owners.contains(&device) {
                    owners.push(device);
                }
            }
            table.contacts.insert(device, entry);
        }
        Ok(table)
    }

    /// A table at `now` for `contacts` (device, committed pair PSK,
    /// generation), as [`ContactStore::discovery_table`] builds it. For the
    /// matching benchmark only (the `bench-support` feature): a shipped
    /// table comes from the contact store.
    ///
    /// # Errors
    ///
    /// [`DiscoveryError`] if a derivation fails.
    #[cfg(feature = "bench-support")]
    pub fn from_pair_psks<'a>(
        now: UnixTime,
        contacts: impl IntoIterator<Item = (Ed25519PublicKey, &'a [u8; 32], u64)>,
    ) -> Result<Self, DiscoveryError> {
        Self::build(now, contacts.into_iter())
    }

    /// `device`'s rendezvous token for the table's epoch (§9, §10): what
    /// both devices register with at a relay to meet. Linkable within the
    /// epoch, and seen by the relay; it authenticates nothing.
    #[must_use]
    pub fn rendezvous_token(&self, device: &Ed25519PublicKey) -> Option<Zeroizing<[u8; 32]>> {
        self.contacts
            .get(device)
            .map(|entry| entry.rendezvous.clone())
    }

    /// The local epoch the table was built for.
    #[must_use]
    pub const fn epoch(&self) -> Epoch {
        self.epoch
    }

    /// Whether the table no longer covers `now`'s epoch and must be rebuilt.
    #[must_use]
    pub fn is_stale(&self, now: UnixTime) -> bool {
        Epoch::of(now) != self.epoch
    }

    /// How many contacts the table covers.
    #[must_use]
    pub fn len(&self) -> usize {
        self.contacts.len()
    }

    /// Whether the table covers no contact.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.contacts.is_empty()
    }

    /// The pair generation `device`'s entries were derived at. A table is
    /// current for a contact only while the store's generation for it is
    /// the same: every committed session moves it on, and state from an
    /// earlier generation must not stay in use (§9).
    #[must_use]
    pub fn generation(&self, device: &Ed25519PublicKey) -> Option<u64> {
        self.contacts.get(device).map(|entry| entry.generation)
    }

    /// The contacts in the table, in key order.
    pub fn contacts(&self) -> impl Iterator<Item = &Ed25519PublicKey> {
        self.contacts.keys()
    }

    /// The contacts a paired-mode record may be from: its claimed epoch is
    /// the local epoch or a neighbour, and its token is that contact's token
    /// for exactly that epoch. Usually none or one; more on a token
    /// collision, each of which needs its own authenticated session (§9).
    /// A stranger-mode record matches nobody.
    #[must_use]
    pub fn candidates(&self, record: &DiscoveryRecord) -> Vec<Ed25519PublicKey> {
        if record.mode() != DiscoveryMode::Paired {
            return Vec::new();
        }
        let claimed = record.epoch();
        if !self.epoch.adjacent().any(|epoch| epoch == claimed) {
            return Vec::new();
        }
        self.by_token
            .get(record.token())
            .map(|owners| {
                owners
                    .iter()
                    .filter(|(epoch, _)| *epoch == claimed)
                    .map(|(_, device)| *device)
                    .collect()
            })
            .unwrap_or_default()
    }

    /// The contacts a contact Hello's locator may name, for the local epoch
    /// or a neighbour (§4.1). More than one only on a collision; the
    /// handshake then decides.
    #[must_use]
    pub fn resolve_locator(&self, locator: &[u8; LOCATOR_LEN]) -> &[Ed25519PublicKey] {
        self.by_locator.get(locator).map_or(&[], Vec::as_slice)
    }

    /// The record to advertise for `device` in the local epoch, if it is
    /// in the table.
    #[must_use]
    pub fn advertisement(&self, device: &Ed25519PublicKey) -> Option<DiscoveryRecord> {
        let token = self.token_at(device, self.epoch)?;
        // An all-zero token (probability 2^-64) cannot be advertised.
        DiscoveryRecord::new(DiscoveryMode::Paired, self.epoch, token).ok()
    }

    /// The locator an initiator puts in its contact Hello for `device`: the
    /// local epoch's (§4.1).
    #[must_use]
    pub fn locator(&self, device: &Ed25519PublicKey) -> Option<[u8; LOCATOR_LEN]> {
        self.contacts
            .get(device)?
            .locators
            .iter()
            .find_map(|(epoch, locator)| (*epoch == self.epoch).then_some(*locator))
    }

    fn token_at(&self, device: &Ed25519PublicKey, at: Epoch) -> Option<[u8; DISCOVERY_TOKEN_LEN]> {
        self.contacts
            .get(device)?
            .tokens
            .iter()
            .find_map(|(epoch, token)| (*epoch == at).then_some(*token))
    }
}

/// Redacted: tokens and locators link a device pair within an epoch.
impl fmt::Debug for DiscoveryTable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DiscoveryTable")
            .field("epoch", &self.epoch)
            .field("contacts", &self.contacts.len())
            .finish_non_exhaustive()
    }
}

impl<S: Sealer, B: BlobStorage> ContactStore<S, B> {
    /// The discovery table for `now` over every contact that may start a
    /// session now ([`Self::availability`]): a revoked, blocked, or
    /// ratchet-uncertain contact is neither advertised nor matched.
    ///
    /// # Errors
    ///
    /// [`DiscoveryError`] if a derivation fails (fails closed: no table).
    pub fn discovery_table(&self, now: UnixTime) -> Result<DiscoveryTable, DiscoveryError> {
        // `handshake_inputs` refuses every contact that is not available.
        let available: Vec<(Ed25519PublicKey, Zeroizing<[u8; 32]>, u64)> = self
            .contacts()
            .map(|contact| *contact.pinned().device_public())
            .filter_map(|device| {
                self.handshake_inputs(&device)
                    .ok()
                    .map(|inputs| (device, inputs.psk, inputs.generation))
            })
            .collect();
        DiscoveryTable::build(
            now,
            available
                .iter()
                .map(|(device, psk, generation)| (*device, &**psk, *generation)),
        )
    }
}

#[cfg(test)]
mod tests;
