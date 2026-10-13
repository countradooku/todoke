//! What this device advertises, and when (PROTOCOL §9).
//!
//! - **Paired:** one record at a time, rotating over the available contacts
//!   every [`ROTATION`] (§9: a pair advertises one token at a time, and a
//!   device with several contacts rotates entries rather than broadcast
//!   its contact graph in one record). The record is the contact's token
//!   for the current epoch, so it changes at every epoch boundary and after
//!   every committed session (a new table). The instance label is fresh
//!   random for every epoch, and never a device name.
//! - **Stranger:** only after an explicit local enable, for at most
//!   [`STRANGER_LIFETIME`], with a fresh random token and label every
//!   [`STRANGER_ROTATION`]. It identifies nobody and is never a credential.
//!
//! Randomness comes from the caller (the OS CSPRNG in production) so the
//! schedule can be tested deterministically.

use core::time::Duration;

use todoke_crypto::discovery::DiscoveryTable;
use todoke_crypto::identity::Ed25519PublicKey;
use todoke_proto::discovery::{
    DISCOVERY_TOKEN_LEN, DiscoveryMode, DiscoveryRecord, Epoch, InstanceLabel,
};
use todoke_proto::time::UnixTime;

/// How long each contact's record is shown before the next one's.
pub const ROTATION: Duration = Duration::from_secs(3);
/// How long stranger mode lasts after it is enabled (§9).
pub const STRANGER_LIFETIME: Duration = Duration::from_secs(300);
/// How often the stranger token (and its label) changes (§9).
pub const STRANGER_ROTATION: Duration = Duration::from_secs(60);

/// A source of OS randomness for labels and stranger tokens.
pub trait Random {
    /// Eight random bytes, or `None` if the OS has none (then nothing new
    /// is advertised).
    fn bytes(&mut self) -> Option<[u8; 8]>;
}

/// The operating system's CSPRNG.
#[derive(Clone, Copy, Debug, Default)]
pub struct OsRandom;

impl Random for OsRandom {
    fn bytes(&mut self) -> Option<[u8; 8]> {
        let mut out = [0; 8];
        getrandom::fill(&mut out).ok()?;
        Some(out)
    }
}

/// One advertisement: an instance label and the record in its TXT string.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Advertisement {
    /// The instance label.
    pub label: InstanceLabel,
    /// The record.
    pub record: DiscoveryRecord,
}

/// What to advertise now.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Plan {
    /// The paired record, if any contact is available.
    pub paired: Option<Advertisement>,
    /// The stranger record, while stranger mode is on.
    pub stranger: Option<Advertisement>,
}

impl Plan {
    /// The labels in this plan.
    #[must_use]
    pub fn labels(&self) -> Vec<InstanceLabel> {
        self.paired
            .iter()
            .chain(self.stranger.iter())
            .map(|advertisement| advertisement.label)
            .collect()
    }
}

#[derive(Clone, Copy, Debug)]
struct Stranger {
    started: Duration,
    rotated: Duration,
    advertisement: Advertisement,
}

/// The advertising schedule. Times: `wall` is the trusted wall clock (for
/// epochs), `mono` the caller's monotonic clock.
#[derive(Debug, Default)]
pub struct Advertiser {
    label: Option<(Epoch, InstanceLabel)>,
    stranger: Option<Stranger>,
}

impl Advertiser {
    /// A schedule advertising nothing yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Starts stranger mode for [`STRANGER_LIFETIME`] (an explicit local
    /// action, §9). Returns whether it started (it needs randomness).
    pub fn enable_stranger(
        &mut self,
        wall: UnixTime,
        mono: Duration,
        random: &mut impl Random,
    ) -> bool {
        self.stranger = stranger(wall, random).map(|advertisement| Stranger {
            started: mono,
            rotated: mono,
            advertisement,
        });
        self.stranger.is_some()
    }

    /// Ends stranger mode now.
    pub fn disable_stranger(&mut self) {
        self.stranger = None;
    }

    /// Whether stranger mode is on.
    #[must_use]
    pub const fn stranger_enabled(&self) -> bool {
        self.stranger.is_some()
    }

    /// What to advertise at `wall` / `mono`, given the contacts in `table`.
    /// A table built for another epoch than `wall`'s advertises nothing
    /// paired; rebuild it at each epoch and after each committed session. `priority`, if it is in the table, gets
    /// every other slot: a device the user is about to send to or expects
    /// a file from.
    pub fn plan(
        &mut self,
        table: &DiscoveryTable,
        priority: Option<&Ed25519PublicKey>,
        wall: UnixTime,
        mono: Duration,
        random: &mut impl Random,
    ) -> Plan {
        Plan {
            paired: self.paired(table, priority, wall, mono, random),
            stranger: self.stranger(wall, mono, random),
        }
    }

    fn paired(
        &mut self,
        table: &DiscoveryTable,
        priority: Option<&Ed25519PublicKey>,
        wall: UnixTime,
        mono: Duration,
        random: &mut impl Random,
    ) -> Option<Advertisement> {
        // A table for another epoch would advertise an old token (§9).
        if table.is_stale(wall) {
            return None;
        }
        let contacts: Vec<&Ed25519PublicKey> = table.contacts().collect();
        if contacts.is_empty() {
            return None;
        }
        let epoch = Epoch::of(wall);
        let label = match self.label {
            Some((at, label)) if at == epoch => label,
            _ => {
                let label = InstanceLabel::from_random(random.bytes()?).ok()?;
                self.label = Some((epoch, label));
                label
            }
        };
        let slot = mono.as_secs() / ROTATION.as_secs().max(1);
        let device = match priority.filter(|device| contacts.contains(device)) {
            Some(device) if slot.is_multiple_of(2) => device,
            _ => {
                let count = u64::try_from(contacts.len()).ok()?;
                let index = usize::try_from(slot % count).ok()?;
                *contacts.get(index)?
            }
        };
        let record = table.advertisement(device)?;
        Some(Advertisement { label, record })
    }

    fn stranger(
        &mut self,
        wall: UnixTime,
        mono: Duration,
        random: &mut impl Random,
    ) -> Option<Advertisement> {
        let current = self.stranger?;
        if mono.saturating_sub(current.started) >= STRANGER_LIFETIME {
            self.stranger = None;
            return None;
        }
        if mono.saturating_sub(current.rotated) >= STRANGER_ROTATION {
            let Some(advertisement) = stranger(wall, random) else {
                // No randomness: stop rather than keep a stale token.
                self.stranger = None;
                return None;
            };
            self.stranger = Some(Stranger {
                rotated: mono,
                advertisement,
                ..current
            });
            return Some(advertisement);
        }
        Some(current.advertisement)
    }
}

fn stranger(wall: UnixTime, random: &mut impl Random) -> Option<Advertisement> {
    let token: [u8; DISCOVERY_TOKEN_LEN] = random.bytes()?;
    let label = InstanceLabel::from_random(random.bytes()?).ok()?;
    let record = DiscoveryRecord::new(DiscoveryMode::Stranger, Epoch::of(wall), token).ok()?;
    Some(Advertisement { label, record })
}

#[cfg(all(test, not(target_family = "wasm")))]
mod tests;
