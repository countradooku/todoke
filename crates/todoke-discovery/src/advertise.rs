//! What this device advertises, and when (PROTOCOL §9).
//!
//! - **Paired:** one record at a time, rotating over the available contacts
//!   (§9: a pair advertises one token at a time, and a device with several
//!   contacts rotates entries rather than broadcast its contact graph in
//!   one record). Each round shows every contact once, in a fresh uniformly
//!   random order, each for a random time between [`ROTATION_MIN`] and
//!   [`ROTATION_MAX`]: an observer learns neither the order nor a fixed
//!   period. It can still count the contacts by watching one label through
//!   a whole round (docs/adr/0013-private-discovery.md). The caller applies
//!   each change at [`Advertiser::next_change`], not on a coarser tick of
//!   its own, so the times are not quantised. The record is the contact's token for the
//!   current epoch, so it changes at every epoch boundary and after every
//!   committed session (a new table). The instance label is fresh random
//!   for every epoch, and never a device name.
//! - **Stranger:** only after an explicit local enable, for at most
//!   [`STRANGER_LIFETIME`], with a new token and a fresh random label every
//!   [`STRANGER_ROTATION`]. For code pairing the token is random; while a
//!   QR is shown it is the QR's token for the current minute, so only its
//!   scanner recognises it. It identifies nobody and is never a credential.
//!
//! Randomness comes from the caller (the OS CSPRNG in production) so the
//! schedule can be tested deterministically.

use core::time::Duration;

use todoke_crypto::discovery::DiscoveryTable;
use todoke_crypto::identity::Ed25519PublicKey;
use todoke_crypto::pairing::QrStrangerTokens;
use todoke_proto::discovery::{
    DISCOVERY_TOKEN_LEN, DiscoveryMode, DiscoveryRecord, Epoch, InstanceLabel,
};
use todoke_proto::time::UnixTime;

/// The shortest time a contact's record is shown before the next one's.
pub const ROTATION_MIN: Duration = Duration::from_secs(2);
/// The longest; each record's time is uniform in between, to the
/// millisecond (applied on time when the caller wakes at
/// [`Advertiser::next_change`]).
pub const ROTATION_MAX: Duration = Duration::from_secs(4);
/// How long stranger mode lasts after it is enabled (§9).
pub const STRANGER_LIFETIME: Duration = Duration::from_secs(300);
/// How often the stranger token (and its label) changes (§9).
pub const STRANGER_ROTATION: Duration = Duration::from_secs(60);

/// A source of OS randomness for labels, stranger tokens, and the paired
/// rotation's order and times.
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

#[derive(Clone, Debug)]
struct Stranger {
    started: Duration,
    rotated: Duration,
    advertisement: Advertisement,
    tokens: Tokens,
}

/// Where stranger tokens come from.
#[derive(Clone, Debug)]
enum Tokens {
    /// Fresh random every [`STRANGER_ROTATION`] (code pairing).
    Random,
    /// The shown QR's token for each minute (§9).
    Qr(QrStrangerTokens),
}

/// The paired rotation: who is shown, from when until when, and who is
/// left in this round.
#[derive(Clone, Default)]
struct Rotation {
    shown: Option<Ed25519PublicKey>,
    since: Duration,
    until: Duration,
    /// The rest of this round, next last.
    left: Vec<Ed25519PublicKey>,
}

/// The advertising schedule. Times: `wall` is the trusted wall clock (for
/// epochs), `mono` the caller's monotonic clock.
#[derive(Default)]
pub struct Advertiser {
    label: Option<(Epoch, InstanceLabel)>,
    rotation: Rotation,
    stranger: Option<Stranger>,
}

/// Redacted: the rotation holds the contacts' device keys (the contact
/// graph), and a stranger record its token.
impl core::fmt::Debug for Advertiser {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Advertiser")
            .field("showing", &self.rotation.shown.is_some())
            .field("left_in_round", &self.rotation.left.len())
            .field("stranger", &self.stranger.is_some())
            .finish_non_exhaustive()
    }
}

impl Advertiser {
    /// A schedule advertising nothing yet.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Starts stranger mode with random tokens for [`STRANGER_LIFETIME`]
    /// (an explicit local action, §9), for code pairing. Returns whether
    /// it started (it needs randomness).
    pub fn enable_stranger(
        &mut self,
        wall: UnixTime,
        mono: Duration,
        random: &mut impl Random,
    ) -> bool {
        self.start_stranger(Tokens::Random, wall, mono, random)
    }

    /// Starts stranger mode for a shown QR (§9): each minute's token comes
    /// from `tokens`, and stranger mode ends early when the wall clock
    /// leaves the offer's minutes. Returns whether it started (it needs
    /// randomness for the labels, and `wall` within the offer's minutes).
    pub fn enable_qr_stranger(
        &mut self,
        tokens: QrStrangerTokens,
        wall: UnixTime,
        mono: Duration,
        random: &mut impl Random,
    ) -> bool {
        self.start_stranger(Tokens::Qr(tokens), wall, mono, random)
    }

    fn start_stranger(
        &mut self,
        tokens: Tokens,
        wall: UnixTime,
        mono: Duration,
        random: &mut impl Random,
    ) -> bool {
        self.stranger = stranger(&tokens, wall, random).map(|advertisement| Stranger {
            started: mono,
            rotated: mono,
            advertisement,
            tokens,
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
    /// paired; rebuild it at each epoch and after each committed session.
    ///
    /// No contact is ever favoured: a contact shown more often than the
    /// others would tell an observer whom this device is about to exchange
    /// files with (and §9's pair token is the same on both devices).
    pub fn plan(
        &mut self,
        table: &DiscoveryTable,
        wall: UnixTime,
        mono: Duration,
        random: &mut impl Random,
    ) -> Plan {
        Plan {
            paired: self.paired(table, wall, mono, random),
            stranger: self.stranger(wall, mono, random),
        }
    }

    /// When the paired record is next due to change, if that is after
    /// `mono`: the caller plans again then, so changes are not quantised to
    /// a tick of its own (which would also give its devices a common
    /// phase). `None` when nothing paired is shown or the change is
    /// already due (the caller's next plan makes it).
    #[must_use]
    pub fn next_change(&self, mono: Duration) -> Option<Duration> {
        let rotation = &self.rotation;
        (rotation.shown.is_some() && rotation.until > mono).then_some(rotation.until)
    }

    fn paired(
        &mut self,
        table: &DiscoveryTable,
        wall: UnixTime,
        mono: Duration,
        random: &mut impl Random,
    ) -> Option<Advertisement> {
        // A table for another epoch would advertise an old token (§9).
        if table.is_stale(wall) || table.is_empty() {
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
        let device = self.turn(table, mono, random)?;
        let record = table.advertisement(&device)?;
        Some(Advertisement { label, record })
    }

    fn stranger(
        &mut self,
        wall: UnixTime,
        mono: Duration,
        random: &mut impl Random,
    ) -> Option<Advertisement> {
        let current = self.stranger.as_mut()?;
        if mono.saturating_sub(current.started) >= STRANGER_LIFETIME {
            self.stranger = None;
            return None;
        }
        let due = match &current.tokens {
            Tokens::Random => mono.saturating_sub(current.rotated) >= STRANGER_ROTATION,
            // At each minute boundary (§9).
            Tokens::Qr(tokens) => tokens.at(wall) != Some(*current.advertisement.record.token()),
        };
        if due {
            let Some(advertisement) = stranger(&current.tokens, wall, random) else {
                // No randomness, or past the QR's minutes: stop rather
                // than keep a stale token.
                self.stranger = None;
                return None;
            };
            current.rotated = mono;
            current.advertisement = advertisement;
        }
        Some(current.advertisement)
    }
}

impl Advertiser {
    /// The contact whose record is shown at `mono`: the current one until
    /// its time is up (or it left the table, or the clock went back), then
    /// the next of this round's shuffled order. `None` without randomness
    /// for a new order or time; the round is then left as it was.
    fn turn(
        &mut self,
        table: &DiscoveryTable,
        mono: Duration,
        random: &mut impl Random,
    ) -> Option<Ed25519PublicKey> {
        let rotation = &mut self.rotation;
        if let Some(shown) = rotation.shown
            && (rotation.since..rotation.until).contains(&mono)
            && table.advertisement(&shown).is_some()
        {
            return Some(shown);
        }
        // Drawn first, so a failing source changes nothing.
        let dwell = dwell(random)?;
        let device = next_in_round(&mut rotation.left, table, random)?;
        rotation.shown = Some(device);
        rotation.since = mono;
        rotation.until = mono.saturating_add(dwell);
        Some(device)
    }
}

/// The next contact of the round in `left` that is still in `table`; a new
/// round, shuffled, when none is left. On `None` (no randomness for the
/// shuffle) `left` is unchanged but for contacts that had left the table.
fn next_in_round(
    left: &mut Vec<Ed25519PublicKey>,
    table: &DiscoveryTable,
    random: &mut impl Random,
) -> Option<Ed25519PublicKey> {
    while let Some(device) = left.pop() {
        if table.advertisement(&device).is_some() {
            return Some(device);
        }
    }
    let mut round: Vec<Ed25519PublicKey> = table.contacts().copied().collect();
    shuffle(&mut round, random)?;
    let device = round.pop()?;
    *left = round;
    Some(device)
}

/// Fisher–Yates with unbiased indices.
fn shuffle<T>(items: &mut [T], random: &mut impl Random) -> Option<()> {
    for last in (1..items.len()).rev() {
        let pick = below(u64::try_from(last).ok()? + 1, random)?;
        items.swap(last, usize::try_from(pick).ok()?);
    }
    Some(())
}

/// How long the next record is shown: uniform in
/// [`ROTATION_MIN`]..=[`ROTATION_MAX`], to the millisecond.
fn dwell(random: &mut impl Random) -> Option<Duration> {
    let min = u64::try_from(ROTATION_MIN.as_millis()).ok()?;
    let max = u64::try_from(ROTATION_MAX.as_millis()).ok()?;
    Some(Duration::from_millis(min + below(max - min + 1, random)?))
}

/// A uniform integer in `0..bound` (`bound` > 0), by rejection: values in
/// the last, partial run of `bound` are drawn again. A source that keeps
/// giving rejected values (a broken one: each draw is rejected with
/// probability below `bound / 2^64`) gives `None` after 64 draws.
fn below(bound: u64, random: &mut impl Random) -> Option<u64> {
    let zone = u64::MAX - u64::MAX % bound;
    for _ in 0..64 {
        let value = u64::from_be_bytes(random.bytes()?);
        if value < zone {
            return Some(value % bound);
        }
    }
    None
}

fn stranger(tokens: &Tokens, wall: UnixTime, random: &mut impl Random) -> Option<Advertisement> {
    let token: [u8; DISCOVERY_TOKEN_LEN] = match tokens {
        Tokens::Random => random.bytes()?,
        Tokens::Qr(tokens) => tokens.at(wall)?,
    };
    let label = InstanceLabel::from_random(random.bytes()?).ok()?;
    let record = DiscoveryRecord::new(DiscoveryMode::Stranger, Epoch::of(wall), token).ok()?;
    Some(Advertisement { label, record })
}

#[cfg(all(test, not(target_family = "wasm")))]
mod tests;
