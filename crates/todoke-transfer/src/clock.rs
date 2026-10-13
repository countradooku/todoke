//! Wall-clock time anchored to the session's monotonic clock (§1).

use core::time::Duration;

use todoke_proto::time::{MAX_UNIX_TIME, UnixTime};

/// The trusted wall-clock time at one monotonic instant. Later wall times
/// add monotonic elapsed time, so expiry checks never use a clock that can
/// jump (§1: durations use a monotonic clock).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Clock {
    wall: UnixTime,
    monotonic: Duration,
}

impl Clock {
    /// `wall` is the trusted time at monotonic instant `monotonic`. An
    /// unknown or regressed wall clock needs local confirmation instead
    /// (§1); it must never be passed here to bypass expiry.
    #[must_use]
    pub const fn new(wall: UnixTime, monotonic: Duration) -> Self {
        Self { wall, monotonic }
    }

    /// The wall-clock time at monotonic instant `now`, clamped to the
    /// protocol range.
    #[must_use]
    pub fn wall(&self, now: Duration) -> UnixTime {
        let elapsed = now.saturating_sub(self.monotonic).as_secs();
        let seconds = self
            .wall
            .seconds()
            .saturating_add(elapsed)
            .min(MAX_UNIX_TIME);
        UnixTime::new(seconds).unwrap_or(self.wall)
    }

    /// The monotonic instant at which wall-clock time reaches `at`.
    #[must_use]
    pub fn monotonic_at(&self, at: UnixTime) -> Duration {
        let ahead = at.seconds().saturating_sub(self.wall.seconds());
        self.monotonic.saturating_add(Duration::from_secs(ahead))
    }
}
