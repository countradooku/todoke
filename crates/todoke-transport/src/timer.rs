//! The session layer's monotonic clock on tokio's timer.

use core::time::Duration;

use todoke_crypto::session::Timer;
use tokio::time::{Instant, Sleep};

/// A [`Timer`] on tokio's monotonic clock, counting from its creation.
/// Clones share the same origin.
#[derive(Clone, Copy, Debug)]
pub struct TokioTimer {
    origin: Instant,
}

impl TokioTimer {
    /// A timer whose `now` is zero at this instant.
    #[must_use]
    pub fn new() -> Self {
        Self {
            origin: Instant::now(),
        }
    }
}

impl Default for TokioTimer {
    fn default() -> Self {
        Self::new()
    }
}

impl Timer for TokioTimer {
    type Sleep = Sleep;

    fn now(&self) -> Duration {
        self.origin.elapsed()
    }

    fn sleep_until(&self, deadline: Duration) -> Sleep {
        // A deadline too far to represent never fires.
        let at = self
            .origin
            .checked_add(deadline)
            .unwrap_or_else(|| Instant::now() + Duration::from_hours(24 * 365 * 30));
        tokio::time::sleep_until(at)
    }
}
