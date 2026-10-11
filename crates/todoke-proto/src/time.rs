//! Unix time values as constrained by PROTOCOL §1.

/// The largest representable protocol time: 9999-12-31T23:59:59Z.
pub const MAX_UNIX_TIME: u64 = 253_402_300_799;

/// Integer seconds since 1970-01-01 UTC without leap seconds, in
/// `0..=MAX_UNIX_TIME` (PROTOCOL §1).
///
/// This is a wire value. It says nothing about whether the local wall clock is
/// trustworthy; callers with an unknown or regressed clock must not use it to
/// bypass expiry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct UnixTime(u64);

impl UnixTime {
    /// Returns `None` when `seconds` exceeds [`MAX_UNIX_TIME`].
    #[must_use]
    pub const fn new(seconds: u64) -> Option<Self> {
        if seconds <= MAX_UNIX_TIME {
            Some(Self(seconds))
        } else {
            None
        }
    }

    /// Seconds since the Unix epoch.
    #[must_use]
    pub const fn seconds(self) -> u64 {
        self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn range_is_enforced() {
        assert_eq!(UnixTime::new(0).map(UnixTime::seconds), Some(0));
        assert_eq!(
            UnixTime::new(MAX_UNIX_TIME).map(UnixTime::seconds),
            Some(MAX_UNIX_TIME)
        );
        assert_eq!(UnixTime::new(MAX_UNIX_TIME + 1), None);
        assert_eq!(UnixTime::new(u64::MAX), None);
    }
}
