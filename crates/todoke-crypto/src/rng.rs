//! Operating-system randomness for keys and identifiers (PROTOCOL §1).

use core::fmt;

/// The OS CSPRNG was unavailable. Carries no detail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RandomError;

impl fmt::Display for RandomError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("operating-system randomness unavailable")
    }
}

impl std::error::Error for RandomError {}

/// Fills `dest` from the OS CSPRNG.
pub(crate) fn fill(dest: &mut [u8]) -> Result<(), RandomError> {
    getrandom::fill(dest).map_err(|_| RandomError)
}

/// Returns a random identifier that is not all zero (§1 forbids zero IDs).
pub(crate) fn nonzero_id<const N: usize>() -> Result<[u8; N], RandomError> {
    // An all-zero draw has probability 2^-128 for 16 bytes; retrying a few
    // times only guards against a broken source, which then fails closed.
    for _ in 0..4 {
        let mut id = [0; N];
        fill(&mut id)?;
        if id.iter().any(|&byte| byte != 0) {
            return Ok(id);
        }
    }
    Err(RandomError)
}
