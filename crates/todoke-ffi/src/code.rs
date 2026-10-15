//! A pairing code to show: a class, so the code is no field of a record a
//! platform prints (`toString`, `description`), and crosses only when the
//! app asks for it.

#![allow(
    clippy::must_use_candidate,
    reason = "exported to foreign callers: must_use means nothing there"
)]

use boltffi::export;
use zeroize::Zeroizing;

/// A shown pairing code (ten digits, two groups of five). It works until it
/// expires or five wrong tries; stop it with `Core::stop_pairing`.
pub struct CodeOffer {
    code: Zeroizing<String>,
    expires_at: u64,
}

impl CodeOffer {
    pub(crate) fn new(code: String, expires_at: u64) -> Self {
        Self {
            code: Zeroizing::new(code),
            expires_at,
        }
    }
}

impl core::fmt::Debug for CodeOffer {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("CodeOffer")
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

#[export]
impl CodeOffer {
    /// The code, to show the user. Never log it.
    pub fn code(&self) -> String {
        self.code.as_str().to_owned()
    }

    /// When it expires (Unix seconds).
    pub fn expires_at(&self) -> u64 {
        self.expires_at
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Printing a code offer never prints the code.
    #[test]
    fn debug_hides_the_code() {
        let offer = CodeOffer::new("48213 90577".to_owned(), 7);
        let printed = format!("{offer:?}");
        assert!(!printed.contains("48213") && !printed.contains("90577"));
        assert!(printed.contains("expires_at: 7"));
        assert_eq!(offer.code(), "48213 90577");
        assert_eq!(offer.expires_at(), 7);
    }
}
