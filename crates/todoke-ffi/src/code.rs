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
