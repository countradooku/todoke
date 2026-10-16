//! What the discovery backends (`mdns-sd`, and Bonjour on Apple platforms)
//! share.

use core::fmt;
use core::time::Duration;

use crate::advertise::STRANGER_ROTATION;

/// The longest a stranger advertisement stays registered, whatever plans
/// the caller applies: one rotation and some slack (§9).
pub const STRANGER_MAX: Duration = Duration::from_secs(STRANGER_ROTATION.as_secs() + 10);

/// A discovery backend failure; the platform's own message is not kept (it
/// may name addresses or instances).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MdnsError;

impl fmt::Display for MdnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("mDNS failed")
    }
}

impl std::error::Error for MdnsError {}
