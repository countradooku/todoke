//! What the core calls back into the app for: keeping the storage key,
//! posting notifications, and (reserved) radio links.

use boltffi::{data, error, export};

use crate::types::{KeyProtection, Offer};

/// Why the platform's key store failed.
#[error]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum KeyStoreError {
    /// Not available now (locked, no hardware): the policy decides.
    Unavailable {
        /// For people.
        message: String,
    },
    /// A key is stored already; it is never replaced.
    AlreadyExists,
    /// The user or the system refused.
    Refused {
        /// For people.
        message: String,
    },
}

impl core::fmt::Display for KeyStoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Unavailable { message } | Self::Refused { message } => f.write_str(message),
            Self::AlreadyExists => f.write_str("a key is stored already"),
        }
    }
}

impl std::error::Error for KeyStoreError {}

/// The app's key store threw something it does not declare: unavailable.
impl From<boltffi::UnexpectedFfiCallbackError> for KeyStoreError {
    fn from(error: boltffi::UnexpectedFfiCallbackError) -> Self {
        Self::Unavailable { message: error.0 }
    }
}

/// The platform's secret storage for the 32-byte key that seals this
/// device's state (Android: a non-exportable Keystore key, in `StrongBox`
/// where present, encrypts it; iOS keeps it in the Keychain, wrapped by
/// the Secure Enclave).
///
/// This is the one secret that crosses the boundary, and only here: the
/// app keeps it encrypted under a hardware key and hands it back to the
/// core. Implementations must not log it, copy it elsewhere, or keep it
/// in memory after the call. `profile` names the profile (a random ID kept
/// beside its state): one app may hold several, each with its own key.
///
/// The core calls these on its own thread while `Core::with_key_store`
/// blocks its caller: they must not wait for that caller's thread.
#[export]
pub trait KeyStore: Send + Sync {
    /// What protects a key stored here.
    fn protection(&self) -> KeyProtection;

    /// The stored key, or `None` if none is stored.
    ///
    /// # Errors
    ///
    /// The store is unavailable now: never "no key".
    fn load(&self, profile: String) -> Result<Option<Vec<u8>>, KeyStoreError>;

    /// Stores `key`; never replaces a stored one.
    ///
    /// # Errors
    ///
    /// [`KeyStoreError::AlreadyExists`] if a key is stored.
    fn store(&self, profile: String, key: Vec<u8>) -> Result<(), KeyStoreError>;
}

/// An offer to notify (no file names: lock screens show notifications).
#[data]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OfferNotice {
    /// The transfer.
    pub transfer: String,
    /// The sender's fingerprint.
    pub from: String,
    /// What to call the sender.
    pub from_name: String,
    /// Files in it.
    pub files: u32,
    /// Folders in it.
    pub folders: u32,
    /// Bytes in all.
    pub total_bytes: u64,
}

impl From<&Offer> for OfferNotice {
    fn from(offer: &Offer) -> Self {
        let folders = offer.entries.iter().filter(|entry| entry.directory).count();
        Self {
            transfer: offer.transfer.clone(),
            from: offer.from.clone(),
            from_name: offer.from_name.clone(),
            files: crate::types::count(offer.entries.len() - folders),
            folders: crate::types::count(folders),
            total_bytes: offer.total_bytes,
        }
    }
}

/// The app's notifications, called from a thread of the core's (never the
/// UI thread) while the app may be in the background; a slow one delays
/// the events behind it. Deciding an offer happens in the app, never in a
/// notification.
#[export]
pub trait Notifier: Send + Sync {
    /// An offer awaits a decision.
    fn offer_received(&self, notice: OfferNotice);
    /// An offer was decided, withdrawn, or expired: its notification goes.
    fn offer_gone(&self, transfer: String);
    /// A transfer finished; `text` is for people.
    fn transfer_finished(&self, transfer: String, text: String);
    /// Events were lost: read `Core::offers` and settle the notifications
    /// shown (offers that went meanwhile are not reported one by one).
    fn missed(&self);
}

/// What kind of radio a link uses. todoke uses no Bluetooth and no USB
/// (PROTOCOL §10.1).
#[data]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkKind {
    /// A Wi-Fi Aware data path, a Wi-Fi Direct group, or a hotspot (§10.2).
    WifiP2p,
    /// Apple peer-to-peer Wi-Fi (AWDL) or Apple Wi-Fi Aware.
    Awdl,
}

/// Why a link failed.
#[error]
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum LinkError {
    /// The link is closed.
    Closed,
    /// The radio failed.
    Failed {
        /// For people.
        message: String,
    },
}

impl core::fmt::Display for LinkError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Closed => f.write_str("the link is closed"),
            Self::Failed { message } => f.write_str(message),
        }
    }
}

impl std::error::Error for LinkError {}

/// The app's link threw something it does not declare: failed.
impl From<boltffi::UnexpectedFfiCallbackError> for LinkError {
    fn from(error: boltffi::UnexpectedFfiCallbackError) -> Self {
        Self::Failed { message: error.0 }
    }
}

/// A byte pipe over a platform Wi-Fi link, for the core to run a session on
/// (PROTOCOL §10.1 to §10.3).
///
/// Reserved: the adapters are not built yet, so `Core::attach_link`
/// refuses every link for now. The shape is fixed here so the apps can be
/// written against it.
#[export]
pub trait RadioLink: Send + Sync {
    /// The radio.
    fn kind(&self) -> LinkKind;
    /// Sends bytes, in order.
    ///
    /// # Errors
    ///
    /// The link is closed or failed.
    fn send(&self, bytes: Vec<u8>) -> Result<(), LinkError>;
    /// Closes the link.
    fn close(&self);
}
