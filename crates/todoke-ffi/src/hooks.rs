//! What the core calls back into the app for: keeping the storage key,
//! posting notifications, and setting up direct Wi-Fi links.

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

/// A direct Wi-Fi link's kind (PROTOCOL §10.2). todoke uses no Bluetooth
/// and no USB (§10.1).
#[data]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkKind {
    /// A Wi-Fi Aware data path.
    WifiAware,
    /// A Wi-Fi Direct group.
    WifiDirect,
    /// A hotspot.
    Hotspot,
}

/// A direct link's link-layer security (§10.2).
#[data]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkSecurity {
    /// WPA3-Personal, SAE only.
    Wpa3,
    /// WPA3-Personal transition mode.
    Wpa3Transition,
    /// WPA2-PSK.
    Wpa2,
    /// Wi-Fi Aware NCS-SK-256.
    AwareSk256,
    /// Wi-Fi Aware NCS-SK-128.
    AwareSk128,
}

/// What this device can host and join now (§10.2), as lists.
#[data]
#[derive(Clone, Debug, PartialEq, Eq, Default)]
pub struct LinkAbilities {
    /// The kinds it can host.
    pub host: Vec<LinkKind>,
    /// The kinds it can join.
    pub join: Vec<LinkKind>,
    /// The securities it can join with.
    pub join_security: Vec<LinkSecurity>,
}

/// A link to host or join, with the credentials of the offer (§10.2). The
/// secret is the passphrase (or, for Wi-Fi Aware, the PMK): give it to the
/// operating system and keep no copy.
#[data]
#[derive(Clone, PartialEq, Eq)]
pub struct LinkRequest {
    /// The kind.
    pub kind: LinkKind,
    /// The security.
    pub security: LinkSecurity,
    /// The network name (empty for Wi-Fi Aware).
    pub ssid: String,
    /// The passphrase (ASCII) or PMK.
    pub secret: Vec<u8>,
    /// For Wi-Fi Aware: the service-specific information to publish or
    /// match (8 bytes).
    pub service_info: Vec<u8>,
    /// How long the offer stands, in milliseconds: give up after it.
    pub within_ms: u64,
}

impl core::fmt::Debug for LinkRequest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("LinkRequest")
            .field("kind", &self.kind)
            .field("security", &self.security)
            .finish_non_exhaustive()
    }
}

/// A link that is up: the app keeps it until [`WifiLinks::release`].
#[data]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LinkLease {
    /// The app's handle for the link, for `bind_socket` and `release`.
    pub id: u64,
    /// This device's address on the link (IPv4 or IPv6 text).
    pub local: String,
    /// The host's address on the link, for a joiner; none for the host.
    pub host: Option<String>,
    /// The link's interface index (the scope of link-local IPv6), or 0.
    pub interface: u32,
    /// Sockets must be bound to the link before use (`bind_socket`): the
    /// link is a network of its own (Android).
    pub bind_sockets: bool,
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

/// What sets up direct Wi-Fi links on this device (PROTOCOL §10.2): the
/// app's platform code. The core decides when (only for a transfer the user
/// started or accepted), makes the credentials, and runs the session over
/// the link; the app only brings links up and down with the platform's
/// app-scoped, temporary mechanisms (never a saved or suggested network,
/// WPS, or an open network). Every call may block; the core calls them off
/// its thread.
#[export]
pub trait WifiLinks: Send + Sync {
    /// What this device can host and join now (hardware, permissions, the
    /// platform). Empty lists take no part. Cheap.
    fn abilities(&self) -> LinkAbilities;

    /// Hosts the link `request` describes, with exactly its credentials,
    /// forwarding nothing between the link and other networks.
    ///
    /// # Errors
    ///
    /// The link could not be brought up.
    fn host(&self, request: LinkRequest) -> Result<LinkLease, LinkError>;

    /// Joins the link `request` describes, within its deadline.
    ///
    /// # Errors
    ///
    /// The link could not be joined.
    fn join(&self, request: LinkRequest) -> Result<LinkLease, LinkError>;

    /// Binds `socket` (a file descriptor the core keeps) to the link
    /// `lease`, before the core listens or connects on it.
    ///
    /// # Errors
    ///
    /// The socket could not be bound.
    // Not `handle`: BoltFFI's JNI glue names the callback object that.
    fn bind_socket(&self, lease: u64, socket: i64) -> Result<(), LinkError>;

    /// Tears the link `lease` down: leaves or removes the group, hotspot,
    /// or data path and any configuration created for it.
    fn release(&self, lease: u64);
}
