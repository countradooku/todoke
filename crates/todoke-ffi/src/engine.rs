//! The core as an app holds it: one object that starts the core, answers
//! commands, hands out event subscriptions, and hands out contact and
//! transfer handles.
//!
//! Commands block until the core answers (on the calling thread; most
//! answer at once, offering a large folder hashes it first): call them off
//! the UI thread, as the platform's async wrappers do (Swift
//! `Task.detached`, Kotlin `Dispatchers.IO`). They are not `async` on
//! purpose: `BoltFFI` 0.31.1's Swift glue can poll a Rust future after a
//! cancelled task freed it (docs/adr/0012-bindings.md), so no Rust future
//! crosses the boundary.

#![allow(
    clippy::needless_pass_by_value,
    clippy::must_use_candidate,
    reason = "exported to foreign callers: arguments arrive owned, and must_use means nothing there"
)]

use std::sync::{Arc, Mutex};

use boltffi::export;
use todoke_core::api::{Request, Response};

use crate::code::CodeOffer;
use crate::error::TodokeError;
use crate::events::{Events, Subscribers};
use crate::handles::{ContactHandle, TransferHandle, valid_id};
use crate::hooks::{KeyStore, Notifier, RadioLink};
use crate::qr::QrOffer;
use crate::types::{Contact, HistoryItem, Offer, Settings, Status, Stranger, Transfer};

/// The app's notifier, shared with the event thread.
pub(crate) type NotifierSlot = Arc<Mutex<Option<Arc<dyn Notifier>>>>;

/// What the core, its handles, and the event thread share.
pub(crate) struct Shared {
    #[cfg(not(target_family = "wasm"))]
    core: todoke_core::runtime::Core,
    pub(crate) subscribers: Arc<Subscribers>,
    notifier: NotifierSlot,
}

impl Shared {
    /// Sends `request` and waits for the answer, or the core's error.
    pub(crate) fn request(&self, request: Request) -> Result<Response, TodokeError> {
        #[cfg(not(target_family = "wasm"))]
        {
            match crate::block::block_on(self.core.request(request)) {
                Response::Error { code, message } => Err(TodokeError::from_core(code, &message)),
                response => Ok(response),
            }
        }
        #[cfg(target_family = "wasm")]
        {
            let _ = request;
            Err(unsupported())
        }
    }

    /// Offers open `files` under `names` to `contact`, as `request` would
    /// offer paths.
    #[cfg(unix)]
    pub(crate) fn send_files(
        &self,
        contact: String,
        names: Vec<String>,
        files: Vec<std::fs::File>,
    ) -> Result<Response, TodokeError> {
        let files = names
            .into_iter()
            .zip(files)
            .map(|(name, file)| todoke_core::send::OpenFile { name, file })
            .collect();
        match crate::block::block_on(self.core.send_files(contact, files)) {
            Response::Error { code, message } => Err(TodokeError::from_core(code, &message)),
            response => Ok(response),
        }
    }

    /// Sends `request`, which answers `Done`.
    pub(crate) fn done(&self, request: Request) -> Result<(), TodokeError> {
        match self.request(request)? {
            Response::Done => Ok(()),
            _ => Err(TodokeError::unexpected()),
        }
    }
}

#[cfg(target_family = "wasm")]
fn unsupported() -> TodokeError {
    TodokeError::Unsupported {
        message: "the core does not run in a browser yet (browser mode comes later)".to_owned(),
    }
}

/// The running core of one profile. It stops when the app releases it and
/// every handle it gave out (its subscriptions then end); that release
/// joins the core's thread (a moment): do it off the UI thread too.
pub struct Core {
    shared: Arc<Shared>,
}

impl core::fmt::Debug for Core {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Core")
    }
}

impl Core {
    fn start(
        settings: &Settings,
        key_store: Option<Arc<dyn KeyStore>>,
    ) -> Result<Self, TodokeError> {
        #[cfg(target_family = "wasm")]
        {
            let _ = (settings, key_store);
            Err(unsupported())
        }
        #[cfg(not(target_family = "wasm"))]
        {
            #[cfg(target_os = "android")]
            crate::android::record_api_level();
            let config = crate::config::core_config(settings, key_store.is_some())?;
            let source = crate::keys::source(&config.state_dir, key_store, config.key_storage)?;
            let core = todoke_core::runtime::Core::start(config, Box::new(source))
                .map_err(crate::config::start_error)?;
            let subscribers = Arc::new(Subscribers::default());
            let notifier: NotifierSlot = Arc::new(Mutex::new(None));
            crate::forward::spawn(
                core.subscribe(),
                Arc::clone(&subscribers),
                Arc::clone(&notifier),
            )
            .map_err(|_| TodokeError::Internal {
                message: "the event thread could not start".to_owned(),
            })?;
            Ok(Self {
                shared: Arc::new(Shared {
                    core,
                    subscribers,
                    notifier,
                }),
            })
        }
    }

    fn handle_for(&self, contact: String) -> ContactHandle {
        ContactHandle {
            shared: Arc::clone(&self.shared),
            device: contact,
        }
    }
}

#[export]
impl Core {
    /// Starts the core for the profile in `settings.home` with no key store
    /// of the app's: the storage key in the macOS Keychain (natively,
    /// nothing crosses), or with `KeyStoragePolicy::File` a private file.
    /// On Android and iOS, use [`Core::with_key_store`] (or ask for a file
    /// explicitly). Blocks while the profile opens: call it off the UI
    /// thread.
    ///
    /// # Errors
    ///
    /// [`TodokeError::Disabled`] in builds without development sessions;
    /// [`TodokeError::Invalid`] for settings that cannot be used;
    /// [`TodokeError::Profile`] or [`TodokeError::KeyStore`] when the
    /// profile cannot be opened.
    pub fn new(settings: Settings) -> Result<Self, TodokeError> {
        Self::start(&settings, None)
    }

    /// Starts the core with the app's key store for the storage key
    /// (Android's Keystore, iOS's Keychain and Secure Enclave). The key
    /// then lives only there (`settings.key_storage` must be
    /// `KeyStoragePolicy::Platform`). The key store is called on the
    /// core's thread while this blocks: it must not wait for the thread
    /// that calls this (the UI thread, for one).
    ///
    /// # Errors
    ///
    /// As [`Core::new`]; [`TodokeError::KeyStore`] when the key store
    /// refuses or fails.
    pub fn with_key_store(
        settings: Settings,
        key_store: Arc<dyn KeyStore>,
    ) -> Result<Self, TodokeError> {
        Self::start(&settings, Some(key_store))
    }

    /// This library's version.
    pub fn version() -> String {
        env!("CARGO_PKG_VERSION").to_owned()
    }

    /// What the core is doing.
    ///
    /// # Errors
    ///
    /// The core stopped.
    pub fn status(&self) -> Result<Status, TodokeError> {
        match self.shared.request(Request::Status)? {
            Response::Status(status) => Ok(status.into()),
            _ => Err(TodokeError::unexpected()),
        }
    }

    /// The paired devices.
    ///
    /// # Errors
    ///
    /// The core stopped.
    pub fn contacts(&self) -> Result<Vec<Contact>, TodokeError> {
        match self.shared.request(Request::Contacts)? {
            Response::Contacts(contacts) => Ok(contacts.into_iter().map(Contact::from).collect()),
            _ => Err(TodokeError::unexpected()),
        }
    }

    /// A handle to the contact with fingerprint `device` (from
    /// [`Contact::device`]).
    ///
    /// # Errors
    ///
    /// [`TodokeError::Invalid`] for something that is not a fingerprint.
    pub fn contact(&self, device: String) -> Result<ContactHandle, TodokeError> {
        if !valid_id(&device) {
            return Err(TodokeError::Invalid {
                message: "not a device fingerprint".to_owned(),
            });
        }
        Ok(self.handle_for(device))
    }

    /// Transfers in progress or awaiting a decision.
    ///
    /// # Errors
    ///
    /// The core stopped.
    pub fn transfers(&self) -> Result<Vec<Transfer>, TodokeError> {
        match self.shared.request(Request::Transfers)? {
            Response::Transfers(transfers) => {
                Ok(transfers.into_iter().map(Transfer::from).collect())
            }
            _ => Err(TodokeError::unexpected()),
        }
    }

    /// A handle to the transfer `id` (from [`Transfer::id`] or an offer).
    ///
    /// # Errors
    ///
    /// [`TodokeError::Invalid`] for something that is not a transfer ID.
    pub fn transfer(&self, id: String) -> Result<TransferHandle, TodokeError> {
        if !valid_id(&id) {
            return Err(TodokeError::Invalid {
                message: "not a transfer ID".to_owned(),
            });
        }
        Ok(TransferHandle {
            shared: Arc::clone(&self.shared),
            id,
        })
    }

    /// Offers awaiting this user's decision (what an app that starts late,
    /// or that missed events, has not seen).
    ///
    /// # Errors
    ///
    /// The core stopped.
    pub fn offers(&self) -> Result<Vec<Offer>, TodokeError> {
        match self.shared.request(Request::Offers)? {
            Response::Offers(offers) => Ok(offers.into_iter().map(Offer::from).collect()),
            _ => Err(TodokeError::unexpected()),
        }
    }

    /// Finished transfers, newest first.
    ///
    /// # Errors
    ///
    /// The core stopped.
    pub fn history(&self) -> Result<Vec<HistoryItem>, TodokeError> {
        match self.shared.request(Request::History)? {
            Response::History(entries) => Ok(entries.into_iter().map(HistoryItem::from).collect()),
            _ => Err(TodokeError::unexpected()),
        }
    }

    /// Forgets every finished transfer.
    ///
    /// # Errors
    ///
    /// The core stopped.
    pub fn clear_history(&self) -> Result<(), TodokeError> {
        self.shared.done(Request::ClearHistory)
    }

    /// Shows a QR pairing offer (this device responds; it is visible to
    /// everyone nearby while the offer shows).
    ///
    /// # Errors
    ///
    /// The core refused (an offer already shows; sessions disabled).
    pub fn pair_show_qr(&self) -> Result<QrOffer, TodokeError> {
        match self.shared.request(Request::PairShowQr)? {
            Response::Qr { text, expires_at } => QrOffer::new(text, expires_at).ok_or_else(|| {
                // Not shown, so not offered either.
                let _ = self.shared.done(Request::StopPairing);
                TodokeError::Internal {
                    message: "the offer does not fit a QR code".to_owned(),
                }
            }),
            _ => Err(TodokeError::unexpected()),
        }
    }

    /// Pairs with the device whose QR offer was scanned (or pasted).
    ///
    /// # Errors
    ///
    /// [`TodokeError::Pairing`] when the offer is wrong, used, or expired.
    pub fn pair_scan_qr(&self, text: String) -> Result<ContactHandle, TodokeError> {
        let text = zeroize::Zeroizing::new(text);
        match self.shared.request(Request::PairScanQr {
            text: text.as_str().to_owned(),
        })? {
            Response::Paired { contact } => Ok(self.handle_for(contact)),
            _ => Err(TodokeError::unexpected()),
        }
    }

    /// Shows a ten-digit pairing code (stranger mode while it shows).
    ///
    /// # Errors
    ///
    /// The core refused.
    pub fn pair_show_code(&self) -> Result<CodeOffer, TodokeError> {
        match self.shared.request(Request::PairShowCode)? {
            Response::Code { code, expires_at } => Ok(CodeOffer::new(code, expires_at)),
            _ => Err(TodokeError::unexpected()),
        }
    }

    /// Nearby devices showing a pairing code.
    ///
    /// # Errors
    ///
    /// The core stopped.
    pub fn strangers(&self) -> Result<Vec<Stranger>, TodokeError> {
        match self.shared.request(Request::Strangers)? {
            Response::Strangers(strangers) => Ok(strangers
                .into_iter()
                .map(|stranger| Stranger {
                    stranger: stranger.stranger,
                })
                .collect()),
            _ => Err(TodokeError::unexpected()),
        }
    }

    /// Pairs with the nearby device `stranger` using the code it shows.
    ///
    /// # Errors
    ///
    /// [`TodokeError::Pairing`] for a wrong code (five end the offer).
    pub fn pair_enter_code(
        &self,
        code: String,
        stranger: String,
    ) -> Result<ContactHandle, TodokeError> {
        let code = zeroize::Zeroizing::new(code);
        match self.shared.request(Request::PairEnterCode {
            code: code.as_str().to_owned(),
            stranger,
        })? {
            Response::Paired { contact } => Ok(self.handle_for(contact)),
            _ => Err(TodokeError::unexpected()),
        }
    }

    /// Stops showing a pairing offer.
    ///
    /// # Errors
    ///
    /// The core stopped.
    pub fn stop_pairing(&self) -> Result<(), TodokeError> {
        self.shared.done(Request::StopPairing)
    }

    /// Hides this device from contacts, or shows it again.
    ///
    /// # Errors
    ///
    /// The core stopped.
    pub fn set_hidden(&self, hidden: bool) -> Result<(), TodokeError> {
        self.shared.done(Request::SetHidden { hidden })
    }

    /// A subscription to the core's events from now on.
    ///
    /// # Errors
    ///
    /// [`TodokeError::State`] beyond 16 subscriptions at once.
    pub fn subscribe(&self) -> Result<Events, TodokeError> {
        Ok(Events {
            queue: self.shared.subscribers.subscribe()?,
        })
    }

    /// Notifications go to `notifier` from now on (replacing one set).
    pub fn set_notifier(&self, notifier: Arc<dyn Notifier>) {
        let previous = self
            .shared
            .notifier
            .lock()
            .ok()
            .and_then(|mut slot| slot.replace(notifier));
        // Released after the lock: releasing calls into the app.
        drop(previous);
    }

    /// No notifications from now on.
    pub fn clear_notifier(&self) {
        let previous = self
            .shared
            .notifier
            .lock()
            .ok()
            .and_then(|mut slot| slot.take());
        drop(previous);
    }

    /// Offers a Wi-Fi link for sessions (PROTOCOL §10.1 to §10.3).
    ///
    /// # Errors
    ///
    /// Always [`TodokeError::Disabled`] for now: the Wi-Fi link adapters
    /// are not built yet.
    pub fn attach_link(&self, link: Arc<dyn RadioLink>) -> Result<(), TodokeError> {
        link.close();
        Err(TodokeError::Disabled {
            message: "Wi-Fi links are not available yet".to_owned(),
        })
    }
}
