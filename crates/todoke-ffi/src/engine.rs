//! The core as an app holds it: one object that starts the core, sends it
//! requests, streams its events, and hands out contact and transfer
//! handles.

#![allow(
    clippy::needless_pass_by_value,
    clippy::must_use_candidate,
    reason = "exported to foreign callers: arguments arrive owned, and must_use means nothing there"
)]

use std::sync::{Arc, Mutex};

use boltffi::{EventSubscription, StreamProducer, export};
use todoke_core::api::{Request, Response};

use crate::error::TodokeError;
use crate::handles::{ContactHandle, TransferHandle, valid_id};
use crate::hooks::{KeyStore, Notifier, RadioLink};
use crate::qr::QrOffer;
use crate::types::{
    CodeOffer, Contact, CoreEvent, HistoryItem, Offer, Settings, Status, Stranger, Transfer,
};

/// Events buffered per subscriber before the oldest are dropped (the app
/// then sees [`CoreEvent::Missed`] from the core's own stream, or reads
/// the offers and transfers again).
const EVENT_BUFFER: usize = 1024;

/// What the core, its handles, and the event thread share.
pub(crate) struct Shared {
    #[cfg(not(target_family = "wasm"))]
    core: todoke_core::runtime::Core,
    pub(crate) events: Arc<StreamProducer<CoreEvent>>,
    notifier: Arc<Mutex<Option<Arc<dyn Notifier>>>>,
}

impl Shared {
    /// Sends `request` and returns the answer, or the core's error.
    pub(crate) async fn request(&self, request: Request) -> Result<Response, TodokeError> {
        #[cfg(not(target_family = "wasm"))]
        {
            match self.core.request(request).await {
                Response::Error { code, message } => Err(TodokeError::from_core(code, message)),
                response => Ok(response),
            }
        }
        #[cfg(target_family = "wasm")]
        {
            let _ = request;
            Err(unsupported())
        }
    }

    /// Sends `request`, which answers `Done`.
    pub(crate) async fn done(&self, request: Request) -> Result<(), TodokeError> {
        match self.request(request).await? {
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

/// The running core of one profile. It stops when the app releases it
/// (and every handle it gave out).
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
            let config = crate::config::core_config(settings)?;
            let source = crate::keys::source(&config.state_dir, key_store, config.key_storage);
            let core = todoke_core::runtime::Core::start(config, Box::new(source))
                .map_err(crate::config::start_error)?;
            let events = Arc::new(StreamProducer::new(EVENT_BUFFER));
            let notifier: Arc<Mutex<Option<Arc<dyn Notifier>>>> = Arc::new(Mutex::new(None));
            crate::forward::spawn(core.subscribe(), Arc::clone(&events), Arc::clone(&notifier))
                .map_err(|_| TodokeError::Internal {
                    message: "the event thread could not start".to_owned(),
                })?;
            Ok(Self {
                shared: Arc::new(Shared {
                    core,
                    events,
                    notifier,
                }),
            })
        }
    }
}

#[export]
impl Core {
    /// Starts the core for the profile in `settings.home`, keeping the
    /// storage key where the platform keeps it natively (the macOS
    /// Keychain) or in a private file, as `settings.key_storage` allows.
    /// Blocks while the profile opens: call it off the UI thread.
    ///
    /// # Errors
    ///
    /// [`TodokeError::Disabled`] in builds without development sessions;
    /// [`TodokeError::Profile`] when the profile cannot be opened.
    pub fn new(settings: Settings) -> Result<Self, TodokeError> {
        Self::start(&settings, None)
    }

    /// Starts the core with the app's key store for the storage key
    /// (Android's Keystore, iOS's Keychain and Secure Enclave).
    ///
    /// # Errors
    ///
    /// As [`Core::new`]; [`TodokeError::Profile`] when the key store
    /// refuses and the policy needs it.
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
    pub async fn status(&self) -> Result<Status, TodokeError> {
        match self.shared.request(Request::Status).await? {
            Response::Status(status) => Ok(status.into()),
            _ => Err(TodokeError::unexpected()),
        }
    }

    /// The paired devices.
    ///
    /// # Errors
    ///
    /// The core stopped.
    pub async fn contacts(&self) -> Result<Vec<Contact>, TodokeError> {
        match self.shared.request(Request::Contacts).await? {
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
        Ok(ContactHandle {
            shared: Arc::clone(&self.shared),
            device,
        })
    }

    /// Transfers in progress or awaiting a decision.
    ///
    /// # Errors
    ///
    /// The core stopped.
    pub async fn transfers(&self) -> Result<Vec<Transfer>, TodokeError> {
        match self.shared.request(Request::Transfers).await? {
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

    /// Offers awaiting this user's decision (what an app that starts late
    /// has not seen as events).
    ///
    /// # Errors
    ///
    /// The core stopped.
    pub async fn offers(&self) -> Result<Vec<Offer>, TodokeError> {
        match self.shared.request(Request::Offers).await? {
            Response::Offers(offers) => Ok(offers.into_iter().map(Offer::from).collect()),
            _ => Err(TodokeError::unexpected()),
        }
    }

    /// Finished transfers, newest first.
    ///
    /// # Errors
    ///
    /// The core stopped.
    pub async fn history(&self) -> Result<Vec<HistoryItem>, TodokeError> {
        match self.shared.request(Request::History).await? {
            Response::History(entries) => Ok(entries.into_iter().map(HistoryItem::from).collect()),
            _ => Err(TodokeError::unexpected()),
        }
    }

    /// Forgets every finished transfer.
    ///
    /// # Errors
    ///
    /// The core stopped.
    pub async fn clear_history(&self) -> Result<(), TodokeError> {
        self.shared.done(Request::ClearHistory).await
    }

    /// Shows a QR pairing offer (this device responds; it is visible to
    /// everyone nearby while the offer shows).
    ///
    /// # Errors
    ///
    /// The core refused (an offer already shows; sessions disabled).
    pub async fn pair_show_qr(&self) -> Result<QrOffer, TodokeError> {
        match self.shared.request(Request::PairShowQr).await? {
            Response::Qr { text, expires_at } => {
                QrOffer::new(text, expires_at).ok_or_else(|| TodokeError::Internal {
                    message: "the offer does not fit a QR code".to_owned(),
                })
            }
            _ => Err(TodokeError::unexpected()),
        }
    }

    /// Pairs with the device whose QR offer was scanned (or pasted).
    ///
    /// # Errors
    ///
    /// [`TodokeError::Pairing`] when the offer is wrong, used, or expired.
    pub async fn pair_scan_qr(&self, text: String) -> Result<ContactHandle, TodokeError> {
        let text = zeroize::Zeroizing::new(text);
        match self
            .shared
            .request(Request::PairScanQr {
                text: text.as_str().to_owned(),
            })
            .await?
        {
            Response::Paired { contact } => Ok(ContactHandle {
                shared: Arc::clone(&self.shared),
                device: contact,
            }),
            _ => Err(TodokeError::unexpected()),
        }
    }

    /// Shows a ten-digit pairing code (stranger mode while it shows).
    ///
    /// # Errors
    ///
    /// The core refused.
    pub async fn pair_show_code(&self) -> Result<CodeOffer, TodokeError> {
        match self.shared.request(Request::PairShowCode).await? {
            Response::Code { code, expires_at } => Ok(CodeOffer { code, expires_at }),
            _ => Err(TodokeError::unexpected()),
        }
    }

    /// Nearby devices showing a pairing code.
    ///
    /// # Errors
    ///
    /// The core stopped.
    pub async fn strangers(&self) -> Result<Vec<Stranger>, TodokeError> {
        match self.shared.request(Request::Strangers).await? {
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
    pub async fn pair_enter_code(
        &self,
        code: String,
        stranger: String,
    ) -> Result<ContactHandle, TodokeError> {
        let code = zeroize::Zeroizing::new(code);
        match self
            .shared
            .request(Request::PairEnterCode {
                code: code.as_str().to_owned(),
                stranger,
            })
            .await?
        {
            Response::Paired { contact } => Ok(ContactHandle {
                shared: Arc::clone(&self.shared),
                device: contact,
            }),
            _ => Err(TodokeError::unexpected()),
        }
    }

    /// Stops showing a pairing offer.
    ///
    /// # Errors
    ///
    /// The core stopped.
    pub async fn stop_pairing(&self) -> Result<(), TodokeError> {
        self.shared.done(Request::StopPairing).await
    }

    /// Hides this device from contacts, or shows it again.
    ///
    /// # Errors
    ///
    /// The core stopped.
    pub async fn set_hidden(&self, hidden: bool) -> Result<(), TodokeError> {
        self.shared.done(Request::SetHidden { hidden }).await
    }

    /// The core's events from now on.
    #[ffi_stream(item = CoreEvent)]
    pub fn events(&self) -> Arc<EventSubscription<CoreEvent>> {
        self.shared.events.subscribe()
    }

    /// Notifications go to `notifier` from now on (replacing one set).
    pub fn set_notifier(&self, notifier: Arc<dyn Notifier>) {
        if let Ok(mut slot) = self.shared.notifier.lock() {
            *slot = Some(notifier);
        }
    }

    /// No notifications from now on.
    pub fn clear_notifier(&self) {
        if let Ok(mut slot) = self.shared.notifier.lock() {
            *slot = None;
        }
    }

    /// Offers a radio link for sessions.
    ///
    /// # Errors
    ///
    /// Always [`TodokeError::Disabled`] for now: PROTOCOL §16 O7 keeps
    /// radio transports disabled.
    pub fn attach_link(&self, link: Arc<dyn RadioLink>) -> Result<(), TodokeError> {
        link.close();
        Err(TodokeError::Disabled {
            message: "radio links are disabled (PROTOCOL §16 O7)".to_owned(),
        })
    }
}
