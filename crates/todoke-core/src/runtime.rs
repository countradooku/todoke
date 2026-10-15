//! The running core: one thread with a single-threaded runtime that owns
//! the profile, the quarantine, the LAN listener, discovery, pairing, and
//! every session, driven by [`Request`]s and reporting [`Event`]s.
//!
//! Everything runs on one thread so that sessions can borrow the device
//! identity for their whole life (the transfer engine signs Accepts and
//! receipts with it) without sharing key material across threads. The
//! contact store is behind an async lock held only while a handshake runs
//! (docs/adr/0008-core-daemon-cli.md records what that costs).
//!
//! Sessions are suite 0x0001, which PROTOCOL §16 keeps out of production
//! (O6, O10), and code pairing needs O2: without the `unaudited-dev`
//! feature, [`Core::start`] refuses with [`StartError::Disabled`].

use core::fmt;

use tokio::sync::{broadcast, mpsc, oneshot};

use crate::api::{Event, Request, Response};
use crate::config::CoreConfig;
use crate::profile::ProfileError;
use crate::storage_key::StorageKeySource;

/// Why the core did not start.
#[derive(Debug)]
pub enum StartError {
    /// Sessions are disabled in this build (PROTOCOL §16 gates).
    Disabled,
    /// The identity could not be opened.
    Profile(ProfileError),
    /// The quarantine (the receive state) could not be opened: in use by
    /// another instance, damaged, or unavailable.
    Quarantine(String),
    /// The downloads directory or listener could not be used.
    Io(std::io::ErrorKind),
    /// The core thread could not start or stopped at once.
    Thread,
}

impl fmt::Display for StartError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Disabled => f.write_str(
                "sessions are disabled in this build: suite 0x0001 is not production-enabled (PROTOCOL §16)",
            ),
            Self::Profile(error) => write!(f, "{error}"),
            Self::Quarantine(error) => write!(f, "{error}"),
            Self::Io(kind) => write!(f, "{kind}"),
            Self::Thread => f.write_str("the core thread failed"),
        }
    }
}

impl std::error::Error for StartError {}

/// What the core thread is asked to do.
#[cfg_attr(
    not(feature = "unaudited-dev"),
    expect(dead_code, reason = "without sessions no core thread reads commands")
)]
enum Command {
    /// An API request (what the daemon's clients send too).
    Api(Request),
    /// Files handed over already open, to offer to a contact: in this
    /// process only (an open file cannot cross the daemon's socket).
    SendFiles {
        contact: String,
        files: Vec<crate::send::OpenFile>,
    },
}

type Envelope = (Command, oneshot::Sender<Response>);

/// A handle to the running core. Cloning shares it; the core stops when
/// the last handle is dropped.
#[derive(Clone)]
pub struct Core {
    requests: mpsc::Sender<Envelope>,
    events: broadcast::Sender<Event>,
    _thread: std::sync::Arc<Stopper>,
}

impl fmt::Debug for Core {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Core")
    }
}

struct Stopper {
    stop: std::sync::Mutex<Option<oneshot::Sender<()>>>,
    thread: std::sync::Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl Drop for Stopper {
    fn drop(&mut self) {
        if let Some(stop) = self.stop.lock().ok().and_then(|mut stop| stop.take()) {
            let _ = stop.send(());
        }
        if let Some(thread) = self.thread.lock().ok().and_then(|mut thread| thread.take()) {
            let _ = thread.join();
        }
    }
}

impl Core {
    /// Starts the core with `config`, sealing its state with the key from
    /// `key_source`. Returns once the identity is open and the LAN listener
    /// (if enabled) is bound.
    ///
    /// # Errors
    ///
    /// [`StartError`]; [`StartError::Disabled`] in builds without the
    /// `unaudited-dev` feature.
    pub fn start(
        config: CoreConfig,
        key_source: Box<dyn StorageKeySource + Send>,
    ) -> Result<Self, StartError> {
        #[cfg(not(feature = "unaudited-dev"))]
        {
            let _ = (config, key_source);
            Err(StartError::Disabled)
        }
        #[cfg(feature = "unaudited-dev")]
        {
            let (requests, receiver) = mpsc::channel(64);
            let (events, _) = broadcast::channel(1024);
            let (ready, started) = std::sync::mpsc::channel();
            let (stop, stopped) = oneshot::channel();
            let sender = events.clone();
            let thread = std::thread::Builder::new()
                .name("todoke-core".into())
                .spawn(move || {
                    let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                        .enable_all()
                        .build()
                    else {
                        let _ = ready.send(Err(StartError::Thread));
                        return;
                    };
                    let local = tokio::task::LocalSet::new();
                    local.block_on(&runtime, async move {
                        match running::State::open(config, &*key_source, sender) {
                            Ok(state) => {
                                let _ = ready.send(Ok(()));
                                running::run(state, receiver, stopped).await;
                            }
                            Err(error) => {
                                let _ = ready.send(Err(error));
                            }
                        }
                    });
                })
                .map_err(|_| StartError::Thread)?;
            started.recv().map_err(|_| StartError::Thread)??;
            Ok(Self {
                requests,
                events,
                _thread: std::sync::Arc::new(Stopper {
                    stop: std::sync::Mutex::new(Some(stop)),
                    thread: std::sync::Mutex::new(Some(thread)),
                }),
            })
        }
    }

    /// Sends `request` and waits for the response.
    pub async fn request(&self, request: Request) -> Response {
        self.command(Command::Api(request)).await
    }

    /// Offers `files`, handed over already open for the local user (an
    /// Android document), to `contact`, as [`Request::Send`] offers paths:
    /// the answer is `Offered`, or an error. Only regular files, each under
    /// its own name (`crate::send::walk_open`).
    pub async fn send_files(&self, contact: String, files: Vec<crate::send::OpenFile>) -> Response {
        self.command(Command::SendFiles { contact, files }).await
    }

    async fn command(&self, command: Command) -> Response {
        let (reply, response) = oneshot::channel();
        if self.requests.send((command, reply)).await.is_err() {
            return Response::error(crate::api::ErrorCode::Internal, "the core stopped");
        }
        response.await.unwrap_or_else(|_| {
            Response::error(crate::api::ErrorCode::Internal, "the core stopped")
        })
    }

    /// Events from now on. A receiver that falls more than 1024 events
    /// behind loses the oldest ones.
    #[must_use]
    pub fn subscribe(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }
}

#[cfg(feature = "unaudited-dev")]
mod relay;
#[cfg(feature = "unaudited-dev")]
mod running;
#[cfg(feature = "unaudited-dev")]
mod session;
#[cfg(all(test, feature = "unaudited-dev"))]
mod tests;

/// Without the development gates nothing starts (PROTOCOL §16). Run alone
/// (`cargo test -p todoke-core`): the workspace's tests enable the gates.
#[cfg(all(test, not(feature = "unaudited-dev")))]
mod gate_tests {
    use super::*;

    #[test]
    fn sessions_are_disabled_without_the_gates() {
        let config = CoreConfig::new("/nonexistent/state".into(), "/nonexistent/down".into());
        let key = crate::storage_key::KeyFile::new("/nonexistent/key");
        assert!(matches!(
            Core::start(config, Box::new(key)),
            Err(StartError::Disabled)
        ));
    }
}
