//! How the app reaches the core. One core runs per user: when a daemon
//! already runs (started at login, say), the app attaches to it over its
//! IPC endpoint; otherwise the app hosts the daemon itself, so the CLI and
//! notifiers reach the same core while the window is open. Either way the
//! views see one [`Backend`]: requests, answers, and the event stream.
//!
//! Nothing here blocks the UI thread: requests are futures over channels,
//! and [`start`] (which opens the profile) runs on the background executor.

use core::future::Future;
use core::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use todoke_core::api::{ErrorCode, Event, Request, Response};
use todoke_daemon::ipc::Client;
use todoke_daemon::{DaemonError, Hosted, Paths};
use tokio::sync::{broadcast, mpsc, oneshot};

use crate::model::Connection;

/// A response on its way.
pub type Reply = Pin<Box<dyn Future<Output = Response> + Send>>;

/// The core, as the views see it.
pub trait Backend: Send + Sync {
    /// Sends `request`; the reply resolves with the core's answer, or an
    /// `Internal` error if the core went away.
    fn request(&self, request: Request) -> Reply;

    /// The events from now on. A receiver that falls behind is told how
    /// many it missed (`Lagged`), and the app fetches everything again.
    fn events(&self) -> broadcast::Receiver<Event>;

    /// Whether the core is still reachable: false after `todoke daemon
    /// stop`, or when an attached daemon went away.
    fn alive(&self) -> bool;
}

/// The core this app hosts.
pub struct HostedBackend {
    hosted: Hosted,
}

impl Backend for HostedBackend {
    fn request(&self, request: Request) -> Reply {
        let core = self.hosted.core().clone();
        Box::pin(async move { core.request(request).await })
    }

    fn events(&self) -> broadcast::Receiver<Event> {
        self.hosted.core().subscribe()
    }

    fn alive(&self) -> bool {
        self.hosted.serving()
    }
}

type Envelope = (Request, oneshot::Sender<Response>);

/// A daemon's core, over its IPC endpoint, from a thread of its own.
pub struct AttachedBackend {
    requests: mpsc::Sender<Envelope>,
    events: broadcast::Sender<Event>,
    alive: Arc<AtomicBool>,
}

/// The answer when the daemon is gone.
fn gone() -> Response {
    Response::error(ErrorCode::Internal, "the todoke daemon is not running")
}

/// The answer when a request got no reply: it may or may not have been
/// carried out.
fn unanswered() -> Response {
    Response::error(
        ErrorCode::Internal,
        "the todoke daemon did not answer; check Transfers before trying again",
    )
}

impl Backend for AttachedBackend {
    fn request(&self, request: Request) -> Reply {
        let requests = self.requests.clone();
        Box::pin(async move {
            let (reply, answer) = oneshot::channel();
            if requests.send((request, reply)).await.is_err() {
                return gone();
            }
            answer.await.unwrap_or_else(|_| gone())
        })
    }

    fn events(&self) -> broadcast::Receiver<Event> {
        self.events.subscribe()
    }

    fn alive(&self) -> bool {
        self.alive.load(Ordering::Acquire)
    }
}

impl AttachedBackend {
    /// Connects to the daemon at `endpoint`: one connection for requests,
    /// one for events. Blocks until both are open.
    ///
    /// # Errors
    ///
    /// An I/O error if no daemon answers there.
    pub fn connect(endpoint: &std::path::Path) -> std::io::Result<Self> {
        let (requests, mut inbox) = mpsc::channel::<Envelope>(64);
        let (events, _) = broadcast::channel(1024);
        let alive = Arc::new(AtomicBool::new(true));
        let (opened, ready) = std::sync::mpsc::channel();
        let endpoint = endpoint.to_owned();
        let (sender, flag) = (events.clone(), Arc::clone(&alive));
        std::thread::Builder::new()
            .name("todoke-attach".into())
            .spawn(move || {
                let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                else {
                    let _ = opened.send(Err(std::io::ErrorKind::Other.into()));
                    return;
                };
                runtime.block_on(async move {
                    let connected = async {
                        let client = Client::connect(&endpoint).await?;
                        let stream = Client::connect(&endpoint).await?.subscribe().await?;
                        std::io::Result::Ok((client, stream))
                    };
                    let (client, mut stream) = match connected.await {
                        Ok(both) => both,
                        Err(error) => {
                            let _ = opened.send(Err(error));
                            return;
                        }
                    };
                    let _ = opened.send(Ok(()));
                    let watch = Arc::clone(&flag);
                    let forward = tokio::spawn(async move {
                        while let Ok(Some(event)) = stream.next().await {
                            let _ = sender.send(event);
                        }
                        watch.store(false, Ordering::Release);
                    });
                    let pool = Arc::new(Pool::new(client));
                    // A failed request is reported to its caller, never as the
                    // daemon being gone (it may be busy, or out of
                    // descriptors): only the end of the event stream says so.
                    while let Some((request, reply)) = inbox.recv().await {
                        let (pool, endpoint) = (Arc::clone(&pool), endpoint.clone());
                        tokio::spawn(async move {
                            let response = pool.request(&endpoint, request).await;
                            let _ = reply.send(response.unwrap_or_else(unanswered));
                        });
                    }
                    forward.abort();
                    flag.store(false, Ordering::Release);
                });
            })?;
        match ready.recv() {
            Ok(Ok(())) => Ok(Self {
                requests,
                events,
                alive,
            }),
            Ok(Err(error)) => Err(error),
            Err(_) => Err(std::io::ErrorKind::Other.into()),
        }
    }
}

/// Idle request connections to a daemon, so a slow request (an offer of
/// a large folder is hashed first) never holds up the others.
struct Pool {
    idle: std::sync::Mutex<Vec<(Client, std::time::Instant)>>,
}

impl Pool {
    /// The most idle connections kept.
    const KEEP: usize = 4;
    /// A connection idle this long is dropped: the daemon closes idle ones
    /// after two minutes, and a request must never be sent twice (it may
    /// not be idempotent: an offer), so none is sent on one that may be
    /// closing.
    const FRESH: core::time::Duration = core::time::Duration::from_secs(60);

    fn new(client: Client) -> Self {
        Self {
            idle: std::sync::Mutex::new(vec![(client, std::time::Instant::now())]),
        }
    }

    /// Sends `request` on an idle connection or a new one; `None` if the
    /// daemon is gone.
    async fn request(&self, endpoint: &std::path::Path, request: Request) -> Option<Response> {
        let idle = self.idle.lock().ok().and_then(|mut idle| {
            idle.retain(|(_, since)| since.elapsed() < Self::FRESH);
            idle.pop()
        });
        let mut client = match idle {
            Some((client, _)) => client,
            None => Client::connect(endpoint).await.ok()?,
        };
        let response = client.request(request).await.ok()?;
        if let Ok(mut idle) = self.idle.lock()
            && idle.len() < Self::KEEP
        {
            idle.push((client, std::time::Instant::now()));
        }
        Some(response)
    }
}

/// A started backend and how it runs.
pub struct Started {
    /// The core.
    pub backend: Arc<dyn Backend>,
    /// [`Connection::Hosted`] or [`Connection::Attached`].
    pub connection: Connection,
}

/// Attaches to a running daemon, or hosts one. Blocks while the profile
/// opens: run it on the background executor.
///
/// # Errors
///
/// The [`Connection`] to show instead: `Disabled` or `Failed`.
pub fn start(paths: &Paths) -> Result<Started, Connection> {
    let attached = |paths: &Paths| {
        AttachedBackend::connect(&paths.endpoint()).map(|backend| Started {
            backend: Arc::new(backend),
            connection: Connection::Attached,
        })
    };
    if let Ok(started) = attached(paths) {
        return Ok(started);
    }
    match todoke_daemon::host(paths) {
        Ok(hosted) => Ok(Started {
            backend: Arc::new(HostedBackend { hosted }),
            connection: Connection::Hosted,
        }),
        // A daemon started meanwhile, or one refused the first attempt.
        Err(DaemonError::Endpoint(error)) if error.kind() == std::io::ErrorKind::AddrInUse => {
            attached(paths).map_err(|_| {
                Connection::Failed(
                    "another todoke is running for this user but does not answer".to_owned(),
                )
            })
        }
        Err(DaemonError::Disabled) => Err(Connection::Disabled),
        Err(error) => Err(Connection::Failed(error.to_string())),
    }
}

/// Asks the daemon at `paths` to stop, so it can start again with a new
/// configuration. Blocks until it was asked.
///
/// # Errors
///
/// An I/O error if no daemon answers.
pub fn stop_daemon(paths: &Paths) -> std::io::Result<()> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async { Client::connect(&paths.endpoint()).await?.shutdown().await })
}

#[cfg(any(test, feature = "mock"))]
pub mod mock {
    //! A scripted core for the UI tests: it answers from a closure, records
    //! every request, and sends events on demand.

    use std::sync::Mutex;

    use super::{Backend, Reply, broadcast};
    use todoke_core::api::{Event, Request, Response};

    type Script = Box<dyn Fn(&Request) -> Response + Send + Sync>;

    /// The mock core.
    pub struct Mock {
        script: Script,
        requests: Mutex<Vec<Request>>,
        events: broadcast::Sender<Event>,
        alive: std::sync::atomic::AtomicBool,
    }

    impl Mock {
        /// A core that answers with `script`.
        #[must_use]
        pub fn new(script: impl Fn(&Request) -> Response + Send + Sync + 'static) -> Self {
            Self {
                script: Box::new(script),
                requests: Mutex::new(Vec::new()),
                events: broadcast::channel(64).0,
                alive: std::sync::atomic::AtomicBool::new(true),
            }
        }

        /// Makes the core look stopped (`todoke daemon stop`).
        pub fn stop(&self) {
            self.alive
                .store(false, std::sync::atomic::Ordering::Release);
        }

        /// Sends `event` to the app.
        pub fn emit(&self, event: Event) {
            let _ = self.events.send(event);
        }

        /// Every request so far.
        #[must_use]
        pub fn requests(&self) -> Vec<Request> {
            self.requests
                .lock()
                .map(|requests| requests.clone())
                .unwrap_or_default()
        }

        /// The requests other than the periodic fetches.
        #[must_use]
        pub fn actions(&self) -> Vec<Request> {
            self.requests()
                .into_iter()
                .filter(|request| {
                    !matches!(
                        request,
                        Request::Status
                            | Request::Contacts
                            | Request::Transfers
                            | Request::Offers
                            | Request::History
                            | Request::Strangers
                    )
                })
                .collect()
        }
    }

    impl Backend for Mock {
        fn request(&self, request: Request) -> Reply {
            let response = (self.script)(&request);
            if let Ok(mut requests) = self.requests.lock() {
                requests.push(request);
            }
            Box::pin(async move { response })
        }

        fn events(&self) -> broadcast::Receiver<Event> {
            self.events.subscribe()
        }

        fn alive(&self) -> bool {
            self.alive.load(std::sync::atomic::Ordering::Acquire)
        }
    }
}
