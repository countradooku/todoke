//! Background service integration around the public todoke core.
//!
//! # Trust boundary
//!
//! Service-manager, IPC, and process requests do not grant peer authentication,
//! file access, or transfer consent; all authorization stays in the core.
//!
//! # Pieces
//!
//! | Piece | What it does |
//! | --- | --- |
//! | [`run`] | Starts the core with the configuration and serves it on the local IPC endpoint until stopped |
//! | [`host`] | The same inside another process (the desktop app): the core for it, served on the endpoint from a thread of its own |
//! | [`ipc`] | The IPC messages, the client the CLI uses, and who may connect (only this user) |
//! | [`paths`] | Configuration, state, and Downloads locations (`TODOKE_HOME` overrides) |
//! | [`keys`] | Where the storage key is kept: the platform's secret storage, behind the core's policy |
//! | [`service`] | Service definitions: a systemd user unit, a launchd agent, a Windows logon task |
//!
//! Notifications: the daemon runs no commands. A notifier subscribes to the
//! event stream (`todoke events --json`) and decides what to show.

#![forbid(unsafe_code)]

#[cfg(not(target_family = "wasm"))]
mod endpoint;
#[cfg(not(target_family = "wasm"))]
pub mod ipc;
#[cfg(not(target_family = "wasm"))]
pub mod keys;
pub mod paths;
#[cfg(not(target_family = "wasm"))]
mod server;
pub mod service;

use core::fmt;

pub use paths::Paths;

/// Why the daemon stopped with an error.
#[derive(Debug)]
pub enum DaemonError {
    /// The configuration could not be read.
    Config(std::io::Error),
    /// Sessions are disabled in this build (PROTOCOL §16 gates).
    Disabled,
    /// The core did not start.
    Core(String),
    /// The IPC endpoint could not be bound (another daemon may be running).
    Endpoint(std::io::Error),
    /// The runtime could not start.
    Runtime(std::io::Error),
}

impl fmt::Display for DaemonError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(error) => write!(f, "configuration: {error}"),
            Self::Disabled => f.write_str(
                "sessions are disabled in this build: suite 0x0001 is not production-enabled (PROTOCOL §16)",
            ),
            Self::Core(error) => write!(f, "{error}"),
            Self::Endpoint(error) if error.kind() == std::io::ErrorKind::AddrInUse => {
                f.write_str("another daemon is already running for this user")
            }
            Self::Endpoint(error) => write!(f, "IPC endpoint: {error}"),
            Self::Runtime(error) => write!(f, "runtime: {error}"),
        }
    }
}

impl std::error::Error for DaemonError {}

/// Runs the daemon in this process until it is interrupted (Ctrl-C,
/// SIGTERM through the service manager) or a client asks it to stop.
///
/// # Errors
///
/// [`DaemonError`].
#[cfg(not(target_family = "wasm"))]
pub fn run(paths: &Paths) -> Result<(), DaemonError> {
    let config = prepare(paths)?;
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(DaemonError::Runtime)?;
    // The endpoint first: a second daemon stops here, before it touches
    // the identity or the quarantine.
    let listener = runtime
        .block_on(endpoint::Listener::bind(&paths.endpoint()))
        .map_err(DaemonError::Endpoint)?;
    let key = keys::source(&config);
    let core = todoke_core::Core::start(config, Box::new(key)).map_err(core_error)?;
    runtime.block_on(async {
        let stop = std::sync::Arc::new(tokio::sync::Notify::new());
        let signal = {
            let stop = std::sync::Arc::clone(&stop);
            async move {
                // Ctrl-C, or SIGTERM from a service manager.
                #[cfg(unix)]
                {
                    let terminate =
                        tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate());
                    match terminate {
                        Ok(mut terminate) => {
                            tokio::select! {
                                _ = tokio::signal::ctrl_c() => {}
                                _ = terminate.recv() => {}
                            }
                        }
                        Err(_) => {
                            let _ = tokio::signal::ctrl_c().await;
                        }
                    }
                }
                #[cfg(not(unix))]
                let _ = tokio::signal::ctrl_c().await;
                stop.notify_one();
            }
        };
        tokio::select! {
            () = server::serve(core, listener, std::sync::Arc::clone(&stop)) => {}
            () = signal => {}
        }
        Ok(())
    })
}

/// The configuration, checked against `paths`, with the private state
/// directory created.
#[cfg(not(target_family = "wasm"))]
fn prepare(paths: &Paths) -> Result<todoke_core::config::CoreConfig, DaemonError> {
    let config = paths.config().map_err(DaemonError::Config)?;
    // The endpoint, the storage key, and every client derive from the
    // state directory the paths give; a configuration naming another
    // would split them.
    let normal = |path: &std::path::Path| path.components().collect::<std::path::PathBuf>();
    if normal(&config.state_dir) != normal(&paths.state_dir) {
        return Err(DaemonError::Config(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            format!(
                "state_dir must be {} (set TODOKE_HOME to move it)",
                paths.state_dir.display()
            ),
        )));
    }
    raise_open_file_limit();
    // The state directory must exist (private) before the endpoint and
    // the key file.
    std::fs::create_dir_all(&config.state_dir).map_err(DaemonError::Config)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&config.state_dir, std::fs::Permissions::from_mode(0o700))
            .map_err(DaemonError::Config)?;
    }
    Ok(config)
}

/// A daemon hosted inside another process (the desktop app): its core,
/// served on the IPC endpoint from a thread of its own, so the CLI and
/// notifiers reach it as they reach the daemon. Dropping it stops serving
/// and, with the last handle, the core.
#[cfg(not(target_family = "wasm"))]
pub struct Hosted {
    core: todoke_core::Core,
    stop: std::sync::Arc<tokio::sync::Notify>,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(not(target_family = "wasm"))]
impl fmt::Debug for Hosted {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Hosted")
    }
}

#[cfg(not(target_family = "wasm"))]
impl Hosted {
    /// The core.
    #[must_use]
    pub const fn core(&self) -> &todoke_core::Core {
        &self.core
    }

    /// Whether the endpoint is still served: false once a client asked the
    /// daemon to stop (`todoke daemon stop`).
    #[must_use]
    pub fn serving(&self) -> bool {
        self.thread
            .as_ref()
            .is_some_and(|thread| !thread.is_finished())
    }
}

#[cfg(not(target_family = "wasm"))]
impl Drop for Hosted {
    fn drop(&mut self) {
        self.stop.notify_one();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Starts the core with the configuration in `paths` and serves it on the
/// IPC endpoint from a new thread, as [`run`] does, until the [`Hosted`] is
/// dropped or a client asks the daemon to stop. Blocks while the identity
/// opens; call it away from a user interface thread.
///
/// # Errors
///
/// [`DaemonError`]; [`DaemonError::Endpoint`] with `AddrInUse` when a
/// daemon already runs for this user.
#[cfg(not(target_family = "wasm"))]
pub fn host(paths: &Paths) -> Result<Hosted, DaemonError> {
    let config = prepare(paths)?;
    let endpoint = paths.endpoint();
    let key = keys::source(&config);
    let stop = std::sync::Arc::new(tokio::sync::Notify::new());
    let (started, ready) = std::sync::mpsc::channel();
    let serving = std::sync::Arc::clone(&stop);
    let thread = std::thread::Builder::new()
        .name("todoke-ipc".into())
        .spawn(move || {
            let runtime = match tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            {
                Ok(runtime) => runtime,
                Err(error) => {
                    let _ = started.send(Err(DaemonError::Runtime(error)));
                    return;
                }
            };
            // The endpoint first, as in `run`.
            let listener = match runtime.block_on(endpoint::Listener::bind(&endpoint)) {
                Ok(listener) => listener,
                Err(error) => {
                    let _ = started.send(Err(DaemonError::Endpoint(error)));
                    return;
                }
            };
            let core = match todoke_core::Core::start(config, Box::new(key)) {
                Ok(core) => core,
                Err(error) => {
                    let _ = started.send(Err(core_error(error)));
                    return;
                }
            };
            if started.send(Ok(core.clone())).is_err() {
                return;
            }
            runtime.block_on(server::serve(core, listener, serving));
        })
        .map_err(DaemonError::Runtime)?;
    match ready.recv() {
        Ok(Ok(core)) => Ok(Hosted {
            core,
            stop,
            thread: Some(thread),
        }),
        Ok(Err(error)) => {
            let _ = thread.join();
            Err(error)
        }
        Err(_) => {
            let _ = thread.join();
            Err(DaemonError::Runtime(std::io::ErrorKind::Other.into()))
        }
    }
}

#[cfg(not(target_family = "wasm"))]
fn core_error(error: todoke_core::StartError) -> DaemonError {
    match error {
        todoke_core::StartError::Disabled => DaemonError::Disabled,
        other => DaemonError::Core(other.to_string()),
    }
}

/// Raises this process's open-file limit toward its hard limit: an offer
/// holds every file open (two handles each, up to §13's 10000 entries),
/// and service managers start with low limits (launchd 256).
#[cfg(not(target_family = "wasm"))]
fn raise_open_file_limit() {
    #[cfg(unix)]
    {
        use rustix::process::{Resource, Rlimit, getrlimit, setrlimit};
        const WANTED: u64 = 65_536;
        let limit = getrlimit(Resource::Nofile);
        let current = limit.current.unwrap_or(u64::MAX);
        let mut target = limit.maximum.map_or(WANTED, |maximum| maximum.min(WANTED));
        // macOS refuses more than its per-process maximum: halve until a
        // value is accepted or nothing would be gained.
        while target > current {
            let raised = Rlimit {
                current: Some(target),
                maximum: limit.maximum,
            };
            if setrlimit(Resource::Nofile, raised).is_ok() {
                return;
            }
            target /= 2;
        }
    }
}

#[cfg(all(test, unix))]
mod tests {
    /// The soft open-file limit rises toward the hard limit (launchd starts
    /// agents at 256, too few for one large folder).
    #[test]
    fn the_open_file_limit_is_raised() {
        use rustix::process::{Resource, getrlimit};
        let before = getrlimit(Resource::Nofile);
        super::raise_open_file_limit();
        let after = getrlimit(Resource::Nofile);
        let current = |limit: &rustix::process::Rlimit| limit.current.unwrap_or(u64::MAX);
        assert!(current(&after) >= current(&before));
        let hard = before.maximum.unwrap_or(u64::MAX);
        assert!(current(&after) >= hard.min(4096), "{after:?}");
    }
}
