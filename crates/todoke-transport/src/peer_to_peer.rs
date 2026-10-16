//! LAN links over Apple peer-to-peer Wi-Fi (AWDL, PROTOCOL §10.1): the same
//! TCP stream and session as on any LAN, carried by Network.framework
//! (`todoke_sys_macos::p2p`), the only way Apple supports. A candidate's
//! address is link-local IPv6 scoped to a peer-to-peer interface; the
//! policy applies as to every LAN address, on both sides.

use core::time::Duration;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use todoke_sys_macos::p2p;
use tokio::sync::{Mutex, mpsc};

use crate::policy::LanPolicy;
use crate::tcp::{CONNECT_TIMEOUT, TcpLink};

/// Connections accepted and not yet taken; more wait in the platform.
const QUEUE: usize = 16;
/// How often the accepting thread looks whether it should stop.
const STOP_CHECK: Duration = Duration::from_millis(500);

/// Whether `address` is reached over peer-to-peer Wi-Fi.
pub(crate) fn reaches(address: SocketAddr) -> bool {
    matches!(address, SocketAddr::V6(v6)
        if v6.ip().is_unicast_link_local() && p2p::is_peer_to_peer(v6.scope_id()))
}

/// Opens a LAN link to `address` over peer-to-peer Wi-Fi.
pub(crate) async fn connect(address: SocketAddr) -> io::Result<TcpLink> {
    let started = tokio::time::Instant::now();
    let bridged = tokio::task::spawn_blocking(move || p2p::connect(address, true, CONNECT_TIMEOUT))
        .await
        .map_err(|_| io::Error::other("the peer-to-peer connection did not finish"))??;
    TcpLink::bridged(
        bridged.stream,
        Some(bridged.remote.unwrap_or(address)),
        Some(started.elapsed()),
    )
}

/// A listener for peer-to-peer connections, accepted on a thread of its
/// own and handed over as links.
pub(crate) struct Accepting {
    port: u16,
    links: Mutex<mpsc::Receiver<p2p::Bridged>>,
    stop: Arc<AtomicBool>,
}

impl core::fmt::Debug for Accepting {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Accepting")
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

impl Accepting {
    /// Listens on a free port, peer-to-peer interfaces included.
    pub(crate) fn start() -> io::Result<Self> {
        let listener = p2p::Listener::start(true)?;
        let port = listener.port();
        let (accepted, links) = mpsc::channel(QUEUE);
        let stop = Arc::new(AtomicBool::new(false));
        let stopping = Arc::clone(&stop);
        std::thread::Builder::new()
            .name("todoke-p2p-listen".to_owned())
            .spawn(move || {
                // The listener goes (cancelled) when this thread ends.
                while !stopping.load(Ordering::Acquire) {
                    match listener.accept(STOP_CHECK) {
                        Ok(bridged) => {
                            if accepted.blocking_send(bridged).is_err() {
                                return;
                            }
                        }
                        Err(error) if error.kind() == io::ErrorKind::TimedOut => {}
                        Err(_) => return,
                    }
                }
            })?;
        Ok(Self {
            port,
            links: Mutex::new(links),
            stop,
        })
    }

    pub(crate) const fn port(&self) -> u16 {
        self.port
    }

    /// The next connection from an address the policy allows; `None` once
    /// the listener is gone.
    pub(crate) async fn next(&self, policy: LanPolicy) -> Option<TcpLink> {
        loop {
            let bridged = self.links.lock().await.recv().await?;
            let Some(remote) = bridged.remote else {
                continue;
            };
            if policy.check_source(remote).is_err() {
                continue;
            }
            if let Ok(link) = TcpLink::bridged(bridged.stream, Some(remote), None) {
                return Some(link);
            }
        }
    }
}

impl Drop for Accepting {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
    }
}
