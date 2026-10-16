//! TCP links on the local network.
//!
//! Connections go only to addresses the [`LanPolicy`] allows, and the
//! listener drops connections from any other source before reading a byte.
//! `TCP_NODELAY` is set: every write is one complete session record, and
//! Nagle's algorithm would hold back small control frames (chunk requests,
//! acknowledgements) behind unacknowledged data. Send and receive buffer
//! sizes are left to the system, whose automatic tuning (Linux, macOS,
//! Windows) grows them with the path; fixing a size turns that tuning off.

use core::pin::Pin;
use core::task::{Context, Poll};
use core::time::Duration;
use std::io;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use futures_io::{AsyncRead, AsyncWrite};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncRead as _, AsyncWrite as _, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

use crate::link::{Link, LinkInfo, LinkKind};
use crate::policy::LanPolicy;
use crate::race::{Candidate, Connector};

/// Binds a socket to a direct link before it listens or connects, given
/// its raw handle (a file descriptor, or a Windows socket): what a platform
/// needs where a link is a network of its own (Android's
/// `Network.bindSocket`).
pub type BindSocket = dyn Fn(i64) -> io::Result<()> + Send + Sync;

/// A socket's raw handle, for [`BindSocket`].
#[cfg(unix)]
fn raw_handle(socket: &impl std::os::fd::AsRawFd) -> i64 {
    i64::from(socket.as_raw_fd())
}

#[cfg(windows)]
fn raw_handle(socket: &impl std::os::windows::io::AsRawSocket) -> i64 {
    i64::try_from(socket.as_raw_socket()).unwrap_or(-1)
}

/// How long one TCP connection attempt may take.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// Pending connections the listener's backlog holds; unauthenticated
/// attempts are limited further by the session layer (§13).
const BACKLOG: i32 = 16;

/// A TCP connection as a [`Link`].
pub struct TcpLink {
    stream: TcpStream,
    info: LinkInfo,
}

impl TcpLink {
    fn new(stream: TcpStream, latency: Option<Duration>, kind: LinkKind) -> io::Result<Self> {
        stream.set_nodelay(true)?;
        let mut info =
            LinkInfo::new(kind).with_addresses(stream.local_addr()?, stream.peer_addr()?);
        if let Some(latency) = latency {
            info = info.with_latency(latency);
        }
        Ok(Self { stream, info })
    }
}

impl core::fmt::Debug for TcpLink {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("TcpLink")
            .field("info", &self.info)
            .finish_non_exhaustive()
    }
}

impl Link for TcpLink {
    fn info(&self) -> &LinkInfo {
        &self.info
    }
}

impl AsyncRead for TcpLink {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let mut read = ReadBuf::new(buf);
        match Pin::new(&mut self.stream).poll_read(cx, &mut read) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(read.filled().len())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for TcpLink {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write_vectored(cx, bufs)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_close(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

/// Opens [`TcpLink`]s to policy-approved LAN candidates.
#[derive(Clone, Copy, Debug, Default)]
pub struct TcpConnector {
    policy: LanPolicy,
}

impl TcpConnector {
    /// A connector under `policy`.
    #[must_use]
    pub const fn new(policy: LanPolicy) -> Self {
        Self { policy }
    }
}

impl Connector for TcpConnector {
    type Link = TcpLink;

    async fn connect(&self, candidate: Candidate) -> io::Result<TcpLink> {
        let address = candidate.address();
        if candidate.kind() != LinkKind::Lan {
            return Err(io::ErrorKind::Unsupported.into());
        }
        self.policy
            .check_peer(address)
            .map_err(|refusal| io::Error::new(io::ErrorKind::PermissionDenied, refusal))?;
        let started = tokio::time::Instant::now();
        let stream = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(address))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        TcpLink::new(stream, Some(started.elapsed()), LinkKind::Lan)
    }
}

impl TcpConnector {
    /// Opens a [`LinkKind::Direct`] link to `host` from `local`, this
    /// device's address on a direct link (§10.2): the socket is bound to
    /// that address first, so the connection leaves through that link.
    /// `host` is the address the link reported for the host; the policy
    /// still checks it. `bind`, if given, binds the socket to the link
    /// first.
    ///
    /// # Errors
    ///
    /// The policy's refusal (`PermissionDenied`), a socket error, or
    /// `TimedOut`.
    pub async fn connect_direct(
        &self,
        local: IpAddr,
        host: SocketAddr,
        bind: Option<&BindSocket>,
    ) -> io::Result<TcpLink> {
        self.policy
            .check_peer(host)
            .map_err(|refusal| io::Error::new(io::ErrorKind::PermissionDenied, refusal))?;
        let from = SocketAddr::new(local, 0);
        let socket = match host {
            SocketAddr::V4(_) => tokio::net::TcpSocket::new_v4()?,
            SocketAddr::V6(_) => tokio::net::TcpSocket::new_v6()?,
        };
        let from = match (from, host) {
            // A link-local IPv6 source carries the host's scope (its
            // interface).
            (SocketAddr::V6(mut v6), SocketAddr::V6(to)) => {
                v6.set_scope_id(to.scope_id());
                SocketAddr::V6(v6)
            }
            (from, _) => from,
        };
        if let Some(bind) = bind {
            bind(raw_handle(&socket))?;
        }
        socket.bind(from)?;
        let started = tokio::time::Instant::now();
        let stream = tokio::time::timeout(CONNECT_TIMEOUT, socket.connect(host))
            .await
            .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
        TcpLink::new(stream, Some(started.elapsed()), LinkKind::Direct)
    }
}

/// Accepts [`TcpLink`]s on every interface, IPv6 and IPv4 on one port.
#[derive(Debug)]
pub struct LanListener {
    listener: TcpListener,
    policy: LanPolicy,
    kind: LinkKind,
    /// Only link-local IPv6 peers arriving on these interfaces (a direct
    /// link whose address is not known yet), if set.
    scopes: Option<Vec<u32>>,
}

impl LanListener {
    /// Listens on `port` (0 for any free port) on every IPv6 and IPv4
    /// address, or, if the system has no IPv6, on every IPv4 address.
    ///
    /// The port is never shared: listening on IPv4 alone happens only
    /// when the system has no IPv6 (never because the port is taken, which
    /// would leave its IPv6 side to another socket), and on Windows the
    /// port is held exclusively (`SO_EXCLUSIVEADDRUSE`).
    ///
    /// # Errors
    ///
    /// The socket error (`AddrInUse` for a taken port). Must be called
    /// within a tokio runtime.
    pub fn bind(port: u16, policy: LanPolicy) -> io::Result<Self> {
        let socket = match dual_stack(port)? {
            Some(socket) => socket,
            None => ipv4_only(port)?,
        };
        socket.listen(BACKLOG)?;
        socket.set_nonblocking(true)?;
        let listener = TcpListener::from_std(socket.into())?;
        Ok(Self {
            listener,
            policy,
            kind: LinkKind::Lan,
            scopes: None,
        })
    }

    /// Listens on `local`, this device's address on a direct link (§10.2),
    /// on a free port: only connections that arrive on that link's address
    /// are accepted, as [`LinkKind::Direct`] links. `bind`, if given, binds
    /// the socket to the link first.
    ///
    /// # Errors
    ///
    /// The socket error. Must be called within a tokio runtime.
    pub fn bind_direct(
        local: SocketAddr,
        policy: LanPolicy,
        bind: Option<&BindSocket>,
    ) -> io::Result<Self> {
        let domain = Domain::for_address(local);
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        if local.is_ipv6() {
            socket.set_only_v6(true)?;
        }
        claim_port(&socket)?;
        if let Some(bind) = bind {
            bind(raw_handle(&socket))?;
        }
        // The address as given (a link-local IPv6 one keeps its scope), on
        // a free port.
        let mut at = local;
        at.set_port(0);
        socket.bind(&at.into())?;
        socket.listen(BACKLOG)?;
        socket.set_nonblocking(true)?;
        let listener = TcpListener::from_std(socket.into())?;
        Ok(Self {
            listener,
            policy,
            kind: LinkKind::Direct,
            scopes: None,
        })
    }

    /// Listens for a direct link (§10.2) whose own address is not known
    /// before the joiner sets it up (a Wi-Fi Aware data path): on every
    /// IPv6 address, on a free port, accepting only link-local peers that
    /// arrive on one of `scopes`, the link's possible interfaces.
    /// `bind`, if given, binds the socket to the link first.
    ///
    /// # Errors
    ///
    /// [`io::ErrorKind::InvalidInput`] for no interfaces; the socket
    /// error. Must be called within a tokio runtime.
    pub fn bind_direct_scoped(
        scopes: Vec<u32>,
        policy: LanPolicy,
        bind: Option<&BindSocket>,
    ) -> io::Result<Self> {
        if scopes.is_empty() || scopes.contains(&0) {
            return Err(io::ErrorKind::InvalidInput.into());
        }
        let mut listener =
            Self::bind_direct(SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)), policy, bind)?;
        listener.scopes = Some(scopes);
        Ok(listener)
    }

    /// The port it listens on, for the mDNS SRV record.
    ///
    /// # Errors
    ///
    /// The socket error.
    pub fn port(&self) -> io::Result<u16> {
        Ok(self.listener.local_addr()?.port())
    }

    /// The next connection from an address the policy allows; connections
    /// from anywhere else, and connections that fail while they are set up,
    /// are closed unread.
    ///
    /// # Errors
    ///
    /// An accept error. Some are transient (for example, too many open
    /// files); the caller decides whether to keep accepting.
    pub async fn accept(&self) -> io::Result<TcpLink> {
        loop {
            let (stream, source) = self.listener.accept().await?;
            if self.policy.check_source(source).is_err() || !self.in_scope(source) {
                continue;
            }
            // A connection reset before it was set up (some systems then fail
            // `TCP_NODELAY` or the address queries) is that connection's
            // problem, not the listener's: drop it and keep accepting.
            if let Ok(link) = TcpLink::new(stream, None, self.kind) {
                return Ok(link);
            }
        }
    }
}

impl LanListener {
    /// Whether `source` arrived where this listener accepts.
    fn in_scope(&self, source: SocketAddr) -> bool {
        let Some(scopes) = &self.scopes else {
            return true;
        };
        match source {
            SocketAddr::V6(v6) => {
                v6.ip().is_unicast_link_local() && scopes.contains(&v6.scope_id())
            }
            SocketAddr::V4(_) => false,
        }
    }
}

fn ipv4_only(port: u16) -> io::Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    claim_port(&socket)?;
    socket.bind(&SocketAddr::from(([0, 0, 0, 0], port)).into())?;
    Ok(socket)
}

/// A dual-stack socket bound to `port`; `None` if the system has no IPv6
/// (no IPv6 sockets, no dual stack, or no IPv6 address). Any other error,
/// a taken port first of all, is returned.
fn dual_stack(port: u16) -> io::Result<Option<Socket>> {
    let Ok(socket) = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP)) else {
        return Ok(None);
    };
    if socket.set_only_v6(false).is_err() {
        return Ok(None);
    }
    claim_port(&socket)?;
    match socket.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).into()) {
        Ok(()) => Ok(Some(socket)),
        Err(error) if error.kind() == io::ErrorKind::AddrNotAvailable => Ok(None),
        Err(error) => Err(error),
    }
}

/// On Unix, lets a restarted listener reuse its port while old connections
/// linger in `TIME_WAIT`, as tokio's own `bind` does (it lets no one
/// share a port that is listened on).
#[cfg(unix)]
fn claim_port(socket: &Socket) -> io::Result<()> {
    socket.set_reuse_address(true)
}

/// On Windows, holds the port exclusively: no socket binds beside it, and
/// it binds beside none (never `SO_REUSEADDR`, which would let another
/// process take the port).
#[cfg(windows)]
fn claim_port(socket: &Socket) -> io::Result<()> {
    todoke_sys_windows::socket::exclusive_address_use(socket)
}

#[cfg(not(any(unix, windows)))]
#[expect(clippy::unnecessary_wraps, reason = "the same signature as elsewhere")]
fn claim_port(_: &Socket) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests;
