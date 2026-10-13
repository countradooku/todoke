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
use std::net::{Ipv6Addr, SocketAddr};

use futures_io::{AsyncRead, AsyncWrite};
use socket2::{Domain, Protocol, Socket, Type};
use tokio::io::{AsyncRead as _, AsyncWrite as _, ReadBuf};
use tokio::net::{TcpListener, TcpStream};

use crate::link::{Link, LinkInfo, LinkKind};
use crate::policy::LanPolicy;
use crate::race::{Candidate, Connector};

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
    fn new(stream: TcpStream, latency: Option<Duration>) -> io::Result<Self> {
        stream.set_nodelay(true)?;
        let mut info =
            LinkInfo::new(LinkKind::Lan).with_addresses(stream.local_addr()?, stream.peer_addr()?);
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
        TcpLink::new(stream, Some(started.elapsed()))
    }
}

/// Accepts [`TcpLink`]s on every interface, IPv6 and IPv4 on one port.
#[derive(Debug)]
pub struct LanListener {
    listener: TcpListener,
    policy: LanPolicy,
}

impl LanListener {
    /// Listens on `port` (0 for any free port) on every IPv6 and IPv4
    /// address, or, if the system has no IPv6, on every IPv4 address.
    ///
    /// # Errors
    ///
    /// The socket error. Must be called within a tokio runtime.
    pub fn bind(port: u16, policy: LanPolicy) -> io::Result<Self> {
        let socket = dual_stack(port).or_else(|_| ipv4_only(port))?;
        socket.listen(BACKLOG)?;
        socket.set_nonblocking(true)?;
        let listener = TcpListener::from_std(socket.into())?;
        Ok(Self { listener, policy })
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
    /// from anywhere else are closed unread.
    ///
    /// # Errors
    ///
    /// An accept error. Some are transient (for example, too many open
    /// files); the caller decides whether to keep accepting.
    pub async fn accept(&self) -> io::Result<TcpLink> {
        loop {
            let (stream, source) = self.listener.accept().await?;
            if self.policy.check_source(source).is_ok() {
                return TcpLink::new(stream, None);
            }
            drop(stream);
        }
    }
}

fn ipv4_only(port: u16) -> io::Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))?;
    reuse_address(&socket)?;
    socket.bind(&SocketAddr::from(([0, 0, 0, 0], port)).into())?;
    Ok(socket)
}

fn dual_stack(port: u16) -> io::Result<Socket> {
    let socket = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    socket.set_only_v6(false)?;
    reuse_address(&socket)?;
    socket.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, port)).into())?;
    Ok(socket)
}

/// On Unix, lets a restarted listener reuse its port while old connections
/// linger in `TIME_WAIT`, as tokio's own `bind` does.
#[cfg(unix)]
fn reuse_address(socket: &Socket) -> io::Result<()> {
    socket.set_reuse_address(true)
}

/// Not on Windows, where `SO_REUSEADDR` would let another process bind the
/// same port.
#[cfg(not(unix))]
#[expect(clippy::unnecessary_wraps, reason = "the same signature as on Unix")]
fn reuse_address(_: &Socket) -> io::Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests;
