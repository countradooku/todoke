//! The relay transport (PROTOCOL §10): QUIC v1 / TLS 1.3 to an untrusted
//! relay, a rendezvous on a token both endpoints know, and the control
//! stream turned into an opaque tunnel that carries a session.
//!
//! TLS protects the path to the relay and authenticates the relay chosen
//! (platform validation, or a pinned key): it says nothing about the peer.
//! The session over the tunnel authenticates the peer and protects every
//! byte (§4, §5); a relay that tampers with, replays, or drops tunnel
//! bytes breaks the session, never its confidentiality or integrity.
//!
//! This client sends no direct-path candidates and never probes: §10 and
//! §16 (O7) keep hole punching disabled until a direct-path profile is
//! ratified. Candidates and `Punch` from the relay are ignored.

use core::fmt;
use core::pin::Pin;
use core::task::{Context, Poll};
use core::time::Duration;
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use futures_io::{AsyncRead, AsyncWrite};
use quinn::{RecvStream, SendStream};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::crypto::CryptoProvider;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use todoke_proto::relay::{
    CloseCode, Control, MAX_ROOM_SECONDS, MAX_WAIT_SECONDS, Random16, RendezvousToken,
};

use crate::link::{Link, LinkInfo, LinkKind};

/// The relay's ALPN. §10 fixes the record layout but not the relay's
/// ALPN; this one names the record version.
pub const ALPN: &[u8] = b"todoke-relay/1";
/// The prefix of a written key pin: `spki-sha256:` and 64 hex digits, the
/// SHA-256 of the relay certificate's DER `SubjectPublicKeyInfo`.
pub const PIN_PREFIX: &str = "spki-sha256:";

/// How long connecting to a relay may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// How long the relay has to answer `Register`.
const ANSWER_TIMEOUT: Duration = Duration::from_secs(10);
/// QUIC keep-alive and idle timeout: a tunnel idle between transfers stays
/// open, a dead relay is noticed.
const KEEP_ALIVE: Duration = Duration::from_secs(10);
const IDLE: Duration = Duration::from_secs(30);
/// The tunnel's receive window: what a relay can make this device buffer.
const STREAM_WINDOW: u32 = 1 << 20;

/// A relay this device may use. Everything here is local configuration;
/// nothing is learned from the network.
#[derive(Clone, PartialEq, Eq)]
pub struct RelayEndpoint {
    /// Its name in the relay list (also its rendezvous-hashing key).
    pub name: String,
    /// `host:port` of its UDP listener.
    pub address: String,
    /// The TLS server name.
    pub server_name: String,
    /// Its key pin; without one, the platform validates its certificate.
    pub pin: Option<[u8; 32]>,
}

impl fmt::Debug for RelayEndpoint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayEndpoint")
            .field("name", &self.name)
            .field("pinned", &self.pin.is_some())
            .finish_non_exhaustive()
    }
}

/// A written pin (`spki-sha256:` and 64 lowercase or uppercase hex).
#[must_use]
pub fn parse_pin(text: &str) -> Option<[u8; 32]> {
    let hex = text.strip_prefix(PIN_PREFIX)?.as_bytes();
    if hex.len() != 64 {
        return None;
    }
    let digit = |c: u8| (c as char).to_digit(16).and_then(|d| u8::try_from(d).ok());
    let mut pin = [0; 32];
    for (pair, byte) in hex.as_chunks::<2>().0.iter().zip(pin.iter_mut()) {
        *byte = (digit(pair[0])? << 4) | digit(pair[1])?;
    }
    Some(pin)
}

/// The relay both endpoints of `token` use: of `relays`, the one with the
/// highest `BLAKE3(name || token)` (rendezvous hashing), so peers with the
/// same relay list meet on the same node without asking anyone, and a
/// node leaving the list moves only its own tokens.
#[must_use]
pub fn choose<'r>(
    relays: &'r [RelayEndpoint],
    token: &RendezvousToken,
) -> Option<&'r RelayEndpoint> {
    relays.iter().max_by_key(|relay| {
        let mut hasher = blake3::Hasher::new();
        hasher.update(relay.name.as_bytes());
        hasher.update(&[0]);
        hasher.update(token.as_bytes());
        *hasher.finalize().as_bytes()
    })
}

/// Why a rendezvous failed. Carries no relay text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RelayError {
    /// The relay could not be reached (or its name resolved).
    Unreachable(io::ErrorKind),
    /// TLS failed: wrong certificate, pin, or ALPN. Never retried without
    /// validation.
    Tls,
    /// The relay closed the room.
    Closed(CloseCode),
    /// No peer came within the wait.
    NoPeer,
    /// The relay broke §10: a malformed, out-of-order, or inconsistent
    /// record.
    Protocol,
}

impl fmt::Display for RelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Unreachable(kind) => write!(f, "the relay could not be reached: {kind}"),
            Self::Tls => f.write_str("the relay's certificate or key pin did not match"),
            Self::Closed(code) => write!(f, "the relay closed the room: {code:?}"),
            Self::NoPeer => f.write_str("the other device did not come to the relay in time"),
            Self::Protocol => f.write_str("the relay broke the protocol"),
        }
    }
}

impl std::error::Error for RelayError {}

/// How long each step of a rendezvous may take.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Timeouts {
    /// Connecting to the relay.
    pub(crate) connect: Duration,
    /// The relay's answer to `Register`.
    pub(crate) answer: Duration,
    /// The longest wait for the peer (§10: 30 seconds).
    pub(crate) longest_wait: Duration,
    /// The whole wait for `ForwardReady`: the room's lifetime (§10: 120
    /// seconds).
    pub(crate) room: Duration,
}

impl Timeouts {
    /// The timeouts every client uses.
    pub(crate) const STANDARD: Self = Self {
        connect: CONNECT_TIMEOUT,
        answer: ANSWER_TIMEOUT,
        longest_wait: Duration::from_secs(MAX_WAIT_SECONDS as u64),
        room: Duration::from_secs(MAX_ROOM_SECONDS as u64),
    };
}

/// Rendezvous through relays.
pub struct RelayClient {
    endpoint: quinn::Endpoint,
    provider: Arc<CryptoProvider>,
    timeouts: Timeouts,
}

impl fmt::Debug for RelayClient {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("RelayClient")
    }
}

impl RelayClient {
    /// A client on an ephemeral UDP port (dual-stack where available).
    ///
    /// # Errors
    ///
    /// If no UDP socket can be bound.
    pub fn new() -> io::Result<Self> {
        let endpoint =
            quinn::Endpoint::client(SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, 0)))
                .or_else(|_| quinn::Endpoint::client(SocketAddr::from(([0, 0, 0, 0], 0))))?;
        Ok(Self {
            endpoint,
            provider: Arc::new(rustls::crypto::aws_lc_rs::default_provider()),
            timeouts: Timeouts::STANDARD,
        })
    }

    /// A client with other timeouts (tests: real time, short waits).
    #[cfg(test)]
    pub(crate) fn with_timeouts(timeouts: Timeouts) -> io::Result<Self> {
        Ok(Self {
            timeouts,
            ..Self::new()?
        })
    }

    /// Meets the other endpoint of `token` at `relay` and returns the
    /// tunnel. Waits for the peer at most `wait` (and §10's 30 seconds).
    ///
    /// # Errors
    ///
    /// [`RelayError`].
    pub async fn rendezvous(
        &self,
        relay: &RelayEndpoint,
        token: RendezvousToken,
        wait: Duration,
    ) -> Result<RelayLink, RelayError> {
        let connection = tokio::time::timeout(self.timeouts.connect, self.connect(relay))
            .await
            .map_err(|_| RelayError::Unreachable(io::ErrorKind::TimedOut))??;
        let (mut send, mut recv) = connection
            .open_bi()
            .await
            .map_err(|_| RelayError::Unreachable(io::ErrorKind::ConnectionAborted))?;
        let nonce = random16().ok_or(RelayError::Unreachable(io::ErrorKind::Other))?;
        let wait = wait.min(self.timeouts.longest_wait);
        let ttl = MAX_ROOM_SECONDS;
        write(
            &mut send,
            &Control::Register {
                token,
                client_nonce: nonce,
                ttl_seconds: ttl,
            },
        )
        .await?;
        let mut reader = Reader::default();
        let answer = tokio::time::timeout(self.timeouts.answer, reader.next(&mut recv))
            .await
            .map_err(|_| RelayError::Protocol)??;
        let room = match answer {
            Control::Registered {
                room,
                client_nonce,
                expires_in,
            } if client_nonce == nonce && expires_in <= ttl => room,
            Control::RelayClose { code, .. } => return Err(RelayError::Closed(code)),
            _ => return Err(RelayError::Protocol),
        };
        // The peer, within the wait.
        let ready = tokio::time::timeout(wait, reader.next(&mut recv))
            .await
            .map_err(|_| RelayError::NoPeer)??;
        match ready {
            Control::PeerReady {
                room: named,
                peer_nonce,
            } if named == room && peer_nonce != nonce => {}
            Control::RelayClose { code, .. } => return Err(RelayError::Closed(code)),
            _ => return Err(RelayError::Protocol),
        }
        write(&mut send, &Control::Forward { room }).await?;
        // One deadline for the whole wait (the room's lifetime), and each
        // optional record at most once (§10): a relay can neither stall
        // the rendezvous nor flood it.
        let deadline = tokio::time::Instant::now() + self.timeouts.room;
        let (mut candidates, mut punch) = (false, false);
        loop {
            let next = tokio::time::timeout_at(deadline, reader.next(&mut recv))
                .await
                .map_err(|_| RelayError::Protocol)??;
            match next {
                Control::ForwardReady { room: named } if named == room => break,
                // Allowed before ForwardReady, and ignored: no probes.
                Control::Candidates { room: named, .. } if named == room && !candidates => {
                    candidates = true;
                }
                Control::Punch { room: named, .. } if named == room && !punch => punch = true,
                Control::RelayClose { code, .. } => return Err(RelayError::Closed(code)),
                _ => return Err(RelayError::Protocol),
            }
        }
        let info = LinkInfo::new(LinkKind::Relay).with_latency(connection.rtt());
        Ok(RelayLink {
            tunnel: Some(Tunnel {
                connection,
                send,
                recv,
            }),
            early: reader.buffer,
            info,
        })
    }

    /// Connects to the relay, trying each address its name resolves to in
    /// turn; TLS failures are not retried on another address.
    async fn connect(&self, relay: &RelayEndpoint) -> Result<quinn::Connection, RelayError> {
        let addresses: Vec<SocketAddr> = tokio::net::lookup_host(&relay.address)
            .await
            .map_err(|error| RelayError::Unreachable(error.kind()))?
            .take(4)
            .collect();
        let mut failure = RelayError::Unreachable(io::ErrorKind::NotFound);
        for address in addresses {
            let config = self.client_config(relay)?;
            let connecting = self
                .endpoint
                .connect_with(config, address, &relay.server_name)
                .map_err(|_| RelayError::Unreachable(io::ErrorKind::InvalidInput))?;
            match connecting.await {
                Ok(connection) => return Ok(connection),
                Err(error) => {
                    failure = connection_error(&error);
                    if failure == RelayError::Tls {
                        return Err(failure);
                    }
                }
            }
        }
        Err(failure)
    }

    fn client_config(&self, relay: &RelayEndpoint) -> Result<quinn::ClientConfig, RelayError> {
        let builder = rustls::ClientConfig::builder_with_provider(Arc::clone(&self.provider))
            .with_protocol_versions(&[&rustls::version::TLS13])
            .map_err(|_| RelayError::Tls)?;
        let verifier: Arc<dyn ServerCertVerifier> = match relay.pin {
            Some(pin) => Arc::new(Pinned {
                pin,
                provider: Arc::clone(&self.provider),
            }),
            None => Arc::new(
                rustls_platform_verifier::Verifier::new(Arc::clone(&self.provider))
                    .map_err(|_| RelayError::Tls)?,
            ),
        };
        let mut tls = builder
            .dangerous()
            .with_custom_certificate_verifier(verifier)
            .with_no_client_auth();
        tls.alpn_protocols = vec![ALPN.to_vec()];
        // No 0-RTT and no resumption: nothing links two connections.
        tls.enable_early_data = false;
        tls.resumption = rustls::client::Resumption::disabled();
        let crypto =
            quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(|_| RelayError::Tls)?;
        let mut config = quinn::ClientConfig::new(Arc::new(crypto));
        let mut transport = quinn::TransportConfig::default();
        // The relay opens no streams: nothing it sends unasked is
        // buffered, and the one tunnel stream's window is bounded.
        transport
            .keep_alive_interval(Some(KEEP_ALIVE))
            .max_concurrent_uni_streams(quinn::VarInt::from_u32(0))
            .max_concurrent_bidi_streams(quinn::VarInt::from_u32(0))
            .stream_receive_window(quinn::VarInt::from_u32(STREAM_WINDOW))
            .receive_window(quinn::VarInt::from_u32(STREAM_WINDOW))
            .datagram_receive_buffer_size(None);
        if let Ok(idle) = quinn::IdleTimeout::try_from(IDLE) {
            transport.max_idle_timeout(Some(idle));
        }
        config.transport_config(Arc::new(transport));
        Ok(config)
    }
}

/// What a failed connection means: TLS (a certificate, pin, or ALPN
/// alert), a relay at its limits (refused), or no answer.
fn connection_error(error: &quinn::ConnectionError) -> RelayError {
    let code = match error {
        quinn::ConnectionError::TransportError(error) => Some(error.code),
        quinn::ConnectionError::ConnectionClosed(close) => Some(close.error_code),
        quinn::ConnectionError::TimedOut => {
            return RelayError::Unreachable(io::ErrorKind::TimedOut);
        }
        _ => None,
    };
    match code {
        Some(code) if code == quinn::TransportErrorCode::CONNECTION_REFUSED => {
            RelayError::Unreachable(io::ErrorKind::ConnectionRefused)
        }
        // TLS alerts are carried as CRYPTO_ERROR codes 0x0100..=0x01ff.
        Some(code) if (0x100..=0x1ff).contains(&u64::from(code)) => RelayError::Tls,
        _ => RelayError::Unreachable(io::ErrorKind::ConnectionAborted),
    }
}

/// Accepts exactly the relay certificate whose key has the pin; its
/// handshake signature is still checked.
#[derive(Debug)]
struct Pinned {
    pin: [u8; 32],
    provider: Arc<CryptoProvider>,
}

impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let parsed = webpki::EndEntityCert::try_from(end_entity).map_err(|_| {
            rustls::Error::InvalidCertificate(rustls::CertificateError::BadEncoding)
        })?;
        let digest = libcrux_sha2::sha256(parsed.subject_public_key_info().as_ref());
        // Public values; no secret is compared.
        if digest == self.pin {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        // TLS 1.3 only.
        Err(rustls::Error::PeerIncompatible(
            rustls::PeerIncompatible::Tls13RequiredForQuic,
        ))
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// A tunnel through a relay: an untrusted, ordered byte pipe for one
/// session. Dropping it closes the tunnel.
pub struct RelayLink {
    /// The connection and streams; taken when the link is dropped.
    tunnel: Option<Tunnel>,
    /// Tunnel bytes that arrived with `ForwardReady`.
    early: Vec<u8>,
    info: LinkInfo,
}

struct Tunnel {
    connection: quinn::Connection,
    send: SendStream,
    recv: RecvStream,
}

impl RelayLink {
    fn tunnel(&mut self) -> io::Result<&mut Tunnel> {
        self.tunnel
            .as_mut()
            .ok_or_else(|| io::Error::from(io::ErrorKind::NotConnected))
    }
}

impl fmt::Debug for RelayLink {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RelayLink")
            .field("info", &self.info)
            .finish_non_exhaustive()
    }
}

/// How long a dropped tunnel waits for its last bytes to be acknowledged.
const LINGER: Duration = Duration::from_secs(5);

impl Drop for RelayLink {
    /// Dropping a QUIC connection closes it at once and discards bytes in
    /// flight, such as a session's last handshake message. So the stream is
    /// finished, and the connection kept until the relay acknowledged
    /// everything and the other end finished too (the relay forwarded both
    /// ways), or `LINGER` passed: what TCP does in the kernel.
    fn drop(&mut self) {
        let Some(mut tunnel) = self.tunnel.take() else {
            return;
        };
        let Ok(runtime) = tokio::runtime::Handle::try_current() else {
            return;
        };
        let _ = tunnel.send.finish();
        runtime.spawn(async move {
            let acknowledged = tunnel.send.stopped();
            let drained = async {
                let mut sink = [0; 4096];
                while let Ok(Some(_)) = tunnel.recv.read(&mut sink).await {}
            };
            let _ =
                tokio::time::timeout(LINGER, async { tokio::join!(acknowledged, drained) }).await;
            tunnel.connection.close(quinn::VarInt::from_u32(0), b"");
        });
    }
}

impl Link for RelayLink {
    fn info(&self) -> &LinkInfo {
        &self.info
    }
}

impl AsyncRead for RelayLink {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if !this.early.is_empty() {
            let take = this.early.len().min(buf.len());
            buf[..take].copy_from_slice(&this.early[..take]);
            this.early.drain(..take);
            return Poll::Ready(Ok(take));
        }
        let mut read = tokio::io::ReadBuf::new(buf);
        let recv = &mut this.tunnel()?.recv;
        match tokio::io::AsyncRead::poll_read(Pin::new(recv), cx, &mut read) {
            Poll::Ready(Ok(())) => Poll::Ready(Ok(read.filled().len())),
            Poll::Ready(Err(error)) => Poll::Ready(Err(error)),
            Poll::Pending => Poll::Pending,
        }
    }
}

impl AsyncWrite for RelayLink {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let send = &mut self.get_mut().tunnel()?.send;
        tokio::io::AsyncWrite::poll_write(Pin::new(send), cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let send = &mut self.get_mut().tunnel()?.send;
        tokio::io::AsyncWrite::poll_flush(Pin::new(send), cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let send = &mut self.get_mut().tunnel()?.send;
        tokio::io::AsyncWrite::poll_shutdown(Pin::new(send), cx)
    }
}

/// Control records from the relay, keeping bytes past the last one.
#[derive(Default)]
struct Reader {
    buffer: Vec<u8>,
}

impl Reader {
    async fn next(&mut self, recv: &mut RecvStream) -> Result<Control, RelayError> {
        loop {
            match Control::split(&self.buffer) {
                Ok(Some((control, used))) => {
                    self.buffer.drain(..used);
                    return Ok(control);
                }
                Ok(None) => {}
                Err(_) => return Err(RelayError::Protocol),
            }
            let mut chunk = [0; 2 + 2048];
            match recv.read(&mut chunk).await {
                Ok(Some(read)) => self.buffer.extend_from_slice(&chunk[..read]),
                Ok(None) => return Err(RelayError::Closed(CloseCode::Unavailable)),
                Err(_) => return Err(RelayError::Unreachable(io::ErrorKind::ConnectionReset)),
            }
        }
    }
}

async fn write(send: &mut SendStream, control: &Control) -> Result<(), RelayError> {
    let bytes = control.encode().map_err(|_| RelayError::Protocol)?;
    send.write_all(&bytes)
        .await
        .map_err(|_| RelayError::Unreachable(io::ErrorKind::ConnectionReset))
}

fn random16() -> Option<Random16> {
    let mut bytes = [0; 16];
    getrandom::fill(&mut bytes).ok()?;
    Random16::new(bytes).ok()
}

#[cfg(test)]
mod tests;
