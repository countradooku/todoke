//! Raw QUIC clients against a relay node: the §10 record order, deadlines,
//! limits, and what the stock client never does.

#![cfg(not(target_family = "wasm"))]

use core::time::Duration;
use std::sync::Arc;

use quinn::{RecvStream, SendStream};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{DigitallySignedStruct, SignatureScheme};
use todoke_proto::relay::{CloseCode, Control, Random16, RendezvousToken, RoomId};
use todoke_relay::{ALPN, Config, Identity, Metrics, Relay};
use todoke_transport::relay::{RelayClient, RelayEndpoint, RelayError};

type AnyResult<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Debug)]
struct AcceptAll(Arc<rustls::crypto::CryptoProvider>);

impl ServerCertVerifier for AcceptAll {
    fn verify_server_cert(
        &self,
        _: &CertificateDer<'_>,
        _: &[CertificateDer<'_>],
        _: &ServerName<'_>,
        _: &[u8],
        _: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }
    fn verify_tls12_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn verify_tls13_signature(
        &self,
        _: &[u8],
        _: &CertificateDer<'_>,
        _: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.0.signature_verification_algorithms.supported_schemes()
    }
}

struct Node {
    address: std::net::SocketAddr,
    endpoint: RelayEndpoint,
    metrics: Arc<Metrics>,
    stop: Arc<tokio::sync::Notify>,
}

fn node(config: impl FnOnce(&mut Config)) -> AnyResult<Node> {
    let (identity, _, _) = Identity::self_signed(vec!["relay.test".into()])?;
    let mut settings = Config::new(([127, 0, 0, 1], 0).into());
    config(&mut settings);
    let relay = Relay::bind(settings, &identity)?;
    let address = relay.local_addr()?;
    let metrics = relay.metrics();
    let stop = Arc::new(tokio::sync::Notify::new());
    tokio::spawn(relay.run(Arc::clone(&stop)));
    Ok(Node {
        address,
        endpoint: RelayEndpoint {
            name: "raw".into(),
            address: address.to_string(),
            server_name: "relay.test".into(),
            pin: Some(identity.pin()?),
        },
        metrics,
        stop,
    })
}

/// A QUIC client that talks to the relay by hand.
struct Raw {
    _endpoint: quinn::Endpoint,
    connection: quinn::Connection,
}

async fn connect(node: &Node) -> AnyResult<Raw> {
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::clone(&provider))
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(AcceptAll(provider)))
        .with_no_client_auth();
    tls.alpn_protocols = vec![ALPN.to_vec()];
    let config = quinn::ClientConfig::new(Arc::new(
        quinn::crypto::rustls::QuicClientConfig::try_from(tls)?,
    ));
    let mut endpoint = quinn::Endpoint::client(([127, 0, 0, 1], 0).into())?;
    endpoint.set_default_client_config(config);
    let connection = endpoint.connect(node.address, "relay.test")?.await?;
    Ok(Raw {
        _endpoint: endpoint,
        connection,
    })
}

/// One room's stream, by hand.
struct Room {
    send: SendStream,
    recv: RecvStream,
    buffer: Vec<u8>,
}

impl Raw {
    async fn room(&self) -> AnyResult<Room> {
        let (send, recv) = self.connection.open_bi().await?;
        Ok(Room {
            send,
            recv,
            buffer: Vec::new(),
        })
    }
}

impl Room {
    async fn send(&mut self, control: &Control) -> AnyResult<()> {
        self.send.write_all(&control.encode()?).await?;
        Ok(())
    }

    async fn send_raw(&mut self, bytes: &[u8]) -> AnyResult<()> {
        self.send.write_all(bytes).await?;
        Ok(())
    }

    /// The next record; `None` at the end of the stream or on a reset.
    async fn next(&mut self) -> AnyResult<Option<Control>> {
        loop {
            if let Some((control, used)) = Control::split(&self.buffer)? {
                self.buffer.drain(..used);
                return Ok(Some(control));
            }
            let mut chunk = [0; 4096];
            match self.recv.read(&mut chunk).await {
                Ok(Some(read)) => self.buffer.extend_from_slice(&chunk[..read]),
                Ok(None) | Err(_) => return Ok(None),
            }
        }
    }

    async fn next_within(&mut self, within: Duration) -> AnyResult<Option<Control>> {
        Ok(tokio::time::timeout(within, self.next())
            .await?
            .map_err(|e| e.to_string())?)
    }

    /// Registers `token` and returns the room and the nonce used.
    async fn register(&mut self, token: RendezvousToken, nonce: u8) -> AnyResult<RoomId> {
        self.send(&Control::Register {
            token,
            client_nonce: Random16::new([nonce; 16])?,
            ttl_seconds: 120,
        })
        .await?;
        match self.next_within(Duration::from_secs(5)).await? {
            Some(Control::Registered { room, .. }) => Ok(room),
            other => Err(format!("not registered: {other:?}").into()),
        }
    }
}

fn token(byte: u8) -> RendezvousToken {
    RendezvousToken::new([byte; 32]).unwrap_or_else(|_| unreachable!())
}

const WAIT: Duration = Duration::from_secs(5);

/// A member that registers and leaves does not keep the token: the next
/// pair meets at once (a regression would match one of them with the
/// departed member, and turn the other away as Full).
#[tokio::test(flavor = "multi_thread")]
async fn a_member_that_leaves_frees_its_token() -> AnyResult<()> {
    let node = node(|_| {})?;
    let raw = connect(&node).await?;
    let mut ghost = raw.room().await?;
    ghost.register(token(1), 9).await?;
    drop(ghost);
    raw.connection.close(0u8.into(), b"");
    tokio::time::sleep(Duration::from_millis(300)).await;
    let (one, two) = (RelayClient::new()?, RelayClient::new()?);
    let (a, b) = tokio::join!(
        one.rendezvous(&node.endpoint, token(1), WAIT),
        two.rendezvous(&node.endpoint, token(1), WAIT)
    );
    assert!(
        a.is_ok() && b.is_ok(),
        "{:?} {:?}",
        a.map(|_| ()),
        b.map(|_| ())
    );
    node.stop.notify_waiters();
    Ok(())
}

/// What a relay answers to records out of §10's order: the room closes
/// with Malformed (and, before registration, room zero).
#[tokio::test(flavor = "multi_thread")]
async fn records_out_of_order_close_the_room_malformed() -> AnyResult<()> {
    let node = node(|_| {})?;
    let raw = connect(&node).await?;
    let some_room = Random16::new([7; 16])?;
    // Not a Register first: Forward, Candidates, an unknown type, junk.
    for first in [
        Control::Forward { room: some_room }.encode()?,
        Control::Candidates {
            room: some_room,
            candidates: Vec::new(),
        }
        .encode()?,
        vec![
            0, 17, 0x09, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16,
        ],
        vec![0, 0],
    ] {
        let mut room = raw.room().await?;
        room.send_raw(&first).await?;
        assert_eq!(
            room.next_within(WAIT).await?,
            Some(Control::RelayClose {
                room: None,
                code: CloseCode::Malformed
            }),
            "{first:?}"
        );
    }
    // Forward before PeerReady, and Candidates before PeerReady.
    for (byte, early) in [(2_u8, true), (3, false)] {
        let mut room = raw.room().await?;
        let id = room.register(token(byte), 1).await?;
        let record = if early {
            Control::Forward { room: id }
        } else {
            Control::Candidates {
                room: id,
                candidates: Vec::new(),
            }
        };
        room.send(&record).await?;
        assert_eq!(
            room.next_within(WAIT).await?,
            Some(Control::RelayClose {
                room: Some(id),
                code: CloseCode::Malformed
            })
        );
    }
    let metrics = node.metrics.render();
    assert!(
        metrics.contains("todoke_relay_closes_total{reason=\"malformed\"} 6"),
        "{metrics}"
    );
    node.stop.notify_waiters();
    Ok(())
}

/// A relay never sends a second `PeerReady`, and a member's second
/// `Candidates` closes the room for both.
#[tokio::test(flavor = "multi_thread")]
async fn a_second_candidates_closes_the_room_for_both() -> AnyResult<()> {
    let node = node(|_| {})?;
    let raw_a = connect(&node).await?;
    let raw_b = connect(&node).await?;
    let (mut a, mut b) = (raw_a.room().await?, raw_b.room().await?);
    let room = a.register(token(4), 1).await?;
    b.register(token(4), 2).await?;
    assert!(matches!(
        a.next_within(WAIT).await?,
        Some(Control::PeerReady { .. })
    ));
    assert!(matches!(
        b.next_within(WAIT).await?,
        Some(Control::PeerReady { .. })
    ));
    a.send(&Control::Candidates {
        room,
        candidates: Vec::new(),
    })
    .await?;
    a.send(&Control::Candidates {
        room,
        candidates: Vec::new(),
    })
    .await?;
    assert_eq!(
        b.next_within(WAIT).await?,
        Some(Control::Candidates {
            room,
            candidates: Vec::new()
        })
    );
    assert_eq!(
        b.next_within(WAIT).await?,
        Some(Control::RelayClose {
            room: Some(room),
            code: CloseCode::Malformed
        })
    );
    node.stop.notify_waiters();
    Ok(())
}

/// A member waiting after its `Forward` keeps its streams while the other
/// member sends `Candidates`, and gets the tunnel when the other forwards.
#[tokio::test(flavor = "multi_thread")]
async fn a_waiting_member_survives_the_others_candidates() -> AnyResult<()> {
    let node = node(|_| {})?;
    let raw_b = connect(&node).await?;
    let first = tokio::spawn({
        let endpoint = node.endpoint.clone();
        async move {
            let client = RelayClient::new().map_err(|e| e.to_string())?;
            client
                .rendezvous(&endpoint, token(5), WAIT)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string())
        }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut b = raw_b.room().await?;
    let room = b.register(token(5), 2).await?;
    assert!(matches!(
        b.next_within(WAIT).await?,
        Some(Control::PeerReady { .. })
    ));
    // The first member has forwarded and waits; the other speaks first.
    b.send(&Control::Candidates {
        room,
        candidates: Vec::new(),
    })
    .await?;
    tokio::time::sleep(Duration::from_millis(300)).await;
    b.send(&Control::Forward { room }).await?;
    assert!(matches!(
        b.next_within(WAIT).await?,
        Some(Control::ForwardReady { .. })
    ));
    assert_eq!(first.await?, Ok(()));
    node.stop.notify_waiters();
    Ok(())
}

/// Bytes a member sends right behind its `Forward` reach the other member
/// first, in order.
#[tokio::test(flavor = "multi_thread")]
async fn bytes_behind_a_forward_are_not_lost() -> AnyResult<()> {
    use core::future::poll_fn;
    use core::pin::Pin;
    use futures_io::AsyncRead;
    let node = node(|_| {})?;
    let raw_b = connect(&node).await?;
    let first = tokio::spawn({
        let endpoint = node.endpoint.clone();
        async move {
            let client = RelayClient::new().map_err(|e| e.to_string())?;
            client
                .rendezvous(&endpoint, token(6), WAIT)
                .await
                .map_err(|e| e.to_string())
        }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut b = raw_b.room().await?;
    let room = b.register(token(6), 2).await?;
    assert!(matches!(
        b.next_within(WAIT).await?,
        Some(Control::PeerReady { .. })
    ));
    let mut bytes = Control::Forward { room }.encode()?;
    bytes.extend_from_slice(b"first tunnel bytes");
    b.send_raw(&bytes).await?;
    let mut link = first.await??;
    let mut got = [0_u8; 18];
    let mut filled = 0;
    while filled < got.len() {
        let read = tokio::time::timeout(
            WAIT,
            poll_fn(|cx| Pin::new(&mut link).poll_read(cx, &mut got[filled..])),
        )
        .await??;
        assert!(read > 0);
        filled += read;
    }
    assert_eq!(&got, b"first tunnel bytes");
    node.stop.notify_waiters();
    Ok(())
}

/// A tunnel ends at its lifetime.
#[tokio::test(flavor = "multi_thread")]
async fn a_tunnel_ends_at_its_lifetime() -> AnyResult<()> {
    use core::future::poll_fn;
    use core::pin::Pin;
    use futures_io::AsyncRead;
    let node = node(|config| config.tunnel_lifetime = Duration::from_secs(1))?;
    let (one, two) = (RelayClient::new()?, RelayClient::new()?);
    let (a, b) = tokio::join!(
        one.rendezvous(&node.endpoint, token(7), WAIT),
        two.rendezvous(&node.endpoint, token(7), WAIT)
    );
    let (mut a, _b) = (a?, b?);
    let mut byte = [0_u8; 1];
    let ended = tokio::time::timeout(
        Duration::from_secs(5),
        poll_fn(|cx| Pin::new(&mut a).poll_read(cx, &mut byte)),
    )
    .await;
    assert!(matches!(ended, Ok(Ok(0) | Err(_))), "{ended:?}");
    node.stop.notify_waiters();
    Ok(())
}

/// A connection holds two rooms and no more, and no unidirectional streams.
#[tokio::test(flavor = "multi_thread")]
async fn a_connection_holds_two_rooms_only() -> AnyResult<()> {
    let node = node(|_| {})?;
    let raw = connect(&node).await?;
    let mut one = raw.room().await?;
    let mut two = raw.room().await?;
    one.register(token(8), 1).await?;
    two.register(token(9), 1).await?;
    let third = tokio::time::timeout(Duration::from_millis(500), raw.connection.open_bi()).await;
    assert!(third.is_err(), "a third room was allowed");
    let uni = tokio::time::timeout(Duration::from_millis(500), raw.connection.open_uni()).await;
    assert!(uni.is_err(), "a unidirectional stream was allowed");
    node.stop.notify_waiters();
    Ok(())
}

/// New connections are rate-limited per source: bursts of two at 1 a second.
#[tokio::test(flavor = "multi_thread")]
async fn new_connections_are_rate_limited_per_source() -> AnyResult<()> {
    let node = node(|config| config.connections_per_source_per_second = 1)?;
    let mut open = Vec::new();
    let mut refused = 0;
    for _ in 0..5 {
        match connect(&node).await {
            Ok(raw) => open.push(raw),
            Err(_) => refused += 1,
        }
    }
    assert_eq!((open.len(), refused), (2, 3));
    node.stop.notify_waiters();
    Ok(())
}

/// The node-wide connection limit applies whatever the source.
#[tokio::test(flavor = "multi_thread")]
async fn connections_are_limited_in_total() -> AnyResult<()> {
    let node = node(|config| config.max_connections = 1)?;
    let _first = connect(&node).await?;
    assert!(connect(&node).await.is_err());
    node.stop.notify_waiters();
    Ok(())
}

/// Every new address answers a Retry before it gets a connection.
#[tokio::test(flavor = "multi_thread")]
async fn a_new_address_is_sent_to_retry_first() -> AnyResult<()> {
    let node = node(|_| {})?;
    let _raw = connect(&node).await?;
    assert!(
        node.metrics
            .refused
            .load(std::sync::atomic::Ordering::Relaxed)
            >= 1
    );
    node.stop.notify_waiters();
    Ok(())
}

/// Gauges return to zero when tunnels and connections end.
#[tokio::test(flavor = "multi_thread")]
async fn gauges_do_not_drift() -> AnyResult<()> {
    use std::sync::atomic::Ordering::Relaxed;
    let node = node(|_| {})?;
    let (one, two) = (RelayClient::new()?, RelayClient::new()?);
    let (a, b) = tokio::join!(
        one.rendezvous(&node.endpoint, token(10), WAIT),
        two.rendezvous(&node.endpoint, token(10), WAIT)
    );
    let (a, b) = (a?, b?);
    assert_eq!(node.metrics.tunnels.load(Relaxed), 1);
    drop((a, b));
    let ended = async {
        while node.metrics.tunnels.load(Relaxed) != 0 || node.metrics.connections.load(Relaxed) != 0
        {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    };
    assert!(
        tokio::time::timeout(Duration::from_secs(10), ended)
            .await
            .is_ok(),
        "tunnels {} connections {}",
        node.metrics.tunnels.load(Relaxed),
        node.metrics.connections.load(Relaxed)
    );
    node.stop.notify_waiters();
    let _ = RelayError::NoPeer;
    Ok(())
}

/// A stream that never says `Register` is closed at the deadline, and a
/// connection that holds no room is closed.
#[tokio::test(flavor = "multi_thread")]
async fn silence_is_not_kept() -> AnyResult<()> {
    let node = node(|config| {
        config.register_deadline = Duration::from_millis(300);
        config.roomless = Duration::from_millis(600);
    })?;
    let raw = connect(&node).await?;
    let mut room = raw.room().await?;
    // Nothing is sent (a stream is only known to the relay once it carries
    // a byte).
    room.send_raw(&[0]).await?;
    assert_eq!(
        room.next_within(Duration::from_secs(3)).await?,
        Some(Control::RelayClose {
            room: None,
            code: CloseCode::Malformed
        })
    );
    // No room open: the connection is closed by the relay.
    let closed = tokio::time::timeout(Duration::from_secs(5), raw.connection.closed()).await;
    assert!(
        matches!(closed, Ok(quinn::ConnectionError::ApplicationClosed(_))),
        "{closed:?}"
    );
    node.stop.notify_waiters();
    Ok(())
}

/// A lone member whose wait ended leaves nothing behind.
#[tokio::test(flavor = "multi_thread")]
async fn a_wait_that_ends_leaves_no_room() -> AnyResult<()> {
    let node = node(|config| config.peer_wait = Duration::from_millis(400))?;
    let raw = connect(&node).await?;
    let mut lone = raw.room().await?;
    let room = lone.register(token(11), 1).await?;
    assert_eq!(
        lone.next_within(Duration::from_secs(5)).await?,
        Some(Control::RelayClose {
            room: Some(room),
            code: CloseCode::Expired
        })
    );
    // The token is free: the next member waits alone (a left-over room
    // would match it at once).
    let other = connect(&node).await?;
    let mut next = other.room().await?;
    next.register(token(11), 2).await?;
    let matched = next.next_within(Duration::from_millis(200)).await;
    assert!(
        matched.is_err(),
        "matched with a room that had expired: {matched:?}"
    );
    let metrics = node.metrics.render();
    assert!(
        metrics.contains("todoke_relay_closes_total{reason=\"expired\"} 1"),
        "{metrics}"
    );
    node.stop.notify_waiters();
    Ok(())
}

/// A connection that holds a room is not closed for being quiet.
#[tokio::test(flavor = "multi_thread")]
async fn a_connection_with_a_room_is_not_closed() -> AnyResult<()> {
    let node = node(|config| config.roomless = Duration::from_millis(300))?;
    let raw = connect(&node).await?;
    let mut room = raw.room().await?;
    room.register(token(13), 1).await?;
    let closed = tokio::time::timeout(Duration::from_millis(1000), raw.connection.closed()).await;
    assert!(closed.is_err(), "{closed:?}");
    node.stop.notify_waiters();
    Ok(())
}

/// A waiting member is told when the other member leaves.
#[tokio::test(flavor = "multi_thread")]
async fn a_waiting_member_is_told_when_the_other_leaves() -> AnyResult<()> {
    let node = node(|_| {})?;
    let raw_b = connect(&node).await?;
    let first = tokio::spawn({
        let endpoint = node.endpoint.clone();
        async move {
            let client = RelayClient::new().map_err(|e| e.to_string())?;
            client
                .rendezvous(&endpoint, token(12), WAIT)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string())
        }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    let mut b = raw_b.room().await?;
    b.register(token(12), 2).await?;
    assert!(matches!(
        b.next_within(WAIT).await?,
        Some(Control::PeerReady { .. })
    ));
    // The first member has forwarded and waits. The second leaves.
    raw_b.connection.close(0u8.into(), b"");
    assert_eq!(
        first.await?,
        Err(RelayError::Closed(CloseCode::Unavailable).to_string())
    );
    node.stop.notify_waiters();
    Ok(())
}

/// A tunnel forwards exactly its quota in a direction, and no more.
#[tokio::test(flavor = "multi_thread")]
async fn the_quota_is_exact() -> AnyResult<()> {
    use core::future::poll_fn;
    use core::pin::Pin;
    use futures_io::{AsyncRead, AsyncWrite};
    let node = node(|config| config.tunnel_bytes = 100_000)?;
    let (one, two) = (RelayClient::new()?, RelayClient::new()?);
    let (a, b) = tokio::join!(
        one.rendezvous(&node.endpoint, token(14), WAIT),
        two.rendezvous(&node.endpoint, token(14), WAIT)
    );
    let (mut a, mut b) = (a?, b?);
    let payload = vec![3_u8; 100_001];
    let mut sent = &payload[..];
    let writing = async {
        while !sent.is_empty() {
            let Ok(written) = poll_fn(|cx| Pin::new(&mut a).poll_write(cx, sent)).await else {
                break;
            };
            sent = &sent[written..];
        }
        let _ = poll_fn(|cx| Pin::new(&mut a).poll_flush(cx)).await;
        tokio::time::sleep(Duration::from_secs(2)).await;
    };
    let reading = async {
        let mut total = 0_usize;
        let mut chunk = vec![0_u8; 8192];
        while let Ok(read) = poll_fn(|cx| Pin::new(&mut b).poll_read(cx, &mut chunk)).await {
            if read == 0 {
                break;
            }
            total += read;
        }
        total
    };
    let ((), total) = tokio::time::timeout(Duration::from_secs(10), async {
        tokio::join!(writing, reading)
    })
    .await?;
    // The byte past the quota ended the tunnel (the reset may cut what was
    // still in flight, so not all of the quota need arrive).
    assert!(total <= 100_000, "{total} bytes arrived");
    node.stop.notify_waiters();
    Ok(())
}

/// Once both members are in the room, it lasts its TTL, not the 30-second
/// wait for a lone member.
#[tokio::test(flavor = "multi_thread")]
async fn a_matched_room_outlives_the_wait() -> AnyResult<()> {
    let node = node(|config| config.peer_wait = Duration::from_millis(400))?;
    let (raw_a, raw_b) = (connect(&node).await?, connect(&node).await?);
    let (mut a, mut b) = (raw_a.room().await?, raw_b.room().await?);
    let room = a.register(token(15), 1).await?;
    b.register(token(15), 2).await?;
    assert!(matches!(
        a.next_within(WAIT).await?,
        Some(Control::PeerReady { .. })
    ));
    assert!(matches!(
        b.next_within(WAIT).await?,
        Some(Control::PeerReady { .. })
    ));
    tokio::time::sleep(Duration::from_millis(900)).await;
    a.send(&Control::Forward { room }).await?;
    b.send(&Control::Forward { room }).await?;
    assert_eq!(
        a.next_within(WAIT).await?,
        Some(Control::ForwardReady { room })
    );
    assert_eq!(
        b.next_within(WAIT).await?,
        Some(Control::ForwardReady { room })
    );
    node.stop.notify_waiters();
    Ok(())
}
