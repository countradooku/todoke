//! A scripted relay (PROTOCOL §10): a QUIC server that answers the client
//! as a malicious relay would, to check what the client refuses, bounds,
//! and keeps.

use core::future::poll_fn;
use core::pin::Pin;
use core::time::Duration;
use std::sync::Arc;

use futures_io::{AsyncRead, AsyncWrite};
use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use todoke_proto::relay::{Candidate, CloseCode, Control, Random16, RendezvousToken, RoomId};
use todoke_relay::Identity;

use crate::relay::{ALPN, RelayClient, RelayEndpoint, RelayError, RelayLink};

type AnyResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// The relay's side of one control stream, as the script drives it.
struct Peer {
    connection: quinn::Connection,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    buffer: Vec<u8>,
    /// What the client's `Register` carried.
    nonce: Random16,
}

impl Peer {
    async fn send(&mut self, control: &Control) {
        let bytes = control.encode().unwrap_or_default();
        let _ = self.send.write_all(&bytes).await;
    }

    async fn send_raw(&mut self, bytes: &[u8]) {
        let _ = self.send.write_all(bytes).await;
    }

    async fn next(&mut self) -> Option<Control> {
        loop {
            if let Ok(Some((control, used))) = Control::split(&self.buffer) {
                self.buffer.drain(..used);
                return Some(control);
            }
            let mut chunk = [0; 4096];
            match self.recv.read(&mut chunk).await {
                Ok(Some(read)) => self.buffer.extend_from_slice(&chunk[..read]),
                _ => return None,
            }
        }
    }

    /// `Registered` and `PeerReady` (with the right room and a fresh nonce).
    async fn matched(&mut self, room: RoomId) {
        let nonce = self.nonce;
        self.send(&Control::Registered {
            room,
            client_nonce: nonce,
            expires_in: 60,
        })
        .await;
        self.send(&Control::PeerReady {
            room,
            peer_nonce: other(7),
        })
        .await;
    }
}

fn other(byte: u8) -> Random16 {
    Random16::new([byte; 16]).unwrap_or_else(|_| unreachable!())
}

fn token(byte: u8) -> RendezvousToken {
    RendezvousToken::new([byte; 32]).unwrap_or_else(|_| unreachable!())
}

fn room() -> RoomId {
    other(0x42)
}

/// A certificate resolver that always serves one key.
#[derive(Debug)]
struct Fixed(Arc<rustls::sign::CertifiedKey>);

impl rustls::server::ResolvesServerCert for Fixed {
    fn resolve(
        &self,
        _: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        Some(Arc::clone(&self.0))
    }
}

/// A relay that serves one connection and one stream with `script`.
/// `signer` is the key that signs the handshake (the certificate's, for an
/// honest relay).
fn scripted<F, Fut>(
    cert: &Identity,
    cert_pem: &str,
    signer_pem: &str,
    alpn: &[u8],
    script: F,
) -> AnyResult<(RelayEndpoint, tokio::task::JoinHandle<()>)>
where
    F: FnOnce(Peer) -> Fut + Send + 'static,
    Fut: core::future::Future<Output = ()> + Send + 'static,
{
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let chain: Vec<CertificateDer<'static>> =
        CertificateDer::pem_slice_iter(cert_pem.as_bytes()).collect::<Result<_, _>>()?;
    let key = PrivateKeyDer::from_pem_slice(signer_pem.as_bytes())?;
    let signing = rustls::crypto::aws_lc_rs::sign::any_supported_type(&key)?;
    let certified = Arc::new(rustls::sign::CertifiedKey::new(chain, signing));
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(Fixed(certified)));
    tls.alpn_protocols = vec![alpn.to_vec()];
    let server = quinn::ServerConfig::with_crypto(Arc::new(
        quinn::crypto::rustls::QuicServerConfig::try_from(tls)?,
    ));
    let endpoint = quinn::Endpoint::server(server, ([127, 0, 0, 1], 0).into())?;
    let address = endpoint.local_addr()?;
    let handle = tokio::spawn(async move {
        let Some(incoming) = endpoint.accept().await else {
            return;
        };
        let Ok(connection) = incoming.await else {
            return;
        };
        let Ok((send, mut recv)) = connection.accept_bi().await else {
            return;
        };
        let mut peer = Peer {
            connection,
            send,
            recv: {
                let _ = &mut recv;
                recv
            },
            buffer: Vec::new(),
            nonce: other(1),
        };
        let Some(Control::Register { client_nonce, .. }) = peer.next().await else {
            return;
        };
        peer.nonce = client_nonce;
        script(peer).await;
        // Keep the endpoint alive until the script's work is seen.
        tokio::time::sleep(Duration::from_millis(200)).await;
        endpoint.close(0u8.into(), b"");
    });
    Ok((
        RelayEndpoint {
            name: "script".into(),
            address: address.to_string(),
            server_name: "relay.test".into(),
            pin: Some(cert.pin()?),
        },
        handle,
    ))
}

fn honest<F, Fut>(script: F) -> AnyResult<(RelayEndpoint, tokio::task::JoinHandle<()>)>
where
    F: FnOnce(Peer) -> Fut + Send + 'static,
    Fut: core::future::Future<Output = ()> + Send + 'static,
{
    let (identity, cert, key) = Identity::self_signed(vec!["relay.test".into()])?;
    scripted(&identity, &cert, &key, ALPN, script)
}

async fn meet(endpoint: &RelayEndpoint) -> Result<RelayLink, RelayError> {
    RelayClient::new()
        .map_err(|_| RelayError::Protocol)?
        .rendezvous(endpoint, token(1), Duration::from_secs(5))
        .await
}

fn refused(script_result: Result<RelayLink, RelayError>) -> RelayError {
    script_result
        .map(|_| ())
        .err()
        .unwrap_or(RelayError::NoPeer)
}

#[tokio::test(flavor = "multi_thread")]
async fn the_client_checks_what_registered_echoes() -> AnyResult<()> {
    let (endpoint, _) = honest(|mut relay| async move {
        relay
            .send(&Control::Registered {
                room: room(),
                client_nonce: other(0x99),
                expires_in: 60,
            })
            .await;
        let _ = relay.next().await;
    })?;
    assert_eq!(refused(meet(&endpoint).await), RelayError::Protocol);
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn peer_ready_must_name_the_room_and_another_nonce() -> AnyResult<()> {
    // Another room.
    let (endpoint, _) = honest(|mut relay| async move {
        let nonce = relay.nonce;
        relay
            .send(&Control::Registered {
                room: room(),
                client_nonce: nonce,
                expires_in: 60,
            })
            .await;
        relay
            .send(&Control::PeerReady {
                room: other(0x43),
                peer_nonce: other(7),
            })
            .await;
        let _ = relay.next().await;
    })?;
    assert_eq!(refused(meet(&endpoint).await), RelayError::Protocol);
    // The client's own nonce.
    let (endpoint, _) = honest(|mut relay| async move {
        let nonce = relay.nonce;
        relay
            .send(&Control::Registered {
                room: room(),
                client_nonce: nonce,
                expires_in: 60,
            })
            .await;
        relay
            .send(&Control::PeerReady {
                room: room(),
                peer_nonce: nonce,
            })
            .await;
        let _ = relay.next().await;
    })?;
    assert_eq!(refused(meet(&endpoint).await), RelayError::Protocol);
    Ok(())
}

/// `Candidates` and `Punch` are each allowed once, for this room, before
/// `ForwardReady`.
#[tokio::test(flavor = "multi_thread")]
async fn optional_records_come_once_and_for_this_room() -> AnyResult<()> {
    let candidates = |room| Control::Candidates {
        room,
        candidates: vec![
            Candidate::new(([198, 51, 100, 1], 4000).into()).unwrap_or_else(|_| unreachable!()),
        ],
    };
    let punch = |room| Control::Punch {
        room,
        delay_ms: 0,
        punch_nonce: other(5),
    };
    let cases: Vec<(&str, Vec<Control>, bool)> = vec![
        (
            "one of each is fine",
            vec![candidates(room()), punch(room())],
            true,
        ),
        (
            "candidates twice",
            vec![candidates(room()), candidates(room())],
            false,
        ),
        ("punch twice", vec![punch(room()), punch(room())], false),
        (
            "candidates for another room",
            vec![candidates(other(0x43))],
            false,
        ),
        ("punch for another room", vec![punch(other(0x43))], false),
        (
            "a second PeerReady",
            vec![Control::PeerReady {
                room: room(),
                peer_nonce: other(8),
            }],
            false,
        ),
        (
            "a second Registered",
            vec![Control::Registered {
                room: room(),
                client_nonce: other(1),
                expires_in: 5,
            }],
            false,
        ),
        ("a Forward", vec![Control::Forward { room: room() }], false),
    ];
    for (name, records, fine) in cases {
        let (endpoint, _) = honest(move |mut relay| async move {
            relay.matched(room()).await;
            let _ = relay.next().await; // Forward
            for record in &records {
                relay.send(record).await;
            }
            relay.send(&Control::ForwardReady { room: room() }).await;
            tokio::time::sleep(Duration::from_millis(300)).await;
        })?;
        let outcome = meet(&endpoint).await;
        assert_eq!(outcome.is_ok(), fine, "{name}: {:?}", outcome.map(|_| ()));
    }
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn forward_ready_must_name_the_room() -> AnyResult<()> {
    let (endpoint, _) = honest(|mut relay| async move {
        relay.matched(room()).await;
        let _ = relay.next().await;
        relay
            .send(&Control::ForwardReady { room: other(0x43) })
            .await;
        tokio::time::sleep(Duration::from_millis(300)).await;
    })?;
    assert_eq!(refused(meet(&endpoint).await), RelayError::Protocol);
    Ok(())
}

/// A relay can open no streams to the client.
#[tokio::test(flavor = "multi_thread")]
async fn a_relay_cannot_open_streams() -> AnyResult<()> {
    let (done, result) = tokio::sync::oneshot::channel();
    let (endpoint, _) = honest(move |mut relay| async move {
        relay.matched(room()).await;
        let _ = relay.next().await;
        relay.send(&Control::ForwardReady { room: room() }).await;
        let bi = tokio::time::timeout(Duration::from_millis(500), relay.connection.open_bi()).await;
        let uni =
            tokio::time::timeout(Duration::from_millis(500), relay.connection.open_uni()).await;
        let _ = done.send((bi.is_err(), uni.is_err()));
    })?;
    let _link = meet(&endpoint).await?;
    assert_eq!(result.await?, (true, true));
    Ok(())
}

/// Bytes the relay sends right behind `ForwardReady` are the tunnel's first.
#[tokio::test(flavor = "multi_thread")]
async fn bytes_behind_forward_ready_are_delivered() -> AnyResult<()> {
    let (endpoint, _) = honest(|mut relay| async move {
        relay.matched(room()).await;
        let _ = relay.next().await;
        let mut bytes = Control::ForwardReady { room: room() }
            .encode()
            .unwrap_or_default();
        bytes.extend_from_slice(b"behind");
        relay.send_raw(&bytes).await;
        tokio::time::sleep(Duration::from_millis(500)).await;
    })?;
    let mut link = meet(&endpoint).await?;
    let mut got = [0_u8; 6];
    let mut filled = 0;
    while filled < got.len() {
        let read = poll_fn(|cx| Pin::new(&mut link).poll_read(cx, &mut got[filled..])).await?;
        assert!(read > 0);
        filled += read;
    }
    assert_eq!(&got, b"behind");
    Ok(())
}

/// Dropping a link keeps the connection until what was written is
/// acknowledged: the relay reads every byte.
#[tokio::test(flavor = "multi_thread")]
async fn a_dropped_link_still_delivers_its_last_bytes() -> AnyResult<()> {
    let (done, result) = tokio::sync::oneshot::channel();
    let (endpoint, _) = honest(move |mut relay| async move {
        relay.matched(room()).await;
        let _ = relay.next().await;
        relay.send(&Control::ForwardReady { room: room() }).await;
        let mut total = 0_usize;
        let mut chunk = vec![0; 65536];
        while let Ok(Some(read)) = relay.recv.read(&mut chunk).await {
            total += read;
        }
        let _ = done.send(total);
    })?;
    let mut link = meet(&endpoint).await?;
    let payload = vec![7_u8; 200_000];
    let mut rest = &payload[..];
    while !rest.is_empty() {
        let written = poll_fn(|cx| Pin::new(&mut link).poll_write(cx, rest)).await?;
        rest = &rest[written..];
    }
    drop(link);
    // Promptly: the stream was finished, so the relay sees its end at once
    // (without that it would wait for the 5-second linger to end).
    assert_eq!(
        tokio::time::timeout(Duration::from_secs(3), result).await??,
        payload.len()
    );
    Ok(())
}

/// A relay with another ALPN is a TLS failure; so is one that proves
/// possession of another key than its certificate's.
#[tokio::test(flavor = "multi_thread")]
async fn alpn_and_certificate_possession_are_checked() -> AnyResult<()> {
    let (identity, cert, key) = Identity::self_signed(vec!["relay.test".into()])?;
    let (endpoint, _) = scripted(&identity, &cert, &key, b"other/1", |_| async {})?;
    assert_eq!(refused(meet(&endpoint).await), RelayError::Tls);
    // The pinned certificate, signed for by another key.
    let (_, _, other_key) = Identity::self_signed(vec!["relay.test".into()])?;
    let (endpoint, _) = scripted(&identity, &cert, &other_key, ALPN, |_| async {})?;
    assert_eq!(refused(meet(&endpoint).await), RelayError::Tls);
    // And with the right key it works up to the script.
    let (endpoint, _) = scripted(&identity, &cert, &key, ALPN, |mut relay| async move {
        relay
            .send(&Control::RelayClose {
                room: None,
                code: CloseCode::Full,
            })
            .await;
        let _ = relay.send.finish();
        tokio::time::sleep(Duration::from_millis(300)).await;
    })?;
    assert_eq!(
        refused(meet(&endpoint).await),
        RelayError::Closed(CloseCode::Full)
    );
    Ok(())
}

/// Short timeouts, so the timing tests run in real time: paused time does
/// not mix with real sockets (the runtime looks idle while it waits on
/// one, and jumps the clock).
fn quick() -> std::io::Result<RelayClient> {
    RelayClient::with_timeouts(crate::relay::Timeouts {
        connect: Duration::from_millis(800),
        answer: Duration::from_millis(500),
        longest_wait: Duration::from_millis(700),
        room: Duration::from_millis(900),
    })
}

/// Asserts that `waited` is `at_least`, plus at most two seconds.
fn about(waited: Duration, at_least: Duration) {
    assert!(
        waited >= at_least && waited <= at_least + Duration::from_secs(2),
        "{waited:?} for {at_least:?}"
    );
}

/// Every client uses §10's limits and ten-second connect and answer
/// timeouts.
#[test]
fn the_standard_timeouts_are_the_documented_ones() {
    assert_eq!(
        crate::relay::Timeouts::STANDARD,
        crate::relay::Timeouts {
            connect: Duration::from_secs(10),
            answer: Duration::from_secs(10),
            longest_wait: Duration::from_secs(30),
            room: Duration::from_secs(120),
        }
    );
}

/// One deadline (the room's lifetime) covers the wait for `ForwardReady`,
/// and a relay that trickles allowed records cannot stretch it.
#[tokio::test(flavor = "multi_thread")]
async fn a_relay_cannot_stall_the_forward_wait() -> AnyResult<()> {
    let (endpoint, _) = honest(|mut relay| async move {
        relay.matched(room()).await;
        let _ = relay.next().await; // Forward
        // Candidates once, then silence for longer than any deadline.
        relay
            .send(&Control::Candidates {
                room: room(),
                candidates: Vec::new(),
            })
            .await;
        tokio::time::sleep(Duration::from_secs(60)).await;
    })?;
    let started = tokio::time::Instant::now();
    let outcome = quick()?
        .rendezvous(&endpoint, token(1), Duration::from_secs(30))
        .await
        .map(|_| ());
    assert_eq!(outcome, Err(RelayError::Protocol));
    about(started.elapsed(), Duration::from_millis(900));
    Ok(())
}

/// A relay that never answers `Register` is given up on after the answer
/// timeout.
#[tokio::test(flavor = "multi_thread")]
async fn a_relay_that_never_answers_register_is_given_up_on() -> AnyResult<()> {
    let (endpoint, _) = honest(|relay| async move {
        let _held = relay;
        tokio::time::sleep(Duration::from_secs(60)).await;
    })?;
    let started = tokio::time::Instant::now();
    let outcome = quick()?
        .rendezvous(&endpoint, token(1), Duration::from_secs(30))
        .await
        .map(|_| ());
    assert_eq!(outcome, Err(RelayError::Protocol));
    about(started.elapsed(), Duration::from_millis(500));
    Ok(())
}

/// The wait for the peer is the caller's, at most the longest wait.
#[tokio::test(flavor = "multi_thread")]
async fn the_wait_for_the_peer_is_bounded() -> AnyResult<()> {
    let (endpoint, _) = honest(|mut relay| async move {
        let nonce = relay.nonce;
        relay
            .send(&Control::Registered {
                room: room(),
                client_nonce: nonce,
                expires_in: 60,
            })
            .await;
        tokio::time::sleep(Duration::from_secs(60)).await;
    })?;
    let started = tokio::time::Instant::now();
    let outcome = quick()?
        .rendezvous(&endpoint, token(1), Duration::from_secs(500))
        .await
        .map(|_| ());
    assert_eq!(outcome, Err(RelayError::NoPeer));
    about(started.elapsed(), Duration::from_millis(700));
    Ok(())
}

/// A relay that never answers the handshake is given up on after the
/// connect timeout, whatever QUIC's own idle timeout.
#[tokio::test(flavor = "multi_thread")]
async fn an_unanswered_connection_attempt_times_out() -> AnyResult<()> {
    let silent = tokio::net::UdpSocket::bind(("127.0.0.1", 0)).await?;
    let endpoint = RelayEndpoint {
        name: "silent".into(),
        address: silent.local_addr()?.to_string(),
        server_name: "relay.test".into(),
        pin: Some([1; 32]),
    };
    let started = tokio::time::Instant::now();
    let outcome = quick()?
        .rendezvous(&endpoint, token(1), Duration::from_secs(30))
        .await
        .map(|_| ());
    assert_eq!(
        outcome,
        Err(RelayError::Unreachable(std::io::ErrorKind::TimedOut))
    );
    about(started.elapsed(), Duration::from_millis(800));
    drop(silent);
    Ok(())
}
