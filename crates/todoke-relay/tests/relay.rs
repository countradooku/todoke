//! A relay node and the endpoints' client on loopback (PROTOCOL §10): two
//! clients meet on a token and get an ordered byte tunnel; a pin, a full
//! room, a missing peer, the record order, and the byte quota are
//! enforced.

#![cfg(not(target_family = "wasm"))]

use core::future::poll_fn;
use core::pin::Pin;
use core::time::Duration;
use std::sync::Arc;

use futures_io::{AsyncRead, AsyncWrite};
use todoke_proto::relay::{CloseCode, RendezvousToken};
use todoke_relay::{Config, Identity, Relay};
use todoke_transport::relay::{RelayClient, RelayEndpoint, RelayError, RelayLink};

type AnyResult<T> = Result<T, Box<dyn std::error::Error>>;

/// A relay on loopback with a self-signed certificate, and how clients
/// reach it (pinned).
fn relay(config: impl FnOnce(&mut Config)) -> AnyResult<(RelayEndpoint, Arc<tokio::sync::Notify>)> {
    let (identity, _, _) = Identity::self_signed(vec!["relay.test".into()])?;
    let mut settings = Config::new(([127, 0, 0, 1], 0).into());
    config(&mut settings);
    let relay = Relay::bind(settings, &identity)?;
    let endpoint = RelayEndpoint {
        name: "test".into(),
        address: relay.local_addr()?.to_string(),
        server_name: "relay.test".into(),
        pin: Some(identity.pin()?),
    };
    let stop = Arc::new(tokio::sync::Notify::new());
    tokio::spawn(relay.run(Arc::clone(&stop)));
    Ok((endpoint, stop))
}

fn token(byte: u8) -> RendezvousToken {
    RendezvousToken::new([byte; 32]).unwrap_or_else(|_| unreachable!())
}

async fn write_all(link: &mut RelayLink, mut bytes: &[u8]) -> std::io::Result<()> {
    while !bytes.is_empty() {
        let written = poll_fn(|cx| Pin::new(&mut *link).poll_write(cx, bytes)).await?;
        bytes = &bytes[written..];
    }
    poll_fn(|cx| Pin::new(&mut *link).poll_flush(cx)).await
}

async fn read_exact(link: &mut RelayLink, buffer: &mut [u8]) -> std::io::Result<()> {
    let mut filled = 0;
    while filled < buffer.len() {
        let read = poll_fn(|cx| Pin::new(&mut *link).poll_read(cx, &mut buffer[filled..])).await?;
        if read == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        filled += read;
    }
    Ok(())
}

/// A rendezvous, tried again (as the app does) if the connection did not
/// come up: many tests at once on one loopback can lose handshakes.
async fn meet(
    client: &RelayClient,
    relay: &RelayEndpoint,
    token: RendezvousToken,
    wait: Duration,
) -> Result<RelayLink, RelayError> {
    let mut attempts = 0;
    loop {
        attempts += 1;
        match client.rendezvous(relay, token, wait).await {
            Err(RelayError::Unreachable(std::io::ErrorKind::TimedOut)) if attempts < 3 => {}
            other => return other,
        }
    }
}

async fn pair_up(relay: &RelayEndpoint, byte: u8) -> AnyResult<(RelayLink, RelayLink)> {
    let (one, two) = (RelayClient::new()?, RelayClient::new()?);
    let wait = Duration::from_secs(10);
    let (a, b) = tokio::join!(
        meet(&one, relay, token(byte), wait),
        meet(&two, relay, token(byte), wait)
    );
    Ok((a?, b?))
}

#[tokio::test(flavor = "multi_thread")]
async fn two_clients_meet_and_get_an_ordered_tunnel() -> AnyResult<()> {
    let (relay, stop) = relay(|_| {})?;
    let (mut a, mut b) = pair_up(&relay, 1).await?;
    // Both ways at once, more than the relay's buffers, in order.
    let payload: Vec<u8> = (0..3_000_000_u32).map(|n| (n % 251) as u8).collect();
    let (sent, received) = tokio::join!(
        async {
            write_all(&mut a, &payload).await?;
            let mut back = vec![0; 1000];
            read_exact(&mut a, &mut back).await?;
            Ok::<_, std::io::Error>(back)
        },
        async {
            let mut got = vec![0; payload.len()];
            read_exact(&mut b, &mut got).await?;
            write_all(&mut b, &[9; 1000]).await?;
            Ok::<_, std::io::Error>(got)
        }
    );
    assert_eq!(sent?, vec![9; 1000]);
    // Not assert_eq: a failure would print 3 MB.
    let equal = received? == payload;
    assert!(equal);
    stop.notify_waiters();
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_relay_with_another_key_is_refused() -> AnyResult<()> {
    let (mut relay, stop) = relay(|_| {})?;
    relay.pin = Some([0; 32]);
    let client = RelayClient::new()?;
    let refused = client
        .rendezvous(&relay, token(2), Duration::from_secs(1))
        .await
        .map(|_| ());
    assert_eq!(refused, Err(RelayError::Tls));
    // Without a pin, the platform's roots do not know a self-signed key.
    relay.pin = None;
    let refused = client
        .rendezvous(&relay, token(2), Duration::from_secs(1))
        .await
        .map(|_| ());
    assert_eq!(refused, Err(RelayError::Tls));
    stop.notify_waiters();
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_lone_client_waits_then_hears_nothing() -> AnyResult<()> {
    let (relay, stop) = relay(|_| {})?;
    let client = RelayClient::new()?;
    let alone = client
        .rendezvous(&relay, token(3), Duration::from_millis(500))
        .await
        .map(|_| ());
    assert_eq!(alone, Err(RelayError::NoPeer));
    stop.notify_waiters();
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_third_client_finds_the_room_full() -> AnyResult<()> {
    let (relay, stop) = relay(|_| {})?;
    let (one, two, three) = (
        RelayClient::new()?,
        RelayClient::new()?,
        RelayClient::new()?,
    );
    let wait = Duration::from_secs(10);
    let waiting = tokio::spawn({
        let relay = relay.clone();
        async move { one.rendezvous(&relay, token(4), wait).await.map(|_| ()) }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    // The second member matches; it waits in the tunnel until the first
    // forwards (which it does at once).
    let second = two.rendezvous(&relay, token(4), wait).await?;
    let third = three
        .rendezvous(&relay, token(4), Duration::from_secs(1))
        .await
        .map(|_| ());
    // The room is a tunnel now: the token is free, and the third waits
    // alone.
    assert_eq!(third, Err(RelayError::NoPeer));
    assert_eq!(waiting.await?, Ok(()));
    drop(second);
    stop.notify_waiters();
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn the_byte_quota_ends_a_tunnel() -> AnyResult<()> {
    let (relay, stop) = relay(|config| config.tunnel_bytes = 100_000)?;
    let (mut a, mut b) = pair_up(&relay, 5).await?;
    let (_, read) = tokio::join!(
        async { write_all(&mut a, &vec![1; 300_000]).await },
        async {
            let mut got = vec![0; 300_000];
            read_exact(&mut b, &mut got).await
        }
    );
    assert!(read.is_err(), "more than the quota went through");
    stop.notify_waiters();
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn rooms_close_with_a_code_when_the_relay_is_full() -> AnyResult<()> {
    let (relay, stop) = relay(|config| config.max_rooms = 1)?;
    let client = RelayClient::new()?;
    let first = tokio::spawn({
        let relay = relay.clone();
        async move {
            RelayClient::new()?
                .rendezvous(&relay, token(6), Duration::from_secs(3))
                .await
                .map(|_| ())
                .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)
        }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    let refused = client
        .rendezvous(&relay, token(7), Duration::from_secs(1))
        .await
        .map(|_| ());
    assert_eq!(refused, Err(RelayError::Closed(CloseCode::Unavailable)));
    let _ = first.await;
    stop.notify_waiters();
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_burst_of_registers_hears_quota() -> AnyResult<()> {
    let (relay, stop) = relay(|config| {
        config.registers_per_source_per_second = 1;
        config.connections_per_source_per_second = 1000;
    })?;
    let client = Arc::new(RelayClient::new()?);
    let mut tasks = Vec::new();
    for byte in 0..6 {
        let (client, relay) = (Arc::clone(&client), relay.clone());
        tasks.push(tokio::spawn(async move {
            client
                .rendezvous(&relay, token(100 + byte), Duration::from_millis(500))
                .await
                .map(|_| ())
        }));
    }
    let mut quota = 0;
    for task in tasks {
        if task.await? == Err(RelayError::Closed(CloseCode::Quota)) {
            quota += 1;
        }
    }
    // A burst of two registers is allowed; the rest hear Quota.
    assert_eq!(quota, 4);
    stop.notify_waiters();
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_refused_connection_is_not_a_tls_failure() -> AnyResult<()> {
    let (relay, stop) = relay(|config| config.max_connections_per_source = 1)?;
    let waiting = tokio::spawn({
        let relay = relay.clone();
        async move {
            RelayClient::new()?
                .rendezvous(&relay, token(120), Duration::from_secs(3))
                .await
                .map(|_| ())
                .map_err(|error| Box::new(error) as Box<dyn std::error::Error + Send + Sync>)
        }
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    let refused = RelayClient::new()?
        .rendezvous(&relay, token(121), Duration::from_secs(1))
        .await
        .map(|_| ());
    assert_eq!(
        refused,
        Err(RelayError::Unreachable(
            std::io::ErrorKind::ConnectionRefused
        ))
    );
    let _ = waiting.await;
    stop.notify_waiters();
    Ok(())
}

/// A connection whose stream became a tunnel holds a room as long as the
/// tunnel lives: the idle close for connections without a room never
/// cuts a tunnel.
#[tokio::test(flavor = "multi_thread")]
async fn tunnels_outlive_the_roomless_close() -> AnyResult<()> {
    let (relay, stop) = relay(|config| config.roomless = Duration::from_millis(300))?;
    let (mut a, mut b) = pair_up(&relay, 9).await?;
    tokio::time::sleep(Duration::from_secs(1)).await;
    write_all(&mut a, b"later").await?;
    let mut got = [0; 5];
    read_exact(&mut b, &mut got).await?;
    assert_eq!(&got, b"later");
    write_all(&mut b, b"back!").await?;
    read_exact(&mut a, &mut got).await?;
    assert_eq!(&got, b"back!");
    stop.notify_waiters();
    Ok(())
}
