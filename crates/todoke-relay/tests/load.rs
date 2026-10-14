//! Load: 10000 concurrent rendezvous on one relay node: 20000 QUIC
//! connections, each with a TLS 1.3 handshake, meeting in batches as fast
//! as handshakes allow, every tunnel held open until all 10000 are open
//! together, then each carrying a byte each way. Run in release:
//!
//! ```text
//! cargo test --release -p todoke-relay --test load -- --ignored --nocapture
//! ```
//!
//! `TODOKE_LOAD_ROOMS` changes the number of rendezvous.

#![cfg(not(target_family = "wasm"))]

use core::future::poll_fn;
use core::pin::Pin;
use core::time::Duration;
use std::sync::Arc;
use std::time::Instant;

use futures_io::{AsyncRead, AsyncWrite};
use todoke_proto::relay::RendezvousToken;
use todoke_relay::{Config, Identity, Relay};
use todoke_transport::relay::{RelayClient, RelayEndpoint, RelayError, RelayLink};

type AnyResult<T> = Result<T, Box<dyn std::error::Error + Send + Sync>>;

/// Pairs meeting at once.
const BATCH: u32 = 250;

fn token(index: u32) -> AnyResult<RendezvousToken> {
    let mut bytes = [0xa5; 32];
    bytes[..4].copy_from_slice(&index.to_be_bytes());
    Ok(RendezvousToken::new(bytes)?)
}

/// One byte each way: the tunnel is real and in order.
async fn ping(link: &mut RelayLink, byte_out: u8) -> std::io::Result<u8> {
    let written = poll_fn(|cx| Pin::new(&mut *link).poll_write(cx, &[byte_out])).await?;
    if written != 1 {
        return Err(std::io::ErrorKind::WriteZero.into());
    }
    poll_fn(|cx| Pin::new(&mut *link).poll_flush(cx)).await?;
    let mut byte = [0];
    let read = poll_fn(|cx| Pin::new(&mut *link).poll_read(cx, &mut byte)).await?;
    if read != 1 {
        return Err(std::io::ErrorKind::UnexpectedEof.into());
    }
    Ok(byte[0])
}

#[tokio::test(flavor = "multi_thread")]
#[ignore = "load test: run in release (see the module docs)"]
async fn ten_thousand_concurrent_rendezvous() -> AnyResult<()> {
    let rooms: u32 = std::env::var("TODOKE_LOAD_ROOMS")
        .ok()
        .and_then(|value| value.parse().ok())
        .unwrap_or(10_000);
    let (identity, _, _) = Identity::self_signed(vec!["relay.test".into()])?;
    let mut config = Config::new(([127, 0, 0, 1], 0).into());
    // Every client is on loopback: one source.
    config.max_connections = 2 * rooms as usize + 100;
    config.max_connections_per_source = config.max_connections;
    let relay = Relay::bind(config, &identity)?;
    let endpoint = Arc::new(RelayEndpoint {
        name: "load".into(),
        address: relay.local_addr()?.to_string(),
        server_name: "relay.test".into(),
        pin: Some(identity.pin()?),
    });
    let metrics = relay.metrics();
    tokio::spawn(relay.run(Arc::new(tokio::sync::Notify::new())));
    // One UDP socket for every client connection.
    let client = Arc::new(RelayClient::new()?);
    let started = Instant::now();
    // Pairs arrive in batches, as handshakes allow; every tunnel stays
    // open, so all of them are open together at the end.
    let mut links = Vec::with_capacity(2 * rooms as usize);
    let mut next = 0;
    while next < rooms {
        let batch = next..(next + BATCH).min(rooms);
        next = batch.end;
        let mut tasks = Vec::with_capacity(2 * BATCH as usize);
        for index in batch {
            for side in [0_u8, 1] {
                let (client, endpoint) = (Arc::clone(&client), Arc::clone(&endpoint));
                tasks.push(tokio::spawn(async move {
                    // As the app does: a connection that did not come up
                    // (a lost handshake under a burst of UDP) is tried
                    // again while the peer still waits.
                    let mut attempts = 0;
                    let link = loop {
                        attempts += 1;
                        match client
                            .rendezvous(&endpoint, token(index)?, Duration::from_secs(30))
                            .await
                        {
                            Err(RelayError::Unreachable(_)) if attempts < 3 => {}
                            other => break other?,
                        }
                    };
                    Ok::<_, Box<dyn std::error::Error + Send + Sync>>((side, link))
                }));
            }
        }
        for task in tasks {
            links.push(task.await??);
        }
    }
    let met = started.elapsed();
    let open = metrics.tunnels.load(std::sync::atomic::Ordering::Relaxed);
    // Every tunnel is open at once.
    assert_eq!(open, rooms as usize);
    let mut pings = Vec::with_capacity(links.len());
    for (side, mut link) in links {
        pings.push(tokio::spawn(async move {
            let back = ping(&mut link, side).await?;
            Ok::<_, std::io::Error>((side, back, link))
        }));
    }
    for ping in pings {
        let (side, back, _link) = ping.await??;
        assert_eq!(back, 1 - side);
    }
    println!(
        "{rooms} rendezvous ({} connections) met in {:.1} s; all tunnels carried a byte each way after {:.1} s",
        2 * rooms,
        met.as_secs_f64(),
        started.elapsed().as_secs_f64()
    );
    Ok(())
}
