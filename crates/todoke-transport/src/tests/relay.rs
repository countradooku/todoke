//! A malicious relay (PROTOCOL §10, §14): a relay sees and controls every
//! tunnel byte, so it can flip, replay, or drop bytes. Sessions run through
//! a real relay node with one tunnel end altered as such a relay would;
//! none of it breaks confidentiality or integrity: the plaintext never
//! crosses the relay, a damaged handshake never completes, and a damaged
//! transfer stops without a corrupted file being published.

use core::pin::Pin;
use core::task::{Context, Poll};
use std::sync::{Arc, Mutex};

use todoke_proto::relay::RendezvousToken;
use todoke_relay::{Config, Identity, Relay};
use todoke_transfer::{MemorySink, MemorySource, TransferEvent};

use super::*;
use crate::relay::{RelayClient, RelayEndpoint, RelayLink};

/// What a malicious relay does to the bytes it hands one endpoint.
#[derive(Clone, Copy, Debug)]
enum Attack {
    /// Nothing: an honest relay.
    None,
    /// Flips one bit of the byte at this offset.
    Flip(u64),
    /// At this offset, inserts again the `len` bytes before it.
    Replay { at: u64, len: usize },
    /// Leaves out `len` bytes from this offset.
    Drop { at: u64, len: u64 },
}

/// One endpoint's tunnel, as a malicious relay delivers it. Every byte the
/// relay forwarded is recorded.
struct Tampered<L> {
    inner: L,
    attack: Attack,
    offset: u64,
    replay: Vec<u8>,
    seen: Arc<Mutex<Vec<u8>>>,
}

impl<L: Link> Link for Tampered<L> {
    fn info(&self) -> &LinkInfo {
        self.inner.info()
    }
}

impl<L: Link> futures_io::AsyncRead for Tampered<L> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if !this.replay.is_empty() {
            let take = this.replay.len().min(buf.len());
            buf[..take].copy_from_slice(&this.replay[..take]);
            this.replay.drain(..take);
            return Poll::Ready(Ok(take));
        }
        let read = match Pin::new(&mut this.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(read)) => read,
            other => return other,
        };
        let start = this.offset;
        this.offset += read as u64;
        let mut seen = this
            .seen
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        seen.extend_from_slice(&buf[..read]);
        let range = start..this.offset;
        match this.attack {
            Attack::Flip(at) if range.contains(&at) => {
                let index = usize::try_from(at - start).unwrap_or(0);
                buf[index] ^= 0x01;
                Poll::Ready(Ok(read))
            }
            Attack::Replay { at, len } if range.contains(&at) => {
                // Deliver up to `at`; then the `len` bytes before it, again;
                // then the rest.
                let cut = usize::try_from(at - start).unwrap_or(0);
                let before = seen.len() - read + cut;
                let mut queued = seen[before.saturating_sub(len)..before].to_vec();
                queued.extend_from_slice(&buf[cut..read]);
                this.replay = queued;
                Poll::Ready(Ok(cut))
            }
            Attack::Drop { at, len } if range.contains(&at) => {
                let cut = usize::try_from(at - start).unwrap_or(0);
                let skip = usize::try_from(len).unwrap_or(usize::MAX).min(read - cut);
                buf.copy_within(cut + skip..read, cut);
                Poll::Ready(Ok(read - skip))
            }
            _ => Poll::Ready(Ok(read)),
        }
    }
}

impl<L: Link> futures_io::AsyncWrite for Tampered<L> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_close(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_close(cx)
    }
}

/// A relay node on loopback and how to reach it (pinned).
fn relay() -> AnyResult<RelayEndpoint> {
    let (identity, _, _) = Identity::self_signed(vec!["relay.test".into()])?;
    let node = Relay::bind(Config::new(([127, 0, 0, 1], 0).into()), &identity)?;
    let endpoint = RelayEndpoint {
        name: "test".into(),
        address: node.local_addr()?.to_string(),
        server_name: "relay.test".into(),
        pin: Some(identity.pin()?),
    };
    tokio::spawn(node.run(Arc::new(tokio::sync::Notify::new())));
    Ok(endpoint)
}

/// Alice's and Bob's tunnel ends, met on their pair's rendezvous token.
async fn tunnel(alice: &Device, bob: &Device) -> AnyResult<(RelayLink, RelayLink)> {
    let relay = relay()?;
    let token = alice
        .table()?
        .rendezvous_token(&bob.key())
        .ok_or("no token")?;
    assert_eq!(
        bob.table()?.rendezvous_token(&alice.key()),
        Some(token.clone())
    );
    let token = RendezvousToken::new(*token)?;
    let (one, two) = (RelayClient::new()?, RelayClient::new()?);
    let wait = Duration::from_secs(10);
    // Tried again if a connection did not come up: many tests at once on
    // one loopback can lose handshakes, and the app retries too.
    let meet = |client: RelayClient| {
        let relay = relay.clone();
        async move {
            let mut attempts = 0;
            loop {
                attempts += 1;
                match client.rendezvous(&relay, token, wait).await {
                    Err(crate::relay::RelayError::Unreachable(_)) if attempts < 3 => {}
                    other => return other,
                }
            }
        }
    };
    let (a, b) = tokio::join!(meet(one), meet(two));
    Ok((a?, b?))
}

/// What happened when Alice offered Bob a file through a relay that did
/// `attack` to Bob's side of the tunnel.
struct Outcome {
    handshake: bool,
    sent: Vec<TransferEvent>,
    received: Vec<TransferEvent>,
    published: usize,
    /// Every byte the relay forwarded to Bob.
    forwarded: Vec<u8>,
}

const FILE: usize = 16_384 * 30 + 5;

/// The contact handshake on a relay tunnel, in §4's roles: the smaller
/// device key initiates. `None` if it failed (within 30 seconds).
async fn handshake(
    alice: &mut Device,
    bob: &mut Device,
    a: RelayLink,
    b: Tampered<RelayLink>,
) -> AnyResult<Option<(Established<RelayLink>, Established<Tampered<RelayLink>>)>> {
    let (alice_manager, bob_manager) = (alice.manager(), bob.manager());
    let (alice_table, bob_table) = (alice.table()?, bob.table()?);
    let alice_first = alice.key().as_bytes() < bob.key().as_bytes();
    let (alice_key, bob_key) = (alice.key(), bob.key());
    let (alice_local, alice_store) = alice.parts()?;
    let (bob_local, bob_store) = bob.parts()?;
    let established = tokio::time::timeout(Duration::from_secs(30), async {
        if alice_first {
            let initiate = alice_manager
                .claim_outgoing(bob_key)?
                .with_link(a)
                .initiate(&alice_table, alice_store, &alice_local, wall()?);
            let respond = async {
                let Incoming::Contact(incoming) = bob_manager.accept(b).await? else {
                    return Err::<_, Box<dyn std::error::Error>>("expected a contact".into());
                };
                Ok(incoming
                    .claim(&bob_table, wall()?)
                    .await?
                    .respond(&bob_table, bob_store, &bob_local, wall()?)
                    .await?)
            };
            let (alice_side, bob_side) = tokio::join!(initiate, respond);
            Ok::<_, Box<dyn std::error::Error>>((alice_side?, bob_side?))
        } else {
            let initiate = bob_manager
                .claim_outgoing(alice_key)?
                .with_link(b)
                .initiate(&bob_table, bob_store, &bob_local, wall()?);
            let respond = async {
                let Incoming::Contact(incoming) = alice_manager.accept(a).await? else {
                    return Err::<_, Box<dyn std::error::Error>>("expected a contact".into());
                };
                Ok(incoming
                    .claim(&alice_table, wall()?)
                    .await?
                    .respond(&alice_table, alice_store, &alice_local, wall()?)
                    .await?)
            };
            let (bob_side, alice_side) = tokio::join!(initiate, respond);
            Ok((alice_side?, bob_side?))
        }
    })
    .await;
    Ok(match established {
        Ok(Ok(sessions)) => Some(sessions),
        _ => None,
    })
}

async fn through_relay(attack: Attack) -> AnyResult<Outcome> {
    let (mut alice, mut bob) = paired().await?;
    let (a, b) = tunnel(&alice, &bob).await?;
    let seen = Arc::new(Mutex::new(Vec::new()));
    let b = Tampered {
        inner: b,
        attack,
        offset: 0,
        replay: Vec::new(),
        seen: Arc::clone(&seen),
    };
    let established = handshake(&mut alice, &mut bob, a, b).await?;
    let forwarded = || {
        seen.lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    };
    let Some((mut alice_session, mut bob_session)) = established else {
        return Ok(Outcome {
            handshake: false,
            sent: Vec::new(),
            received: Vec::new(),
            published: 0,
            forwarded: forwarded(),
        });
    };
    let mut source = MemorySource::new();
    let offered = offer(&alice, &bob, FILE, &mut source)?;
    let sending = engine(
        &mut alice_session,
        &alice,
        source,
        MemorySink::new(),
        "relay",
    )?;
    let receiving = engine(
        &mut bob_session,
        &bob,
        MemorySource::new(),
        MemorySink::new(),
        "relay",
    )?;
    let (sent, (received, _)) = tokio::time::timeout(Duration::from_secs(60), async {
        tokio::join!(
            send(&mut alice_session, sending, Some(offered)),
            receive(&mut bob_session, receiving, None)
        )
    })
    .await?;
    Ok(Outcome {
        handshake: true,
        sent: sent.events,
        received: received.events,
        published: received.engine.sink().published_count(),
        forwarded: forwarded(),
    })
}

fn completed(events: &[TransferEvent]) -> bool {
    events
        .iter()
        .any(|event| matches!(event, TransferEvent::Completed { .. }))
}

/// The plaintext never crosses the relay: no 64-byte run of the file is in
/// what it forwarded.
fn hidden(forwarded: &[u8]) -> bool {
    let plain = content(FILE, 9);
    !forwarded
        .windows(64)
        .any(|window| window == &plain[1000..1064])
}

#[tokio::test(flavor = "multi_thread")]
async fn an_honest_relay_carries_the_transfer_and_sees_no_plaintext() -> TestResult {
    let outcome = through_relay(Attack::None).await?;
    assert!(outcome.handshake);
    assert!(completed(&outcome.received));
    assert!(
        outcome
            .sent
            .iter()
            .any(|event| matches!(event, TransferEvent::DeliveryConfirmed { .. }))
    );
    assert_eq!(outcome.published, 1);
    assert!(outcome.forwarded.len() > FILE);
    assert!(hidden(&outcome.forwarded));
    Ok(())
}

/// A damaged handshake never completes.
async fn handshake_refused(attack: Attack) -> TestResult {
    let outcome = through_relay(attack).await?;
    assert!(!outcome.handshake, "{attack:?}");
    Ok(())
}

/// A damaged transfer stops: nothing published, no receipt, no plaintext
/// at the relay.
async fn transfer_refused(attack: Attack) -> TestResult {
    let outcome = through_relay(attack).await?;
    assert!(outcome.handshake, "{attack:?}");
    assert!(!completed(&outcome.received), "{attack:?}");
    assert_eq!(outcome.published, 0, "{attack:?}");
    assert!(
        !outcome
            .sent
            .iter()
            .any(|event| matches!(event, TransferEvent::DeliveryConfirmed { .. })),
        "{attack:?}"
    );
    assert!(hidden(&outcome.forwarded), "{attack:?}");
    Ok(())
}

#[tokio::test(flavor = "multi_thread")]
async fn a_flipped_hello_bit_ends_the_handshake() -> TestResult {
    handshake_refused(Attack::Flip(40)).await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_flipped_key_exchange_bit_ends_the_handshake() -> TestResult {
    handshake_refused(Attack::Flip(1500)).await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_dropped_handshake_byte_ends_the_handshake() -> TestResult {
    handshake_refused(Attack::Drop { at: 200, len: 1 }).await
}

#[tokio::test(flavor = "multi_thread")]
async fn replayed_handshake_bytes_end_the_handshake() -> TestResult {
    handshake_refused(Attack::Replay { at: 300, len: 16 }).await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_flipped_transfer_bit_stops_the_transfer() -> TestResult {
    transfer_refused(Attack::Flip(200_000)).await
}

#[tokio::test(flavor = "multi_thread")]
async fn a_replayed_frame_stops_the_transfer() -> TestResult {
    transfer_refused(Attack::Replay {
        at: 200_000,
        len: 4096,
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn dropped_frames_stop_the_transfer() -> TestResult {
    transfer_refused(Attack::Drop {
        at: 200_000,
        len: 4096,
    })
    .await
}

#[tokio::test(flavor = "multi_thread")]
async fn one_dropped_byte_stops_the_transfer() -> TestResult {
    transfer_refused(Attack::Drop {
        at: 200_000,
        len: 1,
    })
    .await
}
