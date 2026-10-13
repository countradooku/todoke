//! End to end: real suite 0x0001 contact sessions through the
//! [`TransportManager`] over simulated links (latency, bandwidth, loss),
//! simultaneous attempts, hostile Hellos, the unauthenticated-attempt
//! budget, and migration to a faster link in the middle of a transfer.

use core::future::Future;
use core::pin::{Pin, pin};
use core::task::Poll;
use core::time::Duration;
use std::net::SocketAddr;

use futures_io::{AsyncRead as _, AsyncWrite as _};
use todoke_crypto::content::ContentSuites;
use todoke_crypto::discovery::DiscoveryTable;
use todoke_crypto::identity::{
    BindingRequest, ContactStore, Ed25519PublicKey, ExportPolicy, KeyId, KeyRole, KeyStore,
    MemoryStorage, SoftwareKeyStore, SoftwareSealer, StorageKey, VerifiedDeviceBinding,
    issue_device_binding,
};
use todoke_crypto::pairing::{PairingError, PairingOffers, QrPayload};
use todoke_crypto::session::{
    Accepted, IncomingSession, LocalIdentity, NoiseStaticKey, Session, SessionError, SessionMode,
    UnauditedSuite0001,
};
use todoke_proto::session::{Hello, PreludeKind, encode_prelude_record};
use todoke_proto::time::UnixTime;
use todoke_proto::transfer::EntryKind;
use todoke_proto::transfer::{Capabilities, ManifestLimits};
use todoke_transfer::{
    Clock, EngineConfig, LocalCapabilities, ManifestBuilder, MemoryFile, MemorySink, MemorySource,
    OutgoingOffer, TransferEngine, TransferEvent, pump,
};
use zeroize::Zeroizing;

use crate::LinkKind;
use crate::link::LinkInfo;
use crate::manager::{
    ConnectError, Established, Incoming, MigrationPolicy, OutgoingClaim, TransportManager,
};
use crate::race::Candidate;
use crate::sim::{Answer, Path, SimConnector, SimLink};
use crate::timer::TokioTimer;

type AnyResult<T> = Result<T, Box<dyn std::error::Error>>;
type TestResult = AnyResult<()>;
type Keys = SoftwareKeyStore<MemoryStorage>;
type Store = ContactStore<SoftwareSealer, MemoryStorage>;

const T0: u64 = 1_760_000_000;
const WALL: u64 = T0 + 60;
const GATE: UnauditedSuite0001 = UnauditedSuite0001::acknowledge_not_production_ready();
const MS: Duration = Duration::from_millis(1);

fn time(seconds: u64) -> Result<UnixTime, &'static str> {
    UnixTime::new(seconds).ok_or("time")
}

fn wall() -> Result<UnixTime, &'static str> {
    time(WALL)
}

fn sealer(byte: u8) -> SoftwareSealer {
    SoftwareSealer::new(StorageKey::from_bytes(Zeroizing::new([byte; 32])))
}

fn address(last: u8) -> SocketAddr {
    SocketAddr::from(([192, 168, 7, last], 47_000))
}

/// A device with real keys and a binding valid for 30 days from `T0`.
struct Device {
    keys: Keys,
    signing_key: KeyId,
    noise: NoiseStaticKey,
    binding: VerifiedDeviceBinding,
    store: Store,
}

impl Device {
    fn new(kem_seed: u8) -> AnyResult<Self> {
        let mut keys = SoftwareKeyStore::open(sealer(1), MemoryStorage::new())?;
        let root = keys.generate(KeyRole::PersonRoot, ExportPolicy::NonExportable)?;
        let device = keys.generate(KeyRole::Device, ExportPolicy::NonExportable)?;
        let noise = NoiseStaticKey::generate()?;
        let pair = libcrux_ml_kem::mlkem768::generate_key_pair([kem_seed; 64]);
        let kem_static: [u8; 1184] = *pair.public_key().as_slice();
        let request = BindingRequest {
            noise_static: *noise.public_key(),
            kem_static: Box::new(kem_static),
            serial: core::num::NonZeroU64::new(1).ok_or("serial")?,
            not_before: time(T0)?,
            not_after: time(T0 + 30 * 86_400)?,
        };
        let binding = issue_device_binding(&keys, &root, &device, request)?;
        Ok(Self {
            keys,
            signing_key: device,
            noise,
            binding,
            store: ContactStore::open(sealer(kem_seed), MemoryStorage::new())?,
        })
    }

    fn key(&self) -> Ed25519PublicKey {
        *self.binding.device_public()
    }

    /// The local identity and the contact store, borrowed together.
    fn parts(&mut self) -> AnyResult<(LocalIdentity<'_, Keys>, &mut Store)> {
        let local = LocalIdentity::new(
            &self.keys,
            self.signing_key,
            &self.binding,
            &self.noise,
            wall()?,
        )?;
        Ok((local, &mut self.store))
    }

    fn table(&self) -> AnyResult<DiscoveryTable> {
        Ok(self.store.discovery_table(wall()?)?)
    }

    fn manager(&self) -> TransportManager {
        TransportManager::new(GATE, self.key(), PairingOffers::new())
    }
}

/// Alice and Bob, paired by QR over a simulated link (Alice scans).
async fn paired() -> AnyResult<(Device, Device)> {
    {
        let mut alice = Device::new(0x41)?;
        let mut bob = Device::new(0x42)?;
        let offers = PairingOffers::new();
        let timer = TokioTimer::new();
        let text = {
            let (bob_local, _) = bob.parts()?;
            offers
                .create_qr(&bob_local, wall()?, timer_now(&timer))?
                .to_text()
        };
        let payload = QrPayload::from_text(&text, wall()?)?;
        let (a, b) = crate::sim::link(Path::new(MS), address(1), address(2), 7);
        {
            let (alice_local, alice_store) = alice.parts()?;
            let (bob_local, bob_store) = bob.parts()?;
            let (plan, mut initiator) = alice_store.begin_qr_pairing(&payload, wall()?)?;
            let initiate =
                Session::initiate(a, timer, GATE, &alice_local, wall()?, plan, &mut initiator);
            let respond = async {
                let Accepted::Hello(mut incoming) =
                    IncomingSession::accept_any(b, timer, GATE, &offers).await?
                else {
                    return Err::<_, Box<dyn std::error::Error>>("expected a ClientHello".into());
                };
                let reservation = incoming.reserve_offer(&offers, wall()?)?;
                let (plan, mut authority) = reservation.into_qr_responder(bob_store)?;
                Ok(incoming
                    .respond(&bob_local, wall()?, plan, &mut authority)
                    .await?)
            };
            let (initiated, responded) = tokio::join!(initiate, respond);
            drop((initiated?, responded?));
        }
        Ok((alice, bob))
    }
}

fn timer_now(timer: &TokioTimer) -> Duration {
    todoke_crypto::session::Timer::now(timer)
}

/// Alice connects to Bob through `connector` (whose far ends Bob accepts)
/// and both run the contact handshake.
async fn connect(
    alice: &mut Device,
    bob: &mut Device,
    alice_manager: &TransportManager,
    bob_manager: &TransportManager,
    connector: &SimConnector,
    candidates: &[Candidate],
) -> AnyResult<(Established<SimLink>, Established<SimLink>)> {
    let claim = alice_manager.claim_outgoing(bob.key())?;
    connect_claimed(claim, alice, bob, bob_manager, connector, candidates).await
}

/// As [`connect`], from a claim Alice already holds.
async fn connect_claimed(
    claim: OutgoingClaim<'_>,
    alice: &mut Device,
    bob: &mut Device,
    bob_manager: &TransportManager,
    connector: &SimConnector,
    candidates: &[Candidate],
) -> AnyResult<(Established<SimLink>, Established<SimLink>)> {
    let (alice_table, bob_table) = (alice.table()?, bob.table()?);
    let connected = claim.connect(connector, candidates).await?;
    let (_, far) = connector.accepted().pop().ok_or("no link opened")?;
    let (alice_local, alice_store) = alice.parts()?;
    let (bob_local, bob_store) = bob.parts()?;
    let initiate = connected.initiate(&alice_table, alice_store, &alice_local, wall()?);
    let respond = async {
        let Incoming::Contact(incoming) = bob_manager.accept(far).await? else {
            return Err::<_, Box<dyn std::error::Error>>("expected a contact Hello".into());
        };
        Ok(incoming
            .claim(&bob_table, wall()?)
            .await?
            .respond(&bob_table, bob_store, &bob_local, wall()?)
            .await?)
    };
    let (initiated, responded) = tokio::join!(initiate, respond);
    Ok((initiated?, responded?))
}

fn fast() -> Answer {
    Answer::Connect {
        setup: MS * 2,
        path: Path::new(MS),
    }
}

/// A session runs over the link that connected first, both ends agree on
/// it, and after its ratchet the next session uses the new locator.
#[tokio::test(start_paused = true)]
async fn contact_sessions_run_over_the_winning_link() -> TestResult {
    let (mut alice, mut bob) = paired().await?;
    let (alice_manager, bob_manager) = (alice.manager(), bob.manager());
    let connector = SimConnector::default();
    connector.answer(
        address(10),
        Answer::Connect {
            setup: Duration::from_secs(2),
            path: Path::new(MS * 30),
        },
    );
    connector.answer(address(11), fast());
    let candidates = [
        Candidate::new(LinkKind::Simulated, address(10)),
        Candidate::new(LinkKind::Simulated, address(11)),
    ];
    let stale_table = bob.table()?;
    let (mut at_alice, mut at_bob) = connect(
        &mut alice,
        &mut bob,
        &alice_manager,
        &bob_manager,
        &connector,
        &candidates,
    )
    .await?;
    assert_eq!(at_alice.link().remote(), Some(address(11)));
    assert_eq!(at_alice.peer(), &bob.key());
    assert_eq!(at_bob.peer(), &alice.key());
    assert_eq!(at_alice.session().mode(), SessionMode::Contact);
    assert_eq!(
        at_alice.session().session_id(),
        at_bob.session().session_id()
    );
    // One session per pair while it lives.
    assert!(matches!(
        alice_manager.claim_outgoing(bob.key()),
        Err(ConnectError::Busy)
    ));
    drop((at_alice, at_bob));
    assert!(!alice_manager.is_busy(&bob.key()));
    // The ratchet committed: the old table's locator is gone.
    assert_ne!(
        stale_table.locator(&alice.key()),
        bob.table()?.locator(&alice.key())
    );
    let (second, _) = connect(
        &mut alice,
        &mut bob,
        &alice_manager,
        &bob_manager,
        &connector,
        &candidates,
    )
    .await?;
    assert_eq!(second.link().remote(), Some(address(11)));
    Ok(())
}

/// A `ClientHello` as anyone who saw (or guessed) a locator can send it.
fn forged_hello(locator: [u8; 16]) -> AnyResult<Vec<u8>> {
    let hello = Hello::client(SessionMode::Contact, 1, locator, [0x5e; 16])?;
    Ok(encode_prelude_record(
        PreludeKind::ClientHello,
        &hello.encode(),
    )?)
}

async fn write_all(link: &mut SimLink, mut data: &[u8]) -> std::io::Result<()> {
    while !data.is_empty() {
        let written = core::future::poll_fn(|cx| Pin::new(&mut *link).poll_write(cx, data)).await?;
        data = &data[written..];
    }
    Ok(())
}

/// A link carrying a forged Hello, its far end for `accept`.
async fn forged_link(locator: [u8; 16], from: u8) -> AnyResult<(SimLink, SimLink)> {
    let (mut near, far) =
        crate::sim::link(Path::new(MS), address(from), address(99), u64::from(from));
    write_all(&mut near, &forged_hello(locator)?).await?;
    Ok((near, far))
}

/// A table from before the last committed session is refused locally,
/// before anything is sent; a replayed Hello with a locator from before
/// that session is refused before any handshake.
#[tokio::test(start_paused = true)]
async fn stale_tables_and_old_locators_are_refused() -> TestResult {
    let (mut alice, mut bob) = paired().await?;
    let (alice_manager, bob_manager) = (alice.manager(), bob.manager());
    let connector = SimConnector::default();
    connector.answer(address(11), fast());
    let candidates = [Candidate::new(LinkKind::Simulated, address(11))];
    let (alice_old, bob_old) = (alice.table()?, bob.table()?);
    let old_locator = alice_old.locator(&bob.key()).ok_or("locator")?;
    // One session moves both sides to a new generation.
    drop(
        connect(
            &mut alice,
            &mut bob,
            &alice_manager,
            &bob_manager,
            &connector,
            &candidates,
        )
        .await?,
    );
    // Alice with the old table: refused before a byte is sent.
    let connected = alice_manager
        .claim_outgoing(bob.key())?
        .connect(&connector, &candidates)
        .await?;
    let (_, mut far) = connector.accepted().pop().ok_or("link")?;
    let (alice_local, alice_store) = alice.parts()?;
    let initiated = connected
        .initiate(&alice_old, alice_store, &alice_local, wall()?)
        .await;
    assert!(matches!(initiated, Err(ConnectError::StaleTable)));
    let mut byte = [0];
    let read = core::future::poll_fn(|cx| Pin::new(&mut far).poll_read(cx, &mut byte)).await?;
    assert_eq!(read, 0, "nothing may be sent with a stale table");
    // A replay of the old Hello at Bob: no contact matches it now.
    let (_held, link) = forged_link(old_locator, 40).await?;
    let Incoming::Contact(incoming) = bob_manager.accept(link).await? else {
        return Err("expected a contact Hello".into());
    };
    assert!(matches!(
        incoming.claim(&bob.table()?, wall()?).await,
        Err(ConnectError::UnknownPeer)
    ));
    // Bob's own old table is refused once the epoch moves on.
    let (_held, link) = forged_link(old_locator, 41).await?;
    let Incoming::Contact(incoming) = bob_manager.accept(link).await? else {
        return Err("expected a contact Hello".into());
    };
    let later = time(WALL + 3 * todoke_proto::discovery::EPOCH_SECONDS)?;
    assert!(matches!(
        incoming.claim(&bob_old, later).await,
        Err(ConnectError::StaleTable)
    ));
    assert!(matches!(alice.store.availability(&bob.key()), Ok(Ok(_))));
    Ok(())
}

/// R1: a replayed Hello must not cost the larger device its own outgoing
/// session. The replay waits; the real session completes; the replay is
/// refused, and nothing is discarded or blocked.
#[tokio::test(start_paused = true)]
async fn a_replayed_hello_never_displaces_an_outgoing_attempt() -> TestResult {
    let (alice, bob) = paired().await?;
    let (mut small, mut large) = if alice.key() < bob.key() {
        (alice, bob)
    } else {
        (bob, alice)
    };
    let (small_manager, large_manager) = (small.manager(), large.manager());
    let (small_table, large_table) = (small.table()?, large.table()?);
    let locator = small_table.locator(&large.key()).ok_or("locator")?;
    let connector = SimConnector::default();
    connector.answer(address(50), fast());
    let connected = large_manager
        .claim_outgoing(small.key())?
        .connect(
            &connector,
            &[Candidate::new(LinkKind::Simulated, address(50))],
        )
        .await?;
    let (_, at_small) = connector.accepted().pop().ok_or("link")?;
    // The replay arrives while the larger device's attempt is under way.
    let (_held, replay) = forged_link(locator, 51).await?;
    let Incoming::Contact(replayed) = large_manager.accept(replay).await? else {
        return Err("expected a contact Hello".into());
    };
    let (large_local, large_store) = large.parts()?;
    let (small_local, small_store) = small.parts()?;
    let replay_claim = replayed.claim(&large_table, wall()?);
    let outgoing = connected.initiate(&large_table, large_store, &large_local, wall()?);
    let responding = async {
        let Incoming::Contact(incoming) = small_manager.accept(at_small).await? else {
            return Err::<_, Box<dyn std::error::Error>>("expected a contact Hello".into());
        };
        Ok(incoming
            .claim(&small_table, wall()?)
            .await?
            .respond(&small_table, small_store, &small_local, wall()?)
            .await?)
    };
    let (claimed, initiated, responded) = tokio::join!(replay_claim, outgoing, responding);
    let (mut at_large, mut at_small) = (initiated?, responded?);
    assert!(matches!(claimed, Err(ConnectError::Busy)));
    assert_eq!(
        at_large.session().session_id(),
        at_small.session().session_id()
    );
    assert!(large_manager.is_busy(&small.key()));
    Ok(())
}

/// Both devices connect at once: they keep the same single connection, the
/// smaller key's outgoing one (§4), and neither pairing is disturbed.
#[tokio::test(start_paused = true)]
async fn simultaneous_attempts_keep_one_connection() -> TestResult {
    let (alice, bob) = paired().await?;
    let (mut small, mut large) = if alice.key() < bob.key() {
        (alice, bob)
    } else {
        (bob, alice)
    };
    let (small_manager, large_manager) = (small.manager(), large.manager());
    let (small_table, large_table) = (small.table()?, large.table()?);
    let (small_key, large_key) = (small.key(), large.key());
    // Each opens a link to the other.
    let small_connector = SimConnector::default();
    small_connector.answer(address(20), fast());
    let large_connector = SimConnector::default();
    large_connector.answer(address(21), fast());
    let small_out = small_manager
        .claim_outgoing(large_key)?
        .connect(
            &small_connector,
            &[Candidate::new(LinkKind::Simulated, address(20))],
        )
        .await?;
    let large_out = large_manager
        .claim_outgoing(small_key)?
        .connect(
            &large_connector,
            &[Candidate::new(LinkKind::Simulated, address(21))],
        )
        .await?;
    let (_, at_large) = small_connector.accepted().pop().ok_or("link")?;
    let (_, at_small) = large_connector.accepted().pop().ok_or("link")?;
    let (small_local, small_store) = small.parts()?;
    let (large_local, large_store) = large.parts()?;
    // Each sends its Hello. The smaller device refuses the larger's attempt
    // at its Hello (§4) while its own runs; the larger takes the smaller's
    // attempt over its own, whose handshake then fails before anything is
    // journaled, and responds once its store is free again.
    let small_side = async {
        let refuse = async {
            let Incoming::Contact(incoming) = small_manager.accept(at_small).await? else {
                return Err::<(), Box<dyn std::error::Error>>("expected a contact Hello".into());
            };
            match incoming.claim(&small_table, wall()?).await {
                Err(ConnectError::Busy) => Ok(()),
                other => Err(format!("{other:?}").into()),
            }
        };
        let (initiated, refused) = tokio::join!(
            small_out.initiate(&small_table, small_store, &small_local, wall()?),
            refuse
        );
        refused?;
        Ok::<_, Box<dyn std::error::Error>>(initiated?)
    };
    let large_side = async {
        let take = async {
            let Incoming::Contact(incoming) = large_manager.accept(at_large).await? else {
                return Err::<_, Box<dyn std::error::Error>>("expected a contact Hello".into());
            };
            Ok(incoming.claim(&large_table, wall()?).await?)
        };
        let (own, claimed) = tokio::join!(
            large_out.initiate(&large_table, &mut *large_store, &large_local, wall()?),
            take
        );
        // Refused at its Hello by the smaller device: the stream closes
        // before the Noise handshake, so nothing was journaled.
        assert!(
            matches!(
                own,
                Err(ConnectError::Session(
                    SessionError::Closed | SessionError::Io(_)
                ))
            ),
            "{own:?}"
        );
        let responded = claimed?
            .respond(&large_table, large_store, &large_local, wall()?)
            .await?;
        Ok::<_, Box<dyn std::error::Error>>(responded)
    };
    let (small_result, large_result) = tokio::join!(small_side, large_side);
    let mut at_small_session = small_result?;
    let mut at_large_session = large_result?;
    assert_eq!(
        at_small_session.session().session_id(),
        at_large_session.session().session_id()
    );
    assert_eq!(at_small_session.link().remote(), Some(address(20)));
    assert!(large_manager.is_busy(&small_key));
    assert!(small_manager.is_busy(&large_key));
    drop((at_small_session, at_large_session));
    assert!(!large_manager.is_busy(&small_key));
    assert!(matches!(small.store.availability(&large_key), Ok(Ok(_))));
    assert!(matches!(large.store.availability(&small_key), Ok(Ok(_))));
    Ok(())
}

/// Polls `future` once, so that it starts and registers interest.
async fn start<F: Future>(mut future: Pin<&mut F>) -> Option<F::Output> {
    core::future::poll_fn(|cx| match future.as_mut().poll(cx) {
        Poll::Ready(output) => Poll::Ready(Some(output)),
        Poll::Pending => Poll::Ready(None),
    })
    .await
}

/// At most four unauthenticated attempts at once (§13): silent links hold
/// their places until their Hello deadline, and a fifth is refused at once.
#[tokio::test(start_paused = true)]
async fn the_unauthenticated_attempt_budget_applies() -> TestResult {
    let bob = Device::new(0x42)?;
    let manager = bob.manager();
    let mut held = Vec::new();
    let mut far_ends = Vec::new();
    for n in 0..5_u8 {
        let (near, far) = crate::sim::link(Path::new(MS), address(n), address(99), u64::from(n));
        held.push(near);
        far_ends.push(far);
    }
    let mut far_ends = far_ends.into_iter();
    let mut first = pin!(manager.accept(far_ends.next().ok_or("link")?));
    let mut second = pin!(manager.accept(far_ends.next().ok_or("link")?));
    let mut third = pin!(manager.accept(far_ends.next().ok_or("link")?));
    let mut fourth = pin!(manager.accept(far_ends.next().ok_or("link")?));
    for future in [
        start(first.as_mut()).await.is_none(),
        start(second.as_mut()).await.is_none(),
        start(third.as_mut()).await.is_none(),
        start(fourth.as_mut()).await.is_none(),
    ] {
        assert!(future, "a silent link finished early");
    }
    let refused = manager.accept(far_ends.next().ok_or("link")?).await;
    assert!(matches!(
        refused,
        Err(ConnectError::Session(SessionError::Pairing(
            PairingError::RateLimited
        )))
    ));
    // The silent ones give up after the first-record deadline, well before
    // the 30-second handshake bound.
    let started = tokio::time::Instant::now();
    assert!(matches!(
        first.await,
        Err(ConnectError::Session(SessionError::Timeout))
    ));
    assert!(started.elapsed() <= crate::manager::FIRST_RECORD_TIMEOUT);
    drop(held);
    Ok(())
}

/// R1: 20 attempt starts a minute (§13) is a sliding window on one clock:
/// after a burst the manager refuses for a minute, then accepts again. With
/// a clock per link the window never slid and 20 connections locked the
/// device out for good.
#[tokio::test(start_paused = true)]
async fn the_start_budget_window_slides() -> TestResult {
    let bob = Device::new(0x42)?;
    let manager = bob.manager();
    let closed = |n: u8| {
        let (near, far) = crate::sim::link(Path::new(MS), address(n), address(99), u64::from(n));
        drop(near);
        far
    };
    let refused = |result: &Result<Incoming<'_, SimLink>, ConnectError>| {
        matches!(
            result,
            Err(ConnectError::Session(SessionError::Pairing(
                PairingError::RateLimited
            )))
        )
    };
    for n in 0..20_u8 {
        let result = manager.accept(closed(n)).await;
        assert!(result.is_err() && !refused(&result), "start {n}");
    }
    assert!(refused(&manager.accept(closed(20)).await));
    tokio::time::sleep(Duration::from_secs(30)).await;
    assert!(refused(&manager.accept(closed(21)).await));
    tokio::time::sleep(Duration::from_secs(31)).await;
    let again = manager.accept(closed(22)).await;
    assert!(
        again.is_err() && !refused(&again),
        "the window did not slide"
    );
    Ok(())
}

/// At most two unauthenticated attempts from one address at a time.
#[tokio::test(start_paused = true)]
async fn one_source_cannot_take_every_attempt() -> TestResult {
    let bob = Device::new(0x42)?;
    let manager = bob.manager();
    let mut held = Vec::new();
    let mut from_one = Vec::new();
    for n in 0..3_u8 {
        let (near, far) = crate::sim::link(Path::new(MS), address(60), address(99), u64::from(n));
        held.push(near);
        from_one.push(far);
    }
    let mut from_one = from_one.into_iter();
    let mut first = pin!(manager.accept(from_one.next().ok_or("link")?));
    let mut second = pin!(manager.accept(from_one.next().ok_or("link")?));
    assert!(start(first.as_mut()).await.is_none());
    assert!(start(second.as_mut()).await.is_none());
    assert!(matches!(
        manager.accept(from_one.next().ok_or("link")?).await,
        Err(ConnectError::SourceBusy)
    ));
    // Another address still gets in.
    let (other_near, other) = crate::sim::link(Path::new(MS), address(61), address(99), 9);
    let mut other_accept = pin!(manager.accept(other));
    assert!(start(other_accept.as_mut()).await.is_none());
    drop((held, other_near));
    Ok(())
}

// --- Migration in the middle of a transfer -------------------------------

fn content(len: usize, salt: u8) -> Vec<u8> {
    (0..len)
        .map(|i| {
            let bytes = (i as u64).to_le_bytes();
            bytes[0] ^ bytes[1].rotate_left(3) ^ salt
        })
        .collect()
}

fn engine_config(label: &'static str) -> AnyResult<EngineConfig> {
    let maximums = Capabilities::PROTOCOL_MAXIMUMS;
    let record = Capabilities::new(
        ContentSuites::local().bits(),
        maximums.max_manifest_bytes(),
        maximums.max_entries(),
        maximums.max_file_bytes(),
        maximums.max_transfer_bytes(),
        16,
    )?;
    Ok(EngineConfig {
        capabilities: LocalCapabilities::new(record)?,
        transport: label,
    })
}

type Engine<'k> = TransferEngine<'k, Keys, MemorySource, MemorySink>;

fn engine<'k>(
    established: &mut Established<SimLink>,
    device: &'k Device,
    source: MemorySource,
    sink: MemorySink,
    label: &'static str,
) -> AnyResult<Engine<'k>> {
    let session = established.session();
    let now = session.now();
    Ok(TransferEngine::new(
        session.transfer_binding(),
        &device.keys,
        device.signing_key,
        source,
        sink,
        engine_config(label)?,
        Clock::new(wall()?, now),
        now,
    )?)
}

/// Offers one file of `len` bytes from Alice to Bob.
fn offer(
    alice: &Device,
    bob: &Device,
    len: usize,
    source: &mut MemorySource,
) -> AnyResult<OutgoingOffer> {
    let suite = ContentSuites::local()
        .select(ContentSuites::local())
        .ok_or("suite")?;
    let mut builder = ManifestBuilder::new(&alice.key(), &bob.key(), wall()?, time(WALL + 3600)?)?;
    let memory = MemoryFile::new(content(len, 9));
    let id = builder.add_file(
        0,
        "video.bin",
        "application/octet-stream",
        memory.size(),
        *memory.root(),
    );
    let manifest = builder.build(suite, &ManifestLimits::SPEC)?;
    source.insert(*manifest.transfer_id(), id, memory);
    Ok(OutgoingOffer::new(manifest)?)
}

/// What one side saw in one session.
struct Run<'k> {
    events: Vec<TransferEvent>,
    engine: Engine<'k>,
}

/// Drives the sender until a terminal event, the session's end, or `stop`
/// returns true for its engine.
async fn send<'k>(
    established: &mut Established<SimLink>,
    mut engine: Engine<'k>,
    mut offer: Option<OutgoingOffer>,
) -> Run<'k> {
    let mut events = Vec::new();
    loop {
        let session = established.session();
        let until = session.now() + Duration::from_secs(3600);
        let pumped = pump(session, &mut engine, until).await;
        let mut done = false;
        while let Some(event) = engine.pop_event() {
            match &event {
                TransferEvent::Ready { .. } => {
                    if let Some(offer) = offer.take()
                        && engine.offer(offer, established.session().now()).is_err()
                    {
                        done = true;
                    }
                }
                TransferEvent::DeliveryConfirmed { .. }
                | TransferEvent::DeliveryUnconfirmed { .. }
                | TransferEvent::Failed { .. }
                | TransferEvent::Interrupted { .. } => done = true,
                _ => {}
            }
            events.push(event);
        }
        if pumped.is_err() || done {
            return Run { events, engine };
        }
    }
}

/// Drives the receiver, accepting every offer (the user's decision, made
/// again for the resumed transfer), until a terminal event, the session's
/// end, or (if `migrate_after` is set) that many stored segments.
async fn receive<'k>(
    established: &mut Established<SimLink>,
    mut engine: Engine<'k>,
    migrate_after: Option<usize>,
) -> (Run<'k>, bool) {
    let mut events = Vec::new();
    loop {
        let session = established.session();
        let until = session.now() + Duration::from_secs(3600);
        let pumped = pump(session, &mut engine, until).await;
        let mut done = false;
        while let Some(event) = engine.pop_event() {
            match &event {
                TransferEvent::OfferReceived(view) => {
                    let selection = view
                        .entries
                        .iter()
                        .filter(|entry| entry.kind == EntryKind::File)
                        .map(|entry| entry.id)
                        .collect();
                    if engine
                        .accept(&view.transfer_id, selection, established.session().now())
                        .is_err()
                    {
                        done = true;
                    }
                }
                TransferEvent::Completed { .. }
                | TransferEvent::Failed { .. }
                | TransferEvent::Interrupted { .. } => done = true,
                _ => {}
            }
            events.push(event);
        }
        if migrate_after.is_some_and(|segments| engine.sink().stored_count() >= segments) {
            return (Run { events, engine }, true);
        }
        if pumped.is_err() || done {
            return (Run { events, engine }, false);
        }
    }
}

/// The first leg of a migration: what is left after the slow session ends.
struct Interrupted {
    /// Alice's session on the slow link, which Bob closed.
    session: Established<SimLink>,
    resumed: OutgoingOffer,
    source: MemorySource,
    sink: MemorySink,
    slow: LinkInfo,
}

const SLOW: u8 = 30;
const FAST: u8 = 31;
const FILE_LEN: usize = 16_384 * 40 + 77;

/// Starts a one-file transfer over the slow, lossy link and, once Bob has
/// stored 10 segments, closes that session (break before make).
async fn interrupted_on_the_slow_link(
    alice: &mut Device,
    bob: &mut Device,
    managers: (&TransportManager, &TransportManager),
    connector: &SimConnector,
) -> AnyResult<(Interrupted, todoke_transfer::TransferId)> {
    connector.answer(
        address(SLOW),
        Answer::Connect {
            setup: MS * 80,
            path: Path::new(MS * 40).with_bandwidth(2_000_000).with_loss(0.02),
        },
    );
    let slow = [Candidate::new(LinkKind::Simulated, address(SLOW))];
    let mut source = MemorySource::new();
    let outgoing = offer(alice, bob, FILE_LEN, &mut source)?;
    let transfer_id = *outgoing.transfer_id();
    let (mut at_alice, mut at_bob) =
        connect(alice, bob, managers.0, managers.1, connector, &slow).await?;
    let slow_info = *at_alice.link();
    let alice_engine = engine(&mut at_alice, alice, source, MemorySink::new(), "slow")?;
    let bob_engine = engine(
        &mut at_bob,
        bob,
        MemorySource::new(),
        MemorySink::new(),
        "slow",
    )?;
    let (sent, received) = {
        let mut sending = pin!(send(&mut at_alice, alice_engine, Some(outgoing)));
        let received = {
            let mut receiving = pin!(receive(&mut at_bob, bob_engine, Some(10)));
            tokio::select! {
                biased;
                received = receiving.as_mut() => received,
                _ = sending.as_mut() => return Err("the sender finished first".into()),
            }
        };
        // Bob closes the slow session; Alice sees the connection end.
        drop(at_bob);
        (sending.await, received)
    };
    assert!(received.1, "the transfer ended before the migration point");
    let Run {
        events,
        engine: mut alice_engine,
    } = sent;
    assert!(
        events
            .iter()
            .any(|event| matches!(event, TransferEvent::Interrupted { .. }))
    );
    let resumed = alice_engine
        .take_resumable()
        .pop()
        .ok_or("resumable offer")?;
    let (source, _) = alice_engine.into_parts();
    let (_, sink) = received.0.engine.into_parts();
    Ok((
        Interrupted {
            session: at_alice,
            resumed,
            source,
            sink,
            slow: slow_info,
        },
        transfer_id,
    ))
}

/// A transfer starts on a slow, lossy link; a link with a fraction of its
/// latency turns up; the session moves to it (break before make), the
/// receiver accepts the resumed transfer afresh, the segments already
/// delivered are not sent again, and the file arrives intact with a signed
/// receipt. The new session is the same authenticated mode: a link change
/// never changes authentication.
#[tokio::test(start_paused = true)]
async fn a_transfer_migrates_to_a_faster_link() -> TestResult {
    let (mut alice, mut bob) = paired().await?;
    let (alice_manager, bob_manager) = (alice.manager(), bob.manager());
    let connector = SimConnector::default();
    let (left, transfer_id) = Box::pin(interrupted_on_the_slow_link(
        &mut alice,
        &mut bob,
        (&alice_manager, &bob_manager),
        &connector,
    ))
    .await?;
    let retained = left.sink.stored_segments(&transfer_id);
    assert!(retained >= 10);
    // The faster link appears, and the policy says it is worth a new
    // session (and a new Accept).
    connector.answer(
        address(FAST),
        Answer::Connect {
            setup: MS * 2,
            path: Path::new(MS).with_bandwidth(100_000_000),
        },
    );
    let fast = [Candidate::new(LinkKind::Simulated, address(FAST))];
    // Probe it (a connection, no session) and compare measured latencies.
    let probe = crate::race::race(&connector, &fast, &crate::race::RaceConfig::default()).await?;
    let fast_info = *crate::link::Link::info(&probe);
    drop((probe, connector.accepted()));
    assert!(MigrationPolicy::default().should_migrate(&left.slow, &fast_info));
    assert!(!MigrationPolicy::default().should_migrate(&fast_info, &left.slow));
    // Break before make: the old session is closed and its slot reused.
    let claim = alice_manager.migrate(left.session)?;
    let (mut at_alice, mut at_bob) =
        connect_claimed(claim, &mut alice, &mut bob, &bob_manager, &connector, &fast).await?;
    assert_eq!(at_alice.link().remote(), Some(address(FAST)));
    assert_eq!(at_alice.session().mode(), SessionMode::Contact);
    let alice_engine = engine(
        &mut at_alice,
        &alice,
        left.source,
        MemorySink::new(),
        "fast",
    )?;
    let bob_engine = engine(&mut at_bob, &bob, MemorySource::new(), left.sink, "fast")?;
    let (sent, (received, _)) = tokio::join!(
        send(&mut at_alice, alice_engine, Some(left.resumed)),
        receive(&mut at_bob, bob_engine, None)
    );
    let view = received
        .events
        .iter()
        .find_map(|event| match event {
            TransferEvent::OfferReceived(view) => Some(view.clone()),
            _ => None,
        })
        .ok_or("the resumed offer was not shown for a new decision")?;
    assert!(view.resume_selection.is_some());
    assert!(
        sent.events
            .iter()
            .any(|event| matches!(event, TransferEvent::DeliveryConfirmed { .. }))
    );
    assert_eq!(
        received.engine.sink().published(&transfer_id, 1),
        Some(content(FILE_LEN, 9).as_slice())
    );
    // Progress names the link in use.
    assert!(
        received
            .events
            .iter()
            .any(|event| matches!(event, TransferEvent::Progress(p) if p.transport == "fast"))
    );
    // What the slow session delivered is not sent again: the fast link
    // carried less than the file (plus the session's own records).
    let (to_bob, _) = connector.carried(address(FAST));
    let whole = u64::try_from(FILE_LEN)?;
    let missing = whole - u64::try_from(retained)? * 16_384;
    assert!(to_bob > missing, "{to_bob} <= {missing}");
    assert!(
        to_bob < whole,
        "the fast link carried {to_bob} of {whole} bytes"
    );
    Ok(())
}

// --- R3: paths the tests above do not reach ------------------------------

/// The larger and the smaller of two paired devices.
async fn ordered() -> AnyResult<(Device, Device)> {
    let (alice, bob) = paired().await?;
    Ok(if alice.key() < bob.key() {
        (alice, bob)
    } else {
        (bob, alice)
    })
}

/// R3: on the larger device, an incoming attempt waits for its own
/// outgoing attempt to the same peer at most `SIMULTANEOUS_WAIT`, then is
/// refused; the wait is released, so the next incoming attempt may wait
/// again, and it takes the slot once the outgoing attempt is dropped.
#[tokio::test(start_paused = true)]
async fn an_incoming_attempt_waits_at_most_the_simultaneous_wait() -> TestResult {
    let (small, large) = ordered().await?;
    let manager = large.manager();
    let (small_table, large_table) = (small.table()?, large.table()?);
    let locator = small_table.locator(&large.key()).ok_or("locator")?;
    let own = manager.claim_outgoing(small.key())?;
    let (_held, link) = forged_link(locator, 70).await?;
    let Incoming::Contact(incoming) = manager.accept(link).await? else {
        return Err("expected a contact Hello".into());
    };
    assert!(!format!("{incoming:?}").contains("192.168"));
    let started = tokio::time::Instant::now();
    assert!(matches!(
        incoming.claim(&large_table, wall()?).await,
        Err(ConnectError::Busy)
    ));
    assert_eq!(started.elapsed(), crate::manager::SIMULTANEOUS_WAIT);
    // The next one waits again (the first wait was released) and gets the
    // slot when the outgoing attempt ends.
    let (_held, link) = forged_link(locator, 71).await?;
    let Incoming::Contact(incoming) = manager.accept(link).await? else {
        return Err("expected a contact Hello".into());
    };
    let mut claim = pin!(incoming.claim(&large_table, wall()?));
    assert!(start(claim.as_mut()).await.is_none(), "it did not wait");
    tokio::time::sleep(Duration::from_secs(3)).await;
    drop(own);
    let claimed = claim.await?;
    assert!(!format!("{claimed:?}").contains("192.168"));
    assert!(manager.is_busy(&small.key()));
    drop(claimed);
    assert!(!manager.is_busy(&small.key()));
    Ok(())
}

/// R3: pairing Hellos and code offer requests are handed to the pairing
/// flow, not resolved as contacts.
#[tokio::test(start_paused = true)]
async fn pairing_streams_go_to_the_pairing_flow() -> TestResult {
    let bob = Device::new(0x42)?;
    let manager = bob.manager();
    let hello = Hello::client(SessionMode::Qr, 0, [0x77; 16], [0x5e; 16])?;
    let (mut near, far) = crate::sim::link(Path::new(MS), address(80), address(99), 80);
    write_all(
        &mut near,
        &encode_prelude_record(PreludeKind::ClientHello, &hello.encode())?,
    )
    .await?;
    let accepted = manager.accept(far).await?;
    assert!(matches!(accepted, Incoming::Pairing(_)));
    assert_eq!(format!("{accepted:?}"), "Incoming::Pairing");
    let request = todoke_proto::pairing::CodeOfferRequest::new([7; 8])?;
    let (mut near, far) = crate::sim::link(Path::new(MS), address(81), address(99), 81);
    write_all(
        &mut near,
        &encode_prelude_record(PreludeKind::CodeOfferRequest, &request.encode())?,
    )
    .await?;
    let accepted = manager.accept(far).await?;
    assert!(matches!(accepted, Incoming::CodeOfferRequest(_)));
    assert_eq!(format!("{accepted:?}"), "Incoming::CodeOfferRequest");
    let (mut near, far) = crate::sim::link(Path::new(MS), address(82), address(99), 82);
    write_all(&mut near, &forged_hello([0x42; 16])?).await?;
    let accepted = manager.accept(far).await?;
    assert_eq!(format!("{accepted:?}"), "Incoming::Contact");
    Ok(())
}

/// R3: a table that went stale between the claim and the handshake is
/// refused on both sides before anything is sent, a peer missing from the
/// table is unknown, and a contact that became unavailable after its table
/// was built is refused by the store; every refusal frees the slot.
#[tokio::test(start_paused = true)]
async fn tables_are_checked_again_at_the_handshake() -> TestResult {
    let (mut alice, mut bob) = paired().await?;
    let (alice_manager, bob_manager) = (alice.manager(), bob.manager());
    let (alice_table, bob_table) = (alice.table()?, bob.table()?);
    let later = time(WALL + todoke_proto::discovery::EPOCH_SECONDS)?;
    // Responder: claimed in one epoch, responding in the next.
    let locator = alice_table.locator(&bob.key()).ok_or("locator")?;
    let (_held, link) = forged_link(locator, 90).await?;
    let Incoming::Contact(incoming) = bob_manager.accept(link).await? else {
        return Err("expected a contact Hello".into());
    };
    let claimed = incoming.claim(&bob_table, wall()?).await?;
    let (bob_local, bob_store) = bob.parts()?;
    assert!(matches!(
        claimed
            .respond(&bob_table, bob_store, &bob_local, later)
            .await,
        Err(ConnectError::StaleTable)
    ));
    assert!(!bob_manager.is_busy(&alice.key()));
    // Initiator: a link the caller opened, then a stale table.
    let (near, mut far) = crate::sim::link(Path::new(MS), address(91), address(92), 91);
    let connected = alice_manager.claim_outgoing(bob.key())?.with_link(near);
    assert_eq!(connected.link().kind(), LinkKind::Simulated);
    assert_eq!(connected.link().remote(), Some(address(92)));
    assert!(!format!("{connected:?}").contains("192.168"));
    let (alice_local, alice_store) = alice.parts()?;
    assert!(matches!(
        connected
            .initiate(&alice_table, alice_store, &alice_local, later)
            .await,
        Err(ConnectError::StaleTable)
    ));
    let mut byte = [0];
    let read = core::future::poll_fn(|cx| Pin::new(&mut far).poll_read(cx, &mut byte)).await?;
    assert_eq!(read, 0, "nothing may be sent with a stale table");
    assert!(!alice_manager.is_busy(&bob.key()));
    // The contact became unavailable after the table was built.
    alice.store.mark_ratchet_uncertain(&bob.key())?;
    let (near, _far) = crate::sim::link(Path::new(MS), address(93), address(94), 93);
    let connected = alice_manager.claim_outgoing(bob.key())?.with_link(near);
    let (alice_local, alice_store) = alice.parts()?;
    let refused = connected
        .initiate(&alice_table, alice_store, &alice_local, wall()?)
        .await;
    assert!(
        matches!(refused, Err(ConnectError::Session(_))),
        "{refused:?}"
    );
    // A table built since then no longer has the peer.
    let current = alice.table()?;
    let (near, _far) = crate::sim::link(Path::new(MS), address(95), address(96), 95);
    let connected = alice_manager.claim_outgoing(bob.key())?.with_link(near);
    let (alice_local, alice_store) = alice.parts()?;
    assert!(matches!(
        connected
            .initiate(&current, alice_store, &alice_local, wall()?)
            .await,
        Err(ConnectError::UnknownPeer)
    ));
    assert!(!alice_manager.is_busy(&bob.key()));
    Ok(())
}

/// R3: a responder handshake that fails (the initiator went away after its
/// Hello) frees the slot and the source's attempt, and leaves the pairing
/// usable.
#[tokio::test(start_paused = true)]
async fn a_failed_responder_handshake_frees_everything() -> TestResult {
    let (alice, mut bob) = paired().await?;
    let bob_manager = bob.manager();
    let (alice_table, bob_table) = (alice.table()?, bob.table()?);
    let locator = alice_table.locator(&bob.key()).ok_or("locator")?;
    let (held, link) = forged_link(locator, 100).await?;
    let Incoming::Contact(incoming) = bob_manager.accept(link).await? else {
        return Err("expected a contact Hello".into());
    };
    let claimed = incoming.claim(&bob_table, wall()?).await?;
    drop(held);
    let (bob_local, bob_store) = bob.parts()?;
    let failed = claimed
        .respond(&bob_table, bob_store, &bob_local, wall()?)
        .await;
    assert!(
        matches!(failed, Err(ConnectError::Session(_))),
        "{failed:?}"
    );
    assert!(!bob_manager.is_busy(&alice.key()));
    assert!(matches!(bob.store.availability(&alice.key()), Ok(Ok(_))));
    // The source's two attempts are both free again, and only two.
    let mut kept = Vec::new();
    for _ in 0..2 {
        let (held, link) = forged_link(locator, 100).await?;
        kept.push((held, bob_manager.accept(link).await?));
    }
    let (_held, link) = forged_link(locator, 100).await?;
    assert!(matches!(
        bob_manager.accept(link).await,
        Err(ConnectError::SourceBusy)
    ));
    drop(kept);
    Ok(())
}

/// R3: when no link opens, the attempt ends with the race's error and
/// frees its slot; `with_race` sets the race's timing.
#[tokio::test(start_paused = true)]
async fn failed_races_free_the_slot() -> TestResult {
    let (alice, bob) = paired().await?;
    let config = crate::race::RaceConfig {
        deadline: Duration::from_secs(1),
        ..crate::race::RaceConfig::default()
    };
    let manager = alice.manager().with_race(config);
    let connector = SimConnector::default();
    let none = manager
        .claim_outgoing(bob.key())?
        .connect(&connector, &[])
        .await;
    assert!(matches!(
        none,
        Err(ConnectError::Race(crate::race::RaceError::NoCandidates))
    ));
    assert!(!manager.is_busy(&bob.key()));
    let started = tokio::time::Instant::now();
    let silent = manager
        .claim_outgoing(bob.key())?
        .connect(
            &connector,
            &[Candidate::new(LinkKind::Simulated, address(9))],
        )
        .await;
    assert!(matches!(
        silent,
        Err(ConnectError::Race(crate::race::RaceError::Timeout))
    ));
    assert_eq!(started.elapsed(), Duration::from_secs(1));
    assert!(!manager.is_busy(&bob.key()));
    Ok(())
}

/// R3: an established session's debug output names no address.
#[tokio::test(start_paused = true)]
async fn established_sessions_hide_their_addresses() -> TestResult {
    let (mut alice, mut bob) = paired().await?;
    let (alice_manager, bob_manager) = (alice.manager(), bob.manager());
    let connector = SimConnector::default();
    connector.answer(address(11), fast());
    let candidates = [Candidate::new(LinkKind::Simulated, address(11))];
    let (at_alice, at_bob) = connect(
        &mut alice,
        &mut bob,
        &alice_manager,
        &bob_manager,
        &connector,
        &candidates,
    )
    .await?;
    let shown = format!("{at_alice:?} {at_bob:?}");
    assert!(!shown.contains("192.168"), "{shown}");
    Ok(())
}

/// R3: the manager keeps one clock from its creation; a fresh timer starts
/// at zero; a deadline too far to represent never fires.
#[tokio::test(start_paused = true)]
async fn the_manager_keeps_one_clock() -> TestResult {
    let bob = Device::new(0x42)?;
    let manager = bob.manager();
    tokio::time::sleep(Duration::from_secs(10)).await;
    assert_eq!(timer_now(&manager.timer()), Duration::from_secs(10));
    assert_eq!(timer_now(&TokioTimer::default()), Duration::ZERO);
    let timer = TokioTimer::new();
    let never = todoke_crypto::session::Timer::sleep_until(&timer, Duration::MAX);
    let three_years = Duration::from_hours(3 * 365 * 24);
    assert!(tokio::time::timeout(three_years, never).await.is_err());
    let soon = todoke_crypto::session::Timer::sleep_until(&timer, Duration::from_secs(5));
    let started = tokio::time::Instant::now();
    soon.await;
    assert_eq!(started.elapsed(), Duration::ZERO, "the deadline had passed");
    Ok(())
}

/// R3: what is known about a link, and only its kind and metrics in debug
/// output.
#[test]
fn link_information_is_kept_and_addresses_are_not_shown() {
    let (local, remote) = (address(1), address(2));
    let info = LinkInfo::new(LinkKind::Lan)
        .with_addresses(local, remote)
        .with_latency(MS * 3)
        .with_bandwidth(12_345);
    assert_eq!(info.local(), Some(local));
    assert_eq!(info.remote(), Some(remote));
    assert_eq!(info.latency(), Some(MS * 3));
    assert_eq!(info.bandwidth(), Some(12_345));
    let bare = LinkInfo::new(LinkKind::Lan);
    assert_eq!((bare.local(), bare.bandwidth()), (None, None));
    let shown = format!("{info:?}");
    assert!(!shown.contains("192.168"), "{shown}");
    assert!(shown.contains("12345"), "{shown}");
}

/// R3: the responder's store decides after the claim: a Hello for another
/// pair generation is refused locally (§4.4), and so is a contact that
/// became unavailable after the table was built; both free the slot.
#[tokio::test(start_paused = true)]
async fn the_responder_store_decides_after_the_claim() -> TestResult {
    let (alice, mut bob) = paired().await?;
    let bob_manager = bob.manager();
    let (alice_table, bob_table) = (alice.table()?, bob.table()?);
    let locator = alice_table.locator(&bob.key()).ok_or("locator")?;
    let hello = Hello::client(SessionMode::Contact, 99, locator, [0x5e; 16])?;
    let (mut near, far) = crate::sim::link(Path::new(MS), address(110), address(99), 110);
    write_all(
        &mut near,
        &encode_prelude_record(PreludeKind::ClientHello, &hello.encode())?,
    )
    .await?;
    let Incoming::Contact(incoming) = bob_manager.accept(far).await? else {
        return Err("expected a contact Hello".into());
    };
    let claimed = incoming.claim(&bob_table, wall()?).await?;
    let (bob_local, bob_store) = bob.parts()?;
    let refused = claimed
        .respond(&bob_table, bob_store, &bob_local, wall()?)
        .await;
    assert!(
        matches!(
            refused,
            Err(ConnectError::Session(SessionError::GenerationMismatch))
        ),
        "{refused:?}"
    );
    assert!(!bob_manager.is_busy(&alice.key()));
    let (_held, link) = forged_link(locator, 111).await?;
    let Incoming::Contact(incoming) = bob_manager.accept(link).await? else {
        return Err("expected a contact Hello".into());
    };
    let claimed = incoming.claim(&bob_table, wall()?).await?;
    bob.store.mark_ratchet_uncertain(&alice.key())?;
    let (bob_local, bob_store) = bob.parts()?;
    let refused = claimed
        .respond(&bob_table, bob_store, &bob_local, wall()?)
        .await;
    assert!(
        matches!(refused, Err(ConnectError::Session(_))),
        "{refused:?}"
    );
    assert!(!bob_manager.is_busy(&alice.key()));
    Ok(())
}
