use core::time::Duration;

use todoke_crypto::identity::{
    ExportPolicy, KeyRole, MemoryStorage, SoftwareKeyStore, SoftwareSealer, StorageKey,
};
use zeroize::Zeroizing;

use super::*;
use crate::link::LinkKind;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const GATE: UnauditedSuite0001 = UnauditedSuite0001::acknowledge_not_production_ready();

/// Two distinct valid device keys, the smaller first.
fn two_keys() -> Result<(Ed25519PublicKey, Ed25519PublicKey), Box<dyn std::error::Error>> {
    let sealer = SoftwareSealer::new(StorageKey::from_bytes(Zeroizing::new([3; 32])));
    let mut keys = SoftwareKeyStore::open(sealer, MemoryStorage::new())?;
    let a = keys.generate(KeyRole::Device, ExportPolicy::NonExportable)?;
    let b = keys.generate(KeyRole::Device, ExportPolicy::NonExportable)?;
    let (a, b) = (keys.public_key(&a)?, keys.public_key(&b)?);
    Ok(if a < b { (a, b) } else { (b, a) })
}

fn manager(local: Ed25519PublicKey) -> TransportManager {
    TransportManager::new(GATE, local, PairingOffers::new())
}

fn taken(claim: Result<Claim, ConnectError>) -> Result<SlotGuard, Box<dyn std::error::Error>> {
    match claim? {
        Claim::Taken(slot) => Ok(slot),
        Claim::Wait(_) => Err("expected the slot, got a wait".into()),
    }
}

fn busy(claim: &Result<Claim, ConnectError>) -> bool {
    matches!(claim, Err(ConnectError::Busy))
}

#[test]
fn one_attempt_or_session_per_device_pair() -> TestResult {
    let (local, peer) = two_keys()?;
    let manager = manager(local);
    let first = taken(manager.claim(peer, Direction::Outgoing))?;
    assert!(manager.is_busy(&peer));
    assert!(busy(&manager.claim(peer, Direction::Outgoing)));
    first.activate()?;
    // An established session blocks both directions.
    assert!(busy(&manager.claim(peer, Direction::Incoming)));
    drop(first);
    assert!(!manager.is_busy(&peer));
    let incoming = taken(manager.claim(peer, Direction::Incoming))?;
    assert!(busy(&manager.claim(peer, Direction::Outgoing)));
    assert!(busy(&manager.claim(peer, Direction::Incoming)));
    drop(incoming);
    assert!(!manager.is_busy(&peer));
    Ok(())
}

/// §4: the smaller key keeps its outgoing attempt; the larger keeps its
/// incoming one, but only after its own outgoing attempt has failed: an
/// incoming Hello (unauthenticated) never displaces anything.
#[test]
fn simultaneous_attempts_follow_the_key_order_without_displacement() -> TestResult {
    let (small, large) = two_keys()?;
    // The smaller device refuses the larger's incoming attempt.
    let at_small = manager(small);
    let outgoing = taken(at_small.claim(large, Direction::Outgoing))?;
    assert!(busy(&at_small.claim(large, Direction::Incoming)));
    outgoing.activate()?;
    // The larger device: the incoming attempt waits; only one may.
    let at_large = manager(large);
    let own = taken(at_large.claim(small, Direction::Outgoing))?;
    let Claim::Wait(id) = at_large.claim(small, Direction::Incoming)? else {
        return Err("the incoming attempt must wait".into());
    };
    assert_eq!(id, own.id);
    assert!(busy(&at_large.claim(small, Direction::Incoming)));
    // Its own attempt failed: the incoming one now gets the slot.
    at_large.stop_waiting(&small, id);
    drop(own);
    let theirs = taken(at_large.claim(small, Direction::Incoming))?;
    theirs.activate()?;
    drop(theirs);
    // Its own attempt succeeded: the waiting incoming one is refused.
    let own = taken(at_large.claim(small, Direction::Outgoing))?;
    assert!(matches!(
        at_large.claim(small, Direction::Incoming)?,
        Claim::Wait(_)
    ));
    own.activate()?;
    assert!(busy(&at_large.claim(small, Direction::Incoming)));
    assert!(at_large.is_busy(&small));
    Ok(())
}

/// A stale guard (an outgoing attempt that lost its slot) cannot activate
/// another attempt's slot, and dropping it frees nothing that is not its.
#[test]
fn guards_only_touch_their_own_slot() -> TestResult {
    let (local, peer) = two_keys()?;
    let manager = manager(local);
    let first = taken(manager.claim(peer, Direction::Outgoing))?;
    let stale = SlotGuard {
        state: Arc::clone(&manager.state),
        peer,
        id: first.id.wrapping_add(100),
    };
    assert!(matches!(stale.activate(), Err(ConnectError::Busy)));
    drop(stale);
    assert!(manager.is_busy(&peer));
    drop(first);
    assert!(!manager.is_busy(&peer));
    Ok(())
}

/// At most two unauthenticated attempts from one source address; others
/// are counted separately; dropping a guard frees its place.
#[test]
fn attempts_per_source_are_bounded() -> TestResult {
    let (local, _) = two_keys()?;
    let manager = manager(local);
    let host: IpAddr = "192.168.1.9".parse()?;
    let other: IpAddr = "192.168.1.10".parse()?;
    let first = manager.source(Some(host))?;
    let second = manager.source(Some(host))?;
    assert!(matches!(
        manager.source(Some(host)),
        Err(ConnectError::SourceBusy)
    ));
    let elsewhere = manager.source(Some(other))?;
    drop(first);
    let third = manager.source(Some(host))?;
    drop((second, third, elsewhere));
    assert_eq!(lock(&manager.state).sources.len(), 0);
    // A link without an address is not counted.
    let _unknown = manager.source(None)?;
    assert_eq!(lock(&manager.state).sources.len(), 0);
    Ok(())
}

#[test]
fn debug_output_names_no_device() -> TestResult {
    let (local, peer) = two_keys()?;
    let manager = manager(local);
    let slot = taken(manager.claim(peer, Direction::Outgoing))?;
    let shown = format!("{manager:?} {slot:?} {:?}", lock(&manager.state));
    assert!(!shown.contains(&format!("{peer:?}")), "{shown}");
    Ok(())
}

#[test]
fn migration_needs_a_clearly_better_link() {
    let policy = MigrationPolicy::default();
    let lan = |ms: u64| LinkInfo::new(LinkKind::Lan).with_latency(Duration::from_millis(ms));
    assert!(policy.should_migrate(&lan(40), &lan(10)));
    assert!(policy.should_migrate(&lan(40), &lan(1)));
    assert!(!policy.should_migrate(&lan(40), &lan(11)));
    assert!(!policy.should_migrate(&lan(10), &lan(40)));
    // Unknown metrics never justify a new session and a new Accept.
    assert!(!policy.should_migrate(&LinkInfo::new(LinkKind::Lan), &lan(1)));
    assert!(!policy.should_migrate(&lan(40), &LinkInfo::new(LinkKind::Lan)));
    // A ratio below 2 is treated as 2.
    let eager = MigrationPolicy { latency_ratio: 0 };
    assert!(!eager.should_migrate(&lan(10), &lan(9)));
    assert!(eager.should_migrate(&lan(10), &lan(5)));
}
