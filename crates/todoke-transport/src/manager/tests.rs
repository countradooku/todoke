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

#[test]
fn one_attempt_or_session_per_device_pair() -> TestResult {
    let (local, peer) = two_keys()?;
    let manager = manager(local);
    let first = manager.claim(peer, Direction::Outgoing)?;
    assert!(manager.is_busy(&peer));
    assert!(matches!(
        manager.claim(peer, Direction::Outgoing),
        Err(ConnectError::Busy)
    ));
    first.activate()?;
    // An established session blocks both directions.
    assert!(matches!(
        manager.claim(peer, Direction::Incoming),
        Err(ConnectError::Busy)
    ));
    drop(first);
    assert!(!manager.is_busy(&peer));
    let incoming = manager.claim(peer, Direction::Incoming)?;
    assert!(matches!(
        manager.claim(peer, Direction::Outgoing),
        Err(ConnectError::Busy)
    ));
    assert!(matches!(
        manager.claim(peer, Direction::Incoming),
        Err(ConnectError::Busy)
    ));
    drop(incoming);
    assert!(!manager.is_busy(&peer));
    Ok(())
}

/// §4: the smaller key keeps its outgoing attempt, the larger its incoming.
#[test]
fn simultaneous_attempts_follow_the_key_order() -> TestResult {
    let (small, large) = two_keys()?;
    // The smaller device refuses the larger's incoming attempt.
    let at_small = manager(small);
    let outgoing = at_small.claim(large, Direction::Outgoing)?;
    assert!(matches!(
        at_small.claim(large, Direction::Incoming),
        Err(ConnectError::Busy)
    ));
    outgoing.activate()?;
    // The larger device takes the smaller's incoming attempt over its own
    // outgoing one, which can then never become the session.
    let at_large = manager(large);
    let own = at_large.claim(small, Direction::Outgoing)?;
    let theirs = at_large.claim(small, Direction::Incoming)?;
    assert!(matches!(own.activate(), Err(ConnectError::Superseded)));
    theirs.activate()?;
    // The superseded attempt ending does not free the winner's slot.
    drop(own);
    assert!(at_large.is_busy(&small));
    assert!(matches!(
        at_large.claim(small, Direction::Incoming),
        Err(ConnectError::Busy)
    ));
    drop(theirs);
    assert!(!at_large.is_busy(&small));
    assert_eq!(lock(&at_large.slots).superseded.len(), 0);
    Ok(())
}

/// Once the larger device's outgoing session is established, a late
/// incoming attempt is refused like any other.
#[test]
fn an_established_session_is_never_superseded() -> TestResult {
    let (small, large) = two_keys()?;
    let at_large = manager(large);
    let own = at_large.claim(small, Direction::Outgoing)?;
    own.activate()?;
    assert!(matches!(
        at_large.claim(small, Direction::Incoming),
        Err(ConnectError::Busy)
    ));
    own.activate()?;
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
