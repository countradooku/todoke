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

#[test]
fn errors_have_distinct_messages() {
    let errors = [
        ConnectError::Busy,
        ConnectError::UnknownPeer,
        ConnectError::StaleTable,
        ConnectError::SourceBusy,
        ConnectError::Race(RaceError::NoCandidates),
        ConnectError::Session(SessionError::Timeout),
    ];
    let messages: Vec<String> = errors.iter().map(ToString::to_string).collect();
    for (index, message) in messages.iter().enumerate() {
        assert_ne!(message, "");
        assert!(!messages[..index].contains(message), "{message}");
    }
    assert_eq!(
        ConnectError::from(RaceError::Timeout).to_string(),
        RaceError::Timeout.to_string()
    );
    assert!(
        ConnectError::from(SessionError::Timeout)
            .to_string()
            .contains(&SessionError::Timeout.to_string())
    );
}

mod model {
    //! R3: a model-based test of the slot table.

    use std::sync::OnceLock;

    use proptest::prelude::*;

    use super::*;

    /// Device keys in increasing order; the local device is the middle one,
    /// so peers sit on both sides of it in the §4 key order.
    fn keys() -> Result<&'static [Ed25519PublicKey], TestCaseError> {
        static KEYS: OnceLock<Result<Vec<Ed25519PublicKey>, String>> = OnceLock::new();
        KEYS.get_or_init(|| {
            let sealer = SoftwareSealer::new(StorageKey::from_bytes(Zeroizing::new([4; 32])));
            let mut store = SoftwareKeyStore::open(sealer, MemoryStorage::new())
                .map_err(|error| error.to_string())?;
            let mut keys = Vec::new();
            for _ in 0..5 {
                let id = store
                    .generate(KeyRole::Device, ExportPolicy::NonExportable)
                    .map_err(|error| error.to_string())?;
                keys.push(store.public_key(&id).map_err(|error| error.to_string())?);
            }
            keys.sort();
            Ok(keys)
        })
        .as_deref()
        .map_err(|error| TestCaseError::fail(error.clone()))
    }

    const LOCAL: usize = 2;

    #[derive(Clone, Debug)]
    enum Op {
        Claim {
            peer: usize,
            incoming: bool,
        },
        /// Activates guard `index` (modulo the guards held).
        Activate(usize),
        /// Drops guard `index`.
        Drop(usize),
        /// Ends wait `index` (modulo the waits returned so far).
        StopWaiting(usize),
        /// A guard for `peer` with an ID no claim ever returned, as a guard
        /// that lost its slot would hold.
        Stale {
            peer: usize,
            offset: u64,
        },
    }

    fn op() -> impl Strategy<Value = Op> {
        // Peers are every key but the local one.
        let peer = prop_oneof![0_usize..LOCAL, LOCAL + 1..5];
        prop_oneof![
            6 => (peer.clone(), any::<bool>()).prop_map(|(peer, incoming)| Op::Claim { peer, incoming }),
            2 => any::<usize>().prop_map(Op::Activate),
            3 => any::<usize>().prop_map(Op::Drop),
            2 => any::<usize>().prop_map(Op::StopWaiting),
            1 => (peer, 0_u64..4).prop_map(|(peer, offset)| Op::Stale { peer, offset }),
        ]
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    struct ModelSlot {
        id: u64,
        direction: Direction,
        active: bool,
        waiter: bool,
    }

    /// The §4 rules and the module notes, written plainly.
    #[derive(Default)]
    struct Model {
        slots: BTreeMap<usize, ModelSlot>,
        next_id: u64,
    }

    #[derive(Debug, PartialEq, Eq)]
    enum Outcome {
        Taken(u64),
        Wait(u64),
        Busy,
    }

    impl Model {
        fn claim(&mut self, peer: usize, direction: Direction) -> Outcome {
            if let Some(slot) = self.slots.get_mut(&peer) {
                // Only an incoming attempt on the larger-key device may
                // wait, once, for an outgoing attempt still under way.
                if direction == Direction::Incoming
                    && slot.direction == Direction::Outgoing
                    && !slot.active
                    && !slot.waiter
                    && LOCAL > peer
                {
                    slot.waiter = true;
                    return Outcome::Wait(slot.id);
                }
                return Outcome::Busy;
            }
            let id = self.next_id;
            self.next_id += 1;
            self.slots.insert(
                peer,
                ModelSlot {
                    id,
                    direction,
                    active: false,
                    waiter: false,
                },
            );
            Outcome::Taken(id)
        }

        fn owns(&self, peer: usize, id: u64) -> bool {
            self.slots.get(&peer).is_some_and(|slot| slot.id == id)
        }
    }

    fn fail(error: impl core::fmt::Display) -> TestCaseError {
        TestCaseError::fail(error.to_string())
    }

    proptest! {
        /// R3: the slot table against a plain model. Claims in both
        /// directions for peers on both sides of the local key, activation,
        /// guards dropped in any order, waits ended, and guards that do not
        /// own their peer's slot: at most one slot per peer, a waiting
        /// claim never displaces the slot it waits for, only an incoming
        /// claim on the larger-key device waits (and only one at a time),
        /// and a guard frees or activates only its own slot.
        #[test]
        fn the_slot_table_follows_its_model(ops in proptest::collection::vec(op(), 1..80)) {
            let keys = keys()?;
            let local = *keys.get(LOCAL).ok_or_else(|| fail("key"))?;
            let manager = manager(local);
            let mut model = Model::default();
            // Live guards with the peer index they were claimed for.
            let mut guards: Vec<(usize, SlotGuard)> = Vec::new();
            let mut waits: Vec<(usize, u64)> = Vec::new();
            for op in ops {
                match op {
                    Op::Claim { peer, incoming } => {
                        let direction = if incoming { Direction::Incoming } else { Direction::Outgoing };
                        let key = *keys.get(peer).ok_or_else(|| fail("key"))?;
                        let before = model.slots.get(&peer).copied();
                        let expected = model.claim(peer, direction);
                        let outcome = match manager.claim(key, direction) {
                            Ok(Claim::Taken(guard)) => {
                                let id = guard.id;
                                guards.push((peer, guard));
                                Outcome::Taken(id)
                            }
                            Ok(Claim::Wait(id)) => {
                                waits.push((peer, id));
                                Outcome::Wait(id)
                            }
                            Err(ConnectError::Busy) => Outcome::Busy,
                            Err(error) => return Err(fail(error)),
                        };
                        prop_assert_eq!(&outcome, &expected);
                        // Independently of the model: a claim on an existing
                        // slot never replaces it, and only the larger-key
                        // device's incoming claim waits.
                        if let Some(before) = before {
                            prop_assert!(!matches!(outcome, Outcome::Taken(_)));
                            prop_assert_eq!(model.slots.get(&peer).map(|s| s.id), Some(before.id));
                        }
                        if matches!(outcome, Outcome::Wait(_)) {
                            prop_assert!(incoming && local > key);
                        }
                    }
                    Op::Activate(index) => {
                        if guards.is_empty() {
                            continue;
                        }
                        let (peer, guard) = &guards[index % guards.len()];
                        let owns = model.owns(*peer, guard.id);
                        prop_assert_eq!(guard.activate().is_ok(), owns);
                        if let Some(slot) = model.slots.get_mut(peer).filter(|_| owns) {
                            slot.active = true;
                        }
                    }
                    Op::Drop(index) => {
                        if guards.is_empty() {
                            continue;
                        }
                        let (peer, guard) = guards.swap_remove(index % guards.len());
                        if model.owns(peer, guard.id) {
                            model.slots.remove(&peer);
                        }
                        drop(guard);
                    }
                    Op::StopWaiting(index) => {
                        if waits.is_empty() {
                            continue;
                        }
                        let (peer, id) = waits[index % waits.len()];
                        manager.stop_waiting(keys.get(peer).ok_or_else(|| fail("key"))?, id);
                        if let Some(slot) = model.slots.get_mut(&peer).filter(|slot| slot.id == id) {
                            slot.waiter = false;
                        }
                    }
                    Op::Stale { peer, offset } => {
                        let guard = SlotGuard {
                            state: Arc::clone(&manager.state),
                            peer: *keys.get(peer).ok_or_else(|| fail("key"))?,
                            id: u64::MAX - offset,
                        };
                        guards.push((peer, guard));
                    }
                }
                // The table is the model's, peer by peer.
                let table: Vec<(Ed25519PublicKey, ModelSlot)> = lock(&manager.state)
                    .by_peer
                    .iter()
                    .map(|(key, slot)| {
                        (*key, ModelSlot {
                            id: slot.id,
                            direction: slot.direction,
                            active: slot.active,
                            waiter: slot.waiter,
                        })
                    })
                    .collect();
                let expected: Vec<(Ed25519PublicKey, ModelSlot)> = model
                    .slots
                    .iter()
                    .map(|(peer, slot)| Ok((*keys.get(*peer).ok_or_else(|| fail("key"))?, *slot)))
                    .collect::<Result<_, TestCaseError>>()?;
                prop_assert_eq!(table, expected);
                for (peer, key) in keys.iter().enumerate() {
                    prop_assert_eq!(manager.is_busy(key), model.slots.contains_key(&peer));
                    // At most one live guard owns a peer's slot.
                    let owners = guards
                        .iter()
                        .filter(|(p, guard)| *p == peer && model.owns(peer, guard.id))
                        .count();
                    prop_assert!(owners <= 1);
                }
            }
        }
    }
}
