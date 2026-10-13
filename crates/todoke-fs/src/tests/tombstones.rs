//! A proptest state machine over the tombstone list against a model:
//! cancels (an earlier deadline never shortens a later one), lapsing at
//! the deadline's end, writes that fail and are retried, the refusal of
//! new transfers while the list on disk is behind, the tombstone bound,
//! and restarts that read back only what reached the disk.

use std::collections::BTreeMap;

use proptest::prelude::*;
use todoke_crypto::consent::CanonicalManifest;
use todoke_transfer::{ReceiveSink, SinkRefusal};

use super::sink::{Harness, entries};
use super::support::*;
use super::*;
use crate::SinkConfig;
use crate::quarantine::codec::decode_tombstones;

/// The most unexpired tombstones before no new transfer is taken.
const LIMIT: usize = 2;

#[derive(Clone, Debug)]
enum Op {
    /// Cancel transfer `id` until `WALL + until`.
    Tombstone { id: u8, until: u64 },
    /// Make every write of the list fail (or succeed again).
    Block(bool),
    /// Sweep at `WALL + now`.
    Sweep { now: u64 },
    /// Ask for room at `WALL + now`.
    Room { now: u64 },
    /// An offer, which retries a pending write first.
    Offer,
    /// Drop the sink and open a new one.
    Reopen,
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        5 => (0_u8..4, 0_u64..8).prop_map(|(id, until)| Op::Tombstone { id, until }),
        2 => any::<bool>().prop_map(Op::Block),
        2 => (0_u64..10).prop_map(|now| Op::Sweep { now }),
        2 => (0_u64..10).prop_map(|now| Op::Room { now }),
        1 => Just(Op::Offer),
        1 => Just(Op::Reopen),
    ]
}

#[derive(Default)]
struct Model {
    /// The sink's list: transfer to deadline (seconds after `WALL`).
    memory: BTreeMap<u8, u64>,
    /// What the list on disk holds.
    disk: BTreeMap<u8, u64>,
    /// A write of the list failed and was not retried successfully.
    dirty: bool,
    blocked: bool,
}

impl Model {
    fn save(&mut self) {
        if self.dirty && !self.blocked {
            self.disk = self.memory.clone();
            self.dirty = false;
        }
    }

    fn sweep(&mut self, now: u64) {
        let before = self.memory.len();
        self.memory.retain(|_, until| now <= *until);
        if before != self.memory.len() {
            self.dirty = true;
        }
        self.save();
    }
}

fn transfer_id(id: u8) -> [u8; 16] {
    [0xa0 + id; 16]
}

struct Run {
    harness: Harness,
    manifest: CanonicalManifest,
    model: Model,
}

impl Run {
    fn new() -> AnyResult<Self> {
        let fixture = fixture()?;
        let manifest = build_manifest(&fixture, [0xb0; 16], &entries(), 3600)?;
        let harness = Harness::with_config(SinkConfig {
            tombstone_limit: LIMIT,
            ..SinkConfig::default()
        })?;
        Ok(Self {
            harness,
            manifest,
            model: Model::default(),
        })
    }

    fn blocker(&self) -> std::path::PathBuf {
        self.harness.state.path().join("tombstones.tmp")
    }

    fn apply(&mut self, op: &Op) -> AnyResult<()> {
        match *op {
            Op::Tombstone { id, until } => {
                let deadline = until.max(self.model.memory.get(&id).copied().unwrap_or(0));
                self.model.memory.insert(id, deadline);
                self.model.dirty = true;
                self.model.save();
                self.harness
                    .sink()?
                    .tombstone(&transfer_id(id), time(WALL + until)?);
            }
            Op::Block(blocked) => {
                if blocked && !self.model.blocked {
                    std::fs::create_dir(self.blocker())?;
                } else if !blocked && self.model.blocked {
                    std::fs::remove_dir(self.blocker())?;
                }
                self.model.blocked = blocked;
            }
            Op::Sweep { now } => {
                self.model.sweep(now);
                self.harness.sink()?.sweep(time(WALL + now)?);
            }
            Op::Room { now } => {
                self.model.sweep(now);
                let expected = !self.model.dirty && self.model.memory.len() < LIMIT;
                let room = self.harness.sink()?.tombstone_room(time(WALL + now)?);
                assert_eq!(room, expected, "room");
            }
            Op::Offer => {
                self.model.save();
                let offered = self.harness.sink()?.check_offer(&self.manifest);
                if self.model.dirty {
                    assert_eq!(offered, Err(SinkRefusal::UnsupportedDestination));
                } else {
                    assert_eq!(offered, Ok(()));
                }
            }
            Op::Reopen => {
                // A restart (or a crash) keeps only what reached the disk.
                self.model.memory = self.model.disk.clone();
                self.model.dirty = false;
                self.harness.reopen(WALL)?;
            }
        }
        Ok(())
    }

    fn check(&mut self) -> AnyResult<()> {
        let sink = self.harness.sink()?;
        assert_eq!(sink.tombstones_durable(), !self.model.dirty, "durable");
        for id in 0..4 {
            for now in 0..10 {
                let expected = self
                    .model
                    .memory
                    .get(&id)
                    .is_some_and(|until| now <= *until);
                assert_eq!(
                    sink.is_tombstoned(&transfer_id(id), time(WALL + now)?),
                    expected,
                    "transfer {id} at {now}"
                );
            }
        }
        let path = self.harness.state.path().join("tombstones");
        let on_disk: BTreeMap<u8, u64> = match std::fs::read(&path) {
            Ok(bytes) => decode_tombstones(&bytes)
                .map_err(|_| "damaged list")?
                .into_iter()
                .map(|(id, until)| (id[0] - 0xa0, until - WALL))
                .collect(),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => BTreeMap::new(),
            Err(error) => return Err(error.into()),
        };
        assert_eq!(on_disk, self.model.disk, "list on disk");
        Ok(())
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn tombstones_follow_the_model(ops in proptest::collection::vec(op(), 1..40)) {
        let mut run = Run::new().map_err(|e| TestCaseError::fail(e.to_string()))?;
        for op in &ops {
            run.apply(op).map_err(|e| TestCaseError::fail(format!("{op:?}: {e}")))?;
            run.check().map_err(|e| TestCaseError::fail(format!("after {op:?}: {e}")))?;
        }
    }
}
