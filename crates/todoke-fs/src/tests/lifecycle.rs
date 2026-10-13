//! A proptest state machine over the quarantine and publication
//! lifecycle: segments stored and dropped, keys (same or different
//! master), publication, restarts with torn journals, resumed sessions,
//! damaged ciphertext, names and links planted in the destination,
//! cancellation, and expiry, against a model.

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;

use proptest::prelude::*;
use todoke_transfer::{ReceiveSink, SinkError};

use super::sink::{Harness, files_below, read_at_rest};
use super::support::*;
use super::*;
use crate::{Durability, SinkConfig};

const SIZES: [(u32, usize); 3] = [(2, 40_000), (3, 0), (4, 20_000)];

fn entries() -> Vec<Entry> {
    vec![
        dir_entry("d", 0),
        file_entry("a.bin", 1, content(SIZES[0].1, 1)),
        file_entry("empty", 1, Vec::new()),
        file_entry("c.txt", 0, content(SIZES[2].1, 3)),
    ]
}

const SELECTION: [u32; 3] = [2, 3, 4];

#[derive(Clone, Debug)]
enum Op {
    /// Keys the file (honest master) and stores every segment.
    Receive(usize),
    Key(usize),
    KeyOther(usize),
    Store(usize, u32),
    Drop(usize, u32),
    Publish(usize),
    Restart {
        torn: bool,
    },
    Resume,
    Corrupt(usize, u32),
    Plant {
        top_file: bool,
        link: bool,
    },
    Tamper(usize),
    Cancel,
    Expire,
}

fn op() -> impl Strategy<Value = Op> {
    let file = 0_usize..3;
    let index = 0_u32..3;
    prop_oneof![
        8 => file.clone().prop_map(Op::Receive),
        3 => file.clone().prop_map(Op::Key),
        1 => file.clone().prop_map(Op::KeyOther),
        6 => (file.clone(), index.clone()).prop_map(|(f, i)| Op::Store(f, i)),
        1 => (file.clone(), index.clone()).prop_map(|(f, i)| Op::Drop(f, i)),
        10 => file.clone().prop_map(Op::Publish),
        3 => any::<bool>().prop_map(|torn| Op::Restart { torn }),
        3 => Just(Op::Resume),
        1 => (file.clone(), index).prop_map(|(f, i)| Op::Corrupt(f, i)),
        2 => (any::<bool>(), any::<bool>()).prop_map(|(top_file, link)| Op::Plant { top_file, link }),
        2 => file.prop_map(Op::Tamper),
        1 => Just(Op::Cancel),
        1 => Just(Op::Expire),
    ]
}

#[derive(Default)]
struct Model {
    /// Files whose sealed master is stored.
    sealed: BTreeSet<u32>,
    /// Files keyed in the current sink instance (consent in memory).
    keyed: BTreeSet<u32>,
    /// Which master each sealed file has: false for the honest one.
    other_master: BTreeSet<u32>,
    stored: BTreeSet<(u32, u32)>,
    corrupted: BTreeSet<(u32, u32)>,
    published: BTreeSet<u32>,
    tampered: BTreeSet<u32>,
    /// Destination files that are not ours, with their content.
    sentinels: BTreeMap<PathBuf, Vec<u8>>,
    gone: bool,
}

fn count(file_id: u32) -> u32 {
    let size = SIZES
        .iter()
        .find(|(id, _)| *id == file_id)
        .map_or(0, |(_, s)| *s);
    u32::try_from(size.div_ceil(16_384).max(1)).unwrap_or(1)
}

struct Run {
    harness: Harness,
    outside: TempDir,
    consents: Vec<Consented>,
    current: usize,
    other: Consented,
    model: Model,
}

impl Run {
    fn new() -> AnyResult<Self> {
        let fixture = fixture()?;
        let manifest = build_manifest(&fixture, [0x5a; 16], &entries(), 3600)?;
        let consents = vec![
            Consented::new(&fixture, &manifest, &entries(), &SELECTION, false, 0x11)?,
            Consented::new(&fixture, &manifest, &entries(), &SELECTION, true, 0x11)?,
        ];
        let other = Consented::new(&fixture, &manifest, &entries(), &SELECTION, true, 0x99)?;
        let harness = Harness::with_config(SinkConfig {
            durability: Durability::Periodic { bytes: 1 << 16 },
            ..SinkConfig::default()
        })?;
        let mut run = Self {
            harness,
            outside: TempDir::new()?,
            consents,
            current: 0,
            other,
            model: Model::default(),
        };
        let consented = &run.consents[0];
        let sink = run.harness.sink()?;
        sink.check_offer(&consented.manifest)
            .map_err(|r| format!("{r:?}"))?;
        sink.record_accept(&consented.manifest, &consented.accept)?;
        Ok(run)
    }

    fn consented(&self) -> &Consented {
        &self.consents[self.current]
    }

    fn apply(&mut self, op: &Op) -> AnyResult<()> {
        match *op {
            Op::Receive(file) => {
                self.key(file, false)?;
                for index in 0..count(SELECTION[file]) {
                    self.store(file, index)?;
                }
                Ok(())
            }
            Op::Key(file) => self.key(file, false),
            Op::KeyOther(file) => self.key(file, true),
            Op::Store(file, index) => self.store(file, index),
            Op::Drop(file, index) => {
                let file_id = SELECTION[file];
                if index < count(file_id) {
                    let transfer_id = *self.consented().manifest.transfer_id();
                    self.harness
                        .sink()?
                        .drop_segment(&transfer_id, file_id, index);
                    self.model.stored.remove(&(file_id, index));
                    self.model.corrupted.remove(&(file_id, index));
                }
                Ok(())
            }
            Op::Publish(file) => self.publish(file),
            Op::Restart { torn } => self.restart(torn),
            Op::Resume => self.resume(),
            Op::Corrupt(file, index) => self.corrupt(file, index),
            Op::Plant { top_file, link } => self.plant(top_file, link),
            Op::Tamper(file) => self.tamper(file),
            Op::Cancel => {
                let transfer_id = *self.consented().manifest.transfer_id();
                self.harness
                    .sink()?
                    .tombstone(&transfer_id, time(WALL + 7200)?);
                self.mark_gone();
                Ok(())
            }
            Op::Expire => {
                // The clock stays there: later operations see the expiry.
                self.harness.reopen(WALL + 3600)?;
                self.mark_gone();
                Ok(())
            }
        }
    }

    fn key(&mut self, file: usize, other: bool) -> AnyResult<()> {
        let file_id = SELECTION[file];
        let source = if other { &self.other } else { self.consented() };
        let accepted = self.consented().accept.file(file_id).ok_or("file")?;
        let master = source.master(file_id)?;
        let result = self.harness.sink()?.record_file_key(&accepted, &master);
        if self.model.gone {
            assert_eq!(result, Err(SinkError::Storage));
        } else if self.model.published.contains(&file_id) {
            // Requirement: a key for an already-published file (honest or
            // not) is refused and creates no sealed master. The engine
            // never sends one for a file it counts as published, and a
            // published file is never published again, so accepting it
            // would only keep a master at rest for nothing.
            assert_eq!(result, Err(SinkError::Storage));
        } else {
            result?;
            let changed = self.model.other_master.contains(&file_id) != other
                || !self.model.sealed.contains(&file_id);
            if changed && self.model.sealed.contains(&file_id) {
                self.model.stored.retain(|(f, _)| *f != file_id);
                self.model.corrupted.retain(|(f, _)| *f != file_id);
            }
            if changed && !self.model.sealed.contains(&file_id) {
                // A first key for this file: nothing retained yet
                // could have opened anyway.
                self.model.stored.retain(|(f, _)| *f != file_id);
                self.model.corrupted.retain(|(f, _)| *f != file_id);
            }
            self.model.sealed.insert(file_id);
            self.model.keyed.insert(file_id);
            if other {
                self.model.other_master.insert(file_id);
            } else {
                self.model.other_master.remove(&file_id);
            }
        }
        Ok(())
    }

    fn store(&mut self, file: usize, index: u32) -> AnyResult<()> {
        let file_id = SELECTION[file];
        if index >= count(file_id) || self.model.other_master.contains(&file_id) {
            return Ok(());
        }
        let ciphertext = self.consented().ciphertext(file_id, index)?;
        let segment = self.consented().verified(file_id, index, &ciphertext)?;
        let result = self.harness.sink()?.store_segment(&segment, &ciphertext);
        if self.model.gone || !self.model.sealed.contains(&file_id) {
            assert_eq!(result, Err(SinkError::Storage));
        } else {
            result?;
            self.model.stored.insert((file_id, index));
            self.model.corrupted.remove(&(file_id, index));
        }
        Ok(())
    }

    fn publish(&mut self, file: usize) -> AnyResult<()> {
        let manifest = self.consented().manifest.clone();
        let file_id = SELECTION[file];
        let result = self.harness.sink()?.publish(&manifest, file_id);
        let model = &self.model;
        let complete = (0..count(file_id)).all(|i| {
            model.stored.contains(&(file_id, i)) && !model.corrupted.contains(&(file_id, i))
        });
        if model.gone {
            assert_eq!(result, Err(SinkError::Storage));
        } else if model.published.contains(&file_id) {
            result?;
        } else if !model.keyed.contains(&file_id) {
            assert_eq!(result, Err(SinkError::Storage));
        } else if model.other_master.contains(&file_id) || !complete {
            assert!(result.is_err(), "published without its verified segments");
            if !model.other_master.contains(&file_id) {
                assert_eq!(result, Err(SinkError::Integrity));
            }
        } else {
            result?;
            self.model.published.insert(file_id);
            self.model.sealed.remove(&file_id);
            self.model.keyed.remove(&file_id);
            self.model.stored.retain(|(f, _)| *f != file_id);
            self.model.corrupted.retain(|(f, _)| *f != file_id);
        }
        Ok(())
    }

    fn restart(&mut self, torn: bool) -> AnyResult<()> {
        let manifest = self.consented().manifest.clone();
        let transfer_id = *manifest.transfer_id();
        if torn {
            let journal = self.harness.transfer_dir(&transfer_id).join("journal");
            if journal.exists() {
                let mut bytes = std::fs::read(&journal)?;
                bytes.extend_from_slice(&[2, 0, 0, 0, 7, 0]);
                std::fs::write(&journal, &bytes)?;
            }
        }
        self.harness.reopen(WALL + 1)?;
        self.model.keyed.clear();
        Ok(())
    }

    fn resume(&mut self) -> AnyResult<()> {
        let manifest = self.consented().manifest.clone();
        let transfer_id = *manifest.transfer_id();
        if self.model.gone {
            return Ok(());
        }
        self.current = 1 - self.current;
        let sink = self.harness.sink.as_mut().ok_or("sink")?;
        let consented = &self.consents[self.current];
        assert!(sink.retained(&transfer_id, time(WALL + 1)?).is_some());
        sink.record_accept(&consented.manifest, &consented.accept)?;
        self.model.keyed.clear();
        Ok(())
    }

    fn corrupt(&mut self, file: usize, index: u32) -> AnyResult<()> {
        let manifest = self.consented().manifest.clone();
        let transfer_id = *manifest.transfer_id();
        let file_id = SELECTION[file];
        if !self.model.stored.contains(&(file_id, index)) {
            return Ok(());
        }
        let path = self
            .harness
            .transfer_dir(&transfer_id)
            .join(format!("s{file_id}"));
        let mut bytes = std::fs::read(&path)?;
        let size = SIZES
            .iter()
            .find(|(id, _)| *id == file_id)
            .map_or(0, |(_, s)| *s);
        let stride = crate::quarantine::store::max_ciphertext_len(size as u64) + 2;
        let at = stride * index as usize + 2 + 30;
        if at < bytes.len() {
            bytes[at] ^= 0x40;
            std::fs::write(&path, &bytes)?;
            self.model.corrupted.insert((file_id, index));
        }
        Ok(())
    }

    fn plant(&mut self, top_file: bool, link: bool) -> AnyResult<()> {
        let name = if top_file { "c.txt" } else { "d" };
        let path = self.harness.dest.path().join(name);
        if path.symlink_metadata().is_ok() {
            return Ok(());
        }
        if link {
            if symlink_dir(self.outside.path(), &path)?.is_some() {
                self.model.sentinels.insert(path, Vec::new());
            }
        } else if top_file {
            std::fs::write(&path, b"theirs")?;
            self.model.sentinels.insert(path, b"theirs".to_vec());
        } else {
            std::fs::create_dir(&path)?;
            std::fs::write(path.join("a.bin"), b"theirs")?;
            self.model
                .sentinels
                .insert(path.join("a.bin"), b"theirs".to_vec());
        }
        Ok(())
    }

    fn tamper(&mut self, file: usize) -> AnyResult<()> {
        let manifest = self.consented().manifest.clone();
        let transfer_id = *manifest.transfer_id();
        let file_id = SELECTION[file];
        if !self.model.published.contains(&file_id) || self.model.tampered.contains(&file_id) {
            return Ok(());
        }
        let Some(path) = self.harness.sink()?.published_path(&transfer_id, file_id) else {
            return Ok(());
        };
        let full = path
            .iter()
            .fold(self.harness.dest.path().to_owned(), |p, c| p.join(c));
        let mut bytes = std::fs::read(&full)?;
        bytes.push(1);
        std::fs::write(&full, &bytes)?;
        self.model.tampered.insert(file_id);
        Ok(())
    }

    fn mark_gone(&mut self) {
        self.model.gone = true;
        self.model.sealed.clear();
        self.model.keyed.clear();
        self.model.stored.clear();
        self.model.corrupted.clear();
    }

    fn check(&mut self) -> AnyResult<()> {
        let manifest = self.consented().manifest.clone();
        let transfer_id = *manifest.transfer_id();
        let contents = self.consented().contents.clone();
        // At rest: never the plaintext of a file.
        for path in files_below(self.harness.state.path())? {
            let bytes = read_at_rest(self.harness.state.path(), &path)?;
            for content in contents.values().filter(|c| c.len() >= 64) {
                assert!(
                    !bytes
                        .windows(content.len())
                        .any(|w| w == content.as_slice())
                );
            }
        }
        // Nothing ever lands outside the destination.
        assert_eq!(files_below(self.outside.path())?, Vec::<PathBuf>::new());
        // The destination holds exactly the sentinels, unchanged, and the
        // published files at their recorded paths with their content.
        let mut expected: BTreeSet<PathBuf> = BTreeSet::new();
        for (path, content) in &self.model.sentinels {
            if content.is_empty()
                && path
                    .symlink_metadata()
                    .is_ok_and(|m| m.file_type().is_symlink())
            {
                continue;
            }
            assert_eq!(
                &std::fs::read(path)?,
                content,
                "a file that was not ours changed"
            );
            expected.insert(path.clone());
        }
        if !self.model.gone {
            // No sealed master is kept for a published file.
            for &file_id in &self.model.published {
                let master = self
                    .harness
                    .transfer_dir(&transfer_id)
                    .join(format!("k{file_id}"));
                assert!(
                    !master.exists(),
                    "a master kept for published file {file_id}"
                );
            }
            for &file_id in &self.model.published {
                let path = self
                    .harness
                    .sink()?
                    .published_path(&transfer_id, file_id)
                    .ok_or("published path")?;
                let full = path
                    .iter()
                    .fold(self.harness.dest.path().to_owned(), |p, c| p.join(c));
                if !self.model.tampered.contains(&file_id) {
                    assert_eq!(
                        std::fs::read(&full)?,
                        *contents.get(&file_id).ok_or("content")?
                    );
                }
                expected.insert(full);
                let intact = self.harness.sink()?.published_intact(&manifest, file_id);
                assert_eq!(intact, !self.model.tampered.contains(&file_id));
            }
        }
        let actual: BTreeSet<PathBuf> = files_below(self.harness.dest.path())?
            .into_iter()
            .filter(|p| {
                !p.symlink_metadata()
                    .is_ok_and(|m| m.file_type().is_symlink())
            })
            .collect();
        if self.model.gone {
            // Published files stay; nothing else of ours may remain.
            for path in &actual {
                let name = path
                    .file_name()
                    .map(|n| n.to_string_lossy().into_owned())
                    .unwrap_or_default();
                assert!(!name.starts_with(".todoke-"), "a temporary file remains");
            }
            assert!(!self.harness.transfer_dir(&transfer_id).exists());
        } else {
            assert_eq!(actual, expected);
            // Retained segments are exactly the stored ones.
            for &file_id in &SELECTION {
                if self.model.published.contains(&file_id) {
                    continue;
                }
                for index in 0..count(file_id) {
                    let retained =
                        self.harness
                            .sink()?
                            .retained_segment(&transfer_id, file_id, index)?;
                    if self.model.corrupted.contains(&(file_id, index)) {
                        continue;
                    }
                    if self.model.stored.contains(&(file_id, index)) {
                        assert_eq!(retained, Some(self.consented().ciphertext(file_id, index)?));
                    } else {
                        assert_eq!(retained, None, "file {file_id} segment {index}");
                    }
                }
            }
        }
        Ok(())
    }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    #[test]
    fn quarantine_and_publication_follow_the_model(ops in proptest::collection::vec(op(), 1..60)) {
        let mut run = Run::new().map_err(|e| TestCaseError::fail(e.to_string()))?;
        for op in &ops {
            run.apply(op).map_err(|e| TestCaseError::fail(format!("{op:?}: {e}")))?;
            run.check().map_err(|e| TestCaseError::fail(format!("after {op:?}: {e}")))?;
        }
    }
}
