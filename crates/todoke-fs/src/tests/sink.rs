//! The filesystem sink: quarantine, publication, restart, cancel, expiry,
//! quota, damaged state, and races, through `ReceiveSink` directly with
//! real verified Accepts and real content ciphertext.

use std::path::{Path, PathBuf};

use todoke_crypto::identity::SoftwareSealer;
use todoke_proto::time::UnixTime;
use todoke_transfer::{ReceiveSink, SinkError, SinkRefusal, TransferId};

use super::support::*;
use super::*;
use crate::dest::DirDestination;
use crate::quarantine::codec::decode_journal;
use crate::{Change, Durability, FsProfile, FsSink, OpenError, PathLimit, SinkConfig};

pub(crate) type Sink = FsSink<DirDestination, SoftwareSealer>;

/// A sink over a fresh state directory and destination.
pub(crate) struct Harness {
    pub(crate) state: TempDir,
    pub(crate) dest: TempDir,
    pub(crate) config: SinkConfig,
    pub(crate) sink: Option<Sink>,
}

impl Harness {
    pub(crate) fn new() -> AnyResult<Self> {
        Self::with_config(SinkConfig::default())
    }

    pub(crate) fn with_config(config: SinkConfig) -> AnyResult<Self> {
        let mut harness = Self {
            state: TempDir::new()?,
            dest: TempDir::new()?,
            config,
            sink: None,
        };
        harness.reopen(WALL)?;
        Ok(harness)
    }

    /// Drops the sink (as a crash or restart would) and opens a new one at
    /// `now`.
    pub(crate) fn reopen(&mut self, now: u64) -> AnyResult<()> {
        self.sink = None;
        let destination = DirDestination::open(self.dest.path())?;
        self.sink = Some(FsSink::open(
            self.state.path(),
            destination,
            sealer(7),
            self.config,
            time(now)?,
        )?);
        Ok(())
    }

    pub(crate) fn sink(&mut self) -> AnyResult<&mut Sink> {
        Ok(self.sink.as_mut().ok_or("no sink")?)
    }

    pub(crate) fn transfer_dir(&self, id: &TransferId) -> PathBuf {
        self.state
            .path()
            .join("transfers")
            .join(crate::quarantine::store::hex(id))
    }
}

/// Every file below `path`, recursively.
pub(crate) fn files_below(path: &Path) -> AnyResult<Vec<PathBuf>> {
    let mut out = Vec::new();
    let mut stack = vec![path.to_owned()];
    while let Some(dir) = stack.pop() {
        for entry in std::fs::read_dir(&dir)? {
            let entry = entry?;
            let kind = entry.file_type()?;
            if kind.is_dir() {
                stack.push(entry.path());
            } else {
                out.push(entry.path());
            }
        }
    }
    out.sort();
    Ok(out)
}

fn contains(haystack: &[u8], needle: &[u8]) -> bool {
    !needle.is_empty()
        && haystack
            .windows(needle.len())
            .any(|window| window == needle)
}

pub(crate) fn entries() -> Vec<Entry> {
    vec![
        dir_entry("photos", 0),
        file_entry("a.bin", 1, content(40_000, 1)),
        file_entry("empty", 1, Vec::new()),
        dir_entry("deep", 1),
        file_entry("b.bin", 4, content(16_384 * 3 + 5, 3)),
        file_entry("c.txt", 0, content(100, 4)),
    ]
}

pub(crate) const FILES: [u32; 4] = [2, 3, 5, 6];

/// Accepts `selection`, keys the files, and stores every segment.
pub(crate) fn receive_all(
    sink: &mut Sink,
    consented: &Consented,
    selection: &[u32],
) -> AnyResult<()> {
    sink.check_offer(&consented.manifest)
        .map_err(|refusal| format!("{refusal:?}"))?;
    sink.record_accept(&consented.manifest, &consented.accept)?;
    for &file_id in selection {
        let file = consented.accept.file(file_id).ok_or("file")?;
        sink.record_file_key(&file, &consented.master(file_id)?)?;
        for index in 0..consented.count(file_id)? {
            let ciphertext = consented.ciphertext(file_id, index)?;
            let segment = consented.verified(file_id, index, &ciphertext)?;
            sink.store_segment(&segment, &ciphertext)?;
        }
    }
    Ok(())
}

fn setup(id: u8) -> AnyResult<(Harness, Consented)> {
    let fixture = fixture()?;
    let manifest = build_manifest(&fixture, [id; 16], &entries(), 3600)?;
    let consented = Consented::new(&fixture, &manifest, &entries(), &FILES, false, id)?;
    Ok((Harness::new()?, consented))
}

#[test]
fn a_transfer_is_quarantined_as_ciphertext_then_published() -> TestResult {
    let (mut harness, consented) = setup(1)?;
    let transfer_id = *consented.manifest.transfer_id();
    receive_all(harness.sink()?, &consented, &FILES)?;
    // At rest: ciphertext and sealed masters only.
    let stored = files_below(harness.state.path())?;
    assert_ne!(stored, Vec::<PathBuf>::new());
    for path in &stored {
        let bytes = std::fs::read(path)?;
        for (file_id, content) in &consented.contents {
            assert!(!contains(&bytes, content), "file {file_id} in plaintext");
        }
        for master in consented.masters.values() {
            assert!(!contains(&bytes, master), "a master in the clear");
        }
    }
    assert_eq!(files_below(harness.dest.path())?, Vec::<PathBuf>::new());
    // Publication.
    for file_id in FILES {
        harness.sink()?.publish(&consented.manifest, file_id)?;
        assert!(
            harness
                .sink()?
                .published_intact(&consented.manifest, file_id)
        );
    }
    let dest = harness.dest.path();
    assert_eq!(
        std::fs::read(dest.join("photos").join("a.bin"))?,
        content(40_000, 1)
    );
    assert_eq!(
        std::fs::read(dest.join("photos").join("empty"))?,
        Vec::<u8>::new()
    );
    assert_eq!(
        std::fs::read(dest.join("photos").join("deep").join("b.bin"))?,
        content(16_384 * 3 + 5, 3)
    );
    assert_eq!(std::fs::read(dest.join("c.txt"))?, content(100, 4));
    assert_eq!(files_below(dest)?.len(), 4, "no temporary files remain");
    assert_eq!(
        harness.sink()?.published_path(&transfer_id, 5),
        Some(vec![
            "photos".to_owned(),
            "deep".to_owned(),
            "b.bin".to_owned()
        ])
    );
    // Published files' ciphertext and masters are gone.
    let left: Vec<String> = files_below(&harness.transfer_dir(&transfer_id))?
        .iter()
        .filter_map(|path| {
            path.file_name()
                .map(|name| name.to_string_lossy().into_owned())
        })
        .collect();
    assert_eq!(left, ["journal", "manifest"]);
    harness.sink()?.finish(&transfer_id);
    let retained = harness
        .sink()?
        .retained(&transfer_id, time(WALL)?)
        .ok_or("record")?;
    assert_eq!(retained.selection, FILES);
    // After a restart the record and the published files are still known.
    harness.reopen(WALL + 10)?;
    for file_id in FILES {
        assert!(
            harness
                .sink()?
                .published_intact(&consented.manifest, file_id)
        );
    }
    let report = harness.sink()?.content_report(&transfer_id, 6);
    assert!(report.is_none(), "reports are per session");
    Ok(())
}

#[test]
fn existing_names_get_suffixes_and_nothing_is_overwritten() -> TestResult {
    let (mut harness, consented) = setup(2)?;
    let dest = harness.dest.path().to_owned();
    std::fs::create_dir(dest.join("Photos"))?;
    std::fs::write(dest.join("Photos").join("a.bin"), b"theirs")?;
    std::fs::write(dest.join("C.TXT"), b"theirs too")?;
    let transfer_id = *consented.manifest.transfer_id();
    receive_all(harness.sink()?, &consented, &FILES)?;
    let plan = harness.sink()?.plan(&transfer_id).ok_or("plan")?;
    assert_eq!(
        plan.entry(1).map(|e| e.local().as_str()),
        Some("photos (2)")
    );
    assert_eq!(plan.entry(6).map(|e| e.local().as_str()), Some("c (2).txt"));
    assert_eq!(
        plan.entry(6).map(crate::PlannedEntry::changes),
        Some(&[Change::Exists][..])
    );
    // Something takes the planned name after consent: the next one.
    std::fs::write(dest.join("c (2).txt"), b"late")?;
    for file_id in FILES {
        harness.sink()?.publish(&consented.manifest, file_id)?;
    }
    assert_eq!(std::fs::read(dest.join("Photos").join("a.bin"))?, b"theirs");
    assert_eq!(std::fs::read(dest.join("C.TXT"))?, b"theirs too");
    assert_eq!(std::fs::read(dest.join("c (2).txt"))?, b"late");
    assert_eq!(std::fs::read(dest.join("c (3).txt"))?, content(100, 4));
    assert_eq!(
        std::fs::read(dest.join("photos (2)").join("a.bin"))?,
        content(40_000, 1)
    );
    assert_eq!(
        harness.sink()?.published_path(&transfer_id, 6),
        Some(vec!["c (3).txt".to_owned()])
    );
    Ok(())
}

#[test]
fn a_restart_keeps_verified_segments_and_removes_temporaries() -> TestResult {
    let (mut harness, consented) = setup(3)?;
    let transfer_id = *consented.manifest.transfer_id();
    let sink = harness.sink()?;
    sink.check_offer(&consented.manifest)
        .map_err(|r| format!("{r:?}"))?;
    sink.record_accept(&consented.manifest, &consented.accept)?;
    let file = consented.accept.file(5).ok_or("file")?;
    sink.record_file_key(&file, &consented.master(5)?)?;
    for index in [0, 2] {
        let ciphertext = consented.ciphertext(5, index)?;
        sink.store_segment(&consented.verified(5, index, &ciphertext)?, &ciphertext)?;
    }
    sink.drop_segment(&transfer_id, 5, 2);
    // A crash during publication left a temporary file behind.
    let journal = std::fs::read(harness.transfer_dir(&transfer_id).join("journal"))?;
    let (header, _, _) = decode_journal(&journal).map_err(|_| "journal")?;
    let temp = crate::sink::temp_name(&header, 6);
    std::fs::write(harness.dest.path().join(&temp), b"partial")?;
    harness.reopen(WALL + 5)?;
    assert!(!harness.dest.path().join(&temp).exists());
    let sink = harness.sink()?;
    let retained = sink
        .retained(&transfer_id, time(WALL + 5)?)
        .ok_or("retained")?;
    assert_eq!(retained.manifest_hash, *consented.manifest.hash());
    assert_eq!(
        sink.retained_segment(&transfer_id, 5, 0)?,
        Some(consented.ciphertext(5, 0)?)
    );
    assert_eq!(sink.retained_segment(&transfer_id, 5, 1)?, None);
    assert_eq!(sink.retained_segment(&transfer_id, 5, 2)?, None);
    // A fresh session (fresh consent) with the same master keeps them.
    let fixture = fixture()?;
    let resumed = Consented::new(&fixture, &consented.manifest, &entries(), &FILES, true, 3)?;
    sink.record_accept(&resumed.manifest, &resumed.accept)?;
    let file = resumed.accept.file(5).ok_or("file")?;
    sink.record_file_key(&file, &resumed.master(5)?)?;
    assert!(sink.retained_segment(&transfer_id, 5, 0)?.is_some());
    // A different master makes them useless: they go.
    let other = Consented::new(
        &fixture,
        &consented.manifest,
        &entries(),
        &FILES,
        true,
        0x55,
    )?;
    sink.record_file_key(&file, &other.master(5)?)?;
    assert_eq!(sink.retained_segment(&transfer_id, 5, 0)?, None);
    Ok(())
}

#[test]
fn cancel_deletes_the_quarantine_and_the_tombstone_survives() -> TestResult {
    let config = SinkConfig {
        tombstone_limit: 2,
        ..SinkConfig::default()
    };
    let (_, consented) = setup(4)?;
    let mut harness = Harness::with_config(config)?;
    let transfer_id = *consented.manifest.transfer_id();
    receive_all(harness.sink()?, &consented, &FILES)?;
    harness.sink()?.publish(&consented.manifest, 6)?;
    let until = time(WALL + 3600 + 120)?;
    harness.sink()?.tombstone(&transfer_id, until);
    assert!(!harness.transfer_dir(&transfer_id).exists());
    assert!(harness.sink()?.is_tombstoned(&transfer_id, time(WALL)?));
    assert!(
        harness
            .sink()?
            .retained(&transfer_id, time(WALL)?)
            .is_none()
    );
    // Published files stay under the user's control.
    assert_eq!(
        std::fs::read(harness.dest.path().join("c.txt"))?,
        content(100, 4)
    );
    harness.reopen(WALL + 60)?;
    let sink = harness.sink()?;
    assert!(sink.is_tombstoned(&transfer_id, time(WALL + 60)?));
    assert!(sink.tombstone_room(time(WALL + 60)?));
    sink.tombstone(&[9; 16], until);
    assert!(!sink.tombstone_room(time(WALL + 60)?));
    // Expired tombstones make room; a live one is never dropped early.
    assert!(
        sink.tombstone_room(
            until
                .seconds()
                .checked_add(1)
                .and_then(UnixTime::new)
                .ok_or("t")?
        )
    );
    assert!(!sink.is_tombstoned(&transfer_id, time(WALL + 3600 + 121)?));
    Ok(())
}

#[test]
fn expired_transfers_are_deleted() -> TestResult {
    let (mut harness, consented) = setup(5)?;
    let transfer_id = *consented.manifest.transfer_id();
    receive_all(harness.sink()?, &consented, &FILES)?;
    let expires = consented.manifest.expires_at().seconds();
    assert!(
        harness
            .sink()?
            .retained(&transfer_id, time(expires)?)
            .is_none()
    );
    // At startup.
    harness.reopen(expires)?;
    assert!(!harness.transfer_dir(&transfer_id).exists());
    // And while running.
    let (mut harness, consented) = setup(6)?;
    let transfer_id = *consented.manifest.transfer_id();
    receive_all(harness.sink()?, &consented, &FILES)?;
    assert!(harness.sink()?.tombstone_room(time(expires)?));
    assert!(!harness.transfer_dir(&transfer_id).exists());
    assert_eq!(harness.sink()?.reserved_bytes(), 0);
    Ok(())
}

#[test]
fn damaged_state_is_discarded_or_fails_closed() -> TestResult {
    let (mut harness, consented) = setup(7)?;
    let transfer_id = *consented.manifest.transfer_id();
    receive_all(harness.sink()?, &consented, &FILES)?;
    harness.sink()?.publish(&consented.manifest, 6)?;
    let journal = harness.transfer_dir(&transfer_id).join("journal");
    // A torn tail is ignored.
    let mut bytes = std::fs::read(&journal)?;
    bytes.extend_from_slice(&[2, 0, 0]);
    std::fs::write(&journal, &bytes)?;
    harness.reopen(WALL)?;
    assert!(harness.sink()?.published_intact(&consented.manifest, 6));
    assert!(
        harness
            .sink()?
            .retained(&transfer_id, time(WALL)?)
            .is_some()
    );
    // A damaged header discards the transfer.
    let mut bytes = std::fs::read(&journal)?;
    bytes[10] ^= 1;
    std::fs::write(&journal, &bytes)?;
    harness.reopen(WALL)?;
    assert!(
        harness
            .sink()?
            .retained(&transfer_id, time(WALL)?)
            .is_none()
    );
    assert!(!harness.transfer_dir(&transfer_id).exists());
    // A stray directory in the quarantine goes too.
    std::fs::create_dir(harness.state.path().join("transfers").join("not-hex"))?;
    harness.reopen(WALL)?;
    assert!(
        !harness
            .state
            .path()
            .join("transfers")
            .join("not-hex")
            .exists()
    );
    // A damaged tombstone list fails closed.
    harness.sink()?.tombstone(&[1; 16], time(WALL + 10)?);
    harness.sink = None;
    let tombstones = harness.state.path().join("tombstones");
    let mut bytes = std::fs::read(&tombstones)?;
    bytes[12] ^= 1;
    std::fs::write(&tombstones, &bytes)?;
    let reopened = FsSink::open(
        harness.state.path(),
        DirDestination::open(harness.dest.path())?,
        sealer(7),
        SinkConfig::default(),
        time(WALL)?,
    );
    assert!(matches!(reopened, Err(OpenError::CorruptTombstones)));
    Ok(())
}

#[test]
fn one_sink_per_state_directory() -> TestResult {
    let mut harness = Harness::new()?;
    let second = FsSink::open(
        harness.state.path(),
        DirDestination::open(harness.dest.path())?,
        sealer(7),
        SinkConfig::default(),
        time(WALL)?,
    );
    assert!(matches!(second, Err(OpenError::InUse)));
    harness.reopen(WALL)?;
    Ok(())
}

#[test]
fn published_files_are_rehashed_before_they_count() -> TestResult {
    let (mut harness, consented) = setup(8)?;
    receive_all(harness.sink()?, &consented, &FILES)?;
    for file_id in FILES {
        harness.sink()?.publish(&consented.manifest, file_id)?;
    }
    let dest = harness.dest.path().to_owned();
    // Same length, one byte different.
    let mut changed = content(100, 4);
    changed[50] ^= 1;
    std::fs::write(dest.join("c.txt"), &changed)?;
    assert!(!harness.sink()?.published_intact(&consented.manifest, 6));
    // Longer.
    let mut longer = content(40_000, 1);
    longer.push(0);
    std::fs::write(dest.join("photos").join("a.bin"), &longer)?;
    assert!(!harness.sink()?.published_intact(&consented.manifest, 2));
    // Gone.
    std::fs::remove_file(dest.join("photos").join("deep").join("b.bin"))?;
    assert!(!harness.sink()?.published_intact(&consented.manifest, 5));
    // Replaced by a link to an identical file elsewhere: refused.
    let outside = TempDir::new()?;
    std::fs::write(outside.path().join("empty"), b"")?;
    std::fs::remove_file(dest.join("photos").join("empty"))?;
    if symlink_file(
        &outside.path().join("empty"),
        &dest.join("photos").join("empty"),
    )?
    .is_some()
    {
        assert!(!harness.sink()?.published_intact(&consented.manifest, 3));
    }
    Ok(())
}

#[test]
fn quota_and_rejections_refuse_before_anything_is_stored() -> TestResult {
    let fixture = fixture()?;
    let manifest = build_manifest(&fixture, [9; 16], &entries(), 3600)?;
    // Too small for any file.
    let mut harness = Harness::with_config(SinkConfig {
        quota_bytes: 1000,
        ..SinkConfig::default()
    })?;
    assert_eq!(
        harness.sink()?.check_offer(&manifest),
        Err(SinkRefusal::Quota)
    );
    // Enough for the small files only: the offer stands, the full
    // selection is refused at Accept.
    let mut harness = Harness::with_config(SinkConfig {
        quota_bytes: 150_000,
        ..SinkConfig::default()
    })?;
    assert_eq!(harness.sink()?.check_offer(&manifest), Ok(()));
    let all = Consented::new(&fixture, &manifest, &entries(), &FILES, false, 9)?;
    assert_eq!(
        harness.sink()?.record_accept(&manifest, &all.accept),
        Err(SinkError::Storage)
    );
    let small = Consented::new(&fixture, &manifest, &entries(), &[3, 6], false, 9)?;
    harness.sink()?.record_accept(&manifest, &small.accept)?;
    // A destination too deep for the nested files rejects them.
    let mut harness = Harness::with_config(SinkConfig {
        profile: FsProfile {
            path: PathLimit {
                max: harness_root_len()? + 1 + 7,
                ..PathLimit::host()
            },
            ..FsProfile::host()
        },
        ..SinkConfig::default()
    })?;
    assert_eq!(harness.sink()?.check_offer(&manifest), Ok(()));
    assert_eq!(
        harness.sink()?.record_accept(&manifest, &all.accept),
        Err(SinkError::Storage)
    );
    let top = Consented::new(&fixture, &manifest, &entries(), &[6], false, 9)?;
    harness.sink()?.record_accept(&manifest, &top.accept)?;
    let mut harness = Harness::with_config(SinkConfig {
        profile: FsProfile {
            path: PathLimit {
                max: 3,
                ..PathLimit::host()
            },
            ..FsProfile::host()
        },
        ..SinkConfig::default()
    })?;
    assert_eq!(
        harness.sink()?.check_offer(&manifest),
        Err(SinkRefusal::UnsupportedDestination)
    );
    Ok(())
}

/// The length of a fresh destination root's canonical path, in the host's
/// units.
fn harness_root_len() -> AnyResult<usize> {
    let temp = TempDir::new()?;
    let destination = DirDestination::open(temp.path())?;
    Ok(crate::dest::Destination::root_len(&destination))
}

#[test]
fn nothing_is_stored_without_a_key_and_damage_is_never_published() -> TestResult {
    let (mut harness, consented) = setup(10)?;
    let transfer_id = *consented.manifest.transfer_id();
    let sink = harness.sink()?;
    sink.check_offer(&consented.manifest)
        .map_err(|r| format!("{r:?}"))?;
    sink.record_accept(&consented.manifest, &consented.accept)?;
    let ciphertext = consented.ciphertext(6, 0)?;
    let segment = consented.verified(6, 0, &ciphertext)?;
    assert_eq!(
        sink.store_segment(&segment, &ciphertext),
        Err(SinkError::Storage)
    );
    let file = consented.accept.file(6).ok_or("file")?;
    sink.record_file_key(&file, &consented.master(6)?)?;
    sink.store_segment(&segment, &ciphertext)?;
    // Damage the stored ciphertext on disk.
    let slots = harness.transfer_dir(&transfer_id).join("s6");
    let mut bytes = std::fs::read(&slots)?;
    bytes[20] ^= 1;
    std::fs::write(&slots, &bytes)?;
    assert_eq!(
        harness.sink()?.publish(&consented.manifest, 6),
        Err(SinkError::Integrity)
    );
    assert_eq!(files_below(harness.dest.path())?, Vec::<PathBuf>::new());
    // A missing segment is never published either.
    let file = consented.accept.file(2).ok_or("file")?;
    harness
        .sink()?
        .record_file_key(&file, &consented.master(2)?)?;
    let ciphertext = consented.ciphertext(2, 0)?;
    harness
        .sink()?
        .store_segment(&consented.verified(2, 0, &ciphertext)?, &ciphertext)?;
    assert_eq!(
        harness.sink()?.publish(&consented.manifest, 2),
        Err(SinkError::Integrity)
    );
    assert_eq!(files_below(harness.dest.path())?, Vec::<PathBuf>::new());
    Ok(())
}

#[test]
fn links_planted_in_the_destination_are_never_followed() -> TestResult {
    let (mut harness, consented) = setup(11)?;
    let outside = TempDir::new()?;
    let dest = harness.dest.path().to_owned();
    receive_all(harness.sink()?, &consented, &FILES)?;
    // A link appears under the planned top-level directory name.
    if symlink_dir(outside.path(), &dest.join("photos"))?.is_none() {
        return Ok(());
    }
    harness.sink()?.publish(&consented.manifest, 2)?;
    assert_eq!(
        std::fs::read(dest.join("photos (2)").join("a.bin"))?,
        content(40_000, 1)
    );
    // The directory it created is swapped for a link: refused.
    std::fs::rename(dest.join("photos (2)"), dest.join("moved"))?;
    if symlink_dir(outside.path(), &dest.join("photos (2)"))?.is_none() {
        return Ok(());
    }
    assert_eq!(
        harness.sink()?.publish(&consented.manifest, 3),
        Err(SinkError::Storage)
    );
    // A link at a file's planned name: the next name.
    if symlink_file(&outside.path().join("c.txt"), &dest.join("c.txt"))?.is_none() {
        return Ok(());
    }
    harness.sink()?.publish(&consented.manifest, 6)?;
    assert_eq!(std::fs::read(dest.join("c (2).txt"))?, content(100, 4));
    assert_eq!(files_below(outside.path())?, Vec::<PathBuf>::new());
    Ok(())
}

#[test]
fn revoking_a_sender_tombstones_its_transfers() -> TestResult {
    let (mut harness, consented) = setup(12)?;
    let transfer_id = *consented.manifest.transfer_id();
    receive_all(harness.sink()?, &consented, &FILES)?;
    let fixture = fixture()?;
    let until = time(WALL + 7200)?;
    harness.sink()?.revoke_sender(&fixture.bob.key(), until);
    assert!(
        harness
            .sink()?
            .retained(&transfer_id, time(WALL)?)
            .is_some()
    );
    harness.sink()?.revoke_sender(&fixture.alice.key(), until);
    assert!(
        harness
            .sink()?
            .retained(&transfer_id, time(WALL)?)
            .is_none()
    );
    assert!(harness.sink()?.is_tombstoned(&transfer_id, time(WALL)?));
    assert!(!harness.transfer_dir(&transfer_id).exists());
    Ok(())
}

#[test]
fn periodic_durability_publishes_the_same_bytes() -> TestResult {
    let (_, consented) = setup(13)?;
    let mut harness = Harness::with_config(SinkConfig {
        durability: Durability::Periodic { bytes: 1 << 20 },
        ..SinkConfig::default()
    })?;
    receive_all(harness.sink()?, &consented, &FILES)?;
    for file_id in FILES {
        harness.sink()?.publish(&consented.manifest, file_id)?;
    }
    assert_eq!(
        std::fs::read(harness.dest.path().join("c.txt"))?,
        content(100, 4)
    );
    Ok(())
}

#[test]
fn debug_output_contains_no_names_or_paths() -> TestResult {
    let (mut harness, consented) = setup(14)?;
    receive_all(harness.sink()?, &consented, &FILES)?;
    let rendered = format!("{:?}", harness.sink()?);
    let state = harness.state.path().to_string_lossy().into_owned();
    assert!(!rendered.contains(&state));
    assert!(!rendered.contains("photos"));
    Ok(())
}

/// Start-up clean-up deletes retained state only when it is positively
/// damaged or expired. A journal or manifest it cannot read now
/// (permissions here; also I/O errors, too many open files, a lock) is
/// kept for a later start, and no new Accept may replace it meanwhile.
#[cfg(unix)]
#[test]
fn unreadable_state_is_kept_not_deleted() -> TestResult {
    use std::os::unix::fs::PermissionsExt as _;
    for record in ["journal", "manifest"] {
        let (mut harness, consented) = setup(15)?;
        let transfer_id = *consented.manifest.transfer_id();
        receive_all(harness.sink()?, &consented, &FILES)?;
        harness.sink = None;
        let path = harness.transfer_dir(&transfer_id).join(record);
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o000))?;
        if std::fs::read(&path).is_ok() {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
            eprintln!("skipping: this account reads files without permission (root)");
            return Ok(());
        }
        harness.reopen(WALL)?;
        assert!(path.exists(), "the {record} was deleted");
        assert!(harness.transfer_dir(&transfer_id).join("s6").exists());
        let sink = harness.sink()?;
        assert!(sink.retained(&transfer_id, time(WALL)?).is_none());
        sink.check_offer(&consented.manifest)
            .map_err(|r| format!("{r:?}"))?;
        assert_eq!(
            sink.record_accept(&consented.manifest, &consented.accept),
            Err(SinkError::Storage)
        );
        assert!(path.exists());
        // Readable again: the transfer is back, with its segments.
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600))?;
        harness.reopen(WALL)?;
        let sink = harness.sink()?;
        assert!(sink.retained(&transfer_id, time(WALL)?).is_some());
        assert_eq!(
            sink.retained_segment(&transfer_id, 6, 0)?,
            Some(consented.ciphertext(6, 0)?)
        );
    }
    Ok(())
}

/// A cancel whose tombstone cannot be written is not forgotten silently:
/// the sink reports the tombstones as not durable and takes no new or
/// resumed transfer until a retry persists them.
#[test]
fn a_tombstone_that_cannot_be_written_fails_closed_until_it_is() -> TestResult {
    let (mut harness, consented) = setup(16)?;
    let transfer_id = *consented.manifest.transfer_id();
    receive_all(harness.sink()?, &consented, &FILES)?;
    let fixture = fixture()?;
    let other = build_manifest(&fixture, [17; 16], &entries(), 3600)?;
    let other_consent = Consented::new(&fixture, &other, &entries(), &FILES, false, 17)?;
    harness
        .sink()?
        .check_offer(&other)
        .map_err(|r| format!("{r:?}"))?;
    // The atomic write's temporary name is taken by a directory: every
    // write of the tombstone list fails.
    let blocker = harness.state.path().join("tombstones.tmp");
    std::fs::create_dir(&blocker)?;
    let until = time(WALL + 7200)?;
    let sink = harness.sink()?;
    sink.tombstone(&transfer_id, until);
    assert!(sink.is_tombstoned(&transfer_id, time(WALL)?));
    assert!(!sink.tombstones_durable());
    assert!(
        !sink.tombstone_room(time(WALL)?),
        "a new transfer was taken"
    );
    assert_eq!(
        sink.record_accept(&other, &other_consent.accept),
        Err(SinkError::Storage)
    );
    assert_eq!(
        sink.check_offer(&other),
        Err(SinkRefusal::UnsupportedDestination)
    );
    sink.sweep(time(WALL)?);
    assert!(!sink.tombstones_durable());
    // The next retry persists it.
    std::fs::remove_dir(&blocker)?;
    assert!(sink.tombstone_room(time(WALL)?));
    assert!(sink.tombstones_durable());
    harness.reopen(WALL + 1)?;
    assert!(harness.sink()?.is_tombstoned(&transfer_id, time(WALL + 1)?));
    Ok(())
}

/// In both durability modes the tombstone is on disk, through the synced
/// atomic replacement, before `tombstone` returns (so before the engine
/// reports the cancel).
#[test]
fn tombstones_are_on_disk_before_the_cancel_returns() -> TestResult {
    for durability in [
        Durability::EverySegment,
        Durability::Periodic { bytes: 1 << 30 },
    ] {
        let (_, consented) = setup(18)?;
        let mut harness = Harness::with_config(SinkConfig {
            durability,
            ..SinkConfig::default()
        })?;
        let transfer_id = *consented.manifest.transfer_id();
        receive_all(harness.sink()?, &consented, &FILES)?;
        let until = time(WALL + 7200)?;
        harness.sink()?.tombstone(&transfer_id, until);
        assert!(harness.sink()?.tombstones_durable());
        let bytes = std::fs::read(harness.state.path().join("tombstones"))?;
        let list = crate::quarantine::codec::decode_tombstones(&bytes).map_err(|_| "list")?;
        assert_eq!(list, [(transfer_id, until.seconds())]);
        assert!(!harness.state.path().join("tombstones.tmp").exists());
    }
    Ok(())
}
