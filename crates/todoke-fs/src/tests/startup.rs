//! Start-up: which retained records are damage (deleted), which are only
//! unreadable now (kept, see the sink tests), and what each record must
//! agree with; a cancel whose deletion a crash interrupted; the journal at
//! its entry bound; and a torn tail cut before the next append.

use std::path::{Path, PathBuf};

use todoke_crypto::consent::CanonicalManifest;
use todoke_transfer::{ReceiveSink, SinkError};

use super::sink::{FILES, Harness, entries, receive_all};
use super::support::*;
use super::*;
use crate::dest::DirDestination;
use crate::quarantine::codec::{
    JournalEntry, MAX_JOURNAL_ENTRIES, decode_journal, encode_tombstones,
};
use crate::{Change, FsSink, OpenError, SinkConfig};

/// A harness holding a received (unpublished) transfer of `entries()`
/// with `selection`.
fn received(id: u8, selection: &[u32]) -> AnyResult<(Harness, CanonicalManifest, PathBuf)> {
    let fixture = fixture()?;
    let manifest = build_manifest(&fixture, [id; 16], &entries(), 3600)?;
    let consented = Consented::new(&fixture, &manifest, &entries(), selection, false, id)?;
    let mut harness = Harness::new()?;
    receive_all(harness.sink()?, &consented, selection)?;
    let dir = harness.transfer_dir(manifest.transfer_id());
    Ok((harness, manifest, dir))
}

fn journal(dir: &Path) -> AnyResult<Vec<u8>> {
    Ok(std::fs::read(dir.join("journal"))?)
}

/// Reopens and reports whether the transfer is still retained, and
/// whether its directory still exists.
fn survives(harness: &mut Harness, manifest: &CanonicalManifest) -> AnyResult<(bool, bool)> {
    harness.reopen(WALL)?;
    let retained = harness
        .sink()?
        .retained(manifest.transfer_id(), time(WALL)?)
        .is_some();
    Ok((
        retained,
        harness.transfer_dir(manifest.transfer_id()).exists(),
    ))
}

/// Records that are missing, oversized, or disagree with each other are
/// damage: the transfer is deleted at start-up rather than published
/// under names or a manifest nobody consented to.
#[test]
fn missing_oversized_or_inconsistent_records_are_damage() -> TestResult {
    type Damage = fn(&Path) -> AnyResult<()>;
    let damages: [(&str, Damage); 4] = [
        ("journal missing", |dir| {
            std::fs::remove_file(dir.join("journal"))?;
            Ok(())
        }),
        ("journal over 64 MiB", |dir| {
            std::fs::OpenOptions::new()
                .write(true)
                .open(dir.join("journal"))?
                .set_len((64 << 20) + 1)?;
            Ok(())
        }),
        ("manifest missing", |dir| {
            std::fs::remove_file(dir.join("manifest"))?;
            Ok(())
        }),
        ("manifest over 64 MiB", |dir| {
            std::fs::OpenOptions::new()
                .write(true)
                .open(dir.join("manifest"))?
                .set_len((64 << 20) + 1)?;
            Ok(())
        }),
    ];
    for (what, damage) in damages {
        let (mut harness, manifest, dir) = received(80, &FILES)?;
        harness.sink = None;
        damage(&dir)?;
        assert_eq!(survives(&mut harness, &manifest)?, (false, false), "{what}");
    }
    Ok(())
}

/// The manifest must be the one the journal names, and the journal must
/// be the one of the directory it is in.
#[test]
fn records_must_belong_to_their_transfer() -> TestResult {
    // Another valid manifest in place of the consented one.
    let (mut harness, manifest, dir) = received(81, &FILES)?;
    harness.sink = None;
    let fixture = fixture()?;
    let mut changed = entries();
    if let Some(entry) = changed.last_mut() {
        entry.content = Some(content(100, 5));
    }
    let other = build_manifest(&fixture, [81; 16], &changed, 3600)?;
    std::fs::write(dir.join("manifest"), other.bytes())?;
    assert_eq!(survives(&mut harness, &manifest)?, (false, false));
    // A copy of a transfer's records under another transfer's directory
    // name.
    let (mut harness, manifest, dir) = received(82, &FILES)?;
    harness.sink = None;
    let elsewhere = harness.transfer_dir(&[83; 16]);
    std::fs::create_dir(&elsewhere)?;
    for entry in std::fs::read_dir(&dir)? {
        let entry = entry?;
        std::fs::copy(entry.path(), elsewhere.join(entry.file_name()))?;
    }
    harness.reopen(WALL)?;
    assert!(!elsewhere.exists());
    assert!(dir.exists());
    let sink = harness.sink()?;
    assert!(sink.retained(&[83; 16], time(WALL)?).is_none());
    assert!(sink.retained(manifest.transfer_id(), time(WALL)?).is_some());
    Ok(())
}

/// Every directory on a selected file's path needs its consented name: a
/// journal holding only the files' names is damage.
#[test]
fn a_journal_missing_a_directory_name_is_damage() -> TestResult {
    let (mut harness, manifest, dir) = received(84, &FILES)?;
    harness.sink = None;
    let (header, journaled, _) = decode_journal(&journal(&dir)?).map_err(|_| "journal")?;
    let mut bytes = header.encode();
    for entry in journaled {
        if let JournalEntry::Planned { id, .. } = entry
            && !FILES.contains(&id)
        {
            continue;
        }
        bytes.extend_from_slice(&entry.encode());
    }
    std::fs::write(dir.join("journal"), &bytes)?;
    assert_eq!(survives(&mut harness, &manifest)?, (false, false));
    Ok(())
}

/// A publication journaled for a file outside the selection is ignored,
/// even where a file with the right content sits at that name.
#[test]
fn a_publication_outside_the_selection_is_ignored() -> TestResult {
    let (mut harness, manifest, dir) = received(85, &[2])?;
    harness.sink = None;
    let mut bytes = journal(&dir)?;
    bytes.extend_from_slice(
        &JournalEntry::Published {
            id: 6,
            name: "c.txt".to_owned(),
        }
        .encode(),
    );
    std::fs::write(dir.join("journal"), &bytes)?;
    std::fs::write(harness.dest.path().join("c.txt"), content(100, 4))?;
    assert_eq!(survives(&mut harness, &manifest)?, (true, true));
    let sink = harness.sink()?;
    assert!(sink.published_path(manifest.transfer_id(), 6).is_none());
    assert!(!sink.published_intact(&manifest, 6));
    Ok(())
}

/// A cancel whose tombstone reached the disk but whose quarantine a crash
/// left behind: start-up deletes the quarantine.
#[test]
fn a_tombstoned_transfer_found_at_start_up_is_deleted() -> TestResult {
    let (mut harness, manifest, dir) = received(86, &FILES)?;
    harness.sink = None;
    let until = WALL + 7200;
    std::fs::write(
        harness.state.path().join("tombstones"),
        encode_tombstones(&[(*manifest.transfer_id(), until)]),
    )?;
    assert_eq!(survives(&mut harness, &manifest)?, (false, false));
    assert!(!dir.exists());
    assert!(
        harness
            .sink()?
            .is_tombstoned(manifest.transfer_id(), time(WALL)?)
    );
    Ok(())
}

/// A tombstone list that exists but cannot be read is not taken as an
/// empty one: the sink does not open.
#[test]
fn an_unreadable_tombstone_list_fails_closed() -> TestResult {
    let mut harness = Harness::new()?;
    harness.sink = None;
    std::fs::create_dir(harness.state.path().join("tombstones"))?;
    let opened = FsSink::open(
        harness.state.path(),
        DirDestination::open(harness.dest.path())?,
        sealer(7),
        SinkConfig::default(),
        time(WALL)?,
    );
    assert!(matches!(opened, Err(OpenError::Io(_))), "{opened:?}");
    Ok(())
}

/// A finished transfer needs only its journal: without its manifest it is
/// kept, and its published files are still checked against the manifest
/// the engine passes.
#[test]
fn a_finished_transfer_needs_only_its_journal() -> TestResult {
    let (mut harness, manifest, dir) = received(87, &FILES)?;
    for file_id in FILES {
        harness.sink()?.publish(&manifest, file_id)?;
    }
    harness.sink()?.finish(manifest.transfer_id());
    harness.sink = None;
    std::fs::remove_file(dir.join("manifest"))?;
    assert_eq!(survives(&mut harness, &manifest)?, (true, true));
    let sink = harness.sink()?;
    for file_id in FILES {
        assert!(sink.published_intact(&manifest, file_id), "{file_id}");
    }
    std::fs::remove_dir_all(harness.dest.path().join("photos"))?;
    let sink = harness.sink()?;
    assert!(!sink.published_intact(&manifest, 2));
    // Checking does not create anything.
    assert!(!harness.dest.path().join("photos").exists());
    Ok(())
}

/// A torn tail is cut before the next entry is appended, so the entry
/// written after a crash is read back after the next one.
#[test]
fn a_torn_tail_is_cut_before_the_next_entry() -> TestResult {
    let (mut harness, manifest, dir) = received(88, &FILES)?;
    harness.sink = None;
    let mut bytes = journal(&dir)?;
    bytes.extend_from_slice(&[2, 0, 0, 0]);
    std::fs::write(dir.join("journal"), &bytes)?;
    harness.reopen(WALL)?;
    let fixture = fixture()?;
    let resumed = Consented::new(&fixture, &manifest, &entries(), &FILES, true, 88)?;
    let sink = harness.sink()?;
    sink.record_accept(&manifest, &resumed.accept)?;
    let six = resumed.accept.file(6).ok_or("file")?;
    sink.record_file_key(&six, &resumed.master(6)?)?;
    sink.publish(&manifest, 6)?;
    harness.sink = None;
    let bytes = journal(&dir)?;
    let (_, journaled, valid) = decode_journal(&bytes).map_err(|_| "journal")?;
    assert_eq!(valid, bytes.len());
    assert!(journaled.contains(&JournalEntry::Published {
        id: 6,
        name: "c.txt".to_owned()
    }));
    harness.reopen(WALL)?;
    assert!(harness.sink()?.published_intact(&manifest, 6));
    Ok(())
}

/// A journal at its entry bound takes no further entry (one more would be
/// read back as damage and lose the transfer): the publication is
/// reported as a storage failure and the journal stays readable.
#[test]
fn a_journal_at_its_entry_bound_takes_no_more() -> TestResult {
    let (mut harness, manifest, dir) = received(89, &FILES)?;
    harness.sink = None;
    let mut bytes = journal(&dir)?;
    let (_, journaled, _) = decode_journal(&bytes).map_err(|_| "journal")?;
    let filler = JournalEntry::Planned {
        id: 6,
        name: "c.txt".to_owned(),
    }
    .encode();
    for _ in journaled.len()..MAX_JOURNAL_ENTRIES {
        bytes.extend_from_slice(&filler);
    }
    std::fs::write(dir.join("journal"), &bytes)?;
    harness.reopen(WALL)?;
    let fixture = fixture()?;
    let resumed = Consented::new(&fixture, &manifest, &entries(), &FILES, true, 89)?;
    let sink = harness.sink()?;
    sink.record_accept(&manifest, &resumed.accept)?;
    let six = resumed.accept.file(6).ok_or("file")?;
    sink.record_file_key(&six, &resumed.master(6)?)?;
    assert_eq!(sink.publish(&manifest, 6), Err(SinkError::Storage));
    assert_eq!(journal(&dir)?, bytes);
    assert_eq!(survives(&mut harness, &manifest)?, (true, true));
    Ok(())
}

/// After a restart, a top-level name that differs from the sanitized
/// manifest name still shows why: the destination held it at consent.
#[test]
fn a_consented_suffix_is_explained_after_a_restart() -> TestResult {
    let fixture = fixture()?;
    let manifest = build_manifest(&fixture, [90; 16], &entries(), 3600)?;
    let consented = Consented::new(&fixture, &manifest, &entries(), &FILES, false, 90)?;
    let mut harness = Harness::new()?;
    std::fs::create_dir(harness.dest.path().join("photos"))?;
    receive_all(harness.sink()?, &consented, &FILES)?;
    harness.sink()?.publish(&manifest, 6)?;
    harness.reopen(WALL)?;
    let sink = harness.sink()?;
    let plan = sink.plan(manifest.transfer_id()).ok_or("plan")?;
    let photos = plan.entry(1).ok_or("entry")?;
    assert_eq!(photos.local().as_str(), "photos (2)");
    assert_eq!(photos.changes(), [Change::Exists]);
    let six = plan.entry(6).ok_or("entry")?;
    assert_eq!(six.changes(), []);
    // Published under its consented name: nothing to report.
    assert!(sink.published_path(manifest.transfer_id(), 6).is_some());
    assert!(sink.renamed(manifest.transfer_id(), 6).is_none());
    Ok(())
}
