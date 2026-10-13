//! The sink's gates, each checked from both sides: keys, publication, and
//! re-verification only under the recorded consent (the Accept, its
//! manifest, its selection, and this session's keys); sealed masters that
//! open only for their own file and manifest; Accepts that must match
//! their manifest and the root they will publish into; and the quota at
//! its exact bound.

use std::path::PathBuf;

use todoke_crypto::consent::CanonicalManifest;
use todoke_crypto::identity::SoftwareSealer;
use todoke_transfer::{ReceiveSink, SinkError, SinkRefusal, TransferId};

use super::race::Hooked;
use super::sink::{FILES, Harness, entries, files_below, receive_all};
use super::support::*;
use super::*;
use crate::dest::DirDestination;
use crate::quarantine::codec::{JournalEntry, decode_journal};
use crate::{FsSink, SinkConfig};

/// `entries()` with other content in `c.txt` (file 6): under the same
/// transfer ID, a manifest with another hash.
fn other_entries() -> Vec<Entry> {
    let mut changed = entries();
    if let Some(entry) = changed.last_mut() {
        entry.content = Some(content(100, 5));
    }
    changed
}

/// The manifest of `entries()` under `id` and, under the same ID, the
/// one of `other_entries()`.
fn manifests(fixture: &Fixture, id: u8) -> AnyResult<(CanonicalManifest, CanonicalManifest)> {
    Ok((
        build_manifest(fixture, [id; 16], &entries(), 3600)?,
        build_manifest(fixture, [id; 16], &other_entries(), 3600)?,
    ))
}

fn transfer_dir(harness: &Harness, manifest: &CanonicalManifest) -> PathBuf {
    harness.transfer_dir(manifest.transfer_id())
}

/// A key is kept only for a selected file of the recorded Accept's
/// manifest: before any Accept, for another manifest under the same ID,
/// or for a file outside the selection, it is refused and no sealed master
/// is written.
#[test]
fn keys_are_refused_outside_the_recorded_consent() -> TestResult {
    let fixture = fixture()?;
    let (manifest, other) = manifests(&fixture, 60)?;
    let only_six = Consented::new(&fixture, &manifest, &entries(), &[6], false, 60)?;
    let all = Consented::new(&fixture, &manifest, &entries(), &FILES, false, 60)?;
    let changed = Consented::new(&fixture, &other, &other_entries(), &FILES, false, 61)?;
    let mut harness = Harness::new()?;
    let dir = transfer_dir(&harness, &manifest);
    let sink = harness.sink()?;
    let six = all.accept.file(6).ok_or("file")?;
    assert_eq!(
        sink.record_file_key(&six, &all.master(6)?),
        Err(SinkError::Storage)
    );
    assert!(!dir.exists());
    sink.check_offer(&manifest)
        .map_err(|refusal| format!("{refusal:?}"))?;
    sink.record_accept(&manifest, &only_six.accept)?;
    let two = all.accept.file(2).ok_or("file")?;
    assert_eq!(
        sink.record_file_key(&two, &all.master(2)?),
        Err(SinkError::Storage)
    );
    let changed_six = changed.accept.file(6).ok_or("file")?;
    assert_eq!(
        sink.record_file_key(&changed_six, &changed.master(6)?),
        Err(SinkError::Storage)
    );
    assert!(!dir.join("k2").exists() && !dir.join("k6").exists());
    // The consented key is kept.
    let six = only_six.accept.file(6).ok_or("file")?;
    sink.record_file_key(&six, &only_six.master(6)?)?;
    assert!(dir.join("k6").exists());
    Ok(())
}

/// Publication and re-verification answer only for the recorded manifest
/// and its selected files; a published file must have its exact length
/// and hash.
#[test]
fn publication_answers_only_for_the_recorded_manifest_and_selection() -> TestResult {
    let fixture = fixture()?;
    let (manifest, other) = manifests(&fixture, 61)?;
    let only_six = Consented::new(&fixture, &manifest, &entries(), &[6], false, 61)?;
    let mut harness = Harness::new()?;
    let dest = harness.dest.path().to_owned();
    receive_all(harness.sink()?, &only_six, &[6])?;
    let sink = harness.sink()?;
    assert_eq!(sink.publish(&other, 6), Err(SinkError::Storage));
    assert_eq!(sink.publish(&manifest, 2), Err(SinkError::Storage));
    assert!(sink.publish(&manifest, 99).is_err());
    assert_eq!(files_below(&dest)?, Vec::<PathBuf>::new());
    sink.publish(&manifest, 6)?;
    assert!(sink.published_intact(&manifest, 6));
    assert!(!sink.published_intact(&other, 6));
    // Another manifest under this ID whose file 6 is the same: still not
    // the consented one.
    let mut same_six = entries();
    if let Some(entry) = same_six.get_mut(1) {
        entry.content = Some(content(40_000, 9));
    }
    let same_six = build_manifest(&fixture, [61; 16], &same_six, 3600)?;
    assert_eq!(
        same_six.file(6).map(|file| *file.root()),
        manifest.file(6).map(|file| *file.root())
    );
    let sink = harness.sink()?;
    assert!(!sink.published_intact(&same_six, 6));
    assert!(!sink.published_intact(&manifest, 2));
    // One byte short.
    std::fs::write(dest.join("c.txt"), &content(100, 4)[..99])?;
    assert!(!sink.published_intact(&manifest, 6));
    std::fs::write(dest.join("c.txt"), content(100, 4))?;
    assert!(sink.published_intact(&manifest, 6));
    Ok(())
}

/// Each sealed master opens only under its own file and manifest: one
/// moved to another file's place, or kept from an earlier manifest under
/// the same transfer ID, fails publication as a storage error, before any
/// content is decrypted.
#[test]
fn sealed_masters_open_only_for_their_own_file_and_manifest() -> TestResult {
    let fixture = fixture()?;
    let (manifest, other) = manifests(&fixture, 62)?;
    let first = Consented::new(&fixture, &manifest, &entries(), &FILES, false, 62)?;
    let mut harness = Harness::new()?;
    let dest = harness.dest.path().to_owned();
    let dir = transfer_dir(&harness, &manifest);
    receive_all(harness.sink()?, &first, &FILES)?;
    let honest = std::fs::read(dir.join("k6"))?;
    std::fs::copy(dir.join("k2"), dir.join("k6"))?;
    assert_eq!(
        harness.sink()?.publish(&manifest, 6),
        Err(SinkError::Storage)
    );
    assert!(!dest.join("c.txt").exists());
    // A master of the earlier manifest under the same transfer ID.
    let second = Consented::new(&fixture, &other, &other_entries(), &FILES, false, 63)?;
    let sink = harness.sink()?;
    sink.check_offer(&other)
        .map_err(|refusal| format!("{refusal:?}"))?;
    sink.record_accept(&other, &second.accept)?;
    let six = second.accept.file(6).ok_or("file")?;
    sink.record_file_key(&six, &second.master(6)?)?;
    let ciphertext = second.ciphertext(6, 0)?;
    sink.store_segment(&second.verified(6, 0, &ciphertext)?, &ciphertext)?;
    let current = std::fs::read(dir.join("k6"))?;
    std::fs::write(dir.join("k6"), &honest)?;
    assert_eq!(harness.sink()?.publish(&other, 6), Err(SinkError::Storage));
    assert!(!dest.join("c.txt").exists());
    // Its own master publishes.
    std::fs::write(dir.join("k6"), &current)?;
    harness.sink()?.publish(&other, 6)?;
    assert_eq!(std::fs::read(dest.join("c.txt"))?, content(100, 5));
    Ok(())
}

/// An Accept is recorded only with its own manifest.
#[test]
fn an_accept_is_recorded_only_with_its_own_manifest() -> TestResult {
    let fixture = fixture()?;
    let (manifest, other) = manifests(&fixture, 63)?;
    let unrelated = build_manifest(&fixture, [64; 16], &entries(), 3600)?;
    let consented = Consented::new(&fixture, &manifest, &entries(), &FILES, false, 63)?;
    let mut harness = Harness::new()?;
    let sink = harness.sink()?;
    for offered in [&manifest, &other, &unrelated] {
        sink.check_offer(offered)
            .map_err(|refusal| format!("{refusal:?}"))?;
    }
    assert_eq!(
        sink.record_accept(&other, &consented.accept),
        Err(SinkError::Storage)
    );
    assert_eq!(
        sink.record_accept(&unrelated, &consented.accept),
        Err(SinkError::Storage)
    );
    assert!(!harness.transfer_dir(unrelated.transfer_id()).exists());
    assert!(!transfer_dir(&harness, &manifest).exists());
    harness
        .sink()?
        .record_accept(&manifest, &consented.accept)?;
    assert!(transfer_dir(&harness, &manifest).exists());
    Ok(())
}

/// A resumed session's Accept replaces the last session's consent: files
/// are published only after this session's key for them.
#[test]
fn consent_does_not_carry_over_to_a_resumed_session() -> TestResult {
    let fixture = fixture()?;
    let manifest = build_manifest(&fixture, [65; 16], &entries(), 3600)?;
    let first = Consented::new(&fixture, &manifest, &entries(), &FILES, false, 65)?;
    let resumed = Consented::new(&fixture, &manifest, &entries(), &FILES, true, 65)?;
    let mut harness = Harness::new()?;
    receive_all(harness.sink()?, &first, &FILES)?;
    let sink = harness.sink()?;
    sink.record_accept(&manifest, &resumed.accept)?;
    assert_eq!(sink.publish(&manifest, 6), Err(SinkError::Storage));
    assert!(!harness.dest.path().join("c.txt").exists());
    let sink = harness.sink()?;
    let six = resumed.accept.file(6).ok_or("file")?;
    sink.record_file_key(&six, &resumed.master(6)?)?;
    sink.publish(&manifest, 6)?;
    assert_eq!(
        std::fs::read(harness.dest.path().join("c.txt"))?,
        content(100, 4)
    );
    Ok(())
}

/// A new selection under a retained transfer ID starts over: nothing of
/// the earlier selection's quarantine carries over.
#[test]
fn a_new_selection_under_a_retained_id_starts_over() -> TestResult {
    let fixture = fixture()?;
    let manifest = build_manifest(&fixture, [66; 16], &entries(), 3600)?;
    let first = Consented::new(&fixture, &manifest, &entries(), &[6], false, 66)?;
    let wider = Consented::new(&fixture, &manifest, &entries(), &[3, 6], true, 66)?;
    let mut harness = Harness::new()?;
    let transfer_id: TransferId = *manifest.transfer_id();
    receive_all(harness.sink()?, &first, &[6])?;
    let sink = harness.sink()?;
    sink.check_offer(&manifest)
        .map_err(|refusal| format!("{refusal:?}"))?;
    sink.record_accept(&manifest, &wider.accept)?;
    let retained = sink.retained(&transfer_id, time(WALL)?).ok_or("retained")?;
    assert_eq!(retained.selection, [3, 6]);
    assert_eq!(sink.retained_segment(&transfer_id, 6, 0)?, None);
    assert!(!transfer_dir(&harness, &manifest).join("k6").exists());
    Ok(())
}

/// The quota admits a selection that needs exactly what is free and
/// refuses one byte more, both at the offer (its smallest storable file)
/// and at the Accept (the whole selection). A retained transfer offered
/// again is not refused for the quota it already holds, and a finished
/// one holds none, also after a restart.
#[test]
fn the_quota_bound_is_exact() -> TestResult {
    let fixture = fixture()?;
    let manifest = build_manifest(&fixture, [67; 16], &entries(), 3600)?;
    let reserved = |selection: &[u32]| -> AnyResult<u64> {
        let consented = Consented::new(&fixture, &manifest, &entries(), selection, false, 67)?;
        let mut harness = Harness::new()?;
        let sink = harness.sink()?;
        sink.check_offer(&manifest)
            .map_err(|refusal| format!("{refusal:?}"))?;
        sink.record_accept(&manifest, &consented.accept)?;
        Ok(sink.reserved_bytes())
    };
    let needed = reserved(&FILES)?;
    let mut smallest = u64::MAX;
    for file_id in FILES {
        smallest = smallest.min(reserved(&[file_id])?);
    }
    assert!(smallest < needed);
    let consented = Consented::new(&fixture, &manifest, &entries(), &FILES, false, 67)?;
    let with_quota = |quota_bytes: u64| {
        Harness::with_config(SinkConfig {
            quota_bytes,
            ..SinkConfig::default()
        })
    };
    // The offer.
    assert_eq!(with_quota(smallest)?.sink()?.check_offer(&manifest), Ok(()));
    assert_eq!(
        with_quota(smallest - 1)?.sink()?.check_offer(&manifest),
        Err(SinkRefusal::Quota)
    );
    // The Accept.
    let mut short = with_quota(needed - 1)?;
    short
        .sink()?
        .check_offer(&manifest)
        .map_err(|refusal| format!("{refusal:?}"))?;
    assert_eq!(
        short.sink()?.record_accept(&manifest, &consented.accept),
        Err(SinkError::Storage)
    );
    let mut exact = with_quota(needed)?;
    receive_all(exact.sink()?, &consented, &FILES)?;
    assert_eq!(exact.sink()?.reserved_bytes(), needed);
    // Full: another offer is refused, the retained one is not.
    let unrelated = build_manifest(&fixture, [68; 16], &entries(), 3600)?;
    assert_eq!(
        exact.sink()?.check_offer(&unrelated),
        Err(SinkRefusal::Quota)
    );
    assert_eq!(exact.sink()?.check_offer(&manifest), Ok(()));
    // Finished: nothing is held, now and after a restart.
    for file_id in FILES {
        exact.sink()?.publish(&manifest, file_id)?;
    }
    exact.sink()?.finish(manifest.transfer_id());
    assert_eq!(exact.sink()?.reserved_bytes(), 0);
    exact.reopen(WALL + 1)?;
    assert_eq!(exact.sink()?.reserved_bytes(), 0);
    assert_eq!(exact.sink()?.check_offer(&unrelated), Ok(()));
    Ok(())
}

/// The end marker is journaled once, however often `finish` is called.
#[test]
fn the_end_marker_is_journaled_once() -> TestResult {
    let fixture = fixture()?;
    let manifest = build_manifest(&fixture, [69; 16], &entries(), 3600)?;
    let consented = Consented::new(&fixture, &manifest, &entries(), &FILES, false, 69)?;
    let mut harness = Harness::new()?;
    receive_all(harness.sink()?, &consented, &FILES)?;
    for file_id in FILES {
        harness.sink()?.publish(&manifest, file_id)?;
    }
    let transfer_id = *manifest.transfer_id();
    for _ in 0..3 {
        harness.sink()?.finish(&transfer_id);
    }
    harness.sink()?.finish(&[0x7f; 16]);
    let journal = std::fs::read(transfer_dir(&harness, &manifest).join("journal"))?;
    let (_, journaled, _) = decode_journal(&journal).map_err(|_| "journal")?;
    let ends = journaled
        .iter()
        .filter(|entry| matches!(entry, JournalEntry::Finished))
        .count();
    assert_eq!(ends, 1);
    Ok(())
}

/// The Accept journals the consented names of the selected files and of
/// the directories on their paths, and nothing else.
#[test]
fn the_accept_journals_exactly_the_consented_names() -> TestResult {
    let fixture = fixture()?;
    let manifest = build_manifest(&fixture, [70; 16], &entries(), 3600)?;
    let consented = Consented::new(&fixture, &manifest, &entries(), &[5], false, 70)?;
    let mut harness = Harness::new()?;
    let sink = harness.sink()?;
    sink.check_offer(&manifest)
        .map_err(|refusal| format!("{refusal:?}"))?;
    sink.record_accept(&manifest, &consented.accept)?;
    let journal = std::fs::read(transfer_dir(&harness, &manifest).join("journal"))?;
    let (_, journaled, _) = decode_journal(&journal).map_err(|_| "journal")?;
    let planned: Vec<(u32, String)> = journaled
        .iter()
        .filter_map(|entry| match entry {
            JournalEntry::Planned { id, name } => Some((*id, name.clone())),
            _ => None,
        })
        .collect();
    assert_eq!(
        planned,
        [
            (1, "photos".to_owned()),
            (4, "deep".to_owned()),
            (5, "b.bin".to_owned())
        ]
    );
    Ok(())
}

/// A hooked sink with its state and destination directories and hooks.
type HookedSink = (
    TempDir,
    TempDir,
    FsSink<Hooked, SoftwareSealer>,
    std::rc::Rc<super::race::Hooks>,
);

/// A sink over a hooked destination, with an offer for `manifest` made.
fn hooked(manifest: &CanonicalManifest) -> AnyResult<HookedSink> {
    let (state, dest) = (TempDir::new()?, TempDir::new()?);
    let (destination, hooks) = Hooked::new(DirDestination::open(dest.path())?);
    let mut sink = FsSink::open(
        state.path(),
        destination,
        sealer(7),
        SinkConfig::default(),
        time(WALL)?,
    )?;
    sink.check_offer(manifest)
        .map_err(|refusal| format!("{refusal:?}"))?;
    Ok((state, dest, sink, hooks))
}

/// An Accept whose destination root cannot be held (gone, or replaced by
/// a junction) is refused, leaves nothing behind, and lets the root go.
#[test]
fn an_accept_is_refused_when_the_root_cannot_be_held() -> TestResult {
    let fixture = fixture()?;
    let manifest = build_manifest(&fixture, [71; 16], &entries(), 3600)?;
    let consented = Consented::new(&fixture, &manifest, &entries(), &FILES, false, 71)?;
    let (state, _dest, mut sink, hooks) = hooked(&manifest)?;
    hooks.fail_hold.set(true);
    assert_eq!(
        sink.record_accept(&manifest, &consented.accept),
        Err(SinkError::Storage)
    );
    assert_eq!(hooks.held.get(), Some(false));
    assert!(sink.retained(manifest.transfer_id(), time(WALL)?).is_none());
    assert_eq!(
        files_below(&state.path().join("transfers"))?,
        Vec::<PathBuf>::new()
    );
    hooks.fail_hold.set(false);
    sink.record_accept(&manifest, &consented.accept)?;
    assert_eq!(hooks.held.get(), Some(true));
    Ok(())
}

/// An Accept whose records cannot be written is refused, nothing is
/// retained, and the root is let go.
#[test]
fn an_accept_whose_records_cannot_be_written_leaves_nothing() -> TestResult {
    let fixture = fixture()?;
    let manifest = build_manifest(&fixture, [72; 16], &entries(), 3600)?;
    let consented = Consented::new(&fixture, &manifest, &entries(), &FILES, false, 72)?;
    let (state, _dest, mut sink, hooks) = hooked(&manifest)?;
    let dir = state
        .path()
        .join("transfers")
        .join(crate::quarantine::store::hex(manifest.transfer_id()));
    // Something that is not a directory where the transfer's directory
    // goes: no record can be written.
    std::fs::write(&dir, b"in the way")?;
    assert_eq!(
        sink.record_accept(&manifest, &consented.accept),
        Err(SinkError::Storage)
    );
    assert_eq!(
        files_below(&state.path().join("transfers"))?,
        core::slice::from_ref(&dir)
    );
    assert_eq!(hooks.held.get(), Some(false));
    assert!(sink.retained(manifest.transfer_id(), time(WALL)?).is_none());
    std::fs::remove_file(&dir)?;
    sink.record_accept(&manifest, &consented.accept)?;
    assert!(dir.join("journal").exists());
    Ok(())
}

/// The root stays held while any transfer is retained: cancelling one of
/// two keeps it.
#[test]
fn the_root_stays_held_while_another_transfer_is_retained() -> TestResult {
    let fixture = fixture()?;
    let first = build_manifest(&fixture, [73; 16], &entries(), 3600)?;
    let second = build_manifest(&fixture, [74; 16], &entries(), 3600)?;
    let (_state, _dest, mut sink, hooks) = hooked(&first)?;
    for (manifest, seed) in [(&first, 73), (&second, 74)] {
        let consented = Consented::new(&fixture, manifest, &entries(), &FILES, false, seed)?;
        receive_all(&mut sink, &consented, &[6])?;
    }
    assert_eq!(hooks.held.get(), Some(true));
    sink.tombstone(first.transfer_id(), time(WALL + 7200)?);
    assert_eq!(hooks.held.get(), Some(true), "let go with a transfer left");
    sink.tombstone(second.transfer_id(), time(WALL + 7200)?);
    assert_eq!(hooks.held.get(), Some(false));
    Ok(())
}

/// Stored segments are served only for selected files of a retained
/// transfer, and a slots file that cannot be opened is a storage error,
/// not an absence.
#[test]
fn segments_are_served_only_for_selected_files() -> TestResult {
    let fixture = fixture()?;
    let manifest = build_manifest(&fixture, [75; 16], &entries(), 3600)?;
    let consented = Consented::new(&fixture, &manifest, &entries(), &[6], false, 75)?;
    let mut harness = Harness::new()?;
    let transfer_id = *manifest.transfer_id();
    receive_all(harness.sink()?, &consented, &[6])?;
    let sink = harness.sink()?;
    assert_eq!(
        sink.retained_segment(&transfer_id, 2, 0),
        Err(SinkError::Storage)
    );
    assert_eq!(
        sink.retained_segment(&[0x7e; 16], 6, 0),
        Err(SinkError::Storage)
    );
    assert_eq!(
        sink.retained_segment(&transfer_id, 6, 0)?,
        Some(consented.ciphertext(6, 0)?)
    );
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let slots = transfer_dir(&harness, &manifest).join("s6");
        std::fs::set_permissions(&slots, std::fs::Permissions::from_mode(0o000))?;
        if std::fs::read(&slots).is_ok() {
            eprintln!("skipping: this account reads files without permission (root)");
        } else {
            harness.reopen(WALL)?;
            assert_eq!(
                harness.sink()?.retained_segment(&transfer_id, 6, 0),
                Err(SinkError::Storage)
            );
        }
        std::fs::set_permissions(&slots, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}
