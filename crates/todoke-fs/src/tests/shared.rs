//! Handles held across calls: a `SharedSink` whose lock was poisoned fails
//! closed, the origin marker runs on the staged file before publication
//! and can stop it, and `FsSource` serves only regular files it holds.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

use todoke_transfer::{ReceiveSink, SendSource, SinkError, SinkRefusal, SourceError};

use super::sink::{FILES, Harness, entries, files_below, receive_all};
use super::support::*;
use super::*;
use crate::dest::{DestError, DirDestination, OriginMarker};
use crate::{FsSink, FsSource, SharedSink, SinkConfig};

/// A shared sink whose lock a panicking holder poisoned takes nothing
/// new, counts every transfer as cancelled and none as retained, and
/// writes nothing.
#[test]
fn a_poisoned_shared_sink_fails_closed() -> TestResult {
    let fixture = fixture()?;
    let manifest = build_manifest(&fixture, [0xc0; 16], &entries(), 3600)?;
    let consented = Consented::new(&fixture, &manifest, &entries(), &FILES, false, 0xc0)?;
    let mut harness = Harness::new()?;
    let transfer_id = *manifest.transfer_id();
    receive_all(harness.sink()?, &consented, &[6])?;
    let sink = harness.sink.take().ok_or("sink")?;
    let mut shared = SharedSink::new(sink);
    // Before: calls pass through.
    let now = time(WALL)?;
    shared.tombstone(&[0xc1; 16], time(WALL + 7200)?);
    assert!(shared.is_tombstoned(&[0xc1; 16], now));
    assert!(!shared.is_tombstoned(&transfer_id, now));
    assert!(shared.tombstone_room(now));
    assert!(shared.retained(&transfer_id, now).is_some());
    shared.revoke_sender(&fixture.bob.key(), time(WALL + 7200)?);
    assert!(shared.retained(&transfer_id, now).is_some());
    shared.drop_segment(&transfer_id, 6, 0);
    assert_eq!(shared.retained_segment(&transfer_id, 6, 0)?, None);
    shared.finish(&[0xc1; 16]);
    // A holder of the lock unwinds (a panic elsewhere), poisoning it.
    let holder = shared.clone();
    let unwound = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = holder.lock();
        std::panic::resume_unwind(Box::new("poisons the lock"));
    }));
    assert!(unwound.is_err());
    assert!(shared.lock().is_err());
    assert_eq!(
        shared.check_offer(&manifest),
        Err(SinkRefusal::UnsupportedDestination)
    );
    assert!(shared.is_tombstoned(&transfer_id, now));
    assert!(shared.is_tombstoned(&[0xc2; 16], now));
    assert!(!shared.tombstone_room(now));
    assert!(shared.retained(&transfer_id, now).is_none());
    assert_eq!(
        shared.record_accept(&manifest, &consented.accept),
        Err(SinkError::Storage)
    );
    let six = consented.accept.file(6).ok_or("file")?;
    assert_eq!(
        shared.record_file_key(&six, &consented.master(6)?),
        Err(SinkError::Storage)
    );
    assert_eq!(
        shared.retained_segment(&transfer_id, 6, 0),
        Err(SinkError::Storage)
    );
    let ciphertext = consented.ciphertext(6, 0)?;
    let segment = consented.verified(6, 0, &ciphertext)?;
    assert_eq!(
        shared.store_segment(&segment, &ciphertext),
        Err(SinkError::Storage)
    );
    assert_eq!(shared.publish(&manifest, 6), Err(SinkError::Storage));
    assert!(!shared.published_intact(&manifest, 6));
    shared.drop_segment(&transfer_id, 6, 0);
    shared.finish(&transfer_id);
    shared.tombstone(&transfer_id, time(WALL + 7200)?);
    shared.revoke_sender(&fixture.alice.key(), time(WALL + 7200)?);
    // None of it reached the disk.
    assert!(harness.transfer_dir(&transfer_id).join("k6").exists());
    assert_eq!(files_below(harness.dest.path())?, Vec::<PathBuf>::new());
    Ok(())
}

/// Records each file it marks: where, and how long the file was.
struct Recorder {
    seen: Arc<Mutex<Vec<(PathBuf, u64)>>>,
    fail: bool,
}

impl OriginMarker for Recorder {
    fn mark(&self, file: &std::fs::File, path: &Path) -> Result<(), DestError> {
        let len = file.metadata()?.len();
        self.seen
            .lock()
            .map_err(|_| DestError::Io(std::io::ErrorKind::Other))?
            .push((path.to_owned(), len));
        if self.fail {
            return Err(DestError::Io(std::io::ErrorKind::PermissionDenied));
        }
        Ok(())
    }
}

/// The origin marker (Mark of the Web, `com.apple.quarantine`) marks the
/// complete staged file under its temporary name before it is published;
/// a marker that fails stops the publication, and nothing is published.
#[test]
fn the_origin_marker_runs_before_publication_and_can_stop_it() -> TestResult {
    let fixture = fixture()?;
    let manifest = build_manifest(&fixture, [0xc3; 16], &entries(), 3600)?;
    let consented = Consented::new(&fixture, &manifest, &entries(), &FILES, false, 0xc3)?;
    for fail in [false, true] {
        let (state, dest) = (TempDir::new()?, TempDir::new()?);
        let seen = Arc::new(Mutex::new(Vec::new()));
        let destination =
            DirDestination::open(dest.path())?.with_origin_marker(Box::new(Recorder {
                seen: Arc::clone(&seen),
                fail,
            }));
        let root = destination.root_path().to_owned();
        let mut sink = FsSink::open(
            state.path(),
            destination,
            sealer(7),
            SinkConfig::default(),
            time(WALL)?,
        )?;
        receive_all(&mut sink, &consented, &[6])?;
        let published = sink.publish(&manifest, 6);
        let marked = seen.lock().map_err(|_| "lock")?.clone();
        assert_eq!(marked.len(), 1);
        let (path, len) = marked.first().ok_or("marked")?;
        assert_eq!(path.parent(), Some(root.as_path()));
        assert!(
            path.file_name()
                .is_some_and(|name| name.to_string_lossy().starts_with(".todoke-"))
        );
        assert_eq!(*len, 100);
        if fail {
            assert_eq!(published, Err(SinkError::Storage));
            assert_eq!(files_below(dest.path())?, Vec::<PathBuf>::new());
        } else {
            published?;
            assert_eq!(std::fs::read(dest.path().join("c.txt"))?, content(100, 4));
        }
    }
    Ok(())
}

/// The sender prepares only regular files, and serves only prepared ones.
#[test]
fn sources_are_regular_files_that_were_prepared() -> TestResult {
    let temp = TempDir::new()?;
    let mut source = FsSource::new(&temp.path().join("state"))?;
    std::fs::create_dir(temp.path().join("folder"))?;
    assert_eq!(
        source.prepare(&temp.path().join("folder")).map(|_| ()),
        Err(SourceError::Io(std::io::ErrorKind::InvalidInput))
    );
    assert_eq!(
        source.prepare(&temp.path().join("missing")).map(|_| ()),
        Err(SourceError::NotFound)
    );
    assert!(matches!(
        source.open(&[1; 16], 1),
        Err(SourceError::NotFound)
    ));
    // No outboard is left behind by a refused preparation.
    assert_eq!(
        files_below(&temp.path().join("state").join("outboards"))?,
        Vec::<PathBuf>::new()
    );
    Ok(())
}
