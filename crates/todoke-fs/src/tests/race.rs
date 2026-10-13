//! Races with a local attacker who can write the destination directory:
//! the temporary file replaced between staging and publication (finding
//! F1). Publication is bound to the staged file that was hashed, so a
//! substitute is never published, journaled, or acknowledged, and is left
//! untouched.

use core::cell::Cell;
use std::path::PathBuf;
use std::rc::Rc;

use todoke_crypto::identity::SoftwareSealer;
use todoke_transfer::{ReceiveSink, SinkError};

use super::sink::{FILES, entries, receive_all};
use super::support::*;
use super::*;
use crate::dest::{Atomicity, DestError, Destination, DirDestination, DirHandle, StagedFile};
use crate::quarantine::codec::{JournalEntry, decode_journal};
use crate::{FsSink, SinkConfig};

/// What replaces the temporary file just before publication.
#[derive(Clone, Debug)]
pub(crate) enum Plant {
    /// A regular file of the attacker's.
    File,
    /// A symbolic link to this target.
    Link(PathBuf),
}

/// A [`DirDestination`] that, at the first publication, removes the staged
/// temporary file by name and plants something else there, as anyone with
/// write access to the directory could (the name is visible to `readdir`).
/// `substituted` records whether that worked: on Windows it must not,
/// because the staged file is held without `FILE_SHARE_DELETE`.
pub(crate) struct Substituting {
    inner: DirDestination,
    plant: Plant,
    substituted: Rc<Cell<Option<bool>>>,
}

impl Substituting {
    pub(crate) fn new(inner: DirDestination, plant: Plant) -> (Self, Rc<Cell<Option<bool>>>) {
        let substituted = Rc::new(Cell::new(None));
        (
            Self {
                inner,
                plant,
                substituted: Rc::clone(&substituted),
            },
            substituted,
        )
    }

    fn substitute(&self, path: &std::path::Path) -> bool {
        if std::fs::remove_file(path).is_err() {
            return false;
        }
        match &self.plant {
            Plant::File => std::fs::write(path, b"planted").is_ok(),
            Plant::Link(target) => symlink_file(target, path).is_ok_and(|made| made.is_some()),
        }
    }
}

impl Destination for Substituting {
    type Dir = DirHandle;
    type Staged = StagedFile;
    type Reader = std::fs::File;

    fn root(&self) -> Result<DirHandle, DestError> {
        self.inner.root()
    }
    fn list(&self, dir: &DirHandle, limit: usize) -> Result<Option<Vec<String>>, DestError> {
        self.inner.list(dir, limit)
    }
    fn exists(&self, dir: &DirHandle, name: &str) -> Result<bool, DestError> {
        self.inner.exists(dir, name)
    }
    fn create_dir(&self, dir: &DirHandle, name: &str) -> Result<DirHandle, DestError> {
        self.inner.create_dir(dir, name)
    }
    fn open_dir(&self, dir: &DirHandle, name: &str) -> Result<DirHandle, DestError> {
        self.inner.open_dir(dir, name)
    }
    fn stage(&self, dir: &DirHandle, temp: &str) -> Result<StagedFile, DestError> {
        self.inner.stage(dir, temp)
    }
    fn finish_staged(&self, staged: &StagedFile) -> Result<(), DestError> {
        self.inner.finish_staged(staged)
    }
    fn publish(
        &self,
        dir: &DirHandle,
        staged: &StagedFile,
        temp: &str,
        name: &str,
    ) -> Result<Atomicity, DestError> {
        if self.substituted.get().is_none() {
            let done = self.substitute(&dir.path().join(temp));
            self.substituted.set(Some(done));
        }
        self.inner.publish(dir, staged, temp, name)
    }
    fn release(&self, dir: &DirHandle, staged: StagedFile, temp: &str) -> Result<(), DestError> {
        self.inner.release(dir, staged, temp)
    }
    fn discard(&self, dir: &DirHandle, temp: &str) -> Result<(), DestError> {
        self.inner.discard(dir, temp)
    }
    fn open_file(&self, dir: &DirHandle, name: &str) -> Result<std::fs::File, DestError> {
        self.inner.open_file(dir, name)
    }
    fn sync_dir(&self, dir: &DirHandle) -> Result<(), DestError> {
        self.inner.sync_dir(dir)
    }
    fn root_len(&self) -> usize {
        self.inner.root_len()
    }
}

/// The planted object, as the test expects to find it untouched.
fn assert_untouched(
    plant: &Plant,
    path: &std::path::Path,
    outside: &std::path::Path,
) -> TestResult {
    match plant {
        Plant::File => assert_eq!(std::fs::read(path)?, b"planted"),
        Plant::Link(target) => {
            assert!(std::fs::symlink_metadata(path)?.file_type().is_symlink());
            assert_eq!(&std::fs::read_link(path)?, target);
        }
    }
    assert_eq!(std::fs::read(outside.join("target"))?, b"outside");
    Ok(())
}

#[test]
fn a_temporary_file_replaced_before_publication_is_never_published() -> TestResult {
    let fixture = fixture()?;
    let manifest = build_manifest(&fixture, [19; 16], &entries(), 3600)?;
    let consented = Consented::new(&fixture, &manifest, &entries(), &FILES, false, 19)?;
    let transfer_id = *manifest.transfer_id();
    let outside = TempDir::new()?;
    std::fs::write(outside.path().join("target"), b"outside")?;
    for plant in [Plant::File, Plant::Link(outside.path().join("target"))] {
        let (state, dest) = (TempDir::new()?, TempDir::new()?);
        let (destination, substituted) =
            Substituting::new(DirDestination::open(dest.path())?, plant.clone());
        let mut sink: FsSink<Substituting, SoftwareSealer> = FsSink::open(
            state.path(),
            destination,
            sealer(7),
            SinkConfig::default(),
            time(WALL)?,
        )?;
        receive_all(&mut sink, &consented, &FILES)?;
        let result = sink.publish(&manifest, 6);
        if substituted.get() != Some(true) {
            if !cfg!(windows) {
                return Err("the staged file could not be replaced on this platform".into());
            }
            // Windows: the held handle made the substitution impossible,
            // and the honest file was published.
            result?;
            assert_eq!(std::fs::read(dest.path().join("c.txt"))?, content(100, 4));
            continue;
        }
        assert_eq!(result, Err(SinkError::Storage), "{plant:?}");
        // Nothing journaled as published, nothing reported.
        let journal_path = state
            .path()
            .join("transfers")
            .join(crate::quarantine::store::hex(&transfer_id))
            .join("journal");
        let journal = std::fs::read(&journal_path)?;
        let (header, journaled, _) = decode_journal(&journal).map_err(|_| "journal")?;
        assert!(
            !journaled
                .iter()
                .any(|entry| matches!(entry, JournalEntry::Published { .. })),
            "a substitute was journaled as published"
        );
        assert!(sink.published_path(&transfer_id, 6).is_none());
        assert!(sink.content_report(&transfer_id, 6).is_none());
        assert!(!sink.published_intact(&manifest, 6));
        assert!(!dest.path().join("c.txt").exists());
        // The substitute is exactly as planted, under the temporary name.
        let temp = dest.path().join(crate::sink::temp_name(&header, 6));
        assert_untouched(&plant, &temp, outside.path())?;
        // A retry does not remove or follow it either.
        assert_eq!(sink.publish(&manifest, 6), Err(SinkError::Storage));
        assert_untouched(&plant, &temp, outside.path())?;
        // The retained ciphertext stays for a later attempt.
        assert_eq!(
            sink.retained_segment(&transfer_id, 6, 0)?,
            Some(consented.ciphertext(6, 0)?)
        );
    }
    Ok(())
}

/// Windows: the staged file is created without `FILE_SHARE_DELETE` and
/// held until it is released, so its temporary name can be neither
/// renamed nor deleted (and so not replaced) in the meantime.
#[cfg(windows)]
#[test]
fn a_held_staged_file_cannot_be_renamed_or_deleted() -> TestResult {
    use std::io::Write as _;
    let temp = TempDir::new()?;
    let destination = DirDestination::open(temp.path())?;
    let root = destination.root()?;
    let mut staged = destination.stage(&root, ".t")?;
    staged.write_all(b"payload")?;
    destination.finish_staged(&staged)?;
    let path = temp.path().join(".t");
    assert!(std::fs::remove_file(&path).is_err(), "deleted while held");
    assert!(
        std::fs::rename(&path, temp.path().join("elsewhere")).is_err(),
        "renamed while held"
    );
    destination.publish(&root, &staged, ".t", "final")?;
    // The final name is a name of the held file too.
    assert!(std::fs::remove_file(temp.path().join("final")).is_err());
    destination.release(&root, staged, ".t")?;
    assert!(!path.exists());
    assert_eq!(std::fs::read(temp.path().join("final"))?, b"payload");
    Ok(())
}
