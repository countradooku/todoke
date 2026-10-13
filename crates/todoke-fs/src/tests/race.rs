//! Races with a local attacker who can write the destination directory,
//! and injected storage failures around publication.
//!
//! - The temporary file replaced between staging and publication:
//!   publication is bound to the staged file that was hashed, so a
//!   substitute is never published, journaled, or acknowledged, and is
//!   left untouched.
//! - A publication that succeeded but whose temporary name could not be
//!   removed, or whose directory sync failed: it is journaled anyway, so a
//!   resume never publishes a duplicate, and start-up removes only the
//!   leftover name.

use core::cell::{Cell, RefCell};
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

/// Behaviour a test switches on in a [`Hooked`] destination.
#[derive(Default)]
pub(crate) struct Hooks {
    /// Planted under the temporary name at the next publication, as
    /// anyone with write access to the directory could (the name is
    /// visible to `readdir`).
    pub(crate) plant: RefCell<Option<Plant>>,
    /// Whether planting worked: on Windows it must not, because the staged
    /// file is held without `FILE_SHARE_DELETE`.
    pub(crate) substituted: Cell<Option<bool>>,
    /// Publish with a hard link that keeps the temporary name, as the Unix
    /// link path and Windows do (APFS and ext4 would rename instead).
    pub(crate) link: Cell<bool>,
    /// `release` fails without removing the temporary name, as a failing
    /// `unlinkat` would.
    pub(crate) fail_release: Cell<bool>,
    /// `sync_dir` fails.
    pub(crate) fail_sync: Cell<bool>,
    /// What the sink last asked of `hold_root`.
    pub(crate) held: Cell<Option<bool>>,
    /// `hold_root(true)` fails, as for a root that is gone or was
    /// replaced by a junction.
    pub(crate) fail_hold: Cell<bool>,
    /// Names `create_dir` reports as taken, as if something appeared there
    /// just before.
    pub(crate) taken: RefCell<std::collections::BTreeSet<String>>,
}

/// A [`DirDestination`] with [`Hooks`] for races and injected failures.
pub(crate) struct Hooked {
    inner: DirDestination,
    hooks: Rc<Hooks>,
}

impl Hooked {
    pub(crate) fn new(inner: DirDestination) -> (Self, Rc<Hooks>) {
        let hooks = Rc::new(Hooks::default());
        (
            Self {
                inner,
                hooks: Rc::clone(&hooks),
            },
            hooks,
        )
    }

    /// A destination that plants `plant` at the first publication.
    pub(crate) fn substituting(inner: DirDestination, plant: Plant) -> (Self, Rc<Hooks>) {
        let (hooked, hooks) = Self::new(inner);
        *hooks.plant.borrow_mut() = Some(plant);
        (hooked, hooks)
    }

    fn substitute(path: &std::path::Path, plant: &Plant) -> bool {
        if std::fs::remove_file(path).is_err() {
            return false;
        }
        match plant {
            Plant::File => std::fs::write(path, b"planted").is_ok(),
            Plant::Link(target) => symlink_file(target, path).is_ok_and(|made| made.is_some()),
        }
    }
}

impl Destination for Hooked {
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
        if self.hooks.taken.borrow().contains(name) {
            return Err(DestError::Exists);
        }
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
        if let Some(plant) = self.hooks.plant.borrow_mut().take() {
            let done = Self::substitute(&dir.path().join(temp), &plant);
            self.hooks.substituted.set(Some(done));
        }
        if self.hooks.link.get() {
            return match std::fs::hard_link(dir.path().join(temp), dir.path().join(name)) {
                Ok(()) => Ok(Atomicity::Atomic),
                Err(error) => Err(DestError::from(error)),
            };
        }
        self.inner.publish(dir, staged, temp, name)
    }
    fn release(&self, dir: &DirHandle, staged: StagedFile, temp: &str) -> Result<(), DestError> {
        if self.hooks.fail_release.get() {
            drop(staged);
            return Err(DestError::Io(std::io::ErrorKind::Other));
        }
        self.inner.release(dir, staged, temp)
    }
    fn same_file(&self, dir: &DirHandle, a: &str, b: &str) -> Result<bool, DestError> {
        self.inner.same_file(dir, a, b)
    }
    fn discard(&self, dir: &DirHandle, temp: &str) -> Result<(), DestError> {
        self.inner.discard(dir, temp)
    }
    fn open_file(&self, dir: &DirHandle, name: &str) -> Result<std::fs::File, DestError> {
        self.inner.open_file(dir, name)
    }
    fn sync_dir(&self, dir: &DirHandle) -> Result<(), DestError> {
        if self.hooks.fail_sync.get() {
            return Err(DestError::Io(std::io::ErrorKind::Other));
        }
        self.inner.sync_dir(dir)
    }
    fn root_len(&self) -> usize {
        self.inner.root_len()
    }
    fn hold_root(&mut self, held: bool) -> Result<(), DestError> {
        self.hooks.held.set(Some(held));
        if held && self.hooks.fail_hold.get() {
            return Err(DestError::WrongKind);
        }
        self.inner.hold_root(held)
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
        let (destination, hooks) =
            Hooked::substituting(DirDestination::open(dest.path())?, plant.clone());
        let mut sink: FsSink<Hooked, SoftwareSealer> = FsSink::open(
            state.path(),
            destination,
            sealer(7),
            SinkConfig::default(),
            time(WALL)?,
        )?;
        receive_all(&mut sink, &consented, &FILES)?;
        let result = sink.publish(&manifest, 6);
        if hooks.substituted.get() != Some(true) {
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
/// renamed nor deleted (and so not replaced) in the meantime. The final
/// name, a second link, is not pinned: NTFS lets it be deleted.
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
    // NTFS has hard links: publication is the link, not the copy fallback.
    assert_eq!(
        destination.publish(&root, &staged, ".t", "final")?,
        Atomicity::Atomic
    );
    // The temporary name stays pinned after the link.
    assert!(
        std::fs::remove_file(&path).is_err(),
        "deleted after the link"
    );
    assert!(destination.same_file(&root, ".t", "final")?);
    destination.release(&root, staged, ".t")?;
    assert!(!path.exists());
    assert_eq!(std::fs::read(temp.path().join("final"))?, b"payload");
    Ok(())
}

/// Windows: a hard link to the held staged file can be made while the
/// handle (without `FILE_SHARE_DELETE`) is open; `CreateHardLinkW` opens
/// the file for attribute access only, which share modes do not restrict.
#[cfg(windows)]
#[test]
fn a_held_staged_file_can_be_hard_linked() -> TestResult {
    let temp = TempDir::new()?;
    let destination = DirDestination::open(temp.path())?;
    let root = destination.root()?;
    let staged = destination.stage(&root, ".t")?;
    let linked = std::fs::hard_link(temp.path().join(".t"), temp.path().join("link"));
    assert!(
        linked.is_ok(),
        "hard link refused while held: {:?}",
        linked.map_err(|error| (error.kind(), error.raw_os_error()))
    );
    destination.release(&root, staged, ".t")?;
    Ok(())
}

/// A sink publishing into a [`Hooked`] destination, with its directories.
struct HookedRun {
    state: TempDir,
    dest: TempDir,
    hooks: Rc<Hooks>,
    sink: FsSink<Hooked, SoftwareSealer>,
    consented: Consented,
}

impl HookedRun {
    fn new(id: u8) -> AnyResult<Self> {
        Self::with(id, &entries(), &FILES)
    }

    fn with(id: u8, files: &[Entry], selection: &[u32]) -> AnyResult<Self> {
        let fixture = fixture()?;
        let manifest = build_manifest(&fixture, [id; 16], files, 3600)?;
        let consented = Consented::new(&fixture, &manifest, files, selection, false, id)?;
        let (state, dest) = (TempDir::new()?, TempDir::new()?);
        let (destination, hooks) = Hooked::new(DirDestination::open(dest.path())?);
        let mut sink = FsSink::open(
            state.path(),
            destination,
            sealer(7),
            SinkConfig::default(),
            time(WALL)?,
        )?;
        receive_all(&mut sink, &consented, selection)?;
        Ok(Self {
            state,
            dest,
            hooks,
            sink,
            consented,
        })
    }

    fn journal(&self) -> AnyResult<(crate::quarantine::codec::JournalHeader, Vec<JournalEntry>)> {
        let path = self
            .state
            .path()
            .join("transfers")
            .join(crate::quarantine::store::hex(
                self.consented.manifest.transfer_id(),
            ))
            .join("journal");
        let (header, entries, _) = decode_journal(&std::fs::read(path)?).map_err(|_| "journal")?;
        Ok((header, entries))
    }

    fn published(&self) -> AnyResult<Vec<u32>> {
        Ok(self
            .journal()?
            .1
            .iter()
            .filter_map(|entry| match entry {
                JournalEntry::Published { id, .. } => Some(*id),
                _ => None,
            })
            .collect())
    }

    /// Drops the sink (a restart) and opens a plain one on the same state.
    fn restart(self) -> AnyResult<(TempDir, TempDir, super::sink::Sink, Consented)> {
        let Self {
            state,
            dest,
            sink,
            consented,
            ..
        } = self;
        drop(sink);
        let sink = FsSink::open(
            state.path(),
            DirDestination::open(dest.path())?,
            sealer(7),
            SinkConfig::default(),
            time(WALL + 1)?,
        )?;
        Ok((state, dest, sink, consented))
    }
}

/// A hard link succeeded but the temporary name could not be removed:
/// publication still succeeds and is journaled, and the next start removes
/// only the leftover name (a second link to the published file).
#[test]
fn a_temporary_name_left_after_a_hard_link_is_journaled_and_cleaned() -> TestResult {
    let mut run = HookedRun::new(20)?;
    run.hooks.link.set(true);
    run.hooks.fail_release.set(true);
    run.sink.publish(&run.consented.manifest, 6)?;
    assert_eq!(run.published()?, [6]);
    let (header, _) = run.journal()?;
    let temp = run.dest.path().join(crate::sink::temp_name(&header, 6));
    let published = run.dest.path().join("c.txt");
    assert_eq!(std::fs::read(&temp)?, content(100, 4), "the leftover link");
    assert_eq!(std::fs::read(&published)?, content(100, 4));
    let (_state, dest, mut sink, consented) = run.restart()?;
    assert!(!temp.exists(), "the leftover name was not removed");
    assert_eq!(std::fs::read(&published)?, content(100, 4));
    // A resume finds the file published and publishes nothing again.
    assert!(sink.published_intact(&consented.manifest, 6));
    sink.publish(&consented.manifest, 6)?;
    assert_eq!(
        super::sink::files_below(dest.path())?,
        [dest.path().join("c.txt")]
    );
    Ok(())
}

/// Start-up removes the leftover temporary name of a published file only
/// while it is a link to that file: anything else under it stays.
#[test]
fn a_leftover_name_that_is_not_the_published_file_is_kept() -> TestResult {
    let mut run = HookedRun::new(21)?;
    run.sink.publish(&run.consented.manifest, 6)?;
    let (header, _) = run.journal()?;
    let temp = run.dest.path().join(crate::sink::temp_name(&header, 6));
    std::fs::write(&temp, b"someone else's")?;
    let (_state, _dest, _sink, _) = run.restart()?;
    assert_eq!(std::fs::read(&temp)?, b"someone else's");
    Ok(())
}

/// The directory sync after a successful publication failed: the file is
/// journaled as published before the error is returned, so neither this
/// session nor a resume publishes it again.
#[test]
fn a_failed_directory_sync_after_publication_is_journaled_first() -> TestResult {
    let mut run = HookedRun::new(22)?;
    run.hooks.fail_sync.set(true);
    assert_eq!(
        run.sink.publish(&run.consented.manifest, 6),
        Err(SinkError::Storage)
    );
    assert_eq!(run.published()?, [6]);
    run.hooks.fail_sync.set(false);
    run.sink.publish(&run.consented.manifest, 6)?;
    let (_state, dest, mut sink, consented) = run.restart()?;
    assert!(sink.published_intact(&consented.manifest, 6));
    sink.publish(&consented.manifest, 6)?;
    assert_eq!(
        super::sink::files_below(dest.path())?,
        [dest.path().join("c.txt")]
    );
    Ok(())
}

/// The journal could not record a publication: the error is reported, and
/// the same session does not publish the file a second time.
#[cfg(unix)]
#[test]
fn a_publication_the_journal_cannot_record_is_not_repeated() -> TestResult {
    use std::os::unix::fs::PermissionsExt as _;
    let mut run = HookedRun::new(23)?;
    let journal = run
        .state
        .path()
        .join("transfers")
        .join(crate::quarantine::store::hex(
            run.consented.manifest.transfer_id(),
        ))
        .join("journal");
    std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o400))?;
    if std::fs::OpenOptions::new()
        .write(true)
        .open(&journal)
        .is_ok()
    {
        eprintln!("skipping: this account writes read-only files (root)");
        return Ok(());
    }
    assert_eq!(
        run.sink.publish(&run.consented.manifest, 6),
        Err(SinkError::Storage)
    );
    run.sink.publish(&run.consented.manifest, 6)?;
    assert_eq!(
        super::sink::files_below(run.dest.path())?,
        [run.dest.path().join("c.txt")]
    );
    std::fs::set_permissions(&journal, std::fs::Permissions::from_mode(0o600))?;
    Ok(())
}

/// The sink holds the destination root while it retains any transfer
/// (on Windows that pins the folder against rename, deletion, or a
/// junction in its place) and lets it go when none is left.
#[test]
fn the_root_is_held_exactly_while_transfers_are_retained() -> TestResult {
    let run = HookedRun::new(24)?;
    assert_eq!(run.hooks.held.get(), Some(true), "after the Accept");
    let transfer_id = *run.consented.manifest.transfer_id();
    let HookedRun {
        state,
        dest,
        hooks,
        mut sink,
        consented,
    } = run;
    sink.tombstone(&transfer_id, time(WALL + 7200)?);
    assert_eq!(hooks.held.get(), Some(false), "after the cancel");
    drop(sink);
    // A restart with a retained transfer holds it again.
    let fixture = fixture()?;
    let other = build_manifest(&fixture, [25; 16], &entries(), 3600)?;
    let accepted = Consented::new(&fixture, &other, &entries(), &FILES, false, 25)?;
    let (destination, hooks) = Hooked::new(DirDestination::open(dest.path())?);
    let mut sink = FsSink::open(
        state.path(),
        destination,
        sealer(7),
        SinkConfig::default(),
        time(WALL)?,
    )?;
    assert_eq!(hooks.held.get(), Some(false));
    receive_all(&mut sink, &accepted, &FILES)?;
    drop(sink);
    let (destination, hooks) = Hooked::new(DirDestination::open(dest.path())?);
    let _sink = FsSink::open(
        state.path(),
        destination,
        sealer(7),
        SinkConfig::default(),
        time(WALL)?,
    )?;
    assert_eq!(hooks.held.get(), Some(true), "after a restart");
    let _ = consented;
    Ok(())
}

/// A top-level directory the user keeps removing: re-created under the
/// same name, it is not journaled again; under a new name (its name was
/// taken just before, a race), at most a few times, after which
/// publication fails with STORAGE instead of growing the journal without
/// bound.
#[test]
fn top_directory_records_are_bounded() -> TestResult {
    let mut files = vec![dir_entry("d", 0)];
    for k in 0..8 {
        files.push(file_entry(&format!("f{k}"), 1, content(10, k)));
    }
    let selection: Vec<u32> = (2..=9).collect();
    let mut run = HookedRun::with(32, &files, &selection)?;
    let manifest = run.consented.manifest.clone();
    let transfer_id = *manifest.transfer_id();
    let top_records = |run: &HookedRun| -> AnyResult<usize> {
        Ok(run
            .journal()?
            .1
            .iter()
            .filter(|entry| matches!(entry, JournalEntry::TopDirectory { .. }))
            .count())
    };
    run.sink.publish(&manifest, 2)?;
    assert_eq!(top_records(&run)?, 1);
    // Removed and re-created under the same name: no new record.
    std::fs::remove_dir_all(run.dest.path().join("d"))?;
    run.sink.publish(&manifest, 3)?;
    assert!(run.dest.path().join("d").join("f1").exists());
    assert_eq!(top_records(&run)?, 1);
    // Removed, and its name taken each time it is re-created: a new name
    // and a new record, up to the bound.
    let mut current = "d".to_owned();
    let mut recorded = 1;
    for file_id in 4..=9 {
        std::fs::remove_dir_all(run.dest.path().join(&current))?;
        run.hooks.taken.borrow_mut().insert(current.clone());
        let result = run.sink.publish(&manifest, file_id);
        if result.is_err() {
            assert_eq!(result, Err(SinkError::Storage));
            break;
        }
        recorded += 1;
        assert_eq!(top_records(&run)?, recorded);
        current = run
            .sink
            .published_path(&transfer_id, file_id)
            .and_then(|path| path.first().cloned())
            .ok_or("path")?;
    }
    assert_eq!(
        recorded,
        crate::quarantine::codec::MAX_TOP_DIRECTORY_RECORDS
    );
    assert_eq!(top_records(&run)?, recorded);
    Ok(())
}
