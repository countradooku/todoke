//! POSIX directory operations through `openat`-family calls (rustix): every
//! lookup is relative to an open directory, `O_NOFOLLOW` refuses links,
//! `O_CREAT | O_EXCL` never opens an existing entry, and publication uses
//! rename-without-replace (`renameat2(RENAME_NOREPLACE)` on Linux,
//! `renameatx_np(RENAME_EXCL)` on Apple platforms), else a hard link,
//! else an exclusive copy. Publication is bound to the staged file the
//! sink wrote and hashed: before and after the rename or link, the
//! temporary and final names must refer to that open file (same device and
//! inode, and the expected link count), so a file substituted under the
//! temporary name is never reported as published.

use std::fs::File;
use std::io::{self, Seek as _, SeekFrom};
use std::os::fd::OwnedFd;
use std::path::Path;

use rustix::fs::{AtFlags, FileType, Mode, OFlags, RawMode, Stat};
use rustix::io::Errno;

use super::{Atomicity, DestError};

pub(super) type Handle = OwnedFd;

/// New files: read and write for everyone the umask allows, never execute.
const FILE_MODE: RawMode = 0o666;
/// New directories: as the umask allows.
const DIR_MODE: RawMode = 0o777;

const fn mode(bits: RawMode) -> Mode {
    Mode::from_bits_truncate(bits)
}

fn error(errno: Errno) -> DestError {
    match errno {
        Errno::EXIST => DestError::Exists,
        Errno::NOENT => DestError::NotFound,
        // O_NOFOLLOW on a link, O_DIRECTORY on something else.
        Errno::LOOP | Errno::NOTDIR => DestError::WrongKind,
        other => DestError::Io(io::Error::from(other).kind()),
    }
}

pub(super) fn open_root(path: &Path) -> Result<Handle, DestError> {
    let fd = rustix::fs::open(
        path,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(error)?;
    Ok(fd)
}

/// A root handle for one operation: a duplicate of the open root (which
/// keeps following the directory if it is renamed).
pub(super) fn duplicate(handle: &Handle, _: &Path) -> Result<Handle, DestError> {
    handle.try_clone().map_err(DestError::from)
}

pub(super) fn list(dir: &Handle, _: &Path, limit: usize) -> Result<Option<Vec<String>>, DestError> {
    // Reads through a new descriptor for the same directory, so the held
    // one keeps no shared read position.
    let entries = rustix::fs::Dir::read_from(dir).map_err(error)?;
    let mut names = Vec::new();
    for entry in entries {
        let entry = entry.map_err(error)?;
        let name = entry.file_name().to_bytes();
        if name == b"." || name == b".." {
            continue;
        }
        if names.len() == limit {
            return Ok(None);
        }
        names.push(String::from_utf8_lossy(name).into_owned());
    }
    Ok(Some(names))
}

pub(super) fn exists(dir: &Handle, _: &Path, name: &str) -> Result<bool, DestError> {
    match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(_) => Ok(true),
        Err(Errno::NOENT) => Ok(false),
        Err(other) => Err(error(other)),
    }
}

pub(super) fn create_dir(dir: &Handle, _: &Path, name: &str) -> Result<(), DestError> {
    rustix::fs::mkdirat(dir, name, mode(DIR_MODE)).map_err(error)
}

pub(super) fn open_dir(dir: &Handle, _: &Path, name: &str) -> Result<Handle, DestError> {
    rustix::fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(error)
}

pub(super) fn create_new_file(dir: &Handle, _: &Path, name: &str) -> Result<File, DestError> {
    // Readable too: the exclusive-copy fallback copies from the staged
    // handle itself, never from the name.
    let fd = rustix::fs::openat(
        dir,
        name,
        OFlags::RDWR | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
        mode(FILE_MODE),
    )
    .map_err(error)?;
    Ok(File::from(fd))
}

pub(super) fn open_file(dir: &Handle, _: &Path, name: &str) -> Result<File, DestError> {
    // O_NONBLOCK keeps a FIFO planted under this name from blocking the
    // open; it does not affect reads of a regular file.
    let fd = rustix::fs::openat(
        dir,
        name,
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(error)?;
    let stat = rustix::fs::fstat(&fd).map_err(error)?;
    if FileType::from_raw_mode(stat.st_mode) != FileType::RegularFile {
        return Err(DestError::WrongKind);
    }
    Ok(File::from(fd))
}

pub(super) fn remove_file(dir: &Handle, _: &Path, name: &str) -> Result<(), DestError> {
    match rustix::fs::unlinkat(dir, name, AtFlags::empty()) {
        Ok(()) | Err(Errno::NOENT) => Ok(()),
        Err(other) => Err(error(other)),
    }
}

/// Errors meaning "this filesystem or kernel cannot do that", after which
/// the next, weaker method is tried.
fn unsupported(errno: Errno) -> bool {
    // ENOTSUP and EOPNOTSUPP are the same value on Linux, distinct on Apple
    // platforms, so they are compared rather than matched.
    not_supported(errno)
        || matches!(
            errno,
            Errno::INVAL | Errno::NOSYS | Errno::PERM | Errno::MLINK
        )
}

fn not_supported(errno: Errno) -> bool {
    errno == Errno::NOTSUP || errno == Errno::OPNOTSUPP
}

/// A link count as a `u64`, whatever the platform's `nlink_t` is.
fn count<T: TryInto<u64>>(links: T) -> u64 {
    links.try_into().unwrap_or(u64::MAX)
}

/// Whether `name` in `dir` is the file `ours` (same device and inode),
/// without following a link. A missing name is not.
fn same(dir: &Handle, name: &str, ours: &Stat) -> Result<bool, DestError> {
    match rustix::fs::statat(dir, name, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(there) => Ok(there.st_dev == ours.st_dev
            && there.st_ino == ours.st_ino
            && FileType::from_raw_mode(there.st_mode) == FileType::RegularFile),
        Err(Errno::NOENT) => Ok(false),
        Err(other) => Err(error(other)),
    }
}

/// Requires `name` in `dir` to be the open file `file` with exactly
/// `links` names: another file, a link, or an extra hard link made by
/// someone else is [`DestError::Replaced`].
fn verify(dir: &Handle, name: &str, file: &File, links: u64) -> Result<(), DestError> {
    let ours = rustix::fs::fstat(file).map_err(error)?;
    if !same(dir, name, &ours)? || count(ours.st_nlink) != links {
        return Err(DestError::Replaced);
    }
    Ok(())
}

pub(super) fn publish(
    dir: &Handle,
    path: &Path,
    staged: &File,
    temp: &str,
    name: &str,
) -> Result<Atomicity, DestError> {
    // The temporary name is visible to anyone who can list the directory:
    // refuse to move anything but the file that was written and hashed.
    verify(dir, temp, staged, 1)?;
    place(dir, path, staged, temp, name)
}

/// Renames or links `temp` to `name`, or copies the staged file there,
/// then checks that `name` is the staged file (or the copy). If something
/// replaced `temp` after the check in [`publish`], it may now be under
/// `name`: that is reported, and it is left as it is.
fn place(
    dir: &Handle,
    path: &Path,
    staged: &File,
    temp: &str,
    name: &str,
) -> Result<Atomicity, DestError> {
    // Android: bionic declares renameat2 from API level 30 (Android 11),
    // but whether the app seccomp filter of every supported release allows
    // the system call is unverified, and a disallowed call kills the
    // process, so Android starts with the hard link until P16 verifies it
    // on devices (docs/adr/0006-filesystem.md).
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    if let Some(done) = rename_new(dir, staged, temp, name)? {
        return Ok(done);
    }
    if let Some(done) = link_new(dir, staged, temp, name)? {
        return Ok(done);
    }
    copy_exclusive(dir, path, staged, name)?;
    Ok(Atomicity::Copied)
}

/// Renames `temp` to `name` without replacing anything, then requires
/// `name` to be the staged file with one link. `None` if the filesystem
/// cannot rename without replacing.
#[cfg(any(target_os = "linux", target_vendor = "apple"))]
fn rename_new(
    dir: &Handle,
    staged: &File,
    temp: &str,
    name: &str,
) -> Result<Option<Atomicity>, DestError> {
    match rustix::fs::renameat_with(dir, temp, dir, name, rustix::fs::RenameFlags::NOREPLACE) {
        Ok(()) => {
            verify(dir, name, staged, 1)?;
            Ok(Some(Atomicity::Atomic))
        }
        Err(errno) if unsupported(errno) => Ok(None),
        Err(other) => Err(error(other)),
    }
}

/// Links `temp` to `name` (a link never replaces), then requires `name` to
/// be the staged file with exactly two links. `None` if the filesystem
/// has no hard links.
fn link_new(
    dir: &Handle,
    staged: &File,
    temp: &str,
    name: &str,
) -> Result<Option<Atomicity>, DestError> {
    match rustix::fs::linkat(dir, temp, dir, name, AtFlags::empty()) {
        Ok(()) => {
            // Two names now: the temporary one goes in `release`.
            verify(dir, name, staged, 2)?;
            Ok(Some(Atomicity::Atomic))
        }
        Err(errno) if unsupported(errno) => Ok(None),
        Err(other) => Err(error(other)),
    }
}

/// The last resort: an exclusive copy of the staged file (read through
/// its own handle) into the final name.
fn copy_exclusive(dir: &Handle, path: &Path, staged: &File, name: &str) -> Result<(), DestError> {
    let mut source = staged;
    source.seek(SeekFrom::Start(0))?;
    let mut target = create_new_file(dir, path, name)?;
    let copied = io::copy(&mut source, &mut target).and_then(|_| target.sync_all());
    if let Err(failure) = copied {
        // Best effort: the partial copy is ours (created exclusively)
        // while the name still refers to it.
        if let Ok(ours) = rustix::fs::fstat(&target)
            && same(dir, name, &ours).unwrap_or(false)
        {
            let _ = remove_file(dir, path, name);
        }
        return Err(DestError::from(failure));
    }
    verify(dir, name, &target, 1)
}

pub(super) fn same_file(dir: &Handle, _: &Path, a: &str, b: &str) -> Result<bool, DestError> {
    match rustix::fs::statat(dir, a, AtFlags::SYMLINK_NOFOLLOW) {
        Ok(first) => same(dir, b, &first),
        Err(Errno::NOENT) => Ok(false),
        Err(other) => Err(error(other)),
    }
}

pub(super) fn release(
    dir: &Handle,
    path: &Path,
    staged: File,
    temp: &str,
) -> Result<(), DestError> {
    let ours = rustix::fs::fstat(&staged).map_err(error)?;
    let still_ours = same(dir, temp, &ours)?;
    // Closed before the name goes, as on Windows.
    drop(staged);
    if still_ours {
        remove_file(dir, path, temp)?;
    }
    Ok(())
}

pub(super) fn sync_dir(dir: &Handle) -> Result<(), DestError> {
    #[cfg(target_vendor = "apple")]
    let synced = rustix::fs::fcntl_fullfsync(dir).or_else(|_| rustix::fs::fsync(dir));
    #[cfg(not(target_vendor = "apple"))]
    let synced = rustix::fs::fsync(dir);
    match synced {
        // Some filesystems cannot sync a directory; nothing more is
        // possible there.
        Ok(()) | Err(Errno::INVAL | Errno::BADF) => Ok(()),
        Err(errno) if not_supported(errno) => Ok(()),
        Err(other) => Err(error(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{AnyResult, TempDir, TestResult};

    use std::io::Write as _;

    /// A staged file `.t` holding `payload`.
    fn staged(dir: &Handle, path: &Path, payload: &[u8]) -> Result<File, DestError> {
        let mut file = create_new_file(dir, path, ".t")?;
        file.write_all(payload)?;
        Ok(file)
    }

    /// The last-resort copy (FAT and similar filesystems) never replaces
    /// an entry, copies the staged file itself, and leaves the temporary
    /// name for `release`, which removes it once the copy is durable.
    #[test]
    fn the_exclusive_copy_never_replaces() -> TestResult {
        let temp = TempDir::new()?;
        std::fs::write(temp.path().join("taken"), b"theirs")?;
        let dir = open_root(temp.path())?;
        let file = staged(&dir, temp.path(), b"payload")?;
        assert_eq!(
            copy_exclusive(&dir, temp.path(), &file, "taken"),
            Err(DestError::Exists)
        );
        assert_eq!(std::fs::read(temp.path().join("taken"))?, b"theirs");
        copy_exclusive(&dir, temp.path(), &file, "free")?;
        assert_eq!(std::fs::read(temp.path().join("free"))?, b"payload");
        release(&dir, temp.path(), file, ".t")?;
        assert!(!temp.path().join(".t").exists());
        Ok(())
    }

    /// The temporary name replaced after the check in `publish` and before
    /// the rename (the race the check cannot close): the rename moves the
    /// substitute, the check after it refuses, and the substitute is left
    /// exactly as it is. `release` then leaves the name alone.
    #[test]
    fn a_substitute_renamed_in_a_race_is_reported_and_left_alone() -> TestResult {
        let temp = TempDir::new()?;
        let dir = open_root(temp.path())?;
        let file = staged(&dir, temp.path(), b"payload")?;
        // The race: someone replaces the temporary name with a regular
        // file of their own.
        std::fs::remove_file(temp.path().join(".t"))?;
        std::fs::write(temp.path().join(".t"), b"planted")?;
        assert_eq!(
            place(&dir, temp.path(), &file, ".t", "final"),
            Err(DestError::Replaced)
        );
        assert_eq!(std::fs::read(temp.path().join("final"))?, b"planted");
        // A link planted the same way.
        let outside = TempDir::new()?;
        std::fs::write(outside.path().join("target"), b"outside")?;
        std::os::unix::fs::symlink(outside.path().join("target"), temp.path().join(".t"))?;
        assert_eq!(
            place(&dir, temp.path(), &file, ".t", "other"),
            Err(DestError::Replaced)
        );
        assert!(
            std::fs::symlink_metadata(temp.path().join("other"))?
                .file_type()
                .is_symlink()
        );
        assert_eq!(std::fs::read(outside.path().join("target"))?, b"outside");
        std::os::unix::fs::symlink(outside.path().join("target"), temp.path().join(".t"))?;
        release(&dir, temp.path(), file, ".t")?;
        assert!(
            std::fs::symlink_metadata(temp.path().join(".t"))?
                .file_type()
                .is_symlink()
        );
        Ok(())
    }

    /// A hard link to the staged file made by someone else before
    /// publication (which would let them keep a name for the received
    /// file) is refused too.
    #[test]
    fn an_extra_hard_link_to_the_staged_file_is_refused() -> TestResult {
        let temp = TempDir::new()?;
        let dir = open_root(temp.path())?;
        let file = staged(&dir, temp.path(), b"payload")?;
        std::fs::hard_link(temp.path().join(".t"), temp.path().join("theirs"))?;
        assert_eq!(
            publish(&dir, temp.path(), &file, ".t", "final"),
            Err(DestError::Replaced)
        );
        assert!(!temp.path().join("final").exists());
        Ok(())
    }

    fn links(path: &Path) -> AnyResult<u64> {
        use std::os::unix::fs::MetadataExt as _;
        Ok(std::fs::symlink_metadata(path)?.nlink())
    }

    /// The hard-link path (Android's first choice, and the fallback where
    /// a filesystem cannot rename without replacing): the final name must
    /// be the staged file with exactly two links, and an existing name is
    /// never replaced.
    #[test]
    fn the_link_path_publishes_only_the_staged_file() -> TestResult {
        let temp = TempDir::new()?;
        let dir = open_root(temp.path())?;
        std::fs::write(temp.path().join("taken"), b"theirs")?;
        let file = staged(&dir, temp.path(), b"payload")?;
        assert_eq!(link_new(&dir, &file, ".t", "taken"), Err(DestError::Exists));
        assert_eq!(std::fs::read(temp.path().join("taken"))?, b"theirs");
        assert_eq!(
            link_new(&dir, &file, ".t", "final")?,
            Some(Atomicity::Atomic)
        );
        assert_eq!(std::fs::read(temp.path().join("final"))?, b"payload");
        assert_eq!(links(&temp.path().join("final"))?, 2);
        release(&dir, temp.path(), file, ".t")?;
        assert!(!temp.path().join(".t").exists());
        assert_eq!(links(&temp.path().join("final"))?, 1);
        Ok(())
    }

    /// A substitute under the temporary name is linked by the race, then
    /// refused and left alone; so is a staged file someone else linked
    /// first (three names after ours).
    #[test]
    fn the_link_path_refuses_substitutes_and_extra_links() -> TestResult {
        let temp = TempDir::new()?;
        let dir = open_root(temp.path())?;
        let file = staged(&dir, temp.path(), b"payload")?;
        std::fs::remove_file(temp.path().join(".t"))?;
        std::fs::write(temp.path().join(".t"), b"planted")?;
        assert_eq!(
            link_new(&dir, &file, ".t", "final"),
            Err(DestError::Replaced)
        );
        assert_eq!(std::fs::read(temp.path().join("final"))?, b"planted");
        release(&dir, temp.path(), file, ".t")?;
        assert_eq!(std::fs::read(temp.path().join(".t"))?, b"planted");
        std::fs::remove_file(temp.path().join(".t"))?;
        let file = staged(&dir, temp.path(), b"payload")?;
        std::fs::hard_link(temp.path().join(".t"), temp.path().join("theirs"))?;
        assert_eq!(
            link_new(&dir, &file, ".t", "other"),
            Err(DestError::Replaced)
        );
        Ok(())
    }

    /// The rename path requires the final name to be the staged file with
    /// one link, and never replaces.
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    #[test]
    fn the_rename_path_publishes_only_the_staged_file() -> TestResult {
        let temp = TempDir::new()?;
        let dir = open_root(temp.path())?;
        std::fs::write(temp.path().join("taken"), b"theirs")?;
        let file = staged(&dir, temp.path(), b"payload")?;
        assert_eq!(
            rename_new(&dir, &file, ".t", "taken"),
            Err(DestError::Exists)
        );
        assert_eq!(std::fs::read(temp.path().join("taken"))?, b"theirs");
        assert_eq!(
            rename_new(&dir, &file, ".t", "final")?,
            Some(Atomicity::Atomic)
        );
        assert!(!temp.path().join(".t").exists());
        assert_eq!(links(&temp.path().join("final"))?, 1);
        Ok(())
    }

    /// Identity is device, inode, and file type: a different device, a
    /// different inode, a directory, or a missing name is not the file.
    #[test]
    fn identity_needs_device_inode_and_a_regular_file() -> TestResult {
        let temp = TempDir::new()?;
        let dir = open_root(temp.path())?;
        let file = staged(&dir, temp.path(), b"payload")?;
        let ours = rustix::fs::fstat(&file).map_err(error)?;
        assert!(same(&dir, ".t", &ours)?);
        let mut other_device = ours;
        other_device.st_dev ^= 1;
        assert!(!same(&dir, ".t", &other_device)?);
        let mut other_inode = ours;
        other_inode.st_ino ^= 1;
        assert!(!same(&dir, ".t", &other_inode)?);
        assert!(!same(&dir, "missing", &ours)?);
        create_dir(&dir, temp.path(), "sub")?;
        let sub = open_dir(&dir, temp.path(), "sub")?;
        let directory = rustix::fs::fstat(&sub).map_err(error)?;
        assert!(!same(&dir, "sub", &directory)?);
        // One link was expected; with a second one the check refuses.
        verify(&dir, ".t", &file, 1)?;
        std::fs::hard_link(temp.path().join(".t"), temp.path().join("second"))?;
        assert_eq!(verify(&dir, ".t", &file, 1), Err(DestError::Replaced));
        verify(&dir, ".t", &file, 2)?;
        Ok(())
    }

    /// Only "the filesystem cannot do that" moves on to the next, weaker
    /// method; every other failure is reported.
    #[test]
    fn only_unsupported_operations_fall_back() {
        for errno in [
            Errno::NOTSUP,
            Errno::OPNOTSUPP,
            Errno::INVAL,
            Errno::NOSYS,
            Errno::PERM,
            Errno::MLINK,
        ] {
            assert!(unsupported(errno), "{errno:?}");
        }
        for errno in [
            Errno::EXIST,
            Errno::NOENT,
            Errno::ACCESS,
            Errno::XDEV,
            Errno::LOOP,
            Errno::NOTDIR,
            Errno::ROFS,
            Errno::IO,
            Errno::NOSPC,
        ] {
            assert!(!unsupported(errno), "{errno:?}");
        }
        assert_eq!(error(Errno::EXIST), DestError::Exists);
        assert_eq!(error(Errno::NOENT), DestError::NotFound);
        assert_eq!(error(Errno::LOOP), DestError::WrongKind);
        assert_eq!(error(Errno::NOTDIR), DestError::WrongKind);
        assert_eq!(
            error(Errno::ACCESS),
            DestError::Io(io::ErrorKind::PermissionDenied)
        );
    }

    /// A copy that fails part way removes its own partial file.
    #[test]
    fn a_failed_copy_removes_its_partial_file() -> TestResult {
        let temp = TempDir::new()?;
        let dir = open_root(temp.path())?;
        std::fs::write(temp.path().join(".w"), b"payload")?;
        // Write-only: reading it for the copy fails.
        let unreadable = std::fs::OpenOptions::new()
            .write(true)
            .open(temp.path().join(".w"))?;
        assert!(matches!(
            copy_exclusive(&dir, temp.path(), &unreadable, "final"),
            Err(DestError::Io(_))
        ));
        assert!(!temp.path().join("final").exists());
        Ok(())
    }
}
