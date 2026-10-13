//! POSIX directory operations through `openat`-family calls (rustix): every
//! lookup is relative to an open directory, `O_NOFOLLOW` refuses links,
//! `O_CREAT | O_EXCL` never opens an existing entry, and publication uses
//! rename-without-replace (`renameat2(RENAME_NOREPLACE)` on Linux,
//! `renameatx_np(RENAME_EXCL)` on Apple platforms), else a hard link,
//! else an exclusive copy.

use std::fs::File;
use std::io;
use std::os::fd::OwnedFd;
use std::path::Path;

use rustix::fs::{AtFlags, FileType, Mode, OFlags, RawMode};
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

pub(super) fn duplicate(handle: &Handle) -> Result<Handle, DestError> {
    handle.try_clone().map_err(DestError::from)
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
    let fd = rustix::fs::openat(
        dir,
        name,
        OFlags::WRONLY | OFlags::CREATE | OFlags::EXCL | OFlags::NOFOLLOW | OFlags::CLOEXEC,
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
    matches!(
        errno,
        Errno::INVAL | Errno::NOSYS | Errno::NOTSUP | Errno::OPNOTSUPP | Errno::PERM | Errno::MLINK
    )
}

pub(super) fn publish(
    dir: &Handle,
    path: &Path,
    temp: &str,
    name: &str,
) -> Result<Atomicity, DestError> {
    // Android's app seccomp policy is not documented to allow renameat2
    // on every supported release, and a disallowed call kills the process,
    // so Android starts with the hard link.
    #[cfg(any(target_os = "linux", target_vendor = "apple"))]
    match rustix::fs::renameat_with(dir, temp, dir, name, rustix::fs::RenameFlags::NOREPLACE) {
        Ok(()) => return Ok(Atomicity::Atomic),
        Err(errno) if unsupported(errno) => {}
        Err(other) => return Err(error(other)),
    }
    match rustix::fs::linkat(dir, temp, dir, name, AtFlags::empty()) {
        Ok(()) => {
            remove_file(dir, path, temp)?;
            return Ok(Atomicity::Atomic);
        }
        Err(errno) if unsupported(errno) => {}
        Err(other) => return Err(error(other)),
    }
    copy_exclusive(dir, path, temp, name)?;
    Ok(Atomicity::Copied)
}

/// The last resort: an exclusive copy into the final name.
fn copy_exclusive(dir: &Handle, path: &Path, temp: &str, name: &str) -> Result<(), DestError> {
    let mut source = open_file(dir, path, temp)?;
    let mut target = create_new_file(dir, path, name)?;
    let copied = io::copy(&mut source, &mut target).and_then(|_| target.sync_all());
    if let Err(failure) = copied {
        drop(target);
        // Best effort: the partial copy is ours, created exclusively.
        let _ = remove_file(dir, path, name);
        return Err(DestError::from(failure));
    }
    remove_file(dir, path, temp)
}

pub(super) fn sync_dir(dir: &Handle) -> Result<(), DestError> {
    #[cfg(target_vendor = "apple")]
    let synced = rustix::fs::fcntl_fullfsync(dir).or_else(|_| rustix::fs::fsync(dir));
    #[cfg(not(target_vendor = "apple"))]
    let synced = rustix::fs::fsync(dir);
    match synced {
        // Some filesystems cannot sync a directory; nothing more is
        // possible there.
        Ok(()) | Err(Errno::INVAL | Errno::NOTSUP | Errno::OPNOTSUPP | Errno::BADF) => Ok(()),
        Err(other) => Err(error(other)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::{TempDir, TestResult};

    /// The last-resort copy (FAT and similar filesystems) never replaces
    /// an entry and removes the temporary file once the copy is durable.
    #[test]
    fn the_exclusive_copy_never_replaces() -> TestResult {
        let temp = TempDir::new()?;
        std::fs::write(temp.path().join(".t"), b"payload")?;
        std::fs::write(temp.path().join("taken"), b"theirs")?;
        let dir = open_root(temp.path())?;
        assert_eq!(
            copy_exclusive(&dir, temp.path(), ".t", "taken"),
            Err(DestError::Exists)
        );
        assert_eq!(std::fs::read(temp.path().join("taken"))?, b"theirs");
        copy_exclusive(&dir, temp.path(), ".t", "free")?;
        assert_eq!(std::fs::read(temp.path().join("free"))?, b"payload");
        assert!(!temp.path().join(".t").exists());
        Ok(())
    }
}
