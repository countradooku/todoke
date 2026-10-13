//! Windows directory operations with the standard library only (no
//! `unsafe`, no Win32 bindings). Windows has no `openat`, so each
//! operation uses the full verbatim (`\\?\`) path of a directory this
//! crate holds open:
//!
//! - Every directory on the way down is opened with
//!   `FILE_FLAG_OPEN_REPARSE_POINT` (a symbolic link or junction is opened
//!   itself, then refused) and without `FILE_SHARE_DELETE`, so while an
//!   operation holds the handles nobody can rename, delete, or replace
//!   those directories. Between operations nothing is held except the
//!   root, and that with `FILE_SHARE_DELETE`, so the user can still move
//!   the destination folder.
//! - Files are created with `CREATE_NEW` (never an existing entry, link
//!   or not) and opened for reading with `FILE_FLAG_OPEN_REPARSE_POINT`,
//!   then checked to be plain files.
//! - The staged file is created without `FILE_SHARE_DELETE` and its handle
//!   is held from creation until it is released, so while the sink writes,
//!   hashes, and publishes it, nobody can rename, delete, or replace the
//!   temporary name (nor, after the hard link, the final name: both are
//!   names of the one held file).
//! - Publication is `CreateHardLinkW` (fails if the name exists), then the
//!   handle is closed and the temporary name removed; filesystems without
//!   hard links (FAT, exFAT) get an exclusive copy, read from the held
//!   handle, instead.
//! - Publication cannot compare file identities as the Unix code does:
//!   the standard library's `MetadataExt::file_index` and
//!   `volume_serial_number` are unstable (`windows_by_handle`,
//!   rust-lang/rust#63010), and `GetFileInformationByHandle` would need
//!   `unsafe` FFI (a `todoke-sys-windows` exception). The held handle
//!   gives the same guarantee for the temporary name instead.
//! - Verbatim paths disable Win32 name munging: device names, trailing
//!   dots and spaces, and short names are not interpreted.
//!
//! Residual risk, documented in ADR 0006: the path is re-resolved on each
//! call. During an operation the held handles pin every directory from the
//! root down to the entry, so only the root's own ancestors could change,
//! and changing them needs local rights over the user's folders. No rename without
//! replace exists in the standard library (`std::fs::rename` replaces),
//! hence the hard link.

use std::fs::{File, OpenOptions};
use std::io::{self, Seek as _, SeekFrom};
use std::os::windows::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::Path;

use super::{Atomicity, DestError};

pub(super) type Handle = File;

/// `FILE_SHARE_READ | FILE_SHARE_WRITE`, without `FILE_SHARE_DELETE`.
const SHARE_READ_WRITE: u32 = 0x1 | 0x2;
/// `FILE_FLAG_BACKUP_SEMANTICS`: required to open a directory.
const BACKUP_SEMANTICS: u32 = 0x0200_0000;
/// `FILE_FLAG_OPEN_REPARSE_POINT`: open a link itself, not its target.
const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
/// `FILE_ATTRIBUTE_REPARSE_POINT`.
const ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

fn is_link(file: &File) -> Result<bool, DestError> {
    let metadata = file.metadata()?;
    Ok(metadata.file_attributes() & ATTRIBUTE_REPARSE_POINT != 0)
}

fn open_directory(path: &Path) -> Result<Handle, DestError> {
    let handle = OpenOptions::new()
        .read(true)
        .share_mode(SHARE_READ_WRITE)
        .custom_flags(BACKUP_SEMANTICS | OPEN_REPARSE_POINT)
        .open(path)?;
    if is_link(&handle)? || !handle.metadata()?.is_dir() {
        return Err(DestError::WrongKind);
    }
    Ok(handle)
}

/// `FILE_SHARE_DELETE` as well: for the long-lived root handle, so the
/// user can still rename or move the destination folder while the app
/// runs.
const SHARE_ALL: u32 = SHARE_READ_WRITE | 0x4;

fn open_root_with(path: &Path, share: u32) -> Result<Handle, DestError> {
    // The root itself was chosen by the user and canonicalized by the
    // caller; only its contents are untrusted.
    let handle = OpenOptions::new()
        .read(true)
        .share_mode(share)
        .custom_flags(BACKUP_SEMANTICS)
        .open(path)?;
    if !handle.metadata()?.is_dir() {
        return Err(DestError::WrongKind);
    }
    Ok(handle)
}

pub(super) fn open_root(path: &Path) -> Result<Handle, DestError> {
    open_root_with(path, SHARE_ALL)
}

/// A root handle for one operation, opened again from the root's path and
/// held without `FILE_SHARE_DELETE` while the operation runs.
pub(super) fn duplicate(_: &Handle, path: &Path) -> Result<Handle, DestError> {
    open_root_with(path, SHARE_READ_WRITE)
}

pub(super) fn list(_: &Handle, dir: &Path, limit: usize) -> Result<Option<Vec<String>>, DestError> {
    let mut names = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        if names.len() == limit {
            return Ok(None);
        }
        names.push(entry?.file_name().to_string_lossy().into_owned());
    }
    Ok(Some(names))
}

pub(super) fn exists(_: &Handle, dir: &Path, name: &str) -> Result<bool, DestError> {
    match std::fs::symlink_metadata(dir.join(name)) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(DestError::from(error)),
    }
}

pub(super) fn create_dir(_: &Handle, dir: &Path, name: &str) -> Result<(), DestError> {
    std::fs::create_dir(dir.join(name)).map_err(DestError::from)
}

pub(super) fn open_dir(_: &Handle, dir: &Path, name: &str) -> Result<Handle, DestError> {
    open_directory(&dir.join(name))
}

pub(super) fn create_new_file(_: &Handle, dir: &Path, name: &str) -> Result<File, DestError> {
    // Without FILE_SHARE_DELETE: while this handle is open, the name can
    // be neither renamed nor deleted, so it keeps referring to this file.
    // Readable, so the copy fallback reads the handle, never the name.
    OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .share_mode(SHARE_READ_WRITE)
        .custom_flags(OPEN_REPARSE_POINT)
        .open(dir.join(name))
        .map_err(DestError::from)
}

pub(super) fn open_file(_: &Handle, dir: &Path, name: &str) -> Result<File, DestError> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(OPEN_REPARSE_POINT)
        .open(dir.join(name))?;
    if is_link(&file)? || !file.metadata()?.is_file() {
        return Err(DestError::WrongKind);
    }
    Ok(file)
}

pub(super) fn remove_file(_: &Handle, dir: &Path, name: &str) -> Result<(), DestError> {
    match std::fs::remove_file(dir.join(name)) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(DestError::from(error)),
    }
}

pub(super) fn publish(
    handle: &Handle,
    dir: &Path,
    staged: &File,
    temp: &str,
    name: &str,
) -> Result<Atomicity, DestError> {
    // `temp` is pinned to `staged` by the held handle (no
    // FILE_SHARE_DELETE), so the link is to the file that was hashed.
    match std::fs::hard_link(dir.join(temp), dir.join(name)) {
        Ok(()) => Ok(Atomicity::Atomic),
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => Err(DestError::Exists),
        Err(_) => {
            // FAT and exFAT have no hard links; some network shares refuse
            // them. Copy the held file into one created exclusively under
            // the name.
            let mut source = staged;
            source.seek(SeekFrom::Start(0))?;
            let mut target = create_new_file(handle, dir, name)?;
            let copied = io::copy(&mut source, &mut target).and_then(|_| target.sync_all());
            if let Err(failure) = copied {
                drop(target);
                let _ = remove_file(handle, dir, name);
                return Err(DestError::from(failure));
            }
            Ok(Atomicity::Copied)
        }
    }
}

pub(super) fn release(
    handle: &Handle,
    dir: &Path,
    staged: File,
    temp: &str,
) -> Result<(), DestError> {
    // The temporary name can only be removed once no handle without
    // FILE_SHARE_DELETE is open on the file.
    drop(staged);
    remove_file(handle, dir, temp)
}

/// NTFS journals directory changes; the standard library offers no
/// directory flush (`FlushFileBuffers` needs a writable handle), so there
/// is nothing to do.
pub(super) fn sync_dir(_: &Handle) {}
