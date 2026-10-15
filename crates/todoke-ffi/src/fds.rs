//! File descriptors the app hands over (Android
//! `ParcelFileDescriptor.detachFd()` for a document the user picked), for
//! `ContactHandle::send_files`.
//!
//! The only unsafe code in this crate outside `BoltFFI`'s: adopting a raw
//! descriptor number. The contract with the app is that every descriptor
//! passed is open, owned by the app, and given up to this call (detached,
//! never closed by the app afterwards). What can be checked is checked
//! before anything is adopted: a negative number, the standard streams
//! (0 to 2), a number given twice, or one not open is refused, and the
//! descriptors already adopted are closed again.

#![allow(
    unsafe_code,
    reason = "adopting a descriptor the app hands over needs from_raw_fd; each block states why it is sound"
)]

use std::collections::BTreeSet;
use std::fs::File;
use std::os::fd::{BorrowedFd, FromRawFd as _, OwnedFd};

use crate::error::TodokeError;

/// Takes ownership of `fds`, each open and given up by the app, as files.
/// On any refusal, every descriptor already adopted is closed (the
/// numbers refused were never adopted, so nothing else is touched).
///
/// # Errors
///
/// [`TodokeError::Invalid`] for a negative number, a standard stream, a
/// number given twice, or a descriptor that is not open.
pub(crate) fn adopt(fds: &[i32]) -> Result<Vec<File>, TodokeError> {
    let mut seen = BTreeSet::new();
    let mut files = Vec::with_capacity(fds.len());
    let mut refused = false;
    for &fd in fds {
        if fd <= 2 || !seen.insert(fd) {
            refused = true;
            continue;
        }
        // SAFETY: `borrow_raw` needs `fd` to stay open for the borrow, which
        // lasts only this call: nothing in this process closes a descriptor
        // the app has just given up to us while we look at it.
        let open = rustix::io::fcntl_getfd(unsafe { BorrowedFd::borrow_raw(fd) }).is_ok();
        if !open {
            refused = true;
            continue;
        }
        // SAFETY: the app gave up ownership of `fd` (the documented
        // contract of `send_files`), it is open (checked above), and it
        // appears once in `fds` (the set above), so exactly one `OwnedFd`
        // owns it and closes it once.
        files.push(File::from(unsafe { OwnedFd::from_raw_fd(fd) }));
    }
    if refused {
        // Dropping `files` closes what was adopted.
        return Err(TodokeError::Invalid {
            message: "a file handed over was not open, or was given twice".to_owned(),
        });
    }
    Ok(files)
}

#[cfg(test)]
mod tests {
    use std::io::{Read as _, Write as _};
    use std::os::fd::IntoRawFd as _;

    use super::*;

    fn temp_file(content: &[u8]) -> Result<(File, std::path::PathBuf), Box<dyn std::error::Error>> {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random)?;
        let path =
            std::env::temp_dir().join(format!("todoke-ffi-fd-{}", u64::from_le_bytes(random)));
        let mut file = File::create(&path)?;
        file.write_all(content)?;
        Ok((File::open(&path)?, path))
    }

    /// Open descriptors handed over become files this crate owns.
    #[test]
    #[cfg_attr(miri, ignore = "fcntl on real descriptors")]
    fn open_descriptors_are_adopted() -> Result<(), Box<dyn std::error::Error>> {
        let (file, path) = temp_file(b"handed over")?;
        let fd = file.into_raw_fd();
        let mut adopted = adopt(&[fd])?;
        let mut text = String::new();
        adopted.remove(0).read_to_string(&mut text)?;
        assert_eq!(text, "handed over");
        std::fs::remove_file(path)?;
        Ok(())
    }

    /// Standard streams, negative numbers, a number given twice, and a
    /// closed descriptor are refused; what was adopted on the way is
    /// closed again.
    #[test]
    #[cfg_attr(miri, ignore = "fcntl on real descriptors")]
    fn bad_descriptors_are_refused() -> Result<(), Box<dyn std::error::Error>> {
        for fds in [&[0][..], &[1], &[2], &[-1]] {
            assert!(matches!(adopt(fds), Err(TodokeError::Invalid { .. })));
        }
        let (file, path) = temp_file(b"x")?;
        let fd = file.into_raw_fd();
        assert!(matches!(adopt(&[fd, fd]), Err(TodokeError::Invalid { .. })));
        // The first adoption closed it again: it is not open any more.
        // SAFETY: only inspected, never closed or used for I/O.
        let still_open = rustix::io::fcntl_getfd(unsafe { BorrowedFd::borrow_raw(fd) }).is_ok();
        assert!(!still_open);
        std::fs::remove_file(path)?;
        Ok(())
    }
}
