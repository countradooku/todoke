//! Text from the clipboard, sent as a file: written to `outbox/` in the
//! private state directory (0700, files 0600), named for when it was
//! taken, and removed once its transfer is over or after a week (the
//! longest a transfer can resume, §13).

use core::time::Duration;
use std::path::{Path, PathBuf};

/// The most clipboard text sent at once.
pub const MAX_TEXT: usize = 16 << 20;
/// How long an outbox file is kept for an unfinished transfer.
pub const KEEP: Duration = Duration::from_hours(7 * 24);

/// The outbox directory.
#[must_use]
pub fn dir(state_dir: &Path) -> PathBuf {
    state_dir.join("outbox")
}

/// Writes `text` to a new file in the outbox, taken at `unix` seconds.
///
/// # Errors
///
/// `InvalidInput` for empty or oversized text; an I/O error.
pub fn write(state_dir: &Path, text: &str, unix: u64) -> std::io::Result<PathBuf> {
    use std::io::Write as _;
    if text.is_empty() || text.len() > MAX_TEXT {
        return Err(std::io::ErrorKind::InvalidInput.into());
    }
    let dir = dir(state_dir);
    create_private_dir(&dir)?;
    let stamp = crate::format::timestamp(unix)
        .trim_end_matches(" UTC")
        .replace(':', "-");
    for attempt in 0..100_u32 {
        let name = if attempt == 0 {
            format!("Clipboard {stamp}.txt")
        } else {
            format!("Clipboard {stamp} ({attempt}).txt")
        };
        let path = dir.join(name);
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(mut file) => {
                file.write_all(text.as_bytes())?;
                file.sync_all()?;
                return Ok(path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error),
        }
    }
    Err(std::io::ErrorKind::AlreadyExists.into())
}

/// Removes `path` if it is an outbox file of `state_dir`.
pub fn remove(state_dir: &Path, path: &Path) {
    if path.parent() == Some(dir(state_dir).as_path()) {
        let _ = std::fs::remove_file(path);
    }
}

/// Removes outbox files older than [`KEEP`].
pub fn sweep(state_dir: &Path) {
    let Ok(entries) = std::fs::read_dir(dir(state_dir)) else {
        return;
    };
    for entry in entries.flatten() {
        let old = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .ok()
            .and_then(|modified| modified.elapsed().ok())
            .is_some_and(|age| age > KEEP);
        if old {
            let _ = std::fs::remove_file(entry.path());
        }
    }
}

fn create_private_dir(dir: &Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt as _;
        builder.mode(0o700);
    }
    builder.create(dir)?;
    // Refuse a directory someone swapped for a link.
    if std::fs::symlink_metadata(dir)?.file_type().is_symlink() {
        return Err(std::io::ErrorKind::PermissionDenied.into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_is_written_privately_and_removed() -> std::io::Result<()> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_nanos());
        let state = std::env::temp_dir().join(format!("todoke-outbox-{nanos}"));
        let first = write(&state, "hello", 1_791_970_200)?;
        let second = write(&state, "again", 1_791_970_200)?;
        assert_eq!(
            first.file_name().and_then(|name| name.to_str()),
            Some("Clipboard 2026-10-14 09-30.txt")
        );
        assert_ne!(first, second);
        assert_eq!(std::fs::read_to_string(&first)?, "hello");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                std::fs::metadata(&first)?.permissions().mode() & 0o777,
                0o600
            );
            assert_eq!(
                std::fs::metadata(dir(&state))?.permissions().mode() & 0o777,
                0o700
            );
        }
        assert!(write(&state, "", 1).is_err());
        // Only outbox files are removed.
        let outside = state.join("keep.txt");
        std::fs::write(&outside, "x")?;
        remove(&state, &outside);
        assert!(outside.exists());
        remove(&state, &first);
        assert!(!first.exists());
        sweep(&state);
        assert!(second.exists());
        std::fs::remove_dir_all(&state)?;
        Ok(())
    }

    /// A week-old file goes at the next start; a newer one, and anything
    /// outside the outbox, stays; a missing outbox is nothing to sweep.
    #[test]
    fn sweep_removes_only_files_older_than_a_week() -> std::io::Result<()> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_nanos());
        let state = std::env::temp_dir().join(format!("todoke-outbox-sweep-{nanos}"));
        // No outbox yet: nothing happens.
        sweep(&state);
        let age = |path: &Path, by: Duration| -> std::io::Result<()> {
            let when = std::time::SystemTime::now()
                .checked_sub(by)
                .ok_or(std::io::ErrorKind::InvalidInput)?;
            std::fs::File::options()
                .write(true)
                .open(path)?
                .set_modified(when)
        };
        let old = write(&state, "old", 1_791_970_200)?;
        let nearly = write(&state, "nearly", 1_791_970_201)?;
        let recent = write(&state, "recent", 1_791_970_202)?;
        age(&old, KEEP + Duration::from_hours(1))?;
        age(&nearly, Duration::from_hours(6 * 24))?;
        let outside = state.join("old.txt");
        std::fs::write(&outside, "x")?;
        age(&outside, KEEP + Duration::from_hours(1))?;
        sweep(&state);
        assert!(!old.exists());
        assert!(nearly.exists());
        assert!(recent.exists());
        assert!(outside.exists(), "only the outbox is swept");
        std::fs::remove_dir_all(&state)?;
        Ok(())
    }
}
