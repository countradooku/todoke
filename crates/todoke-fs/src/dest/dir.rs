//! [`DirDestination`]: a destination directory on a desktop filesystem
//! (Linux, macOS, Windows), or any POSIX directory on Android and iOS.

use core::fmt;
use std::fs::File;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use super::unix as sys;
#[cfg(windows)]
use super::windows as sys;
use super::{Atomicity, DestError, Destination, OriginMarker};
use crate::plan::PathLimit;

/// An open directory inside a [`DirDestination`]. `Debug` shows no path.
pub struct DirHandle {
    handle: sys::Handle,
    /// Where the directory is expected to be: for path-based platform
    /// calls (Windows, the origin marker); never logged.
    path: PathBuf,
}

#[cfg(test)]
impl DirHandle {
    /// Where the directory is expected to be (tests only).
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

impl fmt::Debug for DirHandle {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("DirHandle")
    }
}

/// A file being written under its temporary name, held open from creation
/// until it is released, so that publication is bound to this file rather
/// than to whatever the name refers to by then.
pub struct StagedFile {
    file: File,
    path: PathBuf,
}

impl fmt::Debug for StagedFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("StagedFile")
    }
}

impl Write for StagedFile {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.file.write(buf)
    }

    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.file.write_all(buf)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.file.flush()
    }
}

/// A destination directory chosen by the user (for example Downloads).
/// See [`Destination`] for the guarantees; `Debug` shows no path.
pub struct DirDestination {
    root: DirHandle,
    /// Held while the sink retains transfers (Windows: without
    /// `FILE_SHARE_DELETE`, pinning the folder; Unix: a harmless
    /// duplicate).
    pin: Option<sys::Handle>,
    limit: PathLimit,
    marker: Option<Box<dyn OriginMarker>>,
}

impl fmt::Debug for DirDestination {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DirDestination")
            .field("held", &self.pin.is_some())
            .field("marker", &self.marker.is_some())
            .finish_non_exhaustive()
    }
}

impl DirDestination {
    /// Opens the destination directory `root`. The root itself is the
    /// user's choice and may be reached through links; everything below it
    /// is resolved without following any.
    ///
    /// # Errors
    ///
    /// [`DestError`] if `root` is not an accessible directory.
    pub fn open(root: &Path) -> Result<Self, DestError> {
        let path = std::fs::canonicalize(root)?;
        let handle = sys::open_root(&path)?;
        Ok(Self {
            root: DirHandle { handle, path },
            pin: None,
            limit: PathLimit::host(),
            marker: None,
        })
    }

    /// Marks every published file with `marker` before it gets its final
    /// name.
    #[must_use]
    pub fn with_origin_marker(mut self, marker: Box<dyn OriginMarker>) -> Self {
        self.marker = Some(marker);
        self
    }

    /// The canonical root path (absolute; verbatim `\\?\` form on
    /// Windows). Local data; never log it.
    #[must_use]
    pub fn root_path(&self) -> &Path {
        &self.root.path
    }
}

impl Destination for DirDestination {
    type Dir = DirHandle;
    type Staged = StagedFile;
    type Reader = File;

    fn root(&self) -> Result<DirHandle, DestError> {
        Ok(DirHandle {
            handle: sys::duplicate(&self.root.handle, &self.root.path)?,
            path: self.root.path.clone(),
        })
    }

    fn list(&self, dir: &DirHandle, limit: usize) -> Result<Option<Vec<String>>, DestError> {
        sys::list(&dir.handle, &dir.path, limit)
    }

    fn exists(&self, dir: &DirHandle, name: &str) -> Result<bool, DestError> {
        sys::exists(&dir.handle, &dir.path, name)
    }

    fn create_dir(&self, dir: &DirHandle, name: &str) -> Result<DirHandle, DestError> {
        sys::create_dir(&dir.handle, &dir.path, name)?;
        self.open_dir(dir, name)
    }

    fn open_dir(&self, dir: &DirHandle, name: &str) -> Result<DirHandle, DestError> {
        let handle = sys::open_dir(&dir.handle, &dir.path, name)?;
        Ok(DirHandle {
            handle,
            path: dir.path.join(name),
        })
    }

    fn stage(&self, dir: &DirHandle, temp: &str) -> Result<StagedFile, DestError> {
        let file = sys::create_new_file(&dir.handle, &dir.path, temp)?;
        Ok(StagedFile {
            file,
            path: dir.path.join(temp),
        })
    }

    fn finish_staged(&self, staged: &StagedFile) -> Result<(), DestError> {
        if let Some(marker) = &self.marker {
            marker.mark(&staged.file, &staged.path)?;
        }
        staged.file.sync_all()?;
        Ok(())
    }

    fn publish(
        &self,
        dir: &DirHandle,
        staged: &StagedFile,
        temp: &str,
        name: &str,
    ) -> Result<Atomicity, DestError> {
        sys::publish(&dir.handle, &dir.path, &staged.file, temp, name)
    }

    fn release(&self, dir: &DirHandle, staged: StagedFile, temp: &str) -> Result<(), DestError> {
        sys::release(&dir.handle, &dir.path, staged.file, temp)
    }

    fn same_file(&self, dir: &DirHandle, a: &str, b: &str) -> Result<bool, DestError> {
        sys::same_file(&dir.handle, &dir.path, a, b)
    }

    fn discard(&self, dir: &DirHandle, temp: &str) -> Result<(), DestError> {
        sys::remove_file(&dir.handle, &dir.path, temp)
    }

    fn open_file(&self, dir: &DirHandle, name: &str) -> Result<File, DestError> {
        sys::open_file(&dir.handle, &dir.path, name)
    }

    fn sync_dir(&self, dir: &DirHandle) -> Result<(), DestError> {
        #[cfg(windows)]
        {
            sys::sync_dir(&dir.handle);
            Ok(())
        }
        #[cfg(unix)]
        sys::sync_dir(&dir.handle)
    }

    fn root_len(&self) -> usize {
        self.limit.measure(&self.root.path.to_string_lossy())
    }

    fn hold_root(&mut self, held: bool) -> Result<(), DestError> {
        if !held {
            self.pin = None;
        } else if self.pin.is_none() {
            self.pin = Some(sys::duplicate(&self.root.handle, &self.root.path)?);
        }
        Ok(())
    }
}
