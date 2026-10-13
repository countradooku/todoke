//! Platform storage: where verified files are published.
//!
//! [`Destination`] is the publication target abstraction: every operation
//! is relative to a directory handle obtained from the destination root
//! without following links, every name is one component that
//! [`crate::DestinationPlan`] produced, files are created exclusively
//! under a temporary name and published under their final name without
//! replacing anything.
//!
//! | Platform | Implementation | Status |
//! | --- | --- | --- |
//! | Linux, macOS, Windows (and any POSIX directory on Android or iOS) | [`DirDestination`] | Here |
//! | Android Storage Access Framework (a user-picked tree URI) | An adapter over `DocumentsContract` in the Android app | Trait only; P16 |
//! | iOS app sandbox and user-picked folders | An adapter using `NSFileCoordinator` and security-scoped URLs in the iOS app | Trait only; P17 |
//!
//! **Android SAF (P16).** `DocumentsContract.createDocument(parent, mime,
//! displayName)` creates a document and never overwrites: providers pick
//! a free display name (the external storage provider appends `" (1)"`),
//! so [`Destination::publish`] must report the name the provider chose,
//! which the sink records. There is no rename-without-replace, so the
//! adapter writes the content into the document created under its final
//! name through a `ParcelFileDescriptor` and deletes it on failure
//! (publication is not atomic there; [`Atomicity::Copied`]). Directory
//! handles are document URIs; there are no links to follow. The private
//! quarantine stays in app-internal storage (a POSIX directory).
//!
//! **iOS (P17).** The app container (`Documents`) is POSIX, so
//! [`DirDestination`] works there unchanged. A folder the user picks
//! outside the container is a security-scoped URL: the adapter brackets
//! every operation with `startAccessingSecurityScopedResource` /
//! `stopAccessingSecurityScopedResource` and coordinates writes with
//! `NSFileCoordinator` so File Provider extensions (iCloud Drive and
//! others) see consistent state; the file system operations underneath are
//! the same `openat`-style calls.

use core::fmt;
use std::io::{Read, Write};

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

#[cfg(any(unix, windows))]
mod dir;

#[cfg(any(unix, windows))]
pub use dir::{DirDestination, DirHandle, StagedFile};

/// A destination operation failed. Carries a code, never a name or path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DestError {
    /// The name is taken.
    Exists,
    /// The entry does not exist.
    NotFound,
    /// The entry is a link, or not the kind expected (a directory where a
    /// file was expected, a device, a FIFO): refused, never followed.
    WrongKind,
    /// Any other failure, by kind.
    Io(std::io::ErrorKind),
}

impl fmt::Display for DestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exists => f.write_str("the name is taken"),
            Self::NotFound => f.write_str("the entry does not exist"),
            Self::WrongKind => f.write_str("the entry is a link or of the wrong kind"),
            Self::Io(kind) => write!(f, "destination storage failed: {kind}"),
        }
    }
}

impl std::error::Error for DestError {}

impl From<std::io::Error> for DestError {
    fn from(error: std::io::Error) -> Self {
        match error.kind() {
            std::io::ErrorKind::AlreadyExists => Self::Exists,
            std::io::ErrorKind::NotFound => Self::NotFound,
            kind => Self::Io(kind),
        }
    }
}

/// How a file was published.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Atomicity {
    /// The complete file appeared under its final name in one step
    /// (rename without replacement, or a hard link).
    Atomic,
    /// The filesystem offers neither: the content was copied into a file
    /// created exclusively under its final name. Nothing was overwritten,
    /// but a crash during the copy can leave a truncated file there.
    Copied,
}

/// Marks a received file with its origin before it gets its final name,
/// so the platform treats it as downloaded from elsewhere. Implemented by
/// the platform crates (P13):
///
/// - **Windows:** the Mark of the Web, an NTFS alternate data stream named
///   `Zone.Identifier` containing `[ZoneTransfer]` and `ZoneId=3`
///   (Internet zone), written through `IAttachmentExecute::Save` or the
///   stream directly; `SmartScreen` and Office Protected View act on it.
///   Volumes without alternate data streams (FAT, exFAT) cannot carry it.
/// - **macOS:** the `com.apple.quarantine` extended attribute, set through
///   `NSURL`'s `NSURLQuarantinePropertiesKey` resource value (Launch
///   Services), never by writing the attribute's undocumented format by
///   hand; Gatekeeper checks it when the file is opened.
/// - **Linux:** no system-wide equivalent; desktop environments may read
///   the `user.xdg.origin.url` extended attribute (freedesktop.org shared
///   metadata), which carries no enforcement.
///
/// `path` is where the staged file is expected to be, for APIs that need
/// a path; the file handle is authoritative. An implementation returns
/// `Ok` where the volume cannot carry the mark.
pub trait OriginMarker: Send + Sync {
    /// Marks `file`.
    ///
    /// # Errors
    ///
    /// [`DestError`]: publication fails rather than publish an unmarked
    /// file where a mark was possible.
    fn mark(&self, file: &std::fs::File, path: &std::path::Path) -> Result<(), DestError>;
}

/// A publication target. Every name passed in is one component from a
/// [`crate::DestinationPlan`] (or a temporary name of this crate); every
/// directory handle comes from [`Self::root`], [`Self::create_dir`], or
/// [`Self::open_dir`], so no operation can leave the destination root.
pub trait Destination {
    /// An open directory inside the destination.
    type Dir;
    /// A file being written under a temporary name.
    type Staged: Write;
    /// A published file, opened for reading.
    type Reader: Read;

    /// The destination root.
    ///
    /// # Errors
    ///
    /// [`DestError`].
    fn root(&self) -> Result<Self::Dir, DestError>;

    /// Whether `name` exists in `dir`, without following a link.
    ///
    /// # Errors
    ///
    /// [`DestError`] other than [`DestError::NotFound`].
    fn exists(&self, dir: &Self::Dir, name: &str) -> Result<bool, DestError>;

    /// Creates directory `name` in `dir` and opens it.
    ///
    /// # Errors
    ///
    /// [`DestError::Exists`] if the name is taken (by anything, including
    /// a link); [`DestError`].
    fn create_dir(&self, dir: &Self::Dir, name: &str) -> Result<Self::Dir, DestError>;

    /// Opens the existing directory `name` in `dir`.
    ///
    /// # Errors
    ///
    /// [`DestError::WrongKind`] for a link or anything but a directory;
    /// [`DestError::NotFound`]; [`DestError`].
    fn open_dir(&self, dir: &Self::Dir, name: &str) -> Result<Self::Dir, DestError>;

    /// Creates the temporary file `temp` in `dir`, exclusively (never
    /// opening an existing entry or following a link), without execute
    /// permission.
    ///
    /// # Errors
    ///
    /// [`DestError::Exists`]; [`DestError`].
    fn stage(&self, dir: &Self::Dir, temp: &str) -> Result<Self::Staged, DestError>;

    /// Marks the staged file's origin (see [`OriginMarker`]), makes its
    /// content durable, and closes it.
    ///
    /// # Errors
    ///
    /// [`DestError`].
    fn finish_staged(&self, staged: Self::Staged) -> Result<(), DestError>;

    /// Publishes the finished temporary file `temp` as `name` in `dir`
    /// without replacing anything, atomically where the filesystem
    /// allows. On [`DestError::Exists`] the temporary file is still there,
    /// so the caller can try another name.
    ///
    /// # Errors
    ///
    /// [`DestError::Exists`]; [`DestError`].
    fn publish(&self, dir: &Self::Dir, temp: &str, name: &str) -> Result<Atomicity, DestError>;

    /// Removes the temporary file `temp` from `dir` if it is there (a
    /// link there is removed, not followed).
    ///
    /// # Errors
    ///
    /// [`DestError`] other than [`DestError::NotFound`].
    fn discard(&self, dir: &Self::Dir, temp: &str) -> Result<(), DestError>;

    /// Opens the published regular file `name` in `dir` for reading.
    ///
    /// # Errors
    ///
    /// [`DestError::WrongKind`] for a link or anything but a regular
    /// file; [`DestError::NotFound`]; [`DestError`].
    fn open_file(&self, dir: &Self::Dir, name: &str) -> Result<Self::Reader, DestError>;

    /// Makes `dir`'s entries (creations, renames, removals) durable, as
    /// far as the platform supports.
    ///
    /// # Errors
    ///
    /// [`DestError`].
    fn sync_dir(&self, dir: &Self::Dir) -> Result<(), DestError>;

    /// The root's path length in the plan's units, for
    /// [`crate::DestinationPlan::new`].
    fn root_len(&self) -> usize;
}
