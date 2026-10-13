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
    /// A name no longer referred to the file this crate staged under it:
    /// someone replaced it during the operation. Nothing of ours was
    /// published, and whatever replaced it is left untouched.
    Replaced,
    /// Any other failure, by kind.
    Io(std::io::ErrorKind),
}

impl fmt::Display for DestError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Exists => f.write_str("the name is taken"),
            Self::NotFound => f.write_str("the entry does not exist"),
            Self::WrongKind => f.write_str("the entry is a link or of the wrong kind"),
            Self::Replaced => f.write_str("the entry was replaced during the operation"),
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
/// the platform crates (P13); not implemented here.
///
/// - **Windows:** the Mark of the Web through Attachment Services
///   (`IAttachmentExecute`: `SetClientGuid`, `SetLocalPath`, then `Save`,
///   which applies the zone policy and records the zone in the file's
///   `Zone.Identifier` alternate data stream, the `[ZoneTransfer]` section
///   with `ZoneId=3` for the Internet zone). `SmartScreen` and Office
///   Protected View act on it. Use the API rather than writing the stream
///   by hand; volumes without alternate data streams (FAT, exFAT) cannot
///   carry the mark.
/// - **macOS:** the `com.apple.quarantine` attribute through `NSURL`'s
///   `NSURLQuarantinePropertiesKey` resource value, a dictionary with the
///   `LSQuarantine.h` keys (`kLSQuarantineTypeKey` =
///   `kLSQuarantineTypeOtherDownload`, `kLSQuarantineAgentNameKey`), never
///   by writing the attribute's undocumented format by hand; Gatekeeper
///   checks it when the file is opened. The keys are macOS-only.
/// - **Linux:** no system-wide equivalent; desktop environments may read
///   the `user.xdg.origin.url` extended attribute (freedesktop.org shared
///   metadata), which carries no enforcement. **iOS, Android:** none.
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

    /// The names in `dir` (lossily converted where they are not UTF-8), or
    /// `None` if it holds more than `limit` entries. Used once per plan so
    /// that most candidate names need no lookup of their own.
    ///
    /// # Errors
    ///
    /// [`DestError`].
    fn list(&self, dir: &Self::Dir, limit: usize) -> Result<Option<Vec<String>>, DestError>;

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
    /// permission. The returned file stays open until
    /// [`Self::release`]: publication is bound to it, not to the name.
    ///
    /// # Errors
    ///
    /// [`DestError::Exists`]; [`DestError`].
    fn stage(&self, dir: &Self::Dir, temp: &str) -> Result<Self::Staged, DestError>;

    /// Marks the staged file's origin (see [`OriginMarker`]) and makes its
    /// content durable. The file stays open.
    ///
    /// # Errors
    ///
    /// [`DestError`].
    fn finish_staged(&self, staged: &Self::Staged) -> Result<(), DestError>;

    /// Publishes `staged`, the finished file created as `temp` in `dir`,
    /// as `name` without replacing anything, atomically where the
    /// filesystem allows, and only if `name` then refers to `staged`
    /// itself: the whole-file check was made over the bytes written through
    /// that handle, and anyone who can write `dir` can see and replace the
    /// temporary name. On [`DestError::Exists`] the temporary file is still
    /// there, so the caller can try another name.
    ///
    /// # Errors
    ///
    /// [`DestError::Exists`]; [`DestError::Replaced`] if `temp` or `name`
    /// referred to something else (nothing of ours was published, and the
    /// substitute is left untouched); [`DestError`].
    fn publish(
        &self,
        dir: &Self::Dir,
        staged: &Self::Staged,
        temp: &str,
        name: &str,
    ) -> Result<Atomicity, DestError>;

    /// Closes `staged` and removes its temporary name `temp` from `dir` if
    /// that name still refers to it (after a hard-link publication it is a
    /// second link to the published file; after a rename it is gone).
    /// Whatever else is under the name is left alone. Call it after
    /// [`Self::publish`], successful or not, and when giving up on a staged
    /// file.
    ///
    /// # Errors
    ///
    /// [`DestError`]; the temporary name may then remain, for start-up
    /// clean-up.
    fn release(&self, dir: &Self::Dir, staged: Self::Staged, temp: &str) -> Result<(), DestError>;

    /// Whether names `a` and `b` in `dir` are both the same regular file
    /// (two hard links), without following links. A missing name is not.
    /// Start-up clean-up uses it to remove a temporary name left as a
    /// second link to a published file, and nothing else.
    ///
    /// # Errors
    ///
    /// [`DestError`].
    fn same_file(&self, dir: &Self::Dir, a: &str, b: &str) -> Result<bool, DestError>;

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
