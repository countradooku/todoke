//! Building an offer from files and folders the local user chose.
//!
//! The paths are the user's choice, but what is inside a chosen folder is
//! not: a link in it could point anywhere. So the walk never follows a
//! symbolic link (or a Windows junction), and sends only regular files and
//! directories; anything else is skipped and counted. Names are sent in
//! Unicode NFC (§7.1; macOS stores NFD); a name that is not valid Unicode
//! is skipped. The walk stops at the §13 bounds (10000 entries, 64 levels)
//! before reading further.
//!
//! Every file is opened and hashed once ([`FsSource::prepare`]) and stays
//! open: what was hashed is what is sent, and a file changed afterwards
//! fails the transfer rather than sending other bytes (§8).

use core::fmt;
use std::path::{Path, PathBuf};

use todoke_crypto::content::ContentSuite;
use todoke_crypto::identity::Ed25519PublicKey;
use todoke_fs::{FsSource, PreparedFile};
use todoke_proto::time::UnixTime;
use todoke_proto::transfer::{ManifestLimits, TransferId};
use todoke_transfer::{ManifestBuilder, OutgoingOffer};
use unicode_normalization::UnicodeNormalization as _;

/// How long an offer stays valid; resume is possible within it (§7.5).
pub const OFFER_LIFETIME: u64 = 7 * 86_400;
/// At most this many entries are walked (§13).
pub const MAX_ENTRIES: usize = 10_000;
/// At most this many directory levels (§13).
pub const MAX_DEPTH: usize = 64;

/// Why files could not be offered.
#[derive(Debug, PartialEq, Eq)]
pub enum SendError {
    /// Nothing to send: no path, or nothing sendable under them.
    Empty,
    /// More entries or deeper folders than the protocol allows.
    TooLarge,
    /// A chosen path could not be read.
    Unreadable(std::io::ErrorKind),
    /// The manifest could not be built.
    Manifest,
}

impl fmt::Display for SendError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => f.write_str("nothing to send"),
            Self::TooLarge => f.write_str("more files or deeper folders than a transfer allows"),
            Self::Unreadable(kind) => write!(f, "a chosen file could not be read: {kind}"),
            Self::Manifest => f.write_str("the offer could not be built"),
        }
    }
}

impl std::error::Error for SendError {}

/// What a walk found.
#[derive(Debug, Default)]
pub struct Walked {
    entries: Vec<Walk>,
    /// Entries skipped: links, special files, names that are not Unicode.
    pub skipped: usize,
}

#[derive(Debug)]
enum Walk {
    /// A directory: its parent's index in the walk (`None` at the top) and
    /// its name.
    Directory { parent: Option<usize>, name: String },
    /// A regular file.
    File {
        parent: Option<usize>,
        name: String,
        path: PathBuf,
    },
}

/// Walks the chosen `paths` without following links.
///
/// # Errors
///
/// [`SendError`].
pub fn walk(paths: &[PathBuf]) -> Result<Walked, SendError> {
    let mut walked = Walked::default();
    for path in paths {
        visit(path, None, 0, &mut walked)?;
    }
    if walked
        .entries
        .iter()
        .all(|entry| matches!(entry, Walk::Directory { .. }))
    {
        return Err(SendError::Empty);
    }
    Ok(walked)
}

fn visit(
    path: &Path,
    parent: Option<usize>,
    depth: usize,
    walked: &mut Walked,
) -> Result<(), SendError> {
    if depth >= MAX_DEPTH {
        return Err(SendError::TooLarge);
    }
    if walked.entries.len() >= MAX_ENTRIES {
        return Err(SendError::TooLarge);
    }
    let metadata = std::fs::symlink_metadata(path).map_err(|error| {
        // A chosen top-level path must exist; inside a folder, a vanished
        // entry is skipped.
        SendError::Unreadable(error.kind())
    })?;
    let Some(name) = path
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.nfc().collect::<String>())
    else {
        walked.skipped += 1;
        return Ok(());
    };
    let kind = metadata.file_type();
    if kind.is_symlink() {
        walked.skipped += 1;
    } else if kind.is_file() {
        walked.entries.push(Walk::File {
            parent,
            name,
            path: path.to_owned(),
        });
    } else if kind.is_dir() {
        walked.entries.push(Walk::Directory { parent, name });
        let index = walked.entries.len() - 1;
        let mut children: Vec<PathBuf> = std::fs::read_dir(path)
            .map_err(|error| SendError::Unreadable(error.kind()))?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .collect();
        children.sort();
        for child in children {
            match visit(&child, Some(index), depth + 1, walked) {
                Err(SendError::Unreadable(_)) => walked.skipped += 1,
                other => other?,
            }
        }
    } else {
        walked.skipped += 1;
    }
    Ok(())
}

/// Files prepared for an offer whose manifest is built once a session has
/// negotiated its content suite and the receiver's limits (§6): every new
/// file must use the negotiated suite.
#[derive(Debug)]
pub struct Prepared {
    transfer_id: TransferId,
    created_at: UnixTime,
    entries: Vec<PreparedEntry>,
}

#[derive(Debug)]
struct PreparedEntry {
    parent: Option<usize>,
    name: String,
    /// `None` for a directory.
    file: Option<(u64, [u8; 32])>,
}

impl Prepared {
    /// The transfer ID the offer will carry.
    #[must_use]
    pub const fn transfer_id(&self) -> &TransferId {
        &self.transfer_id
    }

    /// Bytes in all files.
    #[must_use]
    pub fn total_bytes(&self) -> u64 {
        self.entries
            .iter()
            .filter_map(|entry| entry.file.map(|(size, _)| size))
            .sum()
    }
}

/// Hashes every walked file into `source` under a fresh random transfer ID
/// (from the OS CSPRNG, §1, §7), created at `now`. The files stay open.
///
/// # Errors
///
/// [`SendError`].
pub fn prepare(
    walked: &Walked,
    now: UnixTime,
    source: &mut FsSource,
) -> Result<Prepared, SendError> {
    let mut transfer_id = [0; 16];
    getrandom::fill(&mut transfer_id).map_err(|_| SendError::Manifest)?;
    if transfer_id == [0; 16] {
        return Err(SendError::Manifest);
    }
    let mut entries = Vec::with_capacity(walked.entries.len());
    let mut files: Vec<(usize, PreparedFile)> = Vec::new();
    for entry in &walked.entries {
        match entry {
            Walk::Directory { parent, name } => entries.push(PreparedEntry {
                parent: *parent,
                name: name.clone(),
                file: None,
            }),
            Walk::File { parent, name, path } => {
                let file = source.prepare(path).map_err(|error| match error {
                    todoke_transfer::SourceError::Io(kind) => SendError::Unreadable(kind),
                    todoke_transfer::SourceError::NotFound => {
                        SendError::Unreadable(std::io::ErrorKind::NotFound)
                    }
                })?;
                entries.push(PreparedEntry {
                    parent: *parent,
                    name: name.clone(),
                    file: Some((file.size(), *file.root())),
                });
                files.push((entries.len() - 1, file));
            }
        }
    }
    // Manifest IDs are 1-based walk positions (the builder numbers entries
    // in the order they are added).
    for (index, file) in files {
        let id = u32::try_from(index + 1).map_err(|_| SendError::TooLarge)?;
        source.insert(transfer_id, id, file);
    }
    Ok(Prepared {
        transfer_id,
        created_at: now,
        entries,
    })
}

/// The offer from `sender` to `recipient` for `prepared`, every file in
/// `suite`, within `limits` (the receiver's).
///
/// # Errors
///
/// [`SendError::Manifest`] if it exceeds `limits` or cannot be built.
pub fn build(
    prepared: &Prepared,
    sender: &Ed25519PublicKey,
    recipient: &Ed25519PublicKey,
    suite: ContentSuite,
    limits: &ManifestLimits,
) -> Result<OutgoingOffer, SendError> {
    let expires = UnixTime::new(prepared.created_at.seconds().saturating_add(OFFER_LIFETIME))
        .ok_or(SendError::Manifest)?;
    let mut builder = ManifestBuilder::with_transfer_id(
        prepared.transfer_id,
        sender,
        recipient,
        prepared.created_at,
        expires,
    );
    let mut ids: Vec<u32> = Vec::with_capacity(prepared.entries.len());
    for entry in &prepared.entries {
        let parent = entry
            .parent
            .and_then(|index| ids.get(index).copied())
            .unwrap_or(0);
        let id = match entry.file {
            None => builder.add_directory(parent, &entry.name),
            Some((size, root)) => {
                builder.add_file(parent, &entry.name, "application/octet-stream", size, root)
            }
        };
        // The source holds each file under its 1-based position (prepare).
        if usize::try_from(id).ok() != Some(ids.len() + 1) {
            return Err(SendError::Manifest);
        }
        ids.push(id);
    }
    let manifest = builder
        .build(suite, limits)
        .map_err(|_| SendError::Manifest)?;
    OutgoingOffer::new(manifest).map_err(|_| SendError::Manifest)
}

#[cfg(test)]
mod tests;
