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
use todoke_proto::transfer::ManifestLimits;
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

/// Hashes every walked file into `source` and builds the offer from
/// `sender` to `recipient`, created at `now`, every file in `suite`.
///
/// # Errors
///
/// [`SendError`].
pub fn build(
    walked: &Walked,
    sender: &Ed25519PublicKey,
    recipient: &Ed25519PublicKey,
    now: UnixTime,
    suite: ContentSuite,
    source: &mut FsSource,
) -> Result<OutgoingOffer, SendError> {
    let expires =
        UnixTime::new(now.seconds().saturating_add(OFFER_LIFETIME)).ok_or(SendError::Manifest)?;
    let mut builder =
        ManifestBuilder::new(sender, recipient, now, expires).map_err(|_| SendError::Manifest)?;
    // Manifest IDs by walk index.
    let mut ids: Vec<u32> = Vec::with_capacity(walked.entries.len());
    let mut prepared: Vec<(u32, PreparedFile)> = Vec::new();
    let id_of = |ids: &[u32], parent: Option<usize>| {
        parent
            .and_then(|index| ids.get(index).copied())
            .unwrap_or(0)
    };
    for entry in &walked.entries {
        let id = match entry {
            Walk::Directory { parent, name } => builder.add_directory(id_of(&ids, *parent), name),
            Walk::File { parent, name, path } => {
                let file = source.prepare(path).map_err(|error| match error {
                    todoke_transfer::SourceError::Io(kind) => SendError::Unreadable(kind),
                    todoke_transfer::SourceError::NotFound => {
                        SendError::Unreadable(std::io::ErrorKind::NotFound)
                    }
                })?;
                let id = builder.add_file(
                    id_of(&ids, *parent),
                    name,
                    "application/octet-stream",
                    file.size(),
                    *file.root(),
                );
                prepared.push((id, file));
                id
            }
        };
        ids.push(id);
    }
    let manifest = builder
        .build(suite, &ManifestLimits::SPEC)
        .map_err(|_| SendError::Manifest)?;
    let transfer_id = *manifest.transfer_id();
    for (id, file) in prepared {
        source.insert(transfer_id, id, file);
    }
    OutgoingOffer::new(manifest).map_err(|_| SendError::Manifest)
}

#[cfg(test)]
mod tests;
