//! The `FileKey` body (§8). It carries a file master, so it is encoded only
//! into zeroizing buffers and never printed.

use core::fmt;

use zeroize::Zeroizing;

use super::{ContentSuite, FileMaster};

/// `FileKey` body length: transfer ID, Accept hash, file ID, suite, master.
pub const FILE_KEY_BODY_LEN: usize = 86;

/// Why a `FileKey` body was rejected. Carries no input bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FileKeyError {
    /// Not exactly 86 bytes.
    Length,
    /// An all-zero transfer ID (§1).
    TransferId,
    /// File ID 0 is the implicit root, not a regular file (§7.1).
    FileId,
    /// A suite other than 1 or 2.
    Suite,
}

impl fmt::Display for FileKeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Length => "FileKey body length is not 86 bytes",
            Self::TransferId => "FileKey transfer ID is zero",
            Self::FileId => "FileKey file ID is zero",
            Self::Suite => "FileKey content suite is not 1 or 2",
        })
    }
}

impl std::error::Error for FileKeyError {}

/// A decoded `FileKey` body (§8):
///
/// | Field | Bytes |
/// | --- | ---: |
/// | `transfer_id` | 16 |
/// | `accept_hash` | 32 |
/// | `file_id` | 4 |
/// | `content_suite` | 2 |
/// | `file_master` | 32 |
///
/// Decoding checks only the layout. The transfer layer must still check,
/// before using the master, that the transfer is accepted in this session,
/// `accept_hash` is the current Accept's, the file is selected, and the
/// suite equals the manifest's; that each file gets exactly one master
/// ([`FileMaster::ct_eq`] for identical retransmissions); and that no
/// `FileKey` arrives before Accept (`CONSENT_REQUIRED`).
pub struct FileKeyBody {
    transfer_id: [u8; 16],
    accept_hash: [u8; 32],
    file_id: u32,
    suite: ContentSuite,
    master: FileMaster,
}

impl FileKeyBody {
    /// Assembles a body for sending.
    ///
    /// # Errors
    ///
    /// [`FileKeyError::TransferId`] or [`FileKeyError::FileId`] for a zero
    /// ID.
    pub fn new(
        transfer_id: [u8; 16],
        accept_hash: [u8; 32],
        file_id: u32,
        suite: ContentSuite,
        master: FileMaster,
    ) -> Result<Self, FileKeyError> {
        if transfer_id == [0; 16] {
            return Err(FileKeyError::TransferId);
        }
        if file_id == 0 {
            return Err(FileKeyError::FileId);
        }
        Ok(Self {
            transfer_id,
            accept_hash,
            file_id,
            suite,
            master,
        })
    }

    /// Decodes exactly 86 bytes. The length is checked before anything is
    /// read; the master is copied only into a zeroizing buffer.
    ///
    /// # Errors
    ///
    /// [`FileKeyError`] for a wrong length, zero transfer or file ID, or an
    /// unknown suite.
    pub fn decode(bytes: &[u8]) -> Result<Self, FileKeyError> {
        let body: &[u8; FILE_KEY_BODY_LEN] = bytes.try_into().map_err(|_| FileKeyError::Length)?;
        let (transfer_id, rest) = body.split_first_chunk::<16>().ok_or(FileKeyError::Length)?;
        let (accept_hash, rest) = rest.split_first_chunk::<32>().ok_or(FileKeyError::Length)?;
        let (file_id, rest) = rest.split_first_chunk::<4>().ok_or(FileKeyError::Length)?;
        let (suite, master) = rest.split_first_chunk::<2>().ok_or(FileKeyError::Length)?;
        let suite = ContentSuite::from_id(u16::from_be_bytes(*suite)).ok_or(FileKeyError::Suite)?;
        let mut secret = Zeroizing::new([0; 32]);
        secret.copy_from_slice(master);
        Self::new(
            *transfer_id,
            *accept_hash,
            u32::from_be_bytes(*file_id),
            suite,
            FileMaster::from_secret(secret),
        )
    }

    /// The 86-byte encoding, in a zeroizing buffer: it contains the master.
    #[must_use]
    pub fn encode(&self) -> Zeroizing<[u8; FILE_KEY_BODY_LEN]> {
        let mut body = Zeroizing::new([0; FILE_KEY_BODY_LEN]);
        body[..16].copy_from_slice(&self.transfer_id);
        body[16..48].copy_from_slice(&self.accept_hash);
        body[48..52].copy_from_slice(&self.file_id.to_be_bytes());
        body[52..54].copy_from_slice(&self.suite.id().to_be_bytes());
        body[54..].copy_from_slice(self.master.secret());
        body
    }

    /// The transfer ID.
    #[must_use]
    pub const fn transfer_id(&self) -> &[u8; 16] {
        &self.transfer_id
    }

    /// The Accept hash this key was sent under.
    #[must_use]
    pub const fn accept_hash(&self) -> &[u8; 32] {
        &self.accept_hash
    }

    /// The manifest file ID.
    #[must_use]
    pub const fn file_id(&self) -> u32 {
        self.file_id
    }

    /// The content suite.
    #[must_use]
    pub const fn suite(&self) -> ContentSuite {
        self.suite
    }

    /// The file master.
    #[must_use]
    pub const fn master(&self) -> &FileMaster {
        &self.master
    }

    /// Takes the file master.
    #[must_use]
    pub fn into_master(self) -> FileMaster {
        self.master
    }
}

impl fmt::Debug for FileKeyBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FileKeyBody")
            .field("file_id", &self.file_id)
            .field("suite", &self.suite)
            .finish_non_exhaustive()
    }
}
