//! Content-layer errors. They carry no key material, file bytes, hashes,
//! or peer data (§12).

use core::fmt;

/// A content operation failed. The transfer layer maps the receive-side
/// failures ([`Self::CiphertextLength`], [`Self::Authentication`],
/// [`Self::Integrity`]) to `INTEGRITY` (§12) and discards the segment;
/// none is retryable with another suite (§6, §8).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentError {
    /// A file binding is out of range: a zero transfer ID (§1), a zero file
    /// ID (§7.1), or a size above 1 TiB (§6).
    InvalidFile,
    /// This device does not advertise the file's suite: AES-256-GCM without
    /// an approved hardware AES implementation (§6).
    SuiteUnavailable,
    /// The segment index is not below the file's segment count (§7.4).
    SegmentOutOfRange,
    /// The content ciphertext is outside 24..=32784 bytes (§7.4).
    CiphertextLength,
    /// The content AEAD did not authenticate (§8).
    Authentication,
    /// The authenticated Bao slice is invalid: wrong length header, bad
    /// proof or content for the manifest root, too few bytes, or trailing
    /// bytes (§7.4).
    Integrity,
    /// The sender's source file or outboard no longer matches the manifest
    /// root and size (§8 requires detecting source mutation). The transfer
    /// needs a new transfer ID, master, and consent.
    SourceChanged,
    /// Reading the sender's source file or outboard failed.
    SourceIo(std::io::ErrorKind),
    /// Key derivation failed inside libcrux; unreachable for these fixed
    /// lengths, and fails closed.
    KeyDerivation,
}

impl fmt::Display for ContentError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidFile => "invalid file binding",
            Self::SuiteUnavailable => "content suite not available on this device",
            Self::SegmentOutOfRange => "segment index out of range",
            Self::CiphertextLength => "content ciphertext length out of range",
            Self::Authentication => "content authentication failed",
            Self::Integrity => "content integrity check failed",
            Self::SourceChanged => "source file changed since the manifest was built",
            Self::SourceIo(_) => "reading the source file failed",
            Self::KeyDerivation => "content key derivation failed",
        })
    }
}

impl std::error::Error for ContentError {}
