//! Per-file content encryption and verified segments (PROTOCOL §6, §7.4,
//! §7.5, §8).
//!
//! This is the cryptographic content layer only. Manifests, `Accept`,
//! `FileKey`/`ChunkRequest`/`Chunk`/`ResumeQuery` wire handling, and the
//! transfer state machines belong to the transfer layer and are not
//! implemented here.
//!
//! # Layers
//!
//! | Piece | What it does | Spec |
//! | --- | --- | --- |
//! | [`ContentSuite`], [`ContentSuites`] | Suite IDs 1 (AES-256-GCM STREAM) and 2 (XChaCha20-Poly1305 STREAM), this device's advertisement, and the §6 selection rule | §6 |
//! | [`SegmentLayout`], [`Segment`] | 16384-byte logical segments, epochs of 65536 segments, the final flag | §7.4, §8 |
//! | [`FileMaster`], key schedule (private) | Fresh 32-byte master per file; per-epoch key and nonce prefix by HKDF-SHA-256; STREAM BE32 nonces; the 123-byte AAD | §8 |
//! | [`outboard`], [`write_outboard`] | BLAKE3 root and Bao 0.13.1 outboard tree of a source file | §7.1, §7.4 |
//! | [`ContentSealer`] | Sender: extract the canonical Bao slice, check it against the manifest root (source mutation), then seal it | §7.4, §8 |
//! | [`ContentOpener`], [`VerifiedSegment`] | Receiver: authenticate, then strictly verify the Bao slice against the root | §7.4, §8 |
//! | [`SegmentTracker`] | Receiver: verified segments as ranges, missing segments, resume pages | §7.4, §7.5 |
//! | [`FileKeyBody`] | The 86-byte `FileKey` body codec (secret-bearing) | §8 |
//!
//! # Consent
//!
//! Sealing and opening require an [`AcceptedFile`]. Only the transfer
//! layer's verified-Accept path may create one, through the crate-private
//! `AcceptedFile::from_verified_accept`, which nothing calls yet: the
//! signed Accept (§7.2, §7.3) is not implemented. Until it is, the only
//! other constructor is
//! `AcceptedFile::assume_accepted_without_verification`, which exists in
//! this crate's unit tests and with the non-default
//! `insecure-content-without-accept` feature (benchmarks). CI fails if a
//! shipped graph enables it. A file binding alone ([`FileBinding`]) is public
//! metadata and authorizes nothing.
//!
//! # Verification order
//!
//! [`ContentOpener::open_segment`] checks the ciphertext length, decrypts
//! and authenticates the AEAD, and only then parses the Bao slice: the
//! little-endian length header must equal the manifest size, the decoder
//! must yield exactly the segment's logical bytes verified against the
//! manifest root, and it must consume the whole slice with no trailing
//! bytes. The `bao` decoder's lenient cases (slices past the end of the
//! file, zero-length reads of a nonempty file, an unchecked length header
//! when the slice does not reach the final chunk) are never relied on.
//! Any failure discards the segment.
//!
//! # Secrets
//!
//! File masters, the HKDF pseudorandom key, epoch keys, and nonce prefixes
//! live in `Zeroizing` buffers and appear in no `Debug` output or error;
//! decrypted slices are zeroized when dropped. libcrux-aes keeps its AES
//! key schedule, and libcrux's `XChaCha20` keeps its derived subkey, in
//! stack or state values it does not wipe; HKDF has the HACL temporaries
//! noted in the session module. These residues are recorded under O6 in
//! `docs/adr/0004-content-aead.md`.

mod accepted;
mod aead;
mod cipher;
mod error;
mod file_key;
#[cfg(fuzzing)]
pub mod fuzzing;
mod keys;
mod segment;
mod slice;
mod suite;
mod tracker;

#[cfg(test)]
mod tests;

pub use accepted::{AcceptedFile, FileBinding};
pub use cipher::{ContentOpener, ContentSealer, VerifiedSegment};
pub use error::ContentError;
pub use file_key::{FILE_KEY_BODY_LEN, FileKeyBody, FileKeyError};
pub use keys::FileMaster;
pub use segment::{
    EPOCH_SEGMENTS, MAX_CIPHERTEXT_LEN, MAX_FILE_SIZE, MAX_SEGMENT_COUNT, MAX_SLICE_LEN,
    MIN_CIPHERTEXT_LEN, SEGMENT_LEN, Segment, SegmentLayout, TAG_LEN,
};
pub use slice::{outboard, write_outboard};
pub use suite::{ContentSuite, ContentSuites};
pub use tracker::{
    MAX_RESUME_RANGES, MAX_TRACKED_RANGES, MissingSegments, ResumePage, SegmentTracker,
    TrackerError,
};
