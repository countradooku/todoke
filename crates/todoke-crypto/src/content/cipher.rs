//! Per-segment seal (sender) and open (receiver) (§7.4, §8).

use core::fmt;
use std::io::{Read, Seek};

use zeroize::Zeroizing;

use super::keys::{KeySchedule, content_aad};
use super::slice::{extract_slice, verify_slice};
use super::{
    AcceptedFile, ContentError, ContentSuites, FileBinding, FileMaster, MAX_CIPHERTEXT_LEN,
    MIN_CIPHERTEXT_LEN, Segment, aead,
};

/// The parts both directions share.
struct FileCipher {
    binding: FileBinding,
    schedule: KeySchedule,
}

impl FileCipher {
    fn new(file: &AcceptedFile, master: &FileMaster) -> Result<Self, ContentError> {
        Self::on_device(file, master, ContentSuites::local())
    }

    /// [`Self::new`] on a device that advertises `local`; tests use it to
    /// check the refusal on every host.
    fn on_device(
        file: &AcceptedFile,
        master: &FileMaster,
        local: ContentSuites,
    ) -> Result<Self, ContentError> {
        let binding = *file.binding();
        if !local.contains(binding.suite()) {
            return Err(ContentError::SuiteUnavailable);
        }
        let schedule = KeySchedule::new(&binding, master)?;
        Ok(Self { binding, schedule })
    }

    fn seal_slice(&self, segment: &Segment, slice: &[u8]) -> Result<Vec<u8>, ContentError> {
        let keys = self.schedule.epoch_keys(segment.epoch())?;
        let nonce = keys.nonce(segment)?;
        let aad = content_aad(&self.binding, segment);
        aead::seal(
            self.binding.suite(),
            keys.key(),
            nonce.as_slice(),
            &aad,
            slice,
        )
    }

    fn decrypt_slice(
        &self,
        segment: &Segment,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ContentError> {
        if !(MIN_CIPHERTEXT_LEN..=MAX_CIPHERTEXT_LEN).contains(&ciphertext.len()) {
            return Err(ContentError::CiphertextLength);
        }
        let keys = self.schedule.epoch_keys(segment.epoch())?;
        let nonce = keys.nonce(segment)?;
        let aad = content_aad(&self.binding, segment);
        aead::open(
            self.binding.suite(),
            keys.key(),
            nonce.as_slice(),
            &aad,
            ciphertext,
        )
    }
}

/// The sender's content cipher for one accepted file (§8).
///
/// Each call re-derives the segment's epoch key, extracts the canonical Bao
/// slice from the immutable source and its outboard, checks it against the
/// manifest root, and seals it. The output is a deterministic function of
/// the master, manifest, segment, and source bytes, so a repeated request
/// returns identical ciphertext, and a source that changed is refused
/// ([`ContentError::SourceChanged`]) instead of producing different
/// plaintext under the same key and nonce. Caching ciphertext is equally
/// valid (§8).
pub struct ContentSealer {
    cipher: FileCipher,
}

impl ContentSealer {
    /// Prepares to send `file`'s content under its master.
    ///
    /// # Errors
    ///
    /// [`ContentError::SuiteUnavailable`] if this device does not advertise
    /// the file's suite; [`ContentError::KeyDerivation`].
    pub fn new(file: &AcceptedFile, master: &FileMaster) -> Result<Self, ContentError> {
        Ok(Self {
            cipher: FileCipher::new(file, master)?,
        })
    }

    /// The file's bindings.
    #[must_use]
    pub fn binding(&self) -> &FileBinding {
        &self.cipher.binding
    }

    /// Returns the `content_ciphertext` (24..=32784 bytes) for segment
    /// `index`: the sealed Bao slice, tag appended.
    ///
    /// `content` is the source file and `outboard` its Bao outboard
    /// ([`write_outboard`](super::write_outboard)); both are read from the
    /// positions the slice needs.
    ///
    /// # Errors
    ///
    /// [`ContentError::SegmentOutOfRange`]; [`ContentError::SourceChanged`]
    /// if the source or outboard no longer matches the manifest root and
    /// size; [`ContentError::SourceIo`] for other read failures.
    pub fn seal_segment<C: Read + Seek, O: Read + Seek>(
        &self,
        index: u32,
        content: C,
        outboard: O,
    ) -> Result<Vec<u8>, ContentError> {
        let binding = &self.cipher.binding;
        let segment = binding.layout().segment(index)?;
        let slice = extract_slice(
            content,
            outboard,
            binding.layout(),
            &segment,
            binding.root(),
        )?;
        self.cipher.seal_slice(&segment, &slice)
    }

    /// [`Self::new`] on a device that advertises `local`.
    #[cfg(test)]
    pub(crate) fn on_device(
        file: &AcceptedFile,
        master: &FileMaster,
        local: ContentSuites,
    ) -> Result<Self, ContentError> {
        Ok(Self {
            cipher: FileCipher::on_device(file, master, local)?,
        })
    }

    /// Seals an arbitrary slice for `segment`, bypassing extraction; tests
    /// use it to build forgeries the sender would never produce.
    #[cfg(test)]
    pub(crate) fn seal_raw(
        &self,
        segment: &Segment,
        slice: &[u8],
    ) -> Result<Vec<u8>, ContentError> {
        self.cipher.seal_slice(segment, slice)
    }
}

impl fmt::Debug for ContentSealer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContentSealer")
            .field("binding", &self.cipher.binding)
            .finish_non_exhaustive()
    }
}

/// The receiver's content cipher for one accepted file (§7.4, §8).
pub struct ContentOpener {
    cipher: FileCipher,
}

impl ContentOpener {
    /// Prepares to receive `file`'s content under the master from its
    /// `FileKey`.
    ///
    /// # Errors
    ///
    /// [`ContentError::SuiteUnavailable`] if this device does not advertise
    /// the file's suite; [`ContentError::KeyDerivation`].
    pub fn new(file: &AcceptedFile, master: &FileMaster) -> Result<Self, ContentError> {
        Ok(Self {
            cipher: FileCipher::new(file, master)?,
        })
    }

    /// The file's bindings.
    #[must_use]
    pub fn binding(&self) -> &FileBinding {
        &self.cipher.binding
    }

    /// Opens the `content_ciphertext` of the requested segment `index`:
    /// checks the length, authenticates and decrypts with the key, nonce,
    /// and AAD rebuilt from the accepted manifest, then strictly verifies
    /// the Bao slice against the manifest root (see the
    /// [module documentation](super)).
    ///
    /// The same ciphertext opens again in a later session with a fresh
    /// Accept, which is how a restarted receiver revalidates stored
    /// segments before resuming (§7.5).
    ///
    /// # Errors
    ///
    /// [`ContentError::SegmentOutOfRange`], [`ContentError::CiphertextLength`],
    /// [`ContentError::Authentication`], or [`ContentError::Integrity`]. On
    /// any error the segment must be discarded and the transfer terminated
    /// (§7.4); there is no retry with another suite.
    pub fn open_segment(
        &self,
        index: u32,
        ciphertext: &[u8],
    ) -> Result<VerifiedSegment, ContentError> {
        let binding = &self.cipher.binding;
        let segment = binding.layout().segment(index)?;
        let slice = self.cipher.decrypt_slice(&segment, ciphertext)?;
        let data = verify_slice(&slice, binding.layout(), &segment, binding.root())?;
        Ok(VerifiedSegment {
            transfer_id: *binding.transfer_id(),
            file_id: binding.file_id(),
            segment,
            data,
        })
    }

    /// [`Self::new`] on a device that advertises `local`.
    #[cfg(test)]
    pub(crate) fn on_device(
        file: &AcceptedFile,
        master: &FileMaster,
        local: ContentSuites,
    ) -> Result<Self, ContentError> {
        Ok(Self {
            cipher: FileCipher::on_device(file, master, local)?,
        })
    }

    /// AEAD only, without the Bao checks: lets tests reach the AEAD layer
    /// with synthetic slices.
    #[cfg(test)]
    pub(crate) fn decrypt_raw(
        &self,
        segment: &Segment,
        ciphertext: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, ContentError> {
        self.cipher.decrypt_slice(segment, ciphertext)
    }
}

impl fmt::Debug for ContentOpener {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ContentOpener")
            .field("binding", &self.cipher.binding)
            .finish_non_exhaustive()
    }
}

/// A segment that passed authentication and Bao verification against the
/// accepted manifest root: its logical bytes and where they belong.
///
/// Only [`ContentOpener::open_segment`] creates one. Until it has been
/// durably stored, the receiver must not expose these bytes to a UI,
/// preview, or final path (§7.4).
pub struct VerifiedSegment {
    transfer_id: [u8; 16],
    file_id: u32,
    segment: Segment,
    data: Zeroizing<Vec<u8>>,
}

impl VerifiedSegment {
    /// The transfer this segment belongs to.
    #[must_use]
    pub const fn transfer_id(&self) -> &[u8; 16] {
        &self.transfer_id
    }

    /// The manifest file ID.
    #[must_use]
    pub const fn file_id(&self) -> u32 {
        self.file_id
    }

    /// The segment's index and range.
    #[must_use]
    pub const fn segment(&self) -> &Segment {
        &self.segment
    }

    /// The verified logical bytes, `segment().len()` of them.
    #[must_use]
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Takes the verified bytes without a copy, still in a buffer that is
    /// wiped when dropped. Moving the `Vec` out of the [`Zeroizing`]
    /// wrapper (or copying from [`data`](Self::data)) makes wiping the
    /// plaintext the caller's responsibility.
    #[must_use]
    pub fn into_data(self) -> Zeroizing<Vec<u8>> {
        self.data
    }

    #[cfg(test)]
    pub(crate) fn for_tests(binding: &FileBinding, index: u32) -> Result<Self, ContentError> {
        Ok(Self {
            transfer_id: *binding.transfer_id(),
            file_id: binding.file_id(),
            segment: binding.layout().segment(index)?,
            data: Zeroizing::new(Vec::new()),
        })
    }
}

impl fmt::Debug for VerifiedSegment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedSegment")
            .field("file_id", &self.file_id)
            .field("index", &self.segment.index())
            .field("len", &self.segment.len())
            .finish_non_exhaustive()
    }
}
