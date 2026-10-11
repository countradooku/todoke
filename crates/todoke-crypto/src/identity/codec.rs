//! Bounded readers and the sealed envelope shared by local storage formats.

use zeroize::Zeroizing;

use super::sealing::Sealer;

/// A local storage blob was malformed or failed authentication.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LocalFormatError {
    /// Structure, enum, ordering, or bound violation.
    Malformed,
    /// The sealed payload failed authentication.
    Seal,
}

/// Envelope: `magic[4] || version:u16 || sealed`, with the six header bytes
/// prefixed by a fixed context string as the sealing associated data.
pub(crate) struct Envelope {
    pub(crate) magic: [u8; 4],
    pub(crate) version: u16,
    pub(crate) context: &'static [u8],
}

impl Envelope {
    const HEADER_LEN: usize = 6;

    fn header(&self) -> [u8; Self::HEADER_LEN] {
        let mut header = [0; Self::HEADER_LEN];
        header[..4].copy_from_slice(&self.magic);
        header[4..].copy_from_slice(&self.version.to_be_bytes());
        header
    }

    fn associated_data(&self) -> Vec<u8> {
        let mut aad = Vec::with_capacity(self.context.len() + Self::HEADER_LEN);
        aad.extend_from_slice(self.context);
        aad.extend_from_slice(&self.header());
        aad
    }

    pub(crate) fn seal<S: Sealer>(
        &self,
        sealer: &S,
        plaintext: &[u8],
    ) -> Result<Vec<u8>, LocalFormatError> {
        let ciphertext = sealer
            .seal(&self.associated_data(), plaintext)
            .map_err(|_| LocalFormatError::Seal)?;
        let mut out = Vec::with_capacity(Self::HEADER_LEN + ciphertext.len());
        out.extend_from_slice(&self.header());
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    pub(crate) fn open<S: Sealer>(
        &self,
        sealer: &S,
        bytes: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, LocalFormatError> {
        let (header, ciphertext) = bytes
            .split_first_chunk::<{ Self::HEADER_LEN }>()
            .ok_or(LocalFormatError::Malformed)?;
        if *header != self.header() {
            return Err(LocalFormatError::Malformed);
        }
        sealer
            .open(&self.associated_data(), ciphertext)
            .map_err(|_| LocalFormatError::Seal)
    }
}

/// Bounded big-endian reader; every read is length-checked.
pub(crate) struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self(bytes)
    }

    pub(crate) fn remaining(&self) -> usize {
        self.0.len()
    }

    pub(crate) fn bytes(&mut self, length: usize) -> Result<&'a [u8], LocalFormatError> {
        if length > self.0.len() {
            return Err(LocalFormatError::Malformed);
        }
        let (head, rest) = self.0.split_at(length);
        self.0 = rest;
        Ok(head)
    }

    /// Copies exactly `out.len()` bytes into `out`. Secrets are read this way
    /// into a caller-owned `Zeroizing` buffer, so no unwiped temporary copy is
    /// returned by value as with [`Self::array`]. On error nothing is consumed.
    pub(crate) fn read_into(&mut self, out: &mut [u8]) -> Result<(), LocalFormatError> {
        out.copy_from_slice(self.bytes(out.len())?);
        Ok(())
    }

    /// Reads public fixed-size data. Use [`Self::read_into`] for secrets.
    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], LocalFormatError> {
        let (head, rest) = self
            .0
            .split_first_chunk::<N>()
            .ok_or(LocalFormatError::Malformed)?;
        self.0 = rest;
        Ok(*head)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, LocalFormatError> {
        self.array::<1>().map(|[byte]| byte)
    }

    pub(crate) fn u16(&mut self) -> Result<u16, LocalFormatError> {
        self.array().map(u16::from_be_bytes)
    }

    pub(crate) fn u32(&mut self) -> Result<u32, LocalFormatError> {
        self.array().map(u32::from_be_bytes)
    }

    pub(crate) fn u64(&mut self) -> Result<u64, LocalFormatError> {
        self.array().map(u64::from_be_bytes)
    }

    pub(crate) fn finish(self) -> Result<(), LocalFormatError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(LocalFormatError::Malformed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity::test_support::{TestResult, sealer};

    const TEST_ENVELOPE: Envelope = Envelope {
        magic: *b"TDKT",
        version: 0x0102,
        context: b"todoke/local/test\0",
    };

    /// The blob starts with `magic || version`, and the sealed part is bound
    /// to `context || magic || version` as associated data, so a blob opens
    /// only under the exact envelope that sealed it.
    #[test]
    fn envelope_layout_and_associated_data() -> TestResult {
        let sealer = sealer(3);
        let blob = TEST_ENVELOPE
            .seal(&sealer, b"plaintext")
            .map_err(|_| "seal")?;
        assert_eq!(&blob[..6], b"TDKT\x01\x02");
        let mut aad = b"todoke/local/test\0".to_vec();
        aad.extend_from_slice(b"TDKT\x01\x02");
        assert_eq!(sealer.open(&aad, &blob[6..])?.as_slice(), b"plaintext");
        assert_eq!(
            TEST_ENVELOPE
                .open(&sealer, &blob)
                .map_err(|_| "open")?
                .as_slice(),
            b"plaintext"
        );
        // Same header, different context: authentication fails.
        let other_context = Envelope {
            context: b"todoke/local/other\0",
            ..TEST_ENVELOPE
        };
        assert_eq!(
            other_context.open(&sealer, &blob).err(),
            Some(LocalFormatError::Seal)
        );
        // A different magic or version is rejected before opening.
        for other in [
            Envelope {
                magic: *b"TDKU",
                ..TEST_ENVELOPE
            },
            Envelope {
                version: 0x0103,
                ..TEST_ENVELOPE
            },
        ] {
            assert_eq!(
                other.open(&sealer, &blob).err(),
                Some(LocalFormatError::Malformed)
            );
        }
        assert_eq!(
            TEST_ENVELOPE.open(&sealer, &blob[..5]).err(),
            Some(LocalFormatError::Malformed)
        );
        Ok(())
    }

    #[test]
    fn finish_rejects_trailing_bytes() {
        assert_eq!(Reader::new(&[]).finish(), Ok(()));
        assert_eq!(Reader::new(&[0]).finish(), Err(LocalFormatError::Malformed));
        let mut reader = Reader::new(&[1, 2, 3]);
        assert_eq!(reader.u16(), Ok(0x0102));
        assert_eq!(reader.finish(), Err(LocalFormatError::Malformed));
    }

    #[test]
    fn read_into_reads_exactly_and_fails_without_consuming() {
        let mut reader = Reader::new(&[1, 2, 3, 4, 5]);
        let mut secret = Zeroizing::new([0u8; 3]);
        assert_eq!(reader.read_into(secret.as_mut()), Ok(()));
        assert_eq!(*secret, [1, 2, 3]);
        assert_eq!(reader.remaining(), 2);
        let mut long = Zeroizing::new([0xaau8; 3]);
        assert_eq!(
            reader.read_into(long.as_mut()),
            Err(LocalFormatError::Malformed)
        );
        assert_eq!(reader.remaining(), 2);
        assert_eq!(*long, [0xaa; 3]);
        assert_eq!(reader.read_into(&mut []), Ok(()));
        assert_eq!(reader.u16(), Ok(0x0405));
        assert_eq!(reader.finish(), Ok(()));
    }
}
