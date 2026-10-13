//! Content suites, this device's advertisement, and selection (§6, §8).

/// A per-file content suite: the manifest entry's `content_suite` (§7.1).
///
/// The suite is bound into the manifest, Accept, key derivation, and AAD.
/// Selection happens once per file from both peers' Capabilities
/// ([`ContentSuites::select`]); nothing switches suite after a failure,
/// probe, or peer request, and a resumed transfer keeps its original suite.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ContentSuite {
    /// Suite 1: AES-256-GCM, STREAM BE32 with 12-byte nonces (7-byte epoch
    /// prefix).
    Aes256GcmStream,
    /// Suite 2: XChaCha20-Poly1305, STREAM BE32 with 24-byte nonces (19-byte
    /// epoch prefix).
    XChaCha20Poly1305Stream,
}

impl ContentSuite {
    /// The wire value: 1 or 2.
    #[must_use]
    pub const fn id(self) -> u16 {
        match self {
            Self::Aes256GcmStream => 1,
            Self::XChaCha20Poly1305Stream => 2,
        }
    }

    /// Parses a wire value; 0 (directories) and 3.. are not suites.
    #[must_use]
    pub const fn from_id(id: u16) -> Option<Self> {
        match id {
            1 => Some(Self::Aes256GcmStream),
            2 => Some(Self::XChaCha20Poly1305Stream),
            _ => None,
        }
    }

    /// The epoch nonce prefix length N (§8).
    pub(crate) const fn prefix_len(self) -> usize {
        match self {
            Self::Aes256GcmStream => 7,
            Self::XChaCha20Poly1305Stream => 19,
        }
    }

    /// The AEAD nonce length: prefix, 4-byte counter, final byte (§8).
    #[cfg(test)]
    pub(crate) const fn nonce_len(self) -> usize {
        self.prefix_len() + 5
    }

    const fn bit(self) -> u16 {
        match self {
            Self::Aes256GcmStream => 1,
            Self::XChaCha20Poly1305Stream => 1 << 1,
        }
    }
}

/// The Capabilities `content_suites` field (§6): bit 0 AES-256-GCM STREAM,
/// bit 1 XChaCha20-Poly1305 STREAM, every other bit zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ContentSuites(u16);

impl ContentSuites {
    const DEFINED: u16 = 0b11;

    /// Parses the field; `None` if a reserved bit is set. Whether a set
    /// lacking `XChaCha` (which v1 peers MUST support) is acceptable is the
    /// Capabilities validator's decision, not this parser's.
    #[must_use]
    pub const fn from_bits(bits: u16) -> Option<Self> {
        if bits & !Self::DEFINED == 0 {
            Some(Self(bits))
        } else {
            None
        }
    }

    /// The wire value.
    #[must_use]
    pub const fn bits(self) -> u16 {
        self.0
    }

    /// Whether `suite` is in the set.
    #[must_use]
    pub const fn contains(self, suite: ContentSuite) -> bool {
        self.0 & suite.bit() != 0
    }

    /// What this device advertises: `XChaCha` always, and AES only where
    /// libcrux-aes uses hardware AES and carry-less multiplication, which
    /// are constant time. Its portable bit-sliced fallback is constant
    /// time too, but far slower; a device without the hardware path
    /// omits AES (§6 permits this for lack of an approved implementation),
    /// so a pair where either side lacks it uses `XChaCha`.
    ///
    /// The result depends only on the local CPU, never on a peer, and is
    /// stable for the life of the process. Fix it per session before
    /// receiving the peer's Capabilities (§6).
    #[must_use]
    pub fn local() -> Self {
        let mut bits = ContentSuite::XChaCha20Poly1305Stream.bit();
        if hardware_aes_gcm() {
            bits |= ContentSuite::Aes256GcmStream.bit();
        }
        Self(bits)
    }

    /// The §6 rule for a new file: AES if both advertise it, otherwise
    /// `XChaCha` if both advertise it, otherwise `None` (abort; there is no
    /// fallback).
    #[must_use]
    pub const fn select(self, peer: Self) -> Option<ContentSuite> {
        let common = Self(self.0 & peer.0);
        if common.contains(ContentSuite::Aes256GcmStream) {
            Some(ContentSuite::Aes256GcmStream)
        } else if common.contains(ContentSuite::XChaCha20Poly1305Stream) {
            Some(ContentSuite::XChaCha20Poly1305Stream)
        } else {
            None
        }
    }
}

/// Whether libcrux-aes 0.0.10's multiplexer runs its hardware AES-GCM path
/// here. These are the same checks, in the same order, as its
/// `AesGcm256` dispatch, so a device never advertises AES and then runs
/// the portable implementation. On aarch64 the PMULL check is added: the
/// NEON GHASH needs it, and libcrux's dispatch checks only AES. libcrux-platform
/// 0.0.4 detects aarch64 features only on Linux and macOS, so Android and
/// iOS devices report no hardware AES and advertise `XChaCha` only.
fn hardware_aes_gcm() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        libcrux_platform::simd256_support() && libcrux_platform::aes_ni_support()
    }
    #[cfg(target_arch = "aarch64")]
    {
        libcrux_platform::simd128_support()
            && libcrux_platform::aes_ni_support()
            && libcrux_platform::pmull_support()
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        false
    }
}
