//! `CPACE-RISTR255-SHA512`, pinned to draft-irtf-cfrg-cpace-21 §7 and §8.3
//! (PROTOCOL §3.2), from the `pakery-cpace` library
//! (`docs/adr/0002-cpace.md`). Nothing here implements `CPace` or a group
//! operation: this module adapts the library's API to todoke's randomness,
//! fixed sizes, and zeroizing buffers.
//!
//! The backend is compiled only in unit tests and with the non-default
//! `unaudited-code-pairing` feature. Without it every entry point returns
//! [`CpaceError::Unavailable`], so code pairing cannot run (gate O2).

use core::fmt;

use zeroize::Zeroizing;

use crate::session::engine::Entropy;

/// A `CPace` share: a canonical Ristretto255 encoding.
pub(crate) const SHARE_LEN: usize = 32;
/// The intermediate session key: one SHA-512 output.
pub(crate) const ISK_LEN: usize = 64;
/// Randomness drawn per scalar: pakery reduces 64 uniform bytes modulo the
/// group order (draft-21 §8.3 permits uniform sampling).
const SCALAR_SEED_LEN: usize = 64;

/// Why `CPace` did not produce a key. Carries no detail about the input.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CpaceError {
    /// No `CPace` backend in this build (gate O2).
    #[cfg_attr(
        test,
        expect(dead_code, reason = "only a build without the backend returns it")
    )]
    Unavailable,
    /// The peer's share is not a canonical, non-neutral Ristretto255
    /// element, or the shared point is the neutral element: abort (§3.2,
    /// draft-21 §7.2).
    Abort,
    /// Randomness was unavailable.
    Random,
}

impl fmt::Display for CpaceError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Unavailable => "CPace is not available in this build",
            Self::Abort => "CPace aborted",
            Self::Random => "randomness unavailable",
        })
    }
}

impl std::error::Error for CpaceError {}

/// The `CPace` ISK. Zeroized on drop, redacted in `Debug`.
pub(crate) struct Isk(pub(super) Zeroizing<[u8; ISK_LEN]>);

impl Isk {
    pub(crate) fn as_bytes(&self) -> &[u8; ISK_LEN] {
        &self.0
    }
}

impl fmt::Debug for Isk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Isk([REDACTED])")
    }
}

/// Initiator (party A) state between sending `Ya` and receiving `Yb`.
pub(crate) struct Initiator(backend::State);

impl fmt::Debug for Initiator {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("cpace::Initiator { .. }")
    }
}

/// Party A: computes `Ya` from the password and context (draft-21 §7.2).
pub(crate) fn start(
    password: &[u8],
    ci: &[u8],
    sid: &[u8],
    ad_a: &[u8],
    entropy: &Entropy,
) -> Result<([u8; SHARE_LEN], Initiator), CpaceError> {
    backend::start(password, ci, sid, ad_a, entropy).map(|(share, state)| (share, Initiator(state)))
}

impl Initiator {
    /// Party A: derives the ISK from `Yb` (initiator/responder transcript).
    pub(crate) fn finish(self, share_b: &[u8; SHARE_LEN], ad_b: &[u8]) -> Result<Isk, CpaceError> {
        backend::finish(self.0, share_b, ad_b)
    }
}

/// Party B: computes `Yb` and the ISK from `Ya` (draft-21 §7.2).
pub(crate) fn respond(
    share_a: &[u8; SHARE_LEN],
    password: &[u8],
    ci: &[u8],
    sid: &[u8],
    ad_a: &[u8],
    ad_b: &[u8],
    entropy: &Entropy,
) -> Result<([u8; SHARE_LEN], Isk), CpaceError> {
    backend::respond(share_a, password, ci, sid, ad_a, ad_b, entropy)
}

#[cfg(any(test, feature = "unaudited-code-pairing"))]
mod backend {
    use core::convert::Infallible;

    use pakery_cpace::{CpaceCiphersuite, CpaceInitiator, CpaceMode, CpaceResponder};
    use pakery_crypto::{Ristretto255Group, Sha512Hash};
    use zeroize::Zeroizing;

    use super::{CpaceError, ISK_LEN, Isk, SCALAR_SEED_LEN, SHARE_LEN};
    use crate::session::engine::Entropy;

    /// `CPACE-RISTR255-SHA512` (draft-21 §8.3): `G.DSI =
    /// "CPaceRistretto255"`, SHA-512 with its 128-byte input block, and
    /// 32-byte field elements.
    pub(super) struct Ristretto255Sha512;

    impl CpaceCiphersuite for Ristretto255Sha512 {
        type Group = Ristretto255Group;
        type Hash = Sha512Hash;
        const DSI: &'static [u8] = b"CPaceRistretto255";
        const HASH_BLOCK_SIZE: usize = 128;
        const FIELD_SIZE_BYTES: usize = 32;
    }

    pub(super) type State = pakery_cpace::InitiatorState<Ristretto255Sha512>;

    /// pakery's API takes an infallible RNG. This one serves bytes drawn
    /// beforehand from [`Entropy`] (the OS CSPRNG, with error handling).
    /// Should the library ever ask for more than was drawn, it records the
    /// overdraw and the caller discards the result, so a scalar is never
    /// built from anything but fresh randomness.
    pub(super) struct Drawn {
        bytes: Zeroizing<[u8; SCALAR_SEED_LEN]>,
        used: usize,
        pub(super) overdrawn: bool,
    }

    impl Drawn {
        pub(super) fn new(entropy: &Entropy) -> Result<Self, CpaceError> {
            let mut bytes = Zeroizing::new([0; SCALAR_SEED_LEN]);
            entropy
                .fill(bytes.as_mut_slice())
                .map_err(|_| CpaceError::Random)?;
            Ok(Self {
                bytes,
                used: 0,
                overdrawn: false,
            })
        }

        fn check(&self) -> Result<(), CpaceError> {
            if self.overdrawn {
                Err(CpaceError::Random)
            } else {
                Ok(())
            }
        }
    }

    impl rand_core::TryRng for Drawn {
        type Error = Infallible;

        fn try_next_u32(&mut self) -> Result<u32, Infallible> {
            let mut out = [0; 4];
            self.try_fill_bytes(&mut out)?;
            Ok(u32::from_le_bytes(out))
        }

        fn try_next_u64(&mut self) -> Result<u64, Infallible> {
            let mut out = [0; 8];
            self.try_fill_bytes(&mut out)?;
            Ok(u64::from_le_bytes(out))
        }

        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Infallible> {
            let available = &self.bytes[self.used..];
            if dest.len() > available.len() {
                self.overdrawn = true;
                dest.fill(0);
                return Ok(());
            }
            dest.copy_from_slice(&available[..dest.len()]);
            self.used += dest.len();
            Ok(())
        }
    }

    impl rand_core::TryCryptoRng for Drawn {}

    fn share(bytes: &[u8]) -> Result<[u8; SHARE_LEN], CpaceError> {
        bytes.try_into().map_err(|_| CpaceError::Abort)
    }

    fn isk(bytes: &[u8]) -> Result<Isk, CpaceError> {
        let mut out = Zeroizing::new([0; ISK_LEN]);
        if bytes.len() != ISK_LEN {
            return Err(CpaceError::Abort);
        }
        out.copy_from_slice(bytes);
        Ok(Isk(out))
    }

    pub(super) fn start(
        password: &[u8],
        ci: &[u8],
        sid: &[u8],
        ad_a: &[u8],
        entropy: &Entropy,
    ) -> Result<([u8; SHARE_LEN], State), CpaceError> {
        let mut rng = Drawn::new(entropy)?;
        let (ya, state) =
            CpaceInitiator::<Ristretto255Sha512>::start(password, ci, sid, ad_a, &mut rng)
                .map_err(|_| CpaceError::Abort)?;
        rng.check()?;
        Ok((share(&ya)?, state))
    }

    pub(super) fn finish(
        state: State,
        share_b: &[u8; SHARE_LEN],
        ad_b: &[u8],
    ) -> Result<Isk, CpaceError> {
        let output = state
            .finish(share_b, ad_b, CpaceMode::InitiatorResponder)
            .map_err(|_| CpaceError::Abort)?;
        isk(output.isk.as_bytes())
    }

    pub(super) fn respond(
        share_a: &[u8; SHARE_LEN],
        password: &[u8],
        ci: &[u8],
        sid: &[u8],
        ad_a: &[u8],
        ad_b: &[u8],
        entropy: &Entropy,
    ) -> Result<([u8; SHARE_LEN], Isk), CpaceError> {
        let mut rng = Drawn::new(entropy)?;
        let (yb, output) = CpaceResponder::<Ristretto255Sha512>::respond(
            share_a,
            password,
            ci,
            sid,
            ad_a,
            ad_b,
            CpaceMode::InitiatorResponder,
            &mut rng,
        )
        .map_err(|_| CpaceError::Abort)?;
        rng.check()?;
        Ok((share(&yb)?, isk(output.isk.as_bytes())?))
    }
}

#[cfg(not(any(test, feature = "unaudited-code-pairing")))]
mod backend {
    use super::{CpaceError, Isk, SHARE_LEN};
    use crate::session::engine::Entropy;

    /// No backend: there is no state to hold.
    pub(super) enum State {}

    pub(super) fn start(
        _password: &[u8],
        _ci: &[u8],
        _sid: &[u8],
        _ad_a: &[u8],
        _entropy: &Entropy,
    ) -> Result<([u8; SHARE_LEN], State), CpaceError> {
        Err(CpaceError::Unavailable)
    }

    #[expect(
        clippy::needless_pass_by_value,
        reason = "same signature as the real backend; the state is uninhabited"
    )]
    pub(super) fn finish(
        state: State,
        _share_b: &[u8; SHARE_LEN],
        _ad_b: &[u8],
    ) -> Result<Isk, CpaceError> {
        match state {}
    }

    pub(super) fn respond(
        _share_a: &[u8; SHARE_LEN],
        _password: &[u8],
        _ci: &[u8],
        _sid: &[u8],
        _ad_a: &[u8],
        _ad_b: &[u8],
        _entropy: &Entropy,
    ) -> Result<([u8; SHARE_LEN], Isk), CpaceError> {
        Err(CpaceError::Unavailable)
    }
}

#[cfg(test)]
mod tests;
