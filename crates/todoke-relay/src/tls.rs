//! The relay's TLS identity: a certificate chain and key from PEM files,
//! or a self-signed certificate that clients pin by key (§10: platform
//! validation or an explicitly pinned relay key).
//!
//! A pin is the SHA-256 of the certificate's DER `SubjectPublicKeyInfo`,
//! written `spki-sha256:` and 64 lowercase hex digits.

use rustls::pki_types::pem::PemObject as _;
use rustls::pki_types::{CertificateDer, PrivateKeyDer};

/// The prefix of a written pin.
pub const PIN_PREFIX: &str = "spki-sha256:";

/// A certificate chain and its private key.
pub struct Identity {
    chain: Vec<CertificateDer<'static>>,
    key: PrivateKeyDer<'static>,
}

impl core::fmt::Debug for Identity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Identity")
            .field("certificates", &self.chain.len())
            .finish_non_exhaustive()
    }
}

impl Identity {
    /// The chain and key in PEM (`cert` leaf first).
    ///
    /// # Errors
    ///
    /// `InvalidData` if either does not parse or the chain is empty.
    pub fn from_pem(cert: &[u8], key: &[u8]) -> std::io::Result<Self> {
        let invalid = || std::io::Error::from(std::io::ErrorKind::InvalidData);
        let chain = CertificateDer::pem_slice_iter(cert)
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| invalid())?;
        if chain.is_empty() {
            return Err(invalid());
        }
        let key = PrivateKeyDer::from_pem_slice(key).map_err(|_| invalid())?;
        Ok(Self { chain, key })
    }

    /// A fresh self-signed certificate for `names` (ECDSA P-256), and its
    /// PEM certificate and key to keep.
    ///
    /// # Errors
    ///
    /// If generation fails.
    pub fn self_signed(names: Vec<String>) -> std::io::Result<(Self, String, String)> {
        let failed = |_| std::io::Error::other("certificate generation failed");
        let key = rcgen::KeyPair::generate().map_err(failed)?;
        let cert = rcgen::CertificateParams::new(names)
            .map_err(failed)?
            .self_signed(&key)
            .map_err(failed)?;
        let (cert_pem, key_pem) = (cert.pem(), key.serialize_pem());
        let identity = Self::from_pem(cert_pem.as_bytes(), key_pem.as_bytes())?;
        Ok((identity, cert_pem, key_pem))
    }

    /// The leaf certificate's key pin.
    ///
    /// # Errors
    ///
    /// `InvalidData` if the leaf does not parse.
    pub fn pin(&self) -> std::io::Result<[u8; 32]> {
        let leaf = self
            .chain
            .first()
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
        spki_pin(leaf)
    }

    pub(crate) fn chain(&self) -> Vec<CertificateDer<'static>> {
        self.chain.clone()
    }

    pub(crate) fn key(&self) -> PrivateKeyDer<'static> {
        self.key.clone_key()
    }
}

/// The pin of `cert`: SHA-256 of its DER `SubjectPublicKeyInfo`.
///
/// # Errors
///
/// `InvalidData` if the certificate does not parse.
pub fn spki_pin(cert: &CertificateDer<'_>) -> std::io::Result<[u8; 32]> {
    let parsed = webpki::EndEntityCert::try_from(cert)
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
    Ok(libcrux_sha2::sha256(
        parsed.subject_public_key_info().as_ref(),
    ))
}

/// `pin` as written: `spki-sha256:` and lowercase hex.
#[must_use]
pub fn format_pin(pin: &[u8; 32]) -> String {
    use core::fmt::Write as _;
    let mut out = String::from(PIN_PREFIX);
    for byte in pin {
        let _ = write!(out, "{byte:02x}");
    }
    out
}
