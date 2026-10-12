//! Pairing: the QR payload and human-code pairing (PROTOCOL §3, §10).
//!
//! Pairing is local intent to trust a device, never consent to receive a
//! file (§3.1, §7). It ends in a contact with pinned keys and a ratcheted
//! pair PSK, created only after a mutually authenticated session (§4.3)
//! commits its first ratchet (§4.4).
//!
//! # Secrets
//!
//! The QR payload carries the displayer's one-time PSK. It is zeroized,
//! redacted in `Debug`, and absent from every error. The QR text is
//! sensitive: anyone who sees it may race to pair (§3.1), so it must not be
//! logged, uploaded, placed in a URL, or passed across FFI as raw bytes.
//! How a platform UI renders or scans it without that is open (O5).

mod base45;
#[cfg(fuzzing)]
pub mod fuzzing;
mod qr;

pub use qr::{
    OFFER_LIFETIME_SECONDS, QR_MAGIC, QR_PAYLOAD_LEN, QR_TEXT_LEN, QR_TEXT_PREFIX, QrError,
    QrPayload, QrRendezvousError, RendezvousToken,
};
