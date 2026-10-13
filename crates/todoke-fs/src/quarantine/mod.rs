//! The receiver's quarantine: verified content ciphertext of partial
//! transfers, their sealed file masters, journals, and tombstones, in
//! private application storage until publication, cancellation, or expiry.

pub mod codec;
#[cfg(any(unix, windows))]
pub(crate) mod store;
