//! Wire-format definitions and bounded parsing for the todoke protocol.
//!
//! # Trust boundary
//!
//! Every peer-provided field is untrusted. Parsing must be bounded and fallible;
//! syntactic validity must never imply authentication or consent.
//!
//! # Status
//!
//! Implemented: the fixed layouts of `DeviceBinding` and `Revoke` (PROTOCOL §2),
//! the protocol Unix time range (§1), and the session records of [`session`]:
//! prelude framing, `ClientHello`/`ServerHello`, `NoiseHandshake` framing
//! (§4.1, §4.2.5), the transport frame header and registry (§5), and the
//! `Identity`, ratchet, `KeyUpdate`, `Ping`/`Pong`, and `Error` bodies (§4.3,
//! §4.4, §12, §13), and the human-code pairing bodies of [`pairing`]
//! (`CodeOfferRequest`, `CodeOffer`, `CodeShareA`/`CodeShareB`, §3.2).
//! Decoding checks layout only; key validation, signature verification,
//! decryption, and state machines belong to `todoke-crypto`. The QR payload
//! (§3.1) carries a secret and lives in `todoke-crypto::pairing`.
//! The `Capabilities` record and the transfer records of [`transfer`]
//! (§6, §7): `ManifestStart`/`ManifestPart` and the canonical manifest,
//! `Accept`/`Reject`, `ChunkRequest`/`Chunk`, `ResumeQuery`/`ResumeStatus`,
//! `Cancel`/`CancelAck`, `Complete`, and `DeliveryReceipt` (the secret
//! `FileKey` body is in `todoke-crypto`). The [`discovery`] records
//! (§9): `DiscoveryRecord`, its mDNS TXT string, and the mDNS instance
//! label. The [`relay`] control records (§10): the envelope and every
//! record from `Register` to `RelayClose`.
//! Read `docs/DESIGN.md` and `spec/PROTOCOL.md` before adding behavior.

#![forbid(unsafe_code)]

pub mod discovery;
pub mod identity;
pub mod pairing;
pub mod relay;
pub mod session;
pub mod time;
pub mod transfer;
