//! Cryptographic orchestration and secret ownership for todoke.
//!
//! # Trust boundary
//!
//! Use reviewed libcrux, `RustCrypto`, or dalek implementations only. Secrets remain
//! inside Rust, are zeroized, and never reach logs or foreign interfaces.
//!
//! # Status
//!
//! Implemented: device and person identities, `DeviceBinding` and `Revoke`
//! issuance and verification, a key store interface with an encrypted software
//! backend, and a contact store (see [`identity`]); suite 0x0001 sessions
//! (see [`session`]): the hybrid `IKpsk2`/`KKpsk2`/`XXpsk3` handshakes, identity
//! confirmation, the PSK ratchet with its durable journal and crash policy,
//! encrypted framing, rekey, and keepalive; and QR and human-code pairing
//! (see [`pairing`]): the QR payload, the displayer's offers and attempt
//! budgets, `CPace` (from `pakery`, behind the non-default
//! `unaudited-code-pairing` feature), and the pairing authority that pins
//! the QR keys, burns the offer durably, and creates the contact. Sessions
//! and pairing are **not production enabled**: every session entry point
//! takes an
//! [`UnauditedSuite0001`](session::UnauditedSuite0001) acknowledgement, which
//! only unit tests and the non-default `unaudited-suite-0001` feature can
//! construct, because PROTOCOL §16 keeps the suite disabled until gates O6 and
//! O10 close (`docs/adr/0001-noise-crate.md`); code pairing additionally
//! needs [`UnauditedCodePairing`](pairing::UnauditedCodePairing) until O2
//! closes (`docs/adr/0002-cpace.md`). Capabilities, transfers, and content
//! encryption are not implemented yet.
//! Read `docs/DESIGN.md` and `spec/PROTOCOL.md` before adding behavior.

#![forbid(unsafe_code)]

pub mod identity;
pub mod pairing;
mod rng;
pub mod session;
