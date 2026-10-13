//! Transfer coordination, consent enforcement, and verified file delivery
//! (PROTOCOL §6, §7, §11–§13).
//!
//! # Trust boundary
//!
//! Peer input and transport delivery are untrusted. No file byte is
//! accepted before a signed `AcceH` (the `Accept` record) has been verified
//! by the core, and none outside its selection. An authenticated session
//! is not consent (§7.2).
//!
//! # Pieces
//!
//! | Piece | What it does | Spec |
//! | --- | --- | --- |
//! | [`TransferEngine`] | Sans-IO engine for one authenticated session: Capabilities exchange, both directions' transfer state machines, §13 budgets and timers, outgoing frames, and events | §6, §7, §11, §13 |
//! | [`ManifestBuilder`], [`OutgoingOffer`] | The sender's manifest (a folder tree of entries, no archive) and its fresh per-file masters | §7.1, §8 |
//! | [`SendSource`], [`ReceiveSink`] | Where content comes from and where verified segments go; `todoke-fs` (P08) implements them for real files; [`MemorySource`]/[`MemorySink`] are in-memory | §7.4, §7.5, §7.7 |
//! | [`TransferEvent`] | Offers, consent, progress (speed, ETA, transport label), completion, delivery receipts, cancellation, and failures as stable codes with messages | — |
//! | [`pump`] | Runs an engine over a `todoke_crypto::session::Session` | — |
//!
//! # Consent
//!
//! The receiver's consent invariant lives in a small consent gate that
//! every `FileKey` and `Chunk` passes before any processing: the transfer
//! must be accepted by a verified Accept of this session, the file must be
//! in its selection, and content needs that file's key first.
//!
//! What is checked how:
//!
//! - **The gate's admission rules** are model-checked: Kani proof harnesses
//!   compare the gate with an independent model for every proof and every
//!   short operation sequence (`cargo kani`, run in CI), and the same
//!   harness bodies run exhaustively over short sequences in the unit
//!   tests.
//! - **That the engine routes every key and chunk through the gate** is
//!   not model-checked; it is covered by tests: deterministic scenarios
//!   (keys and content before consent, outside the selection, under another
//!   Accept, after cancel or expiry) and adversarial proptest state machines
//!   that inject forged and replayed frames.
//! - **Below the gate**, the type system enforces the rest: decryption
//!   needs an `AcceptedFile`, which only `todoke_crypto::consent` creates
//!   after verifying the signed Accept.
//!
//! # Scope
//!
//! Filesystem publication, name sanitization, collision mapping, and
//! quarantine are `todoke-fs`'s (P08), through [`ReceiveSink`]; transports
//! are P09 (the engine only reports a caller-supplied label). No
//! compression and no content deduplication are defined by the protocol,
//! so neither is implemented.
//!
//! # Logging
//!
//! Nothing here logs. `Debug` output of engine state, events, and offers
//! contains no keys, file content, names, MIME labels, or paths.

#![forbid(unsafe_code)]

mod capabilities;
mod clock;
mod driver;
mod engine;
mod events;
mod gate;
#[cfg(any(kani, test))]
mod gate_proofs;
pub mod limits;
mod offer;
mod storage;

#[cfg(test)]
mod tests;

pub use capabilities::{CapabilitiesError, LocalCapabilities, Negotiated};
pub use clock::Clock;
pub use driver::{DriveError, pump};
pub use engine::{EngineConfig, EngineError, OutgoingFrame, TransferEngine};
pub use events::{
    Direction, Failure, FailureCode, OfferEntry, OfferView, Party, Progress, TransferEvent,
};
pub use offer::{BuildError, ManifestBuilder, OfferError, OutgoingOffer};
pub use storage::{
    MemoryFile, MemorySink, MemorySource, ReceiveSink, Retained, SendSource, SinkError,
    SinkRefusal, SourceError,
};

/// A transfer ID: 16 random bytes, never zero (§7).
pub use todoke_proto::transfer::TransferId;
