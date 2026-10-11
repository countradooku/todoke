//! Transport interfaces for BLE, Wi-Fi P2P, AWDL, USB, LAN, and QUIC relay.
//!
//! # Trust boundary
//!
//! Every transport is an untrusted byte pipe. Connectivity and transport-layer
//! security must never grant peer identity, consent, or content authenticity.
//!
//! # Status
//!
//! Empty scaffold: no protocol behavior or security guarantees are implemented.
//! Read `docs/DESIGN.md` and `spec/PROTOCOL.md` before adding behavior.

#![forbid(unsafe_code)]
