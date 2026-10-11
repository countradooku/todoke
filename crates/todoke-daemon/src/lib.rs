//! Background service integration around the public todoke core.
//!
//! # Trust boundary
//!
//! Local IPC clients, lifecycle events, and service requests are untrusted.
//! Service privileges must never bypass authentication, consent, or file policy.
//! This library scaffold does not yet provide a running service.
//!
//! # Status
//!
//! Empty scaffold: no protocol behavior or security guarantees are implemented.
//! Read `docs/DESIGN.md` and `spec/PROTOCOL.md` before adding behavior.

#![forbid(unsafe_code)]
