//! The command-line adapter for the public todoke core.
//!
//! # Trust boundary
//!
//! Arguments, terminal input, and displayed peer metadata are untrusted.
//! The CLI must request core operations rather than duplicate security policy.
//! This library scaffold does not yet provide an executable.
//!
//! # Status
//!
//! Empty scaffold: no protocol behavior or security guarantees are implemented.
//! Read `docs/DESIGN.md` and `spec/PROTOCOL.md` before adding behavior.

#![forbid(unsafe_code)]
