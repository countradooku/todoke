//! `todoke`: send files between your devices, end-to-end encrypted.
//!
//! Every command except `daemon run` and `completions` talks to the
//! running daemon; the daemon holds the identity and does the work.

#![forbid(unsafe_code)]

#[cfg(not(target_family = "wasm"))]
mod app;

#[cfg(not(target_family = "wasm"))]
fn main() -> std::process::ExitCode {
    app::main()
}

#[cfg(target_family = "wasm")]
fn main() {}
