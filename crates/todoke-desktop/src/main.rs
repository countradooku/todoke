//! The todoke desktop app.

#![forbid(unsafe_code)]
// A window, not a console (release builds; debug builds keep the console
// for logs and `--version`).
#![cfg_attr(not(debug_assertions), windows_subsystem = "windows")]

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
fn main() {
    todoke_desktop::run();
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
fn main() {
    eprintln!("todoke-desktop runs on macOS, Windows, and Linux.");
    std::process::exit(1);
}
