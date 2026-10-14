//! The todoke desktop app.

#![forbid(unsafe_code)]

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
fn main() {
    todoke_desktop::run();
}

#[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
fn main() {
    eprintln!("todoke-desktop runs on macOS, Windows, and Linux.");
    std::process::exit(1);
}
