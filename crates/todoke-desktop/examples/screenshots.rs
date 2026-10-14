//! Renders every screen of the desktop app in both themes to PNG files
//! (default `docs/qa/screenshots`), off screen, against the mock core.
//! macOS only: the off-screen renderer is Metal.

#![forbid(unsafe_code)]

#[cfg(target_os = "macos")]
fn main() {
    let dir = std::env::args_os()
        .nth(1)
        .map_or_else(|| "docs/qa/screenshots".into(), std::path::PathBuf::from);
    match todoke_desktop::ui::screenshots::capture_all(&dir) {
        Ok(files) => {
            for file in files {
                println!("{}", file.display());
            }
        }
        Err(error) => {
            eprintln!("screenshots: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(target_os = "macos"))]
fn main() {
    eprintln!("screenshots are rendered with Metal: run this on macOS");
    std::process::exit(1);
}
