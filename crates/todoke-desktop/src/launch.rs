//! How the app was launched: `todoke-desktop [--background]
//! [--send PATH... | --send-clipboard] [--version]`. File managers, the
//! Quick Action, and login items launch it this way; a second launch hands
//! the request to the window already running (`todoke_daemon::handoff`).

use std::ffi::OsString;
use std::path::{Path, PathBuf};

use todoke_daemon::handoff::{Handoff, MAX_PATHS};

/// What a launch asks for.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Launch {
    /// What to hand the window (to the running one, or this one).
    pub handoff: Handoff,
    /// Start without showing the window (a login item; the tray stays).
    pub background: bool,
    /// Print the version and exit.
    pub version: bool,
}

/// Parses `args` (without the program name), resolving relative paths
/// against `cwd`.
///
/// # Errors
///
/// For people: an unknown option, `--send` without paths, or too many.
pub fn parse(args: impl IntoIterator<Item = OsString>, cwd: &Path) -> Result<Launch, String> {
    let mut launch = Launch {
        handoff: Handoff::Show,
        background: false,
        version: false,
    };
    let mut sending: Option<Vec<PathBuf>> = None;
    for arg in args {
        if let Some(paths) = &mut sending {
            // Everything after --send is a path, even if it starts with "-".
            let path = cwd.join(arg);
            if !path.is_absolute() {
                return Err(format!("cannot tell where {} is", path.display()));
            }
            paths.push(path);
            continue;
        }
        match arg.to_str() {
            Some("--send") => sending = Some(Vec::new()),
            Some("--send-clipboard") => launch.handoff = Handoff::SendClipboard,
            Some("--background") => launch.background = true,
            Some("--version" | "-V") => launch.version = true,
            Some(other) if other.starts_with("-psn_") => {} // macOS Finder's process serial
            _ => {
                return Err(format!(
                    "unknown argument {:?}; usage: todoke-desktop [--background] [--send PATH... | --send-clipboard] [--version]",
                    arg.to_string_lossy()
                ));
            }
        }
    }
    if let Some(paths) = sending {
        if paths.is_empty() {
            return Err("--send needs at least one file or folder".to_owned());
        }
        if paths.len() > MAX_PATHS {
            return Err(format!("at most {MAX_PATHS} files at once"));
        }
        launch.handoff = Handoff::Send { paths };
    }
    Ok(launch)
}

/// The path of a `file:` URL (macOS hands files opened with the app as
/// these); `None` for any other URL or another host's file.
#[must_use]
pub fn file_url(url: &str) -> Option<PathBuf> {
    let rest = url.strip_prefix("file://")?;
    let rest = rest.strip_prefix("localhost").unwrap_or(rest);
    if !rest.starts_with('/') {
        return None;
    }
    let mut bytes = Vec::with_capacity(rest.len());
    let mut input = rest.bytes();
    while let Some(byte) = input.next() {
        match byte {
            b'%' => {
                let high = hex(input.next()?)?;
                let low = hex(input.next()?)?;
                bytes.push(high << 4 | low);
            }
            b'?' | b'#' => return None,
            byte => bytes.push(byte),
        }
    }
    if bytes.contains(&0) {
        return None;
    }
    Some(path_of(bytes))
}

fn hex(digit: u8) -> Option<u8> {
    char::from(digit)
        .to_digit(16)
        .and_then(|value| u8::try_from(value).ok())
}

#[cfg(unix)]
fn path_of(bytes: Vec<u8>) -> PathBuf {
    use std::os::unix::ffi::OsStringExt as _;
    PathBuf::from(OsString::from_vec(bytes))
}

// Only macOS hands files over as URLs; elsewhere a name that is not UTF-8
// names no file, and sending it fails.
#[cfg(not(unix))]
fn path_of(bytes: Vec<u8>) -> PathBuf {
    PathBuf::from(String::from_utf8_lossy(&bytes).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(list: &[&str]) -> Vec<OsString> {
        list.iter().map(OsString::from).collect()
    }

    #[test]
    fn launches_are_parsed() -> Result<(), String> {
        let cwd = Path::new("/home/me");
        assert_eq!(parse(args(&[]), cwd)?.handoff, Handoff::Show);
        let launch = parse(
            args(&["--background", "--send", "a.txt", "/abs/b", "--odd"]),
            cwd,
        )?;
        assert!(launch.background);
        assert_eq!(
            launch.handoff,
            Handoff::Send {
                paths: vec![
                    "/home/me/a.txt".into(),
                    "/abs/b".into(),
                    "/home/me/--odd".into()
                ]
            }
        );
        assert_eq!(
            parse(args(&["--send-clipboard"]), cwd)?.handoff,
            Handoff::SendClipboard
        );
        assert!(parse(args(&["--version"]), cwd)?.version);
        assert_eq!(parse(args(&["-psn_0_12345"]), cwd)?.handoff, Handoff::Show);
        assert!(parse(args(&["--send"]), cwd).is_err());
        assert!(parse(args(&["--nope"]), cwd).is_err());
        assert!(parse(args(&["--send", "a"]), Path::new("relative")).is_err());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn file_urls_become_paths() {
        assert_eq!(
            file_url("file:///Users/me/My%20File%E2%80%AE.txt"),
            Some(PathBuf::from("/Users/me/My File\u{202e}.txt"))
        );
        assert_eq!(
            file_url("file://localhost/tmp/a"),
            Some(PathBuf::from("/tmp/a"))
        );
        for refused in [
            "https://example.com/a",
            "file://server/share/a",
            "file:///a%00b",
            "file:///a%zz",
            "file:///a%2",
            "file:///a?b",
        ] {
            assert_eq!(file_url(refused), None, "{refused}");
        }
    }
}
