//! How the app was launched: `todoke-desktop [--background]
//! [--send PATH... | --send-stdin | --send-clipboard] [--version]`. File managers, the
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
    /// Read the paths to send from standard input ([`read_paths`]): the
    /// Explorer command passes any number this way.
    pub send_stdin: bool,
}

/// Parses `args` (without the program name), resolving relative paths
/// against `cwd`. Arguments that are not options are paths to send, as
/// "Open With" passes them (`todoke-desktop FILE...` is `--send FILE...`).
///
/// # Errors
///
/// For people: an unknown option, `--send` without paths, or too many.
pub fn parse(args: impl IntoIterator<Item = OsString>, cwd: &Path) -> Result<Launch, String> {
    let mut launch = Launch {
        handoff: Handoff::Show,
        background: false,
        version: false,
        send_stdin: false,
    };
    let mut sending: Option<Vec<PathBuf>> = None;
    let absolute = |arg: OsString| {
        let path = cwd.join(unquote(arg));
        if path.is_absolute() {
            Ok(path)
        } else {
            Err(format!("cannot tell where {} is", path.display()))
        }
    };
    for arg in args {
        if let Some(paths) = &mut sending {
            // Everything after --send is a path, even if it starts with "-".
            paths.push(absolute(arg)?);
            continue;
        }
        match arg.to_str() {
            Some("--send") => sending = Some(Vec::new()),
            Some("--send-clipboard") => launch.handoff = Handoff::SendClipboard,
            Some("--send-stdin") => launch.send_stdin = true,
            Some("--background") => launch.background = true,
            Some("--version" | "-V") => launch.version = true,
            Some(other) if other.starts_with("-psn_") => {} // macOS Finder's process serial
            // A path (not an option): Open With.
            Some(other) if !other.starts_with('-') => {
                sending = Some(vec![absolute(arg)?]);
            }
            None => sending = Some(vec![absolute(arg)?]),
            _ => {
                return Err(format!(
                    "unknown argument {:?}; usage: todoke-desktop [--background] [--send PATH... | --send-stdin | --send-clipboard] [--version]",
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

/// Windows: Explorer quotes a verb's `"%1"`, and a folder ending in a
/// backslash (a drive, `C:\`) turns the closing quote into a literal one
/// (`C:"`). Such a quote is the backslash it replaced.
fn unquote(arg: OsString) -> OsString {
    #[cfg(windows)]
    if let Some(text) = arg.to_str()
        && let Some(path) = text.strip_suffix('"')
    {
        return OsString::from(format!("{path}\\"));
    }
    arg
}

/// At most this many bytes of paths on standard input.
const MAX_STDIN: u64 = 8 << 20;

/// The paths on standard input of `--send-stdin`: UTF-8, each ended by a
/// NUL byte, absolute.
///
/// # Errors
///
/// For people: unreadable, too long, not UTF-8, relative, or none.
pub fn read_paths(input: impl std::io::Read) -> Result<Vec<PathBuf>, String> {
    use std::io::Read as _;
    let mut bytes = Vec::new();
    input
        .take(MAX_STDIN + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| format!("cannot read the paths: {error}"))?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_STDIN {
        return Err("too many paths".to_owned());
    }
    let mut paths = Vec::new();
    for raw in bytes.split(|byte| *byte == 0).filter(|raw| !raw.is_empty()) {
        let text = std::str::from_utf8(raw).map_err(|_| "a path is not UTF-8".to_owned())?;
        let path = PathBuf::from(text);
        if !path.is_absolute() {
            return Err(format!("{} is not an absolute path", path.display()));
        }
        paths.push(path);
        if paths.len() > MAX_PATHS {
            return Err(format!("at most {MAX_PATHS} files at once"));
        }
    }
    if paths.is_empty() {
        return Err("no paths to send".to_owned());
    }
    Ok(paths)
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
        // Open With passes bare paths.
        assert_eq!(
            parse(args(&["b.txt", "/abs/c"]), cwd)?.handoff,
            Handoff::Send {
                paths: vec!["/home/me/b.txt".into(), "/abs/c".into()]
            }
        );
        assert!(parse(args(&["--send", "a"]), Path::new("relative")).is_err());
        Ok(())
    }

    #[test]
    fn paths_come_from_standard_input() {
        let root = if cfg!(windows) { "C:\\" } else { "/" };
        let input = format!("{root}a b\0{root}c\0");
        assert_eq!(
            read_paths(input.as_bytes()),
            Ok(vec![
                PathBuf::from(format!("{root}a b")),
                PathBuf::from(format!("{root}c"))
            ])
        );
        assert!(read_paths(&b"relative\0"[..]).is_err());
        assert!(read_paths(&b"\0\0"[..]).is_err());
        assert!(read_paths(&b"/\xff\0"[..]).is_err());
        assert!(
            parse(args(&["--send-stdin"]), Path::new("/")).is_ok_and(|launch| launch.send_stdin)
        );
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
