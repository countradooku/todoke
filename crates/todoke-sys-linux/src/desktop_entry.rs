//! Writing the `Exec` key of desktop entries (the Desktop Entry
//! specification, "The Exec key"): arguments with reserved characters are
//! quoted, `"`, `` ` ``, `$`, and `\` are escaped inside quotes, then the
//! value's own escapes apply (a backslash doubles again), and `%` doubles.

use std::io;
use std::path::Path;

/// One argument as the `Exec` value carries it.
///
/// # Errors
///
/// `InvalidInput` for an argument that cannot be written: not UTF-8, or
/// with a control character (a newline would end the key).
pub fn quote(argument: &Path) -> io::Result<String> {
    let text = argument
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "not UTF-8"))?;
    if text.chars().any(char::is_control) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a control character",
        ));
    }
    let mut out = String::with_capacity(text.len() + 2);
    out.push('"');
    for c in text.chars() {
        match c {
            // Escaped for the quoting rule, then the backslash doubled for
            // the string rule.
            '"' | '`' | '$' => {
                out.push_str("\\\\");
                out.push(c);
            }
            '\\' => out.push_str("\\\\\\\\"),
            '%' => out.push_str("%%"),
            c => out.push(c),
        }
    }
    out.push('"');
    Ok(out)
}

/// Writes `contents` to `path` atomically, with `mode`.
pub(crate) fn write(path: &Path, contents: &str, mode: u32) -> io::Result<()> {
    use std::io::Write as _;
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};
    let dir = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no directory"))?;
    std::fs::create_dir_all(dir)?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "no file name"))?;
    let temporary = dir.join(format!(
        ".{}.{}.tmp",
        name.to_string_lossy(),
        std::process::id()
    ));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&temporary)?;
    let written = file
        .write_all(contents.as_bytes())
        .and_then(|()| file.set_permissions(std::fs::Permissions::from_mode(mode)))
        .and_then(|()| file.sync_all())
        .and_then(|()| std::fs::rename(&temporary, path));
    if written.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    written
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exec_arguments_are_quoted_and_escaped() -> io::Result<()> {
        assert_eq!(
            quote(Path::new("/usr/bin/todoke-desktop"))?,
            "\"/usr/bin/todoke-desktop\""
        );
        assert_eq!(
            quote(Path::new("/opt/a b/$x`\"\\%"))?,
            r#""/opt/a b/\\$x\\`\\"\\\\%%""#
        );
        assert!(quote(Path::new("/tmp/a\nb")).is_err());
        Ok(())
    }
}
