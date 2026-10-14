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

/// Readers of what [`quote`] writes, as the specifications define them,
/// for tests of the writers.
#[cfg(test)]
pub(crate) mod read {
    /// The string value of a key (Desktop Entry specification, "Value
    /// types"): `\s`, `\n`, `\t`, `\r`, and `\\` are escapes; any other
    /// backslash sequence is invalid.
    pub(crate) fn string_value(raw: &str) -> Option<String> {
        let mut out = String::new();
        let mut chars = raw.chars();
        while let Some(c) = chars.next() {
            if c != '\\' {
                out.push(c);
                continue;
            }
            out.push(match chars.next()? {
                's' => ' ',
                'n' => '\n',
                't' => '\t',
                'r' => '\r',
                '\\' => '\\',
                _ => return None,
            });
        }
        Some(out)
    }

    /// The arguments of an `Exec` value (specification, "The Exec key"):
    /// the value's string escapes first, then arguments separated by
    /// spaces, double quotes enclosing one with `"`, `` ` ``, `$`, and `\`
    /// escaped by a backslash, and `%%` for one `%`. Field codes (`%F`,
    /// ...) are kept as written. `None` for what the specification
    /// does not allow.
    pub(crate) fn exec_arguments(value: &str) -> Option<Vec<String>> {
        let text = string_value(value)?;
        let mut arguments = Vec::new();
        let mut chars = text.chars().peekable();
        loop {
            while chars.next_if_eq(&' ').is_some() {}
            if chars.peek().is_none() {
                return Some(arguments);
            }
            let quoted = chars.next_if_eq(&'"').is_some();
            let mut argument = String::new();
            loop {
                match chars.next() {
                    None if quoted => return None,
                    None => break,
                    Some(' ') if !quoted => break,
                    Some('"') if quoted => break,
                    Some('\\') if quoted => match chars.next()? {
                        c @ ('"' | '`' | '$' | '\\') => argument.push(c),
                        _ => return None,
                    },
                    // Reserved characters must be quoted.
                    Some(
                        '"' | '`' | '$' | '\\' | '\'' | '>' | '<' | '~' | '|' | '&' | ';' | '*'
                        | '?' | '#' | '(' | ')',
                    ) if !quoted => {
                        return None;
                    }
                    Some('%') => match chars.next()? {
                        '%' => argument.push('%'),
                        code => {
                            argument.push('%');
                            argument.push(code);
                        }
                    },
                    Some(c) => argument.push(c),
                }
            }
            if quoted && chars.peek().is_some_and(|c| *c != ' ') {
                return None;
            }
            arguments.push(argument);
        }
    }

    /// The words of a line of POSIX shell made only of single-quoted
    /// strings, backslash-escaped characters outside quotes, and plain
    /// words (what `shell_quote` writes), with the `"$@"` expansion kept
    /// as written. `None` for anything else.
    pub(crate) fn shell_words(line: &str) -> Option<Vec<String>> {
        let mut words = Vec::new();
        let mut chars = line.chars().peekable();
        loop {
            while chars.next_if_eq(&' ').is_some() {}
            if chars.peek().is_none() {
                return Some(words);
            }
            let mut word = String::new();
            while let Some(c) = chars.next_if(|c| *c != ' ') {
                match c {
                    '\'' => loop {
                        match chars.next()? {
                            '\'' => break,
                            c => word.push(c),
                        }
                    },
                    '\\' => word.push(chars.next()?),
                    '"' => {
                        // Only `"$@"` is allowed in double quotes here.
                        if chars.next()? != '$' || chars.next()? != '@' || chars.next()? != '"' {
                            return None;
                        }
                        word.push_str("$@");
                    }
                    c => word.push(c),
                }
            }
            words.push(word);
        }
    }

    /// Program paths whose names hold every character that needs care.
    pub(crate) const AWKWARD: &[&str] = &[
        "/usr/bin/todoke-desktop",
        "/opt/a b/todoke",
        "/opt/  two  spaces /todoke",
        "/opt/it's/todoke",
        "/opt/'quoted'/todoke",
        "/opt/\"double\"/todoke",
        "/opt/$HOME/${x}/$(id)/todoke",
        "/opt/`id`/todoke",
        "/opt/100%/%F/%%/%u/todoke",
        "/opt/back\\slash/\\s/\\n/\\\\/todoke",
        "/opt/\\\"/todoke",
        "/opt/everything \" $ ` % \\ ' ;&|<>*?#()~/todoke",
        "/opt/e\u{301} \u{65e5}\u{672c}/todoke",
        "/opt/trailing\\",
    ];
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

    /// The readers agree with the specification's own examples, so the
    /// round trips below mean something.
    #[test]
    fn the_test_reader_follows_the_specification() {
        use read::{exec_arguments, string_value};
        assert_eq!(string_value(r"a\sb\\c").as_deref(), Some("a b\\c"));
        assert_eq!(string_value(r"a\qb"), None);
        assert_eq!(string_value("a\\"), None);
        assert_eq!(
            exec_arguments(r#""a \\"b\\" c" x %F"#),
            Some(vec!["a \"b\" c".into(), "x".into(), "%F".into()])
        );
        assert_eq!(
            exec_arguments("a%%b %F"),
            Some(vec!["a%b".into(), "%F".into()])
        );
        assert_eq!(exec_arguments(r#"a"b"#), None);
        assert_eq!(exec_arguments(r#""a"b"#), None);
        assert_eq!(exec_arguments(r#""a \q""#), None);
        assert_eq!(exec_arguments(r#""unterminated"#), None);
    }

    /// Pins that every awkward program path comes back exactly from the
    /// `Exec` line, as a launcher reads it per the specification, and that
    /// the arguments after it stay separate.
    #[test]
    fn quoted_program_paths_round_trip() -> io::Result<()> {
        for name in read::AWKWARD {
            let line = format!("{} --send %F", quote(Path::new(name))?);
            assert!(!line.contains('\n'), "{name}");
            assert_eq!(
                read::exec_arguments(&line),
                Some(vec![(*name).to_owned(), "--send".into(), "%F".into()]),
                "{name}: {line}"
            );
        }
        Ok(())
    }

    /// Pins that no path leaves a field code or a variable for the
    /// launcher to expand: a lone `%` never survives into the value.
    #[test]
    fn a_percent_in_a_path_is_never_a_field_code() -> io::Result<()> {
        let quoted = quote(Path::new("/opt/%F/%u/100%"))?;
        let without_pairs = quoted.replace("%%", "");
        assert!(!without_pairs.contains('%'), "{quoted}");
        Ok(())
    }
}
