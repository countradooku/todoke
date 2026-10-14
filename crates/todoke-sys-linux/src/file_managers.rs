//! "Send with todoke" in the file managers, for this user only: a Dolphin
//! service menu, a Nemo action, and a Nautilus script. Packages install
//! the same items for every user (`packaging/linux`); these are for
//! installs without one (an `AppImage`, a binary).

use std::io;
use std::path::{Path, PathBuf};

use crate::autostart::xdg_home;
use crate::desktop_entry;

/// The items, under `$XDG_DATA_HOME`, with their modes. Dolphin runs only
/// executable service menus from the user's directory.
const DOLPHIN: &str = "kio/servicemenus/org.todoke.todoke.desktop";
const NEMO: &str = "nemo/actions/todoke.nemo_action";
const NAUTILUS: &str = "nautilus/scripts/Send with todoke";

/// The file-manager items that send with the app at `exec`.
#[derive(Debug)]
pub struct FileManagers {
    exec: PathBuf,
}

/// `exec` for a POSIX shell: single-quoted.
fn shell_quote(exec: &Path) -> io::Result<String> {
    let text = exec
        .to_str()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "not UTF-8"))?;
    if text.chars().any(char::is_control) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "a control character",
        ));
    }
    Ok(format!("'{}'", text.replace('\'', r"'\''")))
}

/// The items for `exec`: each one's place, contents, and mode. Nemo's is
/// left out for a program path with a `%` (below).
fn items(exec: &Path) -> io::Result<Vec<(&'static str, String, u32)>> {
    let entry = desktop_entry::quote(exec)?;
    let shell = shell_quote(exec)?;
    // Nemo reads Exec as a key-file string, then splits it as a shell does,
    // and takes any `%` as a field code (it has no `%%`): a program path
    // with one cannot be written for it, so it gets no Nemo item.
    let nemo = (!shell.contains('%')).then(|| shell.replace('\\', "\\\\"));
    let mut items = vec![
        (
            DOLPHIN,
            format!(
                "[Desktop Entry]\nType=Service\nMimeType=all/all;inode/directory;\nActions=send\nX-KDE-Priority=TopLevel\n\n[Desktop Action send]\nName=Send with todoke\nIcon=org.todoke.todoke\nExec={entry} --send %F\n"
            ),
            0o755,
        ),
        (
            NAUTILUS,
            format!(
                "#!/bin/sh\n# Send with todoke: the selection is in the arguments.\nexec {shell} --send \"$@\"\n"
            ),
            0o755,
        ),
    ];
    if let Some(nemo) = nemo {
        items.push((
            NEMO,
            format!(
                "[Nemo Action]\nName=Send with todoke\nComment=Send the selection to a contact\nExec={nemo} --send %F\nIcon-Name=org.todoke.todoke\nSelection=notnone\nExtensions=any;dir;\n"
            ),
            0o644,
        ));
    }
    Ok(items)
}

impl FileManagers {
    /// The items that run `exec` (an absolute path).
    #[must_use]
    pub fn new(exec: PathBuf) -> Self {
        Self { exec }
    }

    fn data_home() -> io::Result<PathBuf> {
        xdg_home("XDG_DATA_HOME", ".local/share")
    }

    /// Whether every item this app gets is there.
    #[must_use]
    pub fn installed(&self) -> bool {
        let (Ok(home), Ok(items)) = (Self::data_home(), items(&self.exec)) else {
            return false;
        };
        items.iter().all(|(item, ..)| home.join(item).is_file())
    }

    /// Adds the items (replacing older ones).
    ///
    /// # Errors
    ///
    /// No home directory; an executable path that cannot be written; I/O.
    pub fn install(&self) -> io::Result<()> {
        let home = Self::data_home()?;
        for (item, contents, mode) in items(&self.exec)? {
            desktop_entry::write(&home.join(item), &contents, mode)?;
        }
        Ok(())
    }

    /// Removes the items.
    ///
    /// # Errors
    ///
    /// No home directory; I/O other than "not found".
    pub fn uninstall(&self) -> io::Result<()> {
        let home = Self::data_home()?;
        for item in [DOLPHIN, NEMO, NAUTILUS] {
            match std::fs::remove_file(home.join(item)) {
                Err(error) if error.kind() != io::ErrorKind::NotFound => return Err(error),
                _ => {}
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn items_run_the_app_with_the_selection() -> io::Result<()> {
        let all = items(Path::new("/home/me/it's/todoke.AppImage"))?;
        let [dolphin, nautilus, nemo] = [
            find(&all, DOLPHIN)?,
            find(&all, NAUTILUS)?,
            find(&all, NEMO)?,
        ];
        assert!(
            dolphin
                .1
                .contains("Exec=\"/home/me/it's/todoke.AppImage\" --send %F\n")
        );
        // The shell quoting's backslash, escaped for the key-file string.
        assert!(
            nemo.1
                .contains(r"Exec='/home/me/it'\\''s/todoke.AppImage' --send %F")
        );
        assert!(
            nautilus
                .1
                .ends_with("exec '/home/me/it'\\''s/todoke.AppImage' --send \"$@\"\n")
        );
        assert_eq!((dolphin.2, nemo.2, nautilus.2), (0o755, 0o644, 0o755));
        assert!(items(Path::new("/a\tb")).is_err());
        Ok(())
    }

    /// The item placed at `place`.
    fn find<'a>(
        items: &'a [(&'static str, String, u32)],
        place: &str,
    ) -> io::Result<&'a (&'static str, String, u32)> {
        items
            .iter()
            .find(|(item, ..)| *item == place)
            .ok_or_else(|| io::Error::other(format!("no {place}")))
    }

    /// The value of the `Exec` key of the first line that has one.
    fn exec_value(contents: &str) -> Option<&str> {
        contents.lines().find_map(|line| line.strip_prefix("Exec="))
    }

    /// Names that a single-quoted shell word and a desktop-entry string
    /// can both hold: every awkward name the writers promise to handle.
    fn awkward() -> impl Iterator<Item = &'static str> {
        desktop_entry::read::AWKWARD.iter().copied()
    }

    /// Pins that the Dolphin service menu's `Exec` line gives the program
    /// back exactly, whatever its name holds.
    #[test]
    fn the_dolphin_exec_line_round_trips() -> io::Result<()> {
        for name in awkward() {
            let all = items(Path::new(name))?;
            let dolphin = find(&all, DOLPHIN)?;
            let value = exec_value(&dolphin.1).ok_or_else(|| io::Error::other("no Exec"))?;
            assert_eq!(
                desktop_entry::read::exec_arguments(value),
                Some(vec![name.to_owned(), "--send".into(), "%F".into()]),
                "{name}: {value}"
            );
        }
        Ok(())
    }

    /// Pins that the Nautilus script runs the program from its name
    /// exactly, passing the selection through, whatever the name holds.
    #[test]
    fn the_nautilus_script_round_trips() -> io::Result<()> {
        for name in awkward() {
            let all = items(Path::new(name))?;
            let nautilus = find(&all, NAUTILUS)?;
            let line = nautilus
                .1
                .lines()
                .find_map(|line| line.strip_prefix("exec "))
                .ok_or_else(|| io::Error::other("no exec"))?;
            assert_eq!(
                desktop_entry::read::shell_words(line),
                Some(vec![name.to_owned(), "--send".into(), "$@".into()]),
                "{name}: {line}"
            );
            assert!(nautilus.1.starts_with("#!/bin/sh\n"), "{name}");
            assert_eq!(nautilus.1.lines().count(), 3, "{name}");
        }
        Ok(())
    }

    /// The Nemo action's `Exec` line for `name`, read as a desktop-entry
    /// string and then as a shell line.
    fn nemo_words(name: &str) -> io::Result<Vec<String>> {
        let all = items(Path::new(name))?;
        let nemo = find(&all, NEMO)?;
        let value = exec_value(&nemo.1).ok_or_else(|| io::Error::other("no Exec"))?;
        let line = desktop_entry::read::string_value(value)
            .ok_or_else(|| io::Error::other(format!("{name}: invalid string {value}")))?;
        desktop_entry::read::shell_words(&line)
            .ok_or_else(|| io::Error::other(format!("{name}: not a shell line {line}")))
    }

    /// Pins that the Nemo action's `Exec` line gives the program back
    /// exactly for names with no `'`, `\`, or `%`.
    #[test]
    fn the_nemo_exec_line_round_trips() -> io::Result<()> {
        for name in awkward().filter(|name| !name.contains(['\'', '\\', '%'])) {
            assert_eq!(nemo_words(name)?, [name, "--send", "%F"], "{name}");
        }
        Ok(())
    }

    /// Pins that the Nemo action's `Exec` line (a key-file string holding
    /// a shell line) gives back every program path without a `%`, and that
    /// a path with one gets no Nemo item rather than one Nemo would expand.
    #[test]
    fn the_nemo_exec_line_round_trips_for_every_name() -> io::Result<()> {
        for name in awkward() {
            if name.contains('%') {
                assert!(find(&items(Path::new(name))?, NEMO).is_err(), "{name}");
            } else {
                assert_eq!(nemo_words(name)?, [name, "--send", "%F"], "{name}");
            }
        }
        Ok(())
    }

    /// Pins the shell quoting alone for the awkward names: the generated
    /// word is one word and is the name.
    #[test]
    fn shell_words_round_trip() -> io::Result<()> {
        for name in awkward() {
            assert_eq!(
                desktop_entry::read::shell_words(&shell_quote(Path::new(name))?),
                Some(vec![name.to_owned()]),
                "{name}"
            );
        }
        Ok(())
    }
}
