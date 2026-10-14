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

fn items(exec: &Path) -> io::Result<[(&'static str, String, u32); 3]> {
    let entry = desktop_entry::quote(exec)?;
    let shell = shell_quote(exec)?;
    Ok([
        (
            DOLPHIN,
            format!(
                "[Desktop Entry]\nType=Service\nMimeType=all/all;inode/directory;\nActions=send\nX-KDE-Priority=TopLevel\n\n[Desktop Action send]\nName=Send with todoke\nIcon=org.todoke.todoke\nExec={entry} --send %F\n"
            ),
            0o755,
        ),
        (
            NEMO,
            format!(
                "[Nemo Action]\nName=Send with todoke\nComment=Send the selection to a contact\nExec={shell} --send %F\nIcon-Name=org.todoke.todoke\nSelection=notnone\nExtensions=any;dir;\n"
            ),
            0o644,
        ),
        (
            NAUTILUS,
            format!(
                "#!/bin/sh\n# Send with todoke: the selection is in the arguments.\nexec {shell} --send \"$@\"\n"
            ),
            0o755,
        ),
    ])
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

    /// Whether every item is there.
    #[must_use]
    pub fn installed(&self) -> bool {
        Self::data_home().is_ok_and(|home| {
            [DOLPHIN, NEMO, NAUTILUS]
                .iter()
                .all(|item| home.join(item).is_file())
        })
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
        let [dolphin, nemo, nautilus] = items(Path::new("/home/me/it's/todoke.AppImage"))?;
        assert!(
            dolphin
                .1
                .contains("Exec=\"/home/me/it's/todoke.AppImage\" --send %F\n")
        );
        assert!(
            nemo.1
                .contains(r"Exec='/home/me/it'\''s/todoke.AppImage' --send %F")
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
}
