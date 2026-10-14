//! "Send with todoke" in Explorer's context menu for unpackaged installs:
//! verbs under this user's classes (no admin). On Windows 11 they appear
//! under "Show more options"; the MSIX package declares an Explorer
//! command (`todoke-shell-windows`) that appears at the top level.
//!
//! Explorer starts one process per selected item for such verbs; each
//! hands its item to the running window, whose "Send to…" gathers them.

use std::io;
use std::path::PathBuf;

use windows_registry::CURRENT_USER;

const VERB: &str = "todoke.send";
const CLASSES: [&str; 2] = [
    r"Software\Classes\*\shell",
    r"Software\Classes\Directory\shell",
];

#[expect(clippy::needless_pass_by_value, reason = "used as map_err(os)")]
fn os(error: windows::core::Error) -> io::Error {
    io::Error::other(format!("Windows error {:#010x}", error.code().0))
}

/// The verbs that send with the app at `exec`.
#[derive(Debug)]
pub struct ContextMenu {
    exec: PathBuf,
}

impl ContextMenu {
    /// The verbs that run `exec`.
    #[must_use]
    pub fn new(exec: PathBuf) -> Self {
        Self { exec }
    }

    fn command(&self) -> String {
        format!("\"{}\" --send \"%1\"", self.exec.display())
    }

    /// Whether the verbs are there and run this app.
    #[must_use]
    pub fn installed(&self) -> bool {
        CLASSES.iter().all(|class| {
            CURRENT_USER
                .open(format!(r"{class}\{VERB}\command"))
                .and_then(|key| key.get_string(""))
                .is_ok_and(|command| command == self.command())
        })
    }

    /// Adds the verbs.
    ///
    /// # Errors
    ///
    /// The registry's error.
    pub fn install(&self) -> io::Result<()> {
        let icon = format!("\"{}\",0", self.exec.display());
        for class in CLASSES {
            let verb = CURRENT_USER
                .create(format!(r"{class}\{VERB}"))
                .map_err(os)?;
            verb.set_string("MUIVerb", "Send with todoke").map_err(os)?;
            verb.set_string("Icon", &icon).map_err(os)?;
            verb.set_string("MultiSelectModel", "Player").map_err(os)?;
            verb.create("command")
                .and_then(|command| command.set_string("", self.command()))
                .map_err(os)?;
        }
        Ok(())
    }

    /// Removes the verbs.
    ///
    /// # Errors
    ///
    /// The registry's error, other than "not found".
    pub fn uninstall(&self) -> io::Result<()> {
        for class in CLASSES {
            match CURRENT_USER.remove_tree(format!(r"{class}\{VERB}")) {
                Ok(()) => {}
                Err(error)
                    if error.code()
                        == windows::Win32::Foundation::ERROR_FILE_NOT_FOUND.to_hresult() => {}
                Err(error) => return Err(os(error)),
            }
        }
        Ok(())
    }
}
