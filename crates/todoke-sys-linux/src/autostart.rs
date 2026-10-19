//! Starting todoke when the user logs in: an XDG autostart entry
//! (`~/.config/autostart`), or, inside Flatpak, the Background portal (the
//! desktop asks the user, and keeps the entry itself).

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

use zbus::{Connection, OwnedVariant, Variant};

use crate::{desktop_entry, portal};

/// The entry's file name.
const FILE: &str = "org.todoke.todoke.desktop";

/// The login item of the app at `exec`.
#[derive(Debug)]
pub struct Autostart {
    exec: PathBuf,
}

/// `$XDG_CONFIG_HOME`, or `~/.config` (a relative value is ignored, as the
/// specification says).
fn config_home() -> io::Result<PathBuf> {
    xdg_home("XDG_CONFIG_HOME", ".config")
}

pub(crate) fn xdg_home(variable: &str, fallback: &str) -> io::Result<PathBuf> {
    if let Some(dir) = std::env::var_os(variable).map(PathBuf::from)
        && dir.is_absolute()
    {
        return Ok(dir);
    }
    std::env::var_os("HOME")
        .map(PathBuf::from)
        .filter(|home| home.is_absolute())
        .map(|home| home.join(fallback))
        .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "no home directory"))
}

/// The entry that starts `exec` in the background.
fn entry(exec: &Path) -> io::Result<String> {
    Ok(format!(
        "[Desktop Entry]\nType=Application\nName=todoke\nComment=Receive files from your devices\nExec={} --background\nIcon=org.todoke.todoke\nTerminal=false\nNoDisplay=true\nX-GNOME-Autostart-enabled=true\n",
        desktop_entry::quote(exec)?
    ))
}

impl Autostart {
    /// The login item that starts `exec` (an absolute path; for an
    /// `AppImage`, the image, not its mount).
    #[must_use]
    pub fn new(exec: PathBuf) -> Self {
        Self { exec }
    }

    fn file() -> io::Result<PathBuf> {
        Ok(config_home()?.join("autostart").join(FILE))
    }

    /// Whether todoke starts at login; `None` inside Flatpak, where the
    /// desktop keeps that and does not tell.
    ///
    /// # Errors
    ///
    /// No home directory; the entry cannot be read.
    pub fn enabled(&self) -> io::Result<Option<bool>> {
        if portal::sandboxed() {
            return Ok(None);
        }
        let text = match std::fs::read_to_string(Self::file()?) {
            Ok(text) => text,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Some(false)),
            Err(error) => return Err(error),
        };
        let off = text.lines().any(|line| {
            let line = line.replace(' ', "");
            line == "Hidden=true" || line == "X-GNOME-Autostart-enabled=false"
        });
        Ok(Some(!off))
    }

    /// Starts todoke at login, or stops doing so. Inside Flatpak this asks
    /// the Background portal, which may ask the user: call it off the UI
    /// thread.
    ///
    /// # Errors
    ///
    /// I/O errors; `PermissionDenied` when the user refused.
    pub fn set(&self, on: bool) -> io::Result<()> {
        if portal::sandboxed() {
            return Self::request_background(on);
        }
        let file = Self::file()?;
        if on {
            desktop_entry::write(&file, &entry(&self.exec)?, 0o644)
        } else {
            match std::fs::remove_file(&file) {
                Err(error) if error.kind() != io::ErrorKind::NotFound => Err(error),
                _ => Ok(()),
            }
        }
    }

    fn request_background(on: bool) -> io::Result<()> {
        let results = zbus::block_on(async {
            let connection = Connection::session().await.map_err(portal::bus)?;
            let background =
                portal::proxy(&connection, "org.freedesktop.portal.Background").await?;
            portal::request(&connection, async |token| {
                let options: HashMap<&str, Variant<'_>> = HashMap::from([
                    ("handle_token", Variant::from(token)),
                    (
                        "reason",
                        Variant::from("Start todoke when you log in, to receive files"),
                    ),
                    ("autostart", Variant::from(on)),
                    (
                        "commandline",
                        Variant::from(vec!["todoke-desktop", "--background"]),
                    ),
                ]);
                background.call("RequestBackground", &("", options)).await
            })
            .await
        })?;
        let granted = results
            .get("autostart")
            .and_then(|value: &OwnedVariant| bool::try_from(value).ok())
            .unwrap_or(false);
        if on && !granted {
            return Err(io::ErrorKind::PermissionDenied.into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_entry_starts_the_app_in_the_background() -> io::Result<()> {
        let text = entry(Path::new("/opt/to doke/todoke-desktop"))?;
        assert!(text.contains("\nExec=\"/opt/to doke/todoke-desktop\" --background\n"));
        assert!(text.starts_with("[Desktop Entry]\n"));
        assert!(entry(Path::new("/a\nb")).is_err());
        Ok(())
    }
}
