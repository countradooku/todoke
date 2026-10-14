//! This computer: starting at login and "Send with todoke" in the file
//! manager, over the platform crates (`todoke-sys-*`). Nothing here needs
//! admin rights. Calls may block (a portal may ask the user): run them on
//! the background executor.

use std::io;
use std::path::PathBuf;

/// The state of a setting the system keeps.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Integration {
    /// On.
    On,
    /// Off.
    Off,
    /// On once the user approves it in the system's settings (macOS).
    NeedsApproval,
    /// Installed and kept by the package (or the bundle): always on here.
    Packaged,
    /// The system does not say (Flatpak's Background portal).
    Unknown,
    /// Not available in this kind of install; the reason, for people.
    Unavailable(&'static str),
}

/// The program a login item or a file-manager item starts: the
/// `AppImage` itself rather than its temporary mount.
fn program() -> io::Result<PathBuf> {
    if cfg!(target_os = "linux")
        && let Some(image) = std::env::var_os("APPIMAGE").map(PathBuf::from)
        && image.is_absolute()
        && image.is_file()
    {
        return Ok(image);
    }
    std::env::current_exe()
}

/// Whether todoke starts at login.
#[must_use]
pub fn login_item() -> Integration {
    #[cfg(target_os = "macos")]
    {
        use todoke_sys_macos::login_item::{self, State};
        match login_item::state() {
            State::On => Integration::On,
            State::Off => Integration::Off,
            State::NeedsApproval => Integration::NeedsApproval,
            State::Unavailable => {
                Integration::Unavailable("Only the installed app can start at login.")
            }
        }
    }
    #[cfg(target_os = "windows")]
    {
        let Ok(program) = program() else {
            return Integration::Unavailable("The app's location is unknown.");
        };
        match todoke_sys_windows::autostart::Autostart::new(program).enabled() {
            Ok(true) => Integration::On,
            Ok(false) => Integration::Off,
            Err(_) => Integration::Unavailable("Windows did not answer."),
        }
    }
    #[cfg(target_os = "linux")]
    {
        let Ok(program) = program() else {
            return Integration::Unavailable("The app's location is unknown.");
        };
        match todoke_sys_linux::autostart::Autostart::new(program).enabled() {
            Ok(Some(true)) => Integration::On,
            Ok(Some(false)) => Integration::Off,
            Ok(None) => Integration::Unknown,
            Err(_) => Integration::Unavailable("There is no home directory."),
        }
    }
}

/// Starts todoke at login, or stops.
///
/// # Errors
///
/// The system's error; `PermissionDenied` when the user refused.
pub fn set_login_item(on: bool) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        let set = todoke_sys_macos::login_item::set(on);
        if on
            && todoke_sys_macos::login_item::state()
                == todoke_sys_macos::login_item::State::NeedsApproval
        {
            todoke_sys_macos::login_item::open_settings();
        }
        set
    }
    #[cfg(target_os = "windows")]
    {
        todoke_sys_windows::autostart::Autostart::new(program()?).set(on)
    }
    #[cfg(target_os = "linux")]
    {
        todoke_sys_linux::autostart::Autostart::new(program()?).set(on)
    }
}

/// Whether "Send with todoke" is in the file manager's menu.
#[must_use]
pub fn file_manager() -> Integration {
    #[cfg(target_os = "macos")]
    {
        // The bundle's Info.plist declares the service.
        if program().is_ok_and(|program| {
            program
                .ancestors()
                .any(|dir| dir.extension().is_some_and(|ext| ext == "app"))
        }) {
            Integration::Packaged
        } else {
            Integration::Unavailable("Only the installed app adds Send with todoke to Finder.")
        }
    }
    #[cfg(target_os = "windows")]
    {
        if todoke_sys_windows::package::packaged() {
            return Integration::Packaged;
        }
        match program() {
            Ok(program)
                if todoke_sys_windows::context_menu::ContextMenu::new(program).installed() =>
            {
                Integration::On
            }
            Ok(_) => Integration::Off,
            Err(_) => Integration::Unavailable("The app's location is unknown."),
        }
    }
    #[cfg(target_os = "linux")]
    {
        if todoke_sys_linux::portal::sandboxed() {
            return Integration::Unavailable(
                "Flatpak apps cannot add file-manager actions; use Open With → todoke.",
            );
        }
        match program() {
            Ok(program) if packaged(&program) => Integration::Packaged,
            Ok(program)
                if todoke_sys_linux::file_managers::FileManagers::new(program).installed() =>
            {
                Integration::On
            }
            Ok(_) => Integration::Off,
            Err(_) => Integration::Unavailable("The app's location is unknown."),
        }
    }
}

/// Installed by a package manager: the package installs the actions for
/// every user.
#[cfg(target_os = "linux")]
fn packaged(program: &std::path::Path) -> bool {
    ["/usr/", "/nix/store/", "/opt/"]
        .iter()
        .any(|prefix| program.starts_with(prefix))
}

/// Adds or removes "Send with todoke" in the file manager.
///
/// # Errors
///
/// The system's error; `Unsupported` where the package keeps it.
pub fn set_file_manager(on: bool) -> io::Result<()> {
    #[cfg(target_os = "macos")]
    {
        let _ = on;
        Err(io::ErrorKind::Unsupported.into())
    }
    #[cfg(target_os = "windows")]
    {
        let menu = todoke_sys_windows::context_menu::ContextMenu::new(program()?);
        if on { menu.install() } else { menu.uninstall() }
    }
    #[cfg(target_os = "linux")]
    {
        let items = todoke_sys_linux::file_managers::FileManagers::new(program()?);
        if on {
            items.install()
        } else {
            items.uninstall()
        }
    }
}
