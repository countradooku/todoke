//! The global shortcut: send the clipboard (on Linux, the text selected
//! anywhere, else the clipboard) to a contact, through the "Send to…"
//! picker. ⌃⌥⌘T on macOS, Ctrl+Alt+Shift+T elsewhere.
//!
//! On macOS, Windows, and X11 it is registered with the system
//! (`global-hotkey`: no accessibility permission, no key logging). On
//! Wayland, where no app may grab keys, it goes through the
//! `GlobalShortcuts` portal: the desktop asks the user to confirm and may
//! let them choose other keys.

use std::io;

/// The shortcut, for people.
#[must_use]
pub fn label() -> &'static str {
    if cfg!(target_os = "macos") {
        "⌃⌥⌘T"
    } else {
        "Ctrl+Alt+Shift+T"
    }
}

/// A registered shortcut; dropping it unregisters it.
pub struct Shortcut(Inner);

enum Inner {
    Native {
        manager: global_hotkey::GlobalHotKeyManager,
        hotkey: global_hotkey::hotkey::HotKey,
    },
    #[cfg(target_os = "linux")]
    Portal(
        #[expect(dead_code, reason = "held: dropping releases it")]
        todoke_sys_linux::global_shortcuts::GlobalShortcut,
    ),
}

impl core::fmt::Debug for Shortcut {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Shortcut")
    }
}

impl Drop for Shortcut {
    #[cfg_attr(
        not(target_os = "linux"),
        expect(irrefutable_let_patterns, reason = "the portal is Linux only")
    )]
    fn drop(&mut self) {
        if let Inner::Native { manager, hotkey } = &self.0 {
            let _ = manager.unregister(*hotkey);
        }
    }
}

/// Whether this session needs the portal (Wayland).
#[must_use]
pub fn portal() -> bool {
    cfg!(target_os = "linux") && std::env::var_os("WAYLAND_DISPLAY").is_some()
}

/// Registers the shortcut with the system, calling `on` (from any thread)
/// when it is pressed. Call on the main thread; not on Wayland (see
/// [`bind_portal`]).
///
/// # Errors
///
/// The shortcut is taken by another app, or the system refused.
pub fn register(on: impl Fn() + Send + Sync + 'static) -> io::Result<Shortcut> {
    use global_hotkey::hotkey::{Code, HotKey, Modifiers};
    use global_hotkey::{GlobalHotKeyEvent, GlobalHotKeyManager, HotKeyState};
    let modifiers = if cfg!(target_os = "macos") {
        Modifiers::CONTROL | Modifiers::ALT | Modifiers::SUPER
    } else {
        Modifiers::CONTROL | Modifiers::ALT | Modifiers::SHIFT
    };
    let hotkey = HotKey::new(Some(modifiers), Code::KeyT);
    let manager = GlobalHotKeyManager::new().map_err(io::Error::other)?;
    manager.register(hotkey).map_err(io::Error::other)?;
    let id = hotkey.id();
    GlobalHotKeyEvent::set_event_handler(Some(move |event: GlobalHotKeyEvent| {
        if event.id == id && event.state == HotKeyState::Pressed {
            on();
        }
    }));
    Ok(Shortcut(Inner::Native { manager, hotkey }))
}

/// Binds the shortcut through the `GlobalShortcuts` portal (Wayland).
/// Blocks while the desktop asks the user: call it off the UI thread, then
/// keep it with [`Shortcut::from_portal`].
///
/// # Errors
///
/// No portal; the user refused.
#[cfg(target_os = "linux")]
pub fn bind_portal(
    on: impl Fn() + Send + 'static,
) -> io::Result<todoke_sys_linux::global_shortcuts::GlobalShortcut> {
    todoke_sys_linux::global_shortcuts::bind(
        "send-clipboard",
        "Send the selection or the clipboard with todoke",
        "CTRL+ALT+SHIFT+t",
        on,
    )
}

#[cfg(target_os = "linux")]
impl Shortcut {
    /// Keeps a shortcut bound through the portal.
    #[must_use]
    pub fn from_portal(shortcut: todoke_sys_linux::global_shortcuts::GlobalShortcut) -> Self {
        Self(Inner::Portal(shortcut))
    }
}
