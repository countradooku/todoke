//! The tray icon (Windows), menu-bar item (macOS), or `StatusNotifierItem`
//! (Linux): Open, Send clipboard…, Quit. While it is there, closing the
//! window keeps todoke running, receiving offers and notifying.
//!
//! On Linux the item is shown only when a `StatusNotifierItem` host runs
//! (KDE, most other desktops; GNOME with the `AppIndicator` extension):
//! without one, nothing would show it, and closing the window quits.

use tray_icon::menu::{Menu, MenuEvent, MenuItem, PredefinedMenuItem};
use tray_icon::{Icon, MouseButton, MouseButtonState, TrayIcon, TrayIconBuilder, TrayIconEvent};

use crate::icon::{self, Style};

/// What the tray asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Show the window.
    Open,
    /// Send what the clipboard holds (asks who).
    SendClipboard,
    /// Quit todoke.
    Quit,
}

const OPEN: &str = "open";
const CLIPBOARD: &str = "clipboard";
const QUIT: &str = "quit";

/// The tray item; dropping it removes it.
pub struct Tray(#[expect(dead_code, reason = "held: dropping removes the item")] TrayIcon);

impl core::fmt::Debug for Tray {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Tray")
    }
}

/// Adds the tray item, calling `on` (from any thread) with each action;
/// `None` where there is nowhere to show it. Call on the main thread once
/// the app runs.
pub fn install(on: impl Fn(Action) + Send + Sync + 'static) -> Option<Tray> {
    #[cfg(target_os = "linux")]
    if !todoke_sys_linux::tray::host_available() {
        return None;
    }
    let menu = Menu::new();
    let items = [
        MenuItem::with_id(OPEN, "Open todoke", true, None),
        MenuItem::with_id(CLIPBOARD, "Send clipboard…", true, None),
    ];
    let quit = MenuItem::with_id(QUIT, "Quit todoke", true, None);
    menu.append_items(&[
        &items[0],
        &items[1],
        &PredefinedMenuItem::separator(),
        &quit,
    ])
    .ok()?;
    #[cfg(target_os = "macos")]
    let builder = {
        let icon = Icon::from_rgba(icon::rgba(44, Style::Template), 44, 44).ok()?;
        TrayIconBuilder::new().with_icon_templated(icon)
    };
    #[cfg(not(target_os = "macos"))]
    let builder = {
        let icon = Icon::from_rgba(icon::rgba(32, Style::Color), 32, 32).ok()?;
        TrayIconBuilder::new().with_icon(icon)
    };
    let tray = builder
        .with_id("todoke")
        .with_tooltip("todoke")
        .with_menu(Box::new(menu))
        // A click opens the window on Windows and Linux; the menu is on the
        // right button there, and on any click in the macOS menu bar.
        .with_menu_on_left_click(cfg!(target_os = "macos"))
        .build()
        .ok()?;
    let on = std::sync::Arc::new(on);
    let menu_on = std::sync::Arc::clone(&on);
    MenuEvent::set_event_handler(Some(move |event: MenuEvent| {
        if let Some(action) = menu_action(event.id.as_ref()) {
            menu_on(action);
        }
    }));
    TrayIconEvent::set_event_handler(Some(move |event: TrayIconEvent| {
        if opens(&event) {
            on(Action::Open);
        }
    }));
    Some(Tray(tray))
}

fn menu_action(id: &str) -> Option<Action> {
    match id {
        OPEN => Some(Action::Open),
        CLIPBOARD => Some(Action::SendClipboard),
        QUIT => Some(Action::Quit),
        _ => None,
    }
}

/// A left click (released) or a double click opens the window.
fn opens(event: &TrayIconEvent) -> bool {
    matches!(
        event,
        TrayIconEvent::Click {
            button: MouseButton::Left,
            button_state: MouseButtonState::Up,
            ..
        } | TrayIconEvent::DoubleClick {
            button: MouseButton::Left,
            ..
        }
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn menu_items_map_to_actions() {
        assert_eq!(menu_action(OPEN), Some(Action::Open));
        assert_eq!(menu_action(CLIPBOARD), Some(Action::SendClipboard));
        assert_eq!(menu_action(QUIT), Some(Action::Quit));
        assert_eq!(menu_action("other"), None);
    }
}
