//! Settings → This computer: starting at login, "Send with todoke" in the
//! file manager, and the global shortcut. The state is the system's, read
//! and changed on the background executor (a portal may ask the user).

use gpui_kit::component::switch::Switch;
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{AnyElement, AppContext as _, Context, IntoElement as _, ParentElement as _};

use super::widgets::{muted, section};
use super::{Command, Commander, Todoke};
use crate::hotkey;
use crate::model::Level;
use crate::prefs;
use crate::system::{self, Integration};
use crate::tokens::Palette;

/// What the system says about todoke's integration.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct System {
    /// Starting at login.
    pub login: Integration,
    /// "Send with todoke" in the file manager.
    pub file_manager: Integration,
}

/// The file manager's name, for people.
const FILE_MANAGER: &str = if cfg!(target_os = "macos") {
    "Finder"
} else if cfg!(windows) {
    "File Explorer"
} else {
    "the file manager"
};

impl Todoke {
    /// Lets this view change the computer's settings and register the
    /// global shortcut, whose presses go to `commander` (the app does
    /// this; tests do not).
    pub(crate) fn connect_system(&mut self, commander: Commander, cx: &mut Context<Self>) {
        self.commander = Some(commander);
        Self::read_system(cx);
    }

    fn read_system(cx: &mut Context<Self>) {
        cx.spawn(async move |this, cx| {
            let read = cx
                .background_spawn(async {
                    System {
                        login: system::login_item(),
                        file_manager: system::file_manager(),
                    }
                })
                .await;
            let _ = this.update(cx, |app, cx| {
                app.system = Some(read);
                cx.notify();
            });
        })
        .detach();
    }

    /// Whether the global shortcut is on.
    fn shortcut_on(&self) -> bool {
        self.prefs.shortcut.unwrap_or(!hotkey::portal())
    }

    /// Registers or releases the global shortcut as the preferences say.
    pub(super) fn apply_shortcut(&mut self, cx: &mut Context<Self>) {
        let Some(commander) = self.commander.clone() else {
            return;
        };
        if !self.shortcut_on() {
            self.shortcut = None;
            return;
        }
        if self.shortcut.is_some() {
            return;
        }
        let press = move || {
            let _ = commander.send(Command::SendSelection);
        };
        if hotkey::portal() {
            #[cfg(target_os = "linux")]
            cx.spawn(async move |this, cx| {
                let bound = cx
                    .background_spawn(async move { hotkey::bind_portal(press) })
                    .await;
                let _ = this.update(cx, |app, cx| match bound {
                    Ok(shortcut) => app.shortcut = Some(hotkey::Shortcut::from_portal(shortcut)),
                    Err(error) => {
                        app.model.notify(
                            Level::Error,
                            format!("The desktop did not give todoke a shortcut: {error}"),
                        );
                        cx.notify();
                    }
                });
            })
            .detach();
            return;
        }
        if let Ok(shortcut) = hotkey::register(press) {
            self.shortcut = Some(shortcut);
        } else {
            self.model.notify(
                Level::Error,
                format!(
                    "{} is taken by another app: the shortcut is off.",
                    hotkey::label()
                ),
            );
            cx.notify();
        }
    }

    fn set_shortcut(&mut self, on: bool, cx: &mut Context<Self>) {
        self.prefs.shortcut = Some(on);
        let (paths, prefs) = (self.paths.clone(), self.prefs);
        cx.background_spawn(async move { prefs::save_prefs(&paths, &prefs) })
            .detach();
        self.apply_shortcut(cx);
        cx.notify();
    }

    /// Changes a system setting with `change`, then reads them all again.
    fn change_system(
        change: impl FnOnce() -> std::io::Result<()> + Send + 'static,
        cx: &mut Context<Self>,
    ) {
        cx.spawn(async move |this, cx| {
            let changed = cx.background_spawn(async move { change() }).await;
            let _ = this.update(cx, |app, cx| {
                if let Err(error) = changed {
                    let text = if error.kind() == std::io::ErrorKind::PermissionDenied {
                        "The system refused: allow todoke in its settings, then try again."
                            .to_owned()
                    } else {
                        format!("The system did not make the change: {error}")
                    };
                    app.model.notify(Level::Error, text);
                }
                Self::read_system(cx);
            });
        })
        .detach();
    }

    pub(super) fn this_computer(
        &self,
        palette: &'static Palette,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let card = section("computer", "This computer", palette);
        let Some(system) = self.system else {
            return card.child(self.shortcut_switch(cx)).into_any_element();
        };
        let login = match system.login {
            Integration::Unavailable(why) => muted(why, palette).into_any_element(),
            state => Switch::new("login-item")
                .checked(matches!(
                    state,
                    Integration::On | Integration::NeedsApproval | Integration::Packaged
                ))
                .label("Start todoke when you log in, in the background")
                .accessibility_label("Start todoke when you log in")
                .on_click(cx.listener(|_, on: &bool, _, cx| {
                    let on = *on;
                    Self::change_system(move || system::set_login_item(on), cx);
                }))
                .into_any_element(),
        };
        let file_manager = match system.file_manager {
            Integration::Unavailable(why) => muted(why, palette).into_any_element(),
            Integration::Packaged => muted(
                format!("Send with todoke is in {FILE_MANAGER}'s menu (installed with the app)."),
                palette,
            )
            .into_any_element(),
            state => Switch::new("file-manager")
                .checked(state == Integration::On)
                .label(format!("Send with todoke in {FILE_MANAGER}'s menu"))
                .accessibility_label(format!("Send with todoke in {FILE_MANAGER}"))
                .on_click(cx.listener(|_, on: &bool, _, cx| {
                    let on = *on;
                    Self::change_system(move || system::set_file_manager(on), cx);
                }))
                .into_any_element(),
        };
        card.child(login)
            .when(system.login == Integration::NeedsApproval, |card| {
                card.child(muted(
                    "Waiting for your approval in System Settings → General → Login Items.",
                    palette,
                ))
            })
            .when(system.login == Integration::Unknown, |card| {
                card.child(muted(
                    "Your desktop keeps this setting; switching it asks the desktop.",
                    palette,
                ))
            })
            .child(file_manager)
            .child(self.shortcut_switch(cx))
            .into_any_element()
    }

    fn shortcut_switch(&self, cx: &mut Context<Self>) -> AnyElement {
        let what = if cfg!(target_os = "linux") {
            "the selected text or the clipboard"
        } else {
            "the clipboard"
        };
        Switch::new("shortcut")
            .checked(self.shortcut_on())
            .label(format!("{}: send {what} (asks who to)", hotkey::label()))
            .accessibility_label("Global shortcut to send the clipboard")
            .on_click(cx.listener(|this, on: &bool, _, cx| this.set_shortcut(*on, cx)))
            .into_any_element()
    }
}
