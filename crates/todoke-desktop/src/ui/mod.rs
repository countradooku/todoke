//! The window: one root view ([`Todoke`]) that owns the [`Model`] and the
//! backend, with a page per screen (`home`, `transfers`, `pair`, `history`,
//! `settings`) and the receive sheet over them.
//!
//! The UI thread never blocks: requests are awaited on the foreground
//! executor (they are channel sends), and file and profile work runs on the
//! background executor. Every interactive element has an ID, a role, and a
//! label for screen readers; every action has a key binding.

mod assets;
#[cfg(any(test, feature = "mock"))]
pub mod fixtures;
mod history;
mod home;
mod pair;
mod qr;
mod receive;
#[cfg(feature = "mock")]
pub mod screenshots;
mod settings;
#[cfg(test)]
mod tests;
mod transfers;
mod widgets;

use core::fmt::Write as _;
use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;

use gpui_kit::TestSupportExt as _;
use gpui_kit::component::input::{InputEvent, InputState};
use gpui_kit::component::{ActiveTheme as _, ThemeMode};
use gpui_kit::{
    App, AppContext as _, Context, Entity, ExternalPaths, FocusHandle, InteractiveElement as _,
    IntoElement, KeyBinding, ParentElement as _, PathPromptOptions, Render, Role,
    StatefulInteractiveElement as _, Styled as _, Subscription, Task, Window, WindowAppearance,
    actions, div, px,
};
use todoke_core::api::{Event, Request, Response};
use todoke_core::config::CoreConfig;
use todoke_daemon::Paths;
use tokio::sync::broadcast::error::RecvError;

use crate::backend::{self, Backend};
use crate::model::{Connection, EVERYTHING, Fetch, Level, Model, Pairing};
use crate::prefs::{self, Prefs, ThemeChoice};
use crate::tokens::{self, size, space};
use crate::{format, outbox};

actions!(
    todoke,
    [
        /// Show the home page.
        ShowHome,
        /// Show the transfers page.
        ShowTransfers,
        /// Show the pairing page.
        ShowPairing,
        /// Show the history page.
        ShowHistory,
        /// Show the settings page.
        ShowSettings,
        /// Choose files and folders to send to the selected contacts.
        ChooseFiles,
        /// Send what the clipboard holds to the selected contacts.
        SendClipboard,
        /// Search the history.
        FocusSearch,
        /// Accept every file of the offer shown.
        AcceptAll,
        /// Hide the receive sheet (the offer stays until it expires).
        CloseSheet,
    ]
);

/// The key context of the window.
const CONTEXT: &str = "Todoke";
/// The key context of the receive sheet.
const SHEET: &str = "TodokeSheet";

/// The key bindings: the platform's command key with a digit for each
/// page, O to choose files, Shift-V to send the clipboard, F to search.
#[must_use]
pub fn bindings() -> Vec<KeyBinding> {
    let m = if cfg!(target_os = "macos") {
        "cmd"
    } else {
        "ctrl"
    };
    vec![
        KeyBinding::new(&format!("{m}-1"), ShowHome, Some(CONTEXT)),
        KeyBinding::new(&format!("{m}-2"), ShowTransfers, Some(CONTEXT)),
        KeyBinding::new(&format!("{m}-3"), ShowPairing, Some(CONTEXT)),
        KeyBinding::new(&format!("{m}-4"), ShowHistory, Some(CONTEXT)),
        KeyBinding::new(&format!("{m}-5"), ShowSettings, Some(CONTEXT)),
        KeyBinding::new(&format!("{m}-o"), ChooseFiles, Some(CONTEXT)),
        KeyBinding::new(&format!("{m}-shift-v"), SendClipboard, Some(CONTEXT)),
        KeyBinding::new(&format!("{m}-f"), FocusSearch, Some(CONTEXT)),
        KeyBinding::new(&format!("{m}-enter"), AcceptAll, Some(SHEET)),
        KeyBinding::new("escape", CloseSheet, Some(SHEET)),
    ]
}

/// A screen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Page {
    /// Contacts, the drop zone, and recent transfers.
    Home,
    /// Transfers in progress.
    Transfers,
    /// Pairing a new device.
    Pairing,
    /// Finished transfers.
    History,
    /// Settings.
    Settings,
}

impl Page {
    const ALL: [Self; 5] = [
        Self::Home,
        Self::Transfers,
        Self::Pairing,
        Self::History,
        Self::Settings,
    ];

    const fn label(self) -> &'static str {
        match self {
            Self::Home => "Home",
            Self::Transfers => "Transfers",
            Self::Pairing => "Pair a device",
            Self::History => "History",
            Self::Settings => "Settings",
        }
    }

    const fn id(self) -> &'static str {
        match self {
            Self::Home => "nav-home",
            Self::Transfers => "nav-transfers",
            Self::Pairing => "nav-pairing",
            Self::History => "nav-history",
            Self::Settings => "nav-settings",
        }
    }

    const fn digit(self) -> char {
        match self {
            Self::Home => '1',
            Self::Transfers => '2',
            Self::Pairing => '3',
            Self::History => '4',
            Self::Settings => '5',
        }
    }
}

/// Which pairing method the pairing page shows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PairTab {
    /// Show a QR code for the other device to scan.
    ShowQr,
    /// Show a ten-digit code (stranger mode, five minutes).
    ShowCode,
    /// Enter the code another device shows.
    EnterCode,
    /// Paste the text of another device's QR code.
    PasteQr,
}

/// The receive sheet.
#[derive(Debug, Default)]
pub struct Sheet {
    /// The offer shown, by transfer.
    pub transfer: Option<String>,
    /// Whether its decisions are enabled (after [`tokens::DECISION_DELAY`]).
    pub armed: bool,
    /// The files chosen, while choosing.
    pub choosing: Option<BTreeSet<u32>>,
    /// Offers the user hid (they stay until they expire).
    pub hidden: BTreeSet<String>,
}

/// The root view.
pub struct Todoke {
    paths: Paths,
    backend: Option<Arc<dyn Backend>>,
    /// The state.
    pub model: Model,
    page: Page,
    focus: FocusHandle,
    /// The receive sheet takes focus when an offer appears (a dialog), so
    /// its keys work and a screen reader announces it.
    sheet_focus: FocusHandle,
    focused_sheet: Option<String>,
    /// Focus of each contact tile and of the drop zone, for the keyboard.
    tile_focus: BTreeMap<String, FocusHandle>,
    zone_focus: FocusHandle,
    search: Entity<InputState>,
    code: Entity<InputState>,
    qr_text: Entity<InputState>,
    pair_tab: PairTab,
    stranger: Option<String>,
    sheet: Sheet,
    /// The configuration as stored, and the one being edited.
    saved: Option<CoreConfig>,
    draft: Option<CoreConfig>,
    prefs: Prefs,
    confirm_clear: bool,
    /// The newest notice given a timer to go.
    noticed: u64,
    /// Clipboard files to remove when their transfer is over.
    outbox: BTreeMap<String, PathBuf>,
    /// Unix seconds, ticking each second (countdowns).
    now: u64,
    /// The one-second tick (countdowns).
    ticker: Option<Task<()>>,
    /// The event stream and the refresh of the backend in use.
    loops: Vec<Task<()>>,
    _subscriptions: Vec<Subscription>,
}

pub(super) fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |since| since.as_secs())
}

impl Todoke {
    /// The window's view, before the core is reached; [`Self::start`]
    /// reaches it.
    pub fn new(paths: Paths, window: &mut Window, cx: &mut Context<Self>) -> Self {
        let search = cx.new(|cx| {
            InputState::new(window, cx).placeholder("Search names, devices, hashes, or states")
        });
        let code = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("10 digits")
                .validate(|text, _| {
                    text.len() <= 11 && text.chars().all(|c| c.is_ascii_digit() || c == ' ')
                })
        });
        let qr_text = cx.new(|cx| {
            InputState::new(window, cx)
                .placeholder("TODOKE:…")
                .masked(true)
        });
        let mut subscriptions = vec![cx.subscribe(&search, |_, _, event: &InputEvent, cx| {
            if matches!(event, InputEvent::Change) {
                cx.notify();
            }
        })];
        subscriptions.push(cx.subscribe_in(
            &code,
            window,
            |this, _, event: &InputEvent, window, cx| {
                if matches!(event, InputEvent::PressEnter { .. }) {
                    this.enter_code(window, cx);
                }
            },
        ));
        subscriptions.push(cx.subscribe_in(
            &qr_text,
            window,
            |this, _, event: &InputEvent, window, cx| {
                if matches!(event, InputEvent::PressEnter { .. }) {
                    this.scan_qr(window, cx);
                }
            },
        ));
        subscriptions.push(cx.observe_window_appearance(window, |this, window, cx| {
            this.apply_theme(window, cx);
        }));
        let prefs = Prefs::default();
        let mut this = Self {
            paths,
            backend: None,
            model: Model::new(),
            page: Page::Home,
            focus: cx.focus_handle(),
            sheet_focus: cx.focus_handle(),
            focused_sheet: None,
            tile_focus: BTreeMap::new(),
            zone_focus: cx.focus_handle().tab_index(0).tab_stop(true),
            search,
            code,
            qr_text,
            pair_tab: PairTab::ShowQr,
            stranger: None,
            sheet: Sheet::default(),
            saved: None,
            draft: None,
            prefs,
            confirm_clear: false,
            noticed: 0,
            outbox: BTreeMap::new(),
            now: unix_now(),
            ticker: None,
            loops: Vec::new(),
            _subscriptions: subscriptions,
        };
        this.ticker = Some(cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor()
                    .timer(core::time::Duration::from_secs(1))
                    .await;
                let ticked = this.update(cx, |app, cx| {
                    app.now = unix_now();
                    let counting =
                        !matches!(app.model.pairing, Pairing::Idle) || app.sheet.transfer.is_some();
                    if counting {
                        cx.notify();
                    }
                });
                if ticked.is_err() {
                    break;
                }
            }
        }));
        window.focus(&this.focus, cx);
        this
    }

    /// Loads the preferences, then attaches to a daemon or hosts one, on
    /// the background executor.
    pub fn start(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.model.connection = Connection::Starting;
        let paths = self.paths.clone();
        cx.spawn_in(window, async move |this, cx| {
            let started = cx
                .background_spawn(async move {
                    let prefs = prefs::load_prefs(&paths);
                    (prefs, backend::start(&paths))
                })
                .await;
            let _ = this.update_in(cx, |app, window, cx| {
                let (prefs, started) = started;
                app.prefs = prefs;
                app.apply_theme(window, cx);
                match started {
                    Ok(started) => app.attach(started.backend, started.connection, cx),
                    Err(connection) => {
                        app.model.connection = connection;
                        cx.notify();
                    }
                }
            });
        })
        .detach();
    }

    /// Uses `backend` from now on: follows its events, refreshes, and
    /// fetches everything.
    pub fn attach(
        &mut self,
        backend: Arc<dyn Backend>,
        connection: Connection,
        cx: &mut Context<Self>,
    ) {
        self.model.connection = connection;
        let mut events = backend.events();
        self.backend = Some(backend);
        self.loops.clear();
        self.loops.push(cx.spawn(async move |this, cx| {
            loop {
                let event = match events.recv().await {
                    Ok(event) => event,
                    Err(RecvError::Lagged(missed)) => Event::Missed { events: missed },
                    Err(RecvError::Closed) => break,
                };
                if this.update(cx, |app, cx| app.on_event(event, cx)).is_err() {
                    break;
                }
            }
        }));
        self.loops.push(cx.spawn(async move |this, cx| {
            loop {
                cx.background_executor().timer(tokens::REFRESH).await;
                if this.update(cx, Self::refresh).is_err() {
                    break;
                }
            }
        }));
        self.fetch(&EVERYTHING, cx);
        self.load_config(cx);
        let state = self.paths.state_dir.clone();
        cx.background_spawn(async move { outbox::sweep(&state) })
            .detach();
        cx.notify();
    }

    /// Reads `config.json` on the background executor.
    fn load_config(&mut self, cx: &mut Context<Self>) {
        let paths = self.paths.clone();
        cx.spawn(async move |this, cx| {
            let config = cx.background_spawn(async move { paths.config() }).await;
            let _ = this.update(cx, |app, cx| {
                match config {
                    Ok(config) => {
                        app.model.relays = !config.relays.is_empty();
                        app.saved = Some(config.clone());
                        app.draft = Some(config);
                    }
                    Err(error) => app.model.notify(
                        Level::Error,
                        format!("The configuration could not be read: {error}"),
                    ),
                }
                cx.notify();
            });
        })
        .detach();
    }

    fn on_event(&mut self, event: Event, cx: &mut Context<Self>) {
        let fetch = self.model.apply(event);
        self.fetch(&fetch, cx);
        self.after_change(cx);
        cx.notify();
    }

    /// The periodic refresh: proximity and progress carry no event.
    fn refresh(&mut self, cx: &mut Context<Self>) {
        let Some(backend) = &self.backend else {
            return;
        };
        if !backend.alive() {
            if self.model.connection.is_up() {
                self.model.connection = Connection::Stopped;
                cx.notify();
            }
            return;
        }
        if self.page == Page::Pairing && self.pair_tab == PairTab::EnterCode {
            self.request(Request::Strangers, cx, |app, response, _| {
                app.model.answer(response);
                app.pick_stranger();
            });
        }
        self.fetch(&[Fetch::Status, Fetch::Contacts, Fetch::Transfers], cx);
    }

    /// Sends `request`; `then` runs with the answer on the UI thread.
    pub(crate) fn request(
        &mut self,
        request: Request,
        cx: &mut Context<Self>,
        then: impl FnOnce(&mut Self, Response, &mut Context<Self>) + 'static,
    ) {
        let Some(backend) = &self.backend else {
            self.model
                .notify(Level::Error, "todoke is not running: nothing was done");
            cx.notify();
            return;
        };
        let reply = backend.request(request);
        cx.spawn(async move |this, cx| {
            let response = reply.await;
            let _ = this.update(cx, |app, cx| {
                then(app, response, cx);
                app.after_change(cx);
                cx.notify();
            });
        })
        .detach();
    }

    /// Fetches `what` again.
    fn fetch(&mut self, what: &[Fetch], cx: &mut Context<Self>) {
        for fetch in what {
            let request = match fetch {
                Fetch::Status => Request::Status,
                Fetch::Contacts => Request::Contacts,
                Fetch::Transfers => Request::Transfers,
                Fetch::Offers => Request::Offers,
                Fetch::History => Request::History,
            };
            self.request(request, cx, |app, response, _| {
                // A failed fetch is retried by the next refresh; it is not
                // worth a notice every two seconds.
                if !matches!(response, Response::Error { .. }) {
                    app.model.answer(response);
                }
            });
        }
    }

    /// Keeps the sheet and the outbox in step with the model.
    pub(super) fn after_change(&mut self, cx: &mut Context<Self>) {
        let front = self
            .model
            .offers
            .iter()
            .find(|offer| !self.sheet.hidden.contains(&offer.transfer))
            .map(|offer| offer.transfer.clone());
        if front != self.sheet.transfer {
            self.sheet.transfer.clone_from(&front);
            self.sheet.armed = false;
            self.sheet.choosing = None;
            if front.is_some() {
                cx.spawn(async move |this, cx| {
                    cx.background_executor().timer(tokens::DECISION_DELAY).await;
                    let _ = this.update(cx, |app, cx| {
                        app.sheet.armed = true;
                        cx.notify();
                    });
                })
                .detach();
            }
        }
        let live: BTreeSet<&String> = self.model.offers.iter().map(|o| &o.transfer).collect();
        self.sheet.hidden.retain(|id| live.contains(id));
        let finished: Vec<String> = self
            .outbox
            .keys()
            .filter(|id| {
                self.model
                    .transfers
                    .get(*id)
                    .is_some_and(|t| t.state.is_finished())
            })
            .cloned()
            .collect();
        for id in finished {
            if let Some(file) = self.outbox.remove(&id) {
                let state = self.paths.state_dir.clone();
                cx.background_spawn(async move { outbox::remove(&state, &file) })
                    .detach();
            }
        }
        // Notices go after a while.
        let fresh: Vec<u64> = self
            .model
            .notices
            .iter()
            .map(|notice| notice.id)
            .filter(|id| *id > self.noticed)
            .collect();
        for id in fresh {
            self.noticed = id;
            cx.spawn(async move |this, cx| {
                cx.background_executor().timer(tokens::NOTICE).await;
                let _ = this.update(cx, |app, cx| {
                    app.model.dismiss(id);
                    cx.notify();
                });
            })
            .detach();
        }
    }

    /// Shows `page`.
    pub fn show(&mut self, page: Page, window: &mut Window, cx: &mut Context<Self>) {
        self.page = page;
        self.confirm_clear = false;
        match page {
            Page::History => {
                self.fetch(&[Fetch::History], cx);
            }
            Page::Pairing if self.pair_tab == PairTab::EnterCode => {
                self.request(Request::Strangers, cx, |app, response, _| {
                    app.model.answer(response);
                    app.pick_stranger();
                });
            }
            _ => {}
        }
        window.focus(&self.focus, cx);
        cx.notify();
    }

    /// The theme the preferences and the system ask for.
    fn apply_theme(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let mode = match self.prefs.theme {
            ThemeChoice::Light => ThemeMode::Light,
            ThemeChoice::Dark => ThemeMode::Dark,
            ThemeChoice::System => match window.appearance() {
                WindowAppearance::Dark | WindowAppearance::VibrantDark => ThemeMode::Dark,
                WindowAppearance::Light | WindowAppearance::VibrantLight => ThemeMode::Light,
            },
        };
        tokens::set_mode(mode, cx);
        cx.notify();
    }

    /// The contacts to send to: those selected, else the only one.
    fn targets(&self) -> Vec<String> {
        if !self.model.selected.is_empty() {
            return self.model.selected.iter().cloned().collect();
        }
        match self.model.contacts.as_slice() {
            [only] => vec![only.device.clone()],
            _ => Vec::new(),
        }
    }

    fn ask_for_targets(&mut self, cx: &mut Context<Self>) {
        let text = if self.model.contacts.is_empty() {
            "Pair a device first: there is no one to send to yet."
        } else {
            "Select who to send to first: click a contact (or several)."
        };
        self.model.notify(Level::Info, text);
        cx.notify();
    }

    /// Offers `paths` to each of `targets`.
    pub(crate) fn send_paths(
        &mut self,
        paths: &[PathBuf],
        targets: &[String],
        clipboard: Option<&std::path::Path>,
        cx: &mut Context<Self>,
    ) {
        if paths.is_empty() {
            return;
        }
        if targets.is_empty() {
            self.ask_for_targets(cx);
            return;
        }
        for contact in targets {
            let contact = contact.clone();
            let clipboard = clipboard.map(std::path::Path::to_path_buf);
            let request = Request::Send {
                contact: contact.clone(),
                paths: paths.to_vec(),
            };
            self.request(request, cx, move |app, response, cx| match response {
                Response::Offered { transfer, skipped } => {
                    if let Some(file) = clipboard {
                        app.outbox.insert(transfer, file);
                    }
                    let mut text = format!("Offered to {}", format::device(&contact));
                    if skipped > 0 {
                        let _ = write!(
                            text,
                            " ({} left out: links, special files, or names other systems cannot use)",
                            format::plural(skipped, "item", "items")
                        );
                    }
                    app.model.notify(Level::Info, text);
                    app.fetch(&[Fetch::Transfers], cx);
                }
                other => app.model.answer(other),
            });
        }
    }

    /// Files dropped on the window or a contact.
    pub(crate) fn dropped(
        &mut self,
        paths: &ExternalPaths,
        target: Option<String>,
        cx: &mut Context<Self>,
    ) {
        let targets = target.map_or_else(|| self.targets(), |one| vec![one]);
        self.send_paths(paths.paths(), &targets, None, cx);
    }

    fn choose_files(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let targets = self.targets();
        if targets.is_empty() {
            self.ask_for_targets(cx);
            return;
        }
        let chosen = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: true,
            multiple: true,
            prompt: Some("Send".into()),
        });
        let task = cx.spawn_in(window, async move |this, cx| {
            if let Ok(Ok(Some(paths))) = chosen.await {
                let _ = this.update(cx, |app, cx| app.send_paths(&paths, &targets, None, cx));
            }
        });
        task.detach();
    }

    fn send_clipboard(&mut self, cx: &mut Context<Self>) {
        let targets = self.targets();
        let Some(item) = cx.read_from_clipboard() else {
            self.model.notify(Level::Info, "The clipboard is empty.");
            cx.notify();
            return;
        };
        let paths: Vec<PathBuf> = item
            .entries()
            .iter()
            .filter_map(|entry| match entry {
                gpui_kit::ClipboardEntry::ExternalPaths(paths) => Some(paths.paths().to_vec()),
                _ => None,
            })
            .flatten()
            .collect();
        if !paths.is_empty() {
            self.send_paths(&paths, &targets, None, cx);
            return;
        }
        let Some(text) = item.text() else {
            self.model.notify(
                Level::Info,
                "Only text and files can be sent from the clipboard.",
            );
            cx.notify();
            return;
        };
        if targets.is_empty() {
            self.ask_for_targets(cx);
            return;
        }
        let state = self.paths.state_dir.clone();
        let now = unix_now();
        cx.spawn(async move |this, cx| {
            let written = cx
                .background_spawn(async move {
                    let text = zeroize::Zeroizing::new(text);
                    outbox::write(&state, &text, now)
                })
                .await;
            let _ = this.update(cx, |app, cx| match written {
                Ok(file) => app.send_paths(std::slice::from_ref(&file), &targets, Some(&file), cx),
                Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => {
                    app.model.notify(
                        Level::Error,
                        "The clipboard text is empty or larger than 16 MiB.",
                    );
                    cx.notify();
                }
                Err(error) => {
                    app.model.notify(
                        Level::Error,
                        format!("The clipboard text could not be saved: {error}"),
                    );
                    cx.notify();
                }
            });
        })
        .detach();
    }

    /// Accepts the offer shown: all files, or those chosen.
    pub(crate) fn accept(&mut self, cx: &mut Context<Self>) {
        let Some(transfer) = self.sheet.transfer.clone() else {
            return;
        };
        if !self.sheet.armed {
            return;
        }
        let resume = self
            .model
            .offers
            .iter()
            .find(|offer| offer.transfer == transfer)
            .and_then(|offer| offer.resume.clone());
        let files = match (&self.sheet.choosing, resume) {
            // A resumed transfer repeats its earlier selection exactly.
            (_, Some(selection)) => Some(selection),
            (Some(chosen), None) if chosen.is_empty() => {
                self.model
                    .notify(Level::Info, "Choose at least one file, or decline.");
                cx.notify();
                return;
            }
            (Some(chosen), None) => Some(chosen.iter().copied().collect()),
            (None, None) => None,
        };
        self.sheet.armed = false;
        self.request(
            Request::Accept { transfer, files },
            cx,
            |app, response, cx| {
                app.model.answer(response);
                app.fetch(&[Fetch::Offers, Fetch::Transfers], cx);
            },
        );
    }

    /// Declines the offer shown.
    pub(crate) fn decline(&mut self, cx: &mut Context<Self>) {
        let Some(transfer) = self.sheet.transfer.clone() else {
            return;
        };
        if !self.sheet.armed {
            return;
        }
        self.sheet.armed = false;
        self.request(Request::Decline { transfer }, cx, |app, response, cx| {
            app.model.answer(response);
            app.fetch(&[Fetch::Offers, Fetch::Transfers], cx);
        });
    }

    /// Cancels a transfer.
    pub(crate) fn cancel(&mut self, transfer: String, cx: &mut Context<Self>) {
        self.request(Request::Cancel { transfer }, cx, |app, response, cx| {
            app.model.answer(response);
            app.fetch(&[Fetch::Transfers], cx);
        });
    }

    fn pick_stranger(&mut self) {
        let known = |token: &String| self.model.strangers.iter().any(|s| s.stranger == *token);
        if self.stranger.as_ref().is_none_or(|token| !known(token)) {
            self.stranger = match self.model.strangers.as_slice() {
                [only] => Some(only.stranger.clone()),
                _ => None,
            };
        }
    }

    /// Pairs with the device whose code was entered.
    pub(crate) fn enter_code(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let code: String = self
            .code
            .read(cx)
            .value()
            .chars()
            .filter(char::is_ascii_digit)
            .collect();
        let code = zeroize::Zeroizing::new(code);
        if code.len() != 10 {
            self.model.notify(Level::Info, "The code has ten digits.");
            cx.notify();
            return;
        }
        let Some(stranger) = self.stranger.clone() else {
            self.model
                .notify(Level::Info, "Choose the nearby device that shows the code.");
            cx.notify();
            return;
        };
        self.code
            .update(cx, |input, cx| input.set_value("", window, cx));
        self.request(
            Request::PairEnterCode {
                code: code.to_string(),
                stranger,
            },
            cx,
            |app, response, cx| match response {
                Response::Paired { contact } => {
                    app.model.notify(
                        Level::Success,
                        format!("Paired with {}", format::device(&contact)),
                    );
                    app.fetch(&[Fetch::Contacts, Fetch::Status], cx);
                }
                other => app.model.answer(other),
            },
        );
    }

    /// Pairs with the device whose QR text was pasted.
    pub(crate) fn scan_qr(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let text = zeroize::Zeroizing::new(self.qr_text.read(cx).value().trim().to_owned());
        if !text.starts_with("TODOKE:") {
            self.model.notify(
                Level::Info,
                "Paste the text of the other device's QR code: it starts with TODOKE:",
            );
            cx.notify();
            return;
        }
        self.qr_text
            .update(cx, |input, cx| input.set_value("", window, cx));
        self.request(
            Request::PairScanQr {
                text: text.to_string(),
            },
            cx,
            |app, response, cx| match response {
                Response::Paired { contact } => {
                    app.model.notify(
                        Level::Success,
                        format!("Paired with {}", format::device(&contact)),
                    );
                    app.fetch(&[Fetch::Contacts, Fetch::Status], cx);
                }
                other => app.model.answer(other),
            },
        );
    }

    /// Hides or shows this device to its contacts, and keeps the choice.
    pub(crate) fn set_hidden(&mut self, hidden: bool, cx: &mut Context<Self>) {
        self.request(
            Request::SetHidden { hidden },
            cx,
            move |app, response, cx| {
                if matches!(response, Response::Done) {
                    app.fetch(&[Fetch::Status], cx);
                    for config in [&mut app.saved, &mut app.draft].into_iter().flatten() {
                        config.hidden = hidden;
                    }
                    if let Some(saved) = app.saved.clone() {
                        let paths = app.paths.clone();
                        cx.background_spawn(async move { prefs::save_config(&paths, &saved) })
                            .detach();
                    }
                } else {
                    app.model.answer(response);
                }
            },
        );
    }

    /// Writes the edited configuration and restarts the core with it.
    pub(crate) fn apply_settings(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let Some(draft) = self.draft.clone() else {
            return;
        };
        if let Err(why) = prefs::check(&self.paths, &draft) {
            self.model.notify(Level::Error, why.to_string());
            cx.notify();
            return;
        }
        let attached = self.model.connection == Connection::Attached;
        let old = self.backend.take();
        self.model.connection = Connection::Starting;
        let paths = self.paths.clone();
        let task = cx.spawn_in(window, async move |this, cx| {
            let saved = cx
                .background_spawn({
                    let paths = paths.clone();
                    async move {
                        prefs::save_config(&paths, &draft)?;
                        if attached {
                            backend::stop_daemon(&paths)?;
                        }
                        // The old core stops here, off the UI thread.
                        drop(old);
                        std::io::Result::Ok(())
                    }
                })
                .await;
            let _ = this.update_in(cx, |app, window, cx| {
                if let Err(error) = saved {
                    app.model.notify(
                        Level::Error,
                        format!("The settings could not be applied: {error}"),
                    );
                }
                app.start(window, cx);
            });
        });
        task.detach();
        cx.notify();
    }

    /// Stores and applies a theme choice.
    pub(crate) fn set_theme(
        &mut self,
        theme: ThemeChoice,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        self.prefs.theme = theme;
        self.apply_theme(window, cx);
        let (paths, prefs) = (self.paths.clone(), self.prefs);
        cx.background_spawn(async move { prefs::save_prefs(&paths, &prefs) })
            .detach();
    }

    /// The badge count of a navigation item.
    fn badge(&self, page: Page) -> usize {
        match page {
            Page::Transfers => self.model.active().len(),
            Page::Home => self.model.offers.len(),
            _ => 0,
        }
    }

    fn render_nav(&self, cx: &mut Context<Self>) -> gpui_kit::AnyElement {
        let palette = tokens::palette(cx);
        let m = if cfg!(target_os = "macos") {
            "⌘"
        } else {
            "Ctrl+"
        };
        div()
            .id("navigation")
            .role(Role::Navigation)
            .aria_label("Sections")
            .flex()
            .flex_col()
            .gap(px(space::XS))
            .w(px(size::SIDEBAR))
            .h_full()
            .p(px(space::M))
            .bg(tokens::color(palette.surface))
            .border_r_1()
            .border_color(tokens::color(palette.border))
            .child(
                div()
                    .px(px(space::S))
                    .pb(px(space::L))
                    .text_size(px(tokens::text::HEADING))
                    .font_weight(gpui_kit::FontWeight::BOLD)
                    .text_color(tokens::color(palette.text))
                    .child("todoke"),
            )
            .children(Page::ALL.into_iter().map(|page| {
                let selected = self.page == page;
                let badge = self.badge(page);
                let mut label = format!("{}, {m}{}", page.label(), page.digit());
                if badge > 0 {
                    let _ = write!(label, ", {badge} waiting");
                }
                div()
                    .id(page.id())
                    .role(Role::Tab)
                    .aria_label(label)
                    .aria_selected(selected)
                    .tab_index(0)
                    .flex()
                    .items_center()
                    .justify_between()
                    .px(px(space::M))
                    .py(px(space::S))
                    .rounded(px(tokens::radius::M))
                    .text_size(px(tokens::text::BODY))
                    .text_color(tokens::color(if selected {
                        palette.text
                    } else {
                        palette.muted
                    }))
                    .when(selected, |row| row.bg(tokens::color(palette.raised)))
                    .hover(|row| row.bg(tokens::color(palette.raised)))
                    .cursor_pointer()
                    .on_click(cx.listener(move |this, _, window, cx| this.show(page, window, cx)))
                    .child(page.label())
                    .when(badge > 0, |row| row.child(widgets::count(badge, palette)))
                    .test_support()
            }))
            .into_any_element()
    }

    fn render_banner(&self, cx: &mut Context<Self>) -> Option<gpui_kit::AnyElement> {
        let palette = tokens::palette(cx);
        let (text, level) = match &self.model.connection {
            Connection::Hosted | Connection::Attached => return None,
            Connection::Starting => ("Starting todoke…".to_owned(), Level::Info),
            Connection::Disabled => (
                "Sessions are disabled in this build: suite 0x0001 is not production-enabled (PROTOCOL §16). Pairing and transfers need a development build."
                    .to_owned(),
                Level::Error,
            ),
            Connection::Failed(why) => (format!("todoke could not start: {why}"), Level::Error),
            Connection::Stopped => (
                "todoke was stopped (todoke daemon stop). Transfers are paused.".to_owned(),
                Level::Error,
            ),
        };
        let retry = !matches!(self.model.connection, Connection::Starting);
        Some(
            div()
                .id("banner")
                .role(Role::Alert)
                .aria_label(text.clone())
                .flex()
                .items_center()
                .justify_between()
                .gap(px(space::M))
                .px(px(space::L))
                .py(px(space::S))
                .bg(tokens::color(match level {
                    Level::Error => palette.danger,
                    _ => palette.accent,
                }))
                .text_color(tokens::color(palette.on_status))
                .text_size(px(tokens::text::BODY))
                .child(text)
                .when(retry, |banner| {
                    banner.child(
                        widgets::button("retry", "Start again", "Start todoke again")
                            .on_click(cx.listener(|this, _, window, cx| this.start(window, cx))),
                    )
                })
                .test_support()
                .into_any_element(),
        )
    }
}

impl Render for Todoke {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        let palette = tokens::palette(cx);
        let page = match self.page {
            Page::Home => self.render_home(window, cx).into_any_element(),
            Page::Transfers => self.render_transfers(cx).into_any_element(),
            Page::Pairing => self.render_pairing(window, cx).into_any_element(),
            Page::History => self.render_history(cx).into_any_element(),
            Page::Settings => self.render_settings(window, cx).into_any_element(),
        };
        if self.focused_sheet != self.sheet.transfer {
            self.focused_sheet.clone_from(&self.sheet.transfer);
            let handle = if self.sheet.transfer.is_some() {
                &self.sheet_focus
            } else {
                &self.focus
            };
            window.focus(handle, cx);
        }
        let banner = self.render_banner(cx);
        let sheet = self.render_sheet(cx);
        let notices = widgets::notices(&self.model, cx);
        div()
            .id("todoke")
            .key_context(CONTEXT)
            .track_focus(&self.focus)
            .on_action(
                cx.listener(|this, _: &ShowHome, window, cx| this.show(Page::Home, window, cx)),
            )
            .on_action(cx.listener(|this, _: &ShowTransfers, window, cx| {
                this.show(Page::Transfers, window, cx);
            }))
            .on_action(cx.listener(|this, _: &ShowPairing, window, cx| {
                this.show(Page::Pairing, window, cx);
            }))
            .on_action(cx.listener(|this, _: &ShowHistory, window, cx| {
                this.show(Page::History, window, cx);
            }))
            .on_action(cx.listener(|this, _: &ShowSettings, window, cx| {
                this.show(Page::Settings, window, cx);
            }))
            .on_action(
                cx.listener(|this, _: &ChooseFiles, window, cx| this.choose_files(window, cx)),
            )
            .on_action(cx.listener(|this, _: &SendClipboard, _, cx| this.send_clipboard(cx)))
            .on_action(cx.listener(|this, _: &FocusSearch, window, cx| {
                this.show(Page::History, window, cx);
                this.search.update(cx, |input, cx| input.focus(window, cx));
            }))
            .on_drop(
                cx.listener(|this, paths: &ExternalPaths, _, cx| this.dropped(paths, None, cx)),
            )
            .size_full()
            .flex()
            .flex_col()
            .bg(tokens::color(palette.background))
            .text_color(tokens::color(palette.text))
            .font_family(cx.theme().font_family.clone())
            .children(banner)
            .child(
                div()
                    .flex()
                    .flex_1()
                    .min_h_0()
                    .child(self.render_nav(cx))
                    .child(
                        div()
                            .id("page")
                            .role(Role::Main)
                            .aria_label(self.page.label())
                            .flex_1()
                            .min_w_0()
                            .h_full()
                            .overflow_y_scroll()
                            .p(px(space::XXL))
                            .child(page),
                    ),
            )
            .children(sheet)
            .child(notices)
    }
}

use gpui_kit::prelude::FluentBuilder as _;

/// Opens the window and runs the app until it quits.
pub fn run() {
    let paths = match Paths::discover() {
        Ok(paths) => paths,
        Err(error) => {
            eprintln!("todoke: no home directory to keep the profile in: {error}");
            std::process::exit(1);
        }
    };
    gpui_kit::application()
        .with_assets(assets::Assets)
        .run(move |cx: &mut App| {
            gpui_kit::init(cx);
            cx.bind_keys(bindings());
            let bounds = gpui_kit::Bounds::centered(
                None,
                gpui_kit::size(px(size::WINDOW.0), px(size::WINDOW.1)),
                cx,
            );
            let options = gpui_kit::WindowOptions {
                window_bounds: Some(gpui_kit::WindowBounds::Windowed(bounds)),
                window_min_size: Some(gpui_kit::size(
                    px(size::MIN_WINDOW.0),
                    px(size::MIN_WINDOW.1),
                )),
                titlebar: Some(gpui_kit::TitlebarOptions {
                    title: Some("todoke".into()),
                    ..Default::default()
                }),
                app_id: Some("org.todoke.todoke".into()),
                ..Default::default()
            };
            let opened = gpui_kit::open_window(options, cx, |window, cx| {
                cx.new(|cx| {
                    let mut app = Todoke::new(paths, window, cx);
                    app.start(window, cx);
                    app
                })
            });
            if let Err(error) = opened {
                eprintln!("todoke: the window could not open: {error}");
                cx.quit();
            }
            cx.on_window_closed(|cx, _| {
                if cx.windows().is_empty() {
                    cx.quit();
                }
            })
            .detach();
        });
}
