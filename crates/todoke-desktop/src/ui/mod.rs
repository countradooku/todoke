//! The window: one root view ([`Todoke`]) that owns the [`Model`] and the
//! backend, with a page per screen (`home`, `transfers`, `pair`, `history`,
//! `settings`) and the receive sheet over them.
//!
//! The UI thread never blocks: requests are awaited on the foreground
//! executor (they are channel sends), and file and profile work runs on the
//! background executor. Every interactive element has an ID, a role, and a
//! label for screen readers; every action has a key binding.

mod assets;
mod computer;
#[cfg(any(test, feature = "mock"))]
pub mod fixtures;
mod history;
mod home;
mod notify;
mod pair;
mod picker;
mod qr;
mod receive;
// Off-screen rendering is Metal: macOS only.
#[cfg(all(feature = "mock", target_os = "macos"))]
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
use todoke_daemon::handoff::{self, Handoff};
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
        /// Close the "Send to…" picker, sending nothing.
        ClosePicker,
    ]
);

/// The key context of the window.
const CONTEXT: &str = "Todoke";
/// The key context of the receive sheet.
const SHEET: &str = "TodokeSheet";
/// The key context of the "Send to…" picker.
const PICKER: &str = "TodokePicker";

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
        KeyBinding::new("escape", CloseSheet, Some(SHEET)),
        KeyBinding::new("escape", ClosePicker, Some(PICKER)),
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
    /// Bumped whenever the offer shown changes: an arming timer started
    /// for an earlier offer arms nothing.
    pub generation: u64,
}

/// The parts of the view that belong to its window.
struct WindowParts {
    search: Entity<InputState>,
    code: Entity<InputState>,
    qr_text: Entity<InputState>,
    subscriptions: Vec<Subscription>,
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
    /// "Send to…": what a launch, the clipboard, or the global shortcut
    /// offered, until the user chooses contacts or cancels.
    picker: picker::State,
    /// The configuration as stored, and the one being edited.
    saved: Option<CoreConfig>,
    draft: Option<CoreConfig>,
    prefs: Prefs,
    confirm_clear: bool,
    /// The newest notice given a timer to go.
    noticed: u64,
    /// Clipboard files of offered transfers, removed when no transfer
    /// needs them any more.
    outbox: BTreeMap<String, PathBuf>,
    /// Clipboard files whose offers still await the core's answer, with
    /// how many: a file is removed only when none is pending and no
    /// offered transfer uses it (one file can go to several contacts).
    outbox_pending: BTreeMap<PathBuf, usize>,
    /// Whether the window is in front: offers and finished transfers
    /// notify the system only while it is not.
    active: bool,
    /// The offers notified, whose notifications go when they do.
    notified: BTreeSet<String>,
    /// This computer's settings, once read (never in tests: they would
    /// change the machine running them).
    system: Option<computer::System>,
    /// The preferences changed off the window: apply the theme when drawing.
    theme_pending: bool,
    /// Where the global shortcut sends its presses; `None` in tests.
    commander: Option<Commander>,
    shortcut: Option<crate::hotkey::Shortcut>,
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
        let WindowParts {
            search,
            code,
            qr_text,
            subscriptions,
        } = Self::window_parts(window, cx);
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
            picker: picker::State::new(cx),
            saved: None,
            draft: None,
            prefs,
            confirm_clear: false,
            noticed: 0,
            outbox: BTreeMap::new(),
            outbox_pending: BTreeMap::new(),
            active: true,
            notified: BTreeSet::new(),
            system: None,
            theme_pending: false,
            commander: None,
            shortcut: None,
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
                    // An expired offer is gone in the core (§3): its secret
                    // goes from here too.
                    if app
                        .model
                        .pairing
                        .expires_at()
                        .is_some_and(|at| at <= app.now)
                    {
                        app.model.pairing = Pairing::Idle;
                        cx.notify();
                    }
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

    /// What belongs to a window: the text fields and what follows the
    /// window's appearance, focus, and activation.
    fn window_parts(window: &mut Window, cx: &mut Context<Self>) -> WindowParts {
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
        subscriptions.push(cx.observe_window_activation(window, |this, window, cx| {
            let active = window.is_window_active();
            if active && !this.active {
                this.came_forward(cx);
            }
            this.active = active;
        }));
        WindowParts {
            search,
            code,
            qr_text,
            subscriptions,
        }
    }

    /// The window was closed while todoke keeps running (the tray or menu
    /// bar item brings it back): offers and transfers now notify.
    /// An open picker goes too: what it held (clipboard text) is dropped,
    /// and it never comes back already armed.
    pub fn closed(&mut self) {
        self.active = false;
        self.picker.open = None;
    }

    /// Started without showing the window (a login item): offers notify.
    pub fn in_background(&mut self) {
        self.active = false;
    }

    /// The window came to the front, under the pointer: a click aimed at
    /// what was there must not decide the offer or send, so the sheet's
    /// decisions and the picker's Send wait the decision delay again.
    fn came_forward(&mut self, cx: &mut Context<Self>) {
        if self.sheet.transfer.is_some() {
            self.sheet.armed = false;
            self.sheet.generation += 1;
            self.arm_later(cx);
        }
        self.arm_picker_later(cx);
        cx.notify();
    }

    /// Shows this view in a new `window` after the last one closed.
    #[expect(
        clippy::used_underscore_binding,
        reason = "the subscriptions are held, never read"
    )]
    pub fn reopened(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        let WindowParts {
            search,
            code,
            qr_text,
            subscriptions,
        } = Self::window_parts(window, cx);
        (self.search, self.code, self.qr_text) = (search, code, qr_text);
        self._subscriptions = subscriptions;
        self.focused_sheet = None;
        self.picker.focused = false;
        self.active = true;
        self.came_forward(cx);
        self.apply_theme(window, cx);
        window.focus(&self.focus, cx);
        // A start that ended with the earlier window: start again.
        if self.backend.is_none() && !matches!(self.model.connection, Connection::Starting) {
            self.start(cx);
        }
        cx.notify();
    }

    /// Loads the preferences, then attaches to a daemon or hosts one, on
    /// the background executor.
    /// Not tied to a window: closing the window while it runs (with a
    /// tray) keeps what it starts.
    pub fn start(&mut self, cx: &mut Context<Self>) {
        self.model.connection = Connection::Starting;
        let paths = self.paths.clone();
        // A core this app still holds must stop first: it holds the profile.
        let old = self.backend.take();
        cx.spawn(async move |this, cx| {
            let started = cx
                .background_spawn(async move {
                    drop(old);
                    let prefs = prefs::load_prefs(&paths);
                    (prefs, backend::start(&paths))
                })
                .await;
            let _ = this.update(cx, |app, cx| {
                let (prefs, started) = started;
                app.prefs = prefs;
                // The theme needs the window: applied when it next draws.
                app.theme_pending = true;
                app.apply_shortcut(cx);
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
        let notification = match &event {
            Event::OfferReceived(offer) => Some(notify::offer(offer)),
            _ => None,
        };
        let ended = match &event {
            Event::Completed { transfer }
            | Event::Delivered { transfer }
            | Event::Ended { transfer, .. } => Some(transfer.clone()),
            _ => None,
        };
        let fetch = self.model.apply(event);
        if !self.active {
            if let Some(notification) = notification {
                self.notified.insert(notification.tag.to_string());
                cx.show_system_notification(notification);
            } else if let (Some(transfer), Some(notice)) = (ended, self.model.notices.back()) {
                cx.show_system_notification(notify::finished(&transfer, &notice.text));
            }
        }
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
            // Stopped from outside (`todoke daemon stop`) or gone: a hosted
            // core must stop too, off this thread (its threads are joined).
            if let Some(old) = self.backend.take() {
                cx.background_spawn(async move { drop(old) }).detach();
            }
            self.model.connection = Connection::Stopped;
            cx.notify();
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
            self.sheet.generation += 1;
            if front.is_some() {
                self.arm_later(cx);
            }
        }
        let live: BTreeSet<&String> = self.model.offers.iter().map(|o| &o.transfer).collect();
        self.sheet.hidden.retain(|id| live.contains(id));
        // An offer decided, expired, or withdrawn: its notification goes.
        let tags: BTreeSet<String> = live.iter().map(|id| notify::offer_tag(id)).collect();
        for gone in self.notified.difference(&tags) {
            cx.dismiss_system_notification(gone);
        }
        self.notified.retain(|tag| tags.contains(tag));
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
                self.sweep_outbox(&file, cx);
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

    /// Arms the sheet's decisions after [`tokens::DECISION_DELAY`], if it
    /// still shows the same offer then.
    fn arm_later(&mut self, cx: &mut Context<Self>) {
        let generation = self.sheet.generation;
        cx.spawn(async move |this, cx| {
            cx.background_executor().timer(tokens::DECISION_DELAY).await;
            let _ = this.update(cx, |app, cx| {
                if app.sheet.generation == generation {
                    app.sheet.armed = true;
                    cx.notify();
                }
            });
        })
        .detach();
    }

    /// After a decision the core refused: the same offer may be decided
    /// again (after the delay), unless another took its place.
    fn rearm(&mut self, transfer: &str, response: &Response, cx: &mut Context<Self>) {
        if matches!(response, Response::Error { .. })
            && self.sheet.transfer.as_deref() == Some(transfer)
        {
            self.sheet.generation += 1;
            self.arm_later(cx);
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
            // What is shown is what is stored, unless edits are pending.
            Page::Settings if self.draft == self.saved => self.load_config(cx),
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
        if let Some(file) = clipboard {
            *self.outbox_pending.entry(file.to_path_buf()).or_default() += targets.len();
        }
        for contact in targets {
            let contact = contact.clone();
            let clipboard = clipboard.map(std::path::Path::to_path_buf);
            let request = Request::Send {
                contact: contact.clone(),
                paths: paths.to_vec(),
            };
            self.request(request, cx, move |app, response, cx| {
                if let Some(file) = &clipboard {
                    if let Some(pending) = app.outbox_pending.get_mut(file) {
                        *pending = pending.saturating_sub(1);
                    }
                    if let Response::Offered { transfer, .. } = &response {
                        app.outbox.insert(transfer.clone(), file.clone());
                    }
                    app.sweep_outbox(file, cx);
                }
                app.offered(&contact, response, cx);
            });
        }
    }

    /// Removes the clipboard file `file` once no offer is pending for it
    /// and no offered transfer uses it.
    fn sweep_outbox(&mut self, file: &std::path::Path, cx: &mut Context<Self>) {
        if self
            .outbox_pending
            .get(file)
            .is_some_and(|pending| *pending > 0)
            || self.outbox.values().any(|used| used == file)
        {
            return;
        }
        self.outbox_pending.remove(file);
        let (state, file) = (self.paths.state_dir.clone(), file.to_path_buf());
        cx.background_spawn(async move { outbox::remove(&state, &file) })
            .detach();
    }

    /// The core's answer to an offer to `contact`.
    fn offered(&mut self, contact: &str, response: Response, cx: &mut Context<Self>) {
        match response {
            Response::Offered { skipped, .. } => {
                let mut text = format!("Offered to {}", format::device(contact));
                if skipped > 0 {
                    let _ = write!(
                        text,
                        " ({} left out: links, special files, or names other systems cannot use)",
                        format::plural(skipped, "item", "items")
                    );
                }
                self.model.notify(Level::Info, text);
                self.fetch(&[Fetch::Transfers], cx);
            }
            other => self.model.answer(other),
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

    /// Sends the clipboard to the selected contacts, or asks who to send it
    /// to when none is selected among several.
    fn send_clipboard(&mut self, cx: &mut Context<Self>) {
        let targets = self.targets();
        if targets.is_empty() && !self.model.contacts.is_empty() {
            self.pick_clipboard(false, cx);
            return;
        }
        if let Some(offered) = self.read_clipboard(false, cx) {
            self.send_offered(offered, targets, cx);
        }
    }

    /// What the clipboard (or, on Linux with `selection`, the text
    /// selected anywhere, if any) holds; a notice when nothing can be sent.
    fn read_clipboard(
        &mut self,
        selection: bool,
        cx: &mut Context<Self>,
    ) -> Option<picker::Offered> {
        #[cfg(target_os = "linux")]
        let item = selection
            .then(|| cx.read_from_primary())
            .flatten()
            .filter(|item| item.text().is_some_and(|text| !text.trim().is_empty()))
            .or_else(|| cx.read_from_clipboard());
        #[cfg(not(target_os = "linux"))]
        let item = {
            let _ = selection;
            cx.read_from_clipboard()
        };
        let Some(item) = item else {
            self.model.notify(Level::Info, "The clipboard is empty.");
            cx.notify();
            return None;
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
            return Some(picker::Offered::Paths(paths));
        }
        if let Some(text) = item.text() {
            let text = zeroize::Zeroizing::new(text);
            // The outbox's limit, checked before the picker holds it.
            if text.len() > outbox::MAX_TEXT {
                self.model
                    .notify(Level::Error, "The clipboard text is larger than 16 MiB.");
                cx.notify();
                return None;
            }
            return Some(picker::Offered::Text(text));
        }
        self.model.notify(
            Level::Info,
            "Only text and files can be sent from the clipboard.",
        );
        cx.notify();
        None
    }

    /// Asks who to send what the clipboard holds now (taken now: what the
    /// user sees in the picker is what is sent).
    pub(crate) fn pick_clipboard(&mut self, selection: bool, cx: &mut Context<Self>) {
        if let Some(offered) = self.read_clipboard(selection, cx) {
            self.pick(offered, cx);
        }
    }

    /// Sends `offered` to `targets`.
    fn send_offered(
        &mut self,
        offered: picker::Offered,
        targets: Vec<String>,
        cx: &mut Context<Self>,
    ) {
        match offered {
            picker::Offered::Paths(paths) => self.send_paths(&paths, &targets, None, cx),
            picker::Offered::Text(text) => self.send_text(text, targets, cx),
        }
    }

    /// Offers `text` to `targets`, as a private file in the outbox.
    fn send_text(
        &mut self,
        text: zeroize::Zeroizing<String>,
        targets: Vec<String>,
        cx: &mut Context<Self>,
    ) {
        if targets.is_empty() {
            self.ask_for_targets(cx);
            return;
        }
        let state = self.paths.state_dir.clone();
        let now = unix_now();
        cx.spawn(async move |this, cx| {
            let written = cx
                .background_spawn(async move { outbox::write(&state, &text, now) })
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

    /// A request from another launch (a file manager's "Send with todoke",
    /// the global shortcut, a login item): shows the window and, for a
    /// send, asks who to send to. Nothing is sent without that choice.
    pub fn handoff(&mut self, handoff: Handoff, window: &mut Window, cx: &mut Context<Self>) {
        window.activate_window();
        match handoff {
            Handoff::Show => {}
            Handoff::Send { paths } => self.pick(picker::Offered::Paths(paths), cx),
            Handoff::SendClipboard => self.pick_clipboard(false, cx),
        }
        cx.notify();
    }

    /// A command from outside the window (see [`Command`]).
    pub(crate) fn command(
        &mut self,
        command: Command,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) {
        match command {
            Command::Handoff(handoff) => self.handoff(handoff, window, cx),
            Command::SendSelection => {
                window.activate_window();
                self.pick_clipboard(true, cx);
            }
            #[cfg(target_os = "macos")]
            Command::SendText(text) => {
                window.activate_window();
                self.pick(picker::Offered::Text(text), cx);
            }
            Command::Quit => {}
        }
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
        let shown = transfer.clone();
        self.request(
            Request::Accept { transfer, files },
            cx,
            move |app, response, cx| {
                app.rearm(&shown, &response, cx);
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
        let shown = transfer.clone();
        self.request(
            Request::Decline { transfer },
            cx,
            move |app, response, cx| {
                app.rearm(&shown, &response, cx);
                app.model.answer(response);
                app.fetch(&[Fetch::Offers, Fetch::Transfers], cx);
            },
        );
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
                    app.keep_hidden(hidden, cx);
                } else {
                    app.model.answer(response);
                }
            },
        );
    }

    /// Stores the visibility for the next start: `config.json` is read
    /// again first, so changes made meanwhile (by the CLI, say) are kept.
    fn keep_hidden(&mut self, hidden: bool, cx: &mut Context<Self>) {
        let paths = self.paths.clone();
        cx.spawn(async move |this, cx| {
            let stored = cx
                .background_spawn(async move {
                    let mut config = paths.config()?;
                    config.hidden = hidden;
                    prefs::save_config(&paths, &config)?;
                    std::io::Result::Ok(config)
                })
                .await;
            let _ = this.update(cx, |app, cx| {
                match stored {
                    Ok(config) => {
                        let unchanged = app.draft == app.saved;
                        app.saved = Some(config.clone());
                        if unchanged {
                            app.draft = Some(config);
                        } else if let Some(draft) = &mut app.draft {
                            draft.hidden = hidden;
                        }
                    }
                    Err(error) => app.model.notify(
                        Level::Error,
                        format!(
                            "Visibility changed for now, but could not be kept for the next start: {error}"
                        ),
                    ),
                }
                cx.notify();
            });
        })
        .detach();
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
            let _ = this.update(cx, |app, cx| {
                if let Err(error) = saved {
                    app.model.notify(
                        Level::Error,
                        format!("The settings could not be applied: {error}"),
                    );
                }
                app.start(cx);
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
                            .on_click(cx.listener(|this, _, _, cx| this.start(cx))),
                    )
                })
                .test_support()
                .into_any_element(),
        )
    }
}

impl Render for Todoke {
    fn render(&mut self, window: &mut Window, cx: &mut Context<Self>) -> impl IntoElement {
        if self.theme_pending {
            self.theme_pending = false;
            self.apply_theme(window, cx);
        }
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
        // The picker takes focus while it is open (a dialog), unless the
        // receive sheet is over it.
        let picking = self.picker.open.is_some() && self.sheet.transfer.is_none();
        if self.picker.focused != picking {
            self.picker.focused = picking;
            if picking {
                window.focus(&self.picker.focus, cx);
            } else if self.sheet.transfer.is_none() {
                window.focus(&self.focus, cx);
            }
        }
        let banner = self.render_banner(cx);
        let picker = self.render_picker(cx);
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
            .children(picker)
            .children(sheet)
            .child(notices)
    }
}

use gpui_kit::prelude::FluentBuilder as _;

/// What the app is asked to do from outside the window.
pub(crate) enum Command {
    /// From another launch, Finder, the Dock, the tray, or a notification.
    Handoff(Handoff),
    /// The global shortcut: the selection (Linux) or the clipboard.
    SendSelection,
    /// Text from the Services menu (macOS).
    #[cfg(target_os = "macos")]
    SendText(zeroize::Zeroizing<String>),
    /// From the tray.
    Quit,
}

type Commands = tokio::sync::mpsc::UnboundedReceiver<Command>;
pub(crate) type Commander = tokio::sync::mpsc::UnboundedSender<Command>;

/// What the app holds while it runs: dropping any of it undoes it.
struct Held {
    _listening: Listening,
    tray: Option<crate::tray::Tray>,
    #[cfg(target_os = "macos")]
    _services: Option<todoke_sys_macos::services::Services>,
}

/// Opens the window and runs the app until it quits; or, when this
/// profile's window already runs, hands it what this launch asks for.
pub fn run() {
    let launch = std::env::current_dir()
        .map_err(|error| format!("no working directory: {error}"))
        .and_then(|cwd| crate::launch::parse(std::env::args_os().skip(1), &cwd));
    let mut launch = match launch {
        Ok(launch) => launch,
        Err(error) => {
            eprintln!("todoke: {error}");
            std::process::exit(2);
        }
    };
    if launch.send_stdin {
        match crate::launch::read_paths(std::io::stdin().lock()) {
            Ok(paths) => launch.handoff = Handoff::Send { paths },
            Err(error) => {
                eprintln!("todoke: {error}");
                std::process::exit(2);
            }
        }
    }
    // Started by the package's startup task or its Share target (MSIX).
    #[cfg(windows)]
    match todoke_sys_windows::activation::activation() {
        todoke_sys_windows::activation::Activation::Startup => launch.background = true,
        todoke_sys_windows::activation::Activation::Share(paths) if !paths.is_empty() => {
            launch.handoff = Handoff::Send { paths };
        }
        _ => {}
    }
    if launch.version {
        println!("todoke-desktop {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    let paths = match Paths::discover() {
        Ok(paths) => paths,
        Err(error) => {
            eprintln!("todoke: no home directory to keep the profile in: {error}");
            std::process::exit(1);
        }
    };
    let Some((listening, commander, commands)) = listen_or_hand_over(&paths, &launch.handoff)
    else {
        return;
    };
    let application = gpui_kit::application().with_assets(assets::Assets);
    {
        // Finder's Open With and drops on the Dock icon (macOS), and a
        // click on the Dock icon.
        let opened = commander.clone();
        application.on_open_urls(move |urls| {
            let paths: Vec<PathBuf> = urls
                .iter()
                .filter_map(|url| crate::launch::file_url(url))
                .collect();
            if !paths.is_empty() {
                let _ = opened.send(Command::Handoff(Handoff::Send { paths }));
            }
        });
        let reopened = commander.clone();
        application.on_reopen(move |_| {
            let _ = reopened.send(Command::Handoff(Handoff::Show));
        });
    }
    application.run(move |cx: &mut App| {
        gpui_kit::init(cx);
        cx.set_app_identity("org.todoke.todoke", "todoke");
        cx.bind_keys(bindings());
        let notified = commander.clone();
        cx.on_system_notification_response(move |_, _| {
            let _ = notified.send(Command::Handoff(Handoff::Show));
        });
        #[cfg(target_os = "macos")]
        let services = {
            let services = commander.clone();
            objc2::MainThreadMarker::new().map(|mtm| {
                todoke_sys_macos::services::provide(mtm, move |service| {
                    use todoke_sys_macos::services::Service;
                    let _ = services.send(match service {
                        Service::Files(paths) => Command::Handoff(Handoff::Send { paths }),
                        Service::Text(text) => Command::SendText(zeroize::Zeroizing::new(text)),
                    });
                })
            })
        };
        let tray = {
            let commander = commander.clone();
            crate::tray::install(move |action| {
                let _ = commander.send(match action {
                    crate::tray::Action::Open => Command::Handoff(Handoff::Show),
                    crate::tray::Action::SendClipboard => Command::Handoff(Handoff::SendClipboard),
                    crate::tray::Action::Quit => Command::Quit,
                });
            })
        };
        let held = Held {
            _listening: listening,
            tray,
            #[cfg(target_os = "macos")]
            _services: services,
        };
        open_window(paths, launch, held, (commander, commands), cx);
    });
}

/// Appends what `command` asks for to `log` (owner-only), for tests.
fn log_command(log: &std::path::Path, command: &Command) {
    use std::io::Write as _;
    let line = match command {
        Command::Handoff(handoff) => serde_json::to_string(handoff).unwrap_or_default(),
        Command::SendSelection => r#"{"type":"send_selection"}"#.to_owned(),
        #[cfg(target_os = "macos")]
        Command::SendText(_) => r#"{"type":"send_text"}"#.to_owned(),
        Command::Quit => r#"{"type":"quit"}"#.to_owned(),
    };
    let mut options = std::fs::OpenOptions::new();
    options.create(true).append(true);
    // Owner-only, and never through a link someone left in its place.
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options
            .mode(0o600)
            .custom_flags(i32::try_from(rustix::fs::OFlags::NOFOLLOW.bits()).unwrap_or(0));
    }
    if let Ok(mut file) = options.open(log) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            let _ = file.set_permissions(std::fs::Permissions::from_mode(0o600));
        }
        let _ = writeln!(file, "{line}");
    }
}

/// What a window holds so other launches reach it: the instance lock and
/// the listening endpoint.
type Listening = (handoff::InstanceLock, Option<handoff::Listening>);

/// Hands `request` to this profile's running window (`None`: done, or
/// failed with a message), or takes the profile's instance lock and
/// listens for other launches' requests (one window per profile). Only "no
/// window listens" opens a window: a window that failed to take the
/// request is never answered with a second one.
fn listen_or_hand_over(
    paths: &Paths,
    request: &Handoff,
) -> Option<(Listening, Commander, Commands)> {
    match handoff::send(paths, request) {
        Ok(()) => return None,
        Err(error) if handoff::no_window(&error) => {}
        Err(error) => {
            eprintln!("todoke: the window of this profile did not take the request: {error}");
            std::process::exit(1);
        }
    }
    let lock = match handoff::lock(paths) {
        Ok(Some(lock)) => lock,
        // Another launch is opening its window: hand the request to it once
        // it listens.
        Ok(None) => {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(20);
            loop {
                match handoff::send(paths, request) {
                    Ok(()) => return None,
                    Err(error)
                        if handoff::no_window(&error) && std::time::Instant::now() < deadline =>
                    {
                        std::thread::sleep(std::time::Duration::from_millis(100));
                    }
                    Err(error) => {
                        eprintln!(
                            "todoke: another window of this profile does not answer: {error}"
                        );
                        std::process::exit(1);
                    }
                }
            }
        }
        Err(error) => {
            eprintln!("todoke: cannot hold this profile: {error}");
            std::process::exit(1);
        }
    };
    let (commander, commands) = tokio::sync::mpsc::unbounded_channel();
    let listening = {
        let commander = commander.clone();
        handoff::listen(paths, move |handoff| {
            let _ = commander.send(Command::Handoff(handoff));
        })
    };
    let listening = match listening {
        Ok(listening) => Some(listening),
        Err(error) => {
            eprintln!("todoke: other launches cannot reach this window: {error}");
            None
        }
    };
    Some(((lock, listening), commander, commands))
}

fn window_options(background: bool, cx: &App) -> gpui_kit::WindowOptions {
    let bounds = gpui_kit::Bounds::centered(
        None,
        gpui_kit::size(px(size::WINDOW.0), px(size::WINDOW.1)),
        cx,
    );
    gpui_kit::WindowOptions {
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
        show: !background,
        focus: !background,
        ..Default::default()
    }
}

/// Opens the window, which takes the launch's request and then the
/// commands that follow. With a tray item, closing the window keeps the
/// view (and the core it hosts) running, and a command opens it again.
fn open_window(
    paths: Paths,
    launch: crate::launch::Launch,
    held: Held,
    (commander, mut commands): (Commander, Commands),
    cx: &mut App,
) {
    let crate::launch::Launch {
        handoff: request,
        background,
        ..
    } = launch;
    let opened = gpui_kit::open_window(window_options(background, cx), cx, |window, cx| {
        cx.new(|cx| {
            let mut app = Todoke::new(paths, window, cx);
            app.connect_system(commander, cx);
            app.start(cx);
            if background {
                app.in_background();
            } else {
                app.handoff(request, window, cx);
            }
            app
        })
    });
    let (window, view) = match opened {
        Ok(opened) => opened,
        Err(error) => {
            eprintln!("todoke: the window could not open: {error}");
            cx.quit();
            return;
        }
    };
    let stays = held.tray.is_some();
    {
        let view = view.clone();
        cx.on_window_closed(move |cx, _| {
            if !cx.windows().is_empty() {
                return;
            }
            if stays {
                view.update(cx, |app, _| app.closed());
            } else {
                cx.quit();
            }
        })
        .detach();
    }
    // For end-to-end tests of the shell integrations: what each request
    // was (paths, never text), one JSON line each.
    let log = std::env::var_os("TODOKE_HANDOFF_LOG").map(PathBuf::from);
    cx.spawn(async move |cx| {
        let _held = held;
        let mut window = Some(window);
        while let Some(command) = commands.recv().await {
            if let Some(log) = &log {
                log_command(log, &command);
            }
            if matches!(command, Command::Quit) {
                cx.update(|cx| cx.quit());
                break;
            }
            // The window takes the command; if it was closed, a new one.
            let mut command = Some(command);
            if let Some(open) = window {
                let handed = open.update(cx, |_, window, cx| {
                    if let Some(command) = command.take() {
                        view.update(cx, |app, cx| app.command(command, window, cx));
                    }
                });
                if handed.is_err() {
                    window = None;
                }
            }
            if let Some(command) = command {
                let view = view.clone();
                window = cx.update(|cx| {
                    gpui_kit::open_window(window_options(false, cx), cx, |window, cx| {
                        view.update(cx, |app, cx| {
                            app.reopened(window, cx);
                            app.command(command, window, cx);
                        });
                        view
                    })
                    .ok()
                    .map(|(window, _)| window)
                });
            }
        }
    })
    .detach();
}
