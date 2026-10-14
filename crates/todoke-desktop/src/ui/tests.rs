//! UI tests against a mock core: every flow, keyboard navigation, and the
//! accessibility tree, in a headless window.

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use gpui_kit::AppContext as _;
use gpui_kit::component::{Theme, ThemeMode};
use gpui_kit::test::TestWindowExt as _;
use gpui_kit::{
    ClipboardItem, Entity, ExternalPaths, FileDropEvent, TestAppContext, VisualTestContext,
};
use todoke_core::api::{Event, Request, Response, StatusInfo, TransferInfo, TransferState, Way};
use todoke_core::config::{CoreConfig, RelayConfig};
use todoke_daemon::Paths;

use super::fixtures::{AWAY, LAN, NEAR, RELAYED, offer, script};
use super::{Page, PairTab, Todoke, bindings};
use crate::backend::mock::Mock;
use crate::model::{Connection, Pairing};
use crate::prefs;
use crate::tokens;

/// A scratch home, removed afterwards.
pub(super) struct Home(pub(super) PathBuf);

impl Home {
    pub(super) fn new(name: &str) -> Self {
        static NEXT: AtomicU32 = AtomicU32::new(0);
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_nanos());
        let n = NEXT.fetch_add(1, Ordering::Relaxed);
        Self(std::env::temp_dir().join(format!("todoke-ui-{name}-{nanos}-{n}")))
    }
}

impl Drop for Home {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The app in a window over `mock`, with everything fetched.
fn open<'a>(
    cx: &'a mut TestAppContext,
    mock: &Arc<Mock>,
    home: &Home,
) -> (Entity<Todoke>, &'a mut VisualTestContext) {
    cx.update(|cx| {
        gpui_kit::init(cx);
        cx.bind_keys(bindings());
        tokens::set_mode(ThemeMode::Light, cx);
    });
    let paths = Paths::under(&home.0);
    let backend: Arc<dyn crate::backend::Backend> = mock.clone();
    // Under a Root, as in the app: it owns Tab navigation.
    let mut built = None;
    let (_, cx) = cx.add_window_view(|window, cx| {
        let view = cx.new(|cx| {
            let mut app = Todoke::new(paths, window, cx);
            app.attach(backend, Connection::Hosted, cx);
            app
        });
        built = Some(view.clone());
        gpui_kit::base::Root::new(view, window, cx)
    });
    let Some(view) = built else {
        unreachable!("the window was built");
    };
    // Tall enough that every settings section is on screen.
    cx.simulate_resize(gpui_kit::size(gpui_kit::px(1040.0), gpui_kit::px(3200.0)));
    cx.run_until_parked();
    (view, cx)
}

fn show(view: &Entity<Todoke>, cx: &mut VisualTestContext, page: Page) {
    view.update_in(cx, |app, window, cx| app.show(page, window, cx));
    cx.run_until_parked();
}

fn click(cx: &mut VisualTestContext, id: &'static str) {
    cx.update(|window, cx| window.click(id, cx));
    cx.run_until_parked();
}

/// Clicks the `index`th item of the group `group` (radios are named by
/// their position).
fn click_in(cx: &mut VisualTestContext, group: &'static str, index: usize) {
    cx.update(|window, cx| window.within(group).click(index, cx));
    cx.run_until_parked();
}

fn actions(mock: &Mock) -> Vec<Request> {
    mock.actions()
}

/// Drops `paths` on the element `id`, as the platform does.
fn drop_on(cx: &mut VisualTestContext, id: &'static str, paths: Vec<PathBuf>) {
    let position = cx.update(|window, _| window.find(id).bounds().center());
    cx.simulate_event(FileDropEvent::Entered {
        position,
        paths: ExternalPaths(paths.into()),
    });
    cx.simulate_event(FileDropEvent::Pending { position });
    cx.simulate_event(FileDropEvent::Submit { position });
    cx.run_until_parked();
}

#[gpui_kit::test]
fn home_shows_contacts_by_proximity(cx: &mut TestAppContext) {
    let home = Home::new("home");
    let mock = Arc::new(Mock::new(script()));
    let (view, cx) = open(cx, &mock, &home);
    let labels: Vec<String> = cx.update(|window, _| {
        [LAN, NEAR, RELAYED, AWAY]
            .iter()
            .map(|device| {
                window
                    .find(gpui_kit::ElementId::Name(
                        format!("contact-{}", &device[..16]).into(),
                    ))
                    .label()
                    .unwrap_or_default()
                    .to_owned()
            })
            .collect()
    });
    assert!(labels[0].contains("Nearby"), "{}", labels[0]);
    assert!(labels[1].contains("Nearby"), "{}", labels[1]);
    assert!(labels[2].contains("Through relay"), "{}", labels[2]);
    assert!(labels[3].contains("Offline"), "{}", labels[3]);
    assert!(labels[0].starts_with("Device A1B2 C3D4"), "{}", labels[0]);
    view.read_with(cx, |app, _| {
        assert_eq!(app.model.contacts.len(), 4);
        assert_eq!(app.model.history.len(), 2);
    });
}

#[gpui_kit::test]
fn dropping_files_sends_to_every_selected_contact(cx: &mut TestAppContext) {
    let home = Home::new("drop");
    let mock = Arc::new(Mock::new(script()));
    let (view, cx) = open(cx, &mock, &home);
    // Nothing selected among several contacts: the app asks first.
    drop_on(cx, "drop-zone", vec![PathBuf::from("/tmp/a.txt")]);
    assert_eq!(actions(&mock).len(), 0);
    view.read_with(cx, |app, _| {
        assert!(
            app.model
                .notices
                .iter()
                .any(|n| n.text.contains("Select who"))
        );
    });
    cx.update(|window, cx| {
        window.click(
            gpui_kit::ElementId::Name(format!("contact-{}", &LAN[..16]).into()),
            cx,
        );
        window.click(
            gpui_kit::ElementId::Name(format!("contact-{}", &AWAY[..16]).into()),
            cx,
        );
    });
    cx.run_until_parked();
    let checked = cx.update(|window, _| {
        window
            .find(gpui_kit::ElementId::Name(
                format!("contact-{}", &LAN[..16]).into(),
            ))
            .label()
            .unwrap_or_default()
            .contains("selected")
    });
    assert!(checked);
    let files = vec![PathBuf::from("/tmp/a.txt"), PathBuf::from("/tmp/folder")];
    drop_on(cx, "drop-zone", files.clone());
    let sent: Vec<(String, Vec<PathBuf>)> = actions(&mock)
        .into_iter()
        .filter_map(|request| match request {
            Request::Send { contact, paths } => Some((contact, paths)),
            _ => None,
        })
        .collect();
    let mut contacts: Vec<&str> = sent.iter().map(|(c, _)| c.as_str()).collect();
    contacts.sort_unstable();
    assert_eq!(contacts, [LAN, AWAY]);
    assert!(sent.iter().all(|(_, paths)| *paths == files));
}

#[gpui_kit::test]
fn dropping_on_a_contact_sends_to_it_alone(cx: &mut TestAppContext) {
    let home = Home::new("tile");
    let mock = Arc::new(Mock::new(script()));
    let (_, cx) = open(cx, &mock, &home);
    let id: &'static str = Box::leak(format!("contact-{}", &RELAYED[..16]).into_boxed_str());
    drop_on(cx, id, vec![PathBuf::from("/tmp/b.bin")]);
    assert_eq!(
        actions(&mock),
        [Request::Send {
            contact: RELAYED.into(),
            paths: vec![PathBuf::from("/tmp/b.bin")],
        }]
    );
}

#[gpui_kit::test]
fn clipboard_text_is_sent_as_a_private_file(cx: &mut TestAppContext) {
    let home = Home::new("clipboard");
    let mock = Arc::new(Mock::new(script()));
    let (view, cx) = open(cx, &mock, &home);
    view.update(cx, |app, cx| {
        app.model.toggle(NEAR);
        cx.notify();
    });
    cx.write_to_clipboard(ClipboardItem::new_string("meet at 6".into()));
    cx.dispatch_action(super::SendClipboard);
    cx.run_until_parked();
    let sent = actions(&mock);
    assert_eq!(sent.len(), 1, "{sent:?}");
    let (contact, file) = match &sent[0] {
        Request::Send { contact, paths } if paths.len() == 1 => (contact.clone(), paths[0].clone()),
        other => (format!("{other:?}"), PathBuf::new()),
    };
    assert_eq!(contact, NEAR);
    let file = &file;
    assert!(
        file.starts_with(home.0.join("state").join("outbox")),
        "{}",
        file.display()
    );
    assert_eq!(
        std::fs::read_to_string(file).unwrap_or_default(),
        "meet at 6"
    );
    // Once its transfer is over, the file goes.
    let transfer = format!("{:032x}", 0);
    view.update(cx, |app, cx| {
        app.model.transfers.insert(
            transfer.clone(),
            TransferInfo {
                transfer: transfer.clone(),
                peer: NEAR.into(),
                way: Way::Outgoing,
                state: TransferState::Offered,
                detail: None,
                bytes_done: 0,
                bytes_total: 9,
            },
        );
        app.on_event(
            Event::Delivered {
                transfer: transfer.clone(),
            },
            cx,
        );
    });
    cx.run_until_parked();
    assert!(!file.exists());
}

#[gpui_kit::test]
fn an_offer_is_accepted_only_after_the_delay(cx: &mut TestAppContext) {
    let home = Home::new("accept");
    let mock = Arc::new(Mock::new(script()));
    let (view, cx) = open(cx, &mock, &home);
    mock.emit(Event::OfferReceived(offer(
        "t1",
        &[
            ("beach.jpg", "image/jpeg", 2048),
            ("notes.pdf", "application/pdf", 512),
        ],
    )));
    cx.run_until_parked();
    let label = cx.update(|window, _| {
        window
            .find("receive-sheet")
            .label()
            .unwrap_or_default()
            .to_owned()
    });
    assert!(
        label.contains("Device A1B2 C3D4 wants to send 2 files"),
        "{label}"
    );
    assert!(label.contains("Verified contact"), "{label}");
    assert!(label.contains("1 image, 1 document"), "{label}");
    view.read_with(cx, |app, _| assert!(!app.sheet.armed));
    // A click before the delay does nothing.
    click(cx, "accept");
    cx.dispatch_action(super::AcceptAll);
    assert_eq!(actions(&mock).len(), 0);
    cx.executor().advance_clock(tokens::DECISION_DELAY);
    cx.run_until_parked();
    view.read_with(cx, |app, _| assert!(app.sheet.armed));
    click(cx, "accept");
    assert_eq!(
        actions(&mock),
        [Request::Accept {
            transfer: "t1".into(),
            files: None,
        }]
    );
    view.read_with(cx, |app, _| assert!(!app.sheet.armed));
}

#[gpui_kit::test]
fn chosen_files_are_the_only_ones_accepted(cx: &mut TestAppContext) {
    let home = Home::new("choose");
    let mock = Arc::new(Mock::new(script()));
    let (_, cx) = open(cx, &mock, &home);
    mock.emit(Event::OfferReceived(offer(
        "t2",
        &[
            ("a.txt", "text/plain", 1),
            ("b.txt", "text/plain", 2),
            ("c.txt", "text/plain", 3),
        ],
    )));
    cx.run_until_parked();
    cx.executor().advance_clock(tokens::DECISION_DELAY);
    cx.run_until_parked();
    click(cx, "choose");
    // Nothing chosen: accepting asks for a choice instead.
    click(cx, "accept");
    assert_eq!(actions(&mock).len(), 0);
    click(cx, "choose-2");
    click(cx, "choose-3");
    click(cx, "accept");
    assert_eq!(
        actions(&mock),
        [Request::Accept {
            transfer: "t2".into(),
            files: Some(vec![2, 3]),
        }]
    );
}

#[gpui_kit::test]
fn an_offer_can_be_declined_or_hidden(cx: &mut TestAppContext) {
    let home = Home::new("decline");
    let mock = Arc::new(Mock::new(script()));
    let (view, cx) = open(cx, &mock, &home);
    mock.emit(Event::OfferReceived(offer("t3", &[("x", "text/plain", 1)])));
    mock.emit(Event::OfferReceived(offer("t4", &[("y", "text/plain", 1)])));
    cx.run_until_parked();
    cx.executor().advance_clock(tokens::DECISION_DELAY);
    cx.run_until_parked();
    // Escape hides the first; the next one shows, disarmed again.
    cx.update(|window, cx| window.press("escape", cx));
    cx.run_until_parked();
    view.read_with(cx, |app, _| {
        assert_eq!(app.sheet.transfer.as_deref(), Some("t4"));
        assert!(!app.sheet.armed);
    });
    cx.executor().advance_clock(tokens::DECISION_DELAY);
    cx.run_until_parked();
    click(cx, "decline");
    assert_eq!(
        actions(&mock),
        [Request::Decline {
            transfer: "t4".into()
        }]
    );
}

#[gpui_kit::test]
fn hostile_names_are_escaped_and_programs_flagged(cx: &mut TestAppContext) {
    let home = Home::new("hostile");
    let mock = Arc::new(Mock::new(script()));
    let (_, cx) = open(cx, &mock, &home);
    mock.emit(Event::OfferReceived(offer(
        "t5",
        &[("invoice\u{202e}fdp.exe", "application/pdf", 10)],
    )));
    cx.run_until_parked();
    let (sheet, warning) = cx.update(|window, _| {
        (
            window
                .find("receive-sheet")
                .label()
                .unwrap_or_default()
                .to_owned(),
            window.find("program-warning").visible(),
        )
    });
    assert!(sheet.contains("1 program or script"), "{sheet}");
    assert!(warning);
    let json = cx
        .update(|window, _| window.debug_a11y_tree_json())
        .unwrap_or_default();
    assert!(
        !json.contains('\u{202e}'),
        "a raw bidi override reached the screen"
    );
}

#[gpui_kit::test]
fn transfers_show_progress_speed_time_left_and_route(cx: &mut TestAppContext) {
    let home = Home::new("progress");
    let mock = Arc::new(Mock::new(script()));
    let (view, cx) = open(cx, &mock, &home);
    view.update(cx, |app, cx| {
        app.model.transfers.insert(
            "t6".into(),
            TransferInfo {
                transfer: "t6".into(),
                peer: LAN.into(),
                way: Way::Outgoing,
                state: TransferState::Accepted,
                detail: None,
                bytes_done: 0,
                bytes_total: 4 << 20,
            },
        );
        cx.notify();
    });
    mock.emit(Event::Progress {
        transfer: "t6".into(),
        way: Way::Outgoing,
        done: 1 << 20,
        total: 4 << 20,
        bytes_per_second: 1 << 20,
    });
    cx.run_until_parked();
    show(&view, cx, Page::Transfers);
    let (row, progress) = cx.update(|window, _| {
        (
            window
                .find("transfer-t6")
                .label()
                .unwrap_or_default()
                .to_owned(),
            window
                .find("progress-t6")
                .label()
                .unwrap_or_default()
                .to_owned(),
        )
    });
    assert!(row.contains("1.0 MiB of 4.0 MiB"), "{row}");
    assert!(row.contains("1.0 MiB/s"), "{row}");
    assert!(row.contains("3 s left"), "{row}");
    assert!(row.contains("Direct (LAN)"), "{row}");
    assert_eq!(progress, "25 percent");
    click(cx, "cancel-t6");
    assert_eq!(
        actions(&mock),
        [Request::Cancel {
            transfer: "t6".into()
        }]
    );
}

#[gpui_kit::test]
fn pairing_by_qr_code_and_by_code(cx: &mut TestAppContext) {
    let home = Home::new("pair");
    let mock = Arc::new(Mock::new(script()));
    let (view, cx) = open(cx, &mock, &home);
    show(&view, cx, Page::Pairing);
    click(cx, "show-qr-button");
    view.read_with(cx, |app, _| {
        assert!(matches!(app.model.pairing, Pairing::Qr { .. }));
    });
    let qr = cx.update(|window, _| {
        window
            .find("qr-code")
            .label()
            .unwrap_or_default()
            .to_owned()
    });
    // The secret is drawn, never spoken.
    assert!(!qr.contains("TODOKE:"), "{qr}");
    click(cx, "stop-pairing");
    click(cx, "tab-show-code");
    click(cx, "show-code-button");
    let code = cx.update(|window, _| {
        window
            .find("pair-code")
            .label()
            .unwrap_or_default()
            .to_owned()
    });
    assert!(code.contains("0 1 2 3 4 5 6 7 8 9"), "{code}");
    // The Paired event ends the offer.
    mock.emit(Event::Paired {
        contact: NEAR.into(),
    });
    cx.run_until_parked();
    view.read_with(cx, |app, _| assert_eq!(app.model.pairing, Pairing::Idle));
    // Entering a code: the only nearby stranger is chosen.
    click(cx, "tab-enter-code");
    view.read_with(cx, |app, _| assert_eq!(app.pair_tab, PairTab::EnterCode));
    cx.update(|window, cx| window.click("code-input", cx));
    cx.update(|window, cx| window.input("01234 56789", cx));
    click(cx, "pair-code");
    let requests = actions(&mock);
    assert_eq!(
        requests,
        [
            Request::PairShowQr,
            Request::StopPairing,
            Request::PairShowCode,
            Request::PairEnterCode {
                code: "0123456789".into(),
                stranger: "5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a5a".into(),
            },
        ]
    );
    // Pasted QR text.
    click(cx, "tab-paste-qr");
    cx.update(|window, cx| window.click("qr-input", cx));
    cx.update(|window, cx| window.input("TODOKE:PASTED", cx));
    click(cx, "pair-qr");
    assert_eq!(
        actions(&mock).last(),
        Some(&Request::PairScanQr {
            text: "TODOKE:PASTED".into()
        })
    );
}

#[gpui_kit::test]
fn history_is_searchable_and_cleared_on_confirmation(cx: &mut TestAppContext) {
    let home = Home::new("history");
    let mock = Arc::new(Mock::new(script()));
    let (view, cx) = open(cx, &mock, &home);
    show(&view, cx, Page::History);
    let count = |cx: &mut VisualTestContext| {
        cx.update(|window, _| {
            window
                .find("history-list")
                .label()
                .unwrap_or_default()
                .to_owned()
        })
    };
    assert_eq!(count(cx), "2 transfers found");
    let row = cx.update(|window, _| {
        window
            .find(gpui_kit::ElementId::Name(
                format!("history-{}", "11".repeat(16)).into(),
            ))
            .label()
            .unwrap_or_default()
            .to_owned()
    });
    assert!(row.contains("signed receipt"), "{row}");
    cx.update(|window, cx| window.click("history-search", cx));
    cx.update(|window, cx| window.input("quarterly", cx));
    cx.run_until_parked();
    assert_eq!(count(cx), "1 transfer found");
    click(cx, "clear-history");
    assert_eq!(actions(&mock).len(), 0);
    click(cx, "clear-history");
    assert_eq!(actions(&mock), [Request::ClearHistory]);
}

#[gpui_kit::test]
fn settings_hide_this_device_and_stage_changes(cx: &mut TestAppContext) {
    let home = Home::new("settings");
    let mock = Arc::new(Mock::new(script()));
    let (view, cx) = open(cx, &mock, &home);
    show(&view, cx, Page::Settings);
    click_in(cx, "visibility-choice", 2);
    assert_eq!(actions(&mock), [Request::SetHidden { hidden: true }]);
    view.read_with(cx, |app, _| {
        assert_eq!(app.saved.as_ref().map(|c| c.hidden), Some(true));
    });
    // A retention change is staged until applied.
    click_in(cx, "retention", 1);
    assert!(cx.update(|window, _| window.try_find("apply-bar").is_some()));
    view.read_with(cx, |app, _| {
        assert_eq!(app.draft.as_ref().map(|c| c.history_days), Some(7));
        assert_eq!(app.saved.as_ref().map(|c| c.history_days), Some(30));
    });
    click(cx, "discard");
    assert!(cx.update(|window, _| window.try_find("apply-bar").is_none()));
    // Everyone for five minutes is a pairing code.
    click_in(cx, "visibility-choice", 1);
    view.read_with(cx, |app, _| {
        assert_eq!(app.page, Page::Pairing);
        assert_eq!(app.pair_tab, PairTab::ShowCode);
        assert!(matches!(app.model.pairing, Pairing::Code { .. }));
    });
}

#[gpui_kit::test]
fn the_theme_follows_the_choice(cx: &mut TestAppContext) {
    let home = Home::new("theme");
    let mock = Arc::new(Mock::new(script()));
    let (view, cx) = open(cx, &mock, &home);
    show(&view, cx, Page::Settings);
    click_in(cx, "theme", 2);
    assert!(cx.update(|_, cx| Theme::global(cx).mode.is_dark()));
    let background = cx.update(|_, cx| Theme::global(cx).background);
    assert_eq!(background, tokens::color(tokens::DARK.background));
    click_in(cx, "theme", 1);
    assert!(cx.update(|_, cx| !Theme::global(cx).mode.is_dark()));
}

#[gpui_kit::test]
fn every_page_has_a_key_binding(cx: &mut TestAppContext) {
    let home = Home::new("keys");
    let mock = Arc::new(Mock::new(script()));
    let (view, cx) = open(cx, &mock, &home);
    let m = if cfg!(target_os = "macos") {
        "cmd"
    } else {
        "ctrl"
    };
    for (digit, page) in [
        ('2', Page::Transfers),
        ('3', Page::Pairing),
        ('4', Page::History),
        ('5', Page::Settings),
        ('1', Page::Home),
    ] {
        cx.update(|window, cx| window.press(&format!("{m}-{digit}"), cx));
        cx.run_until_parked();
        view.read_with(cx, |app, _| assert_eq!(app.page, page, "{m}-{digit}"));
    }
    cx.update(|window, cx| window.press(&format!("{m}-f"), cx));
    cx.run_until_parked();
    view.read_with(cx, |app, _| assert_eq!(app.page, Page::History));
}

#[gpui_kit::test]
fn missed_events_fetch_everything_again(cx: &mut TestAppContext) {
    let home = Home::new("missed");
    let mock = Arc::new(Mock::new(script()));
    let (_, cx) = open(cx, &mock, &home);
    let before = mock.requests().len();
    mock.emit(Event::Missed { events: 9 });
    cx.run_until_parked();
    let after: Vec<Request> = mock.requests().split_off(before);
    for wanted in [
        Request::Status,
        Request::Contacts,
        Request::Transfers,
        Request::Offers,
        Request::History,
    ] {
        assert!(after.contains(&wanted), "{wanted:?} not fetched");
    }
}

#[gpui_kit::test]
fn a_disabled_build_says_so(cx: &mut TestAppContext) {
    let home = Home::new("disabled");
    cx.update(|cx| {
        gpui_kit::init(cx);
        tokens::set_mode(ThemeMode::Light, cx);
    });
    let paths = Paths::under(&home.0);
    let (view, cx) = cx.add_window_view(move |window, cx| {
        let mut app = Todoke::new(paths, window, cx);
        app.model.connection = Connection::Disabled;
        app
    });
    cx.run_until_parked();
    let banner =
        cx.update(|window, _| window.find("banner").label().unwrap_or_default().to_owned());
    assert!(
        banner.contains("Sessions are disabled in this build"),
        "{banner}"
    );
    // Nothing is sent without a core.
    view.update(cx, |app, cx| {
        app.send_paths(&["/tmp/x".into()], &[LAN.into()], None, cx);
    });
    view.read_with(cx, |app, _| {
        assert!(
            app.model
                .notices
                .iter()
                .any(|n| n.text.contains("not running"))
        );
    });
}

/// Every node a screen reader can act on has a label, on every page and
/// with the receive sheet open.
#[gpui_kit::test]
fn every_control_is_labelled_for_screen_readers(cx: &mut TestAppContext) {
    let home = Home::new("a11y");
    let mock = Arc::new(Mock::new(script()));
    let (view, cx) = open(cx, &mock, &home);
    let mut checked = 0;
    for page in [
        Page::Home,
        Page::Transfers,
        Page::Pairing,
        Page::History,
        Page::Settings,
    ] {
        show(&view, cx, page);
        checked += unlabelled(cx, &format!("{page:?}"));
    }
    mock.emit(Event::OfferReceived(offer(
        "t7",
        &[("a.txt", "text/plain", 1)],
    )));
    cx.run_until_parked();
    checked += unlabelled(cx, "sheet");
    assert!(checked > 40, "only {checked} controls found");
}

/// Counts the controls registered on screen and panics on one without a
/// label: what a screen reader would announce as an unnamed control.
fn unlabelled(cx: &mut VisualTestContext, page: &str) -> usize {
    use gpui_kit::Role;
    cx.update(gpui_kit::test::TestWindowExt::render_frame);
    let snapshots = cx.update(|window, _| gpui_kit::base::test_support::snapshots(window));
    let mut controls = 0;
    for snapshot in snapshots {
        let control = matches!(
            snapshot.role(),
            Some(
                Role::Button
                    | Role::CheckBox
                    | Role::RadioButton
                    | Role::Tab
                    | Role::TextInput
                    | Role::Switch
                    | Role::Link
                    | Role::ComboBox
            )
        );
        if !control || !snapshot.visible() {
            continue;
        }
        controls += 1;
        let named = snapshot
            .label()
            .or_else(|| snapshot.value())
            .is_some_and(|text| !text.trim().is_empty());
        assert!(named, "{page}: unlabelled control at {:?}", snapshot.path());
    }
    controls
}

/// Contacts are reached with Tab and chosen with Space, files offered with
/// Return on the drop zone: no pointer needed.
#[gpui_kit::test]
fn contacts_are_chosen_from_the_keyboard(cx: &mut TestAppContext) {
    let home = Home::new("keyboard");
    let mock = Arc::new(Mock::new(script()));
    let (view, cx) = open(cx, &mock, &home);
    let tile = gpui_kit::ElementId::Name(format!("contact-{}", &LAN[..16]).into());
    let mut reached = false;
    for _ in 0..40 {
        cx.update(|window, cx| window.press("tab", cx));
        cx.run_until_parked();
        if cx.update(|window, _| window.find(tile.clone()).focused()) == Some(true) {
            reached = true;
            break;
        }
    }
    assert!(reached, "Tab never reached the first contact");
    cx.update(|window, cx| window.press("space", cx));
    cx.run_until_parked();
    view.read_with(cx, |app, _| {
        assert!(app.model.selected.contains(LAN), "Space did not select");
    });
    cx.update(|window, cx| window.press("space", cx));
    cx.run_until_parked();
    view.read_with(cx, |app, _| assert!(app.model.selected.is_empty()));
}

/// An arming timer started for one offer never arms the next: hiding
/// offer A just before its delay ends leaves B disarmed for B's own delay.
#[gpui_kit::test]
fn a_stale_timer_never_arms_the_next_offer(cx: &mut TestAppContext) {
    let home = Home::new("stale");
    let mock = Arc::new(Mock::new(script()));
    let (view, cx) = open(cx, &mock, &home);
    mock.emit(Event::OfferReceived(offer("ta", &[("a", "text/plain", 1)])));
    mock.emit(Event::OfferReceived(offer("tb", &[("b", "text/plain", 1)])));
    cx.run_until_parked();
    let early = tokens::DECISION_DELAY.saturating_sub(core::time::Duration::from_millis(50));
    cx.executor().advance_clock(early);
    cx.run_until_parked();
    cx.update(|window, cx| window.press("escape", cx));
    cx.run_until_parked();
    view.read_with(cx, |app, _| {
        assert_eq!(app.sheet.transfer.as_deref(), Some("tb"));
    });
    // A's timer fires now; B must stay disarmed.
    cx.executor()
        .advance_clock(core::time::Duration::from_millis(100));
    cx.run_until_parked();
    view.read_with(cx, |app, _| assert!(!app.sheet.armed));
    click(cx, "accept");
    assert_eq!(actions(&mock).len(), 0);
    cx.executor().advance_clock(tokens::DECISION_DELAY);
    cx.run_until_parked();
    view.read_with(cx, |app, _| assert!(app.sheet.armed));
}

/// The command key with Return accepts only when pressed afresh: a key held
/// since before the sheet appeared repeats into nothing.
#[gpui_kit::test]
fn a_held_key_never_accepts(cx: &mut TestAppContext) {
    let home = Home::new("held");
    let mock = Arc::new(Mock::new(script()));
    let (_, cx) = open(cx, &mock, &home);
    mock.emit(Event::OfferReceived(offer("th", &[("a", "text/plain", 1)])));
    cx.run_until_parked();
    cx.executor().advance_clock(tokens::DECISION_DELAY);
    cx.run_until_parked();
    let m = if cfg!(target_os = "macos") {
        "cmd"
    } else {
        "ctrl"
    };
    let Ok(keystroke) = gpui_kit::Keystroke::parse(&format!("{m}-enter")) else {
        unreachable!("a valid keystroke");
    };
    cx.simulate_event(gpui_kit::KeyDownEvent {
        keystroke: keystroke.clone(),
        is_held: true,
        prefer_character_input: false,
    });
    cx.run_until_parked();
    assert_eq!(actions(&mock).len(), 0);
    cx.update(|window, cx| window.press(&format!("{m}-enter"), cx));
    cx.run_until_parked();
    assert_eq!(
        actions(&mock),
        [Request::Accept {
            transfer: "th".into(),
            files: None,
        }]
    );
}

/// A decision the core refuses leaves the offer decidable again.
#[gpui_kit::test]
fn a_refused_decision_rearms_the_sheet(cx: &mut TestAppContext) {
    let home = Home::new("refused");
    let base = script();
    let mock = Arc::new(Mock::new(move |request| match request {
        Request::Accept { .. } => todoke_core::api::Response::error(
            todoke_core::api::ErrorCode::Unreachable,
            "the sender is not connected",
        ),
        // The core still holds the offer it refused to accept.
        Request::Offers => {
            todoke_core::api::Response::Offers(vec![offer("tr", &[("a", "text/plain", 1)])])
        }
        other => base(other),
    }));
    let (view, cx) = open(cx, &mock, &home);
    cx.run_until_parked();
    cx.executor().advance_clock(tokens::DECISION_DELAY);
    cx.run_until_parked();
    click(cx, "accept");
    view.read_with(cx, |app, _| {
        assert!(!app.sheet.armed);
        assert_eq!(app.sheet.transfer.as_deref(), Some("tr"));
    });
    cx.executor().advance_clock(tokens::DECISION_DELAY);
    cx.run_until_parked();
    view.read_with(cx, |app, _| assert!(app.sheet.armed));
}

/// Clipboard text that was offered to no one does not stay on disk, and a
/// file sent to two contacts stays until both transfers are over.
#[gpui_kit::test]
fn clipboard_files_go_when_no_transfer_needs_them(cx: &mut TestAppContext) {
    let home = Home::new("outbox");
    let base = script();
    let refuse = Arc::new(std::sync::atomic::AtomicBool::new(true));
    let refusing = Arc::clone(&refuse);
    let mock = Arc::new(Mock::new(move |request| match request {
        Request::Send { .. } if refusing.load(Ordering::Relaxed) => {
            todoke_core::api::Response::error(todoke_core::api::ErrorCode::Unreachable, "no")
        }
        other => base(other),
    }));
    let (view, cx) = open(cx, &mock, &home);
    let outbox = home.0.join("state").join("outbox");
    let files = || -> usize {
        std::fs::read_dir(home.0.join("state").join("outbox")).map_or(0, Iterator::count)
    };
    view.update(cx, |app, cx| {
        app.model.toggle(NEAR);
        cx.notify();
    });
    cx.write_to_clipboard(ClipboardItem::new_string("secret".into()));
    cx.dispatch_action(super::SendClipboard);
    cx.run_until_parked();
    assert!(outbox.exists());
    assert_eq!(files(), 0, "a refused offer's file stayed");
    // Two contacts this time; the offers succeed.
    refuse.store(false, Ordering::Relaxed);
    view.update(cx, |app, cx| {
        app.model.toggle(LAN);
        cx.notify();
    });
    cx.dispatch_action(super::SendClipboard);
    cx.run_until_parked();
    assert_eq!(files(), 1);
    let ids: Vec<String> = view.read_with(cx, |app, _| app.outbox.keys().cloned().collect());
    assert_eq!(ids.len(), 2);
    let finish = |id: &str, cx: &mut VisualTestContext| {
        let id = id.to_owned();
        view.update(cx, |app, cx| {
            app.model.transfers.insert(
                id.clone(),
                TransferInfo {
                    transfer: id.clone(),
                    peer: NEAR.into(),
                    way: Way::Outgoing,
                    state: TransferState::Offered,
                    detail: None,
                    bytes_done: 0,
                    bytes_total: 6,
                },
            );
            app.on_event(Event::Delivered { transfer: id }, cx);
        });
        cx.run_until_parked();
    };
    finish(&ids[0], cx);
    assert_eq!(files(), 1, "removed while the other transfer needs it");
    finish(&ids[1], cx);
    assert_eq!(files(), 0);
}

/// A core stopped from outside is let go (so it stops for real), and
/// starting again does not reuse it.
#[gpui_kit::test]
fn a_stopped_core_is_let_go(cx: &mut TestAppContext) {
    let home = Home::new("stopped");
    let mock = Arc::new(Mock::new(script()));
    let (view, cx) = open(cx, &mock, &home);
    mock.stop();
    cx.executor().advance_clock(tokens::REFRESH);
    cx.run_until_parked();
    view.read_with(cx, |app, _| {
        assert_eq!(app.model.connection, Connection::Stopped);
        assert!(app.backend.is_none());
    });
    // Only this test's handle is left: the app dropped its own.
    assert_eq!(Arc::strong_count(&mock), 1);
    let banner =
        cx.update(|window, _| window.find("banner").label().unwrap_or_default().to_owned());
    assert!(banner.contains("stopped"), "{banner}");
}

/// Writes `config.json` under `home` (LAN off, so no test opens a
/// listener), as `edit` leaves it.
fn write_config(home: &Home, edit: impl FnOnce(&mut CoreConfig)) -> Paths {
    let paths = Paths::under(&home.0);
    let mut config = CoreConfig::new(paths.state_dir.clone(), paths.downloads_dir.clone());
    // Tests never write to the developer's keyring.
    config.key_storage = todoke_core::config::KeyStorage::File;
    config.lan.enabled = false;
    edit(&mut config);
    if std::fs::create_dir_all(&home.0).is_err()
        || std::fs::write(
            &paths.config_file,
            serde_json::to_vec(&config).unwrap_or_default(),
        )
        .is_err()
    {
        unreachable!("the scratch home is writable");
    }
    paths
}

fn relay(name: &str, address: &str) -> RelayConfig {
    RelayConfig {
        name: name.into(),
        address: address.into(),
        server_name: "relay.example".into(),
        pin: None,
    }
}

/// The names of the relays in the draft.
fn draft_relays(view: &Entity<Todoke>, cx: &mut VisualTestContext) -> Vec<String> {
    view.read_with(cx, |app, _| {
        app.draft
            .as_ref()
            .map(|draft| draft.relays.iter().map(|r| r.name.clone()).collect())
            .unwrap_or_default()
    })
}

/// Local network, retention, the presence period, and the relay list are
/// edited as a draft: the apply bar shows while it differs from the saved
/// configuration, goes when an edit is undone or discarded, and nothing is
/// sent to the core or written to disk meanwhile.
#[gpui_kit::test]
fn settings_stage_connection_and_retention_edits(cx: &mut TestAppContext) {
    let home = Home::new("staging");
    let paths = write_config(&home, |config| {
        config.lan.enabled = true;
        config.relays = vec![
            relay("eu", "eu.example:4433"),
            relay("us", "us.example:4433"),
        ];
    });
    let on_disk = std::fs::read(&paths.config_file).unwrap_or_default();
    let mock = Arc::new(Mock::new(script()));
    let (view, cx) = open(cx, &mock, &home);
    show(&view, cx, Page::Settings);
    let bar =
        |cx: &mut VisualTestContext| cx.update(|window, _| window.try_find("apply-bar").is_some());
    assert!(!bar(cx));
    // Switch the local network off, and back on: no difference remains.
    click(cx, "lan");
    view.read_with(cx, |app, _| {
        assert_eq!(app.draft.as_ref().map(|c| c.lan.enabled), Some(false));
        assert_eq!(app.saved.as_ref().map(|c| c.lan.enabled), Some(true));
    });
    assert!(bar(cx));
    click(cx, "lan");
    assert!(!bar(cx), "undoing the edit leaves nothing to apply");
    // Presence (the 3600-second choice is the fourth) and retention (Off).
    click_in(cx, "presence", 3);
    click_in(cx, "retention", 0);
    view.read_with(cx, |app, _| {
        let draft = app.draft.as_ref();
        assert_eq!(draft.map(|c| c.relay_presence_seconds), Some(3600));
        assert_eq!(draft.map(|c| c.history_days), Some(0));
        assert_eq!(
            app.saved.as_ref().map(|c| c.relay_presence_seconds),
            Some(300)
        );
    });
    assert!(bar(cx));
    // A relay removed from the draft goes from the list.
    // Rows are test elements; the list itself is not.
    let rows = |cx: &mut VisualTestContext| {
        cx.update(|window, _| {
            ["relay-0", "relay-1", "relay-2"]
                .iter()
                .filter(|id| window.try_find(**id).is_some())
                .count()
        })
    };
    assert_eq!(rows(cx), 2);
    click(cx, "remove-relay-0");
    assert_eq!(draft_relays(&view, cx), ["us"]);
    assert_eq!(rows(cx), 1);
    // Discard returns to what is stored; nothing was sent or written.
    click(cx, "discard");
    assert!(!bar(cx));
    view.read_with(cx, |app, _| assert_eq!(app.draft, app.saved));
    assert_eq!(draft_relays(&view, cx), ["eu", "us"]);
    assert_eq!(rows(cx), 2);
    assert_eq!(actions(&mock), []);
    assert_eq!(
        std::fs::read(&paths.config_file).unwrap_or_default(),
        on_disk
    );
}

/// An imported relay list lands in the draft (a relay of the same name is
/// replaced, others are kept), and a list that does not parse changes
/// nothing and says why.
#[gpui_kit::test]
fn an_imported_relay_list_joins_the_draft(cx: &mut TestAppContext) {
    let home = Home::new("import");
    let paths = write_config(&home, |config| {
        config.relays = vec![relay("eu", "old.example:4433")];
    });
    let mock = Arc::new(Mock::new(script()));
    let (view, cx) = open(cx, &mock, &home);
    show(&view, cx, Page::Settings);
    let list = home.0.join("relays.json");
    let choose = |cx: &mut VisualTestContext, file: &std::path::Path| {
        click(cx, "import-relays");
        assert!(cx.did_prompt_for_paths(), "the file picker opened");
        let file = file.to_owned();
        cx.simulate_path_prompt_response(move |_| Some(vec![file]));
        cx.run_until_parked();
    };
    let write_list = |text: &str| {
        if std::fs::write(&list, text).is_err() {
            unreachable!("the scratch home is writable");
        }
    };
    write_list(
        r#"{"version":1,"relays":[
            {"name":"eu","address":"new.example:4433","server_name":"relay.example"},
            {"name":"ap","address":"ap.example:4433","server_name":"relay.example"}]}"#,
    );
    choose(cx, &list);
    assert_eq!(draft_relays(&view, cx), ["eu", "ap"]);
    view.read_with(cx, |app, _| {
        let draft = app.draft.as_ref();
        let eu = draft.and_then(|c| c.relays.iter().find(|r| r.name == "eu"));
        assert_eq!(eu.map(|r| r.address.as_str()), Some("new.example:4433"));
        assert_eq!(app.saved.as_ref().map(|c| c.relays.len()), Some(1));
        assert!(app.model.notices.is_empty());
    });
    assert!(cx.update(|window, _| window.try_find("apply-bar").is_some()));
    // Nothing is written until Apply.
    assert_eq!(
        paths.config().map(|c| c.relays.len()).unwrap_or_default(),
        1
    );
    // A bad list leaves the draft alone and tells the user.
    write_list(r#"{"version":2,"relays":[]}"#);
    choose(cx, &list);
    assert_eq!(draft_relays(&view, cx), ["eu", "ap"]);
    view.read_with(cx, |app, _| {
        assert!(
            app.model
                .notices
                .iter()
                .any(|n| n.text.contains("relay list was not imported")),
            "{:?}",
            app.model.notices
        );
    });
    // A cancelled picker changes nothing.
    click(cx, "import-relays");
    cx.simulate_path_prompt_response(|_| None);
    cx.run_until_parked();
    assert_eq!(draft_relays(&view, cx), ["eu", "ap"]);
}

/// The folder picker sets the downloads folder in the draft.
#[gpui_kit::test]
fn the_chosen_downloads_folder_is_staged(cx: &mut TestAppContext) {
    let home = Home::new("downloads");
    write_config(&home, |_| {});
    let mock = Arc::new(Mock::new(script()));
    let (view, cx) = open(cx, &mock, &home);
    show(&view, cx, Page::Settings);
    click(cx, "downloads");
    let chosen = home.0.join("elsewhere");
    let answer = chosen.clone();
    cx.simulate_path_prompt_response(move |options| {
        assert!(options.directories && !options.files);
        Some(vec![answer])
    });
    cx.run_until_parked();
    view.read_with(cx, |app, _| {
        assert_eq!(
            app.draft.as_ref().map(|c| c.downloads_dir.clone()),
            Some(chosen)
        );
        assert_ne!(app.draft, app.saved);
    });
    assert!(cx.update(|window, _| window.try_find("apply-bar").is_some()));
}

/// Hiding is stored for the next start as well, over the file as it is
/// now (not over a stale copy), and keeps the edits staged meanwhile.
#[gpui_kit::test]
fn hiding_is_kept_for_the_next_start_beside_staged_edits(cx: &mut TestAppContext) {
    let home = Home::new("keep-hidden");
    let paths = write_config(&home, |_| {});
    // A core that remembers whether it is hidden, as the real one does.
    let hidden = std::sync::atomic::AtomicBool::new(false);
    let scripted = script();
    let mock = Arc::new(Mock::new(move |request| match request {
        Request::SetHidden { hidden: now } => {
            hidden.store(*now, Ordering::Relaxed);
            Response::Done
        }
        Request::Status => match scripted(request) {
            Response::Status(status) => Response::Status(StatusInfo {
                hidden: hidden.load(Ordering::Relaxed),
                ..status
            }),
            other => other,
        },
        _ => scripted(request),
    }));
    let (view, cx) = open(cx, &mock, &home);
    show(&view, cx, Page::Settings);
    click_in(cx, "retention", 1);
    // Changed behind the app's back (the CLI, say).
    let mut elsewhere = paths
        .config()
        .unwrap_or_else(|_| unreachable!("config reads"));
    elsewhere.relay_presence_seconds = 900;
    if prefs::save_config(&paths, &elsewhere).is_err() {
        unreachable!("the config writes");
    }
    click_in(cx, "visibility-choice", 2);
    assert_eq!(actions(&mock), [Request::SetHidden { hidden: true }]);
    let stored = paths
        .config()
        .unwrap_or_else(|_| unreachable!("config reads"));
    assert!(stored.hidden);
    assert_eq!(
        stored.relay_presence_seconds, 900,
        "the other change is kept"
    );
    assert_eq!(stored.history_days, 30, "the staged edit is not written");
    view.read_with(cx, |app, _| {
        let draft = app.draft.as_ref();
        assert_eq!(
            draft.map(|c| c.history_days),
            Some(7),
            "the staged edit stays"
        );
        assert_eq!(draft.map(|c| c.hidden), Some(true));
        assert_eq!(app.saved.as_ref().map(|c| c.hidden), Some(true));
    });
    // Visible again is stored too.
    click_in(cx, "visibility-choice", 0);
    assert!(paths.config().is_ok_and(|c| !c.hidden));
}

/// Apply writes the file, drops the old core, and starts a real one that
/// runs with the new configuration; the draft and the saved copy agree
/// afterwards.
#[gpui_kit::test]
fn apply_restarts_the_core_with_the_new_configuration(cx: &mut TestAppContext) {
    let home = Home::new("apply");
    let paths = write_config(&home, |_| {});
    let mock = Arc::new(Mock::new(script()));
    let (view, cx) = open(cx, &mock, &home);
    show(&view, cx, Page::Settings);
    click_in(cx, "retention", 1);
    // The real core runs on its own threads: let the test executor wait.
    cx.executor().allow_parking();
    click(cx, "apply");
    let mut restarted = false;
    for _ in 0..500 {
        cx.run_until_parked();
        let ready = view.read_with(cx, |app, _| {
            app.model.connection == Connection::Hosted
                && app.model.status.as_ref().map(|s| s.history_days) == Some(7)
        });
        if ready {
            restarted = true;
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(restarted, "the core did not restart with the new retention");
    assert_eq!(paths.config().map(|c| c.history_days).ok(), Some(7));
    view.read_with(cx, |app, _| {
        assert_eq!(app.draft, app.saved);
        assert_eq!(app.saved.as_ref().map(|c| c.history_days), Some(7));
        // The old (mock) core was dropped, not asked to do anything.
        assert!(app.model.notices.is_empty(), "{:?}", app.model.notices);
    });
    assert_eq!(Arc::strong_count(&mock), 1);
    assert_eq!(actions(&mock), []);
    assert!(cx.update(|window, _| window.try_find("apply-bar").is_none()));
    // Drop the app's core off the test's thread of control.
    view.update(cx, |app, _| {
        if let Some(core) = app.backend.take() {
            std::thread::spawn(move || drop(core));
        }
    });
}

fn pick(cx: &mut VisualTestContext, device: &str) {
    cx.update(|window, cx| {
        window.click(
            gpui_kit::ElementId::Name(format!("pick-{}", &device[..16]).into()),
            cx,
        );
    });
    cx.run_until_parked();
}

fn sends(mock: &Mock) -> Vec<(String, Vec<PathBuf>)> {
    let mut sent: Vec<(String, Vec<PathBuf>)> = actions(mock)
        .into_iter()
        .filter_map(|request| match request {
            Request::Send { contact, paths } => Some((contact, paths)),
            _ => None,
        })
        .collect();
    sent.sort();
    sent
}

/// Another launch's files wait for the user's choice; Send works only after
/// the decision delay and goes to the contacts chosen.
#[gpui_kit::test]
fn a_handed_over_send_asks_who_first(cx: &mut TestAppContext) {
    let home = Home::new("handoff");
    let mock = Arc::new(Mock::new(script()));
    let (view, cx) = open(cx, &mock, &home);
    let files = vec![PathBuf::from("/tmp/a.txt"), PathBuf::from("/tmp/dir")];
    view.update_in(cx, |app, window, cx| {
        app.handoff(
            todoke_daemon::handoff::Handoff::Send {
                paths: files.clone(),
            },
            window,
            cx,
        );
    });
    cx.run_until_parked();
    let label = cx.update(|window, _| window.find("picker").label().unwrap_or_default().to_owned());
    assert_eq!(label, "Send 2 items");
    pick(cx, LAN);
    pick(cx, AWAY);
    click(cx, "picker-send");
    assert!(sends(&mock).is_empty(), "sent before the delay");
    cx.executor().advance_clock(tokens::DECISION_DELAY);
    cx.run_until_parked();
    click(cx, "picker-send");
    let mut expected = vec![(LAN.to_owned(), files.clone()), (AWAY.to_owned(), files)];
    expected.sort();
    assert_eq!(sends(&mock), expected);
    view.read_with(cx, |app, _| assert!(app.picker.open.is_none()));
}

/// Escape and Cancel send nothing; a receive sheet goes over the picker and
/// takes the keys until it is hidden.
#[gpui_kit::test]
fn the_picker_cancels_and_yields_to_offers(cx: &mut TestAppContext) {
    let home = Home::new("picker-cancel");
    let mock = Arc::new(Mock::new(script()));
    let (view, cx) = open(cx, &mock, &home);
    let send = todoke_daemon::handoff::Handoff::Send {
        paths: vec![PathBuf::from("/tmp/a.txt")],
    };
    view.update_in(cx, |app, window, cx| app.handoff(send.clone(), window, cx));
    cx.run_until_parked();
    pick(cx, NEAR);
    cx.executor().advance_clock(tokens::DECISION_DELAY);
    cx.run_until_parked();
    mock.emit(Event::OfferReceived(offer("tp", &[("a", "text/plain", 1)])));
    cx.run_until_parked();
    cx.update(|window, cx| window.press("escape", cx));
    cx.run_until_parked();
    view.read_with(cx, |app, _| {
        assert!(app.sheet.transfer.is_none(), "escape hid the sheet first");
        assert!(app.picker.open.is_some());
    });
    cx.update(|window, cx| window.press("escape", cx));
    cx.run_until_parked();
    view.read_with(cx, |app, _| assert!(app.picker.open.is_none()));
    view.update_in(cx, |app, window, cx| app.handoff(send, window, cx));
    cx.run_until_parked();
    click(cx, "picker-cancel");
    view.read_with(cx, |app, _| assert!(app.picker.open.is_none()));
    assert_eq!(sends(&mock), []);
}

/// Sending the clipboard with no contact selected among several asks who.
#[gpui_kit::test]
fn the_clipboard_without_a_selection_asks_who(cx: &mut TestAppContext) {
    let home = Home::new("picker-clipboard");
    let mock = Arc::new(Mock::new(script()));
    let (view, cx) = open(cx, &mock, &home);
    cx.write_to_clipboard(ClipboardItem::new_string("see you".into()));
    cx.dispatch_action(super::SendClipboard);
    cx.run_until_parked();
    assert_eq!(sends(&mock), []);
    view.read_with(cx, |app, _| assert!(app.picker.open.is_some()));
    pick(cx, NEAR);
    cx.executor().advance_clock(tokens::DECISION_DELAY);
    cx.run_until_parked();
    click(cx, "picker-send");
    let sent = sends(&mock);
    assert_eq!(sent.len(), 1, "{sent:?}");
    assert_eq!(sent[0].0, NEAR);
    assert_eq!(
        std::fs::read_to_string(&sent[0].1[0]).unwrap_or_default(),
        "see you"
    );
}

/// With the window closed (todoke in the tray), an offer and a finished
/// transfer notify; the offer's notification goes once it is decided.
#[gpui_kit::test]
fn the_background_notifies_offers_and_endings(cx: &mut TestAppContext) {
    let home = Home::new("notify");
    let mock = Arc::new(Mock::new(script()));
    cx.update(|cx| cx.set_app_identity("org.todoke.todoke", "todoke"));
    let (view, vcx) = open(cx, &mock, &home);
    // In front: the window shows it, the system does not.
    mock.emit(Event::OfferReceived(offer("tf", &[("a", "text/plain", 1)])));
    vcx.run_until_parked();
    view.update(vcx, |app, _| app.closed());
    mock.emit(Event::OfferReceived(offer(
        "tn",
        &[("plan.pdf", "application/pdf", 9)],
    )));
    vcx.run_until_parked();
    let shown = vcx.cx.shown_system_notifications();
    assert_eq!(shown.len(), 1, "{shown:?}");
    assert_eq!(shown[0].tag.as_ref(), "offer-tn");
    assert!(!shown[0].body.contains("plan"));
    mock.emit(Event::Ended {
        transfer: "tn".into(),
        reason: TransferState::Rejected,
        message: "declined".into(),
    });
    vcx.run_until_parked();
    assert_eq!(
        vcx.cx
            .delivered_system_notifications()
            .iter()
            .map(|n| n.tag.to_string())
            .collect::<Vec<_>>(),
        ["transfer-tn"]
    );
}

/// Explorer starts one process per selected file: their paths gather in
/// the open picker, each arrival re-arming Send.
#[gpui_kit::test]
fn handed_over_paths_gather_in_one_picker(cx: &mut TestAppContext) {
    let home = Home::new("gather");
    let mock = Arc::new(Mock::new(script()));
    let (view, cx) = open(cx, &mock, &home);
    let send = |path: &str| todoke_daemon::handoff::Handoff::Send {
        paths: vec![PathBuf::from(path)],
    };
    view.update_in(cx, |app, window, cx| {
        app.handoff(send("/tmp/a"), window, cx)
    });
    cx.run_until_parked();
    pick(cx, NEAR);
    cx.executor().advance_clock(tokens::DECISION_DELAY);
    cx.run_until_parked();
    view.update_in(cx, |app, window, cx| {
        app.handoff(send("/tmp/b"), window, cx);
        app.handoff(send("/tmp/a"), window, cx);
    });
    cx.run_until_parked();
    // The new arrival disarmed Send; the choice of contact stayed.
    click(cx, "picker-send");
    assert_eq!(sends(&mock), []);
    cx.executor().advance_clock(tokens::DECISION_DELAY);
    cx.run_until_parked();
    click(cx, "picker-send");
    assert_eq!(
        sends(&mock),
        [(
            NEAR.to_owned(),
            vec![PathBuf::from("/tmp/a"), PathBuf::from("/tmp/b")]
        )]
    );
}
