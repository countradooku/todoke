//! Screenshots of every screen in both themes, rendered off screen by the
//! real renderer (Metal, so macOS only) against the mock core, for
//! `docs/qa/screenshots`. Nothing is captured from the display:
//!
//! ```text
//! cargo run -p todoke-desktop --example screenshots --features mock -- docs/qa/screenshots
//! ```

use std::path::{Path, PathBuf};
use std::sync::Arc;

use gpui_kit::component::ThemeMode;
use gpui_kit::{AppContext as _, Window, px, size};
use todoke_core::api::{Event, TransferInfo, TransferState, Way};
use todoke_daemon::Paths;
use zeroize::Zeroizing;

use super::fixtures::{LAN, RELAYED, offer, script};
use super::{Page, PairTab, Todoke, bindings, unix_now};
use crate::backend::mock::Mock;
use crate::model::{Connection, Pairing};
use crate::prefs::ThemeChoice;
use crate::tokens;

/// Sets up one screen.
type Setup = fn(&mut Todoke, &Mock, &mut Window, &mut gpui_kit::Context<Todoke>);

/// The screens: name, window height, setup.
const SCREENS: [(&str, f32, Setup); 7] = [
    ("home", 760.0, home),
    ("send", 760.0, send),
    ("receive", 760.0, receive),
    ("transfers", 560.0, transfers),
    ("pairing-qr", 640.0, pairing_qr),
    ("pairing-code", 560.0, pairing_code),
    ("history", 700.0, history),
];

fn home(app: &mut Todoke, _: &Mock, window: &mut Window, cx: &mut gpui_kit::Context<Todoke>) {
    app.show(Page::Home, window, cx);
}

fn send(app: &mut Todoke, _: &Mock, window: &mut Window, cx: &mut gpui_kit::Context<Todoke>) {
    app.show(Page::Home, window, cx);
    app.model.toggle(LAN);
    app.model.toggle(RELAYED);
}

fn receive(app: &mut Todoke, mock: &Mock, window: &mut Window, cx: &mut gpui_kit::Context<Todoke>) {
    app.show(Page::Home, window, cx);
    mock.emit(Event::OfferReceived(offer(
        "0f".repeat(16).as_str(),
        &[
            ("Lisbon 2026", "", 0),
            ("IMG_2041.HEIC", "image/heic", 3_481_221),
            ("IMG_2042.HEIC", "image/heic", 3_920_114),
            ("Itinerary.pdf", "application/pdf", 182_330),
        ],
    )));
}

fn transfers(
    app: &mut Todoke,
    mock: &Mock,
    window: &mut Window,
    cx: &mut gpui_kit::Context<Todoke>,
) {
    for (id, peer, way, total) in [
        ("aa".repeat(16), LAN, Way::Outgoing, 1_610_612_736_u64),
        ("bb".repeat(16), RELAYED, Way::Incoming, 52_428_800),
    ] {
        app.model.transfers.insert(
            id.clone(),
            TransferInfo {
                transfer: id,
                peer: peer.into(),
                way,
                state: TransferState::Accepted,
                detail: None,
                bytes_done: 0,
                bytes_total: total,
            },
        );
    }
    mock.emit(Event::Progress {
        transfer: "aa".repeat(16),
        way: Way::Outgoing,
        done: 1_040_187_392,
        total: 1_610_612_736,
        bytes_per_second: 96_468_992,
    });
    mock.emit(Event::Progress {
        transfer: "bb".repeat(16),
        way: Way::Incoming,
        done: 9_437_184,
        total: 52_428_800,
        bytes_per_second: 2_831_155,
    });
    app.show(Page::Transfers, window, cx);
}

fn pairing_qr(app: &mut Todoke, _: &Mock, window: &mut Window, cx: &mut gpui_kit::Context<Todoke>) {
    app.pair_tab = PairTab::ShowQr;
    app.show(Page::Pairing, window, cx);
    app.model.pairing = Pairing::Qr {
        text: Zeroizing::new("TODOKE:6BFR%BZ2DBKC8.FWKAZ4C*96UEB+08MFCX9+KA*S6P$EKGDZ*5".into()),
        expires_at: unix_now() + 272,
    };
}

fn pairing_code(
    app: &mut Todoke,
    _: &Mock,
    window: &mut Window,
    cx: &mut gpui_kit::Context<Todoke>,
) {
    app.pair_tab = PairTab::ShowCode;
    app.show(Page::Pairing, window, cx);
    app.model.pairing = Pairing::Code {
        code: Zeroizing::new("4830215967".into()),
        expires_at: unix_now() + 247,
    };
}

fn history(app: &mut Todoke, _: &Mock, window: &mut Window, cx: &mut gpui_kit::Context<Todoke>) {
    app.show(Page::History, window, cx);
}

fn settings(app: &mut Todoke, _: &Mock, window: &mut Window, cx: &mut gpui_kit::Context<Todoke>) {
    app.show(Page::Settings, window, cx);
    // A plausible folder rather than the scratch home's.
    for config in [&mut app.saved, &mut app.draft].into_iter().flatten() {
        config.downloads_dir = "/Users/alex/Downloads".into();
    }
}

/// Renders every screen in both themes into `dir`; returns the files.
///
/// # Errors
///
/// Why a screen could not be rendered or saved.
pub fn capture_all(dir: &Path) -> Result<Vec<PathBuf>, String> {
    std::fs::create_dir_all(dir).map_err(|error| error.to_string())?;
    let platform = gpui_kit::platform::current_platform(false);
    let mut cx = gpui_kit::VisualTestAppContext::with_asset_source(
        platform,
        Arc::new(super::assets::Assets),
    );
    cx.update(|cx| {
        gpui_kit::init(cx);
        cx.bind_keys(bindings());
        // Final states, not frames of an animation (and the reduced-motion
        // path gets exercised).
        cx.set_reduce_motion(true);
    });
    let mut written = Vec::new();
    let screens = SCREENS
        .iter()
        .copied()
        .chain([("settings", 2300.0, settings as Setup)]);
    for (name, height, setup) in screens {
        for mode in [ThemeMode::Light, ThemeMode::Dark] {
            let home = std::env::temp_dir().join(format!(
                "todoke-shot-{name}-{}-{}",
                mode.name(),
                std::process::id()
            ));
            let paths = Paths::under(&home);
            let mock = Arc::new(Mock::new(script()));
            let backend: Arc<dyn crate::backend::Backend> = mock.clone();
            cx.update(|cx| tokens::set_mode(mode, cx));
            let window = cx
                .open_offscreen_window(
                    size(px(tokens::size::WINDOW.0), px(height)),
                    |window, cx| {
                        cx.new(|cx| {
                            let mut app = Todoke::new(paths, window, cx);
                            app.attach(backend, Connection::Hosted, cx);
                            app
                        })
                    },
                )
                .map_err(|error| error.to_string())?;
            cx.run_until_parked();
            cx.update_window(window.into(), |root, window, cx| {
                if let Ok(view) = root.downcast::<Todoke>() {
                    view.update(cx, |app, cx| {
                        app.prefs.theme = if mode.is_dark() {
                            ThemeChoice::Dark
                        } else {
                            ThemeChoice::Light
                        };
                        app.apply_theme(window, cx);
                        setup(app, &mock, window, cx);
                    });
                }
            })
            .map_err(|error| error.to_string())?;
            // Let the sheet arm and every animation finish.
            cx.run_until_parked();
            cx.advance_clock(tokens::DECISION_DELAY + tokens::motion::NORMAL);
            cx.run_until_parked();
            // Animations run on the frame clock (real time): let them end.
            std::thread::sleep(tokens::motion::NORMAL * 2);
            cx.update(gpui_kit::App::refresh_windows);
            cx.run_until_parked();
            let image = cx
                .capture_screenshot(window.into())
                .map_err(|error| error.to_string())?;
            let file = dir.join(format!("{name}-{}.png", mode.name()));
            image.save(&file).map_err(|error| error.to_string())?;
            written.push(file);
            let _ = cx.update_window(window.into(), |_, window, _| window.remove_window());
            let _ = std::fs::remove_dir_all(&home);
        }
    }
    Ok(written)
}
