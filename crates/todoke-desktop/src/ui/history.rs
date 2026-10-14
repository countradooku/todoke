//! History: finished transfers, sealed at rest by the core and kept for the
//! retention the settings choose (§7.7 leaves receipt retention to local
//! policy). Searchable by name, device, transfer, manifest hash, receipt,
//! or state. Rows are virtual: only the visible ones are laid out.

use std::rc::Rc;

use gpui_kit::TestSupportExt as _;
use gpui_kit::assets::IconName;
use gpui_kit::component::input::Input;
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    AnyElement, Context, FontWeight, InteractiveElement as _, IntoElement, ParentElement as _,
    Role, SharedString, StatefulInteractiveElement as _, Styled as _, div, px, uniform_list,
};
use todoke_core::api::{HistoryEntry, TransferState, Way};

use super::Todoke;
use super::home::state_label;
use super::widgets::{self, heading, muted, section};
use crate::format;
use crate::tokens::{self, Palette, space, text};

/// One row's height: two lines and padding.
const ROW: f32 = 100.0;

impl Todoke {
    pub(super) fn render_history(&mut self, cx: &mut Context<Self>) -> AnyElement {
        let palette = tokens::palette(cx);
        let query = self.search.read(cx).value().to_string();
        let found: Rc<Vec<HistoryEntry>> =
            Rc::new(self.model.search(&query).into_iter().cloned().collect());
        let days = self
            .model
            .status
            .as_ref()
            .map_or(30, |status| status.history_days);
        let retention = match days {
            0 => "History is off: nothing is kept. Turn it on in Settings.".to_owned(),
            1 => "Kept for 1 day, sealed on this device. Change it in Settings.".to_owned(),
            days => format!("Kept for {days} days, sealed on this device. Change it in Settings."),
        };
        let count = found.len();
        let list = if count == 0 {
            muted(
                if self.model.history.is_empty() {
                    "No finished transfers yet."
                } else {
                    "Nothing matches."
                },
                palette,
            )
            .into_any_element()
        } else {
            let rows = Rc::clone(&found);
            let mono = gpui_kit::component::ActiveTheme::theme(&**cx)
                .mono_font_family
                .clone();
            div()
                .id("history-list")
                .test_support()
                .role(Role::List)
                .aria_label(format!(
                    "{} found",
                    format::plural(count, "transfer", "transfers")
                ))
                .h(px(ROW * 6.0))
                .child(
                    uniform_list("history-rows", count, move |range, _, _| {
                        range
                            .filter_map(|index| rows.get(index))
                            .map(|entry| history_row(entry, palette, &mono))
                            .collect()
                    })
                    .h_full(),
                )
                .into_any_element()
        };
        div()
            .flex()
            .flex_col()
            .gap(px(space::XL))
            .child(heading("History", retention, palette))
            .child(
                div()
                    .flex()
                    .gap(px(space::S))
                    .items_center()
                    .child(
                        div().flex_1().child(
                            Input::new(&self.search)
                                .id("history-search")
                                .aria_label("Search the history")
                                .cleanable(true),
                        ),
                    )
                    .child(self.clear_button(cx)),
            )
            .child(section("history", "Finished transfers", palette).child(list))
            .into_any_element()
    }
    /// Clear history, confirmed by a second click.
    fn clear_button(&self, cx: &mut Context<Self>) -> AnyElement {
        let confirming = self.confirm_clear;
        widgets::button(
            "clear-history",
            if confirming {
                "Click again to clear"
            } else {
                "Clear history"
            },
            if confirming {
                "Confirm: forget every finished transfer"
            } else {
                "Clear the history"
            },
        )
        .when(
            confirming,
            gpui_kit::component::button::ButtonVariants::danger,
        )
        .on_click(cx.listener(|this, _, _, cx| {
            if this.confirm_clear {
                this.confirm_clear = false;
                this.request(
                    todoke_core::api::Request::ClearHistory,
                    cx,
                    |app, response, cx| {
                        app.model.answer(response);
                        app.fetch(&[crate::model::Fetch::History], cx);
                    },
                );
            } else {
                this.confirm_clear = true;
            }
            cx.notify();
        }))
        .into_any_element()
    }
}

fn history_row(entry: &HistoryEntry, palette: &'static Palette, mono: &SharedString) -> AnyElement {
    let incoming = entry.way == Way::Incoming;
    let names = entry
        .names
        .iter()
        .map(|name| format::name(name))
        .collect::<Vec<_>>()
        .join(", ");
    let peer = format::device(&entry.peer);
    let state = state_label(entry.state);
    let good = matches!(
        entry.state,
        TransferState::Received | TransferState::Delivered
    );
    let when = format::timestamp(entry.finished_at);
    let mut spoken = format!(
        "{} {peer}, {names}, {}, {}, {state}, {when}",
        if incoming { "From" } else { "To" },
        format::plural(
            usize::try_from(entry.files).unwrap_or(usize::MAX),
            "file",
            "files"
        ),
        format::bytes(entry.bytes),
    );
    if entry.receipt.is_some() {
        spoken.push_str(", signed receipt");
    }
    div()
        .id(gpui_kit::ElementId::Name(
            format!("history-{}", entry.transfer).into(),
        ))
        .test_support()
        .role(Role::ListItem)
        .aria_label(spoken)
        .h(px(ROW))
        .w_full()
        .min_w_0()
        .overflow_hidden()
        .flex()
        .flex_col()
        .justify_center()
        .gap(px(space::XS))
        .border_b_1()
        .border_color(tokens::color(palette.border))
        .child(
            div()
                .flex()
                .items_center()
                .gap(px(space::M))
                .child(widgets::icon(
                    if incoming {
                        IconName::ArrowDownToLine
                    } else {
                        IconName::ArrowUpFromLine
                    },
                    palette.muted,
                ))
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .truncate()
                        .font_weight(FontWeight::MEDIUM)
                        .child(if names.is_empty() {
                            "(no names)".to_owned()
                        } else {
                            names
                        }),
                )
                .child(widgets::badge(
                    state,
                    if good { palette.success } else { palette.muted },
                    palette,
                ))
                .when(entry.receipt.is_some(), |row| {
                    row.child(widgets::icon(IconName::Receipt, palette.success))
                }),
        )
        .child(row_detail(entry, &peer, &when, palette, mono))
        .into_any_element()
}

/// A history row's second line: peer, size, time, and the hashes.
fn row_detail(
    entry: &HistoryEntry,
    peer: &str,
    when: &str,
    palette: &'static Palette,
    mono: &SharedString,
) -> gpui_kit::Div {
    let incoming = entry.way == Way::Incoming;
    let hash = entry.manifest_hash.clone().unwrap_or_default();
    let receipt = entry.receipt.as_ref().map(|receipt| receipt.id.clone());
    let short = |hex: &str| hex.chars().take(16).collect::<String>();
    let hashes = div()
        .flex()
        .items_center()
        .gap(px(space::S))
        .when(!hash.is_empty(), |row| {
            row.child(widgets::mono_in(
                format!("manifest {}…", short(&hash)),
                mono.clone(),
            ))
            .child(widgets::copy(
                format!("copy-hash-{}", entry.transfer),
                hash.clone(),
                "Copy the manifest hash",
            ))
        })
        .when_some(receipt, |row, receipt| {
            row.child(widgets::mono_in(
                format!("receipt {}…", short(&receipt)),
                mono.clone(),
            ))
            .child(widgets::copy(
                format!("copy-receipt-{}", entry.transfer),
                receipt,
                "Copy the receipt ID",
            ))
        });
    div()
        .flex()
        .flex_col()
        .gap(px(space::XS))
        .text_size(px(text::CAPTION))
        .text_color(tokens::color(palette.muted))
        .child(format!(
            "{} {peer} · {} · {}",
            if incoming { "from" } else { "to" },
            format::bytes(entry.bytes),
            when
        ))
        .child(hashes)
}
