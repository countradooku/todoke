//! Transfers in progress: progress, speed, time left, and how the bytes
//! travel (directly on the LAN, or through a relay).

use core::fmt::Write as _;

use gpui_kit::AnyElement;
use gpui_kit::TestSupportExt as _;
use gpui_kit::assets::IconName;
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    Context, FontWeight, InteractiveElement as _, IntoElement, ParentElement as _, Role,
    StatefulInteractiveElement as _, Styled as _, div, px,
};
use todoke_core::api::{Route, TransferInfo, TransferState, Way};

use super::Todoke;
use super::home::state_label;
use super::widgets::{self, badge, heading, muted, progress, section};
use crate::format;
use crate::tokens::{self, Palette, space, text};

impl Todoke {
    pub(super) fn render_transfers(&mut self, cx: &mut Context<Self>) -> gpui_kit::AnyElement {
        let palette = tokens::palette(cx);
        let active: Vec<TransferInfo> = self.model.active().into_iter().cloned().collect();
        let list = section("transfers-list", "In progress", palette).child(if active.is_empty() {
            muted(
                "Nothing is moving. Files you send or accept show here.",
                palette,
            )
            .into_any_element()
        } else {
            div()
                .id("active-transfers")
                .role(Role::List)
                .aria_label(format::plural(active.len(), "transfer", "transfers"))
                .flex()
                .flex_col()
                .gap(px(space::L))
                .children(
                    active
                        .iter()
                        .map(|transfer| self.transfer_row(transfer, palette, cx)),
                )
                .into_any_element()
        });
        div()
            .flex()
            .flex_col()
            .gap(px(space::XL))
            .child(heading(
                "Transfers",
                "Every file is checked against its hash before it is saved.",
                palette,
            ))
            .child(list)
            .into_any_element()
    }

    fn transfer_row(
        &self,
        transfer: &TransferInfo,
        palette: &'static Palette,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let id = transfer.transfer.clone();
        let incoming = transfer.way == Way::Incoming;
        let peer = format::device(&transfer.peer);
        let speed = self.model.speed(&transfer.transfer);
        let route = self.model.route_of(&transfer.peer);
        let moving = transfer.state == TransferState::Transferring;
        let fraction = (moving || transfer.bytes_done > 0)
            .then(|| format::fraction(transfer.bytes_done, transfer.bytes_total));
        let left = format::eta(transfer.bytes_done, transfer.bytes_total, speed);
        let (route_label, route_fill) = match route {
            Some(Route::Lan) => ("Direct (LAN)", palette.success),
            Some(Route::Direct) => ("Direct (Wi-Fi link)", palette.success),
            Some(Route::Relay) => ("Through relay", palette.warning),
            None => ("Waiting for a connection", palette.muted),
        };
        let mut detail = format!(
            "{} of {}",
            format::bytes(transfer.bytes_done),
            format::bytes(transfer.bytes_total)
        );
        if moving && speed > 0 {
            let _ = write!(detail, " · {}", format::rate(speed));
        }
        if let Some(left) = left {
            let _ = write!(detail, " · {} left", format::duration(left));
        }
        let state = state_label(transfer.state);
        let spoken = format!(
            "{} {peer}, {state}, {detail}, {route_label}",
            if incoming { "From" } else { "To" },
        );
        let percent = fraction.map_or(0.0, |f| f * 100.0);
        let cancel_id = id.clone();
        div()
            .id(gpui_kit::ElementId::Name(format!("transfer-{id}").into()))
            .test_support()
            .role(Role::ListItem)
            .aria_label(spoken)
            .flex()
            .flex_col()
            .gap(px(space::S))
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
                            .font_weight(FontWeight::MEDIUM)
                            .child(format!("{} {peer}", if incoming { "From" } else { "To" })),
                    )
                    .child(badge(route_label, route_fill, palette))
                    .child(muted(state, palette))
                    .child(
                        widgets::button(
                            format!("cancel-{id}"),
                            "Cancel",
                            format!("Cancel the transfer with {peer}"),
                        )
                        .on_click(cx.listener(move |this, _, _, cx| {
                            this.cancel(cancel_id.clone(), cx);
                        })),
                    ),
            )
            .child(
                div()
                    .id(gpui_kit::ElementId::Name(format!("progress-{id}").into()))
                    .test_support()
                    .role(Role::ProgressIndicator)
                    .aria_label(format!("{percent:.0} percent"))
                    .child(progress(format!("bar-{id}"), fraction, palette)),
            )
            .child(
                div()
                    .text_size(px(text::CAPTION))
                    .text_color(tokens::color(palette.muted))
                    .child(detail),
            )
            .when(transfer.state == TransferState::Interrupted, |row| {
                row.child(muted(
                    "Paused: it resumes when the contact is reachable again.",
                    palette,
                ))
            })
            .into_any_element()
    }
}
