//! Home: contacts with how near each is, the drop zone, and what moved
//! recently. Click contacts to select them (several at once); drop files or
//! folders on a contact to send to it alone, or on the drop zone to send to
//! every selected contact.

use gpui_kit::TestSupportExt as _;
use gpui_kit::assets::IconName;
use gpui_kit::component::Sizable as _;
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    AnyElement, Context, ExternalPaths, FontWeight, InteractiveElement as _, IntoElement,
    ParentElement as _, Role, StatefulInteractiveElement as _, Styled as _, Window, div, px,
};
use todoke_core::api::{ContactInfo, HistoryEntry, TransferState, Way};

use super::widgets::{self, avatar, heading, muted, section};
use super::{Page, Todoke};
use crate::format;
use crate::tokens::{self, Palette, radius, size, space, text};

/// The command key's name, for hints.
pub(super) const fn command_key() -> &'static str {
    if cfg!(target_os = "macos") {
        "⌘"
    } else {
        "Ctrl+"
    }
}

impl Todoke {
    pub(super) fn render_home(&mut self, _: &mut Window, cx: &mut Context<Self>) -> AnyElement {
        let palette = tokens::palette(cx);
        div()
            .flex()
            .flex_col()
            .gap(px(space::XL))
            .child(heading(
                "Send files",
                "Everything is end-to-end encrypted. The receiver decides what to accept.",
                palette,
            ))
            .child(self.contact_grid(palette, cx))
            .child(self.drop_zone(palette, cx))
            .child(self.home_actions(cx))
            .child(self.recent(palette))
            .into_any_element()
    }

    fn contact_grid(&self, palette: &'static Palette, cx: &mut Context<Self>) -> AnyElement {
        let contacts = &self.model.contacts;
        let card = section("contacts", "Contacts", palette);
        if contacts.is_empty() {
            return card
                .child(
                    div()
                        .flex()
                        .items_center()
                        .gap(px(space::M))
                        .child(muted("No contacts yet.", palette))
                        .child(
                            widgets::primary(
                                "pair-first",
                                "Pair a device",
                                "Pair your first device",
                            )
                            .on_click(cx.listener(
                                |this, _, window, cx| {
                                    this.show(Page::Pairing, window, cx);
                                },
                            )),
                        ),
                )
                .into_any_element();
        }
        let selected = self.model.selected.len();
        card.child(
            div()
                .id("contact-grid")
                .role(Role::List)
                .aria_label(format!(
                    "{}, {selected} selected",
                    format::plural(contacts.len(), "contact", "contacts")
                ))
                .flex()
                .flex_wrap()
                .gap(px(space::M))
                .children(
                    contacts
                        .iter()
                        .map(|contact| self.contact_tile(contact, palette, cx)),
                ),
        )
        .into_any_element()
    }

    fn contact_tile(
        &self,
        contact: &ContactInfo,
        palette: &'static Palette,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let device = contact.device.clone();
        let proximity = self.model.proximity(contact);
        let chosen = self.model.selected.contains(&contact.device);
        let name = format::device(&contact.device);
        let spoken = format!(
            "{name}, {}{}. Drop files to send to this contact.",
            proximity.label(),
            if chosen { ", selected" } else { "" }
        );
        let (toggle, target) = (device.clone(), device.clone());
        div()
            .id(gpui_kit::ElementId::Name(
                format!("contact-{}", &device[..device.len().min(16)]).into(),
            ))
            .test_support()
            .role(Role::CheckBox)
            .aria_label(spoken)
            .aria_toggled(if chosen {
                gpui_kit::Toggled::True
            } else {
                gpui_kit::Toggled::False
            })
            .tab_stop(true)
            .w(px(size::TILE))
            .p(px(space::M))
            .flex()
            .flex_col()
            .items_center()
            .gap(px(space::S))
            .rounded(px(radius::L))
            .border_2()
            .border_color(tokens::color(if chosen {
                palette.accent
            } else {
                palette.surface
            }))
            .when(chosen, |tile| tile.bg(tokens::color(palette.raised)))
            .hover(|tile| tile.bg(tokens::color(palette.raised)))
            .cursor_pointer()
            .drag_over::<ExternalPaths>(move |style, _, _, _| {
                style
                    .border_color(tokens::color(palette.accent))
                    .bg(tokens::color(palette.raised))
            })
            .on_drop(cx.listener(move |this, paths: &ExternalPaths, _, cx| {
                this.dropped(paths, Some(target.clone()), cx);
                cx.stop_propagation();
            }))
            .on_click(cx.listener(move |this, _, _, cx| {
                this.model.toggle(&toggle);
                cx.notify();
            }))
            .child(avatar(&device, Some(proximity), palette))
            .child(
                div()
                    .text_size(px(text::CAPTION))
                    .font_weight(FontWeight::MEDIUM)
                    .text_center()
                    .child(name),
            )
            .child(
                div()
                    .text_size(px(text::CAPTION))
                    .text_color(tokens::color(widgets::proximity_color(proximity, palette)))
                    .child(proximity.label()),
            )
            .into_any_element()
    }

    fn drop_zone(&self, palette: &'static Palette, cx: &mut Context<Self>) -> AnyElement {
        let m = command_key();
        let targets = self.targets();
        let label = match (targets.as_slice(), self.model.contacts.len()) {
            (_, 0) => "Pair a device first, then drop files here to send them".to_owned(),
            ([], _) => "Select contacts above, then drop files or folders here".to_owned(),
            ([one], _) => format!(
                "Drop files or folders here to send them to {}",
                format::device(one)
            ),
            (many, _) => format!(
                "Drop files or folders here to send them to {} contacts",
                many.len()
            ),
        };
        div()
            .id("drop-zone")
            .test_support()
            .role(Role::Button)
            .aria_label(format!("{label}. Press to choose files ({m}O)."))
            .tab_stop(true)
            .flex()
            .flex_col()
            .items_center()
            .justify_center()
            .gap(px(space::S))
            .h(px(180.0))
            .rounded(px(radius::L))
            .border_2()
            .border_dashed()
            .border_color(tokens::color(palette.border))
            .bg(tokens::color(palette.surface))
            .cursor_pointer()
            .drag_over::<ExternalPaths>(move |style, _, _, _| {
                style
                    .border_color(tokens::color(palette.accent))
                    .bg(tokens::color(palette.raised))
            })
            .on_drop(cx.listener(|this, paths: &ExternalPaths, _, cx| {
                this.dropped(paths, None, cx);
                cx.stop_propagation();
            }))
            .on_click(cx.listener(|this, _, window, cx| this.choose_files(window, cx)))
            .child(widgets::icon(IconName::Upload, palette.accent).large())
            .child(
                div()
                    .text_size(px(text::TITLE))
                    .font_weight(FontWeight::MEDIUM)
                    .child(label),
            )
            .child(muted(
                format!("or press {m}O to choose files, {m}⇧V to send the clipboard"),
                palette,
            ))
            .into_any_element()
    }

    fn home_actions(&self, cx: &mut Context<Self>) -> AnyElement {
        let m = command_key();
        div()
            .flex()
            .gap(px(space::S))
            .child(
                widgets::button(
                    "choose-files",
                    "Choose files…",
                    format!("Choose files to send, {m}O"),
                )
                .on_click(cx.listener(|this, _, window, cx| this.choose_files(window, cx))),
            )
            .child(
                widgets::button(
                    "send-clipboard",
                    "Send clipboard",
                    format!("Send the clipboard's text or files, {m}Shift V"),
                )
                .on_click(cx.listener(|this, _, _, cx| this.send_clipboard(cx))),
            )
            .when(!self.model.selected.is_empty(), |row| {
                row.child(
                    widgets::button(
                        "clear-selection",
                        "Clear selection",
                        "Clear the selected contacts",
                    )
                    .on_click(cx.listener(|this, _, _, cx| {
                        this.model.selected.clear();
                        cx.notify();
                    })),
                )
            })
            .into_any_element()
    }

    fn recent(&self, palette: &'static Palette) -> AnyElement {
        let card = section("recent", "Recent", palette);
        if self.model.history.is_empty() {
            return card
                .child(muted("Nothing sent or received yet.", palette))
                .into_any_element();
        }
        card.child(
            div()
                .id("recent-list")
                .role(Role::List)
                .aria_label("Recent transfers")
                .flex()
                .flex_col()
                .gap(px(space::S))
                .children(
                    self.model
                        .history
                        .iter()
                        .take(5)
                        .map(|entry| recent_row(entry, palette)),
                ),
        )
        .into_any_element()
    }
}

fn recent_row(entry: &HistoryEntry, palette: &'static Palette) -> AnyElement {
    let incoming = entry.way == Way::Incoming;
    let names = entry
        .names
        .iter()
        .map(|name| format::name(name))
        .collect::<Vec<_>>()
        .join(", ");
    let peer = format::device(&entry.peer);
    let state = state_label(entry.state);
    let spoken = format!(
        "{} {peer}: {names}, {}, {state}",
        if incoming { "From" } else { "To" },
        format::bytes(entry.bytes)
    );
    div()
        .id(gpui_kit::ElementId::Name(
            format!("recent-{}", entry.transfer).into(),
        ))
        .test_support()
        .role(Role::ListItem)
        .aria_label(spoken)
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
        .child(div().flex_1().min_w_0().truncate().child(names))
        .child(muted(peer, palette))
        .child(muted(format::bytes(entry.bytes), palette))
        .child(muted(state, palette))
        .into_any_element()
}

/// A transfer's state for people.
pub(super) const fn state_label(state: TransferState) -> &'static str {
    match state {
        TransferState::Offered => "Offered",
        TransferState::AwaitingDecision => "Awaiting your decision",
        TransferState::Accepted => "Accepted",
        TransferState::Transferring => "Transferring",
        TransferState::Interrupted => "Paused",
        TransferState::Received => "Received",
        TransferState::Delivered => "Delivered",
        TransferState::Unconfirmed => "Unconfirmed",
        TransferState::Rejected => "Declined",
        TransferState::Cancelled => "Cancelled",
        TransferState::Failed => "Failed",
    }
}
