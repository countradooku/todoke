//! The receive sheet: who offers what, and the user's decision (§7.2).
//!
//! The sender is a paired contact whose identity the session verified (the
//! seal says so; there is nothing else to check). Names, types, and sizes
//! are the sender's claims: names are escaped, and programs and scripts are
//! called out. The decisions stay disabled for
//! [`crate::tokens::DECISION_DELAY`] after the sheet appears, so a click or
//! key press aimed at what was there before cannot accept. The sheet takes
//! focus (it is a dialog); Escape hides it, and the offer waits until it
//! expires.

use std::collections::BTreeSet;

use gpui_kit::TestSupportExt as _;
use gpui_kit::assets::IconName;
use gpui_kit::component::checkbox::Checkbox;
use gpui_kit::component::{Disableable as _, button::ButtonVariants as _};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    Animation, AnimationExt as _, AnyElement, Context, FontWeight, InteractiveElement as _,
    IntoElement, ParentElement as _, Role, StatefulInteractiveElement as _, Styled as _, div, px,
};
use todoke_core::api::{EntryInfo, OfferInfo};

use super::home::command_key;
use super::widgets::{self, avatar, muted};
use super::{AcceptAll, CloseSheet, SHEET, Todoke};
use crate::format::{self, Summary};
use crate::tokens::{self, Palette, radius, size, space, text};

/// The most entries listed in the sheet; the rest are counted.
const LISTED: usize = 200;

/// A reminder that an offer does not wait forever (§13: 300 seconds).
const EXPIRY: &str =
    "Nothing is saved until you accept. Unanswered offers are declined after 5 minutes.";

impl Todoke {
    pub(super) fn render_sheet(&mut self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let transfer = self.sheet.transfer.clone()?;
        let offer = self
            .model
            .offers
            .iter()
            .find(|offer| offer.transfer == transfer)?
            .clone();
        let palette = tokens::palette(cx);
        let summary = Summary::of(&offer.entries);
        let types = summary.types();
        let spoken = format!(
            "{} wants to send {}{}. Verified contact.",
            format::device(&offer.from),
            summary.counts(),
            if types.is_empty() {
                String::new()
            } else {
                format!(": {types}")
            }
        );
        let waiting = self.model.offers.len().saturating_sub(1);
        let card = div()
            .id("receive-sheet")
            .test_support()
            .role(Role::Dialog)
            .aria_label(spoken)
            .track_focus(&self.sheet_focus)
            .key_context(SHEET)
            .on_action(cx.listener(|this, _: &AcceptAll, _, cx| this.accept(cx)))
            // The command key with Return accepts, but only a fresh press: a
            // key held since before the sheet appeared (auto-repeat) never
            // does.
            .on_key_down(cx.listener(|this, event: &gpui_kit::KeyDownEvent, _, cx| {
                let stroke = &event.keystroke;
                let command = if cfg!(target_os = "macos") {
                    stroke.modifiers.platform
                } else {
                    stroke.modifiers.control
                };
                if stroke.key == "enter" && command && !event.is_held {
                    this.accept(cx);
                    cx.stop_propagation();
                }
            }))
            .on_action(cx.listener(|this, _: &CloseSheet, _, cx| {
                if let Some(id) = this.sheet.transfer.clone() {
                    this.sheet.hidden.insert(id);
                }
                this.after_change(cx);
                cx.notify();
            }))
            .w(px(size::SHEET))
            .max_w_full()
            .flex()
            .flex_col()
            .gap(px(space::L))
            .p(px(space::XL))
            .rounded(px(radius::L))
            .bg(tokens::color(palette.surface))
            .border_1()
            .border_color(tokens::color(palette.border))
            .shadow_lg()
            .child(sender(&offer, palette))
            .child(contents(&offer, &summary, palette))
            .child(self.entries(&offer, palette, cx))
            .child(muted(EXPIRY, palette))
            .when(waiting > 0, |card| {
                card.child(muted(
                    format!(
                        "{} more waiting after this one",
                        format::plural(waiting, "offer", "offers")
                    ),
                    palette,
                ))
            })
            .child(self.decisions(&offer, cx))
            .with_animation(
                gpui_kit::ElementId::Name(format!("sheet-{transfer}").into()),
                Animation::new(tokens::motion::NORMAL).with_easing(gpui_kit::ease_out_quint()),
                |card, delta| card.mt(px((1.0 - delta) * space::XL)),
            );
        Some(
            div()
                .id("sheet-scrim")
                .absolute()
                .inset_0()
                .flex()
                .items_center()
                .justify_center()
                .bg(gpui_kit::black().opacity(0.4))
                .child(card)
                .into_any_element(),
        )
    }

    /// The entries, with a checkbox each while choosing.
    fn entries(
        &self,
        offer: &OfferInfo,
        palette: &'static Palette,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let choosing = self.sheet.choosing.as_ref();
        div()
            .id("offer-entries")
            .role(Role::List)
            .aria_label("Files offered")
            .flex()
            .flex_col()
            .gap(px(space::XS))
            .max_h(px(220.0))
            .overflow_y_scroll()
            .children(offer.entries.iter().take(LISTED).map(|entry| {
                let row = entry_row(entry, palette);
                match choosing {
                    Some(chosen) if !entry.directory => {
                        choosable(entry, chosen.contains(&entry.id), row, cx)
                    }
                    _ => row.into_any_element(),
                }
            }))
            .when(offer.entries.len() > LISTED, |list| {
                list.child(muted(
                    format!("and {} more", offer.entries.len() - LISTED),
                    palette,
                ))
            })
            .into_any_element()
    }

    /// Decline, Choose, and Accept.
    fn decisions(&self, offer: &OfferInfo, cx: &mut Context<Self>) -> AnyElement {
        let armed = self.sheet.armed;
        let choosing = self.sheet.choosing.as_ref().map(BTreeSet::len);
        let resume = offer.resume.is_some();
        let sender = format::device(&offer.from);
        let accept = match (resume, choosing) {
            (true, _) => "Resume".to_owned(),
            (false, Some(count)) => format!("Accept {}", format::plural(count, "file", "files")),
            (false, None) => "Accept all".to_owned(),
        };
        div()
            .flex()
            .gap(px(space::S))
            .justify_end()
            .child(
                widgets::button(
                    "decline",
                    "Decline",
                    format!("Decline the offer from {sender}"),
                )
                .danger()
                .disabled(!armed)
                .on_click(cx.listener(|this, _, _, cx| this.decline(cx))),
            )
            .when(!resume, |row| {
                let (label, spoken) = if choosing.is_some() {
                    ("Accept all instead", "Stop choosing and accept every file")
                } else {
                    ("Choose…", "Choose which files to accept")
                };
                row.child(
                    widgets::button("choose", label, spoken)
                        .disabled(!armed)
                        .on_click(cx.listener(|this, _, _, cx| {
                            this.sheet.choosing = match this.sheet.choosing {
                                Some(_) => None,
                                None => Some(BTreeSet::new()),
                            };
                            cx.notify();
                        })),
                )
            })
            .child(
                widgets::primary(
                    "accept",
                    accept.clone(),
                    format!("{accept} from {sender}, {}Return", command_key()),
                )
                .disabled(!armed)
                .on_click(cx.listener(|this, _, _, cx| this.accept(cx))),
            )
            .into_any_element()
    }
}

/// The sender and its seal.
fn sender(offer: &OfferInfo, palette: &'static Palette) -> AnyElement {
    div()
        .flex()
        .items_center()
        .gap(px(space::M))
        .child(avatar(&offer.from, None, palette))
        .child(
            div()
                .flex()
                .flex_col()
                .gap(px(space::XS))
                .child(
                    div()
                        .text_size(px(text::TITLE))
                        .font_weight(FontWeight::SEMIBOLD)
                        .child(format::device(&offer.from)),
                )
                .child(
                    div()
                        .id("verified")
                        .test_support()
                        .role(Role::Image)
                        .aria_label("Verified: a paired contact, authenticated by this session")
                        .flex()
                        .items_center()
                        .gap(px(space::XS))
                        .text_size(px(text::CAPTION))
                        .text_color(tokens::color(palette.success))
                        .child(widgets::icon(IconName::ShieldCheck, palette.success))
                        .child("Verified contact"),
                ),
        )
        .into_any_element()
}

/// Counts, sizes, types, and the programs warning.
fn contents(offer: &OfferInfo, summary: &Summary, palette: &'static Palette) -> AnyElement {
    let types = summary.types();
    let verb = if offer.resume.is_some() {
        "resume"
    } else {
        "send"
    };
    div()
        .flex()
        .flex_col()
        .gap(px(space::XS))
        .child(
            div()
                .text_size(px(text::TITLE))
                .child(format!("wants to {verb} {}", summary.counts())),
        )
        .when(!types.is_empty(), |block| block.child(muted(types, palette)))
        .when(summary.has_programs(), |block| {
            block.child(
                div()
                    .id("program-warning")
                    .test_support()
                    .role(Role::Alert)
                    .aria_label(
                        "This offer includes programs or scripts. Open them only if you expected them.",
                    )
                    .text_size(px(text::CAPTION))
                    .text_color(tokens::color(palette.warning))
                    .child("Includes programs or scripts: open them only if you expected them."),
            )
        })
        .into_any_element()
}

/// One entry: icon, escaped name, a programs badge, size.
fn entry_row(entry: &EntryInfo, palette: &'static Palette) -> gpui_kit::Div {
    let size_text = if entry.directory {
        "folder".to_owned()
    } else {
        format::bytes(entry.size)
    };
    div()
        .flex()
        .items_center()
        .gap(px(space::S))
        .text_size(px(text::BODY))
        .child(widgets::icon(
            if entry.directory {
                IconName::Folder
            } else {
                IconName::File
            },
            palette.muted,
        ))
        .child({
            let (stem, extension) = format::name_parts(&entry.name);
            div()
                .flex_1()
                .min_w_0()
                .flex()
                .child(div().min_w_0().truncate().child(stem))
                .child(div().flex_none().child(extension))
        })
        .when(format::kind(entry) == format::Kind::Program, |row| {
            row.child(widgets::badge("program", palette.warning, palette))
        })
        .child(muted(size_text, palette))
}

/// `row` with a checkbox that chooses `entry`.
fn choosable(
    entry: &EntryInfo,
    checked: bool,
    row: gpui_kit::Div,
    cx: &mut Context<Todoke>,
) -> AnyElement {
    let id = entry.id;
    div()
        .flex()
        .items_center()
        .gap(px(space::S))
        .child(
            Checkbox::new(gpui_kit::ElementId::Name(format!("choose-{id}").into()))
                .checked(checked)
                .accessibility_label(format!(
                    "{}, {}",
                    format::name(&entry.name),
                    format::bytes(entry.size)
                ))
                .on_click(cx.listener(move |this, checked: &bool, _, cx| {
                    if let Some(chosen) = &mut this.sheet.choosing {
                        if *checked {
                            chosen.insert(id);
                        } else {
                            chosen.remove(&id);
                        }
                    }
                    cx.notify();
                })),
        )
        .child(row.flex_1())
        .into_any_element()
}
