//! "Send to…": the contacts to send what another launch (a file manager's
//! "Send with todoke", the global shortcut) or the clipboard offered.
//!
//! Any program of this user can ask the window to send files; the picker is
//! where the user consents. Nothing is sent until they choose contacts and
//! press Send, and Send stays disabled for [`tokens::DECISION_DELAY`] after
//! the picker appears (the window comes to the front under the pointer: a
//! click aimed at what was there before must not send). The paths offered
//! are shown in full.

use std::collections::BTreeSet;
use std::path::PathBuf;

use gpui_kit::TestSupportExt as _;
use gpui_kit::component::Disableable as _;
use gpui_kit::component::checkbox::Checkbox;
use gpui_kit::{
    AnyElement, Context, FocusHandle, FontWeight, InteractiveElement as _, IntoElement,
    ParentElement as _, Role, StatefulInteractiveElement as _, Styled as _, div, px,
};

use super::widgets::{self, avatar, muted};
use super::{ClosePicker, PICKER, Todoke};
use crate::format;
use crate::tokens::{self, Palette, radius, size, space, text};

/// What the picker sends.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Offered {
    /// Files and folders (absolute paths).
    Paths(Vec<PathBuf>),
    /// What the clipboard holds when Send is pressed.
    Clipboard,
}

/// The picker's state.
#[derive(Clone, Debug)]
pub struct Picker {
    /// What it sends.
    pub offered: Offered,
    /// The contacts chosen.
    pub chosen: BTreeSet<String>,
    /// Whether Send works yet.
    pub armed: bool,
    /// Bumped with each picker: a timer started for an earlier one arms
    /// nothing.
    generation: u64,
}

/// The picker of the window.
pub struct State {
    /// The picker shown, if any.
    pub open: Option<Picker>,
    /// Its focus (a dialog takes focus).
    pub focus: FocusHandle,
    /// Whether it has focus now.
    pub focused: bool,
}

impl State {
    pub(super) fn new(cx: &mut Context<Todoke>) -> Self {
        Self {
            open: None,
            focus: cx.focus_handle(),
            focused: false,
        }
    }
}

/// At most this many paths are listed; the rest are counted.
const LISTED: usize = 5;

impl Todoke {
    /// Opens the picker for `offered` (replacing one open), with the
    /// contacts selected on Home (or the only one) chosen.
    pub(crate) fn pick(&mut self, offered: Offered, cx: &mut Context<Self>) {
        let generation = self
            .picker
            .open
            .as_ref()
            .map_or(0, |picker| picker.generation + 1);
        self.picker.open = Some(Picker {
            offered,
            chosen: self.targets().into_iter().collect(),
            armed: false,
            generation,
        });
        cx.spawn(async move |this, cx| {
            cx.background_executor().timer(tokens::DECISION_DELAY).await;
            let _ = this.update(cx, |app, cx| {
                if let Some(picker) = &mut app.picker.open
                    && picker.generation == generation
                {
                    picker.armed = true;
                    cx.notify();
                }
            });
        })
        .detach();
        cx.notify();
    }

    fn send_picked(&mut self, cx: &mut Context<Self>) {
        if !self
            .picker
            .open
            .as_ref()
            .is_some_and(|picker| picker.armed && !picker.chosen.is_empty())
        {
            return;
        }
        let Some(picker) = self.picker.open.take() else {
            return;
        };
        let targets: Vec<String> = picker.chosen.into_iter().collect();
        match picker.offered {
            Offered::Paths(paths) => self.send_paths(&paths, &targets, None, cx),
            Offered::Clipboard => self.send_clipboard_to(targets, cx),
        }
        cx.notify();
    }

    fn close_picker(&mut self, cx: &mut Context<Self>) {
        self.picker.open = None;
        cx.notify();
    }

    pub(super) fn render_picker(&mut self, cx: &mut Context<Self>) -> Option<AnyElement> {
        let picker = self.picker.open.clone()?;
        let palette = tokens::palette(cx);
        let (title, listed) = match &picker.offered {
            Offered::Paths(paths) => {
                let mut listed: Vec<String> = paths
                    .iter()
                    .take(LISTED)
                    .map(|path| format::name(&path.display().to_string()))
                    .collect();
                if paths.len() > LISTED {
                    listed.push(format!("and {} more", paths.len() - LISTED));
                }
                (
                    format!("Send {}", format::plural(paths.len(), "item", "items")),
                    listed,
                )
            }
            Offered::Clipboard => ("Send what the clipboard holds".to_owned(), Vec::new()),
        };
        let count = picker.chosen.len();
        let list = self.contact_list(&picker.chosen, palette, cx);
        let card = div()
            .id("picker")
            .test_support()
            .role(Role::Dialog)
            .aria_label(title.clone())
            .track_focus(&self.picker.focus)
            .key_context(PICKER)
            .on_action(cx.listener(|this, _: &ClosePicker, _, cx| this.close_picker(cx)))
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
            .child(
                div()
                    .text_size(px(text::TITLE))
                    .font_weight(FontWeight::SEMIBOLD)
                    .child(title),
            )
            .children(listed.into_iter().map(|line| muted(line, palette)))
            .child(list)
            .child(
                div()
                    .flex()
                    .justify_end()
                    .gap(px(space::S))
                    .child(
                        widgets::button("picker-cancel", "Cancel", "Cancel: send nothing")
                            .on_click(cx.listener(|this, _, _, cx| this.close_picker(cx))),
                    )
                    .child(
                        widgets::primary(
                            "picker-send",
                            if count > 1 {
                                format!("Send to {count}")
                            } else {
                                "Send".to_owned()
                            },
                            format!("Send to {}", format::plural(count, "contact", "contacts")),
                        )
                        .disabled(count == 0 || !picker.armed)
                        .on_click(cx.listener(|this, _, _, cx| this.send_picked(cx))),
                    ),
            );
        Some(
            div()
                .id("picker-scrim")
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

    /// The contacts, each with a checkbox.
    fn contact_list(
        &self,
        chosen: &BTreeSet<String>,
        palette: &'static Palette,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        if self.model.contacts.is_empty() {
            return muted(
                "Pair a device first: there is no one to send to yet.",
                palette,
            )
            .into_any_element();
        }
        div()
            .id("picker-contacts")
            .role(Role::List)
            .aria_label("Contacts to send to")
            .flex()
            .flex_col()
            .gap(px(space::S))
            .max_h(px(280.0))
            .overflow_y_scroll()
            .children(self.model.contacts.iter().map(|contact| {
                let device = contact.device.clone();
                let name = format::device(&device);
                let proximity = self.model.proximity(contact);
                div()
                    .flex()
                    .items_center()
                    .gap(px(space::M))
                    .child(
                        Checkbox::new(gpui_kit::ElementId::Name(
                            format!("pick-{}", &device[..device.len().min(16)]).into(),
                        ))
                        .checked(chosen.contains(&device))
                        .accessibility_label(format!("{name}, {}", proximity.label()))
                        .on_click(cx.listener(
                            move |this, checked: &bool, _, cx| {
                                if let Some(picker) = &mut this.picker.open {
                                    if *checked {
                                        picker.chosen.insert(device.clone());
                                    } else {
                                        picker.chosen.remove(&device);
                                    }
                                }
                                cx.notify();
                            },
                        )),
                    )
                    .child(avatar(&contact.device, Some(proximity), palette))
                    .child(div().flex_1().min_w_0().child(name))
                    .child(muted(proximity.label(), palette))
            }))
            .into_any_element()
    }
}
