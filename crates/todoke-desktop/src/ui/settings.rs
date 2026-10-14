//! Settings. Visibility applies at once; everything stored in
//! `config.json` (receiving, connections, retention) is edited as a draft
//! and applied by restarting the core with it. Nothing here can accept
//! files automatically: every offer asks.

use gpui_kit::TestSupportExt as _;
use gpui_kit::component::radio::{Radio, RadioGroup};
use gpui_kit::component::switch::Switch;
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    AnyElement, Context, FontWeight, InteractiveElement as _, IntoElement, ParentElement as _,
    PathPromptOptions, Role, StatefulInteractiveElement as _, Styled as _, Window, div, px,
};
use todoke_core::api::Request;
use todoke_core::config::{CoreConfig, RelayConfig};

use super::widgets::{self, heading, muted, section};
use super::{Page, PairTab, Todoke};
use crate::format;
use crate::model::{Connection, Level, Pairing};
use crate::prefs::{self, ThemeChoice};
use crate::tokens::{self, Palette, space, text};

/// Retention choices, in days.
const RETENTION: [u32; 5] = [0, 7, 30, 90, 365];
/// Relay presence choices, in seconds.
const PRESENCE: [u32; 4] = [60, 300, 900, 3600];

/// A smaller heading inside a section.
fn label(content: &'static str) -> gpui_kit::Div {
    div()
        .text_size(px(text::BODY))
        .font_weight(FontWeight::MEDIUM)
        .child(content)
}

impl Todoke {
    pub(super) fn render_settings(&mut self, _: &mut Window, cx: &mut Context<Self>) -> AnyElement {
        let palette = tokens::palette(cx);
        let page = div().flex().flex_col().gap(px(space::XL));
        let Some(config) = self.draft.clone() else {
            return page
                .child(heading("Settings", "Loading the configuration…", palette))
                .child(self.visibility(palette, cx))
                .into_any_element();
        };
        page.child(heading(
            "Settings",
            "Stored in config.json, shared with the todoke command.",
            palette,
        ))
        .when(self.draft != self.saved, |page| {
            page.child(apply_bar(palette, cx))
        })
        .child(self.visibility(palette, cx))
        .child(receiving(&config, palette, cx))
        .child(connections(&config, palette, cx))
        .child(self.security(&config, palette, cx))
        .child(self.devices(palette, cx))
        .child(self.this_computer(palette, cx))
        .child(self.appearance(palette, cx))
        .child(self.about(palette))
        .into_any_element()
    }

    fn visibility(&self, palette: &'static Palette, cx: &mut Context<Self>) -> AnyElement {
        let hidden = self
            .model
            .status
            .as_ref()
            .is_some_and(|status| status.hidden);
        section("visibility", "Visibility", palette)
            .child(
                RadioGroup::vertical("visibility-choice")
                    .selected_index(Some(usize::from(hidden) * 2))
                    .child(
                        Radio::new("visible-contacts")
                            .label("Contacts: paired devices see this one nearby and through relays")
                            .accessibility_label("Visible to contacts"),
                    )
                    .child(
                        Radio::new("visible-everyone")
                            .label("Everyone for 5 minutes: shows a pairing code (stranger mode)")
                            .accessibility_label(
                                "Visible to everyone nearby for 5 minutes, to pair",
                            ),
                    )
                    .child(
                        Radio::new("visible-hidden")
                            .label(
                                "Hidden: no one sees this device; it still reaches contacts it sends to",
                            )
                            .accessibility_label("Hidden from everyone"),
                    )
                    .on_click(cx.listener(|this, index: &usize, window, cx| match index {
                        0 => this.set_hidden(false, cx),
                        1 => this.everyone(window, cx),
                        _ => this.set_hidden(true, cx),
                    })),
            )
            .child(muted(
                "Stranger mode advertises no identity, and expires with the code (PROTOCOL §9).",
                palette,
            ))
            .into_any_element()
    }

    /// Everyone for five minutes: stranger mode is a pairing code (§9).
    fn everyone(&mut self, window: &mut Window, cx: &mut Context<Self>) {
        self.pair_tab = PairTab::ShowCode;
        self.show(Page::Pairing, window, cx);
        if !matches!(self.model.pairing, Pairing::Code { .. }) {
            self.model.pairing = Pairing::Requested;
            self.request(Request::PairShowCode, cx, |app, response, _| {
                app.model.answer(response);
            });
        }
    }

    fn security(
        &self,
        config: &CoreConfig,
        palette: &'static Palette,
        cx: &mut Context<Self>,
    ) -> AnyElement {
        let status = self.model.status.as_ref();
        let device = status.map(|s| s.device.clone()).unwrap_or_default();
        let sessions = match (&self.model.connection, status.map(|s| s.sessions_enabled)) {
            (Connection::Disabled, _) | (_, Some(false)) => "Disabled in this build (PROTOCOL §16)",
            (_, Some(true)) => {
                "Enabled: a development build (suite 0x0001 is not yet production-approved)"
            }
            _ => "Unknown",
        };
        section("security", "Security", palette)
            .child(
                div()
                    .flex()
                    .items_center()
                    .gap(px(space::M))
                    .child("This device")
                    .child(widgets::mono(format::fingerprint(&device), cx))
                    .when(!device.is_empty(), |row| {
                        row.child(widgets::copy(
                            "copy-device",
                            device.clone(),
                            "Copy this device's key",
                        ))
                    }),
            )
            .child(muted(format!("Sessions: {sessions}"), palette))
            .when_some(status.map(|s| s.key_protection), |card, protection| {
                card.child(muted(
                    format!("The key that seals this device's state is kept in {}.", protection.label()),
                    palette,
                ))
            })
            .child(muted(
                "Keys, contacts, and history are sealed under that key. Received names are shown escaped; MIME types grant nothing.",
                palette,
            ))
            .child(label("Keep history for"))
            .child(
                RadioGroup::horizontal("retention")
                    .selected_index(RETENTION.iter().position(|d| *d == config.history_days))
                    .children(RETENTION.iter().map(|days| {
                        let text = match days {
                            0 => "Off".to_owned(),
                            days => format!("{days} days"),
                        };
                        Radio::new(gpui_kit::ElementId::Name(format!("retention-{days}").into()))
                            .label(text.clone())
                            .accessibility_label(format!("Keep history: {text}"))
                    }))
                    .on_click(cx.listener(|this, index: &usize, _, cx| {
                        if let (Some(draft), Some(days)) = (&mut this.draft, RETENTION.get(*index)) {
                            draft.history_days = *days;
                        }
                        cx.notify();
                    })),
            )
            .into_any_element()
    }

    fn devices(&self, palette: &'static Palette, cx: &mut Context<Self>) -> AnyElement {
        let contacts = &self.model.contacts;
        let card = section("devices", "Contacts and devices", palette);
        if contacts.is_empty() {
            return card
                .child(muted("No contacts yet.", palette))
                .into_any_element();
        }
        let mono = gpui_kit::component::ActiveTheme::theme(&**cx)
            .mono_font_family
            .clone();
        card.child(
            div()
                .id("device-list")
                .role(Role::List)
                .aria_label(format::plural(contacts.len(), "contact", "contacts"))
                .flex()
                .flex_col()
                .gap(px(space::M))
                .children(contacts.iter().map(|contact| {
                    let proximity = self.model.proximity(contact);
                    let name = format::device(&contact.device);
                    div()
                        .id(gpui_kit::ElementId::Name(
                            format!("device-{}", contact.device).into(),
                        ))
                        .test_support()
                        .role(Role::ListItem)
                        .aria_label(format!(
                            "{name}, {}, device key {}, person key {}",
                            proximity.label(),
                            format::fingerprint(&contact.device),
                            format::fingerprint(&contact.person)
                        ))
                        .flex()
                        .items_center()
                        .gap(px(space::M))
                        .child(widgets::avatar(&contact.device, Some(proximity), palette))
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .gap(px(space::XS))
                                .child(div().font_weight(FontWeight::MEDIUM).child(name))
                                .child(widgets::mono_in(
                                    format!("device {}", format::fingerprint(&contact.device)),
                                    mono.clone(),
                                ))
                                .child(widgets::mono_in(
                                    format!("person {}", format::fingerprint(&contact.person)),
                                    mono.clone(),
                                )),
                        )
                        .child(div().flex_1())
                        .child(muted(proximity.label(), palette))
                })),
        )
        .into_any_element()
    }

    fn appearance(&self, palette: &'static Palette, cx: &mut Context<Self>) -> AnyElement {
        section("appearance", "Appearance", palette)
            .child(
                RadioGroup::horizontal("theme")
                    .selected_index(Some(match self.prefs.theme {
                        ThemeChoice::System => 0,
                        ThemeChoice::Light => 1,
                        ThemeChoice::Dark => 2,
                    }))
                    .child(
                        Radio::new("theme-system")
                            .label("System")
                            .accessibility_label("Follow the system theme"),
                    )
                    .child(
                        Radio::new("theme-light")
                            .label("Light")
                            .accessibility_label("Light theme"),
                    )
                    .child(
                        Radio::new("theme-dark")
                            .label("Dark")
                            .accessibility_label("Dark theme"),
                    )
                    .on_click(cx.listener(|this, index: &usize, window, cx| {
                        let theme = match index {
                            1 => ThemeChoice::Light,
                            2 => ThemeChoice::Dark,
                            _ => ThemeChoice::System,
                        };
                        this.set_theme(theme, window, cx);
                    })),
            )
            .into_any_element()
    }

    fn about(&self, palette: &'static Palette) -> AnyElement {
        let running = match self.model.connection {
            Connection::Hosted => {
                "This window runs todoke; the todoke command reaches it while it is open."
            }
            Connection::Attached => {
                "The todoke daemon runs in the background; this window is its interface."
            }
            _ => "todoke is not running.",
        };
        section("about", "About", palette)
            .child(format!("todoke {}", env!("CARGO_PKG_VERSION")))
            .child(muted(running, palette))
            .child(muted(
                "End-to-end encrypted file transfer between your devices. Apache-2.0 OR MIT. Interface built with GPUI through gpui-kit; icons from Lucide.",
                palette,
            ))
            .into_any_element()
    }

    fn choose_downloads(window: &mut Window, cx: &mut Context<Self>) {
        let chosen = cx.prompt_for_paths(PathPromptOptions {
            files: false,
            directories: true,
            multiple: false,
            prompt: Some("Save received files here".into()),
        });
        cx.spawn_in(window, async move |this, cx| {
            if let Ok(Ok(Some(mut paths))) = chosen.await
                && let Some(dir) = paths.pop()
            {
                let _ = this.update(cx, |app, cx| {
                    if let Some(draft) = &mut app.draft {
                        draft.downloads_dir = dir;
                    }
                    cx.notify();
                });
            }
        })
        .detach();
    }

    fn import_relays(window: &mut Window, cx: &mut Context<Self>) {
        let chosen = cx.prompt_for_paths(PathPromptOptions {
            files: true,
            directories: false,
            multiple: false,
            prompt: Some("Import".into()),
        });
        cx.spawn_in(window, async move |this, cx| {
            let Ok(Ok(Some(mut paths))) = chosen.await else {
                return;
            };
            let Some(file) = paths.pop() else {
                return;
            };
            let imported = cx
                .background_executor()
                .spawn(async move { prefs::import_relays(&file) })
                .await;
            let _ = this.update(cx, |app, cx| {
                match imported {
                    Ok(relays) => {
                        if let Some(draft) = &mut app.draft {
                            for relay in relays {
                                draft.relays.retain(|old| old.name != relay.name);
                                draft.relays.push(relay);
                            }
                            if let Err(why) = prefs::check_relays(&draft.relays) {
                                app.model.notify(Level::Error, why.to_string());
                            }
                        }
                    }
                    Err(error) => app.model.notify(
                        Level::Error,
                        format!("The relay list was not imported: {error}"),
                    ),
                }
                cx.notify();
            });
        })
        .detach();
    }
}

fn receiving(
    config: &CoreConfig,
    palette: &'static Palette,
    cx: &mut Context<Todoke>,
) -> AnyElement {
    section("receiving", "Receiving", palette)
        .child(muted(
            "Every offer asks you first; nothing is ever accepted automatically. Files are checked against their hashes before they are saved.",
            palette,
        ))
        .child(
            div()
                .flex()
                .items_center()
                .gap(px(space::M))
                .child(
                    div()
                        .flex_1()
                        .min_w_0()
                        .truncate()
                        .child(format!("Save to {}", config.downloads_dir.display())),
                )
                .child(
                    widgets::button("downloads", "Change…", "Choose where received files are saved")
                        .on_click(cx.listener(|_, _, window, cx| {
                            Todoke::choose_downloads(window, cx);
                        })),
                ),
        )
        .into_any_element()
}

fn connections(
    config: &CoreConfig,
    palette: &'static Palette,
    cx: &mut Context<Todoke>,
) -> AnyElement {
    let relays = &config.relays;
    section("connections", "Connections", palette)
        .child(
            Switch::new("lan")
                .checked(config.lan.enabled)
                .label("Local network: find contacts nearby and send directly")
                .accessibility_label("Use the local network")
                .on_click(cx.listener(|this, checked: &bool, _, cx| {
                    if let Some(draft) = &mut this.draft {
                        draft.lan.enabled = *checked;
                    }
                    cx.notify();
                })),
        )
        .child(label("Relays"))
        .child(if relays.is_empty() {
            muted(
                "No relay: contacts are reached only on the local network. A relay forwards encrypted traffic; it never sees keys or files.",
                palette,
            )
            .into_any_element()
        } else {
            div()
                .id("relay-list")
                .role(Role::List)
                .aria_label(format::plural(relays.len(), "relay", "relays"))
                .flex()
                .flex_col()
                .gap(px(space::S))
                .children(
                    relays
                        .iter()
                        .enumerate()
                        .map(|(index, relay)| relay_row(index, relay, palette, cx)),
                )
                .into_any_element()
        })
        .child(
            widgets::button("import-relays", "Import relay list…", "Import a relay list file")
                .on_click(cx.listener(|_, _, window, cx| Todoke::import_relays(window, cx))),
        )
        .when(!relays.is_empty(), |card| {
            card.child(muted(
                "How often idle devices meet at the relay, so a contact can reach this one:",
                palette,
            ))
            .child(
                RadioGroup::horizontal("presence")
                    .selected_index(
                        PRESENCE
                            .iter()
                            .position(|p| *p == config.relay_presence_seconds),
                    )
                    .children(PRESENCE.iter().map(|seconds| {
                        let text = format::duration(core::time::Duration::from_secs(u64::from(
                            *seconds,
                        )));
                        Radio::new(gpui_kit::ElementId::Name(format!("presence-{seconds}").into()))
                            .label(text.clone())
                            .accessibility_label(format!("Meet every {text}"))
                    }))
                    .on_click(cx.listener(|this, index: &usize, _, cx| {
                        if let (Some(draft), Some(seconds)) = (&mut this.draft, PRESENCE.get(*index))
                        {
                            draft.relay_presence_seconds = *seconds;
                        }
                        cx.notify();
                    })),
            )
        })
        .into_any_element()
}

fn relay_row(
    index: usize,
    relay: &RelayConfig,
    palette: &'static Palette,
    cx: &mut Context<Todoke>,
) -> AnyElement {
    // From a file the user chose, possibly from anywhere: escaped.
    let raw = relay.name.clone();
    let name = format::name(&relay.name);
    let address = format::name(&relay.address);
    let pinned = if relay.pin.is_some() {
        "pinned key"
    } else {
        "system certificates"
    };
    div()
        .id(gpui_kit::ElementId::Name(format!("relay-{index}").into()))
        .test_support()
        .role(Role::ListItem)
        .aria_label(format!("{name}, {address}, {pinned}"))
        .flex()
        .items_center()
        .gap(px(space::M))
        .child(div().font_weight(FontWeight::MEDIUM).child(name.clone()))
        .child(
            div()
                .flex_1()
                .child(muted(format!("{address} · {pinned}"), palette)),
        )
        .child(
            widgets::button(
                format!("remove-relay-{index}"),
                "Remove",
                format!("Remove the relay {name}"),
            )
            .on_click(cx.listener(move |this, _, _, cx| {
                if let Some(draft) = &mut this.draft {
                    draft.relays.retain(|relay| relay.name != raw);
                }
                cx.notify();
            })),
        )
        .into_any_element()
}

fn apply_bar(palette: &'static Palette, cx: &mut Context<Todoke>) -> AnyElement {
    div()
        .id("apply-bar")
        .test_support()
        .role(Role::Group)
        .aria_label("Unsaved changes")
        .flex()
        .items_center()
        .gap(px(space::M))
        .p(px(space::L))
        .rounded(px(tokens::radius::L))
        .bg(tokens::color(palette.raised))
        .child(
            div()
                .flex_1()
                .child("Changes apply when todoke restarts (transfers resume after)."),
        )
        .child(
            widgets::button("discard", "Discard", "Discard the changes").on_click(cx.listener(
                |this, _, _, cx| {
                    this.draft.clone_from(&this.saved);
                    cx.notify();
                },
            )),
        )
        .child(
            widgets::primary(
                "apply",
                "Apply and restart",
                "Apply the changes and restart todoke",
            )
            .on_click(cx.listener(|this, _, window, cx| this.apply_settings(window, cx))),
        )
        .into_any_element()
}
