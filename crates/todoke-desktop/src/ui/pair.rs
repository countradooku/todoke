//! Pairing (§3): show a QR code, show a ten-digit code, enter another
//! device's code, or paste another device's QR text (a computer has no
//! camera to scan with).
//!
//! There is no emoji or number comparison step: the protocol has none. A QR
//! code carries a one-time 256-bit secret, and a code runs `CPace`, which a
//! wrong guess fails (five tries per offer). Both secrets are wiped when
//! the offer goes.

use gpui_kit::TestSupportExt as _;
use gpui_kit::component::input::Input;
use gpui_kit::component::radio::Radio;
use gpui_kit::{
    Context, FontWeight, InteractiveElement as _, IntoElement, ParentElement as _, Role,
    StatefulInteractiveElement as _, Styled as _, Window, div, px,
};
use todoke_core::api::{Request, Response};

use super::widgets::{self, heading, muted, section};
use super::{PairTab, Todoke};
use crate::format;
use crate::model::Pairing;
use crate::tokens::{self, space, text};

impl PairTab {
    const ALL: [Self; 4] = [Self::ShowQr, Self::ShowCode, Self::EnterCode, Self::PasteQr];

    const fn label(self) -> &'static str {
        match self {
            Self::ShowQr => "Show QR code",
            Self::ShowCode => "Show code",
            Self::EnterCode => "Enter code",
            Self::PasteQr => "Paste QR text",
        }
    }

    const fn id(self) -> &'static str {
        match self {
            Self::ShowQr => "tab-show-qr",
            Self::ShowCode => "tab-show-code",
            Self::EnterCode => "tab-enter-code",
            Self::PasteQr => "tab-paste-qr",
        }
    }
}

/// `m:ss` until `expires_at`.
fn countdown(expires_at: u64, now: u64) -> String {
    let left = expires_at.saturating_sub(now);
    format!("{}:{:02}", left / 60, left % 60)
}

impl Todoke {
    fn select_tab(&mut self, tab: PairTab, cx: &mut Context<Self>) {
        self.pair_tab = tab;
        if tab == PairTab::EnterCode {
            self.request(Request::Strangers, cx, |app, response, _| {
                app.model.answer(response);
                app.pick_stranger();
            });
        }
        cx.notify();
    }

    fn show_offer(&mut self, request: Request, cx: &mut Context<Self>) {
        self.model.pairing = Pairing::Requested;
        self.request(request, cx, |app, response, _| {
            if matches!(response, Response::Error { .. }) {
                app.model.pairing = Pairing::Idle;
            }
            app.model.answer(response);
        });
    }

    pub(super) fn stop_pairing(&mut self, cx: &mut Context<Self>) {
        self.model.pairing = Pairing::Idle;
        self.request(Request::StopPairing, cx, |app, response, _| {
            app.model.answer(response);
        });
    }

    pub(super) fn render_pairing(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> gpui_kit::AnyElement {
        let palette = tokens::palette(cx);
        let tabs = div()
            .id("pair-tabs")
            .role(Role::TabList)
            .aria_label("Ways to pair")
            .flex()
            .gap(px(space::S))
            .children(PairTab::ALL.into_iter().map(|tab| {
                let selected = self.pair_tab == tab;
                div()
                    .id(tab.id())
                    .role(Role::Tab)
                    .aria_label(tab.label())
                    .aria_selected(selected)
                    .tab_index(0)
                    .px(px(space::L))
                    .py(px(space::S))
                    .rounded_full()
                    .text_size(px(text::BODY))
                    .cursor_pointer()
                    .bg(tokens::color(if selected {
                        palette.accent
                    } else {
                        palette.surface
                    }))
                    .text_color(tokens::color(if selected {
                        palette.on_accent
                    } else {
                        palette.text
                    }))
                    .border_1()
                    .border_color(tokens::color(palette.border))
                    .on_click(cx.listener(move |this, _, _, cx| this.select_tab(tab, cx)))
                    .child(tab.label())
                    .test_support()
            }));
        let body = match self.pair_tab {
            PairTab::ShowQr => self.render_show_qr(cx).into_any_element(),
            PairTab::ShowCode => self.render_show_code(cx).into_any_element(),
            PairTab::EnterCode => self.render_enter_code(window, cx).into_any_element(),
            PairTab::PasteQr => self.render_paste_qr(cx).into_any_element(),
        };
        div()
            .flex()
            .flex_col()
            .gap(px(space::XL))
            .child(heading(
                "Pair a device",
                "Pairing makes a device a contact: only contacts can send you files, and every session proves who it is.",
                palette,
            ))
            .child(tabs)
            .child(body)
            .into_any_element()
    }

    fn render_show_qr(&mut self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let palette = tokens::palette(cx);
        let card = section("show-qr", "Scan this with the other device", palette);
        match &self.model.pairing {
            Pairing::Qr { text, expires_at } => {
                // Zeroized when the closures holding it go.
                let text = text.clone();
                let expires = countdown(*expires_at, self.now);
                card.child(
                    div()
                        .flex()
                        .gap(px(space::XL))
                        .items_start()
                        .child(
                            div()
                                .id("qr-code").test_support()
                                .role(Role::Image)
                                .aria_label("Pairing QR code. It is secret: show it only to the device you are pairing.")
                                .children(super::qr::code(text.as_str())),
                        )
                        .child(
                            div()
                                .flex()
                                .flex_col()
                                .gap(px(space::M))
                                .max_w(px(280.0))
                                .child(muted(
                                    "On the other device: Pair a device → Paste QR text, or scan it with a phone.",
                                    palette,
                                ))
                                .child(
                                    div()
                                        .id("qr-expires")
                                        .role(Role::Timer)
                                        .aria_label(format!("Expires in {expires}"))
                                        .child(format!("Expires in {expires}")),
                                )
                                .child(muted("This device is visible to everyone nearby until then.", palette))
                                .child(
                                    widgets::button(
                                        "copy-qr",
                                        "Copy as text",
                                        "Copy the QR code as text, for a device without a camera. The text is secret.",
                                    )
                                    .on_click(move |_, _, cx| {
                                        cx.write_to_clipboard(gpui_kit::ClipboardItem::new_string(text.to_string()));
                                    }),
                                )
                                .child(
                                    widgets::button("stop-pairing", "Stop", "Stop showing the pairing code")
                                        .on_click(cx.listener(|this, _, _, cx| this.stop_pairing(cx))),
                                ),
                        ),
                )
            }
            Pairing::Requested => card.child(muted("Making a pairing code…", palette)),
            _ => card
                .child(muted(
                    "A QR code works once and expires after 5 minutes. While it shows, nearby devices can see that this one is pairing.",
                    palette,
                ))
                .child(
                    widgets::primary("show-qr-button", "Show QR code", "Show a QR code for pairing")
                        .on_click(cx.listener(|this, _, _, cx| this.show_offer(Request::PairShowQr, cx))),
                ),
        }
    }

    fn render_show_code(&mut self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let palette = tokens::palette(cx);
        let card = section("show-code", "Enter this code on the other device", palette);
        match &self.model.pairing {
            Pairing::Code { code, expires_at } => {
                let shown = format!(
                    "{} {}",
                    code.get(..5).unwrap_or_default(),
                    code.get(5..).unwrap_or_default()
                );
                let spoken = code.chars().fold(String::new(), |mut out, c| {
                    out.push(c);
                    out.push(' ');
                    out
                });
                let expires = countdown(*expires_at, self.now);
                card.child(
                    div()
                        .id("pair-code").test_support()
                        .role(Role::Heading)
                        .aria_label(format!("Pairing code: {spoken}"))
                        .text_size(px(text::DISPLAY))
                        .font_weight(FontWeight::BOLD)
                        .font_family(gpui_kit::component::ActiveTheme::theme(&**cx).mono_font_family.clone())
                        .child(shown),
                )
                .child(
                    div()
                        .id("code-expires")
                        .role(Role::Timer)
                        .aria_label(format!("Expires in {expires}"))
                        .child(format!("Expires in {expires}")),
                )
                .child(muted(
                    "Visible to everyone nearby for 5 minutes (stranger mode). Five wrong tries end the code.",
                    palette,
                ))
                .child(
                    widgets::button("stop-pairing", "Stop", "Stop showing the pairing code")
                        .on_click(cx.listener(|this, _, _, cx| this.stop_pairing(cx))),
                )
            }
            Pairing::Requested => card.child(muted("Making a pairing code…", palette)),
            _ => card
                .child(muted(
                    "For devices on the same network. The code is good for 5 minutes, and this device is visible to everyone nearby while it shows.",
                    palette,
                ))
                .child(
                    widgets::primary("show-code-button", "Show code", "Show a ten-digit pairing code")
                        .on_click(cx.listener(|this, _, _, cx| this.show_offer(Request::PairShowCode, cx))),
                ),
        }
    }

    fn render_enter_code(
        &mut self,
        window: &mut Window,
        cx: &mut Context<Self>,
    ) -> impl IntoElement + use<> {
        let palette = tokens::palette(cx);
        let strangers = self.model.strangers.clone();
        let _ = window;
        let choices = if strangers.is_empty() {
            muted(
                "Looking for nearby devices showing a code… (same network, Show code on the other device)",
                palette,
            )
            .into_any_element()
        } else {
            div()
                .id("strangers")
                .role(Role::RadioGroup)
                .aria_label("Nearby devices showing a code")
                .flex()
                .flex_col()
                .gap(px(space::S))
                .children(strangers.iter().enumerate().map(|(index, stranger)| {
                    let token = stranger.stranger.clone();
                    let checked = self.stranger.as_ref() == Some(&token);
                    let label = format!(
                        "Nearby device {} ({})",
                        index + 1,
                        format::fingerprint(&token)
                            .chars()
                            .take(9)
                            .collect::<String>()
                    );
                    Radio::new(gpui_kit::ElementId::Name(
                        format!("stranger-{index}").into(),
                    ))
                    .label(label.clone())
                    .accessibility_label(label)
                    .checked(checked)
                    .on_click(cx.listener(move |this, _, _, cx| {
                        this.stranger = Some(token.clone());
                        cx.notify();
                    }))
                }))
                .into_any_element()
        };
        section("enter-code", "Enter the code another device shows", palette)
            .child(choices)
            .child(
                div()
                    .flex()
                    .gap(px(space::S))
                    .items_center()
                    .child(
                        div().w(px(220.0)).child(
                            Input::new(&self.code)
                                .id("code-input")
                                .aria_label("The ten-digit pairing code"),
                        ),
                    )
                    .child(
                        widgets::primary(
                            "pair-code",
                            "Pair",
                            "Pair with the chosen device using this code",
                        )
                        .on_click(cx.listener(|this, _, window, cx| this.enter_code(window, cx))),
                    ),
            )
            .child(muted(
                "Strangers advertise no identity; the code proves the device is the one you mean.",
                palette,
            ))
    }

    fn render_paste_qr(&mut self, cx: &mut Context<Self>) -> impl IntoElement + use<> {
        let palette = tokens::palette(cx);
        section("paste-qr", "Paste the other device's QR text", palette)
            .child(muted(
                "On the other device, show a QR code and choose Copy as text, then paste it here. It works across networks through a relay.",
                palette,
            ))
            .child(
                div()
                    .flex()
                    .gap(px(space::S))
                    .items_center()
                    .child(
                        div().flex_1().child(
                            Input::new(&self.qr_text)
                                .id("qr-input")
                                .aria_label("The pairing QR text, starting TODOKE:")
                                .mask_toggle(),
                        ),
                    )
                    .child(
                        widgets::primary("pair-qr", "Pair", "Pair with the device whose QR text was pasted")
                            .on_click(cx.listener(|this, _, window, cx| this.scan_qr(window, cx))),
                    ),
            )
    }
}
