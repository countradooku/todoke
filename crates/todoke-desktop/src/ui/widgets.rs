//! Small pieces the pages share. Every color, space, and size comes from
//! [`crate::tokens`].

use gpui_kit::assets::IconName;
use gpui_kit::component::button::{Button, ButtonVariants as _};
use gpui_kit::component::{Icon, Sizable as _};
use gpui_kit::prelude::FluentBuilder as _;
use gpui_kit::{
    AnyElement, App, Div, FontWeight, InteractiveElement as _, IntoElement, ParentElement as _,
    Role, SharedString, StatefulInteractiveElement as _, Styled as _, div, px,
};

use crate::format;
use crate::model::{Level, Model, Proximity};
use crate::tokens::{self, Palette, radius, size, space, text};

/// A button with a visible label and a screen-reader label.
pub fn button(
    id: impl Into<SharedString>,
    label: impl Into<SharedString>,
    spoken: impl Into<SharedString>,
) -> Button {
    let id: SharedString = id.into();
    Button::new(gpui_kit::ElementId::Name(id))
        .label(label)
        .accessibility_label(spoken)
}

/// The primary button of a view.
pub fn primary(
    id: impl Into<SharedString>,
    label: impl Into<SharedString>,
    spoken: impl Into<SharedString>,
) -> Button {
    button(id, label, spoken).primary()
}

/// A count in a pill (navigation badges).
pub fn count(value: usize, palette: &Palette) -> Div {
    div()
        .min_w(px(20.0))
        .px(px(6.0))
        .rounded_full()
        .bg(tokens::color(palette.accent))
        .text_color(tokens::color(palette.on_accent))
        .text_size(px(text::CAPTION))
        .flex()
        .justify_center()
        .child(value.to_string())
}

/// A small labeled pill.
pub fn badge(label: impl Into<SharedString>, fill: u32, palette: &Palette) -> Div {
    div()
        .px(px(space::S))
        .py(px(2.0))
        .rounded(px(radius::S))
        .bg(tokens::color(fill))
        .text_color(tokens::color(palette.on_status))
        .text_size(px(text::CAPTION))
        .font_weight(FontWeight::MEDIUM)
        .child(label.into())
}

/// The color of a proximity.
pub const fn proximity_color(proximity: Proximity, palette: &Palette) -> u32 {
    match proximity {
        Proximity::Direct => palette.success,
        Proximity::Remote => palette.warning,
        Proximity::Offline => palette.muted,
        Proximity::Blocked => palette.danger,
    }
}

/// A device's avatar: its initials on its color, with a proximity dot.
pub fn avatar(device: &str, proximity: Option<Proximity>, palette: &Palette) -> Div {
    let fill = palette.avatars[format::avatar_index(device)];
    div()
        .relative()
        .size(px(size::AVATAR))
        .flex_none()
        .child(
            div()
                .size_full()
                .rounded_full()
                .bg(tokens::color(fill))
                .text_color(tokens::color(palette.on_accent))
                .text_size(px(text::TITLE))
                .font_weight(FontWeight::BOLD)
                .flex()
                .items_center()
                .justify_center()
                .child(format::initials(device)),
        )
        .when_some(proximity, |avatar, proximity| {
            avatar.child(
                div()
                    .absolute()
                    .right(px(0.0))
                    .bottom(px(0.0))
                    .size(px(size::DOT))
                    .rounded_full()
                    .border_2()
                    .border_color(tokens::color(palette.surface))
                    .bg(tokens::color(proximity_color(proximity, palette))),
            )
        })
}

/// An icon at body size.
pub fn icon(name: IconName, color: u32) -> Icon {
    Icon::new(name).small().text_color(tokens::color(color))
}

/// A progress bar. Its fill follows the fraction; an indeterminate bar
/// (nothing measured yet) pulses.
pub fn progress(
    id: impl Into<SharedString>,
    fraction: Option<f32>,
    palette: &Palette,
) -> AnyElement {
    let id: SharedString = id.into();
    let track = div()
        .h(px(size::BAR))
        .w_full()
        .rounded_full()
        .bg(tokens::color(palette.raised))
        .overflow_hidden();
    if let Some(fraction) = fraction {
        track
            .child(
                div()
                    .h_full()
                    .w(gpui_kit::relative(fraction.clamp(0.0, 1.0)))
                    .rounded_full()
                    .bg(tokens::color(palette.accent)),
            )
            .into_any_element()
    } else {
        {
            use gpui_kit::{Animation, AnimationExt as _, pulsating_between};
            track
                .child(
                    div()
                        .h_full()
                        .w_full()
                        .rounded_full()
                        .bg(tokens::color(palette.accent))
                        .with_animation(
                            gpui_kit::ElementId::Name(id),
                            Animation::new(tokens::motion::PULSE)
                                .repeat()
                                .with_easing(pulsating_between(0.25, 0.7)),
                            gpui_kit::Styled::opacity,
                        ),
                )
                .into_any_element()
        }
    }
}

/// A titled card.
pub fn section(
    id: impl Into<SharedString>,
    title: impl Into<SharedString>,
    palette: &Palette,
) -> gpui_kit::Stateful<Div> {
    let title: SharedString = title.into();
    div()
        .id(gpui_kit::ElementId::Name(id.into()))
        .role(Role::Group)
        .aria_label(title.clone())
        .flex()
        .flex_col()
        .gap(px(space::M))
        .p(px(space::L))
        .rounded(px(radius::L))
        .bg(tokens::color(palette.surface))
        .border_1()
        .border_color(tokens::color(palette.border))
        .child(
            div()
                .text_size(px(text::TITLE))
                .font_weight(FontWeight::SEMIBOLD)
                .child(title),
        )
}

/// A page heading with a short description.
pub fn heading(title: &'static str, detail: impl Into<SharedString>, palette: &Palette) -> Div {
    div()
        .flex()
        .flex_col()
        .gap(px(space::XS))
        .pb(px(space::XL))
        .child(
            div()
                .id(title)
                .role(Role::Heading)
                .aria_label(title)
                .text_size(px(text::HEADING))
                .font_weight(FontWeight::BOLD)
                .child(title),
        )
        .child(
            div()
                .text_size(px(text::BODY))
                .text_color(tokens::color(palette.muted))
                .child(detail.into()),
        )
}

/// Secondary text.
pub fn muted(content: impl Into<SharedString>, palette: &Palette) -> Div {
    div()
        .text_size(px(text::BODY))
        .text_color(tokens::color(palette.muted))
        .child(content.into())
}

/// Monospaced text (keys, hashes), selectable by its own copy button.
pub fn mono(content: impl Into<SharedString>, cx: &App) -> Div {
    use gpui_kit::component::ActiveTheme as _;
    div()
        .font_family(cx.theme().mono_font_family.clone())
        .text_size(px(text::CAPTION))
        .child(content.into())
}

/// Monospaced text in `family`.
pub fn mono_in(content: impl Into<SharedString>, family: SharedString) -> Div {
    div()
        .font_family(family)
        .text_size(px(text::CAPTION))
        .child(content.into())
}

/// A copy button for `value` (hashes and keys; never a secret unless the
/// caller says so in `spoken`).
pub fn copy(id: impl Into<SharedString>, value: String, spoken: impl Into<SharedString>) -> Button {
    let id: SharedString = id.into();
    Button::new(gpui_kit::ElementId::Name(id))
        .ghost()
        .xsmall()
        .icon(gpui_kit::component::IconName::Copy)
        .accessibility_label(spoken)
        .tooltip("Copy")
        .on_click(move |_, _, cx| {
            cx.write_to_clipboard(gpui_kit::ClipboardItem::new_string(value.clone()));
        })
}

/// The notices, bottom right, newest last.
pub fn notices(model: &Model, cx: &App) -> Div {
    let palette = tokens::palette(cx);
    div()
        .absolute()
        .right(px(space::L))
        .bottom(px(space::L))
        .flex()
        .flex_col()
        .gap(px(space::S))
        .max_w(px(380.0))
        .children(model.notices.iter().map(|notice| {
            let fill = match notice.level {
                Level::Info => palette.surface,
                Level::Success => palette.success,
                Level::Error => palette.danger,
            };
            let ink = if notice.level == Level::Info {
                palette.text
            } else {
                palette.on_status
            };
            div()
                .id(gpui_kit::ElementId::Name(
                    format!("notice-{}", notice.id).into(),
                ))
                .role(if notice.level == Level::Error {
                    Role::Alert
                } else {
                    Role::Status
                })
                .aria_label(notice.text.clone())
                .px(px(space::L))
                .py(px(space::M))
                .rounded(px(radius::M))
                .bg(tokens::color(fill))
                .border_1()
                .border_color(tokens::color(palette.border))
                .text_color(tokens::color(ink))
                .text_size(px(text::BODY))
                .shadow_md()
                .child(notice.text.clone())
        }))
}
