//! Design tokens: every color, space, radius, type size, and duration the
//! app uses is defined here and nowhere else. Views read them through
//! [`palette`] and the constants; [`apply`] carries the palette into the
//! component library's theme so its controls match.
//!
//! Colors are sRGB hex. Every text color meets WCAG 2.2 AA (4.5:1) on the
//! surfaces it is drawn on, in both themes; the tests check it.

use core::time::Duration;

/// One theme's colors.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Palette {
    /// The window behind everything.
    pub background: u32,
    /// Cards, sheets, and the sidebar.
    pub surface: u32,
    /// Hovered and selected rows; inputs.
    pub raised: u32,
    /// Hairlines between regions.
    pub border: u32,
    /// Body text.
    pub text: u32,
    /// Secondary text: captions, hints, metadata.
    pub muted: u32,
    /// The accent: primary actions, focus, progress.
    pub accent: u32,
    /// Text on the accent.
    pub on_accent: u32,
    /// Verified, delivered, direct.
    pub success: u32,
    /// Relayed, waiting, needs attention.
    pub warning: u32,
    /// Failed, declined, destructive actions.
    pub danger: u32,
    /// Text on success, warning, and danger fills.
    pub on_status: u32,
    /// Avatar fills, picked by device key.
    pub avatars: [u32; 8],
}

/// The light theme.
pub const LIGHT: Palette = Palette {
    background: 0x00F6_F7F9,
    surface: 0x00FF_FFFF,
    raised: 0x00EE_F0F4,
    border: 0x00DC_DFE6,
    text: 0x0011_1318,
    muted: 0x0052_5866,
    accent: 0x0032_4FD1,
    on_accent: 0x00FF_FFFF,
    success: 0x0017_7A3A,
    warning: 0x009A_5200,
    danger: 0x00C2_2525,
    on_status: 0x00FF_FFFF,
    avatars: [
        0x0032_4FD1,
        0x0017_7A3A,
        0x009A_5200,
        0x00B0_2A6F,
        0x0006_7A8A,
        0x006E_44C9,
        0x00A3_3B1E,
        0x0045_5466,
    ],
};

/// The dark theme.
pub const DARK: Palette = Palette {
    background: 0x000E_1014,
    surface: 0x0017_1A21,
    raised: 0x0020_242D,
    border: 0x002E_333E,
    text: 0x00EC_EEF2,
    muted: 0x00A6_ACB8,
    accent: 0x008C_A6FF,
    on_accent: 0x000E_1014,
    success: 0x006B_D88A,
    warning: 0x00F2_B84B,
    danger: 0x00FF_8A8A,
    on_status: 0x000E_1014,
    avatars: [
        0x008C_A6FF,
        0x006B_D88A,
        0x00F2_B84B,
        0x00F0_8BC0,
        0x005E_D0DE,
        0x00B9_A0FF,
        0x00FF_A47A,
        0x00A9_B4C4,
    ],
};

/// The palette for a theme.
#[must_use]
pub const fn palette_for(dark: bool) -> &'static Palette {
    if dark { &DARK } else { &LIGHT }
}

/// Spacing, in pixels: a 4-pixel scale.
pub mod space {
    /// Between an icon and its label.
    pub const XS: f32 = 4.0;
    /// Inside compact controls.
    pub const S: f32 = 8.0;
    /// Between related items.
    pub const M: f32 = 12.0;
    /// Card padding; between groups.
    pub const L: f32 = 16.0;
    /// Between sections.
    pub const XL: f32 = 24.0;
    /// Page margins.
    pub const XXL: f32 = 32.0;
}

/// Corner radii, in pixels.
pub mod radius {
    /// Badges and small controls.
    pub const S: f32 = 6.0;
    /// Buttons, inputs, rows.
    pub const M: f32 = 10.0;
    /// Cards, sheets, the drop zone.
    pub const L: f32 = 16.0;
}

/// Type sizes, in pixels.
pub mod text {
    /// Captions and badges.
    pub const CAPTION: f32 = 12.0;
    /// Body text and controls.
    pub const BODY: f32 = 14.0;
    /// Row titles.
    pub const TITLE: f32 = 16.0;
    /// Page headings.
    pub const HEADING: f32 = 22.0;
    /// The pairing code.
    pub const DISPLAY: f32 = 34.0;
}

/// Sizes of fixed elements, in pixels.
pub mod size {
    /// The navigation sidebar's width.
    pub const SIDEBAR: f32 = 208.0;
    /// A contact avatar.
    pub const AVATAR: f32 = 56.0;
    /// A contact tile (avatar and label).
    pub const TILE: f32 = 144.0;
    /// The proximity dot on an avatar.
    pub const DOT: f32 = 14.0;
    /// A progress bar's height.
    pub const BAR: f32 = 6.0;
    /// One QR module.
    pub const QR_MODULE: f32 = 5.0;
    /// The receive sheet's width.
    pub const SHEET: f32 = 440.0;
    /// The smallest window.
    pub const MIN_WINDOW: (f32, f32) = (720.0, 520.0);
    /// The first window.
    pub const WINDOW: (f32, f32) = (1040.0, 700.0);
}

/// Motion. Every animation is GPU-driven by the frame clock (120 Hz on
/// displays that offer it) and skipped when the system asks for reduced
/// motion.
pub mod motion {
    use super::Duration;

    /// Hover and press feedback.
    pub const FAST: Duration = Duration::from_millis(120);
    /// Sheets, progress, and selection.
    pub const NORMAL: Duration = Duration::from_millis(200);
    /// The drop zone's pulse while files hover over it.
    pub const PULSE: Duration = Duration::from_millis(1200);
}

/// How long the receive sheet's decisions stay disabled after it appears,
/// so a click aimed at what was there before cannot accept an offer.
pub const DECISION_DELAY: Duration = Duration::from_millis(700);

/// How often the app refreshes contacts and transfers (proximity changes
/// carry no event).
pub const REFRESH: Duration = Duration::from_secs(2);

/// How long a notice stays.
pub const NOTICE: Duration = Duration::from_secs(6);

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
mod gpui_tokens {
    use gpui_kit::component::{Theme, ThemeMode};
    use gpui_kit::{App, Hsla, rgb};

    use super::{Palette, palette_for};

    /// A token color for GPUI.
    #[must_use]
    pub fn color(hex: u32) -> Hsla {
        rgb(hex).into()
    }

    /// The palette of the current theme.
    #[must_use]
    pub fn palette(cx: &App) -> &'static Palette {
        palette_for(Theme::global(cx).mode == ThemeMode::Dark)
    }

    /// Carries `palette` into the component library's theme.
    pub fn apply(palette: &Palette, theme: &mut Theme) {
        let c = color;
        theme.background = c(palette.background);
        theme.foreground = c(palette.text);
        theme.border = c(palette.border);
        theme.muted = c(palette.raised);
        theme.muted_foreground = c(palette.muted);
        theme.primary = c(palette.accent);
        theme.primary_hover = c(palette.accent).opacity(0.9);
        theme.primary_active = c(palette.accent).opacity(0.8);
        theme.primary_foreground = c(palette.on_accent);
        theme.button_primary = c(palette.accent);
        theme.button_primary_hover = c(palette.accent).opacity(0.9);
        theme.button_primary_active = c(palette.accent).opacity(0.8);
        theme.button_primary_foreground = c(palette.on_accent);
        theme.ring = c(palette.accent);
        theme.caret = c(palette.accent);
        theme.selection = c(palette.accent).opacity(0.25);
        theme.progress_bar = c(palette.accent);
        theme.link = c(palette.accent);
        theme.success = c(palette.success);
        theme.success_foreground = c(palette.on_status);
        theme.warning = c(palette.warning);
        theme.warning_foreground = c(palette.on_status);
        theme.danger = c(palette.danger);
        theme.danger_foreground = c(palette.on_status);
        theme.button_danger = c(palette.danger);
        theme.button_danger_foreground = c(palette.on_status);
        theme.popover = c(palette.surface);
        theme.popover_foreground = c(palette.text);
        theme.sidebar = c(palette.surface);
        theme.sidebar_foreground = c(palette.text);
        theme.sidebar_border = c(palette.border);
        theme.sidebar_accent = c(palette.raised);
        theme.sidebar_accent_foreground = c(palette.text);
        theme.sidebar_primary = c(palette.accent);
        theme.sidebar_primary_foreground = c(palette.on_accent);
        theme.input = c(palette.border);
        theme.list_hover = c(palette.raised);
        theme.list_active = c(palette.accent).opacity(0.15);
        theme.list_active_border = c(palette.accent);
        theme.switch = c(palette.border);
        theme.drop_target = c(palette.accent).opacity(0.12);
        theme.drag_border = c(palette.accent);
        theme.overlay = c(0x0000_0000).opacity(0.45);
    }

    /// Switches to `mode` and applies the token palette.
    pub fn set_mode(mode: ThemeMode, cx: &mut App) {
        Theme::change(mode, None, cx);
        Theme::update(cx, |theme| apply(palette_for(mode.is_dark()), theme));
        cx.refresh_windows();
    }
}

#[cfg(any(target_os = "macos", target_os = "windows", target_os = "linux"))]
pub use gpui_tokens::{apply, color, palette, set_mode};

#[cfg(test)]
mod tests {
    use super::*;

    /// WCAG relative luminance of an sRGB color.
    fn luminance(hex: u32) -> f64 {
        let channel = |shift: u32| {
            let value = f64::from((hex >> shift) & 0xff) / 255.0;
            if value <= 0.040_45 {
                value / 12.92
            } else {
                ((value + 0.055) / 1.055).powf(2.4)
            }
        };
        0.2126 * channel(16) + 0.7152 * channel(8) + 0.0722 * channel(0)
    }

    fn contrast(a: u32, b: u32) -> f64 {
        let (a, b) = (luminance(a), luminance(b));
        (a.max(b) + 0.05) / (a.min(b) + 0.05)
    }

    /// Text meets WCAG AA on every surface it is drawn on, in both themes.
    #[test]
    fn text_meets_wcag_aa() {
        for palette in [LIGHT, DARK] {
            for surface in [palette.background, palette.surface, palette.raised] {
                for text in [palette.text, palette.muted] {
                    let ratio = contrast(text, surface);
                    assert!(ratio >= 4.5, "{text:06x} on {surface:06x}: {ratio:.2}");
                }
                for status in [
                    palette.accent,
                    palette.success,
                    palette.warning,
                    palette.danger,
                ] {
                    let ratio = contrast(status, surface);
                    assert!(ratio >= 4.5, "{status:06x} on {surface:06x}: {ratio:.2}");
                }
            }
            let on_accent = contrast(palette.on_accent, palette.accent);
            assert!(on_accent >= 4.5, "on accent: {on_accent:.2}");
            for fill in [palette.success, palette.warning, palette.danger] {
                let ratio = contrast(palette.on_status, fill);
                assert!(ratio >= 4.5, "on {fill:06x}: {ratio:.2}");
            }
            for avatar in palette.avatars {
                let ratio = contrast(palette.on_accent, avatar);
                assert!(ratio >= 4.5, "avatar {avatar:06x}: {ratio:.2}");
            }
        }
    }

    #[test]
    fn spacing_is_on_the_four_pixel_grid() {
        for value in [
            space::XS,
            space::S,
            space::M,
            space::L,
            space::XL,
            space::XXL,
        ] {
            assert!((value % 4.0).abs() < f32::EPSILON, "{value}");
        }
    }
}
