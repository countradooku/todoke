//! A QR code drawn as quads: dark runs on white (always white, whatever the
//! theme, so phones can scan it), with a four-module quiet zone.

use gpui_kit::{
    Bounds, IntoElement, ParentElement as _, Styled as _, canvas, div, fill, point, px, size,
};

use crate::tokens;

/// A run of dark modules: row, first column, length.
pub type Run = (usize, usize, usize);

/// The dark modules of `text`'s QR code as runs `(row, first column,
/// length)`, and its width in modules.
#[must_use]
pub fn runs(text: &str) -> Option<(usize, Vec<Run>)> {
    let code = qrcode::QrCode::with_error_correction_level(text, qrcode::EcLevel::L).ok()?;
    let width = code.width();
    let colors = code.to_colors();
    let mut runs = Vec::new();
    for row in 0..width {
        let mut column = 0;
        while column < width {
            if colors[row * width + column] == qrcode::Color::Dark {
                let start = column;
                while column < width && colors[row * width + column] == qrcode::Color::Dark {
                    column += 1;
                }
                runs.push((row, start, column - start));
            } else {
                column += 1;
            }
        }
    }
    Some((width, runs))
}

/// The QR code of `text`, or nothing if it cannot be encoded.
#[must_use]
#[expect(
    clippy::cast_precision_loss,
    reason = "QR codes are at most 177 modules wide"
)]
pub fn code(text: &str) -> Option<impl IntoElement> {
    const QUIET: usize = 4;
    let (width, runs) = runs(text)?;
    let module = tokens::size::QR_MODULE;
    let side = (width + 2 * QUIET) as f32 * module;
    Some(
        div()
            .size(px(side))
            .flex_none()
            .bg(tokens::color(0x00FF_FFFF))
            .rounded(px(tokens::radius::M))
            .child(
                canvas(
                    |_, _, _| (),
                    move |bounds: Bounds<gpui_kit::Pixels>, (), window, _| {
                        let ink = tokens::color(0x0000_0000);
                        for (row, column, length) in &runs {
                            let origin = point(
                                bounds.origin.x + px((column + QUIET) as f32 * module),
                                bounds.origin.y + px((row + QUIET) as f32 * module),
                            );
                            let extent = size(px(*length as f32 * module), px(module));
                            window.paint_quad(fill(Bounds::new(origin, extent), ink));
                        }
                    },
                )
                .size_full(),
            ),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn runs_cover_the_dark_modules() {
        let (width, runs) = runs("TODOKE:EXAMPLE").unwrap_or_default();
        assert!(width >= 21);
        let dark: usize = runs.iter().map(|(_, _, length)| length).sum();
        let code =
            qrcode::QrCode::with_error_correction_level("TODOKE:EXAMPLE", qrcode::EcLevel::L);
        let expected = code
            .map(|code| {
                code.to_colors()
                    .iter()
                    .filter(|c| **c == qrcode::Color::Dark)
                    .count()
            })
            .unwrap_or_default();
        assert_eq!(dark, expected);
        assert!(runs.len() < expected, "runs merge neighbours");
    }
}
