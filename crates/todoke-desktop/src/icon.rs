//! The todoke mark, drawn in code: an arrow on the accent color (the app
//! icon and the Windows and Linux tray), or a black arrow in a ring that the
//! system tints (the macOS menu bar). One drawing feeds the tray and the
//! packaged icons (`examples/icons.rs`), so they cannot drift apart.

use crate::tokens;

/// Which drawing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Style {
    /// White arrow on an accent rounded square.
    Color,
    /// Black arrow in a ring on transparent (a macOS template image).
    Template,
}

/// Samples per pixel along each axis (antialiasing).
const SAMPLES: u32 = 4;

/// The mark as `size` × `size` RGBA pixels, rows top to bottom.
#[must_use]
pub fn rgba(size: u32, style: Style) -> Vec<u8> {
    let accent = tokens::LIGHT.accent;
    let [_, red, green, blue] = accent.to_be_bytes();
    let mut pixels = Vec::with_capacity((size * size * 4) as usize);
    let scale = f64::from(size * SAMPLES);
    for row in 0..size {
        for column in 0..size {
            let (mut back, mut front) = (0_u32, 0_u32);
            for sy in 0..SAMPLES {
                for sx in 0..SAMPLES {
                    let x = f64::from(column * SAMPLES + sx) / scale + 0.5 / scale;
                    let y = f64::from(row * SAMPLES + sy) / scale + 0.5 / scale;
                    match style {
                        Style::Color => {
                            if rounded_square(x, y) {
                                back += 1;
                                if arrow(x, y) {
                                    front += 1;
                                }
                            }
                        }
                        Style::Template => {
                            if ring(x, y) || arrow(x, y) {
                                front += 1;
                            }
                        }
                    }
                }
            }
            let total = SAMPLES * SAMPLES;
            let alpha = |count: u32| u8::try_from(count * 255 / total).unwrap_or(u8::MAX);
            match style {
                Style::Color => {
                    // White over the accent, by coverage.
                    let mix = |base: u8| {
                        let base = u32::from(base);
                        let mixed = (base * (back - front) + 255 * front) / back.max(1);
                        u8::try_from(mixed).unwrap_or(u8::MAX)
                    };
                    pixels.extend_from_slice(&[mix(red), mix(green), mix(blue), alpha(back)]);
                }
                Style::Template => pixels.extend_from_slice(&[0, 0, 0, alpha(front)]),
            }
        }
    }
    pixels
}

/// The background: a square inset by 6% with 22% corners.
fn rounded_square(x: f64, y: f64) -> bool {
    const INSET: f64 = 0.06;
    const RADIUS: f64 = 0.22;
    let (low, high) = (INSET + RADIUS, 1.0 - INSET - RADIUS);
    let dx = (low - x).max(x - high).max(0.0);
    let dy = (low - y).max(y - high).max(0.0);
    (INSET..=1.0 - INSET).contains(&x)
        && (INSET..=1.0 - INSET).contains(&y)
        && dx * dx + dy * dy <= RADIUS * RADIUS
}

/// The arrow, pointing right: a shaft and a head.
fn arrow(x: f64, y: f64) -> bool {
    let shaft = (0.24..=0.56).contains(&x) && (y - 0.5).abs() <= 0.075;
    // The head: x from 0.50 to 0.78, narrowing from ±0.22 to a point.
    let head = (0.50..=0.78).contains(&x) && (y - 0.5).abs() <= 0.22 * (0.78 - x) / 0.28;
    shaft || head
}

/// The template's ring.
fn ring(x: f64, y: f64) -> bool {
    let distance = ((x - 0.5).powi(2) + (y - 0.5).powi(2)).sqrt();
    (0.40..=0.47).contains(&distance)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(pixels: &[u8], size: u32, x: u32, y: u32) -> [u8; 4] {
        let start = ((y * size + x) * 4) as usize;
        [
            pixels[start],
            pixels[start + 1],
            pixels[start + 2],
            pixels[start + 3],
        ]
    }

    #[test]
    fn the_mark_has_its_parts_where_they_belong() {
        let color = rgba(64, Style::Color);
        assert_eq!(color.len(), 64 * 64 * 4);
        // Corners are transparent; the arrow is white; beside it, accent.
        assert_eq!(at(&color, 64, 0, 0)[3], 0);
        assert_eq!(at(&color, 64, 40, 32), [255, 255, 255, 255]);
        let [_, red, green, blue] = tokens::LIGHT.accent.to_be_bytes();
        assert_eq!(at(&color, 64, 32, 12), [red, green, blue, 255]);
        let template = rgba(32, Style::Template);
        assert!(template.chunks(4).all(|pixel| pixel[..3] == [0, 0, 0]));
        assert_eq!(at(&template, 32, 0, 0)[3], 0);
        assert_eq!(at(&template, 32, 20, 16)[3], 255);
    }
}
