//! Writes the packaged icons from the mark drawn in `todoke_desktop::icon`:
//! PNGs (16 to 1024 pixels), `todoke.ico` (Windows), `todoke.icns`
//! (macOS), and `todoke.svg` (Linux, scalable). Default directory
//! `packaging/icons`.
//!
//! `cargo run -p todoke-desktop --example icons --features mock [DIR]`

#![forbid(unsafe_code)]

use std::io::Cursor;
use std::path::Path;

use todoke_desktop::icon::{self, Style};

const SIZES: [u32; 9] = [16, 24, 32, 48, 64, 128, 256, 512, 1024];

fn png(size: u32) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let image = image::RgbaImage::from_raw(size, size, icon::rgba(size, Style::Color))
        .ok_or("the mark has the wrong size")?;
    let mut bytes = Cursor::new(Vec::new());
    image.write_to(&mut bytes, image::ImageFormat::Png)?;
    Ok(bytes.into_inner())
}

/// A Windows icon: PNG entries (Vista and later).
fn ico() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let sizes = [16_u32, 24, 32, 48, 64, 128, 256];
    let images: Vec<Vec<u8>> = sizes
        .iter()
        .map(|&size| png(size))
        .collect::<Result<_, _>>()?;
    let count = u16::try_from(sizes.len())?;
    let mut out = Vec::new();
    out.extend_from_slice(&[0, 0, 1, 0]);
    out.extend_from_slice(&count.to_le_bytes());
    let mut offset = 6 + 16 * u32::from(count);
    for (size, data) in sizes.iter().zip(&images) {
        // 256 is written as 0.
        let side = u8::try_from(*size % 256)?;
        out.extend_from_slice(&[side, side, 0, 0]);
        out.extend_from_slice(&1_u16.to_le_bytes());
        out.extend_from_slice(&32_u16.to_le_bytes());
        out.extend_from_slice(&u32::try_from(data.len())?.to_le_bytes());
        out.extend_from_slice(&offset.to_le_bytes());
        offset += u32::try_from(data.len())?;
    }
    for data in images {
        out.extend_from_slice(&data);
    }
    Ok(out)
}

/// A macOS icon: PNG entries of each type.
fn icns() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let types: [(&[u8; 4], u32); 10] = [
        (b"icp4", 16),
        (b"icp5", 32),
        (b"icp6", 64),
        (b"ic07", 128),
        (b"ic08", 256),
        (b"ic09", 512),
        (b"ic10", 1024),
        (b"ic11", 32),
        (b"ic12", 64),
        (b"ic13", 256),
    ];
    let mut body = Vec::new();
    for (kind, size) in types {
        let data = png(size)?;
        body.extend_from_slice(kind);
        body.extend_from_slice(&u32::try_from(data.len() + 8)?.to_be_bytes());
        body.extend_from_slice(&data);
    }
    let mut out = b"icns".to_vec();
    out.extend_from_slice(&u32::try_from(body.len() + 8)?.to_be_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// The same geometry as `icon::rgba`, in a 100-unit box.
fn svg() -> String {
    let [_, red, green, blue] = todoke_desktop::tokens::LIGHT.accent.to_be_bytes();
    format!(
        concat!(
            "<svg xmlns=\"http://www.w3.org/2000/svg\" viewBox=\"0 0 100 100\" width=\"256\" height=\"256\">\n",
            "  <rect x=\"6\" y=\"6\" width=\"88\" height=\"88\" rx=\"22\" fill=\"#{:02x}{:02x}{:02x}\"/>\n",
            "  <path d=\"M24 42.5H56V57.5H24Z M50 28L78 50L50 72Z\" fill=\"#ffffff\"/>\n",
            "</svg>\n"
        ),
        red, green, blue
    )
}

fn write(dir: &Path) -> Result<(), Box<dyn std::error::Error>> {
    std::fs::create_dir_all(dir)?;
    for size in SIZES {
        std::fs::write(dir.join(format!("todoke-{size}.png")), png(size)?)?;
    }
    std::fs::write(dir.join("todoke.ico"), ico()?)?;
    std::fs::write(dir.join("todoke.icns"), icns()?)?;
    std::fs::write(dir.join("todoke.svg"), svg())?;
    Ok(())
}

fn main() {
    let dir = std::env::args_os()
        .nth(1)
        .map_or_else(|| "packaging/icons".into(), std::path::PathBuf::from);
    if let Err(error) = write(&dir) {
        eprintln!("icons: {error}");
        std::process::exit(1);
    }
    println!("{}", dir.display());
}
