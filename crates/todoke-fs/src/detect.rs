//! The real type of received content, from its first bytes (magic
//! numbers), compared with the claimed MIME label and extension.
//!
//! Runs only on content that passed verification (after the whole-file
//! check at publication), so it never gates consent: content does not
//! exist before Accept (§7.2). It reads at most [`SNIFF_LEN`] bytes, runs
//! no parser beyond fixed signature comparisons, and never opens,
//! previews, or executes anything (previews are `todoke-preview`'s, P23).
//! Its results are warnings for the UI.

use crate::name::extension::{ExtensionRisk, Platforms, RiskKind, final_extension, is_known};

/// How many leading bytes [`detect`] looks at: enough for an ISO 9660
/// volume descriptor at offset 0x8001.
pub const SNIFF_LEN: usize = 36 * 1024;

/// A content type recognized by its signature.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DetectedType {
    /// Windows PE or DOS executable (`MZ`).
    WindowsExecutable,
    /// ELF executable or library.
    Elf,
    /// Mach-O executable or library, thin or universal.
    MachO,
    /// Java class file.
    JavaClass,
    /// Android DEX bytecode.
    Dex,
    /// WebAssembly module.
    Wasm,
    /// A script with a `#!` interpreter line.
    Shebang,
    /// Windows shell link (`.lnk`).
    ShellLink,
    /// OLE compound file: MSI installers and legacy Office documents.
    CompoundFile,
    /// Microsoft cabinet archive.
    Cabinet,
    /// macOS installer package (xar).
    Xar,
    /// Debian package.
    Deb,
    /// RPM package.
    Rpm,
    /// PDF document.
    Pdf,
    /// Rich Text Format.
    Rtf,
    /// PNG image.
    Png,
    /// JPEG image.
    Jpeg,
    /// GIF image.
    Gif,
    /// WebP image.
    Webp,
    /// BMP image.
    Bmp,
    /// TIFF image.
    Tiff,
    /// Windows icon or cursor.
    Icon,
    /// HEIF/HEIC image.
    Heif,
    /// AVIF image.
    Avif,
    /// MP4 family video (ISO base media).
    Mp4,
    /// Apple `QuickTime` movie.
    QuickTime,
    /// MPEG-4 audio.
    M4a,
    /// MP3 audio.
    Mp3,
    /// WAVE audio.
    Wav,
    /// AVI video.
    Avi,
    /// Ogg container.
    Ogg,
    /// FLAC audio.
    Flac,
    /// Matroska or `WebM`.
    Matroska,
    /// ZIP archive, including Office Open XML, `OpenDocument`, JAR, APK,
    /// IPA, EPUB, and MSIX packages.
    Zip,
    /// RAR archive.
    Rar,
    /// 7-Zip archive.
    SevenZip,
    /// gzip stream.
    Gzip,
    /// bzip2 stream.
    Bzip2,
    /// xz stream.
    Xz,
    /// Zstandard frame.
    Zstd,
    /// ISO 9660 disc image.
    Iso9660,
    /// SQLite database.
    Sqlite,
    /// HTML document.
    Html,
    /// SVG image (XML that can carry script).
    Svg,
    /// Other XML.
    Xml,
}

/// What a detected type is, broadly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Category {
    /// Native code, bytecode, scripts, installers, and shell links.
    Executable,
    /// Images.
    Image,
    /// Audio.
    Audio,
    /// Video.
    Video,
    /// Documents.
    Document,
    /// Archives, compressed streams, and disc images.
    Archive,
    /// Markup that can run script when opened.
    ActiveContent,
    /// Other structured data.
    Data,
}

impl DetectedType {
    /// The broad category.
    #[must_use]
    pub const fn category(self) -> Category {
        match self {
            Self::WindowsExecutable
            | Self::Elf
            | Self::MachO
            | Self::JavaClass
            | Self::Dex
            | Self::Wasm
            | Self::Shebang
            | Self::ShellLink
            | Self::Xar
            | Self::Deb
            | Self::Rpm => Category::Executable,
            Self::Png
            | Self::Jpeg
            | Self::Gif
            | Self::Webp
            | Self::Bmp
            | Self::Tiff
            | Self::Icon
            | Self::Heif
            | Self::Avif => Category::Image,
            Self::M4a | Self::Mp3 | Self::Wav | Self::Flac => Category::Audio,
            Self::Mp4 | Self::QuickTime | Self::Avi | Self::Matroska | Self::Ogg => Category::Video,
            Self::Pdf | Self::Rtf | Self::CompoundFile => Category::Document,
            Self::Zip
            | Self::Rar
            | Self::SevenZip
            | Self::Gzip
            | Self::Bzip2
            | Self::Xz
            | Self::Zstd
            | Self::Cabinet
            | Self::Iso9660 => Category::Archive,
            Self::Html | Self::Svg => Category::ActiveContent,
            Self::Xml | Self::Sqlite => Category::Data,
        }
    }

    /// Where content of this type runs code or installs software.
    #[must_use]
    pub const fn risk(self) -> Option<ExtensionRisk> {
        let (kind, platforms) = match self {
            Self::WindowsExecutable => (RiskKind::Executable, Platforms::WINDOWS),
            Self::Elf => (
                RiskKind::Executable,
                Platforms::LINUX.union(Platforms::ANDROID),
            ),
            Self::MachO => (RiskKind::Executable, Platforms::MACOS.union(Platforms::IOS)),
            Self::JavaClass => (RiskKind::Executable, Platforms::DESKTOP),
            Self::Dex => (RiskKind::Executable, Platforms::ANDROID),
            Self::Wasm => (RiskKind::Executable, Platforms::ALL),
            Self::Shebang => (RiskKind::Script, Platforms::MACOS.union(Platforms::LINUX)),
            Self::ShellLink => (RiskKind::Shortcut, Platforms::WINDOWS),
            Self::Xar => (RiskKind::Installer, Platforms::MACOS),
            Self::Deb | Self::Rpm => (RiskKind::Installer, Platforms::LINUX),
            Self::Cabinet => (RiskKind::Installer, Platforms::WINDOWS),
            Self::Iso9660 => (
                RiskKind::DiskImage,
                Platforms::WINDOWS.union(Platforms::MACOS),
            ),
            Self::Html | Self::Svg => (RiskKind::ActiveContent, Platforms::ALL),
            _ => return None,
        };
        Some(ExtensionRisk { kind, platforms })
    }

    /// Extensions content of this type legitimately has (lowercase).
    #[must_use]
    pub const fn extensions(self) -> &'static [&'static str] {
        match self {
            Self::WindowsExecutable => &[
                "exe", "dll", "sys", "scr", "com", "cpl", "ocx", "efi", "drv", "mui", "xll", "pif",
            ],
            Self::Elf => &["so", "bin", "run", "appimage", "elf", "o", "ko", "out"],
            Self::MachO => &["dylib", "bundle", "o", "so", "out"],
            Self::JavaClass => &["class"],
            Self::Dex => &["dex"],
            Self::Wasm => &["wasm"],
            Self::Shebang => &[
                "sh", "bash", "zsh", "py", "pl", "rb", "command", "tool", "fish", "ksh", "csh",
                "php", "js",
            ],
            Self::ShellLink => &["lnk"],
            Self::CompoundFile => &[
                "msi", "msp", "mst", "doc", "dot", "xls", "xlt", "ppt", "pot", "pps", "msg", "vsd",
                "pub",
            ],
            Self::Cabinet => &["cab", "msu"],
            Self::Xar => &["pkg", "mpkg", "xar", "xip"],
            Self::Deb => &["deb", "udeb"],
            Self::Rpm => &["rpm"],
            Self::Pdf => &["pdf", "ai"],
            Self::Rtf => &["rtf", "doc"],
            Self::Png => &["png", "apng"],
            Self::Jpeg => &["jpg", "jpeg", "jpe", "jfif"],
            Self::Gif => &["gif"],
            Self::Webp => &["webp"],
            Self::Bmp => &["bmp", "dib"],
            Self::Tiff => &["tif", "tiff", "dng", "cr2", "nef", "arw"],
            Self::Icon => &["ico", "cur"],
            Self::Heif => &["heic", "heif", "hif"],
            Self::Avif => &["avif"],
            Self::Mp4 => &["mp4", "m4v", "3gp", "3g2", "mov", "m4a", "f4v"],
            Self::QuickTime => &["mov", "qt"],
            Self::M4a => &["m4a", "m4b", "m4r", "mp4"],
            Self::Mp3 => &["mp3"],
            Self::Wav => &["wav", "wave"],
            Self::Avi => &["avi"],
            Self::Ogg => &["ogg", "oga", "ogv", "opus", "spx"],
            Self::Flac => &["flac"],
            Self::Matroska => &["mkv", "mka", "webm", "mk3d"],
            Self::Zip => &[
                "zip",
                "docx",
                "docm",
                "dotx",
                "xlsx",
                "xlsm",
                "xltx",
                "pptx",
                "pptm",
                "ppsx",
                "odt",
                "ods",
                "odp",
                "odg",
                "epub",
                "jar",
                "war",
                "apk",
                "aab",
                "xapk",
                "ipa",
                "msix",
                "msixbundle",
                "appx",
                "appxbundle",
                "vsix",
                "nupkg",
                "whl",
                "xpi",
                "crx",
                "kmz",
                "3mf",
                "usdz",
                "pages",
                "numbers",
                "key",
                "sketch",
                "cbz",
            ],
            Self::Rar => &["rar", "cbr"],
            Self::SevenZip => &["7z"],
            Self::Gzip => &["gz", "tgz", "gzip"],
            Self::Bzip2 => &["bz2", "tbz", "tbz2"],
            Self::Xz => &["xz", "txz"],
            Self::Zstd => &["zst", "tzst"],
            Self::Iso9660 => &["iso", "img"],
            Self::Sqlite => &["sqlite", "sqlite3", "db", "db3"],
            Self::Html => &["html", "htm", "xhtml", "xht", "shtml"],
            Self::Svg => &["svg"],
            Self::Xml => &[
                "xml", "xsd", "xsl", "xslt", "rss", "atom", "plist", "gpx", "kml", "xaml",
                "csproj", "config", "svg", "xhtml",
            ],
        }
    }
}

/// Something the UI should show about received content.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ContentWarning {
    /// The content is native code, a script, an installer, a shell link,
    /// a disk image, or active markup.
    Risky(DetectedType, ExtensionRisk),
    /// The content is not what its extension or MIME label claims.
    Mismatch(DetectedType),
}

/// What [`assess`] found.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ContentReport {
    detected: Option<DetectedType>,
    warnings: Vec<ContentWarning>,
}

impl ContentReport {
    /// The recognized type, if any signature matched.
    #[must_use]
    pub const fn detected(&self) -> Option<DetectedType> {
        self.detected
    }

    /// Warnings for the UI.
    #[must_use]
    pub fn warnings(&self) -> &[ContentWarning] {
        &self.warnings
    }
}

fn starts(data: &[u8], magic: &[u8]) -> bool {
    data.starts_with(magic)
}

fn at(data: &[u8], offset: usize, magic: &[u8]) -> bool {
    data.get(offset..)
        .is_some_and(|tail| tail.starts_with(magic))
}

/// Signatures at offset 0, longest first where one is a prefix of another.
const SIGNATURES: &[(&[u8], DetectedType)] = &[
    (b"\x7fELF", DetectedType::Elf),
    (b"\xfe\xed\xfa\xce", DetectedType::MachO),
    (b"\xfe\xed\xfa\xcf", DetectedType::MachO),
    (b"\xce\xfa\xed\xfe", DetectedType::MachO),
    (b"\xcf\xfa\xed\xfe", DetectedType::MachO),
    (b"\xca\xfe\xba\xbf", DetectedType::MachO),
    (b"dex\n", DetectedType::Dex),
    (b"\0asm", DetectedType::Wasm),
    (
        b"\x4c\0\0\0\x01\x14\x02\0\0\0\0\0\xc0\0\0\0\0\0\0\x46",
        DetectedType::ShellLink,
    ),
    (
        b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1",
        DetectedType::CompoundFile,
    ),
    (b"MSCF\0\0\0\0", DetectedType::Cabinet),
    (b"xar!", DetectedType::Xar),
    (b"!<arch>\ndebian", DetectedType::Deb),
    (b"\xed\xab\xee\xdb", DetectedType::Rpm),
    (b"{\\rtf", DetectedType::Rtf),
    (b"\x89PNG\r\n\x1a\n", DetectedType::Png),
    (b"\xff\xd8\xff", DetectedType::Jpeg),
    (b"GIF87a", DetectedType::Gif),
    (b"GIF89a", DetectedType::Gif),
    (b"II*\0", DetectedType::Tiff),
    (b"MM\0*", DetectedType::Tiff),
    (b"ID3", DetectedType::Mp3),
    (b"OggS", DetectedType::Ogg),
    (b"fLaC", DetectedType::Flac),
    (b"\x1a\x45\xdf\xa3", DetectedType::Matroska),
    (b"PK\x03\x04", DetectedType::Zip),
    (b"PK\x05\x06", DetectedType::Zip),
    (b"PK\x07\x08", DetectedType::Zip),
    (b"Rar!\x1a\x07", DetectedType::Rar),
    (b"7z\xbc\xaf\x27\x1c", DetectedType::SevenZip),
    (b"\x1f\x8b", DetectedType::Gzip),
    (b"BZh", DetectedType::Bzip2),
    (b"\xfd7zXZ\0", DetectedType::Xz),
    (b"\x28\xb5\x2f\xfd", DetectedType::Zstd),
    (b"SQLite format 3\0", DetectedType::Sqlite),
    (b"#!", DetectedType::Shebang),
    (b"MZ", DetectedType::WindowsExecutable),
];

/// Recognizes `data` (the content's first bytes; anything past
/// [`SNIFF_LEN`] is ignored) by its signature.
#[must_use]
pub fn detect(data: &[u8]) -> Option<DetectedType> {
    let data = &data[..data.len().min(SNIFF_LEN)];
    if let Some(&(_, kind)) = SIGNATURES.iter().find(|(magic, _)| starts(data, magic)) {
        return Some(kind);
    }
    if starts(data, b"\xca\xfe\xba\xbe") {
        // Universal Mach-O and Java class files share this magic. The
        // next word is a small architecture count for Mach-O and the
        // class version (45 or more) for Java, as file(1) decides.
        let next = data.get(4..8).map_or(0, |word| {
            u32::from_be_bytes([word[0], word[1], word[2], word[3]])
        });
        return Some(if next < 30 {
            DetectedType::MachO
        } else {
            DetectedType::JavaClass
        });
    }
    if starts(data, b"RIFF") {
        return match data.get(8..12) {
            Some(b"WEBP") => Some(DetectedType::Webp),
            Some(b"WAVE") => Some(DetectedType::Wav),
            Some(b"AVI ") => Some(DetectedType::Avi),
            _ => None,
        };
    }
    if at(data, 4, b"ftyp") {
        return Some(match data.get(8..12) {
            Some(b"heic" | b"heix" | b"hevc" | b"hevx" | b"heim" | b"heis" | b"mif1" | b"msf1") => {
                DetectedType::Heif
            }
            Some(b"avif" | b"avis") => DetectedType::Avif,
            Some(b"qt  ") => DetectedType::QuickTime,
            Some(b"M4A " | b"M4B ") => DetectedType::M4a,
            _ => DetectedType::Mp4,
        });
    }
    if starts(data, b"BM") && data.get(6..10) == Some(&[0, 0, 0, 0]) {
        return Some(DetectedType::Bmp);
    }
    if (starts(data, b"\0\0\x01\0") || starts(data, b"\0\0\x02\0"))
        && data.get(4..6).is_some_and(|count| count != [0, 0])
    {
        return Some(DetectedType::Icon);
    }
    if [b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"]
        .iter()
        .any(|magic| starts(data, *magic))
    {
        return Some(DetectedType::Mp3);
    }
    // PDF readers accept the header anywhere in the first 1024 bytes.
    let head = &data[..data.len().min(1024)];
    if head.windows(5).any(|window| window == b"%PDF-") {
        return Some(DetectedType::Pdf);
    }
    if [0x8001, 0x8801, 0x9001]
        .iter()
        .any(|&offset| at(data, offset, b"CD001"))
    {
        return Some(DetectedType::Iso9660);
    }
    markup(head)
}

/// HTML, SVG, and XML, after an optional byte order mark and whitespace,
/// compared ASCII-case-insensitively.
fn markup(head: &[u8]) -> Option<DetectedType> {
    let text = head.strip_prefix(b"\xef\xbb\xbf").unwrap_or(head);
    let start = text.iter().position(|b| !b.is_ascii_whitespace())?;
    let text = &text[start..];
    let lower: Vec<u8> = text.iter().map(u8::to_ascii_lowercase).collect();
    let has = |needle: &[u8]| lower.windows(needle.len()).any(|window| window == needle);
    if lower.starts_with(b"<!doctype html") || lower.starts_with(b"<html") {
        return Some(DetectedType::Html);
    }
    if lower.starts_with(b"<svg") || (lower.starts_with(b"<?xml") && has(b"<svg")) {
        return Some(DetectedType::Svg);
    }
    if lower.starts_with(b"<?xml") {
        return Some(if has(b"<html") {
            DetectedType::Html
        } else {
            DetectedType::Xml
        });
    }
    None
}

/// The category a MIME label claims, for the types a user would open
/// without suspicion.
fn claimed_category(mime: &str) -> Option<Category> {
    if mime.starts_with("image/svg") {
        Some(Category::ActiveContent)
    } else if mime.starts_with("image/") {
        Some(Category::Image)
    } else if mime.starts_with("audio/") {
        Some(Category::Audio)
    } else if mime.starts_with("video/") {
        Some(Category::Video)
    } else if mime == "application/pdf" || mime == "text/plain" {
        Some(Category::Document)
    } else {
        None
    }
}

/// Assesses verified content (`prefix`: its first bytes) stored as
/// `local_name` with the peer's claimed `mime`.
#[must_use]
pub fn assess(prefix: &[u8], local_name: &str, mime: &str) -> ContentReport {
    let Some(detected) = detect(prefix) else {
        return ContentReport::default();
    };
    let mut warnings = Vec::new();
    if let Some(risk) = detected.risk() {
        warnings.push(ContentWarning::Risky(detected, risk));
    }
    let extension = final_extension(local_name).map(str::to_ascii_lowercase);
    let extension_mismatch = extension.as_deref().is_some_and(|extension| {
        is_known(extension) && !detected.extensions().contains(&extension)
    });
    // Audio in an MP4 or Ogg container and video labels are close enough.
    let category = detected.category();
    let mime_mismatch = claimed_category(mime).is_some_and(|claimed| {
        claimed != category
            && !matches!(
                (claimed, category),
                (Category::Audio, Category::Video) | (Category::Video, Category::Audio)
            )
    });
    if extension_mismatch || mime_mismatch {
        warnings.push(ContentWarning::Mismatch(detected));
    }
    ContentReport {
        detected: Some(detected),
        warnings,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn signatures_are_recognized() {
        let mut iso = vec![0; 0x8010];
        iso[0x8001..0x8006].copy_from_slice(b"CD001");
        let cases: &[(&[u8], DetectedType)] = &[
            (b"MZ\x90\0", DetectedType::WindowsExecutable),
            (b"\x7fELF\x02\x01", DetectedType::Elf),
            (b"\xcf\xfa\xed\xfe\x07\0\0\x01", DetectedType::MachO),
            (b"\xca\xfe\xba\xbe\0\0\0\x02", DetectedType::MachO),
            (b"\xca\xfe\xba\xbe\0\0\0\x34", DetectedType::JavaClass),
            (b"#!/bin/sh\n", DetectedType::Shebang),
            (b"%PDF-1.7", DetectedType::Pdf),
            (b"junk then %PDF-1.4", DetectedType::Pdf),
            (b"\x89PNG\r\n\x1a\n\0", DetectedType::Png),
            (b"\xff\xd8\xff\xe0", DetectedType::Jpeg),
            (b"RIFF\0\0\0\0WEBPVP8 ", DetectedType::Webp),
            (b"RIFF\0\0\0\0WAVEfmt ", DetectedType::Wav),
            (b"\0\0\0\x18ftypheic", DetectedType::Heif),
            (b"\0\0\0\x18ftypisom", DetectedType::Mp4),
            (b"\0\0\0\x14ftypqt  ", DetectedType::QuickTime),
            (b"PK\x03\x04\x14\0", DetectedType::Zip),
            (b"\x1f\x8b\x08", DetectedType::Gzip),
            (b"  <!DOCTYPE HTML><html>", DetectedType::Html),
            (b"\xef\xbb\xbf<svg xmlns=", DetectedType::Svg),
            (b"<?xml version=\"1.0\"?><svg>", DetectedType::Svg),
            (b"<?xml version=\"1.0\"?><plist>", DetectedType::Xml),
            (b"BM\0\0\0\0\0\0\0\0", DetectedType::Bmp),
            (b"\0\0\x01\0\x01\0", DetectedType::Icon),
            (&iso, DetectedType::Iso9660),
        ];
        for (data, expected) in cases {
            assert_eq!(detect(data), Some(*expected), "{expected:?}");
        }
        for unknown in [
            &b""[..],
            b"M",
            b"hello world",
            b"BMx",
            b"\0\0\x01\0\0\0",
            b"RIFFxxxxABCD",
        ] {
            assert_eq!(detect(unknown), None, "{unknown:?}");
        }
    }

    #[test]
    fn executables_and_mismatches_are_flagged() {
        let report = assess(b"MZ\x90\0", "holiday.jpg", "image/jpeg");
        assert_eq!(report.detected(), Some(DetectedType::WindowsExecutable));
        assert!(matches!(
            report.warnings(),
            [
                ContentWarning::Risky(DetectedType::WindowsExecutable, _),
                ContentWarning::Mismatch(DetectedType::WindowsExecutable)
            ]
        ));
        // An executable named as one is still risky, but not a mismatch.
        let report = assess(b"\x7fELF", "tool.appimage", "application/octet-stream");
        assert!(matches!(
            report.warnings(),
            [ContentWarning::Risky(DetectedType::Elf, _)]
        ));
        // Matching content and name: nothing to say.
        assert_eq!(
            assess(b"%PDF-1.7", "a.pdf", "application/pdf").warnings(),
            []
        );
        assert_eq!(
            assess(b"PK\x03\x04", "report.docx", "application/octet-stream").warnings(),
            []
        );
        // A PNG called .jpg is a harmless mismatch; HTML called .txt is not.
        assert_eq!(
            assess(b"\x89PNG\r\n\x1a\n", "x.jpg", "image/jpeg").warnings(),
            [ContentWarning::Mismatch(DetectedType::Png)]
        );
        let report = assess(b"<html><script>", "notes.txt", "text/plain");
        assert_eq!(report.warnings().len(), 2);
        // Unknown content and unknown extensions say nothing.
        assert_eq!(
            assess(b"plain words", "x.txt", "text/plain"),
            ContentReport::default()
        );
        assert_eq!(
            assess(b"%PDF-", "x.custom", "application/octet-stream").warnings(),
            []
        );
    }

    /// Real headers of every recognized format (from each format's
    /// specification, not from the table), so a missing, mistyped, or
    /// shadowed signature is caught.
    #[test]
    fn every_format_is_recognized_from_a_real_header() {
        use DetectedType as T;
        let mut iso = vec![0; 0x8810];
        iso[0x8801..0x8806].copy_from_slice(b"CD001");
        let cases: &[(&[u8], DetectedType)] = &[
            (b"MZ\x90\0\x03\0\0\0", T::WindowsExecutable),
            (b"\x7fELF\x01\x01\x01\0", T::Elf),
            (b"\xfe\xed\xfa\xce\0\0\0\x12", T::MachO),
            (b"\xfe\xed\xfa\xcf\x01\0\0\x0c", T::MachO),
            (b"\xce\xfa\xed\xfe\x07\0\0\0", T::MachO),
            (b"\xca\xfe\xba\xbf\0\0\0\x02", T::MachO),
            (b"\xca\xfe\xba\xbe", T::MachO),
            (b"\xca\xfe\xba\xbe\0\0\0\x1d", T::MachO),
            (b"\xca\xfe\xba\xbe\0\0\0\x1e", T::JavaClass),
            (b"\xca\xfe\xba\xbe\0\0\0\x41", T::JavaClass),
            (b"dex\n035\0", T::Dex),
            (b"\0asm\x01\0\0\0", T::Wasm),
            (b"#!/usr/bin/env python3\n", T::Shebang),
            (
                b"\x4c\0\0\0\x01\x14\x02\0\0\0\0\0\xc0\0\0\0\0\0\0\x46\x9b\0",
                T::ShellLink,
            ),
            (b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1\0\0", T::CompoundFile),
            (b"MSCF\0\0\0\0\x10\x27", T::Cabinet),
            (b"xar!\0\x1c\0\x01", T::Xar),
            (b"!<arch>\ndebian-binary   ", T::Deb),
            (b"\xed\xab\xee\xdb\x03\0", T::Rpm),
            (b"{\\rtf1\\ansi", T::Rtf),
            (b"GIF87a\x01\0", T::Gif),
            (b"GIF89a\x01\0", T::Gif),
            (b"II*\0\x08\0\0\0", T::Tiff),
            (b"MM\0*\0\0\0\x08", T::Tiff),
            (b"BM\x36\0\x0c\0\0\0\0\0\x36\0", T::Bmp),
            (b"\0\0\x02\0\x01\0\x20\x20", T::Icon),
            (b"\0\0\0\x18ftypheix", T::Heif),
            (b"\0\0\0\x18ftypmif1", T::Heif),
            (b"\0\0\0\x18ftypmsf1", T::Heif),
            (b"\0\0\0\x1cftypavif", T::Avif),
            (b"\0\0\0\x1cftypavis", T::Avif),
            (b"\0\0\0\x20ftypM4A ", T::M4a),
            (b"\0\0\0\x20ftypM4B ", T::M4a),
            (b"\0\0\0\x20ftypmp42", T::Mp4),
            (b"ID3\x04\0\0", T::Mp3),
            (b"\xff\xfb\x90\x64", T::Mp3),
            (b"\xff\xf3\x90\x64", T::Mp3),
            (b"\xff\xf2\x90\x64", T::Mp3),
            (b"RIFF\x24\0\0\0AVI LIST", T::Avi),
            (b"OggS\0\x02", T::Ogg),
            (b"fLaC\0\0\0\x22", T::Flac),
            (b"\x1a\x45\xdf\xa3\x01\0", T::Matroska),
            (b"PK\x05\x06\0\0", T::Zip),
            (b"PK\x07\x08\0\0", T::Zip),
            (b"Rar!\x1a\x07\0", T::Rar),
            (b"Rar!\x1a\x07\x01\0", T::Rar),
            (b"7z\xbc\xaf\x27\x1c\0\x04", T::SevenZip),
            (b"BZh91AY&SY", T::Bzip2),
            (b"\xfd7zXZ\0\0\x04", T::Xz),
            (b"\x28\xb5\x2f\xfd\x24\0", T::Zstd),
            (b"SQLite format 3\0\x10\0", T::Sqlite),
            (b"<html lang=en>", T::Html),
            (b"\n\t <?xml version=\"1.0\"?><html>", T::Html),
            (b"<SVG viewBox=\"0 0 1 1\">", T::Svg),
            (&iso, T::Iso9660),
        ];
        for (data, expected) in cases {
            assert_eq!(detect(data), Some(*expected), "{expected:?}");
        }
        for unknown in [
            &b"BM\x36\0\x0c\0\x01\0\0\0"[..],
            b"\0\0\x03\0\x01\0",
            b"\0\0\x02\0\0\0",
            b"\xff\xfa\x90",
            b"PK\x01\x02",
            b"Rar!\x1a",
            b"\x7fEL",
            b"<?xm",
            b"<htm",
            b"ftypisom",
        ] {
            assert_eq!(detect(unknown), None, "{unknown:?}");
        }
    }

    /// PDF readers find the header anywhere in the first 1024 bytes: one
    /// that ends at byte 1024 counts, one that ends after it does not.
    #[test]
    fn the_pdf_header_counts_only_within_its_first_kilobyte() {
        for (offset, expected) in [(1019, Some(DetectedType::Pdf)), (1020, None)] {
            let mut data = vec![b' '; offset];
            data.extend_from_slice(b"%PDF-1.7");
            assert_eq!(detect(&data), expected, "{offset}");
        }
    }

    /// Each risky type is flagged with its risk, whatever it is called.
    #[test]
    fn every_risky_type_is_flagged() {
        use DetectedType as T;
        let mut iso = vec![0; 0x8010];
        iso[0x8001..0x8006].copy_from_slice(b"CD001");
        let cases: &[(&[u8], DetectedType, RiskKind, Platforms)] = &[
            (
                b"MZ",
                T::WindowsExecutable,
                RiskKind::Executable,
                Platforms::WINDOWS,
            ),
            (
                b"\x7fELF",
                T::Elf,
                RiskKind::Executable,
                Platforms::LINUX.union(Platforms::ANDROID),
            ),
            (
                b"\xcf\xfa\xed\xfe",
                T::MachO,
                RiskKind::Executable,
                Platforms::MACOS.union(Platforms::IOS),
            ),
            (
                b"\xca\xfe\xba\xbe\0\0\0\x34",
                T::JavaClass,
                RiskKind::Executable,
                Platforms::DESKTOP,
            ),
            (b"dex\n", T::Dex, RiskKind::Executable, Platforms::ANDROID),
            (b"\0asm", T::Wasm, RiskKind::Executable, Platforms::ALL),
            (
                b"#!/bin/sh",
                T::Shebang,
                RiskKind::Script,
                Platforms::MACOS.union(Platforms::LINUX),
            ),
            (
                b"\x4c\0\0\0\x01\x14\x02\0\0\0\0\0\xc0\0\0\0\0\0\0\x46",
                T::ShellLink,
                RiskKind::Shortcut,
                Platforms::WINDOWS,
            ),
            (b"xar!", T::Xar, RiskKind::Installer, Platforms::MACOS),
            (
                b"!<arch>\ndebian",
                T::Deb,
                RiskKind::Installer,
                Platforms::LINUX,
            ),
            (
                b"\xed\xab\xee\xdb",
                T::Rpm,
                RiskKind::Installer,
                Platforms::LINUX,
            ),
            (
                b"MSCF\0\0\0\0",
                T::Cabinet,
                RiskKind::Installer,
                Platforms::WINDOWS,
            ),
            (
                &iso,
                T::Iso9660,
                RiskKind::DiskImage,
                Platforms::WINDOWS.union(Platforms::MACOS),
            ),
            (b"<html>", T::Html, RiskKind::ActiveContent, Platforms::ALL),
            (b"<svg>", T::Svg, RiskKind::ActiveContent, Platforms::ALL),
        ];
        for (data, kind, risk, platforms) in cases {
            let report = assess(data, "renamed", "application/octet-stream");
            assert_eq!(report.detected(), Some(*kind));
            assert_eq!(
                report.warnings(),
                [ContentWarning::Risky(
                    *kind,
                    ExtensionRisk {
                        kind: *risk,
                        platforms: *platforms
                    }
                )],
                "{kind:?}"
            );
        }
        // Documents, media, and archives carry no risk of their own.
        for data in [
            &b"%PDF-1.7"[..],
            b"\x89PNG\r\n\x1a\n",
            b"PK\x03\x04",
            b"<?xml?><a/>",
        ] {
            assert_eq!(
                assess(data, "renamed", "application/octet-stream").warnings(),
                []
            );
        }
    }

    /// The MIME label alone can make a mismatch; audio and video labels are
    /// interchangeable for containers that hold either; SVG labels claim
    /// active content.
    #[test]
    fn mime_labels_are_compared_by_category() {
        assert_eq!(
            assess(b"\x89PNG\r\n\x1a\n", "x.png", "audio/mpeg").warnings(),
            [ContentWarning::Mismatch(DetectedType::Png)]
        );
        assert_eq!(
            assess(b"\x89PNG\r\n\x1a\n", "x.png", "image/svg+xml").warnings(),
            [ContentWarning::Mismatch(DetectedType::Png)]
        );
        assert_eq!(
            assess(b"\x89PNG\r\n\x1a\n", "x.png", "video/mp4").warnings(),
            [ContentWarning::Mismatch(DetectedType::Png)]
        );
        assert_eq!(
            assess(b"\x89PNG\r\n\x1a\n", "x.png", "application/pdf").warnings(),
            [ContentWarning::Mismatch(DetectedType::Png)]
        );
        assert_eq!(
            assess(b"\x89PNG\r\n\x1a\n", "x.png", "image/png").warnings(),
            []
        );
        assert_eq!(
            assess(b"\0\0\0\x18ftypisom", "x.mp4", "audio/mp4").warnings(),
            []
        );
        assert_eq!(assess(b"OggS", "x.ogg", "audio/ogg").warnings(), []);
        assert_eq!(assess(b"OggS", "x.ogg", "video/ogg").warnings(), []);
        assert_eq!(assess(b"fLaC", "x.flac", "video/x-flac").warnings(), []);
        assert_eq!(assess(b"%PDF-1.7", "x.pdf", "text/plain").warnings(), []);
        let svg = assess(b"<svg>", "x.svg", "image/svg+xml");
        assert!(
            !svg.warnings()
                .iter()
                .any(|warning| matches!(warning, ContentWarning::Mismatch(_)))
        );
        // Unknown extensions and labels say nothing.
        assert_eq!(
            assess(b"\x89PNG\r\n\x1a\n", "x.custom", "application/x-thing").warnings(),
            []
        );
    }

    #[test]
    fn every_type_is_consistent() {
        use DetectedType as T;
        for kind in [
            T::WindowsExecutable,
            T::Elf,
            T::MachO,
            T::JavaClass,
            T::Dex,
            T::Wasm,
            T::Shebang,
            T::ShellLink,
            T::CompoundFile,
            T::Cabinet,
            T::Xar,
            T::Deb,
            T::Rpm,
            T::Pdf,
            T::Rtf,
            T::Png,
            T::Jpeg,
            T::Gif,
            T::Webp,
            T::Bmp,
            T::Tiff,
            T::Icon,
            T::Heif,
            T::Avif,
            T::Mp4,
            T::QuickTime,
            T::M4a,
            T::Mp3,
            T::Wav,
            T::Avi,
            T::Ogg,
            T::Flac,
            T::Matroska,
            T::Zip,
            T::Rar,
            T::SevenZip,
            T::Gzip,
            T::Bzip2,
            T::Xz,
            T::Zstd,
            T::Iso9660,
            T::Sqlite,
            T::Html,
            T::Svg,
            T::Xml,
        ] {
            assert!(!kind.extensions().is_empty(), "{kind:?}");
            assert!(
                kind.extensions().iter().all(|e| e
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())),
                "{kind:?}"
            );
            if kind.category() == Category::Executable {
                assert!(kind.risk().is_some(), "{kind:?}");
            }
        }
    }
}
