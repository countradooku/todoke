//! Text for people: sizes, durations, device fingerprints, and what kind
//! of file a name is. Names a peer chose always pass through [`name`].

use core::time::Duration;

use todoke_core::api::EntryInfo;

/// A name a peer chose, safe to show: control, bidirectional, and
/// invisible characters are escaped (`invoice\u{202e}fdp.exe` stays
/// visibly odd instead of passing for a PDF).
#[must_use]
pub fn name(raw: &str) -> String {
    todoke_core::api::escape(raw)
}

/// Bytes in binary units, one decimal: `0 B`, `1023 B`, `1.5 KiB`.
#[must_use]
pub fn bytes(count: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = count;
    let mut unit = 0;
    let mut remainder = 0;
    while value >= 1024 && unit < UNITS.len() - 1 {
        remainder = value % 1024;
        value /= 1024;
        unit += 1;
    }
    if unit == 0 {
        format!("{value} B")
    } else {
        format!("{value}.{} {}", remainder * 10 / 1024, UNITS[unit])
    }
}

/// A rate: `12.4 MiB/s`.
#[must_use]
pub fn rate(bytes_per_second: u64) -> String {
    format!("{}/s", bytes(bytes_per_second))
}

/// A duration, coarsely: `less than 1 s`, `42 s`, `3 min 5 s`, `2 h 4 min`.
#[must_use]
pub fn duration(span: Duration) -> String {
    let seconds = span.as_secs();
    match seconds {
        0 => "less than 1 s".to_owned(),
        1..60 => format!("{seconds} s"),
        60..3600 => format!("{} min {} s", seconds / 60, seconds % 60),
        _ => format!("{} h {} min", seconds / 3600, seconds % 3600 / 60),
    }
}

/// The time left at `bytes_per_second`, or `None` while nothing moves.
#[must_use]
pub fn eta(done: u64, total: u64, bytes_per_second: u64) -> Option<Duration> {
    if bytes_per_second == 0 || done >= total {
        return None;
    }
    Some(Duration::from_secs(
        (total - done).div_ceil(bytes_per_second),
    ))
}

/// The share done, 0.0 to 1.0.
#[must_use]
#[expect(
    clippy::cast_precision_loss,
    reason = "a progress bar needs no more than f64 precision"
)]
pub fn fraction(done: u64, total: u64) -> f32 {
    if total == 0 {
        return 1.0;
    }
    let share = done.min(total) as f64 / total as f64;
    #[expect(clippy::cast_possible_truncation, reason = "a share in 0..=1")]
    let share = share as f32;
    share
}

/// A device key's fingerprint for people: its first 16 hex digits in
/// groups of four, upper case (`3F9A 12C4 77B0 0E51`). The same on both
/// devices, so two people can compare it.
#[must_use]
pub fn fingerprint(hex: &str) -> String {
    let digits: Vec<char> = hex
        .chars()
        .filter(char::is_ascii_hexdigit)
        .take(16)
        .map(|c| c.to_ascii_uppercase())
        .collect();
    digits
        .chunks(4)
        .map(|group| group.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join(" ")
}

/// What to call a contact: devices carry no names in the protocol, so
/// the start of the fingerprint.
#[must_use]
pub fn device(hex: &str) -> String {
    let short: String = fingerprint(hex).chars().take(9).collect();
    format!("Device {short}")
}

/// Two characters for a device's avatar.
#[must_use]
pub fn initials(hex: &str) -> String {
    hex.chars()
        .filter(char::is_ascii_hexdigit)
        .take(2)
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// Which avatar color a device gets (stable for its key).
#[must_use]
pub fn avatar_index(hex: &str) -> usize {
    let byte = hex
        .get(2..4)
        .and_then(|pair| u8::from_str_radix(pair, 16).ok())
        .unwrap_or(0);
    usize::from(byte % 8)
}

/// What kind of file something is, for a summary: from the sender's
/// claimed MIME type, then the name's extension. A display hint only.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Kind {
    /// A folder.
    Folder,
    /// Photos and pictures.
    Image,
    /// Video.
    Video,
    /// Audio.
    Audio,
    /// Text, PDF, office documents.
    Document,
    /// Archives and disk images.
    Archive,
    /// Programs and scripts: worth a second look.
    Program,
    /// Anything else.
    Other,
}

impl Kind {
    /// Its name for people, singular or plural.
    #[must_use]
    pub const fn label(self, count: usize) -> &'static str {
        let one = count == 1;
        match self {
            Self::Folder if one => "folder",
            Self::Folder => "folders",
            Self::Image if one => "image",
            Self::Image => "images",
            Self::Video if one => "video",
            Self::Video => "videos",
            Self::Audio if one => "audio file",
            Self::Audio => "audio files",
            Self::Document if one => "document",
            Self::Document => "documents",
            Self::Archive if one => "archive",
            Self::Archive => "archives",
            Self::Program if one => "program or script",
            Self::Program => "programs or scripts",
            Self::Other if one => "other file",
            Self::Other => "other files",
        }
    }
}

/// Extensions of what a system runs: executables, installers, libraries,
/// scripts and script hosts, shortcuts, and documents that run macros.
const PROGRAMS: &[&str] = &[
    "exe",
    "msi",
    "msix",
    "appx",
    "bat",
    "cmd",
    "com",
    "scr",
    "pif",
    "cpl",
    "dll",
    "sys",
    "ps1",
    "psm1",
    "vbs",
    "vbe",
    "js",
    "jse",
    "wsf",
    "wsh",
    "hta",
    "reg",
    "lnk",
    "url",
    "inf",
    "jar",
    "app",
    "pkg",
    "command",
    "tool",
    "workflow",
    "scpt",
    "applescript",
    "dylib",
    "sh",
    "bash",
    "zsh",
    "csh",
    "fish",
    "py",
    "pyw",
    "pl",
    "rb",
    "php",
    "lua",
    "apk",
    "deb",
    "rpm",
    "appimage",
    "flatpakref",
    "snap",
    "desktop",
    "run",
    "elf",
    "html",
    "htm",
    "xhtml",
    "svg",
    "docm",
    "dotm",
    "xlsm",
    "xltm",
    "xlam",
    "pptm",
    "potm",
    "ppam",
    "sldm",
];

/// MIME types that claim to be programs or scripts.
const PROGRAM_TYPES: &[&str] = &[
    "application/x-sh",
    "application/x-shellscript",
    "text/x-shellscript",
    "application/x-executable",
    "application/x-elf",
    "application/x-mach-binary",
    "application/x-msdownload",
    "application/x-msdos-program",
    "application/x-msi",
    "application/vnd.microsoft.portable-executable",
    "application/java-archive",
    "application/javascript",
    "text/javascript",
    "text/x-python",
    "application/x-python-code",
    "text/x-perl",
    "application/x-perl",
    "text/x-ruby",
    "application/x-httpd-php",
    "text/html",
    "application/xhtml+xml",
    "image/svg+xml",
    "application/vnd.android.package-archive",
    "application/x-apple-diskimage",
];

/// A name a peer chose, escaped, split before its last extension (at most
/// 16 characters), so the extension stays visible however the rest is
/// shortened: `("Report       ", ".exe")`.
#[must_use]
pub fn name_parts(raw: &str) -> (String, String) {
    let shown = name(raw);
    match shown.rsplit_once('.') {
        Some((stem, extension))
            if !stem.is_empty() && !extension.is_empty() && extension.chars().count() <= 16 =>
        {
            (stem.to_owned(), format!(".{extension}"))
        }
        _ => (shown, String::new()),
    }
}

/// The kind of `entry`.
#[must_use]
pub fn kind(entry: &EntryInfo) -> Kind {
    if entry.directory {
        return Kind::Folder;
    }
    let extension = entry
        .name
        .rsplit_once('.')
        .map(|(_, extension)| extension.to_ascii_lowercase())
        .unwrap_or_default();
    // A program is a program whatever MIME type it claims: anything a
    // system runs, opens with a script host, or runs macros in.
    if PROGRAMS.contains(&extension.as_str()) || PROGRAM_TYPES.contains(&entry.mime.as_str()) {
        return Kind::Program;
    }
    let mime = entry.mime.as_str();
    if let Some((top, _)) = mime.split_once('/') {
        match top {
            "image" => return Kind::Image,
            "video" => return Kind::Video,
            "audio" => return Kind::Audio,
            "text" => return Kind::Document,
            _ => {}
        }
    }
    match extension.as_str() {
        "jpg" | "jpeg" | "png" | "gif" | "heic" | "heif" | "webp" | "tif" | "tiff" | "bmp"
        | "raw" | "dng" | "avif" => Kind::Image,
        "mp4" | "mov" | "mkv" | "avi" | "webm" | "m4v" => Kind::Video,
        "mp3" | "m4a" | "wav" | "flac" | "aac" | "ogg" | "opus" => Kind::Audio,
        "pdf" | "txt" | "md" | "rtf" | "doc" | "docx" | "odt" | "xls" | "xlsx" | "ods" | "ppt"
        | "pptx" | "odp" | "csv" | "pages" | "numbers" | "key" | "epub" => Kind::Document,
        "zip" | "7z" | "rar" | "tar" | "gz" | "tgz" | "xz" | "bz2" | "zst" | "dmg" | "iso" => {
            Kind::Archive
        }
        _ => Kind::Other,
    }
}

/// What an offer holds, for its consent prompt.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Summary {
    /// Regular files.
    pub files: usize,
    /// Folders.
    pub folders: usize,
    /// Bytes in all files.
    pub bytes: u64,
    /// How many of each kind, most first (folders excluded).
    pub kinds: Vec<(Kind, usize)>,
}

impl Summary {
    /// Summarizes `entries`.
    #[must_use]
    pub fn of(entries: &[EntryInfo]) -> Self {
        let mut summary = Self::default();
        let mut counts = std::collections::BTreeMap::<Kind, usize>::new();
        for entry in entries {
            if entry.directory {
                summary.folders += 1;
            } else {
                summary.files += 1;
                summary.bytes = summary.bytes.saturating_add(entry.size);
                *counts.entry(kind(entry)).or_default() += 1;
            }
        }
        let mut kinds: Vec<(Kind, usize)> = counts.into_iter().collect();
        kinds.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(&b.0)));
        summary.kinds = kinds;
        summary
    }

    /// `3 files, 1 folder · 2.4 MiB`.
    #[must_use]
    pub fn counts(&self) -> String {
        let files = plural(self.files, "file", "files");
        let size = bytes(self.bytes);
        if self.folders == 0 {
            format!("{files} · {size}")
        } else {
            let folders = plural(self.folders, "folder", "folders");
            format!("{files}, {folders} · {size}")
        }
    }

    /// `2 images, 1 document`.
    #[must_use]
    pub fn types(&self) -> String {
        self.kinds
            .iter()
            .map(|(kind, count)| format!("{count} {}", kind.label(*count)))
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Whether it holds programs or scripts.
    #[must_use]
    pub fn has_programs(&self) -> bool {
        self.kinds.iter().any(|(kind, _)| *kind == Kind::Program)
    }
}

/// `1 file`, `2 files`.
#[must_use]
pub fn plural(count: usize, one: &str, many: &str) -> String {
    if count == 1 {
        format!("1 {one}")
    } else {
        format!("{count} {many}")
    }
}

/// A Unix time as a date and time in UTC: `2026-10-14 09:30 UTC` (no
/// time-zone database is shipped; UTC is unambiguous).
#[must_use]
pub fn timestamp(unix: u64) -> String {
    let days = unix / 86_400;
    let rest = unix % 86_400;
    let (year, month, day) = civil(days);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02} UTC",
        rest / 3600,
        rest % 3600 / 60
    )
}

/// Days since 1970-01-01 to a proleptic Gregorian date (Howard Hinnant's
/// algorithm).
fn civil(days: u64) -> (u64, u64, u64) {
    let z = days + 719_468;
    let era = z / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + u64::from(month <= 2);
    (year, month, day)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, mime: &str, directory: bool, size: u64) -> EntryInfo {
        EntryInfo {
            id: 1,
            parent: 0,
            directory,
            name: name.into(),
            mime: mime.into(),
            size,
        }
    }

    #[test]
    fn sizes_rates_and_durations_read_well() {
        assert_eq!(bytes(0), "0 B");
        assert_eq!(bytes(1536), "1.5 KiB");
        assert_eq!(bytes(5 << 30), "5.0 GiB");
        assert_eq!(rate(2 << 20), "2.0 MiB/s");
        assert_eq!(duration(Duration::ZERO), "less than 1 s");
        assert_eq!(duration(Duration::from_secs(42)), "42 s");
        assert_eq!(duration(Duration::from_secs(185)), "3 min 5 s");
        assert_eq!(duration(Duration::from_mins(124)), "2 h 4 min");
    }

    #[test]
    fn eta_and_fraction() {
        assert_eq!(eta(0, 100, 0), None);
        assert_eq!(eta(100, 100, 10), None);
        assert_eq!(eta(50, 100, 10), Some(Duration::from_secs(5)));
        assert_eq!(eta(0, 101, 10), Some(Duration::from_secs(11)));
        assert!((fraction(1, 4) - 0.25).abs() < f32::EPSILON);
        assert!((fraction(0, 0) - 1.0).abs() < f32::EPSILON);
        assert!((fraction(9, 4) - 1.0).abs() < f32::EPSILON);
    }

    #[test]
    fn devices_are_named_by_fingerprint() {
        let hex = "3f9a12c477b00e51aa";
        assert_eq!(fingerprint(hex), "3F9A 12C4 77B0 0E51");
        assert_eq!(device(hex), "Device 3F9A 12C4");
        assert_eq!(initials(hex), "3F");
        assert_eq!(avatar_index(hex), 0x9a % 8);
        assert_eq!(avatar_index(""), 0);
    }

    #[test]
    fn hostile_names_are_escaped() {
        assert_eq!(name("invoice\u{202e}fdp.exe"), "invoice\\u{202e}fdp.exe");
        assert_eq!(name("a\u{1b}[2Jb"), "a\\u{1b}[2Jb");
    }

    /// A program claiming an innocent MIME type is still a program.
    #[test]
    fn kinds_come_from_mime_then_extension_and_programs_win() {
        assert_eq!(
            kind(&entry("a.JPG", "application/octet-stream", false, 1)),
            Kind::Image
        );
        assert_eq!(kind(&entry("clip", "video/mp4", false, 1)), Kind::Video);
        assert_eq!(
            kind(&entry("run.exe", "image/png", false, 1)),
            Kind::Program
        );
        assert_eq!(kind(&entry("photos", "", true, 0)), Kind::Folder);
        assert_eq!(kind(&entry("noext", "", false, 1)), Kind::Other);
        assert_eq!(kind(&entry("x.tar.gz", "", false, 1)), Kind::Archive);
        // Scripts, script hosts, and macro documents, by name or by type.
        for name in [
            "install.py",
            "budget.XLSM",
            "invoice.html",
            "logo.svg",
            "fix.reg",
        ] {
            assert_eq!(
                kind(&entry(name, "application/octet-stream", false, 1)),
                Kind::Program,
                "{name}"
            );
        }
        assert_eq!(
            kind(&entry("readme", "text/x-shellscript", false, 1)),
            Kind::Program
        );
        assert_eq!(kind(&entry("firmware.bin", "", false, 1)), Kind::Other);
    }

    /// The extension stays apart, so shortening the name never hides it.
    #[test]
    fn names_keep_their_extension_visible() {
        assert_eq!(
            name_parts("Report.pdf          .exe"),
            ("Report.pdf          ".to_owned(), ".exe".to_owned())
        );
        assert_eq!(
            name_parts("a\u{202e}b.txt"),
            ("a\\u{202e}b".to_owned(), ".txt".to_owned())
        );
        assert_eq!(
            name_parts("noextension"),
            ("noextension".to_owned(), String::new())
        );
        assert_eq!(
            name_parts(".profile"),
            (".profile".to_owned(), String::new())
        );
    }

    #[test]
    fn offers_are_summarized() {
        let entries = [
            entry("album", "", true, 0),
            entry("a.jpg", "image/jpeg", false, 1024),
            entry("b.png", "image/png", false, 1024),
            entry("notes.pdf", "application/pdf", false, 512),
            entry("install.sh", "text/plain", false, 10),
        ];
        let summary = Summary::of(&entries);
        assert_eq!(summary.files, 4);
        assert_eq!(summary.folders, 1);
        assert_eq!(summary.bytes, 2570);
        assert_eq!(summary.counts(), "4 files, 1 folder · 2.5 KiB");
        assert_eq!(summary.types(), "2 images, 1 document, 1 program or script");
        assert!(summary.has_programs());
        assert_eq!(Summary::of(&[]).counts(), "0 files · 0 B");
    }

    #[test]
    fn timestamps_are_utc_dates() {
        assert_eq!(timestamp(0), "1970-01-01 00:00 UTC");
        assert_eq!(timestamp(1_791_970_200), "2026-10-14 09:30 UTC");
        assert_eq!(timestamp(951_782_400), "2000-02-29 00:00 UTC");
    }
}
