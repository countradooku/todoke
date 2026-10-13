//! File extensions: which ones run code or are processed automatically on
//! each platform, and which are ordinary documents and media. Fixed tables
//! (data, not detection logic); lookups are ASCII-case-insensitive.

/// Platforms on which an extension or content type is a risk.
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash)]
pub struct Platforms(u8);

impl Platforms {
    /// No platform.
    pub const NONE: Self = Self(0);
    /// Windows.
    pub const WINDOWS: Self = Self(1);
    /// macOS.
    pub const MACOS: Self = Self(1 << 1);
    /// Linux desktops.
    pub const LINUX: Self = Self(1 << 2);
    /// Android.
    pub const ANDROID: Self = Self(1 << 3);
    /// iOS and iPadOS.
    pub const IOS: Self = Self(1 << 4);
    /// The three desktop platforms.
    pub const DESKTOP: Self = Self(0b111);
    /// Every platform.
    pub const ALL: Self = Self(0b1_1111);

    /// Both sets.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Whether every platform of `other` is in this set.
    #[must_use]
    pub const fn contains(self, other: Self) -> bool {
        self.0 & other.0 == other.0
    }

    /// Whether the set is empty.
    #[must_use]
    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

impl core::fmt::Debug for Platforms {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let names = [
            (Self::WINDOWS, "windows"),
            (Self::MACOS, "macos"),
            (Self::LINUX, "linux"),
            (Self::ANDROID, "android"),
            (Self::IOS, "ios"),
        ];
        let mut list = f.debug_set();
        for (platform, name) in names {
            if self.contains(platform) {
                list.entry(&name);
            }
        }
        list.finish()
    }
}

/// Why an extension is a risk.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RiskKind {
    /// Native code or a runtime that executes it.
    Executable,
    /// A script an interpreter or the shell runs on open.
    Script,
    /// An installer or package.
    Installer,
    /// A shortcut or link the shell resolves, possibly fetching a remote
    /// icon or target when the folder is displayed.
    Shortcut,
    /// A document format that carries macros.
    Macro,
    /// A disk image the system mounts on open.
    DiskImage,
    /// Markup or help files that run scripts when viewed.
    ActiveContent,
}

/// An extension's risk.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ExtensionRisk {
    /// What kind of risk.
    pub kind: RiskKind,
    /// Where.
    pub platforms: Platforms,
}

const W: Platforms = Platforms::WINDOWS;
const M: Platforms = Platforms::MACOS;
const L: Platforms = Platforms::LINUX;
const WM: Platforms = Platforms(0b011);
const ML: Platforms = Platforms(0b110);
const D: Platforms = Platforms::DESKTOP;
const A: Platforms = Platforms::ALL;

/// Extensions that run code, install software, mount, or are resolved by
/// the shell, per platform. Sources: Microsoft's "Blocked attachments in
/// Outlook" list and Attachment Manager high-risk types, Apple's
/// Gatekeeper-assessed and `LaunchServices` executable types, and the
/// freedesktop.org desktop entry and package formats.
const RISKS: &[(&str, RiskKind, Platforms)] = &[
    // Windows native code and runtimes.
    ("exe", RiskKind::Executable, W),
    ("com", RiskKind::Executable, W),
    ("scr", RiskKind::Executable, W),
    ("pif", RiskKind::Executable, W),
    ("cpl", RiskKind::Executable, W),
    ("dll", RiskKind::Executable, W),
    ("ocx", RiskKind::Executable, W),
    ("sys", RiskKind::Executable, W),
    ("drv", RiskKind::Executable, W),
    ("efi", RiskKind::Executable, W),
    ("msc", RiskKind::Executable, W),
    ("xll", RiskKind::Executable, W),
    ("jar", RiskKind::Executable, D),
    // Windows scripts.
    ("bat", RiskKind::Script, W),
    ("cmd", RiskKind::Script, W),
    ("ps1", RiskKind::Script, W),
    ("psm1", RiskKind::Script, W),
    ("psd1", RiskKind::Script, W),
    ("ps1xml", RiskKind::Script, W),
    ("psc1", RiskKind::Script, W),
    ("vb", RiskKind::Script, W),
    ("vbs", RiskKind::Script, W),
    ("vbe", RiskKind::Script, W),
    ("js", RiskKind::Script, W),
    ("jse", RiskKind::Script, W),
    ("wsf", RiskKind::Script, W),
    ("wsh", RiskKind::Script, W),
    ("wsc", RiskKind::Script, W),
    ("sct", RiskKind::Script, W),
    ("hta", RiskKind::Script, W),
    ("reg", RiskKind::Script, W),
    ("inf", RiskKind::Script, W),
    ("ins", RiskKind::Script, W),
    ("isp", RiskKind::Script, W),
    ("mshxml", RiskKind::Script, W),
    ("pyw", RiskKind::Script, W),
    // Cross-platform interpreters.
    ("py", RiskKind::Script, D),
    ("pl", RiskKind::Script, D),
    ("rb", RiskKind::Script, D),
    ("php", RiskKind::Script, D),
    // Windows installers.
    ("msi", RiskKind::Installer, W),
    ("msp", RiskKind::Installer, W),
    ("mst", RiskKind::Installer, W),
    ("msix", RiskKind::Installer, W),
    ("msixbundle", RiskKind::Installer, W),
    ("appx", RiskKind::Installer, W),
    ("appxbundle", RiskKind::Installer, W),
    ("appinstaller", RiskKind::Installer, W),
    ("application", RiskKind::Installer, W),
    ("xbap", RiskKind::Installer, W),
    ("gadget", RiskKind::Installer, W),
    ("diagcab", RiskKind::Installer, W),
    ("cab", RiskKind::Installer, W),
    // Shell-resolved shortcuts.
    ("lnk", RiskKind::Shortcut, W),
    ("url", RiskKind::Shortcut, W),
    ("scf", RiskKind::Shortcut, W),
    ("website", RiskKind::Shortcut, W),
    ("library-ms", RiskKind::Shortcut, W),
    ("searchconnector-ms", RiskKind::Shortcut, W),
    ("settingcontent-ms", RiskKind::Shortcut, W),
    ("fileloc", RiskKind::Shortcut, M),
    ("inetloc", RiskKind::Shortcut, M),
    ("webloc", RiskKind::Shortcut, M),
    // Macro-enabled documents.
    ("docm", RiskKind::Macro, WM),
    ("dotm", RiskKind::Macro, WM),
    ("xlsm", RiskKind::Macro, WM),
    ("xltm", RiskKind::Macro, WM),
    ("xlam", RiskKind::Macro, WM),
    ("pptm", RiskKind::Macro, WM),
    ("potm", RiskKind::Macro, WM),
    ("ppam", RiskKind::Macro, WM),
    ("sldm", RiskKind::Macro, WM),
    // Disk images.
    ("iso", RiskKind::DiskImage, WM),
    ("img", RiskKind::DiskImage, WM),
    ("vhd", RiskKind::DiskImage, W),
    ("vhdx", RiskKind::DiskImage, W),
    ("dmg", RiskKind::DiskImage, M),
    // macOS.
    ("app", RiskKind::Executable, M),
    ("command", RiskKind::Script, M),
    ("tool", RiskKind::Script, M),
    ("terminal", RiskKind::Script, M),
    ("scpt", RiskKind::Script, M),
    ("scptd", RiskKind::Script, M),
    ("applescript", RiskKind::Script, M),
    ("workflow", RiskKind::Script, M),
    ("action", RiskKind::Script, M),
    ("dylib", RiskKind::Executable, M),
    ("kext", RiskKind::Executable, M),
    ("plugin", RiskKind::Executable, M),
    ("bundle", RiskKind::Executable, M),
    ("prefpane", RiskKind::Executable, M),
    ("osax", RiskKind::Executable, M),
    ("pkg", RiskKind::Installer, M),
    ("mpkg", RiskKind::Installer, M),
    (
        "mobileconfig",
        RiskKind::Installer,
        Platforms(Platforms::MACOS.0 | Platforms::IOS.0),
    ),
    // Unix shells and Linux desktops.
    ("sh", RiskKind::Script, ML),
    ("bash", RiskKind::Script, ML),
    ("zsh", RiskKind::Script, ML),
    ("csh", RiskKind::Script, ML),
    ("ksh", RiskKind::Script, ML),
    ("fish", RiskKind::Script, ML),
    ("run", RiskKind::Executable, L),
    ("bin", RiskKind::Executable, L),
    ("appimage", RiskKind::Executable, L),
    ("so", RiskKind::Executable, L),
    ("desktop", RiskKind::Shortcut, L),
    ("deb", RiskKind::Installer, L),
    ("rpm", RiskKind::Installer, L),
    ("snap", RiskKind::Installer, L),
    ("flatpak", RiskKind::Installer, L),
    ("flatpakref", RiskKind::Installer, L),
    ("flatpakrepo", RiskKind::Installer, L),
    // Android.
    ("apk", RiskKind::Installer, Platforms::ANDROID),
    ("apks", RiskKind::Installer, Platforms::ANDROID),
    ("xapk", RiskKind::Installer, Platforms::ANDROID),
    ("aab", RiskKind::Installer, Platforms::ANDROID),
    // Active content wherever a browser or help viewer opens it.
    ("html", RiskKind::ActiveContent, A),
    ("htm", RiskKind::ActiveContent, A),
    ("xhtml", RiskKind::ActiveContent, A),
    ("xht", RiskKind::ActiveContent, A),
    ("shtml", RiskKind::ActiveContent, A),
    ("mht", RiskKind::ActiveContent, A),
    ("mhtml", RiskKind::ActiveContent, A),
    ("svg", RiskKind::ActiveContent, A),
    ("chm", RiskKind::ActiveContent, W),
    ("hlp", RiskKind::ActiveContent, W),
];

/// Ordinary document, media, and archive extensions: what a disguised
/// name pretends to be ("invoice.pdf.exe").
const BENIGN: &[&str] = &[
    "pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "odt", "ods", "odp", "rtf", "txt", "csv",
    "md", "pages", "numbers", "key", "epub", "json", "xml", "jpg", "jpeg", "png", "gif", "bmp",
    "tif", "tiff", "webp", "heic", "heif", "avif", "raw", "dng", "psd", "mp3", "mp4", "m4a", "m4v",
    "mov", "avi", "mkv", "wav", "flac", "aac", "ogg", "opus", "webm", "wmv", "zip", "rar", "7z",
    "gz", "tgz", "tar", "bz2", "xz", "zst", "eml", "msg", "ics", "vcf",
];

/// Names Windows Explorer processes when it merely displays the folder
/// (custom icons and remote resource lookups), compared
/// ASCII-case-insensitively.
const SHELL_PROCESSED_NAMES: &[&str] = &["desktop.ini", "autorun.inf", "folder.htt"];

/// Extensions of shortcut-like files Explorer resolves (icon, target, or
/// search location) when it displays a folder, with no click. A remote
/// path there leaks the user's NTLM credentials (for example
/// CVE-2025-24054 for `.library-ms`).
const SHELL_PROCESSED_EXTENSIONS: &[&str] = &[
    "lnk",
    "url",
    "scf",
    "website",
    "library-ms",
    "searchconnector-ms",
    "settingcontent-ms",
];

/// Directory extensions macOS treats as an application or loadable
/// bundle.
const BUNDLE_EXTENSIONS: &[&str] = &[
    "app",
    "appex",
    "bundle",
    "framework",
    "kext",
    "plugin",
    "prefpane",
    "qlgenerator",
    "mdimporter",
    "saver",
    "xpc",
    "action",
    "workflow",
    "scptd",
    "pkg",
    "mpkg",
];

/// The final extension of `name`, as written: the text after the last
/// `.`, unless the dot starts the name, the text is empty or longer than
/// 24 characters, or it contains a space.
pub(crate) fn final_extension(name: &str) -> Option<&str> {
    let dot = name.rfind('.')?;
    if dot == 0 {
        return None;
    }
    let extension = &name[dot + 1..];
    let count = extension.chars().count();
    if count == 0 || count > 24 || extension.chars().any(super::chars::is_space) {
        return None;
    }
    Some(extension)
}

fn lookup<'t>(table: &'t [&str], extension: &str) -> Option<&'t str> {
    table
        .iter()
        .copied()
        .find(|candidate| candidate.eq_ignore_ascii_case(extension))
}

/// The risk of extension `extension` (without the dot).
#[must_use]
pub fn extension_risk(extension: &str) -> Option<ExtensionRisk> {
    RISKS
        .iter()
        .find(|(candidate, _, _)| candidate.eq_ignore_ascii_case(extension))
        .map(|&(_, kind, platforms)| ExtensionRisk { kind, platforms })
}

/// Whether `extension` is an ordinary document, media, or archive type.
pub(crate) fn is_benign(extension: &str) -> bool {
    lookup(BENIGN, extension).is_some()
}

/// Whether `extension` appears in either table.
pub(crate) fn is_known(extension: &str) -> bool {
    is_benign(extension) || extension_risk(extension).is_some()
}

/// Whether Explorer acts on this file merely by displaying its folder.
pub(crate) fn is_shell_processed(name: &str) -> bool {
    lookup(SHELL_PROCESSED_NAMES, name).is_some()
        || final_extension(name)
            .is_some_and(|ext| lookup(SHELL_PROCESSED_EXTENSIONS, ext).is_some())
}

/// Whether a directory with this name is a macOS bundle.
pub(crate) fn is_bundle_directory(name: &str) -> bool {
    final_extension(name).is_some_and(|ext| lookup(BUNDLE_EXTENSIONS, ext).is_some())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extensions_and_tables() {
        assert_eq!(final_extension("a.tar.gz"), Some("gz"));
        assert_eq!(final_extension(".bashrc"), None);
        assert_eq!(final_extension("noext"), None);
        assert_eq!(final_extension("a.b c"), None);
        assert_eq!(
            extension_risk("EXE").map(|risk| risk.kind),
            Some(RiskKind::Executable)
        );
        assert!(extension_risk("pdf").is_none());
        assert!(is_benign("PDF"));
        assert!(is_known("lnk"));
        assert!(is_shell_processed("Desktop.INI"));
        assert!(is_shell_processed("x.Library-MS"));
        assert!(!is_shell_processed("x.txt"));
        assert!(is_bundle_directory("Thing.app"));
        assert!(!is_bundle_directory("Thing"));
        for (extension, _, platforms) in RISKS {
            assert!(!platforms.is_empty(), "{extension}");
            assert!(
                extension
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-'),
                "{extension}"
            );
        }
        assert_eq!(
            format!("{:?}", Platforms::WINDOWS.union(Platforms::IOS)),
            "{\"windows\", \"ios\"}"
        );
    }
}
