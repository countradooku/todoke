//! Local names for peer-supplied manifest names.
//!
//! The manifest decoder (`todoke_proto::transfer::manifest`) already
//! rejects everything PROTOCOL §7.1 forbids: non-NFC names, empty names,
//! `.` and `..`, NUL, `/`, `\`, ASCII controls, trailing spaces and dots,
//! `: * ? " < > |`, the DOS device stems, exact sibling duplicates, depth
//! above 64, and paths above 4096 bytes. Those are rejections, never
//! repairs. This module maps each remaining name onto a name this device
//! can show and store safely, deterministically and visibly:
//!
//! | Hazard | Rewrite | [`Change`] |
//! | --- | --- | --- |
//! | Bidi controls (U+061C, U+200E, U+200F, U+202A–U+202E, U+2066–U+2069), C1 controls, zero-width and other invisible format characters, tags, noncharacters | Each becomes U+FFFD | [`Change::InvisibleCharacters`] |
//! | Zero-width joiners and variation selectors outside non-ASCII text, or inside the extension | U+FFFD | [`Change::InvisibleCharacters`] |
//! | A full-stop look-alike before a known extension (`photo\u{2024}jpg.exe`) | `_` | [`Change::LookalikeDot`] |
//! | Spaces padding the final extension away (`report.pdf      .exe`) | Removed | [`Change::PaddedExtension`] |
//! | A final extension spelled with look-alike letters (`file.ехе`) | `_` for each non-ASCII letter | [`Change::ConfusableExtension`] |
//! | A document or media extension in front of a risky one (`invoice.pdf.exe`) | Inner dots become `_` | [`Change::DoubleExtension`] |
//! | Files Explorer processes when it merely lists the folder (`.lnk`, `.url`, `.scf`, `.library-ms`, `desktop.ini`, …) | `.txt` appended | [`Change::ShellFileNeutralized`] |
//! | Windows device names beyond §7.1 (Microsoft's `COM¹`–`COM³` and `LPT¹`–`LPT³`, a device stem with trailing spaces such as `CON .txt`, and conservatively `COM0`, `LPT0`, `CONIN$`, `CONOUT$`, `CLOCK$`), NTFS metafile names, and todoke's own temporary-name prefix | `_` prefixed | [`Change::ReservedName`] |
//! | Names shaped like an NTFS 8.3 short name (`REPORT~1.PDF`), which can alias another file | `~` becomes `_` | [`Change::ShortNameAlias`] |
//! | Components longer than the filesystem allows | Truncated at a character boundary, extension kept | [`Change::Truncated`] |
//!
//! Collisions are resolved by [`crate::DestinationPlan`], with a
//! `" (2)"`-style suffix. Alternate data streams cannot be named: `:` is
//! already forbidden.

pub(crate) mod chars;
pub mod extension;
pub(crate) mod fold;

use unicode_normalization::UnicodeNormalization as _;

use chars::Class;
use extension::{extension_risk, final_extension, is_benign, is_known, is_shell_processed};

/// The longest component, in UTF-8 bytes, every supported filesystem
/// stores: ext4, APFS, and Android's f2fs allow 255 bytes; NTFS and exFAT
/// allow 255 UTF-16 code units, never fewer than the UTF-8 bytes.
pub const MAX_COMPONENT_BYTES: usize = 255;

/// The prefix of todoke's temporary files in a destination directory.
pub(crate) const TEMP_PREFIX: &str = ".todoke-";

/// How a name was rewritten.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Change {
    /// Characters §7.1 forbids (path separators, `: * ? " < > |`,
    /// controls) became `_`, or a `.`/`..`/empty name became `_`. Never
    /// needed for a name the manifest decoder accepted.
    ForbiddenCharacters,
    /// Invisible or direction-changing characters became U+FFFD.
    InvisibleCharacters,
    /// A character drawn like a full stop became `_`.
    LookalikeDot,
    /// Spaces before the final extension were removed.
    PaddedExtension,
    /// Look-alike letters in the final extension became `_`.
    ConfusableExtension,
    /// Dots before a risky final extension became `_`.
    DoubleExtension,
    /// `.txt` was appended to a file the Windows shell processes on sight.
    ShellFileNeutralized,
    /// A reserved name got a `_` prefix.
    ReservedName,
    /// `~` in a short-name-shaped name became `_`.
    ShortNameAlias,
    /// The name was shortened to fit the filesystem.
    Truncated,
    /// A suffix such as `" (2)"` separates it from a sibling that this or
    /// another filesystem would treat as the same name (case, Unicode
    /// normalization, or an earlier rewrite).
    Collision,
    /// A suffix such as `" (2)"` avoids an entry already in the
    /// destination.
    Exists,
}

/// Name rewriting options.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NameRules {
    /// The longest component in UTF-8 bytes, at most
    /// [`MAX_COMPONENT_BYTES`].
    pub max_component_bytes: usize,
    /// Append `.txt` to files the Windows shell processes when it lists
    /// their folder ([`Change::ShellFileNeutralized`]).
    pub neutralize_shell_files: bool,
}

impl NameRules {
    /// The defaults: 255-byte components, shell files neutralized. The
    /// rules are the same on every platform, so received names stay safe
    /// when copied to another system.
    pub const PORTABLE: Self = Self {
        max_component_bytes: MAX_COMPONENT_BYTES,
        neutralize_shell_files: true,
    };
}

impl Default for NameRules {
    fn default() -> Self {
        Self::PORTABLE
    }
}

/// Whether the entry is a regular file or a directory.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A regular file.
    File,
    /// A directory.
    Directory,
}

/// Windows device names, matched ASCII-case-insensitively against the part
/// before the first dot with trailing spaces removed, as Win32 path
/// parsing does. Microsoft's list ("Naming Files, Paths, and Namespaces")
/// is CON, PRN, AUX, NUL, COM1–COM9, COM¹–COM³, LPT1–LPT9, and LPT¹–LPT³,
/// also followed by an extension; §7.1 already rejects all but the
/// superscript forms. COM0, LPT0 (NT namespace aliases), and the console
/// and clock devices CONIN$, CONOUT$, and CLOCK$ are added
/// conservatively.
const DEVICES: &[&str] = &[
    "CON",
    "PRN",
    "AUX",
    "NUL",
    "COM0",
    "COM1",
    "COM2",
    "COM3",
    "COM4",
    "COM5",
    "COM6",
    "COM7",
    "COM8",
    "COM9",
    "COM\u{B9}",
    "COM\u{B2}",
    "COM\u{B3}",
    "LPT0",
    "LPT1",
    "LPT2",
    "LPT3",
    "LPT4",
    "LPT5",
    "LPT6",
    "LPT7",
    "LPT8",
    "LPT9",
    "LPT\u{B9}",
    "LPT\u{B2}",
    "LPT\u{B3}",
    "CONIN$",
    "CONOUT$",
    "CLOCK$",
];

/// NTFS metadata files, reserved in a volume's root directory.
const NTFS_METAFILES: &[&str] = &[
    "$MFT", "$MFTMirr", "$LogFile", "$Volume", "$AttrDef", "$Bitmap", "$Boot", "$BadClus",
    "$Secure", "$UpCase", "$Extend", "$Quota", "$ObjId", "$Reparse",
];

/// Rewrites one manifest name component for local use. `name` should
/// already have passed `todoke_proto::transfer::manifest::validate_name`;
/// anything else still yields a valid name. The result is a single
/// component that passes that same check, contains no character the
/// sanitizer replaces, and fits `rules`.
#[must_use]
pub fn sanitize_component(name: &str, kind: Kind, rules: &NameRules) -> (String, Vec<Change>) {
    // A rewrite can expose another hazard (truncation can leave spaces in
    // front of a new final extension), so repeat until nothing changes.
    let (mut current, mut changes) = sanitize_once(name, kind, rules);
    for _ in 0..4 {
        let (next, more) = sanitize_once(&current, kind, rules);
        if next == current {
            return (current, changes);
        }
        for change in more {
            if !changes.contains(&change) {
                changes.push(change);
            }
        }
        current = next;
    }
    // Unreachable in practice (the property tests check that one more
    // pass is a no-op); fall back to a fixed safe name.
    if !changes.contains(&Change::ReservedName) {
        changes.push(Change::ReservedName);
    }
    ("_unnamed".to_owned(), changes)
}

fn sanitize_once(name: &str, kind: Kind, rules: &NameRules) -> (String, Vec<Change>) {
    let mut changes = Vec::new();
    let mut note = |change: Change| {
        if !changes.contains(&change) {
            changes.push(change);
        }
    };
    let name = replace_forbidden(name, &mut note);
    let mut name = replace_invisible(&name, &mut note);
    name = replace_lookalike_dots(&name, &mut note);
    name = remove_extension_padding(&name, &mut note);
    name = replace_confusable_extension(&name, &mut note);
    name = split_double_extension(&name, &mut note);
    if kind == Kind::File && rules.neutralize_shell_files && is_shell_processed(&name) {
        name.push_str(".txt");
        note(Change::ShellFileNeutralized);
    }
    if is_reserved(&name) {
        name.insert(0, '_');
        note(Change::ReservedName);
    }
    if looks_like_short_name(&name) {
        name = name.replace('~', "_");
        note(Change::ShortNameAlias);
    }
    let limit = rules.max_component_bytes.clamp(16, MAX_COMPONENT_BYTES);
    if name.len() > limit {
        name = truncate_keeping_extension(&name, limit);
        note(Change::Truncated);
    }
    let name = finalize(&name, &mut note);
    (name, changes)
}

/// The name with a collision suffix: `"stem (n).ext"` for a file with an
/// extension, `"name (n)"` otherwise, shortened to fit `limit` bytes.
#[must_use]
pub(crate) fn with_suffix(name: &str, n: u32, kind: Kind, limit: usize) -> String {
    let suffix = format!(" ({n})");
    let (stem, extension) = match (kind, final_extension(name)) {
        // Keep the extension only if the stem keeps at least one byte.
        (Kind::File, Some(extension)) if suffix.len() + extension.len() + 2 <= limit => {
            (&name[..name.len() - extension.len() - 1], extension)
        }
        _ => (name, ""),
    };
    let tail = if extension.is_empty() {
        suffix
    } else {
        format!("{suffix}.{extension}")
    };
    let room = limit.saturating_sub(tail.len());
    let stem = trim_trailing(cut(stem, room));
    let stem = if stem.is_empty() { "_" } else { stem };
    let mut out = String::with_capacity(stem.len() + tail.len());
    out.push_str(stem);
    out.push_str(&tail);
    out
}

/// Whether `name` is reserved on some supported platform (or is
/// todoke's temporary-name prefix).
pub(crate) fn is_reserved(name: &str) -> bool {
    let stem = name.split('.').next().unwrap_or(name).trim_end_matches(' ');
    DEVICES.iter().any(|device| eq_ascii_ci(stem, device))
        || NTFS_METAFILES.iter().any(|meta| eq_ascii_ci(name, meta))
        || name
            .get(..TEMP_PREFIX.len())
            .is_some_and(|prefix| prefix.eq_ignore_ascii_case(TEMP_PREFIX))
}

/// ASCII-case-insensitive equality that also compares non-ASCII
/// characters exactly.
fn eq_ascii_ci(a: &str, b: &str) -> bool {
    a.len() == b.len() && a.eq_ignore_ascii_case(b)
}

/// Defense in depth for callers that pass unchecked names: trailing
/// spaces and dots go, §7.1's forbidden characters become `_`, and a name
/// that is then empty (`.`, `..`, the empty name) becomes `_`.
fn replace_forbidden(name: &str, note: &mut impl FnMut(Change)) -> String {
    let forbidden = |c: char| {
        c.is_ascii_control() || matches!(c, '/' | '\\' | ':' | '*' | '?' | '"' | '<' | '>' | '|')
    };
    let trimmed = trim_trailing(name);
    if trimmed.is_empty() {
        note(Change::ForbiddenCharacters);
        return "_".to_owned();
    }
    if trimmed.len() == name.len() && !name.contains(forbidden) {
        return name.to_owned();
    }
    note(Change::ForbiddenCharacters);
    trimmed
        .chars()
        .map(|c| if forbidden(c) { '_' } else { c })
        .collect()
}

fn replace_invisible(name: &str, note: &mut impl FnMut(Change)) -> String {
    let extension_start = final_extension(name).map(|extension| name.len() - extension.len());
    let mut out = String::with_capacity(name.len());
    let mut previous: Option<char> = None;
    for (at, c) in name.char_indices() {
        let keep = match chars::classify(c) {
            Class::Plain => true,
            Class::Hidden => false,
            // A joiner or selector belongs to the character before it:
            // keep it after non-ASCII, visible text outside the extension.
            Class::Joiner => {
                extension_start.is_none_or(|start| at < start)
                    && previous.is_some_and(|p| {
                        !p.is_ascii()
                            && !chars::is_space(p)
                            && p != '\u{FFFD}'
                            && chars::classify(p) != Class::Hidden
                    })
            }
        };
        if keep {
            out.push(c);
            previous = Some(c);
        } else {
            out.push('\u{FFFD}');
            previous = Some('\u{FFFD}');
            note(Change::InvisibleCharacters);
        }
    }
    out
}

fn replace_lookalike_dots(name: &str, note: &mut impl FnMut(Change)) -> String {
    let mut out = String::with_capacity(name.len());
    for (at, c) in name.char_indices() {
        if chars::is_dot_lookalike(c) {
            let rest = &name[at + c.len_utf8()..];
            let word_len = rest
                .find(|r: char| !r.is_ascii_alphanumeric())
                .unwrap_or(rest.len());
            let word = &rest[..word_len];
            let boundary = rest[word_len..]
                .chars()
                .next()
                .is_none_or(|next| next == '.' || chars::is_space(next));
            if (1..=8).contains(&word.len()) && boundary && is_known(word) {
                out.push('_');
                note(Change::LookalikeDot);
                continue;
            }
        }
        out.push(c);
    }
    out
}

fn remove_extension_padding(name: &str, note: &mut impl FnMut(Change)) -> String {
    let Some(extension) = final_extension(name) else {
        return name.to_owned();
    };
    let dot = name.len() - extension.len() - 1;
    let stem = &name[..dot];
    let trimmed = stem.trim_end_matches(chars::is_space);
    if trimmed.len() == stem.len() {
        return name.to_owned();
    }
    note(Change::PaddedExtension);
    let stem = if trimmed.is_empty() { "_" } else { trimmed };
    format!("{stem}.{extension}")
}

fn replace_confusable_extension(name: &str, note: &mut impl FnMut(Change)) -> String {
    let Some(extension) = final_extension(name) else {
        return name.to_owned();
    };
    if extension.is_ascii() {
        return name.to_owned();
    }
    let skeleton: Option<String> = extension.chars().map(chars::ascii_skeleton).collect();
    if !skeleton.is_some_and(|skeleton| is_known(&skeleton)) {
        return name.to_owned();
    }
    note(Change::ConfusableExtension);
    let dot = name.len() - extension.len();
    let mut out = String::with_capacity(name.len());
    out.push_str(&name[..dot]);
    out.extend(
        extension
            .chars()
            .map(|c| if c.is_ascii() { c } else { '_' }),
    );
    out
}

fn split_double_extension(name: &str, note: &mut impl FnMut(Change)) -> String {
    let Some(extension) = final_extension(name) else {
        return name.to_owned();
    };
    if extension_risk(extension).is_none() {
        return name.to_owned();
    }
    let stem = &name[..name.len() - extension.len() - 1];
    let disguised = stem
        .split('.')
        .skip(1)
        .any(|part| is_benign(part.trim_matches(chars::is_space)));
    if !disguised {
        return name.to_owned();
    }
    note(Change::DoubleExtension);
    format!("{}.{extension}", stem.replace('.', "_"))
}

/// Shaped like an NTFS 8.3 short name: up to six characters, `~`, one to
/// six digits (the base and digits together at most eight), and an
/// optional extension of one to three characters, with no other dot.
fn looks_like_short_name(name: &str) -> bool {
    let (base, extension) = match name.split_once('.') {
        Some((base, extension)) => (base, Some(extension)),
        None => (name, None),
    };
    if extension.is_some_and(|extension| {
        extension.is_empty() || extension.chars().count() > 3 || extension.contains('.')
    }) {
        return false;
    }
    let Some((prefix, digits)) = base.rsplit_once('~') else {
        return false;
    };
    let prefix_len = prefix.chars().count();
    (1..=6).contains(&prefix_len)
        && (1..=6).contains(&digits.len())
        && prefix_len + 1 + digits.len() <= 8
        && digits.bytes().all(|b| b.is_ascii_digit())
}

/// The longest prefix of `text` of at most `limit` bytes that ends at a
/// character boundary and does not separate a character from the
/// combining marks, joiners, or selectors that follow it.
fn cut(text: &str, limit: usize) -> &str {
    if text.len() <= limit {
        return text;
    }
    let mut end = limit;
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    while end > 0 {
        let next = text[end..].chars().next();
        let attached = next.is_some_and(|c| {
            unicode_normalization::char::is_combining_mark(c) || chars::classify(c) == Class::Joiner
        });
        let after_joiner = text[..end]
            .chars()
            .next_back()
            .is_some_and(|c| chars::classify(c) == Class::Joiner);
        if !attached && !after_joiner {
            break;
        }
        end -= text[..end].chars().next_back().map_or(1, char::len_utf8);
    }
    &text[..end]
}

/// Removes trailing ASCII spaces and dots, which Windows strips.
fn trim_trailing(text: &str) -> &str {
    text.trim_end_matches([' ', '.'])
}

fn truncate_keeping_extension(name: &str, limit: usize) -> String {
    match final_extension(name) {
        Some(extension) if extension.len() + 2 <= limit / 2 => {
            let stem = &name[..name.len() - extension.len() - 1];
            let stem = trim_trailing(cut(stem, limit - extension.len() - 1));
            let stem = if stem.is_empty() { "_" } else { stem };
            format!("{stem}.{extension}")
        }
        _ => {
            let kept = trim_trailing(cut(name, limit));
            if kept.is_empty() {
                "_".to_owned()
            } else {
                kept.to_owned()
            }
        }
    }
}

/// NFC, then a last check against the §7.1 rules and the reserved names;
/// a name that still fails becomes a fixed placeholder (never dropped).
fn finalize(name: &str, note: &mut impl FnMut(Change)) -> String {
    let normalized: String = name.nfc().collect();
    if normalized != *name {
        note(Change::ForbiddenCharacters);
    }
    let name = normalized;
    let trimmed = trim_trailing(&name);
    if trimmed.len() != name.len() {
        note(Change::ForbiddenCharacters);
    }
    let name = trimmed.to_owned();
    if acceptable(&name) {
        return name;
    }
    note(Change::ReservedName);
    let prefixed = format!("_{name}");
    if acceptable(&prefixed) {
        return prefixed;
    }
    "_unnamed".to_owned()
}

/// Whether a local name passes the §7.1 component rules, the reserved
/// names, and contains no character the sanitizer replaces.
pub(crate) fn acceptable(name: &str) -> bool {
    todoke_proto::transfer::manifest::validate_name(name.as_bytes()).is_ok()
        && !is_reserved(name)
        && !name.chars().any(|c| chars::classify(c) == Class::Hidden)
        && name.len() <= MAX_COMPONENT_BYTES
}

#[cfg(test)]
mod tests;
