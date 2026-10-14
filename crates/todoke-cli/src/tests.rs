use proptest::prelude::*;
use todoke_core::api::EntryInfo;

use super::*;

/// Names a malicious peer might send to rewrite the terminal.
#[test]
fn hostile_names_are_escaped() {
    let cases = [
        ("\u{1b}[2J\u{1b}[31mok", "\\u{1b}[2J\\u{1b}[31mok"),
        ("invoice\u{202e}fdp.exe", "invoice\\u{202e}fdp.exe"),
        ("a\u{2066}b\u{2069}c", "a\\u{2066}b\\u{2069}c"),
        ("zero\u{200b}width", "zero\\u{200b}width"),
        ("line\nbreak\rreturn", "line\\u{a}break\\u{d}return"),
        ("bell\u{7}", "bell\\u{7}"),
        ("c1\u{9b}31m", "c1\\u{9b}31m"),
        ("back\\slash", "back\\\\slash"),
        ("bom\u{feff}", "bom\\u{feff}"),
        ("caf\u{e9} \u{1f600}", "caf\u{e9} \u{1f600}"),
        // Tags spelling hidden text, a Hangul filler, a variation selector,
        // a soft hyphen, DEL.
        ("a\u{e0041}\u{e0042}b", "a\\u{e0041}\\u{e0042}b"),
        ("x\u{3164}y", "x\\u{3164}y"),
        ("o\u{fe0f}k", "o\\u{fe0f}k"),
        ("soft\u{ad}hyphen", "soft\\u{ad}hyphen"),
        ("del\u{7f}", "del\\u{7f}"),
    ];
    for (raw, shown) in cases {
        assert_eq!(escape(raw), shown, "{raw:?}");
    }
}

#[test]
fn byte_counts_are_readable() {
    assert_eq!(bytes(0), "0 B");
    assert_eq!(bytes(1023), "1023 B");
    assert_eq!(bytes(1024), "1.0 KiB");
    assert_eq!(bytes(1536), "1.5 KiB");
    assert_eq!(bytes(2 << 30), "2.0 GiB");
    assert_eq!(bytes(u64::MAX), "16777215.9 TiB");
}

#[test]
fn entries_are_shown_as_an_escaped_tree() {
    let list = [
        EntryInfo {
            id: 1,
            parent: 0,
            directory: true,
            name: "album".into(),
            size: 0,
        },
        EntryInfo {
            id: 2,
            parent: 1,
            directory: false,
            name: "evil\u{1b}]0;title\u{7}.jpg".into(),
            size: 2048,
        },
    ];
    let shown = entries(&list);
    assert!(shown.contains("album/"));
    assert!(
        shown.contains("    evil\\u{1b}]0;title\\u{7}.jpg  (2.0 KiB)"),
        "{shown}"
    );
    assert!(!shown.contains('\u{1b}'));
}

/// A cyclic parent chain (a malformed view) cannot loop.
#[test]
fn cyclic_parents_terminate() {
    let list = [
        EntryInfo {
            id: 1,
            parent: 2,
            directory: true,
            name: "a".into(),
            size: 0,
        },
        EntryInfo {
            id: 2,
            parent: 1,
            directory: true,
            name: "b".into(),
            size: 0,
        },
    ];
    assert_eq!(entries(&list).lines().count(), 2);
}

#[test]
fn pairing_text_fits_a_qr_code() -> Result<(), Box<dyn std::error::Error>> {
    // The QR text's length: `TODOKE:` and 1968 Base45 characters (§3.1).
    let text = format!("TODOKE:{}", "0".repeat(1968));
    let drawn = qr(&text)?;
    assert!(drawn.lines().count() > 20);
    Ok(())
}

proptest! {
    /// Escaped output never contains a control or hidden character.
    #[test]
    fn escaped_text_is_inert(text in "\\PC*|[\\x00-\\x1f\\x7f-\\x9f\\u{200b}-\\u{200f}\\u{202a}-\\u{202e}]*") {
        let shown = escape(&text);
        prop_assert!(!shown.chars().any(|c| c.is_control() || todoke_fs::is_invisible(c)));
    }
}

/// `--json` output carries no raw control or invisible character a peer
/// chose, and still means the same.
#[test]
fn json_output_escapes_what_a_terminal_would_act_on() -> Result<(), serde_json::Error> {
    let name = "c1\u{9b}2J osc\u{9d}0;t\u{7} del\u{7f} rlo\u{202e} tag\u{e0041} fill\u{3164}";
    let event = Event::Ended {
        transfer: "aa".into(),
        reason: todoke_core::api::TransferState::Failed,
        message: name.into(),
    };
    let line = json(&event);
    assert!(line.is_ascii(), "{line}");
    assert!(
        line.contains("\\u009b") && line.contains("\\udb40\\udc41"),
        "{line}"
    );
    assert_eq!(serde_json::from_str::<Event>(&line)?, event);
    Ok(())
}
