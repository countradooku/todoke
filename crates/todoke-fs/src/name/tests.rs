//! The hostile-name corpus and sanitizer properties.

use proptest::prelude::*;
use todoke_proto::transfer::manifest::validate_name;

use super::*;

const RULES: NameRules = NameRules::PORTABLE;

fn file(name: &str) -> (String, Vec<Change>) {
    sanitize_component(name, Kind::File, &RULES)
}

/// Every output is a valid local name: one component that passes §7.1,
/// is not reserved, and hides nothing.
fn check_output(input: &str, output: &str) {
    assert!(acceptable(output), "{input:?} -> {output:?}");
    assert!(output.len() <= MAX_COMPONENT_BYTES, "{input:?}");
    assert!(!output.contains(['/', '\\', ':', '\0']), "{input:?}");
    assert!(output != "." && output != "..", "{input:?}");
    assert!(
        !output.chars().any(chars::is_bidi_control),
        "{input:?} -> {output:?}"
    );
}

/// Names the manifest decoder must already reject (§7.1). The sanitizer
/// still produces a safe name for each, as defense in depth.
#[test]
fn traversal_and_forbidden_names_are_rejected_by_the_decoder() {
    let corpus = [
        "",
        ".",
        "..",
        "../etc/passwd",
        "..\\..\\boot.ini",
        "/etc/passwd",
        "\\\\server\\share\\x",
        "\\\\?\\C:\\Windows",
        "C:\\Windows\\win.ini",
        "C:relative",
        "file.txt:Zone.Identifier",
        "file.txt::$DATA",
        "a/b",
        "nul",
        "CON",
        "con.txt",
        "NUL.tar.gz",
        "Com1.log",
        "lpt9",
        "file.",
        "file ",
        "file. . .",
        "...",
        "tab\there",
        "nul\0byte",
        "del\u{7f}",
        "a*b",
        "a?b",
        "a\"b",
        "a<b",
        "a>b",
        "a|b",
        "e\u{301}",
    ];
    for name in corpus {
        assert!(
            validate_name(name.as_bytes()).is_err(),
            "the decoder accepts {name:?}"
        );
        let (output, changes) = file(name);
        check_output(name, &output);
        assert!(!changes.is_empty(), "{name:?}");
    }
}

#[test]
fn windows_device_names_beyond_the_spec_list_are_prefixed() {
    for (input, expected) in [
        ("con  .tar.gz", "_con  .tar.gz"),
        ("COM0.log", "_COM0.log"),
        ("lpt0", "_lpt0"),
        ("COM\u{B9}.txt", "_COM\u{B9}.txt"),
        ("com\u{B2}", "_com\u{B2}"),
        ("LPT\u{B3}.dat", "_LPT\u{B3}.dat"),
        ("CONIN$", "_CONIN$"),
        ("conout$.txt", "_conout$.txt"),
        ("CLOCK$", "_CLOCK$"),
        ("$MFT", "_$MFT"),
        ("$extend", "_$extend"),
        (".todoke-1234.partial", "_.todoke-1234.partial"),
        (".TODOKE-x", "_.TODOKE-x"),
    ] {
        assert!(validate_name(input.as_bytes()).is_ok(), "{input}");
        let (output, changes) = file(input);
        assert_eq!(output, expected);
        assert_eq!(changes, vec![Change::ReservedName], "{input}");
        check_output(input, &output);
    }
    // Padding before the extension goes first, exposing the device name.
    assert_eq!(
        file("CON .txt"),
        (
            "_CON.txt".to_owned(),
            vec![Change::PaddedExtension, Change::ReservedName]
        )
    );
    for unchanged in [
        "COM10.txt",
        "CONSOLE.txt",
        "console",
        "LPT",
        "auxiliary.md",
        "$MFT2",
    ] {
        assert_eq!(file(unchanged), (unchanged.to_owned(), Vec::new()));
    }
}

#[test]
fn bidi_and_invisible_characters_become_visible() {
    for (input, expected) in [
        ("photo\u{202E}gpj.exe", "photo\u{FFFD}gpj.exe"),
        ("photo.jpg\u{202E}exe", "photo.jpg\u{FFFD}exe"),
        ("invoice\u{202E}fdp.scr", "invoice\u{FFFD}fdp.scr"),
        ("\u{202B}left", "\u{FFFD}left"),
        ("a\u{2066}b\u{2069}c", "a\u{FFFD}b\u{FFFD}c"),
        ("\u{061C}x", "\u{FFFD}x"),
        ("\u{200E}\u{200F}", "\u{FFFD}\u{FFFD}"),
        ("pass\u{200B}word.txt", "pass\u{FFFD}word.txt"),
        ("\u{FEFF}readme.txt", "\u{FFFD}readme.txt"),
        ("\u{3164}", "\u{FFFD}"),
        ("x\u{115F}y", "x\u{FFFD}y"),
        ("soft\u{AD}hyphen", "soft\u{FFFD}hyphen"),
        ("c1\u{85}nel", "c1\u{FFFD}nel"),
        ("line\u{2028}sep", "line\u{FFFD}sep"),
        ("tag\u{E0041}\u{E0042}.txt", "tag\u{FFFD}\u{FFFD}.txt"),
        ("a\u{200D}b", "a\u{FFFD}b"),
        ("x.ex\u{200D}e", "x.ex\u{FFFD}e"),
        ("\u{200D}lead", "\u{FFFD}lead"),
        ("non\u{FDD0}char", "non\u{FFFD}char"),
    ] {
        let (output, changes) = file(input);
        assert_eq!(output, expected, "{input:?}");
        assert!(changes.contains(&Change::InvisibleCharacters), "{input:?}");
        check_output(input, &output);
    }
    // Joiners and selectors inside non-ASCII text are part of the text.
    for kept in [
        "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}.jpg",
        "\u{645}\u{6CC}\u{200C}\u{62E}\u{648}\u{627}\u{647}\u{645}.txt",
        "\u{2764}\u{FE0F}.png",
        "\u{915}\u{94D}\u{200D}\u{937}.txt",
    ] {
        assert_eq!(file(kept), (kept.to_owned(), Vec::new()), "{kept:?}");
    }
}

#[test]
fn disguised_extensions_are_exposed() {
    for (input, expected, change) in [
        (
            "invoice.pdf.exe",
            "invoice_pdf.exe",
            Change::DoubleExtension,
        ),
        ("x.PDF.EXE", "x_PDF.EXE", Change::DoubleExtension),
        (
            "report.docx.scr",
            "report_docx.scr",
            Change::DoubleExtension,
        ),
        (
            "my.report.pdf.js",
            "my_report_pdf.js",
            Change::DoubleExtension,
        ),
        ("song.mp3.html", "song_mp3.html", Change::DoubleExtension),
        (
            "report.pdf      .exe",
            "report_pdf.exe",
            Change::PaddedExtension,
        ),
        (
            "report.pdf\u{3000}\u{A0}.exe",
            "report_pdf.exe",
            Change::PaddedExtension,
        ),
        (
            "photo\u{2024}jpg.exe",
            "photo_jpg.exe",
            Change::LookalikeDot,
        ),
        ("doc.pdf\u{FF0E}exe", "doc.pdf_exe", Change::LookalikeDot),
        (
            "\u{8CC7}\u{6599}\u{3002}pdf",
            "\u{8CC7}\u{6599}_pdf",
            Change::LookalikeDot,
        ),
        (
            "file.\u{435}\u{445}\u{435}",
            "file.___",
            Change::ConfusableExtension,
        ),
        (
            "file.\u{FF45}\u{FF58}\u{FF45}",
            "file.___",
            Change::ConfusableExtension,
        ),
        ("photo.jp\u{261}", "photo.jp_", Change::ConfusableExtension),
    ] {
        let (output, changes) = file(input);
        assert_eq!(output, expected, "{input:?}");
        assert!(changes.contains(&change), "{input:?}: {changes:?}");
        check_output(input, &output);
    }
    for unchanged in [
        "archive.tar.gz",
        "setup.v2.exe",
        "v1.0 final.docx",
        "\u{41F}\u{440}\u{438}\u{432}\u{435}\u{442}.\u{43C}\u{438}\u{440}",
        "dots\u{2024}in\u{2024}text words",
        "x.pdf",
        ".bashrc",
    ] {
        assert_eq!(
            file(unchanged),
            (unchanged.to_owned(), Vec::new()),
            "{unchanged:?}"
        );
    }
}

#[test]
fn shell_processed_files_are_neutralized() {
    for (input, expected) in [
        ("invoice.lnk", "invoice.lnk.txt"),
        ("Invoice.LNK", "Invoice.LNK.txt"),
        ("home.url", "home.url.txt"),
        ("x.scf", "x.scf.txt"),
        ("Documents.library-ms", "Documents.library-ms.txt"),
        ("s.searchConnector-ms", "s.searchConnector-ms.txt"),
        ("desktop.ini", "desktop.ini.txt"),
        ("AUTORUN.INF", "AUTORUN.INF.txt"),
    ] {
        let (output, changes) = file(input);
        assert_eq!(output, expected);
        assert_eq!(changes, vec![Change::ShellFileNeutralized]);
    }
    // Directories are not opened by the shell, and the option can be off.
    let (output, changes) = sanitize_component("x.lnk", Kind::Directory, &RULES);
    assert_eq!((output.as_str(), changes.len()), ("x.lnk", 0));
    let rules = NameRules {
        neutralize_shell_files: false,
        ..RULES
    };
    assert_eq!(sanitize_component("x.lnk", Kind::File, &rules).0, "x.lnk");
}

#[test]
fn short_name_aliases_are_broken() {
    for (input, expected) in [
        ("PROGRA~1", "PROGRA_1"),
        ("REPORT~1.PDF", "REPORT_1.PDF"),
        ("a~12345.txt", "a_12345.txt"),
        ("doc~2.d", "doc_2.d"),
    ] {
        assert_eq!(
            file(input),
            (expected.to_owned(), vec![Change::ShortNameAlias])
        );
    }
    for unchanged in [
        "a~b.txt",
        "LONGNAME~1.txt",
        "x~1.html",
        "~1",
        "a~1.b.c",
        "~$doc.docx",
    ] {
        assert_eq!(file(unchanged).0, unchanged, "{unchanged}");
    }
}

#[test]
fn overlong_components_are_truncated_keeping_the_extension() {
    // C1 controls are two UTF-8 bytes, their replacement three.
    let grown = format!("{}.txt", "\u{85}".repeat(125));
    assert!(validate_name(grown.as_bytes()).is_ok());
    let (output, changes) = file(&grown);
    assert!(output.len() <= MAX_COMPONENT_BYTES);
    assert!(output.ends_with("\u{FFFD}.txt"));
    assert!(changes.contains(&Change::Truncated));
    check_output(&grown, &output);
    // Truncation never separates a base character from its marks.
    let marks = format!("{}.txt", "e\u{301}\u{302}".repeat(50));
    let rules = NameRules {
        max_component_bytes: 64,
        ..RULES
    };
    let (output, _) = sanitize_component(&marks, Kind::File, &rules);
    assert!(output.len() <= 64);
    let stem = output.trim_end_matches(".txt");
    assert!(
        stem.ends_with('\u{302}') || stem.ends_with('\u{1EBF}'),
        "{output:?}"
    );
    // A suffix fits too.
    let long = "n".repeat(255);
    let suffixed = with_suffix(&long, 12, Kind::File, MAX_COMPONENT_BYTES);
    assert_eq!(suffixed.len(), MAX_COMPONENT_BYTES);
    assert!(suffixed.ends_with(" (12)"));
    let with_extension = format!("{}.jpeg", "p".repeat(250));
    let suffixed = with_suffix(&with_extension, 3, Kind::File, MAX_COMPONENT_BYTES);
    assert!(suffixed.ends_with(" (3).jpeg") && suffixed.len() <= MAX_COMPONENT_BYTES);
    assert_eq!(with_suffix("dir.v2", 2, Kind::Directory, 255), "dir.v2 (2)");
    assert_eq!(with_suffix("a.tar.gz", 2, Kind::File, 255), "a.tar (2).gz");
}

#[test]
fn ordinary_names_are_unchanged() {
    for name in [
        "a",
        "Report 2024 (final).pdf",
        "\u{65E5}\u{672C}\u{8A9E}.txt",
        "\u{1F600}",
        ".hidden",
        "-dash",
        "x~",
        "with  two spaces",
        " leading space",
        "\u{E9}t\u{E9}.png",
    ] {
        assert_eq!(file(name), (name.to_owned(), Vec::new()), "{name:?}");
    }
}

fn any_name() -> impl Strategy<Value = String> {
    let pieces = prop_oneof![
        4 => "[a-zA-Z0-9 ._~$-]{1,8}",
        2 => any::<char>().prop_map(String::from),
        1 => prop_oneof![
            Just("\u{202E}".to_owned()),
            Just("\u{200D}".to_owned()),
            Just("\u{200C}".to_owned()),
            Just("\u{FE0F}".to_owned()),
            Just("\u{2024}".to_owned()),
            Just(".exe".to_owned()),
            Just(".pdf".to_owned()),
            Just(".lnk".to_owned()),
            Just("CON".to_owned()),
            Just("COM\u{B9}".to_owned()),
            Just("~1".to_owned()),
            Just("\u{435}".to_owned()),
            Just("\u{301}".to_owned()),
            Just("\u{3000}".to_owned()),
            Just("/".to_owned()),
            Just("..".to_owned()),
        ],
    ];
    proptest::collection::vec(pieces, 0..12).prop_map(|parts| parts.concat())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2048))]

    /// Any input yields one safe component, and sanitizing is idempotent.
    #[test]
    fn outputs_are_safe_and_stable(name in any_name(), directory in any::<bool>(), limit in 16_usize..=255) {
        let kind = if directory { Kind::Directory } else { Kind::File };
        let rules = NameRules { max_component_bytes: limit, neutralize_shell_files: true };
        let (output, _) = sanitize_component(&name, kind, &rules);
        check_output(&name, &output);
        prop_assert!(output.len() <= limit);
        let (again, changes) = sanitize_component(&output, kind, &rules);
        prop_assert_eq!(&again, &output, "changes {:?}", changes);
        for n in [2, 9, 10, 1001] {
            let suffixed = with_suffix(&output, n, kind, limit);
            prop_assert!(suffixed.len() <= limit);
            check_output(&output, &suffixed);
        }
    }
}
