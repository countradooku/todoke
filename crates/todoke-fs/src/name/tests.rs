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
    assert!(
        nfd_utf16_units(output) <= MAX_COMPONENT_NFD_UNITS,
        "{input:?}"
    );
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

/// HFS+ (and some SMB and NFS servers) store a name as its canonical
/// decomposition in UTF-16 and refuse more than 255 units. Precomposed
/// characters can need more units decomposed than bytes in UTF-8: U+1F82
/// (Greek alpha with psili, varia, and ypogegrammeni) is 3 bytes and 4
/// units, U+0390 is 2 bytes and 3 units. Such names are shortened before
/// consent, visibly, instead of failing with ENAMETOOLONG afterwards.
#[test]
fn components_fit_the_decomposed_utf16_limit_too() {
    let alpha = "\u{1F82}";
    assert_eq!(nfd_utf16_units(alpha), 4);
    assert_eq!(nfd_utf16_units("\u{390}"), 3);
    assert_eq!(nfd_utf16_units("\u{1EC7}"), 3);
    assert_eq!(nfd_utf16_units("\u{AC01}"), 3);
    // 85 of them: 255 bytes, which §7.1 allows, but 340 units.
    let over = alpha.repeat(85);
    assert!(validate_name(over.as_bytes()).is_ok());
    assert!(!acceptable(&over));
    let (output, changes) = file(&over);
    assert!(changes.contains(&Change::Truncated));
    assert_eq!(output, alpha.repeat(63));
    check_output(&over, &output);
    // At the limit: 63 are 252 units and stay; 64 are 256 and do not.
    assert_eq!(file(&alpha.repeat(63)), (alpha.repeat(63), Vec::new()));
    assert_eq!(file(&alpha.repeat(64)).0, alpha.repeat(63));
    // Three-byte characters that decompose to three units fill both
    // limits exactly and are unchanged.
    let viet = "\u{1EC7}".repeat(85);
    assert_eq!(nfd_utf16_units(&viet), 255);
    assert_eq!(file(&viet), (viet.clone(), Vec::new()));
    let hangul = format!("{}.txt", "\u{AC01}".repeat(83));
    assert_eq!(file(&hangul), (hangul.clone(), Vec::new()));
    // The extension is kept.
    let named = format!("{}.txt", alpha.repeat(70));
    let (output, changes) = file(&named);
    assert!(changes.contains(&Change::Truncated));
    assert_eq!(output, format!("{}.txt", alpha.repeat(62)));
    check_output(&named, &output);
    // Suffixes respect it too.
    let suffixed = with_suffix(&alpha.repeat(63), 2, Kind::File, MAX_COMPONENT_BYTES);
    assert!(suffixed.ends_with(" (2)"), "{suffixed:?}");
    check_output(&alpha.repeat(63), &suffixed);
    let suffixed = with_suffix(&format!("{}.txt", alpha.repeat(62)), 1001, Kind::File, 255);
    assert!(suffixed.ends_with(" (1001).txt"), "{suffixed:?}");
    check_output("suffix", &suffixed);
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
            Just("\u{1F82}".repeat(9)),
            Just("\u{390}".repeat(9)),
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

/// Each full-stop look-alike before a known extension is exposed, and only
/// where the word after it is a whole extension: followed by a dot, a
/// space, or the end of the name, and at most eight letters long.
#[test]
fn every_dot_lookalike_before_a_known_extension_is_exposed() {
    for dot in [
        '\u{00B7}', '\u{0701}', '\u{0702}', '\u{06D4}', '\u{2024}', '\u{2027}', '\u{2219}',
        '\u{22C5}', '\u{2E33}', '\u{3002}', '\u{A4F8}', '\u{FE52}', '\u{FF0E}', '\u{FF61}',
    ] {
        let input = format!("photo{dot}jpg.exe");
        let (output, changes) = file(&input);
        assert_eq!(output, "photo_jpg.exe", "{:04X}", dot as u32);
        assert!(
            changes.contains(&Change::LookalikeDot),
            "{:04X}",
            dot as u32
        );
        check_output(&input, &output);
    }
    for (input, expected) in [
        ("a\u{2024}pdf x", "a_pdf x"),
        // Eight letters, the longest the rule considers.
        ("x\u{2024}appimage", "x_appimage"),
    ] {
        let (output, changes) = file(input);
        assert_eq!(output, expected, "{input:?}");
        assert_eq!(changes, [Change::LookalikeDot], "{input:?}");
    }
    // Not a whole word: the next character continues it.
    for unchanged in ["a\u{2024}pdf-x", "a\u{2024}pdfx", "a\u{2024}.txt"] {
        assert_eq!(
            file(unchanged),
            (unchanged.to_owned(), Vec::new()),
            "{unchanged:?}"
        );
    }
}

/// Every space separator pads an extension away; each is removed.
#[test]
fn every_space_separator_padding_an_extension_is_removed() {
    for space in [
        ' ', '\u{00A0}', '\u{1680}', '\u{2000}', '\u{2005}', '\u{200A}', '\u{202F}', '\u{205F}',
        '\u{3000}',
    ] {
        let input = format!("report.pdf{space}{space}.exe");
        let (output, changes) = file(&input);
        assert_eq!(output, "report_pdf.exe", "{:04X}", space as u32);
        assert!(
            changes.contains(&Change::PaddedExtension),
            "{:04X}",
            space as u32
        );
    }
}

/// Joiners survive only right after visible non-ASCII text outside the
/// extension: not after a space, not after a replaced character, and not
/// inside the extension even after non-ASCII text.
#[test]
fn joiners_are_kept_only_inside_non_ascii_text() {
    for (input, expected) in [
        ("a\u{3000}\u{200D}b", "a\u{3000}\u{FFFD}b"),
        ("\u{4E2D}\u{3000}\u{FE0F}", "\u{4E2D}\u{3000}\u{FFFD}"),
        ("\u{202E}\u{200D}x", "\u{FFFD}\u{FFFD}x"),
        ("a.\u{4E2D}\u{200D}", "a.\u{4E2D}\u{FFFD}"),
    ] {
        let (output, changes) = file(input);
        assert_eq!(output, expected, "{input:?}");
        assert!(changes.contains(&Change::InvisibleCharacters), "{input:?}");
        check_output(input, &output);
    }
    assert_eq!(
        file("\u{4E2D}\u{200D}\u{6587}.txt"),
        ("\u{4E2D}\u{200D}\u{6587}.txt".to_owned(), Vec::new())
    );
}

/// A name of a document extension in front of nothing is not a double
/// extension; nor is a plain risky name.
#[test]
fn a_single_extension_is_not_a_disguise() {
    for unchanged in ["pdf.exe", "report.exe", "a.b.exe"] {
        assert_eq!(
            file(unchanged),
            (unchanged.to_owned(), Vec::new()),
            "{unchanged:?}"
        );
    }
    // A benign part padded with spaces still counts, and so does one
    // after a leading dot.
    assert_eq!(file("x. pdf .exe").0, "x_ pdf.exe");
    assert_eq!(file(".pdf.exe").0, "_pdf.exe");
}

#[test]
fn every_shell_processed_name_is_neutralized() {
    for (input, expected) in [
        ("x.website", "x.website.txt"),
        ("x.WEBSITE", "x.WEBSITE.txt"),
        ("x.settingcontent-ms", "x.settingcontent-ms.txt"),
        ("x.SearchConnector-MS", "x.SearchConnector-MS.txt"),
        ("Folder.htt", "Folder.htt.txt"),
    ] {
        let (output, changes) = file(input);
        assert_eq!(output, expected, "{input:?}");
        assert_eq!(changes, [Change::ShellFileNeutralized], "{input:?}");
    }
    for unchanged in ["x.lnkx", "lnk", "desktop.ini.bak", "x.url2"] {
        assert_eq!(file(unchanged).0, unchanged, "{unchanged:?}");
    }
}

#[test]
fn every_ntfs_metafile_name_is_prefixed() {
    for name in [
        "$MFT", "$MFTMirr", "$LogFile", "$Volume", "$AttrDef", "$Bitmap", "$Boot", "$BadClus",
        "$Secure", "$UpCase", "$Extend", "$Quota", "$ObjId", "$Reparse", "$mftmirr", "$LOGFILE",
    ] {
        assert_eq!(
            file(name),
            (format!("_{name}"), vec![Change::ReservedName]),
            "{name}"
        );
    }
    for unchanged in ["$MFT.txt", "$Secure2", "MFT"] {
        assert_eq!(file(unchanged).0, unchanged, "{unchanged:?}");
    }
}

/// A truncation that leaves a Windows device name behind (spaces after the
/// stem are cut away) still yields a prefixed name.
#[test]
fn a_device_name_exposed_by_truncation_is_prefixed() {
    let input = format!("CON{}x", " ".repeat(20));
    assert!(validate_name(input.as_bytes()).is_ok());
    let rules = NameRules {
        max_component_bytes: 16,
        ..RULES
    };
    let (output, changes) = sanitize_component(&input, Kind::File, &rules);
    assert_eq!(output, "_CON");
    assert!(changes.contains(&Change::Truncated), "{changes:?}");
    assert!(changes.contains(&Change::ReservedName), "{changes:?}");
    check_output(&input, &output);
}

/// A rewrite that exposes another hazard is handled by a further pass:
/// here truncation leaves spaces padding a new final extension, behind a
/// document extension.
#[test]
fn hazards_exposed_by_truncation_are_rewritten_too() {
    let input = format!(
        "{}.pdf{}.exe  {}",
        "b".repeat(240),
        " ".repeat(5),
        "x".repeat(10)
    );
    let (output, changes) = file(&input);
    assert_eq!(output, format!("{}_pdf.exe", "b".repeat(240)));
    for change in [
        Change::Truncated,
        Change::PaddedExtension,
        Change::DoubleExtension,
    ] {
        assert!(changes.contains(&change), "{changes:?}");
    }
    check_output(&input, &output);
    assert_eq!(file(&output), (output.clone(), Vec::new()));
}

/// Truncation never separates an emoji sequence at a joiner (neither
/// before nor after it), and a name of nothing but marks becomes `_`.
#[test]
fn truncation_never_splits_a_joined_sequence() {
    let family = "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}";
    assert_eq!(family.len(), 18);
    let input = format!("{}.jpg", family.repeat(5));
    // 60 bytes of stem end inside a joiner's sequence; 61 right after a
    // joiner.
    for limit in [64, 65] {
        let rules = NameRules {
            max_component_bytes: limit,
            ..RULES
        };
        let (output, changes) = sanitize_component(&input, Kind::File, &rules);
        assert_eq!(output, format!("{}.jpg", family.repeat(3)), "{limit}");
        assert_eq!(changes, [Change::Truncated], "{limit}");
    }
    let rules = NameRules {
        max_component_bytes: 64,
        ..RULES
    };
    let marks = "\u{301}".repeat(120);
    assert!(validate_name(marks.as_bytes()).is_ok());
    assert_eq!(sanitize_component(&marks, Kind::File, &rules).0, "_");
    let marks = format!("{}.txt", "\u{301}".repeat(100));
    assert_eq!(sanitize_component(&marks, Kind::File, &rules).0, "_.txt");
}

/// The component limit is clamped to 16..=255 bytes whatever the rules
/// say, and the extension is kept only where it fits beside a suffix.
#[test]
fn limits_are_clamped_and_suffixes_fit() {
    let long = "a".repeat(300);
    for (limit, expected) in [(1000, 255), (256, 255), (0, 16), (15, 16)] {
        let rules = NameRules {
            max_component_bytes: limit,
            ..RULES
        };
        let (output, _) = sanitize_component(&long, Kind::File, &rules);
        assert_eq!(output.len(), expected, "{limit}");
    }
    assert_eq!(
        with_suffix("a.abcdefghijkl", 2, Kind::File, 16),
        "a.abcdefghij (2)"
    );
    assert_eq!(
        with_suffix("a.abcdefghij", 2, Kind::File, 16),
        "a (2).abcdefghij"
    );
    assert_eq!(
        with_suffix(&"\u{301}".repeat(200), 2, Kind::Directory, 255),
        "_ (2)"
    );
    assert_eq!(final_extension_of("a."), None);
    assert_eq!(
        final_extension_of(&format!("a.{}", "x".repeat(24))),
        Some(24)
    );
    assert_eq!(final_extension_of(&format!("a.{}", "x".repeat(25))), None);
}

fn final_extension_of(name: &str) -> Option<usize> {
    extension::final_extension(name).map(str::len)
}
