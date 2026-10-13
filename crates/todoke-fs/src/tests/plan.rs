//! Destination mapping: sibling collisions, existing names, path limits,
//! warnings, and properties over random trees.

use std::collections::BTreeSet;

use proptest::prelude::*;

use super::*;
use crate::name::fold::collision_key;
use crate::name::{acceptable, extension::RiskKind};
use crate::{Change, DestinationPlan, FsProfile, Kind, PathLimit, Platforms, Rejection, Warning};

const ID: [u8; 16] = [7; 16];

fn plan(specs: &[Spec]) -> AnyResult<DestinationPlan> {
    plan_with(specs, &FsProfile::host(), 10, &[])
}

fn plan_with(
    specs: &[Spec],
    profile: &FsProfile,
    root_len: usize,
    existing: &[&str],
) -> AnyResult<DestinationPlan> {
    let manifest = manifest(ID, specs)?;
    let existing: BTreeSet<String> = existing.iter().map(|name| collision_key(name)).collect();
    Ok(DestinationPlan::new(
        &manifest,
        profile,
        root_len,
        &mut |name| existing.contains(&collision_key(name)),
    ))
}

fn locals(plan: &DestinationPlan) -> Vec<&str> {
    plan.entries()
        .iter()
        .map(|entry| entry.local().as_str())
        .collect()
}

#[test]
fn case_and_unicode_variants_of_siblings_are_separated() -> TestResult {
    let plan = plan(&[
        file("a.txt", 0),
        file("A.TXT", 0),
        file("a (2).txt", 0),
        file("Stra\u{DF}e.txt", 0),
        file("STRASSE.txt", 0),
        file("\u{131}.txt", 0),
        file("I.txt", 0),
        file("i.txt", 0),
        file("\u{130}", 0),
        file("i\u{307}", 0),
        file("\u{3A3}", 0),
        file("\u{3C3}", 0),
        file("\u{3C2}", 0),
        file("\u{FB00}", 0),
        file("FF", 0),
    ])?;
    assert_eq!(
        locals(&plan),
        [
            "a.txt",
            "A (3).TXT",
            "a (2).txt",
            "Stra\u{DF}e.txt",
            "STRASSE (2).txt",
            "\u{131}.txt",
            "I (2).txt",
            "i (3).txt",
            "\u{130}",
            "i\u{307} (2)",
            "\u{3A3}",
            "\u{3C3} (2)",
            "\u{3C2} (3)",
            "\u{FB00}",
            "FF (2)",
        ]
    );
    let changed: Vec<bool> = plan
        .entries()
        .iter()
        .map(|entry| entry.changes() == [Change::Collision])
        .collect();
    assert_eq!(
        changed,
        [
            false, true, false, false, true, false, true, true, false, true, false, true, true,
            false, true
        ]
    );
    Ok(())
}

#[test]
fn sanitized_names_that_collide_are_separated_too() -> TestResult {
    // Both become "photo\u{FFFD}gpj.exe".
    let plan = plan(&[
        file("photo\u{202E}gpj.exe", 0),
        file("photo\u{202D}gpj.exe", 0),
    ])?;
    assert_eq!(
        locals(&plan),
        ["photo\u{FFFD}gpj.exe", "photo\u{FFFD}gpj (2).exe"]
    );
    assert_eq!(
        plan.entry(2).map(crate::PlannedEntry::changes),
        Some(&[Change::InvisibleCharacters, Change::Collision][..])
    );
    Ok(())
}

#[test]
fn only_siblings_collide() -> TestResult {
    let plan = plan(&[
        dir("x", 0),
        dir("y", 0),
        file("same.txt", 1),
        file("same.txt", 2),
        file("SAME.TXT", 1),
    ])?;
    assert_eq!(
        locals(&plan),
        ["x", "y", "same.txt", "same.txt", "SAME (2).TXT"]
    );
    let paths: Vec<Vec<&str>> = (1..=5)
        .filter_map(|id| plan.local_path(id))
        .map(|path| path.iter().map(|name| name.as_str()).collect())
        .collect();
    assert_eq!(paths[2], ["x", "same.txt"]);
    assert_eq!(paths[3], ["y", "same.txt"]);
    assert_eq!(paths[4], ["x", "SAME (2).TXT"]);
    Ok(())
}

#[test]
fn top_level_names_avoid_the_destination_and_each_other() -> TestResult {
    let plan = plan_with(
        &[
            file("photo.jpg", 0),
            file("a.txt", 0),
            file("a (2).txt", 0),
            dir("Folder", 0),
            file("inside.txt", 4),
        ],
        &FsProfile::host(),
        10,
        &["PHOTO.JPG", "photo (2).jpg", "a.txt", "folder"],
    )?;
    assert_eq!(
        locals(&plan),
        [
            "photo (3).jpg",
            "a (3).txt",
            "a (2).txt",
            "Folder (2)",
            "inside.txt"
        ]
    );
    assert_eq!(
        plan.entry(1).map(crate::PlannedEntry::changes),
        Some(&[Change::Exists][..])
    );
    assert_eq!(
        plan.entry(5).map(crate::PlannedEntry::changes),
        Some(&[][..])
    );
    Ok(())
}

/// Found by fuzzing: two top-level names that both exist must not be
/// given the same suffixed name (here the 16-byte limit cuts both to
/// "invoice.pdf (2)").
#[test]
fn existing_names_never_share_a_suffix() -> TestResult {
    let profile = FsProfile {
        rules: crate::NameRules {
            max_component_bytes: 16,
            neutralize_shell_files: true,
        },
        ..FsProfile::host()
    };
    let plan = plan_with(
        &[dir("invoice.pdf.exm", 0), dir("invoice.pdf", 0)],
        &profile,
        10,
        &["invoice.pdf.exm", "invoice.pdf"],
    )?;
    assert_eq!(locals(&plan), ["invoice.pdf (2)", "invoice.pdf (3)"]);
    Ok(())
}

#[test]
fn a_destination_with_every_candidate_taken_rejects_the_entry() -> TestResult {
    let manifest = manifest(ID, &[file("x", 0), file("y", 0)])?;
    let plan = DestinationPlan::new(&manifest, &FsProfile::host(), 1, &mut |name| {
        name.starts_with('x')
    });
    assert_eq!(
        plan.entry(1).and_then(crate::PlannedEntry::rejection),
        Some(Rejection::NoFreeName)
    );
    assert!(!plan.accepts(&[1]));
    assert!(plan.accepts(&[2]));
    assert!(plan.any_file_storable());
    Ok(())
}

#[test]
fn paths_beyond_the_limit_are_rejected_with_their_children() -> TestResult {
    let profile = FsProfile {
        path: PathLimit::LINUX,
        ..FsProfile::host()
    };
    let long = "d".repeat(200);
    let specs = [
        dir(&long, 0),
        file("short.txt", 0),
        file(&"f".repeat(100), 1),
        dir("sub", 1),
        file("leaf", 4),
    ];
    // 3900 + 1 + 200 > 4095: the directory itself does not fit.
    let plan = plan_with(&specs, &profile, 3900, &[])?;
    let rejections: Vec<Option<Rejection>> = plan
        .entries()
        .iter()
        .map(crate::PlannedEntry::rejection)
        .collect();
    assert_eq!(
        rejections,
        [
            Some(Rejection::PathTooLong),
            None,
            Some(Rejection::ParentRejected),
            Some(Rejection::ParentRejected),
            Some(Rejection::ParentRejected),
        ]
    );
    assert!(plan.accepts(&[2]));
    assert!(!plan.accepts(&[2, 3]));
    assert!(!plan.accepts(&[1]), "a directory is not selectable");
    // Exactly at the limit is fine: 3894 + 1 + 200 = 4095.
    let plan = plan_with(&specs[..2], &profile, 3894, &[])?;
    assert!(
        plan.entries()
            .iter()
            .all(|entry| entry.rejection().is_none())
    );
    // Nothing fits: the offer is unsupported.
    let plan = plan_with(&specs, &profile, 4090, &[])?;
    assert!(!plan.any_file_storable());
    Ok(())
}

#[test]
fn windows_paths_are_measured_in_utf16_and_warn_above_max_path() -> TestResult {
    let profile = FsProfile {
        path: PathLimit::WINDOWS,
        ..FsProfile::host()
    };
    // 120 emoji: 480 UTF-8 bytes, 240 UTF-16 units.
    let name = "\u{1F600}".repeat(60);
    let plan = plan_with(&[file(&name, 0)], &profile, 10, &[])?;
    assert!(plan.entry(1).is_some_and(|e| e.warnings().is_empty()));
    let plan = plan_with(&[file(&name, 0)], &profile, 200, &[])?;
    assert!(
        plan.entry(1)
            .is_some_and(|e| e.warnings() == [Warning::LongPath])
    );
    Ok(())
}

#[test]
fn warnings_point_out_risky_entries() -> TestResult {
    let mut jpeg_exe = file("holiday.exe", 0);
    jpeg_exe.mime = "image/jpeg";
    let mut pdf_png = file("scan.pdf", 0);
    pdf_png.mime = "image/png";
    let plan = plan(&[
        jpeg_exe,
        pdf_png,
        dir("Tool.app", 0),
        file(".env", 0),
        file("notes.txt", 0),
        file("run.sh", 0),
        dir("plain", 0),
    ])?;
    let warnings: Vec<&[Warning]> = plan
        .entries()
        .iter()
        .map(crate::PlannedEntry::warnings)
        .collect();
    assert_eq!(
        warnings[0],
        [
            Warning::Risky(crate::ExtensionRisk {
                kind: RiskKind::Executable,
                platforms: Platforms::WINDOWS
            }),
            Warning::MimeMismatch
        ]
    );
    assert_eq!(warnings[1], [Warning::MimeMismatch]);
    assert_eq!(warnings[2].first(), Some(&Warning::Bundle));
    assert_eq!(warnings[3], [Warning::Hidden]);
    assert_eq!(warnings[4], []);
    assert!(matches!(
        warnings[5],
        [Warning::Risky(crate::ExtensionRisk {
            kind: RiskKind::Script,
            ..
        })]
    ));
    assert_eq!(warnings[6], []);
    Ok(())
}

#[test]
fn debug_output_contains_no_names() -> TestResult {
    let secret = "very-private-name-0123456789.txt";
    let plan = plan(&[file(secret, 0), dir("private-directory-abcdef", 0)])?;
    let rendered = format!("{plan:?}");
    assert!(!rendered.contains(secret));
    assert!(!rendered.contains("private-directory-abcdef"));
    Ok(())
}

/// Builds random trees whose names come from a collision-heavy alphabet.
fn tree() -> impl Strategy<Value = Vec<(String, bool, usize)>> {
    let name = prop_oneof![
        "[aAbB\u{DF}\u{131}iI. ]{1,4}(\\.(txt|TXT|exe|lnk))?",
        Just("CON .txt".to_owned()),
        Just("x\u{202E}y".to_owned()),
        Just("x\u{202D}y".to_owned()),
        Just("a (2)".to_owned()),
        Just("ss".to_owned()),
        Just("\u{3C3}".to_owned()),
        Just("\u{3C2}".to_owned()),
        Just("PROGRA~1".to_owned()),
    ];
    proptest::collection::vec((name, any::<bool>(), any::<usize>()), 1..40)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(512))]

    /// Every local name is one safe component, siblings never share a
    /// collision key, every local path is unique, and no top-level name
    /// lands on an existing entry.
    #[test]
    fn plans_stay_inside_the_root_and_never_collide(entries in tree(), taken in proptest::collection::vec("[aAbB\u{DF}i. ]{1,3}", 0..6)) {
        let mut specs: Vec<Spec> = Vec::new();
        let mut directories = vec![0_u32];
        for (index, (name, is_dir, parent)) in entries.iter().enumerate() {
            let parent = directories[parent % directories.len()];
            let name = name.trim_end_matches(['.', ' ']).to_owned();
            if todoke_proto::transfer::manifest::validate_name(name.as_bytes()).is_err()
                || specs.iter().any(|spec| spec.parent == parent && spec.name == name)
            {
                continue;
            }
            let id = u32::try_from(specs.len() + 1).unwrap_or(u32::MAX);
            let _ = index;
            if *is_dir {
                directories.push(id);
                specs.push(dir(&name, parent));
            } else {
                specs.push(file(&name, parent));
            }
        }
        prop_assume!(!specs.is_empty());
        let existing: Vec<&str> = taken.iter().map(String::as_str).collect();
        let plan = plan_with(&specs, &FsProfile::host(), 5, &existing).map_err(|e| TestCaseError::fail(e.to_string()))?;
        let existing_keys: BTreeSet<String> = existing.iter().map(|name| collision_key(name)).collect();
        let mut paths = BTreeSet::new();
        let mut siblings = BTreeSet::new();
        for entry in plan.entries() {
            let local = entry.local().as_str();
            prop_assert!(acceptable(local), "{:?}", local);
            prop_assert!(siblings.insert((entry.parent(), collision_key(local))));
            if entry.parent() == 0 {
                prop_assert!(!existing_keys.contains(&collision_key(local)));
            }
            let path: Vec<String> = plan
                .local_path(entry.id())
                .unwrap_or_default()
                .iter()
                .map(|name| collision_key(name.as_str()))
                .collect();
            prop_assert!(paths.insert(path.join("/")));
            prop_assert_eq!(entry.kind() == Kind::Directory, specs[(entry.id() - 1) as usize].content.is_none());
        }
    }
}
