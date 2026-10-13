//! Entry points for the cargo-fuzz harnesses in `fuzz/` (built with
//! `--cfg fuzzing` only). Each runs the same code production uses and
//! asserts its invariants; a failed assertion is a finding. Nothing here
//! touches the filesystem or bypasses a gate.

use std::collections::BTreeSet;

use todoke_proto::time::UnixTime;
use todoke_proto::transfer::manifest::{
    Manifest, ManifestEntry, ManifestHeader, ManifestLimits, validate_name,
};

use crate::name::fold::collision_key;
use crate::name::{Kind, NameRules, acceptable, sanitize_component};
use crate::plan::{DestinationPlan, FsProfile, PathLimit};

/// The sanitizer on arbitrary names, then the destination mapping of a
/// tree built from those that pass the manifest's name check.
///
/// Input: a flags byte (entry kind, component limit, path limit), then
/// names separated by `0xff`; each name's first byte also picks its
/// parent and whether the destination already holds it.
pub fn name_mapping(data: &[u8]) {
    let Some((&flags, rest)) = data.split_first() else {
        return;
    };
    let kind = if flags & 1 == 0 {
        Kind::File
    } else {
        Kind::Directory
    };
    let rules = NameRules {
        max_component_bytes: 16 + usize::from(flags >> 1) * 2,
        neutralize_shell_files: flags & 0x80 == 0,
    };
    let names: Vec<&[u8]> = rest.split(|&byte| byte == 0xff).take(64).collect();
    for raw in &names {
        let name = String::from_utf8_lossy(raw);
        let (local, _) = sanitize_component(&name, kind, &rules);
        assert!(acceptable(&local));
        assert!(local.len() <= rules.max_component_bytes.clamp(16, 255));
        assert_eq!(sanitize_component(&local, kind, &rules).0, local);
    }
    plan_tree(flags, &names, rules);
}

fn plan_tree(flags: u8, names: &[&[u8]], rules: NameRules) {
    let mut entries = Vec::new();
    let mut directories = vec![0_u32];
    let mut siblings = BTreeSet::new();
    let mut existing = BTreeSet::new();
    for raw in names {
        let Ok(name) = validate_name(raw) else {
            continue;
        };
        let selector = raw.first().copied().unwrap_or(0);
        let parent = directories[usize::from(selector) % directories.len()];
        if !siblings.insert((parent, name.to_owned())) {
            continue;
        }
        if selector & 0x40 != 0 {
            existing.insert(collision_key(name));
        }
        let Ok(id) = u32::try_from(entries.len() + 1) else {
            return;
        };
        if selector & 1 == 0 {
            entries.push(ManifestEntry::file(
                id,
                parent,
                name.to_owned(),
                "application/octet-stream".to_owned(),
                0,
                *blake3::hash(b"").as_bytes(),
                2,
            ));
        } else {
            directories.push(id);
            entries.push(ManifestEntry::directory(id, parent, name.to_owned()));
        }
    }
    let (Some(created), Some(expires)) = (UnixTime::new(1_000), UnixTime::new(2_000)) else {
        return;
    };
    let header = ManifestHeader {
        transfer_id: [1; 16],
        sender_public: [2; 32],
        recipient_public: [3; 32],
        created_at: created,
        expires_at: expires,
    };
    let Ok(manifest) = Manifest::new(header, entries, &ManifestLimits::SPEC) else {
        return;
    };
    let profile = FsProfile {
        rules,
        path: if flags & 0x40 == 0 {
            PathLimit::LINUX
        } else {
            PathLimit::WINDOWS
        },
    };
    let plan = DestinationPlan::new(&manifest, &profile, 64, &mut |name| {
        existing.contains(&collision_key(name))
    });
    let mut keys = BTreeSet::new();
    let mut paths = BTreeSet::new();
    for entry in plan.entries() {
        let local = entry.local().as_str();
        assert!(acceptable(local));
        assert!(keys.insert((entry.parent(), collision_key(local))));
        if entry.parent() == 0 && entry.rejection().is_none() {
            assert!(!existing.contains(&collision_key(local)));
        }
        let path: Vec<String> = plan
            .local_path(entry.id())
            .unwrap_or_default()
            .iter()
            .map(|name| collision_key(name.as_str()))
            .collect();
        assert!(!path.is_empty());
        assert!(paths.insert(path.join("/")));
    }
}

/// Content type detection and assessment on arbitrary content, with a
/// name and MIME label taken from the input.
pub fn content_type(data: &[u8]) {
    let Some((&split, rest)) = data.split_first() else {
        return;
    };
    let cut = usize::from(split).min(rest.len());
    let (label, content) = rest.split_at(cut);
    let label = String::from_utf8_lossy(label);
    let (name, mime) = label.split_once('\n').unwrap_or((&label, ""));
    let detected = crate::detect::detect(content);
    let report = crate::detect::assess(content, name, mime);
    assert_eq!(report.detected(), detected);
    if detected.is_none() {
        assert!(report.warnings().is_empty());
    }
    assert!(report.warnings().len() <= 2);
}
