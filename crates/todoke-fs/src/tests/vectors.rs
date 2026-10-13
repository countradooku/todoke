//! The committed `manifest-hash.json` fixture (PROTOCOL §7.1) through this
//! crate: its one name maps to itself with no warning, its MIME label fits
//! its extension, and the sender's source preparation derives the
//! fixture's size and BLAKE3 root from its content.

use todoke_crypto::consent::CanonicalManifest;
use todoke_proto::transfer::ManifestLimits;

use super::*;
use crate::{DestinationPlan, FsProfile, FsSource};

fn fixture_text() -> AnyResult<String> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/test-vectors/manifest-hash.json");
    Ok(std::fs::read_to_string(path)?)
}

/// The string value of `key`, which must occur exactly once.
fn field<'a>(json: &'a str, key: &str) -> AnyResult<&'a str> {
    let marker = format!("\"{key}\": \"");
    let start = json.find(&marker).ok_or("missing field")? + marker.len();
    let end = json[start..].find('"').ok_or("unterminated field")?;
    if json[start + end..].contains(&marker) {
        return Err("field occurs twice".into());
    }
    Ok(&json[start..start + end])
}

fn unhex(text: &str) -> AnyResult<Vec<u8>> {
    if !text.len().is_multiple_of(2) {
        return Err("odd hex".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|at| Ok(u8::from_str_radix(&text[at..at + 2], 16)?))
        .collect()
}

#[test]
fn the_manifest_fixture_maps_and_prepares_as_specified() -> TestResult {
    let json = fixture_text()?;
    let field = |key: &str| field(&json, key);
    let canonical = unhex(field("canonical_hex")?)?;
    let manifest = CanonicalManifest::parse(canonical, &ManifestLimits::SPEC)?;
    assert_eq!(
        manifest.hash().as_slice(),
        unhex(field("manifest_hash_hex")?)?
    );
    assert_eq!(field("name")?, "hello.txt");
    assert_eq!(field("mime")?, "text/plain");
    let plan = DestinationPlan::new(manifest.manifest(), &FsProfile::host(), 10, &mut |_| false);
    let entry = plan.entry(1).ok_or("entry")?;
    assert_eq!(entry.local().as_str(), "hello.txt");
    assert_eq!(entry.changes(), []);
    assert_eq!(entry.warnings(), []);
    assert_eq!(entry.rejection(), None);
    assert!(plan.accepts(&[1]));
    // The sender derives the manifest's size and root from the content.
    let content = unhex(field("content_hex")?)?;
    let root = unhex(field("plaintext_blake3_root_hex")?)?;
    let temp = TempDir::new()?;
    std::fs::write(temp.path().join("hello.txt"), &content)?;
    let mut source = FsSource::new(&temp.path().join("state"))?;
    let prepared = source
        .prepare(&temp.path().join("hello.txt"))
        .map_err(|error| format!("{error:?}"))?;
    assert_eq!(prepared.root().as_slice(), root);
    let binding = manifest.file(1).ok_or("file")?;
    assert_eq!(prepared.size(), binding.layout().size());
    assert_eq!(prepared.root(), binding.root());
    // Plain text: nothing to say about its content.
    assert_eq!(
        crate::detect::assess(&content, "hello.txt", "text/plain"),
        crate::detect::ContentReport::default()
    );
    Ok(())
}
