use super::*;
use crate::profile::tests::Scratch;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn names(walked: &Walked) -> Vec<(Option<usize>, String, bool)> {
    walked
        .entries
        .iter()
        .map(|entry| match entry {
            Walk::Directory { parent, name, .. } => (*parent, name.clone(), true),
            Walk::File { parent, name, .. } => (*parent, name.clone(), false),
        })
        .collect()
}

#[test]
fn folders_are_walked_in_order_and_links_are_not_followed() -> TestResult {
    let scratch = Scratch::new("walk")?;
    let root = scratch.0.join("album");
    std::fs::create_dir_all(root.join("b-sub"))?;
    std::fs::write(root.join("a.txt"), b"a")?;
    std::fs::write(root.join("b-sub").join("c.bin"), b"c")?;
    let outside = scratch.0.join("secret.txt");
    std::fs::write(&outside, b"not chosen")?;
    #[cfg(unix)]
    std::os::unix::fs::symlink(&outside, root.join("link.txt"))?;
    let walked = walk(&[root])?;
    assert_eq!(
        names(&walked),
        vec![
            (None, "album".to_owned(), true),
            (Some(0), "a.txt".to_owned(), false),
            (Some(0), "b-sub".to_owned(), true),
            (Some(2), "c.bin".to_owned(), false),
        ]
    );
    #[cfg(unix)]
    assert_eq!(walked.skipped, 1);
    Ok(())
}

/// macOS stores names decomposed (NFD); the manifest requires NFC.
#[test]
fn names_are_sent_in_nfc() -> TestResult {
    let scratch = Scratch::new("nfc")?;
    std::fs::create_dir_all(&scratch.0)?;
    let decomposed = "cafe\u{301}.txt";
    std::fs::write(scratch.0.join(decomposed), b"x")?;
    let walked = walk(&[scratch.0.join(decomposed)])?;
    assert_eq!(
        names(&walked),
        vec![(None, "caf\u{e9}.txt".to_owned(), false)]
    );
    Ok(())
}

#[test]
fn empty_or_missing_choices_are_refused() -> TestResult {
    let scratch = Scratch::new("empty")?;
    std::fs::create_dir_all(scratch.0.join("nothing"))?;
    assert_eq!(walk(&[]).err(), Some(SendError::Empty));
    assert_eq!(
        walk(&[scratch.0.join("nothing")]).err(),
        Some(SendError::Empty)
    );
    assert_eq!(
        walk(&[scratch.0.join("missing")]).err(),
        Some(SendError::Unreadable(std::io::ErrorKind::NotFound))
    );
    Ok(())
}

#[test]
fn too_deep_folders_are_refused() -> TestResult {
    let scratch = Scratch::new("deep")?;
    let mut path = scratch.0.clone();
    for _ in 0..=MAX_DEPTH {
        path = path.join("d");
    }
    std::fs::create_dir_all(&path)?;
    std::fs::write(path.join("f"), b"x")?;
    assert_eq!(
        walk(&[scratch.0.join("d")]).err(),
        Some(SendError::TooLarge)
    );
    Ok(())
}

/// Names another system cannot use, and a second sibling with the same
/// NFC name, are skipped and counted, so the offer cannot fail on them
/// later; two chosen paths with the same name are refused.
#[test]
fn unusable_and_duplicate_names_never_reach_the_offer() -> TestResult {
    let scratch = Scratch::new("names")?;
    let root = scratch.0.join("box");
    std::fs::create_dir_all(&root)?;
    std::fs::write(root.join("ok.txt"), b"x")?;
    let mut odd = 0;
    if cfg!(unix) {
        for name in ["a:b.txt", "what?.txt", "trailing.", "CON.txt"] {
            std::fs::write(root.join(name), b"x")?;
            odd += 1;
        }
    }
    let walked = walk(&[root])?;
    assert_eq!(
        names(&walked),
        vec![
            (None, "box".to_owned(), true),
            (Some(0), "ok.txt".to_owned(), false)
        ]
    );
    assert_eq!(walked.skipped, odd);
    // NFC and NFD spellings of one name in one folder (distinct on Linux).
    let mixed = scratch.0.join("mixed");
    std::fs::create_dir_all(&mixed)?;
    std::fs::write(mixed.join("caf\u{e9}"), b"1")?;
    std::fs::write(mixed.join("cafe\u{301}"), b"2")?;
    let walked = walk(&[mixed])?;
    assert_eq!(walked.files(), 1);
    // The same name chosen twice from two folders.
    for dir in ["x", "y"] {
        std::fs::create_dir_all(scratch.0.join(dir))?;
        std::fs::write(scratch.0.join(dir).join("same.txt"), dir)?;
    }
    assert_eq!(
        walk(&[
            scratch.0.join("x").join("same.txt"),
            scratch.0.join("y").join("same.txt")
        ])
        .err(),
        Some(SendError::Duplicate)
    );
    Ok(())
}

/// Files are hashed by a preparer, installed in a source, and built into
/// a manifest whose IDs match the source's.
#[test]
fn prepared_files_install_and_build() -> TestResult {
    let scratch = Scratch::new("prepare")?;
    let root = scratch.0.join("album");
    std::fs::create_dir_all(root.join("sub"))?;
    std::fs::write(root.join("a.txt"), b"alpha")?;
    std::fs::write(root.join("sub").join("b.txt"), b"beta")?;
    let walked = walk(&[root])?;
    let hasher = Preparer::new(&scratch.0.join("prepared"))?;
    let now = UnixTime::new(1_800_000_000).ok_or("time")?;
    let mut prepared = prepare(&walked, now, &hasher)?;
    assert_eq!(prepared.total_bytes(), 9);
    let mut source = FsSource::new(&scratch.0.join("source"))?;
    prepared.install(&mut source);
    let id = *prepared.transfer_id();
    // Entries: album (1), a.txt (2), sub (3), b.txt (4).
    for file in [2, 4] {
        assert!(todoke_transfer::SendSource::open(&mut source, &id, file).is_ok());
    }
    Ok(())
}

#[test]
fn more_files_than_the_open_file_limit_allows_are_refused() {
    assert!(check_open_files(1).is_ok());
    #[cfg(unix)]
    assert!(matches!(
        check_open_files(usize::MAX / 4),
        Err(SendError::TooManyOpen { .. })
    ));
}
