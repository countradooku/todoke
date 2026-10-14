use super::*;
use crate::profile::tests::Scratch;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn names(walked: &Walked) -> Vec<(Option<usize>, String, bool)> {
    walked
        .entries
        .iter()
        .map(|entry| match entry {
            Walk::Directory { parent, name } => (*parent, name.clone(), true),
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
