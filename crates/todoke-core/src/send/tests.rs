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
            Walk::Opened { name, .. } => (None, name.clone(), false),
        })
        .collect()
}

/// A directory handle, as an app could hand one over (Windows opens
/// directories only with `FILE_FLAG_BACKUP_SEMANTICS`).
fn open_dir(path: &std::path::Path) -> std::io::Result<std::fs::File> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_BACKUP_SEMANTICS: u32 = 0x0200_0000;
        options.custom_flags(FILE_FLAG_BACKUP_SEMANTICS);
    }
    options.open(path)
}

/// Files handed over open: each under its own name (NFC), regular files
/// only, names other systems cannot use skipped and counted, two with one
/// name refused, and nothing left is `Empty`. Hashing starts from the
/// start of each file, and the offer has the given names.
#[test]
fn open_files_are_offered_under_their_names() -> TestResult {
    let scratch = Scratch::new("open")?;
    std::fs::create_dir_all(&scratch.0)?;
    let (a, b) = (scratch.0.join("1"), scratch.0.join("2"));
    std::fs::write(&a, b"first")?;
    std::fs::write(&b, b"second")?;
    let open = |path: &std::path::Path, name: &str| -> std::io::Result<OpenFile> {
        Ok(OpenFile {
            name: name.to_owned(),
            file: std::fs::File::open(path)?,
        })
    };
    let walked = walk_open(vec![
        open(&a, "Photo.jpg")?,
        open(&b, "Cafe\u{301}.txt")?,
        open(&a, "bad/name")?,
        open(&a, "CON")?,
        OpenFile {
            name: "folder".into(),
            file: open_dir(&scratch.0)?,
        },
    ])?;
    assert_eq!(walked.skipped, 3);
    assert_eq!(walked.files(), 2);
    assert_eq!(names(&walked)[0], (None, "Photo.jpg".to_owned(), false));
    let hasher = todoke_fs::Preparer::new(&scratch.0.join("outboards"))?;
    let offer = prepare(
        &walked,
        UnixTime::new(1_800_000_000).ok_or("time")?,
        &hasher,
    )?;
    assert_eq!(offer.files(), 2);
    assert_eq!(offer.total_bytes(), 11);
    assert_eq!(offer.top_names(8), ["Photo.jpg", "Caf\u{e9}.txt"]);
    assert_eq!(
        walk_open(vec![open(&a, "same")?, open(&b, "same")?]).map(|_| ()),
        Err(SendError::Duplicate)
    );
    assert_eq!(
        walk_open(vec![open(&a, "")?]).map(|_| ()),
        Err(SendError::Empty)
    );
    assert_eq!(walk_open(Vec::new()).map(|_| ()), Err(SendError::Empty));
    Ok(())
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
    // Two handles a file, what is open, and the spare: exactly the limit
    // fits, one more does not.
    #[cfg(unix)]
    {
        assert!(!over_limit(100, 72, 2 * 100 + 72 + SPARE_FILES));
        assert!(over_limit(100, 73, 2 * 100 + 72 + SPARE_FILES));
        assert!(over_limit(usize::MAX, 0, u64::MAX - 1));
    }
    assert!(check_open_files(1).is_ok());
    #[cfg(unix)]
    assert!(matches!(
        check_open_files(usize::MAX / 4),
        Err(SendError::TooManyOpen { .. })
    ));
}

/// The Ed25519 base point: a valid public key.
fn basepoint() -> Result<Ed25519PublicKey, Box<dyn std::error::Error>> {
    let mut bytes = [0x66; 32];
    bytes[0] = 0x58;
    Ok(Ed25519PublicKey::from_bytes(&bytes)?)
}

/// The walk's bounds are the manifest's (§13): what the walk accepts,
/// `build` accepts too, and one more entry or level is refused at once.
#[test]
fn walk_bounds_match_the_manifest() -> TestResult {
    let scratch = Scratch::new("bounds")?;
    let hasher = Preparer::new(&scratch.0.join("prepared"))?;
    let now = UnixTime::new(1_800_000_000).ok_or("time")?;
    let key = basepoint()?;
    let suite = todoke_crypto::content::ContentSuite::Aes256GcmStream;
    // Exactly the deepest allowed: 63 directories and a file (depth 64).
    let mut deep = scratch.0.join("deep");
    for _ in 0..MAX_DEPTH - 2 {
        deep = deep.join("d");
    }
    std::fs::create_dir_all(&deep)?;
    std::fs::write(deep.join("f"), b"x")?;
    let walked = walk(&[scratch.0.join("deep")])?;
    let prepared = prepare(&walked, now, &hasher)?;
    build(&prepared, &key, &key, suite, &ManifestLimits::SPEC)?;
    std::fs::create_dir(deep.join("e"))?;
    std::fs::write(deep.join("e").join("f"), b"x")?;
    assert_eq!(
        walk(&[scratch.0.join("deep")]).err(),
        Some(SendError::TooLarge)
    );
    // Exactly 10000 entries: a folder, 9998 folders, and a file (folders
    // hold no descriptors, so the runner's open-file limit does not bind).
    let wide = scratch.0.join("wide");
    std::fs::create_dir(&wide)?;
    for n in 0..MAX_ENTRIES - 2 {
        std::fs::create_dir(wide.join(format!("{n}")))?;
    }
    std::fs::write(wide.join("file"), b"x")?;
    // A link costs nothing: it is skipped.
    #[cfg(unix)]
    std::os::unix::fs::symlink("/", wide.join("link"))?;
    let walked = walk(core::slice::from_ref(&wide))?;
    let prepared = prepare(&walked, now, &hasher)?;
    build(&prepared, &key, &key, suite, &ManifestLimits::SPEC)?;
    // A receiver with smaller limits cannot take it.
    assert_eq!(
        build(
            &prepared,
            &key,
            &key,
            suite,
            &ManifestLimits::new(2, u64::MAX, u64::MAX)
        )
        .err(),
        Some(SendError::Manifest)
    );
    drop(prepared);
    std::fs::create_dir(wide.join("one-more"))?;
    assert_eq!(walk(&[wide]).err(), Some(SendError::TooLarge));
    Ok(())
}

/// Between walk and hashing, a directory on the way to a file swapped for
/// a link to another tree with the same names, or the file replaced, is
/// refused: the walk's identity of each file is checked.
#[cfg(unix)]
#[test]
fn paths_swapped_after_the_walk_are_refused() -> TestResult {
    let scratch = Scratch::new("swap")?;
    let hasher = Preparer::new(&scratch.0.join("prepared"))?;
    let now = UnixTime::new(1_800_000_000).ok_or("time")?;
    let root = scratch.0.join("root");
    std::fs::create_dir_all(root.join("sub"))?;
    std::fs::write(root.join("sub").join("f"), b"chosen")?;
    let elsewhere = scratch.0.join("elsewhere");
    std::fs::create_dir_all(&elsewhere)?;
    std::fs::write(elsewhere.join("f"), b"secret")?;
    let walked = walk(core::slice::from_ref(&root))?;
    std::fs::rename(root.join("sub"), scratch.0.join("moved"))?;
    std::os::unix::fs::symlink(&elsewhere, root.join("sub"))?;
    let refused = prepare(&walked, now, &hasher).err();
    assert_eq!(
        refused,
        Some(SendError::Unreadable(std::io::ErrorKind::Other))
    );
    assert!(
        refused
            .map(|error| error.to_string())
            .is_some_and(|text| text.contains("changed or was replaced"))
    );
    // The file itself replaced by another.
    std::fs::remove_file(root.join("sub"))?;
    std::fs::rename(scratch.0.join("moved"), root.join("sub"))?;
    let walked = walk(core::slice::from_ref(&root))?;
    std::fs::write(scratch.0.join("other"), b"other")?;
    std::fs::rename(scratch.0.join("other"), root.join("sub").join("f"))?;
    assert_eq!(
        prepare(&walked, now, &hasher).err(),
        Some(SendError::Unreadable(std::io::ErrorKind::Other))
    );
    Ok(())
}

/// Every offer gets a fresh random transfer ID.
#[test]
fn transfer_ids_are_fresh() -> TestResult {
    let scratch = Scratch::new("ids")?;
    std::fs::create_dir_all(&scratch.0)?;
    std::fs::write(scratch.0.join("f"), b"x")?;
    let hasher = Preparer::new(&scratch.0.join("prepared"))?;
    let now = UnixTime::new(1_800_000_000).ok_or("time")?;
    let walked = walk(&[scratch.0.join("f")])?;
    let one = prepare(&walked, now, &hasher)?;
    let two = prepare(&walked, now, &hasher)?;
    assert_ne!(one.transfer_id(), two.transfer_id());
    assert_ne!(*one.transfer_id(), [0; 16]);
    let key = basepoint()?;
    let offer = build(
        &one,
        &key,
        &key,
        todoke_crypto::content::ContentSuite::Aes256GcmStream,
        &ManifestLimits::SPEC,
    )?;
    assert_eq!(offer.transfer_id(), one.transfer_id());
    Ok(())
}

/// A FIFO inside a chosen folder is skipped and counted without being
/// opened; a chosen link is never followed.
#[cfg(unix)]
#[test]
fn special_files_and_chosen_links_are_not_sent() -> TestResult {
    let scratch = Scratch::new("special")?;
    let root = scratch.0.join("box");
    std::fs::create_dir_all(&root)?;
    std::fs::write(root.join("ok.txt"), b"x")?;
    let made = std::process::Command::new("mkfifo")
        .arg(root.join("pipe"))
        .status()?;
    assert!(made.success());
    let walked = walk(core::slice::from_ref(&root))?;
    assert_eq!((walked.files(), walked.skipped), (1, 1));
    std::os::unix::fs::symlink(root.join("ok.txt"), scratch.0.join("link"))?;
    assert_eq!(
        walk(&[scratch.0.join("link")]).err(),
        Some(SendError::Empty)
    );
    Ok(())
}

/// A junction inside a chosen folder is skipped, and the preparer refuses
/// to open one (Windows; `mklink /J` needs no administrator).
#[cfg(windows)]
#[test]
fn junctions_are_not_followed() -> TestResult {
    let scratch = Scratch::new("junction")?;
    let root = scratch.0.join("box");
    let target = scratch.0.join("elsewhere");
    std::fs::create_dir_all(&root)?;
    std::fs::create_dir_all(&target)?;
    std::fs::write(root.join("ok.txt"), b"x")?;
    std::fs::write(target.join("secret.txt"), b"x")?;
    let made = std::process::Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(root.join("jump"))
        .arg(&target)
        .status()?;
    assert!(made.success());
    let walked = walk(core::slice::from_ref(&root))?;
    assert_eq!((walked.files(), walked.skipped), (1, 1));
    let hasher = Preparer::new(&scratch.0.join("prepared"))?;
    assert_eq!(
        hasher.prepare(&root.join("jump"), None).map(|_| ()),
        Err(todoke_transfer::SourceError::Io(
            std::io::ErrorKind::InvalidInput
        ))
    );
    Ok(())
}
