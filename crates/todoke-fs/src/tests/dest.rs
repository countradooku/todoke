//! Destination directory operations: exclusivity, links refused, no
//! replacement, and directories swapped while held.

use std::io::{Read as _, Write as _};

use super::*;
use crate::dest::{Atomicity, DestError, Destination, DirDestination};

fn names(path: &std::path::Path) -> AnyResult<Vec<String>> {
    let mut names: Vec<String> = std::fs::read_dir(path)?
        .map(|entry| entry.map(|entry| entry.file_name().to_string_lossy().into_owned()))
        .collect::<Result<_, _>>()?;
    names.sort();
    Ok(names)
}

fn stage_and_publish(
    destination: &DirDestination,
    dir: &crate::dest::DirHandle,
    temp: &str,
    name: &str,
    content: &[u8],
) -> Result<Atomicity, DestError> {
    let mut staged = destination.stage(dir, temp)?;
    staged.write_all(content).map_err(DestError::from)?;
    destination.finish_staged(&staged)?;
    let published = destination.publish(dir, &staged, temp, name);
    if published.is_ok() {
        destination.release(dir, staged, temp)?;
    }
    published
}

#[test]
fn files_are_created_exclusively_and_never_replaced() -> TestResult {
    let temp = TempDir::new()?;
    let destination = DirDestination::open(temp.path())?;
    let root = destination.root()?;
    assert_eq!(
        stage_and_publish(&destination, &root, ".t1", "a.txt", b"first")?,
        Atomicity::Atomic
    );
    // A second file under the same name is refused; its temporary stays.
    let mut second = destination.stage(&root, ".t2")?;
    second.write_all(b"second")?;
    destination.finish_staged(&second)?;
    assert_eq!(
        destination.publish(&root, &second, ".t2", "a.txt"),
        Err(DestError::Exists)
    );
    assert_eq!(std::fs::read(temp.path().join("a.txt"))?, b"first");
    assert_eq!(names(temp.path())?, [".t2", "a.txt"]);
    assert_eq!(
        destination.publish(&root, &second, ".t2", "b.txt")?,
        Atomicity::Atomic
    );
    destination.release(&root, second, ".t2")?;
    assert_eq!(names(temp.path())?, ["a.txt", "b.txt"]);
    // Staging never opens an existing entry.
    assert!(matches!(
        destination.stage(&root, "a.txt"),
        Err(DestError::Exists)
    ));
    // Reading back.
    let mut content = Vec::new();
    destination
        .open_file(&root, "b.txt")?
        .read_to_end(&mut content)?;
    assert_eq!(content, b"second");
    assert_eq!(destination.exists(&root, "a.txt"), Ok(true));
    assert_eq!(destination.exists(&root, "zzz"), Ok(false));
    destination.discard(&root, "a.txt")?;
    destination.discard(&root, "never-there")?;
    assert_eq!(names(temp.path())?, ["b.txt"]);
    destination.sync_dir(&root)?;
    Ok(())
}

#[cfg(unix)]
#[test]
fn published_files_are_not_executable() -> TestResult {
    use std::os::unix::fs::PermissionsExt as _;
    let temp = TempDir::new()?;
    let destination = DirDestination::open(temp.path())?;
    let root = destination.root()?;
    stage_and_publish(&destination, &root, ".t", "run.sh", b"#!/bin/sh\n")?;
    let mode = std::fs::metadata(temp.path().join("run.sh"))?
        .permissions()
        .mode();
    assert_eq!(mode & 0o111, 0, "{mode:o}");
    Ok(())
}

#[test]
fn directories_are_created_exclusively_and_opened_without_links() -> TestResult {
    let temp = TempDir::new()?;
    let destination = DirDestination::open(temp.path())?;
    let root = destination.root()?;
    let sub = destination.create_dir(&root, "sub")?;
    assert!(matches!(
        destination.create_dir(&root, "sub"),
        Err(DestError::Exists)
    ));
    stage_and_publish(&destination, &sub, ".t", "inner.txt", b"x")?;
    let again = destination.open_dir(&root, "sub")?;
    assert_eq!(destination.exists(&again, "inner.txt"), Ok(true));
    assert!(matches!(
        destination.open_dir(&root, "missing"),
        Err(DestError::NotFound)
    ));
    // A file is not a directory.
    assert!(destination.open_dir(&sub, "inner.txt").is_err());
    // A directory is not a file.
    assert!(destination.open_file(&root, "sub").is_err());
    Ok(())
}

#[test]
fn links_are_refused_never_followed() -> TestResult {
    let temp = TempDir::new()?;
    let outside = TempDir::new()?;
    std::fs::write(outside.path().join("secret.txt"), b"outside")?;
    let root_path = temp.path().join("root");
    std::fs::create_dir(&root_path)?;
    if symlink_dir(outside.path(), &root_path.join("linked-dir"))?.is_none() {
        return Ok(());
    }
    if symlink_file(
        &outside.path().join("secret.txt"),
        &root_path.join("linked-file"),
    )?
    .is_none()
    {
        return Ok(());
    }
    if symlink_file(&outside.path().join("new.txt"), &root_path.join("dangling"))?.is_none() {
        return Ok(());
    }
    let destination = DirDestination::open(&root_path)?;
    let root = destination.root()?;
    assert_eq!(
        destination.open_dir(&root, "linked-dir").map(|_| ()),
        Err(DestError::WrongKind)
    );
    assert!(destination.open_file(&root, "linked-file").is_err());
    // Staging or publishing onto a link, even a dangling one, fails
    // without touching its target.
    assert!(matches!(
        destination.stage(&root, "dangling"),
        Err(DestError::Exists)
    ));
    assert!(matches!(
        destination.create_dir(&root, "dangling"),
        Err(DestError::Exists)
    ));
    assert_eq!(
        stage_and_publish(&destination, &root, ".t", "dangling", b"payload"),
        Err(DestError::Exists)
    );
    assert_eq!(
        stage_and_publish(&destination, &root, ".u", "linked-file", b"payload"),
        Err(DestError::Exists)
    );
    assert_eq!(names(outside.path())?, ["secret.txt"]);
    assert_eq!(
        std::fs::read(outside.path().join("secret.txt"))?,
        b"outside"
    );
    // Discarding a link removes the link only.
    destination.discard(&root, "linked-file")?;
    assert_eq!(
        std::fs::read(outside.path().join("secret.txt"))?,
        b"outside"
    );
    Ok(())
}

/// A directory replaced by a link to somewhere else while it is held:
/// publication still lands in the directory that was opened (POSIX), or
/// the replacement is impossible while the handle is held (Windows).
#[test]
fn a_directory_swapped_for_a_link_while_held_cannot_redirect_files() -> TestResult {
    let temp = TempDir::new()?;
    let outside = TempDir::new()?;
    let destination = DirDestination::open(temp.path())?;
    let root = destination.root()?;
    let held = destination.create_dir(&root, "target")?;
    let moved = std::fs::rename(temp.path().join("target"), temp.path().join("moved"));
    if cfg!(windows) {
        assert!(moved.is_err(), "a held directory must not be renamable");
        return Ok(());
    }
    moved?;
    if symlink_dir(outside.path(), &temp.path().join("target"))?.is_none() {
        return Ok(());
    }
    stage_and_publish(&destination, &held, ".t", "file.txt", b"payload")?;
    assert_eq!(names(outside.path())?, Vec::<String>::new());
    assert_eq!(
        std::fs::read(temp.path().join("moved").join("file.txt"))?,
        b"payload"
    );
    // Resolving the name again refuses the link.
    assert_eq!(
        destination.open_dir(&root, "target").map(|_| ()),
        Err(DestError::WrongKind)
    );
    Ok(())
}

/// Planning lists the root once: every name, and nothing past the limit.
#[test]
fn listing_returns_every_name_within_its_limit() -> TestResult {
    let temp = TempDir::new()?;
    std::fs::write(temp.path().join("a.txt"), b"")?;
    std::fs::write(temp.path().join("B (2).txt"), b"")?;
    std::fs::create_dir(temp.path().join("sub"))?;
    let destination = DirDestination::open(temp.path())?;
    let root = destination.root()?;
    let mut listed = destination.list(&root, 3)?.ok_or("listing")?;
    listed.sort();
    assert_eq!(listed, ["B (2).txt", "a.txt", "sub"]);
    assert_eq!(destination.list(&root, 2)?, None);
    // The held handle still works afterwards.
    assert_eq!(destination.exists(&root, "a.txt"), Ok(true));
    Ok(())
}

#[cfg(unix)]
#[test]
fn fifos_are_not_opened_as_files() -> TestResult {
    let temp = TempDir::new()?;
    let status = std::process::Command::new("mkfifo")
        .arg(temp.path().join("pipe"))
        .status();
    if !status.is_ok_and(|status| status.success()) {
        eprintln!("skipping: mkfifo is unavailable");
        return Ok(());
    }
    let destination = DirDestination::open(temp.path())?;
    let root = destination.root()?;
    assert_eq!(
        destination.open_file(&root, "pipe").map(|_| ()),
        Err(DestError::WrongKind)
    );
    Ok(())
}

#[test]
fn debug_output_shows_no_paths() -> TestResult {
    let temp = TempDir::new()?;
    let destination = DirDestination::open(temp.path())?;
    let root = destination.root()?;
    let rendered = format!("{destination:?} {root:?}");
    let path = temp.path().to_string_lossy().into_owned();
    assert!(!rendered.contains(&path), "{rendered}");
    Ok(())
}

/// Between operations the destination folder is not locked: the user can
/// still rename or move it while the app runs.
#[test]
fn the_destination_folder_can_be_moved_while_open() -> TestResult {
    let temp = TempDir::new()?;
    let root = temp.path().join("Downloads");
    std::fs::create_dir(&root)?;
    let destination = DirDestination::open(&root)?;
    let handle = destination.root()?;
    stage_and_publish(&destination, &handle, ".t", "a.txt", b"x")?;
    drop(handle);
    std::fs::rename(&root, temp.path().join("Moved"))?;
    assert_eq!(
        std::fs::read(temp.path().join("Moved").join("a.txt"))?,
        b"x"
    );
    Ok(())
}

/// Windows re-resolves the root's path on every call. Someone who can
/// write the root's parent can rename the folder away and plant a junction
/// at its path: the root is reopened without following it and refused, so
/// nothing lands in the junction's target. While held (transfers are
/// retained), the folder can be neither moved, deleted, nor replaced.
#[cfg(windows)]
#[test]
fn a_junction_planted_at_the_root_path_redirects_nothing() -> TestResult {
    let temp = TempDir::new()?;
    let outside = TempDir::new()?;
    let root = temp.path().join("Downloads");
    let moved = temp.path().join("Moved");
    std::fs::create_dir(&root)?;
    let mut destination = DirDestination::open(&root)?;
    // Not held: the user can move the folder, and so can anyone else who
    // can write its parent, then plant a junction in its place.
    std::fs::rename(&root, &moved)?;
    junction(outside.path(), &root)?;
    assert_eq!(destination.root().map(|_| ()), Err(DestError::WrongKind));
    assert_eq!(destination.hold_root(true), Err(DestError::WrongKind));
    assert_eq!(names(outside.path())?, Vec::<String>::new());
    // The folder back in place and held: it cannot be moved, deleted, or
    // replaced, and publication lands in it.
    std::fs::remove_dir(&root)?;
    std::fs::rename(&moved, &root)?;
    destination.hold_root(true)?;
    assert!(std::fs::rename(&root, &moved).is_err(), "moved while held");
    assert!(std::fs::remove_dir(&root).is_err(), "deleted while held");
    let handle = destination.root()?;
    stage_and_publish(&destination, &handle, ".t", "a.txt", b"x")?;
    drop(handle);
    assert_eq!(std::fs::read(root.join("a.txt"))?, b"x");
    assert_eq!(names(outside.path())?, Vec::<String>::new());
    // Released: movable again.
    destination.hold_root(false)?;
    std::fs::rename(&root, &moved)?;
    Ok(())
}

/// Every directory below the root is refused as a junction too (the
/// symbolic-link variants of these tests need a privilege CI may lack).
#[cfg(windows)]
#[test]
fn junctions_below_the_root_are_refused_never_followed() -> TestResult {
    let temp = TempDir::new()?;
    let outside = TempDir::new()?;
    junction(outside.path(), &temp.path().join("linked"))?;
    let destination = DirDestination::open(temp.path())?;
    let root = destination.root()?;
    assert_eq!(
        destination.open_dir(&root, "linked").map(|_| ()),
        Err(DestError::WrongKind)
    );
    assert!(matches!(
        destination.create_dir(&root, "linked"),
        Err(DestError::Exists)
    ));
    assert_eq!(
        stage_and_publish(&destination, &root, ".t", "linked", b"payload"),
        Err(DestError::Exists)
    );
    assert_eq!(names(outside.path())?, Vec::<String>::new());
    Ok(())
}
