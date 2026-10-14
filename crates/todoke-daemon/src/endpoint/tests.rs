//! Who may connect, at the endpoint: the peer user ID both ways, and the
//! privacy of the directories a socket goes in.

#![cfg(unix)]

use core::time::Duration;
use std::os::unix::fs::PermissionsExt as _;
use std::path::PathBuf;

use super::*;

type AnyResult<T> = Result<T, Box<dyn std::error::Error>>;

struct Dir(PathBuf);

impl Dir {
    fn new(name: &str) -> AnyResult<Self> {
        let mut random = [0; 8];
        getrandom::fill(&mut random)?;
        // Short: a socket path must fit sun_path.
        let dir = PathBuf::from("/tmp").join(format!("td-{name}-{:x}", u64::from_le_bytes(random)));
        std::fs::create_dir(&dir)?;
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))?;
        Ok(Self(dir))
    }
}

impl Drop for Dir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn ours() -> u32 {
    rustix::process::getuid().as_raw()
}

#[tokio::test]
async fn the_peer_user_id_is_checked_both_ways() -> AnyResult<()> {
    let dir = Dir::new("uid")?;
    let path = dir.0.join("s");
    let mut listener = Listener::bind(&path).await?;
    // The socket itself is this user's alone.
    assert_eq!(
        std::fs::metadata(&path)?.permissions().mode() & 0o777,
        0o600
    );
    // This user's client is let in (kept open: macOS cannot read the
    // credentials of a peer that already left).
    let (_kept, _) = connect_to(&path, ours()).await?;
    let _ = tokio::time::timeout(Duration::from_secs(5), listener.accept()).await??;
    // A client refuses a daemon running as someone else.
    assert_eq!(
        connect_to(&path, ours() ^ 1)
            .await
            .map(|_| ())
            .map_err(|error| error.kind()),
        Err(std::io::ErrorKind::PermissionDenied)
    );
    // A daemon drops a client running as someone else, and waits on.
    listener.owner = ours() ^ 1;
    let (_client, _) = connect_to(&path, ours()).await?;
    assert!(
        tokio::time::timeout(Duration::from_millis(300), listener.accept())
            .await
            .is_err()
    );
    Ok(())
}

#[tokio::test]
async fn bind_never_replaces_something_that_is_not_a_socket() -> AnyResult<()> {
    let dir = Dir::new("file")?;
    let path = dir.0.join("s");
    std::fs::write(&path, b"keep")?;
    assert_eq!(
        Listener::bind(&path)
            .await
            .map(|_| ())
            .map_err(|error| error.kind()),
        Err(std::io::ErrorKind::AlreadyExists)
    );
    assert_eq!(std::fs::read(&path)?, b"keep");
    let link = dir.0.join("l");
    std::os::unix::fs::symlink(&path, &link)?;
    assert!(Listener::bind(&link).await.is_err());
    assert_eq!(std::fs::read(&path)?, b"keep");
    Ok(())
}

#[test]
fn a_shared_socket_directory_must_be_private_and_real() -> AnyResult<()> {
    let dir = Dir::new("priv")?;
    let created = dir.0.join("made");
    private_socket_dir(&created)?;
    assert_eq!(
        std::fs::metadata(&created)?.permissions().mode() & 0o777,
        0o700
    );
    let open = dir.0.join("open");
    std::fs::create_dir(&open)?;
    std::fs::set_permissions(&open, std::fs::Permissions::from_mode(0o755))?;
    assert_eq!(
        private_socket_dir(&open).map_err(|error| error.kind()),
        Err(std::io::ErrorKind::PermissionDenied)
    );
    // A link to a private directory is not the directory.
    let link = dir.0.join("link");
    std::os::unix::fs::symlink(&created, &link)?;
    assert_eq!(
        private_socket_dir(&link).map_err(|error| error.kind()),
        Err(std::io::ErrorKind::PermissionDenied)
    );
    // (Another owner needs root to arrange; the owner check is the same
    // comparison.)
    Ok(())
}
