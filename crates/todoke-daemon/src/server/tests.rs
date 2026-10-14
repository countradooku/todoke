//! The server's limits, against a real core: a client over the limit is
//! told the daemon is busy, a silent connection loses its slot at the
//! hello deadline, and a subscriber that leaves frees its slot at once.

use core::time::Duration;
use std::sync::Arc;

use todoke_core::Core;
use todoke_core::api::{Request, Response};
use todoke_core::config::CoreConfig;

use super::serve;
use crate::endpoint::{self, Listener};
use crate::ipc::{Client, MAX_CONNECTIONS};

type AnyResult<T> = Result<T, Box<dyn std::error::Error>>;

struct Scratch(std::path::PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A core with the LAN off, served on a fresh endpoint.
async fn served() -> AnyResult<(Scratch, std::path::PathBuf)> {
    let mut random = [0; 8];
    getrandom::fill(&mut random)?;
    let home = std::env::temp_dir().join(format!("todoke-srv-{}", u64::from_le_bytes(random)));
    let paths = crate::Paths::under(&home);
    std::fs::create_dir_all(&paths.state_dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::set_permissions(&paths.state_dir, std::fs::Permissions::from_mode(0o700))?;
    }
    let mut config = CoreConfig::new(paths.state_dir.clone(), paths.downloads_dir.clone());
    config.lan.enabled = false;
    let core = Core::start(
        config,
        Box::new(todoke_core::KeyFile::new(paths.storage_key())),
    )?;
    let endpoint = paths.endpoint();
    let listener = Listener::bind(&endpoint).await?;
    tokio::spawn(serve(core, listener, Arc::new(tokio::sync::Notify::new())));
    Ok((Scratch(home), endpoint))
}

async fn status(endpoint: &std::path::Path) -> AnyResult<()> {
    let mut client = Client::connect(endpoint).await?;
    match client.request(Request::Status).await? {
        Response::Status(_) => Ok(()),
        other => Err(format!("{other:?}").into()),
    }
}

#[tokio::test]
async fn silent_connections_lose_their_slots_and_extra_clients_hear_busy() -> AnyResult<()> {
    let (_home, endpoint) = served().await?;
    // Every slot taken by connections that never say hello.
    let mut silent = Vec::new();
    for _ in 0..MAX_CONNECTIONS {
        silent.push(endpoint::connect(&endpoint).await?);
    }
    tokio::time::sleep(Duration::from_millis(50)).await;
    let busy = Client::connect(&endpoint).await.map(|_| ());
    assert_eq!(
        busy.map_err(|error| error.kind()),
        Err(std::io::ErrorKind::ResourceBusy)
    );
    // At the hello deadline they are closed, and service returns.
    tokio::time::sleep(super::HELLO_DEADLINE * 2).await;
    status(&endpoint).await?;
    drop(silent);
    Ok(())
}

#[tokio::test]
async fn subscribers_that_leave_free_their_slots() -> AnyResult<()> {
    let (_home, endpoint) = served().await?;
    for _ in 0..2 {
        let mut subscribers = Vec::new();
        for _ in 0..MAX_CONNECTIONS {
            subscribers.push(Client::connect(&endpoint).await?.subscribe().await?);
        }
        // No event flows; the server still notices they left.
        drop(subscribers);
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    status(&endpoint).await
}

#[tokio::test]
async fn idle_request_connections_are_closed() -> AnyResult<()> {
    let (_home, endpoint) = served().await?;
    let mut client = Client::connect(&endpoint).await?;
    tokio::time::sleep(super::IDLE * 2).await;
    assert!(client.request(Request::Status).await.is_err());
    status(&endpoint).await
}
