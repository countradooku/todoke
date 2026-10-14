//! The server against a real core: the hello comes first and carries the
//! right proof, a client over the limit is told the daemon is busy, a
//! silent connection loses its slot at the hello deadline, a subscriber
//! that leaves frees its slot at once, and one that falls behind is told
//! how much it missed.

use core::time::Duration;
use std::sync::Arc;

use todoke_core::Core;
use todoke_core::api::{Request, Response};
use todoke_core::config::CoreConfig;

use super::{connection, events, serve};
use crate::endpoint::{self, Listener, Proof};
use crate::ipc::{
    Client, ClientMessage, MAX_CLIENT_MESSAGE, MAX_CONNECTIONS, MAX_SERVER_MESSAGE, ServerMessage,
    read_message, write_message,
};

type AnyResult<T> = Result<T, Box<dyn std::error::Error>>;

struct Scratch(std::path::PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// A core with the LAN off.
fn core() -> AnyResult<(Scratch, Core, crate::Paths)> {
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
    Ok((Scratch(home), core, paths))
}

/// A core with the LAN off, served on a fresh endpoint.
async fn served() -> AnyResult<(Scratch, std::path::PathBuf)> {
    let (home, core, paths) = core()?;
    let endpoint = paths.endpoint();
    let listener = Listener::bind(&endpoint).await?;
    tokio::spawn(serve(core, listener, Arc::new(tokio::sync::Notify::new())));
    Ok((home, endpoint))
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

/// Runs one connection with `proof`, sends `messages`, and returns what
/// the server answered before it closed (or went quiet).
async fn exchange(proof: Proof, messages: &[ClientMessage]) -> AnyResult<Vec<ServerMessage>> {
    let (_home, core, _) = core()?;
    let (mut client, server) = tokio::io::duplex(1 << 16);
    let stop = tokio::sync::Notify::new();
    let serving =
        tokio::spawn(async move { connection(core, Box::new(server), &proof, &stop).await });
    for message in messages {
        write_message(&mut client, message, MAX_CLIENT_MESSAGE).await?;
    }
    let mut answers = Vec::new();
    while let Ok(Ok(Some(answer))) = tokio::time::timeout(
        Duration::from_millis(500),
        read_message::<_, ServerMessage>(&mut client, MAX_SERVER_MESSAGE),
    )
    .await
    {
        answers.push(answer);
    }
    drop(client);
    let _ = serving.await;
    Ok(answers)
}

fn hello(token: Option<&str>) -> ClientMessage {
    ClientMessage::Hello {
        token: token.map(str::to_owned),
    }
}

fn status_request() -> ClientMessage {
    ClientMessage::Request {
        id: 1,
        request: Request::Status,
    }
}

fn token_proof(token: &str) -> Proof {
    Proof::Token(zeroize::Zeroizing::new(token.to_owned()))
}

#[tokio::test]
async fn only_the_right_hello_is_welcomed() -> AnyResult<()> {
    let welcomed =
        |answers: &[ServerMessage]| matches!(answers.first(), Some(ServerMessage::Welcome));
    // The right token, then a request: welcomed and answered.
    let answers = exchange(token_proof("aa"), &[hello(Some("aa")), status_request()]).await?;
    assert!(welcomed(&answers));
    assert!(matches!(
        answers.get(1),
        Some(ServerMessage::Response {
            id: 1,
            response: Response::Status(_)
        })
    ));
    // A wrong or missing token: nothing, not even to a request after it.
    for wrong in [Some("ab"), Some("a"), None] {
        assert!(
            exchange(token_proof("aa"), &[hello(wrong), status_request()])
                .await?
                .is_empty()
        );
    }
    // A request before the hello is never answered.
    assert!(
        exchange(Proof::PeerChecked, &[status_request(), hello(None)])
            .await?
            .is_empty()
    );
    // A peer-checked connection presents no token.
    assert!(
        exchange(Proof::PeerChecked, &[hello(Some("aa"))])
            .await?
            .is_empty()
    );
    // A second hello ends the connection.
    let answers = exchange(
        Proof::PeerChecked,
        &[hello(None), hello(None), status_request()],
    )
    .await?;
    assert_eq!(answers.len(), 1);
    assert!(welcomed(&answers));
    Ok(())
}

#[tokio::test]
async fn a_subscriber_that_falls_behind_is_told_how_much_it_missed() -> AnyResult<()> {
    let (sender, receiver) = tokio::sync::broadcast::channel(2);
    for n in 0..10 {
        sender.send(todoke_core::api::Event::Completed {
            transfer: format!("{n}"),
        })?;
    }
    let (mut client, server) = tokio::io::duplex(1 << 16);
    let forwarding = tokio::spawn(events(receiver, Box::new(server)));
    let first = read_message::<_, ServerMessage>(&mut client, MAX_SERVER_MESSAGE).await?;
    assert!(
        matches!(
            first,
            Some(ServerMessage::Event {
                event: todoke_core::api::Event::Missed { events: 8 }
            })
        ),
        "{first:?}"
    );
    // Anything from the subscriber ends the subscription.
    tokio::io::AsyncWriteExt::write_all(&mut client, b"x").await?;
    tokio::time::timeout(Duration::from_secs(2), forwarding).await???;
    Ok(())
}
