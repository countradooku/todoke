//! The desktop app's handoff: a second launch of the app (from a file
//! manager's menu, a Quick Action, a login item) hands its request to the
//! window already running and exits, so one window serves one profile.
//!
//! The endpoint is the daemon's kind ([`crate::ipc`]): only this user can
//! connect (the peer user ID on Unix, a token from the private state
//! directory on Windows). A request only asks the window to show itself or
//! offer a choice of contacts for some files; nothing is sent without the
//! user choosing in the window.

use core::time::Duration;
use std::path::PathBuf;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::Paths;
use crate::endpoint::{self, Listener};
use crate::ipc::{MAX_CLIENT_MESSAGE, ServerMessage, read_message, write_message};

/// How long a connection has to say what it wants.
const DEADLINE: Duration = Duration::from_secs(5);
/// The most paths one request may carry.
pub const MAX_PATHS: usize = 10_000;

/// What a second launch asks of the running window.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum Handoff {
    /// Show the window.
    Show,
    /// Offer these files and folders: the window asks who to send them to.
    Send {
        /// What to send.
        paths: Vec<PathBuf>,
    },
    /// Offer what the clipboard holds: the window asks who to send it to.
    SendClipboard,
}

#[derive(Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
enum Message {
    Hello { token: Option<String> },
    Handoff(Handoff),
}

/// The listening handoff endpoint; dropping it stops listening.
#[derive(Debug)]
pub struct Listening {
    stop: Arc<tokio::sync::Notify>,
    thread: Option<std::thread::JoinHandle<()>>,
}

impl Drop for Listening {
    fn drop(&mut self) {
        self.stop.notify_one();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// Listens for handoffs to the window of the profile in `paths`, calling
/// `deliver` with each (from the listener's thread).
///
/// # Errors
///
/// `AddrInUse` when a window already listens for this profile; other I/O
/// errors.
pub fn listen(
    paths: &Paths,
    deliver: impl Fn(Handoff) + Send + 'static,
) -> std::io::Result<Listening> {
    std::fs::create_dir_all(&paths.state_dir)?;
    let endpoint = paths.handoff_endpoint();
    let stop = Arc::new(tokio::sync::Notify::new());
    let (bound, ready) = std::sync::mpsc::channel();
    let stopping = Arc::clone(&stop);
    let thread = std::thread::Builder::new()
        .name("todoke-handoff".into())
        .spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
            else {
                let _ = bound.send(Err(std::io::ErrorKind::Other.into()));
                return;
            };
            runtime.block_on(async move {
                let listener = match Listener::bind(&endpoint).await {
                    Ok(listener) => listener,
                    Err(error) => {
                        let _ = bound.send(Err(error));
                        return;
                    }
                };
                let _ = bound.send(Ok(()));
                loop {
                    let accepted = tokio::select! {
                        () = stopping.notified() => return,
                        accepted = listener.accept() => accepted,
                    };
                    let Ok((mut stream, proof)) = accepted else {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    };
                    // One at a time: handoffs are rare and tiny.
                    let received = tokio::time::timeout(DEADLINE, async {
                        let Some(Message::Hello { token }) =
                            read_message::<_, Message>(&mut stream, MAX_CLIENT_MESSAGE).await?
                        else {
                            return Ok(None);
                        };
                        if !endpoint::check(&proof, token.as_deref()) {
                            return Ok(None);
                        }
                        let message =
                            read_message::<_, Message>(&mut stream, MAX_CLIENT_MESSAGE).await?;
                        write_message(&mut stream, &ServerMessage::Welcome, MAX_CLIENT_MESSAGE)
                            .await?;
                        std::io::Result::Ok(message)
                    })
                    .await;
                    if let Ok(Ok(Some(Message::Handoff(handoff)))) = received
                        && valid(&handoff)
                    {
                        deliver(handoff);
                    }
                }
            });
        })?;
    match ready.recv() {
        Ok(Ok(())) => Ok(Listening {
            stop,
            thread: Some(thread),
        }),
        Ok(Err(error)) => {
            let _ = thread.join();
            Err(error)
        }
        Err(_) => {
            let _ = thread.join();
            Err(std::io::ErrorKind::Other.into())
        }
    }
}

/// Only absolute paths, and not too many: the window shows what it got
/// and the user decides.
fn valid(handoff: &Handoff) -> bool {
    match handoff {
        Handoff::Send { paths } => {
            !paths.is_empty()
                && paths.len() <= MAX_PATHS
                && paths.iter().all(|path| path.is_absolute())
        }
        Handoff::Show | Handoff::SendClipboard => true,
    }
}

/// Hands `handoff` to the window of the profile in `paths`. Blocks until
/// the window has it.
///
/// # Errors
///
/// `NotFound` or `ConnectionRefused` when no window listens.
pub fn send(paths: &Paths, handoff: &Handoff) -> std::io::Result<()> {
    let endpoint = paths.handoff_endpoint();
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        tokio::time::timeout(DEADLINE, async {
            let (mut stream, token) = endpoint::connect(&endpoint).await?;
            write_message(&mut stream, &Message::Hello { token }, MAX_CLIENT_MESSAGE).await?;
            write_message(
                &mut stream,
                &Message::Handoff(handoff.clone()),
                MAX_CLIENT_MESSAGE,
            )
            .await?;
            match read_message::<_, ServerMessage>(&mut stream, MAX_CLIENT_MESSAGE).await? {
                Some(ServerMessage::Welcome) => Ok(()),
                _ => Err(std::io::ErrorKind::ConnectionRefused.into()),
            }
        })
        .await
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))?
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    type AnyResult<T> = Result<T, Box<dyn std::error::Error>>;

    struct Scratch(PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A handoff reaches the listening window; a second window cannot
    /// listen for the same profile; relative paths are dropped; after the
    /// window goes, nothing listens.
    #[test]
    fn a_second_launch_hands_over_to_the_first() -> AnyResult<()> {
        let mut random = [0; 8];
        getrandom::fill(&mut random)?;
        let home = Scratch(
            std::env::temp_dir().join(format!("todoke-handoff-{}", u64::from_le_bytes(random))),
        );
        let paths = Paths::under(&home.0);
        let (sender, received) = std::sync::mpsc::channel();
        let listening = listen(&paths, move |handoff| {
            let _ = sender.send(handoff);
        })?;
        let wanted = Handoff::Send {
            paths: vec![std::env::temp_dir().join("a.txt")],
        };
        send(&paths, &wanted)?;
        assert_eq!(received.recv_timeout(DEADLINE)?, wanted);
        send(&paths, &Handoff::Show)?;
        assert_eq!(received.recv_timeout(DEADLINE)?, Handoff::Show);
        // Relative paths are not delivered.
        send(
            &paths,
            &Handoff::Send {
                paths: vec!["relative.txt".into()],
            },
        )?;
        assert!(received.recv_timeout(Duration::from_millis(300)).is_err());
        assert_eq!(
            listen(&paths, |_| {}).map(|_| ()).map_err(|e| e.kind()),
            Err(std::io::ErrorKind::AddrInUse)
        );
        drop(listening);
        assert!(send(&paths, &Handoff::Show).is_err());
        Ok(())
    }
}
