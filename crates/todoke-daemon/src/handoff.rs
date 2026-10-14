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
/// How long a connection has to authenticate.
const HELLO_DEADLINE: Duration = Duration::from_secs(2);
/// Connections served at once.
pub const MAX_CONNECTIONS: usize = 8;
/// A request's paths are sent in parts of at most this many bytes (as
/// JSON), well under the message limit; the window gathers them.
const PART_BYTES: usize = MAX_CLIENT_MESSAGE / 2;
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
/// Connections are served concurrently, at most [`MAX_CONNECTIONS`] at a
/// time (more are closed at once); each must authenticate within
/// [`HELLO_DEADLINE`] and finish within [`DEADLINE`], so a slow or hostile
/// local client cannot hold the endpoint.
///
/// # Errors
///
/// `AddrInUse` when a window already listens for this profile; other I/O
/// errors.
pub fn listen(
    paths: &Paths,
    deliver: impl Fn(Handoff) + Send + 'static,
) -> std::io::Result<Listening> {
    private_dir(&paths.state_dir)?;
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
            let local = tokio::task::LocalSet::new();
            local.block_on(&runtime, async move {
                let listener = match Listener::bind(&endpoint).await {
                    Ok(listener) => listener,
                    Err(error) => {
                        let _ = bound.send(Err(error));
                        return;
                    }
                };
                let _ = bound.send(Ok(()));
                let deliver = std::rc::Rc::new(deliver);
                let slots = Arc::new(tokio::sync::Semaphore::new(MAX_CONNECTIONS));
                loop {
                    let accepted = tokio::select! {
                        () = stopping.notified() => return,
                        accepted = listener.accept() => accepted,
                    };
                    let Ok((stream, proof)) = accepted else {
                        tokio::time::sleep(Duration::from_millis(100)).await;
                        continue;
                    };
                    // Busy: this one is closed rather than queued.
                    let Ok(slot) = Arc::clone(&slots).try_acquire_owned() else {
                        continue;
                    };
                    let deliver = std::rc::Rc::clone(&deliver);
                    tokio::task::spawn_local(async move {
                        let _slot = slot;
                        if let Some(handoff) = serve(stream, &proof).await {
                            deliver(handoff);
                        }
                    });
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

/// One connection: the hello within [`HELLO_DEADLINE`], the request
/// within [`DEADLINE`]; the request if it is valid.
async fn serve(mut stream: impl crate::ipc::Stream, proof: &endpoint::Proof) -> Option<Handoff> {
    let Ok(Ok(Some(Message::Hello { token }))) = tokio::time::timeout(
        HELLO_DEADLINE,
        read_message::<_, Message>(&mut stream, MAX_CLIENT_MESSAGE),
    )
    .await
    else {
        return None;
    };
    if !endpoint::check(proof, token.as_deref()) {
        return None;
    }
    let received = tokio::time::timeout(DEADLINE, async {
        let message = read_message::<_, Message>(&mut stream, MAX_CLIENT_MESSAGE).await?;
        write_message(&mut stream, &ServerMessage::Welcome, MAX_CLIENT_MESSAGE).await?;
        std::io::Result::Ok(message)
    })
    .await;
    match received {
        Ok(Ok(Some(Message::Handoff(handoff)))) if valid(&handoff) => Some(handoff),
        _ => None,
    }
}

/// Makes the state directory, private to this user, if it is missing.
fn private_dir(dir: &std::path::Path) -> std::io::Result<()> {
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    std::os::unix::fs::DirBuilderExt::mode(&mut builder, 0o700);
    builder.create(dir)
}

/// The window's hold on its profile: while it lives, no other launch of
/// the app opens a window for the profile (a launch that cannot take it
/// hands its request over instead). Released when dropped or when the
/// process ends.
#[derive(Debug)]
pub struct InstanceLock(
    #[allow(dead_code, reason = "held: dropping releases the lock")] std::fs::File,
);

/// Takes the profile's instance lock (`desktop.lock` in the state
/// directory); `None` when another launch holds it.
///
/// # Errors
///
/// I/O errors other than the lock being held.
pub fn lock(paths: &Paths) -> std::io::Result<Option<InstanceLock>> {
    private_dir(&paths.state_dir)?;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(paths.state_dir.join("desktop.lock"))?;
    match file.try_lock() {
        Ok(()) => Ok(Some(InstanceLock(file))),
        Err(std::fs::TryLockError::WouldBlock) => Ok(None),
        Err(std::fs::TryLockError::Error(error)) => Err(error),
    }
}

/// Whether `error` from [`send`] means that no window listens (rather than
/// one that failed to take the request).
#[must_use]
pub fn no_window(error: &std::io::Error) -> bool {
    matches!(
        error.kind(),
        std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused
    )
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
/// the window has it. Many paths go in several parts (the window gathers
/// them into one "Send to…").
///
/// # Errors
///
/// `NotFound` or `ConnectionRefused` when no window listens ([`no_window`]);
/// `TimedOut` when one does not answer; other I/O errors.
pub fn send(paths: &Paths, handoff: &Handoff) -> std::io::Result<()> {
    let Handoff::Send { paths: files } = handoff else {
        return send_one(paths, handoff);
    };
    let mut part = Vec::new();
    let mut bytes = 0;
    for file in files {
        let size = serde_json::to_string(file).map_or(PART_BYTES, |text| text.len() + 1);
        if !part.is_empty() && bytes + size > PART_BYTES {
            send_one(
                paths,
                &Handoff::Send {
                    paths: core::mem::take(&mut part),
                },
            )?;
            bytes = 0;
        }
        part.push(file.clone());
        bytes += size;
    }
    send_one(paths, &Handoff::Send { paths: part })
}

fn send_one(paths: &Paths, handoff: &Handoff) -> std::io::Result<()> {
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

    fn scratch(name: &str) -> AnyResult<(Scratch, Paths)> {
        let mut random = [0; 8];
        getrandom::fill(&mut random)?;
        let home = Scratch(std::env::temp_dir().join(format!(
            "todoke-handoff-{name}-{}",
            u64::from_le_bytes(random)
        )));
        let paths = Paths::under(&home.0);
        Ok((home, paths))
    }

    /// Many paths arrive in parts, all of them, in order.
    #[test]
    fn many_paths_arrive_in_parts() -> AnyResult<()> {
        let (_home, paths) = scratch("parts")?;
        let (sender, received) = std::sync::mpsc::channel();
        let _listening = listen(&paths, move |handoff| {
            let _ = sender.send(handoff);
        })?;
        let long = "x".repeat(200);
        let files: Vec<PathBuf> = (0..MAX_PATHS)
            .map(|n| std::env::temp_dir().join(format!("{long}-{n}")))
            .collect();
        send(
            &paths,
            &Handoff::Send {
                paths: files.clone(),
            },
        )?;
        let mut got = Vec::new();
        let mut parts = 0;
        while got.len() < files.len() {
            match received.recv_timeout(DEADLINE)? {
                Handoff::Send { paths } => got.extend(paths),
                other => return Err(format!("{other:?}").into()),
            }
            parts += 1;
        }
        assert!(parts > 1);
        assert_eq!(got, files);
        Ok(())
    }

    /// One launch holds the profile; another cannot until it lets go.
    #[test]
    fn one_launch_holds_the_instance_lock() -> AnyResult<()> {
        let (_home, paths) = scratch("lock")?;
        let held = lock(&paths)?.ok_or("not taken")?;
        assert!(lock(&paths)?.is_none());
        drop(held);
        assert!(lock(&paths)?.is_some());
        Ok(())
    }

    /// A client that connects and says nothing does not hold up others.
    #[test]
    fn a_silent_client_blocks_no_one() -> AnyResult<()> {
        let (_home, paths) = scratch("silent")?;
        let (sender, received) = std::sync::mpsc::channel();
        let _listening = listen(&paths, move |handoff| {
            let _ = sender.send(handoff);
        })?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let endpoint = paths.handoff_endpoint();
        let _silent = runtime.block_on(endpoint::connect(&endpoint))?;
        let started = std::time::Instant::now();
        send(&paths, &Handoff::Show)?;
        assert_eq!(received.recv_timeout(DEADLINE)?, Handoff::Show);
        assert!(started.elapsed() < HELLO_DEADLINE);
        Ok(())
    }

    /// More silent clients than the cap, all at once: the extra ones are
    /// closed, the silent ones time out, and a real request gets through
    /// within a few seconds.
    #[test]
    fn silent_clients_beyond_the_cap_do_not_lock_out_a_real_send() -> AnyResult<()> {
        let (_home, paths) = scratch("flood")?;
        let (sender, received) = std::sync::mpsc::channel();
        let _listening = listen(&paths, move |handoff| {
            let _ = sender.send(handoff);
        })?;
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        let endpoint = paths.handoff_endpoint();
        let mut silent = Vec::new();
        for _ in 0..MAX_CONNECTIONS * 2 {
            silent.push(runtime.block_on(endpoint::connect(&endpoint))?);
        }
        let started = std::time::Instant::now();
        let limit = HELLO_DEADLINE + Duration::from_secs(3);
        // While the silent clients hold every slot a request is closed
        // unanswered; once they time out, it is served.
        loop {
            match send(&paths, &Handoff::Show) {
                Ok(()) => break,
                Err(_) if started.elapsed() < limit => {
                    std::thread::sleep(Duration::from_millis(100));
                }
                Err(error) => return Err(error.into()),
            }
        }
        assert_eq!(received.recv_timeout(DEADLINE)?, Handoff::Show);
        assert!(started.elapsed() < limit);
        drop(silent);
        Ok(())
    }

    /// A send with no paths is refused by the window: nothing is delivered,
    /// and the endpoint serves the next request.
    #[test]
    fn a_send_without_paths_delivers_nothing() -> AnyResult<()> {
        let (_home, paths) = scratch("empty-send")?;
        let (sender, received) = std::sync::mpsc::channel();
        let _listening = listen(&paths, move |handoff| {
            let _ = sender.send(handoff);
        })?;
        // The window may answer or close the connection; either way it
        // delivers nothing.
        let _answer = send(&paths, &Handoff::Send { paths: Vec::new() });
        assert!(received.recv_timeout(Duration::from_millis(300)).is_err());
        send(&paths, &Handoff::Show)?;
        assert_eq!(received.recv_timeout(DEADLINE)?, Handoff::Show);
        Ok(())
    }
}
