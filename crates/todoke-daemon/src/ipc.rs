//! The daemon's local IPC: how the CLI (and later other local interfaces)
//! talk to the running core.
//!
//! # Who may connect
//!
//! Only this user. On Unix the endpoint is a socket in the private state
//! directory (0700, the socket itself 0600), and every connection's peer
//! user ID must equal the daemon's. On Windows it is a loopback TCP port,
//! and a client must first present a 32-byte random token from a file in
//! the user's private state directory (compared in constant time); other
//! users can reach the port but cannot read the token. A process running as
//! this user can do anything the user can: that is the boundary.
//!
//! # Messages
//!
//! Each message is a 4-byte big-endian length and that many bytes of JSON.
//! A client's messages are at most [`MAX_CLIENT_MESSAGE`] bytes; larger ones
//! close the connection. The first client message is [`ClientMessage::Hello`]
//! (with the token on Windows). Requests carry an ID echoed by their
//! response; a connection that sends [`ClientMessage::Subscribe`] receives
//! every [`Event`] from then on, and sends nothing more.
//!
//! # Limits
//!
//! At most [`MAX_CONNECTIONS`] connections are served; one more is sent
//! [`ServerMessage::Busy`] and closed. The hello must arrive within 5
//! seconds, and a request connection idle for 2 minutes is closed. A
//! subscriber that falls behind gets [`Event::Missed`] in place of what it
//! missed.

use core::fmt;
use std::path::Path;

use serde::{Deserialize, Serialize};
use todoke_core::api::{Event, Request, Response};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

/// The largest message a client may send.
pub const MAX_CLIENT_MESSAGE: usize = 1 << 20;
/// The largest message the daemon sends.
pub const MAX_SERVER_MESSAGE: usize = 16 << 20;
/// Connections served at once; more wait in the listener's backlog.
pub const MAX_CONNECTIONS: usize = 32;

/// A message from a client.
#[derive(Clone, Serialize, Deserialize)]
#[serde(
    tag = "type",
    content = "body",
    rename_all = "snake_case",
    deny_unknown_fields
)]
pub enum ClientMessage {
    /// The first message: the access token on Windows, none on Unix.
    Hello {
        /// The token, hex.
        token: Option<String>,
    },
    /// A request to the core.
    Request {
        /// Echoed by the response.
        id: u64,
        /// The request.
        request: Request,
    },
    /// Send every event on this connection from now on.
    Subscribe,
    /// Stop the daemon.
    Shutdown,
}

impl fmt::Debug for ClientMessage {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Hello { .. } => f.write_str("Hello { <redacted> }"),
            Self::Request { id, request } => {
                write!(f, "Request {{ id: {id}, request: {request:?} }}")
            }
            Self::Subscribe => f.write_str("Subscribe"),
            Self::Shutdown => f.write_str("Shutdown"),
        }
    }
}

/// A message from the daemon.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", content = "body", rename_all = "snake_case")]
pub enum ServerMessage {
    /// The hello was accepted.
    Welcome,
    /// The response to request `id`.
    Response {
        /// The request's ID.
        id: u64,
        /// The response.
        response: Response,
    },
    /// An event (after `Subscribe`).
    Event {
        /// The event.
        event: Event,
    },
    /// Every connection slot is taken; try again later.
    Busy,
}

/// Writes one message.
///
/// # Errors
///
/// An I/O error; `InvalidInput` for a message over `max` bytes.
pub async fn write_message<W: AsyncWrite + Unpin, T: Serialize>(
    writer: &mut W,
    message: &T,
    max: usize,
) -> std::io::Result<()> {
    let bytes = serde_json::to_vec(message)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    if bytes.len() > max {
        return Err(std::io::ErrorKind::InvalidInput.into());
    }
    let len = u32::try_from(bytes.len())
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
    writer.write_all(&len.to_be_bytes()).await?;
    writer.write_all(&bytes).await?;
    writer.flush().await
}

/// Reads one message of at most `max` bytes; `Ok(None)` at a clean end of
/// stream.
///
/// # Errors
///
/// An I/O error; `InvalidData` for an oversized or malformed message.
pub async fn read_message<R: AsyncRead + Unpin, T: for<'de> Deserialize<'de>>(
    reader: &mut R,
    max: usize,
) -> std::io::Result<Option<T>> {
    let mut len = [0; 4];
    match reader.read_exact(&mut len).await {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(error) => return Err(error),
    }
    let len = usize::try_from(u32::from_be_bytes(len)).unwrap_or(usize::MAX);
    if len > max {
        return Err(std::io::ErrorKind::InvalidData.into());
    }
    // Bounded by `max` before allocating.
    let mut bytes = vec![0; len];
    reader.read_exact(&mut bytes).await?;
    serde_json::from_slice(&bytes)
        .map(Some)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))
}

/// A connection to the daemon.
pub struct Client {
    stream: Box<dyn Stream>,
    next_id: u64,
}

impl fmt::Debug for Client {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Client")
    }
}

/// A byte stream to or from the daemon.
pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}

impl Client {
    /// Connects to the daemon whose endpoint is `endpoint`.
    ///
    /// # Errors
    ///
    /// `NotFound` or `ConnectionRefused` if no daemon runs; `PermissionDenied`
    /// if it refused this client or (Unix) runs as another user;
    /// `ResourceBusy` if every connection slot is taken.
    pub async fn connect(endpoint: &Path) -> std::io::Result<Self> {
        let (stream, token) = crate::endpoint::connect(endpoint).await?;
        let mut client = Self { stream, next_id: 0 };
        write_message(
            &mut client.stream,
            &ClientMessage::Hello { token },
            MAX_CLIENT_MESSAGE,
        )
        .await?;
        match read_message::<_, ServerMessage>(&mut client.stream, MAX_SERVER_MESSAGE).await? {
            Some(ServerMessage::Welcome) => Ok(client),
            Some(ServerMessage::Busy) => Err(std::io::ErrorKind::ResourceBusy.into()),
            _ => Err(std::io::ErrorKind::PermissionDenied.into()),
        }
    }

    /// Sends `request` and waits for its response.
    ///
    /// # Errors
    ///
    /// An I/O error, or `InvalidData` for an unexpected reply.
    pub async fn request(&mut self, request: Request) -> std::io::Result<Response> {
        self.next_id += 1;
        let id = self.next_id;
        write_message(
            &mut self.stream,
            &ClientMessage::Request { id, request },
            MAX_CLIENT_MESSAGE,
        )
        .await?;
        loop {
            match read_message::<_, ServerMessage>(&mut self.stream, MAX_SERVER_MESSAGE).await? {
                Some(ServerMessage::Response {
                    id: reply,
                    response,
                }) if reply == id => {
                    return Ok(response);
                }
                Some(ServerMessage::Event { .. }) => {}
                _ => return Err(std::io::ErrorKind::InvalidData.into()),
            }
        }
    }

    /// Turns this connection into an event stream.
    ///
    /// # Errors
    ///
    /// An I/O error.
    pub async fn subscribe(mut self) -> std::io::Result<Events> {
        write_message(
            &mut self.stream,
            &ClientMessage::Subscribe,
            MAX_CLIENT_MESSAGE,
        )
        .await?;
        Ok(Events {
            stream: self.stream,
        })
    }

    /// Asks the daemon to stop.
    ///
    /// # Errors
    ///
    /// An I/O error.
    pub async fn shutdown(mut self) -> std::io::Result<()> {
        write_message(
            &mut self.stream,
            &ClientMessage::Shutdown,
            MAX_CLIENT_MESSAGE,
        )
        .await
    }
}

/// Events from the daemon.
pub struct Events {
    stream: Box<dyn Stream>,
}

impl fmt::Debug for Events {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Events")
    }
}

impl Events {
    /// The next event; `Ok(None)` when the daemon stops.
    ///
    /// # Errors
    ///
    /// An I/O error.
    pub async fn next(&mut self) -> std::io::Result<Option<Event>> {
        loop {
            match read_message::<_, ServerMessage>(&mut self.stream, MAX_SERVER_MESSAGE).await? {
                Some(ServerMessage::Event { event }) => return Ok(Some(event)),
                Some(_) => {}
                None => return Ok(None),
            }
        }
    }
}

#[cfg(test)]
mod tests;
