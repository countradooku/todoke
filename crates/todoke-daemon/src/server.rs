//! Serving the core over the IPC endpoint.

use core::time::Duration;
use std::sync::Arc;

use todoke_core::Core;
use todoke_core::api::Event;
use tokio::io::AsyncReadExt as _;
use tokio::sync::{Notify, Semaphore, broadcast};

use crate::endpoint::{self, Listener};
use crate::ipc::{
    ClientMessage, MAX_CLIENT_MESSAGE, MAX_CONNECTIONS, MAX_SERVER_MESSAGE, ServerMessage, Stream,
    read_message, write_message,
};

/// How long a new connection has to send its hello.
const HELLO_DEADLINE: Duration = if cfg!(test) {
    Duration::from_millis(300)
} else {
    Duration::from_secs(5)
};
/// A request connection with nothing to say for this long is closed.
const IDLE: Duration = if cfg!(test) {
    Duration::from_millis(600)
} else {
    Duration::from_mins(2)
};
/// How long a refused connection is given to read why.
const BUSY_DEADLINE: Duration = Duration::from_secs(1);
/// How long the server waits after a failed accept before the next.
const ACCEPT_PAUSE: Duration = Duration::from_millis(100);

/// Serves `core` on `listener` until `stop` is notified or a client asks
/// the daemon to stop.
pub(crate) async fn serve(core: Core, listener: Listener, stop: Arc<Notify>) {
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let accepted = tokio::select! {
            () = stop.notified() => return,
            accepted = listener.accept() => accepted,
        };
        let Ok((mut stream, proof)) = accepted else {
            // Out of descriptors, say: never spin on it.
            tokio::time::sleep(ACCEPT_PAUSE).await;
            continue;
        };
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            // Over the limit: say so, then close.
            tokio::spawn(async move {
                let busy = write_message(&mut stream, &ServerMessage::Busy, MAX_SERVER_MESSAGE);
                let _ = tokio::time::timeout(BUSY_DEADLINE, busy).await;
            });
            continue;
        };
        let (core, stop) = (core.clone(), Arc::clone(&stop));
        tokio::spawn(async move {
            let _permit = permit;
            let _ = connection(core, stream, &proof, &stop).await;
        });
    }
}

async fn connection(
    core: Core,
    mut stream: Box<dyn Stream>,
    proof: &endpoint::Proof,
    stop: &Notify,
) -> std::io::Result<()> {
    // The hello first, within its deadline; nothing else is read from an
    // unproven client.
    let hello = tokio::time::timeout(
        HELLO_DEADLINE,
        read_message::<_, ClientMessage>(&mut stream, MAX_CLIENT_MESSAGE),
    )
    .await
    .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
    let Some(ClientMessage::Hello { token }) = hello else {
        return Ok(());
    };
    if !endpoint::check(proof, token.as_deref()) {
        return Ok(());
    }
    write_message(&mut stream, &ServerMessage::Welcome, MAX_SERVER_MESSAGE).await?;
    loop {
        let message = tokio::time::timeout(
            IDLE,
            read_message::<_, ClientMessage>(&mut stream, MAX_CLIENT_MESSAGE),
        )
        .await
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
        let Some(message) = message else {
            return Ok(());
        };
        match message {
            ClientMessage::Request { id, request } => {
                let response = core.request(request).await;
                write_message(
                    &mut stream,
                    &ServerMessage::Response { id, response },
                    MAX_SERVER_MESSAGE,
                )
                .await?;
            }
            ClientMessage::Subscribe => return events(core.subscribe(), stream).await,
            ClientMessage::Shutdown => {
                stop.notify_waiters();
                stop.notify_one();
                return Ok(());
            }
            ClientMessage::Hello { .. } => return Ok(()),
        }
    }
}

/// Forwards events until the client goes away (it sends nothing more, so
/// anything it sends, or its closing, ends the subscription). A client
/// too slow to keep up is told how many events it missed; it never holds
/// the core back.
async fn events(
    mut events: broadcast::Receiver<Event>,
    stream: Box<dyn Stream>,
) -> std::io::Result<()> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let mut probe = [0_u8; 1];
    loop {
        let event = tokio::select! {
            _ = reader.read(&mut probe) => return Ok(()),
            received = events.recv() => match received {
                Ok(event) => event,
                Err(broadcast::error::RecvError::Lagged(missed)) => Event::Missed { events: missed },
                Err(broadcast::error::RecvError::Closed) => return Ok(()),
            },
        };
        write_message(
            &mut writer,
            &ServerMessage::Event { event },
            MAX_SERVER_MESSAGE,
        )
        .await?;
    }
}

#[cfg(test)]
mod tests;
