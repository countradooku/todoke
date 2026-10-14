//! Serving the core over the IPC endpoint.

use std::sync::Arc;

use todoke_core::Core;
use tokio::sync::{Notify, Semaphore, broadcast};

use crate::endpoint::{self, Listener};
use crate::ipc::{
    ClientMessage, MAX_CLIENT_MESSAGE, MAX_CONNECTIONS, MAX_SERVER_MESSAGE, ServerMessage, Stream,
    read_message, write_message,
};

/// Serves `core` on `listener` until `stop` is notified or a client asks
/// the daemon to stop.
pub(crate) async fn serve(core: Core, listener: Listener, stop: Arc<Notify>) {
    let permits = Arc::new(Semaphore::new(MAX_CONNECTIONS));
    loop {
        let accepted = tokio::select! {
            () = stop.notified() => return,
            accepted = listener.accept() => accepted,
        };
        let Ok((stream, proof)) = accepted else {
            continue;
        };
        let Ok(permit) = Arc::clone(&permits).try_acquire_owned() else {
            // Over the limit: close it at once.
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
    // The hello first; nothing else is read from an unproven client.
    let hello = read_message::<_, ClientMessage>(&mut stream, MAX_CLIENT_MESSAGE).await?;
    let Some(ClientMessage::Hello { token }) = hello else {
        return Ok(());
    };
    if !endpoint::check(proof, token.as_deref()) {
        return Ok(());
    }
    write_message(&mut stream, &ServerMessage::Welcome, MAX_SERVER_MESSAGE).await?;
    while let Some(message) =
        read_message::<_, ClientMessage>(&mut stream, MAX_CLIENT_MESSAGE).await?
    {
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
    Ok(())
}

/// Forwards events until the client goes away. A client too slow to keep
/// up loses events (and is told nothing); it never holds the core back.
async fn events(
    mut events: broadcast::Receiver<todoke_core::api::Event>,
    mut stream: Box<dyn Stream>,
) -> std::io::Result<()> {
    loop {
        match events.recv().await {
            Ok(event) => {
                write_message(
                    &mut stream,
                    &ServerMessage::Event { event },
                    MAX_SERVER_MESSAGE,
                )
                .await?;
            }
            Err(broadcast::error::RecvError::Lagged(_)) => {}
            Err(broadcast::error::RecvError::Closed) => return Ok(()),
        }
    }
}
