//! One contact session: a transfer engine driven over it, local decisions
//! applied, events reported, and on its end the unfinished offers kept for
//! the next session (§7.5: resumption needs a fresh session and Accept).

use core::time::Duration;
use std::rc::Rc;

use todoke_proto::transfer::{CancelReason, RejectReason, TransferId};
use todoke_transfer::{
    Clock, Direction, EngineConfig, OutgoingOffer, TransferEngine, TransferEvent, pump,
};
use todoke_transport::{Established, TcpLink};
use tokio::sync::{mpsc, oneshot};

use super::running::{PeerQueue, State, TransferRecord, wall};
use crate::api::{EntryInfo, ErrorCode, Event, OfferInfo, Response, TransferState, Way, hex};

/// How long the session waits for a frame before looking at commands.
const POLL: Duration = Duration::from_millis(100);
/// A session with nothing to do closes after this long.
const IDLE: Duration = Duration::from_secs(30);

/// What the rest of the core asks a session to do.
pub(super) enum SessionCommand {
    /// Offer this transfer.
    Offer(Box<crate::send::Prepared>),
    /// The user accepted (all files when `None`).
    Accept(TransferId, Option<Vec<u32>>),
    /// The user declined.
    Decline(TransferId),
    /// The user cancelled.
    Cancel(TransferId),
    /// A decision with somewhere to report its outcome.
    Reply(Box<SessionCommand>, oneshot::Sender<Response>),
}

impl SessionCommand {
    pub(super) fn with_reply(command: Self, reply: oneshot::Sender<Response>) -> Self {
        Self::Reply(Box::new(command), reply)
    }
}

type Engine<'k> =
    TransferEngine<'k, crate::profile::Keys, todoke_fs::FsSource, super::running::Sink>;

/// Runs `established` until it ends.
pub(super) async fn run(state: Rc<State>, mut established: Established<TcpLink>) {
    let peer = *established.peer();
    let Ok(queue) = state.take_queue(&peer) else {
        return;
    };
    let queue_offers = queue.offers;
    let mut prepared = queue.prepared;
    let queue_source = queue.source;
    let (commands, mut inbox) = mpsc::channel(32);
    state.sessions.borrow_mut().insert(peer, commands);
    let identity = &state.identity;
    let session = established.session();
    let mono = session.now();
    let config = EngineConfig {
        transport: "lan",
        ..EngineConfig::default()
    };
    let engine = TransferEngine::new(
        session.transfer_binding(),
        identity.keys(),
        identity.device_key(),
        queue_source,
        state.sink.clone(),
        config,
        Clock::new(wall(), mono),
        mono,
    );
    let Ok(mut engine) = engine else {
        state.sessions.borrow_mut().remove(&peer);
        return;
    };
    let mut waiting = queue_offers;
    let mut ready = false;
    let mut idle_since = mono;
    loop {
        let session = established.session();
        let until = session.now() + POLL;
        let pumped = pump(session, &mut engine, until).await;
        let now = established.session().now();
        while let Some(event) = engine.pop_event() {
            if matches!(event, TransferEvent::Ready { .. }) {
                ready = true;
                for offer in waiting.drain(..) {
                    offer_or_report(&state, &mut engine, offer, now);
                }
                for new in prepared.drain(..) {
                    offer_new(&state, &mut engine, &new, now);
                }
            }
            report(&state, peer, event);
            idle_since = now;
        }
        while let Ok(command) = inbox.try_recv() {
            apply(&state, &mut engine, &mut prepared, ready, command, now);
            idle_since = now;
        }
        if pumped.is_err() {
            break;
        }
        let busy = state
            .transfers
            .borrow()
            .values()
            .any(|record| record.peer == peer && !record.state.is_finished());
        if !busy
            && waiting.is_empty()
            && prepared.is_empty()
            && now.saturating_sub(idle_since) >= IDLE
        {
            engine.close(None);
            break;
        }
    }
    // Whatever was not finished waits for the next session.
    while let Some(event) = engine.pop_event() {
        report(&state, peer, event);
    }
    state.interrupt(&peer);
    let mut offers = engine.take_resumable();
    offers.extend(waiting);
    let (source, _) = engine.into_parts();
    state.sessions.borrow_mut().remove(&peer);
    state.queues.borrow_mut().insert(
        peer,
        PeerQueue {
            source,
            prepared,
            offers,
        },
    );
    drop(established);
}

fn offer_or_report(state: &State, engine: &mut Engine<'_>, offer: OutgoingOffer, now: Duration) {
    let id = *offer.transfer_id();
    if engine.offer(offer, now).is_err() {
        end(
            state,
            &id,
            TransferState::Failed,
            "the peer cannot take this offer",
        );
    }
}

/// Builds a new transfer's offer for this session's negotiated suite and
/// the receiver's limits (§6), and offers it.
fn offer_new(
    state: &State,
    engine: &mut Engine<'_>,
    prepared: &crate::send::Prepared,
    now: Duration,
) {
    let id = *prepared.transfer_id();
    let Some(negotiated) = engine.negotiated() else {
        end(
            state,
            &id,
            TransferState::Failed,
            "the session is not ready",
        );
        return;
    };
    let built = crate::send::build(
        prepared,
        state.identity.binding().device_public(),
        engine.session().peer_device(),
        negotiated.suite(),
        &negotiated.send_limits(),
    );
    match built {
        Ok(offer) => offer_or_report(state, engine, offer, now),
        Err(_) => end(
            state,
            &id,
            TransferState::Failed,
            "the receiver cannot take a transfer this large",
        ),
    }
}

fn apply(
    state: &State,
    engine: &mut Engine<'_>,
    waiting: &mut Vec<crate::send::Prepared>,
    ready: bool,
    command: SessionCommand,
    now: Duration,
) {
    let (command, reply) = match command {
        SessionCommand::Reply(command, reply) => (*command, Some(reply)),
        other => (other, None),
    };
    let outcome = match command {
        SessionCommand::Offer(prepared) => {
            if ready {
                offer_new(state, engine, &prepared, now);
            } else {
                waiting.push(*prepared);
            }
            Ok(())
        }
        SessionCommand::Accept(id, files) => {
            let selection = files.unwrap_or_else(|| selectable(state, &id));
            engine.accept(&id, selection, now)
        }
        SessionCommand::Decline(id) => engine.reject(&id, RejectReason::Declined),
        SessionCommand::Cancel(id) => engine.cancel(&id, CancelReason::User, now),
        SessionCommand::Reply(..) => Ok(()),
    };
    if let Some(reply) = reply {
        let _ = reply.send(match outcome {
            Ok(()) => Response::Done,
            Err(error) => Response::error(ErrorCode::State, error.to_string()),
        });
    }
}

/// Every file of an offered transfer (for "accept all").
fn selectable(state: &State, id: &TransferId) -> Vec<u32> {
    state
        .received
        .borrow()
        .get(id)
        .map_or_else(Vec::new, |offer| {
            offer
                .entries
                .iter()
                .filter(|entry| !entry.directory)
                .map(|entry| entry.id)
                .collect()
        })
}

fn end(state: &State, id: &TransferId, reason: TransferState, message: &str) {
    state.set_state(id, reason);
    if let Some(record) = state.transfers.borrow_mut().get_mut(id) {
        record.detail = Some(message.to_owned());
    }
    state.emit(Event::Ended {
        transfer: hex(id),
        reason,
        message: message.to_owned(),
    });
}

fn way(direction: Direction) -> Way {
    match direction {
        Direction::Outgoing => Way::Outgoing,
        Direction::Incoming => Way::Incoming,
    }
}

fn offer_received(
    state: &State,
    peer: todoke_crypto::identity::Ed25519PublicKey,
    view: &todoke_transfer::OfferView,
) {
    state.remember(
        view.transfer_id,
        TransferRecord {
            peer,
            way: Way::Incoming,
            state: TransferState::AwaitingDecision,
            detail: None,
            done: 0,
            total: view.total_bytes,
        },
    );
    let offer = OfferInfo {
        transfer: hex(view.transfer_id),
        from: hex(view.sender.as_bytes()),
        entries: view
            .entries
            .iter()
            .map(|entry| EntryInfo {
                id: entry.id,
                parent: entry.parent,
                directory: entry.kind == todoke_proto::transfer::EntryKind::Directory,
                name: entry.name.clone(),
                size: entry.size,
            })
            .collect(),
        total_bytes: view.total_bytes,
        resume: view.resume_selection.clone(),
    };
    state
        .received
        .borrow_mut()
        .insert(view.transfer_id, offer.clone());
    state.emit(Event::OfferReceived(offer));
}

/// Mirrors an engine event into the core's records and events.
fn report(state: &State, peer: todoke_crypto::identity::Ed25519PublicKey, event: TransferEvent) {
    match event {
        TransferEvent::OfferReceived(view) => offer_received(state, peer, &view),
        TransferEvent::Accepted {
            transfer_id, bytes, ..
        } => {
            state.set_state(&transfer_id, TransferState::Accepted);
            if let Some(record) = state.transfers.borrow_mut().get_mut(&transfer_id) {
                record.total = bytes;
            }
        }
        TransferEvent::Progress(progress) => {
            if let Some(record) = state.transfers.borrow_mut().get_mut(&progress.transfer_id) {
                record.state = TransferState::Transferring;
                record.done = progress.bytes_done;
                record.total = progress.bytes_total;
            }
            state.emit(Event::Progress {
                transfer: hex(progress.transfer_id),
                way: way(progress.direction),
                done: progress.bytes_done,
                total: progress.bytes_total,
                bytes_per_second: progress.bytes_per_second,
            });
        }
        TransferEvent::Completed { transfer_id } => {
            state.set_state(&transfer_id, TransferState::Received);
            state.emit(Event::Completed {
                transfer: hex(transfer_id),
            });
        }
        TransferEvent::DeliveryConfirmed { transfer_id, .. } => {
            state.set_state(&transfer_id, TransferState::Delivered);
            state.emit(Event::Delivered {
                transfer: hex(transfer_id),
            });
        }
        TransferEvent::DeliveryUnconfirmed { transfer_id, .. } => {
            end(
                state,
                &transfer_id,
                TransferState::Unconfirmed,
                "no signed receipt arrived",
            );
        }
        TransferEvent::Rejected { transfer_id, .. } => {
            end(
                state,
                &transfer_id,
                TransferState::Rejected,
                "the receiver declined",
            );
        }
        TransferEvent::Cancelled { transfer_id, .. } => {
            end(
                state,
                &transfer_id,
                TransferState::Cancelled,
                "the transfer was cancelled",
            );
        }
        TransferEvent::Failed {
            transfer_id,
            failure,
            ..
        } => {
            end(
                state,
                &transfer_id,
                TransferState::Failed,
                &failure.code.to_string(),
            );
        }
        TransferEvent::Interrupted { transfer_id, .. } => {
            state.set_state(&transfer_id, TransferState::Interrupted);
            state.emit(Event::Ended {
                transfer: hex(transfer_id),
                reason: TransferState::Interrupted,
                message: "the connection ended; the transfer can resume".to_owned(),
            });
        }
        _ => {}
    }
}
