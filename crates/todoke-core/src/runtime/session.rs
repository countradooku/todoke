//! One contact session: a transfer engine driven over it, local decisions
//! applied, events reported, and on its end the unfinished offers kept for
//! the next session (§7.5: resumption needs a fresh session and Accept).

use core::time::Duration;
use std::rc::Rc;

use todoke_crypto::identity::Ed25519PublicKey;
use todoke_proto::transfer::{CancelReason, RejectReason, TransferId};
use todoke_transfer::{
    Clock, Direction, EngineConfig, OutgoingOffer, TransferEngine, TransferEvent, pump,
};
use todoke_transport::{Established, Link};
use tokio::sync::{mpsc, oneshot};

use super::running::{PeerQueue, State, TransferRecord, wall};
use crate::api::{EntryInfo, ErrorCode, Event, OfferInfo, Response, TransferState, Way, hex};

/// How long the session waits for a frame before looking at commands.
const POLL: Duration = Duration::from_millis(100);
/// A session with nothing to do closes after this long.
const IDLE: Duration = Duration::from_secs(30);
/// How long a joiner leaving for a direct link waits for the host to close
/// the session (§10.2).
const DRAIN: Duration = Duration::from_secs(5);

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

pub(super) type Engine<'k> =
    TransferEngine<'k, crate::profile::Keys, todoke_fs::FsSource, super::running::Sink>;

/// Runs `established` until it ends.
pub(super) async fn run<L: Link>(state: Rc<State>, mut established: Established<L>) {
    let peer = *established.peer();
    let Ok(queue) = state.take_queue(&peer) else {
        return;
    };
    let queue_offers = queue.offers;
    let mut prepared = queue.prepared;
    let queue_source = queue.source;
    let (commands, mut inbox) = mpsc::channel(32);
    state.sessions.borrow_mut().insert(peer, commands);
    let kind = established.link().kind();
    let route = match kind {
        todoke_transport::LinkKind::Relay => crate::api::Route::Relay,
        todoke_transport::LinkKind::Direct => crate::api::Route::Direct,
        todoke_transport::LinkKind::Lan => crate::api::Route::Lan,
    };
    let mut link = super::link::SessionLink::new(&state, peer, kind);
    let mut departing = None;
    state.routes.borrow_mut().insert(peer, route);
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
        state.routes.borrow_mut().remove(&peer);
        return;
    };
    let mut waiting = queue_offers;
    let mut ready = false;
    let mut idle_since = mono;
    loop {
        let session = established.session();
        let until = session.now() + POLL;
        let pumped = pump(session, &mut engine, until).await;
        // Moving onto a direct link: the answer went out with this pump.
        if departing.is_some() {
            engine.close(None);
            if matches!(departing, Some(super::link::Move::Join { .. })) {
                drain(established.session()).await;
            }
            break;
        }
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
                link.ready(&mut engine);
            }
            idle_since = now;
            if let Some(event) = link.event(&mut engine, event, now)
                && !accept_retained(&state, peer, &mut engine, &event, now)
            {
                report(&state, peer, event);
            }
        }
        while let Ok(command) = inbox.try_recv() {
            apply(&state, &mut engine, &mut prepared, ready, command, now);
            idle_since = now;
        }
        if pumped.is_err() {
            // The answer may have come with the session's end (the peer
            // closed it as it left): the move still stands.
            departing = link.take_leaving();
            break;
        }
        departing = link.step(&mut engine, now).await;
        let busy = busy(&state, &peer);
        if !busy
            && waiting.is_empty()
            && prepared.is_empty()
            && now.saturating_sub(idle_since) >= IDLE
        {
            engine.close(None);
            break;
        }
    }
    finish(&state, peer, engine, &mut inbox, prepared, waiting);
    drop(established);
    if let Some(to) = departing {
        tokio::task::spawn_local(Rc::clone(&state).move_to(peer, to));
    }
}

/// The joiner, after its answer: reads and drops what the host still sends
/// until the host closes the session (or a few seconds pass). Closing at
/// once with records unread would reset the connection, and a reset can
/// discard the answer before the host reads it.
async fn drain<L: Link>(
    session: &mut todoke_crypto::session::Session<L, todoke_transport::TokioTimer>,
) {
    let until = session.now() + DRAIN;
    while session.now() < until {
        if session.recv_until(until).await.is_err() {
            break;
        }
    }
}

/// Whether a transfer with `peer` is still being offered, decided, or
/// moved (the session does not idle out then).
fn busy(state: &State, peer: &Ed25519PublicKey) -> bool {
    state.transfers.borrow().values().any(|record| {
        record.peer == *peer
            && matches!(
                record.state,
                TransferState::Offered
                    | TransferState::AwaitingDecision
                    | TransferState::Accepted
                    | TransferState::Transferring
            )
    })
}

/// A transfer resumed after a move onto a direct link (§10.2): its user's
/// consent was kept, for the same selection, and the fresh Accept repeats
/// it without asking again (§7.3). Returns whether it was.
fn accept_retained(
    state: &State,
    peer: Ed25519PublicKey,
    engine: &mut Engine<'_>,
    event: &TransferEvent,
    now: Duration,
) -> bool {
    let TransferEvent::OfferReceived(view) = event else {
        return false;
    };
    let Some(selection) = state.take_retained(&view.transfer_id, &peer, &view.manifest_hash) else {
        return false;
    };
    if view
        .resume_selection
        .as_ref()
        .is_some_and(|resumed| *resumed != selection)
    {
        return false;
    }
    offer_received(state, peer, view, true);
    if engine
        .accept(&view.transfer_id, selection.clone(), now)
        .is_err()
    {
        // Listed and asked after all.
        offer_received(state, peer, view, false);
        return true;
    }
    if let Some(record) = state.transfers.borrow_mut().get_mut(&view.transfer_id) {
        record.selection = Some(selection);
    }
    true
}

/// Puts whatever was not finished back in `peer`'s queue for the next
/// session, offers sent to this session after it stopped reading
/// included. Nothing here awaits, so the queue is back in place before
/// anyone looks for it.
fn finish(
    state: &State,
    peer: Ed25519PublicKey,
    mut engine: Engine<'_>,
    inbox: &mut mpsc::Receiver<SessionCommand>,
    mut prepared: Vec<crate::send::Prepared>,
    waiting: Vec<OutgoingOffer>,
) {
    inbox.close();
    while let Ok(command) = inbox.try_recv() {
        match command {
            SessionCommand::Offer(mut new) => {
                new.install(engine.source_mut());
                prepared.push(*new);
            }
            SessionCommand::Reply(_, reply) => {
                let _ = reply.send(Response::error(ErrorCode::Unreachable, "the session ended"));
            }
            _ => {}
        }
    }
    while let Some(event) = engine.pop_event() {
        report(state, peer, event);
    }
    state.interrupt(&peer);
    let mut offers = engine.take_resumable();
    offers.extend(waiting);
    let (source, _) = engine.into_parts();
    state.sessions.borrow_mut().remove(&peer);
    state.routes.borrow_mut().remove(&peer);
    state.queues.borrow_mut().insert(
        peer,
        PeerQueue {
            source,
            prepared,
            offers,
        },
    );
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
            "the receiver's limits do not allow this transfer",
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
        SessionCommand::Offer(mut prepared) => {
            // This engine's source serves its files from now on.
            prepared.install(engine.source_mut());
            if ready {
                offer_new(state, engine, &prepared, now);
            } else {
                waiting.push(*prepared);
            }
            Ok(())
        }
        SessionCommand::Accept(id, files) => {
            let selection = files.unwrap_or_else(|| selectable(state, &id));
            let accepted = engine.accept(&id, selection.clone(), now);
            if accepted.is_ok()
                && let Some(record) = state.transfers.borrow_mut().get_mut(&id)
            {
                record.selection = Some(selection);
            }
            accepted
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

/// What "accept" without a selection accepts: the earlier selection of a
/// resumed transfer (which must be repeated exactly, §7.5), otherwise
/// every file.
fn selectable(state: &State, id: &TransferId) -> Vec<u32> {
    state
        .received
        .borrow()
        .get(id)
        .map_or_else(Vec::new, |offer| {
            offer.resume.clone().unwrap_or_else(|| {
                offer
                    .entries
                    .iter()
                    .filter(|entry| !entry.directory)
                    .map(|entry| entry.id)
                    .collect()
            })
        })
}

/// Ends `id` for good with `reason`, telling the user.
pub(super) fn end(state: &State, id: &TransferId, reason: TransferState, message: &str) {
    // The detail first: the history entry `set_state` writes keeps it.
    if let Some(record) = state.transfers.borrow_mut().get_mut(id) {
        record.detail = Some(message.to_owned());
    }
    state.set_state(id, reason);
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

/// Records an offer; unless `quiet` (a resumed offer whose consent was
/// kept, accepted at once), lists it and tells the user.
fn offer_received(
    state: &State,
    peer: Ed25519PublicKey,
    view: &todoke_transfer::OfferView,
    quiet: bool,
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
            files: view.file_count,
            names: view
                .entries
                .iter()
                .filter(|entry| entry.parent == 0)
                .take(crate::api::HISTORY_NAMES)
                .map(|entry| entry.name.clone())
                .collect(),
            manifest_hash: Some(view.manifest_hash),
            receipt: None,
            selection: None,
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
                mime: entry.mime.clone(),
                size: entry.size,
            })
            .collect(),
        total_bytes: view.total_bytes,
        resume: view.resume_selection.clone(),
    };
    if quiet {
        return;
    }
    state
        .received
        .borrow_mut()
        .insert(view.transfer_id, offer.clone());
    state.emit(Event::OfferReceived(offer));
}

/// Keeps the signed receipt of a transfer for its history entry.
fn keep_receipt(
    state: &State,
    id: &TransferId,
    receipt_id: [u8; 16],
    completed_at: todoke_proto::time::UnixTime,
) {
    if let Some(record) = state.transfers.borrow_mut().get_mut(id) {
        record.receipt = Some((receipt_id, completed_at));
    }
}

/// Why a receiver rejected, for people.
const fn rejection(reason: RejectReason) -> &'static str {
    match reason {
        RejectReason::Declined => "declined",
        RejectReason::Quota => "the receiver's storage quota would be exceeded",
        RejectReason::UnsupportedDestination => {
            "the receiver's destination cannot hold these files"
        }
        RejectReason::Expired => "no decision was made in time",
    }
}

/// Mirrors an engine event into the core's records and events.
fn report(state: &State, peer: Ed25519PublicKey, event: TransferEvent) {
    match event {
        TransferEvent::OfferReceived(view) => offer_received(state, peer, &view, false),
        TransferEvent::OfferSent {
            transfer_id,
            manifest_hash,
        } => {
            if let Some(record) = state.transfers.borrow_mut().get_mut(&transfer_id) {
                record.manifest_hash = Some(manifest_hash);
            }
        }
        TransferEvent::Accepted {
            transfer_id,
            files,
            bytes,
            ..
        } => {
            state.set_state(&transfer_id, TransferState::Accepted);
            if let Some(record) = state.transfers.borrow_mut().get_mut(&transfer_id) {
                record.total = bytes;
                record.files = files;
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
        other => report_end(state, &other),
    }
}

/// Mirrors an engine event that ends (or interrupts) a transfer.
fn report_end(state: &State, event: &TransferEvent) {
    match event {
        TransferEvent::Completed {
            transfer_id,
            completed_at,
            receipt_id,
        } => {
            keep_receipt(state, transfer_id, *receipt_id, *completed_at);
            state.set_state(transfer_id, TransferState::Received);
            state.emit(Event::Completed {
                transfer: hex(transfer_id),
            });
        }
        TransferEvent::DeliveryConfirmed {
            transfer_id,
            completed_at,
            receipt_id,
        } => {
            keep_receipt(state, transfer_id, *receipt_id, *completed_at);
            state.set_state(transfer_id, TransferState::Delivered);
            state.emit(Event::Delivered {
                transfer: hex(transfer_id),
            });
        }
        TransferEvent::DeliveryUnconfirmed { transfer_id, .. } => {
            end(
                state,
                transfer_id,
                TransferState::Unconfirmed,
                "no signed receipt arrived",
            );
        }
        TransferEvent::Rejected {
            transfer_id,
            reason,
            ..
        } => {
            let why = rejection(*reason);
            end(state, transfer_id, TransferState::Rejected, why);
        }
        TransferEvent::Expired { transfer_id, .. } => {
            state.set_state(transfer_id, TransferState::Interrupted);
            state.emit(Event::Ended {
                transfer: hex(transfer_id),
                reason: TransferState::Interrupted,
                message: "the permission expired; the transfer can resume with a new accept"
                    .to_owned(),
            });
        }
        TransferEvent::Cancelled { transfer_id, .. } => {
            end(
                state,
                transfer_id,
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
                transfer_id,
                TransferState::Failed,
                &failure.code.to_string(),
            );
        }
        TransferEvent::Interrupted { transfer_id, .. } => {
            state.set_state(transfer_id, TransferState::Interrupted);
            state.emit(Event::Ended {
                transfer: hex(transfer_id),
                reason: TransferState::Interrupted,
                message: "the connection ended; the transfer can resume".to_owned(),
            });
        }
        _ => {}
    }
}
