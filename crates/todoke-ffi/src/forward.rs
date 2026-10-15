//! The event thread: the core's events, converted, to every stream the app
//! subscribed and to its notifier.

use std::collections::BTreeSet;
use std::sync::{Arc, Mutex};

use boltffi::StreamProducer;
use todoke_core::api::Event;
use tokio::sync::broadcast::{Receiver, error::RecvError};

use crate::hooks::{Notifier, OfferNotice};
use crate::types::{CoreEvent, TransferState};

/// Starts the thread; it ends when the core stops (its event channel
/// closes).
pub(crate) fn spawn(
    mut events: Receiver<Event>,
    streams: Arc<StreamProducer<CoreEvent>>,
    notifier: Arc<Mutex<Option<Arc<dyn Notifier>>>>,
) -> std::io::Result<()> {
    std::thread::Builder::new()
        .name("todoke-ffi-events".into())
        .spawn(move || {
            let mut shown = BTreeSet::new();
            loop {
                let event = match events.blocking_recv() {
                    Ok(event) => CoreEvent::from(event),
                    Err(RecvError::Lagged(missed)) => CoreEvent::Missed { events: missed },
                    Err(RecvError::Closed) => return,
                };
                let current = notifier.lock().ok().and_then(|slot| slot.clone());
                if let Some(current) = current {
                    notify(&*current, &event, &mut shown);
                }
                streams.push(event);
            }
        })?;
    Ok(())
}

/// Tells `notifier` about `event`; `shown` holds the offers it was told
/// about, whose notifications go when they do.
pub(crate) fn notify(notifier: &dyn Notifier, event: &CoreEvent, shown: &mut BTreeSet<String>) {
    let ended = match event {
        CoreEvent::OfferReceived { offer } => {
            shown.insert(offer.transfer.clone());
            notifier.offer_received(OfferNotice::from(offer));
            return;
        }
        CoreEvent::Progress { transfer, .. } => {
            if shown.remove(transfer) {
                notifier.offer_gone(transfer.clone());
            }
            return;
        }
        CoreEvent::Completed { transfer } => (transfer, "Files received".to_owned()),
        CoreEvent::Delivered { transfer } => (
            transfer,
            "Files delivered; the receipt is verified".to_owned(),
        ),
        CoreEvent::Ended {
            transfer, reason, ..
        } => (transfer, ending(*reason).to_owned()),
        CoreEvent::Paired { .. } | CoreEvent::Missed { .. } => return,
    };
    let (transfer, text) = ended;
    if shown.remove(transfer) {
        notifier.offer_gone(transfer.clone());
    }
    notifier.transfer_finished(transfer.clone(), text);
}

fn ending(reason: TransferState) -> &'static str {
    match reason {
        TransferState::Rejected => "The transfer was declined",
        TransferState::Cancelled => "The transfer was cancelled",
        TransferState::Interrupted => "The transfer paused; it resumes when you reconnect",
        TransferState::Unconfirmed => "Sent; delivery is unconfirmed",
        _ => "The transfer failed",
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;

    use super::*;
    use crate::types::{Entry, Offer};

    /// What the notifier was told, in order.
    #[derive(Default)]
    struct Recorder(Mutex<Vec<String>>);

    impl Notifier for Recorder {
        fn offer_received(&self, notice: OfferNotice) {
            if let Ok(mut log) = self.0.lock() {
                log.push(format!(
                    "offer {} {} files {} folders",
                    notice.transfer, notice.files, notice.folders
                ));
            }
        }
        fn offer_gone(&self, transfer: String) {
            if let Ok(mut log) = self.0.lock() {
                log.push(format!("gone {transfer}"));
            }
        }
        fn transfer_finished(&self, transfer: String, text: String) {
            if let Ok(mut log) = self.0.lock() {
                log.push(format!("finished {transfer}: {text}"));
            }
        }
    }

    fn offer(transfer: &str) -> Offer {
        let entry = |id, directory, name: &str| Entry {
            id,
            parent: 0,
            directory,
            name: name.to_owned(),
            mime: String::new(),
            size: 1,
        };
        Offer {
            transfer: transfer.to_owned(),
            from: "ab".repeat(32),
            from_name: "Device ABAB ABAB".to_owned(),
            entries: vec![entry(1, false, "secret-plan.pdf"), entry(2, true, "photos")],
            total_bytes: 2,
            resume: Vec::new(),
        }
    }

    /// An offer notifies without names, goes when its transfer moves or
    /// ends, and an ending notifies once.
    #[test]
    fn notifications_follow_offers_without_names() {
        let recorder = Recorder::default();
        let mut shown = BTreeSet::new();
        for event in [
            CoreEvent::OfferReceived { offer: offer("t1") },
            CoreEvent::Progress {
                transfer: "t1".into(),
                way: crate::types::Way::Incoming,
                done: 1,
                total: 2,
                bytes_per_second: 1,
            },
            CoreEvent::Completed {
                transfer: "t1".into(),
            },
            CoreEvent::OfferReceived { offer: offer("t2") },
            CoreEvent::Ended {
                transfer: "t2".into(),
                reason: TransferState::Rejected,
                message: "no".into(),
            },
        ] {
            notify(&recorder, &event, &mut shown);
        }
        let log = recorder.0.lock().map(|log| log.clone()).unwrap_or_default();
        assert_eq!(
            log,
            [
                "offer t1 1 files 1 folders",
                "gone t1",
                "finished t1: Files received",
                "offer t2 1 files 1 folders",
                "gone t2",
                "finished t2: The transfer was declined",
            ]
        );
        assert!(log.iter().all(|line| !line.contains("secret")));
        assert!(shown.is_empty());
    }
}
