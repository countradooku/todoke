//! The core's events for the app: one queue per subscription, owned here.
//!
//! A slow subscriber loses the oldest events, and the next read reports how
//! many first ([`CoreEvent::Missed`]); the app then reads the offers and
//! transfers again. When the core stops, reads drain what is queued, then
//! fail with [`TodokeError::State`]. Reading blocks for at most the timeout
//! given: call it off the UI thread.

#![allow(
    clippy::needless_pass_by_value,
    clippy::must_use_candidate,
    reason = "exported to foreign callers: arguments arrive owned, and must_use means nothing there"
)]

use std::collections::VecDeque;
use std::sync::{Arc, Condvar, Mutex, Weak};
use std::time::{Duration, Instant};

use boltffi::export;

use crate::error::TodokeError;
use crate::types::CoreEvent;

/// Events queued per subscription before the oldest go.
pub(crate) const QUEUE: usize = 4096;
/// Subscriptions at once.
pub(crate) const MAX_SUBSCRIPTIONS: usize = 16;
/// The longest a read waits.
const MAX_WAIT: Duration = Duration::from_secs(60);
/// The most events one read returns.
const MAX_BATCH: usize = 1024;

#[derive(Default)]
struct State {
    events: VecDeque<CoreEvent>,
    /// Events dropped since the last read.
    missed: u64,
    stopped: bool,
    closed: bool,
}

/// One subscription's queue.
#[derive(Default)]
pub(crate) struct Queue {
    state: Mutex<State>,
    ready: Condvar,
}

impl Queue {
    /// Adds `event`, dropping the oldest when full.
    pub(crate) fn push(&self, event: CoreEvent) {
        if let Ok(mut state) = self.state.lock() {
            if state.closed {
                return;
            }
            if state.events.len() >= QUEUE {
                state.events.pop_front();
                state.missed += 1;
            }
            state.events.push_back(event);
            self.ready.notify_all();
        }
    }

    /// The core lost `count` events before they reached this queue.
    pub(crate) fn lost(&self, count: u64) {
        if let Ok(mut state) = self.state.lock() {
            state.missed = state.missed.saturating_add(count);
            self.ready.notify_all();
        }
    }

    /// The core stopped: no more events.
    pub(crate) fn stop(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.stopped = true;
            self.ready.notify_all();
        }
    }

    fn closed(&self) -> bool {
        self.state.lock().map_or(true, |state| state.closed)
    }

    fn close(&self) {
        if let Ok(mut state) = self.state.lock() {
            state.closed = true;
            state.events.clear();
            self.ready.notify_all();
        }
    }

    fn next(&self, max: usize, timeout: Duration) -> Result<Vec<CoreEvent>, TodokeError> {
        let deadline = Instant::now() + timeout.min(MAX_WAIT);
        let mut state = self.state.lock().map_err(|_| TodokeError::unexpected())?;
        loop {
            if state.closed {
                return Err(TodokeError::State {
                    message: "the subscription is closed".to_owned(),
                });
            }
            if state.missed > 0 || !state.events.is_empty() {
                let mut batch = Vec::new();
                if state.missed > 0 {
                    batch.push(CoreEvent::Missed {
                        events: core::mem::take(&mut state.missed),
                    });
                }
                let take = max.clamp(1, MAX_BATCH).saturating_sub(batch.len()).max(1);
                let take = take.min(state.events.len());
                batch.extend(state.events.drain(..take));
                return Ok(batch);
            }
            if state.stopped {
                return Err(TodokeError::State {
                    message: "the core stopped".to_owned(),
                });
            }
            let now = Instant::now();
            if now >= deadline {
                return Ok(Vec::new());
            }
            state = self
                .ready
                .wait_timeout(state, deadline - now)
                .map_err(|_| TodokeError::unexpected())?
                .0;
        }
    }
}

/// The live subscriptions, as the event thread sees them.
#[derive(Default)]
pub(crate) struct Subscribers(Mutex<Vec<Weak<Queue>>>);

impl Subscribers {
    /// A new subscription.
    pub(crate) fn subscribe(&self) -> Result<Arc<Queue>, TodokeError> {
        let mut queues = self.0.lock().map_err(|_| TodokeError::unexpected())?;
        // A closed subscription gives its place up at once.
        queues.retain(|queue| queue.upgrade().is_some_and(|queue| !queue.closed()));
        if queues.len() >= MAX_SUBSCRIPTIONS {
            return Err(TodokeError::State {
                message: format!("at most {MAX_SUBSCRIPTIONS} event subscriptions at once"),
            });
        }
        let queue = Arc::new(Queue::default());
        queues.push(Arc::downgrade(&queue));
        Ok(queue)
    }

    /// Runs `deliver` on every live subscription.
    pub(crate) fn each(&self, deliver: impl Fn(&Queue)) {
        if let Ok(mut queues) = self.0.lock() {
            queues.retain(|queue| match queue.upgrade() {
                Some(queue) => {
                    deliver(&queue);
                    true
                }
                None => false,
            });
        }
    }
}

/// A subscription to the core's events (from `Core::subscribe`). Read it
/// on a thread of the app's (a loop, or the platform's async wrapper).
pub struct Events {
    pub(crate) queue: Arc<Queue>,
}

#[export]
impl Events {
    /// The next events, at most `max`: waits up to `timeout_ms` for one
    /// (empty after that). A [`CoreEvent::Missed`] first says events were
    /// lost: read the offers and transfers again.
    ///
    /// # Errors
    ///
    /// [`TodokeError::State`] once the core stopped (after what is queued)
    /// or the subscription was closed.
    pub fn next(&self, max: u32, timeout_ms: u32) -> Result<Vec<CoreEvent>, TodokeError> {
        self.queue.next(
            usize::try_from(max).unwrap_or(MAX_BATCH),
            Duration::from_millis(u64::from(timeout_ms)),
        )
    }

    /// Ends the subscription: a read waiting returns at once, and later
    /// reads fail. (Not `close`: Kotlin's `close()` frees the object.)
    pub fn stop(&self) {
        self.queue.close();
    }
}

impl Drop for Events {
    fn drop(&mut self) {
        self.queue.close();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn completed(n: u64) -> CoreEvent {
        CoreEvent::Completed {
            transfer: n.to_string(),
        }
    }

    #[test]
    fn a_slow_reader_loses_the_oldest_and_is_told() -> Result<(), TodokeError> {
        let queue = Queue::default();
        for n in 0..(QUEUE as u64 + 3) {
            queue.push(completed(n));
        }
        let first = queue.next(10, Duration::ZERO)?;
        assert_eq!(first[0], CoreEvent::Missed { events: 3 });
        assert_eq!(first[1], completed(3));
        assert_eq!(first.len(), 10);
        Ok(())
    }

    #[test]
    fn a_stopped_core_drains_then_fails() -> Result<(), TodokeError> {
        let queue = Queue::default();
        queue.push(completed(1));
        queue.stop();
        assert_eq!(queue.next(10, Duration::ZERO)?, [completed(1)]);
        assert!(matches!(
            queue.next(10, Duration::ZERO),
            Err(TodokeError::State { .. })
        ));
        Ok(())
    }

    #[test]
    fn a_read_waits_and_is_woken() -> Result<(), TodokeError> {
        let queue = Arc::new(Queue::default());
        let writer = Arc::clone(&queue);
        std::thread::spawn(move || {
            std::thread::sleep(Duration::from_millis(50));
            writer.push(completed(9));
        });
        assert_eq!(queue.next(10, Duration::from_secs(10))?, [completed(9)]);
        assert_eq!(queue.next(10, Duration::from_millis(10))?, []);
        queue.close();
        assert!(queue.next(10, Duration::ZERO).is_err());
        Ok(())
    }

    #[test]
    fn subscriptions_are_capped_and_freed() -> Result<(), TodokeError> {
        let subscribers = Subscribers::default();
        let held: Vec<_> = (0..MAX_SUBSCRIPTIONS)
            .map(|_| subscribers.subscribe())
            .collect::<Result<_, _>>()?;
        assert!(subscribers.subscribe().is_err());
        drop(held);
        assert!(subscribers.subscribe().is_ok());
        Ok(())
    }
}
