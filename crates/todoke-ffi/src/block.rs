//! Waiting for the core's answer on the caller's thread: the core's
//! request and reply are channel futures that need no runtime, only a
//! waker that unparks this thread.

use core::future::Future;
use core::pin::pin;
use core::task::{Context, Poll, Waker};
use std::sync::Arc;
use std::task::Wake;
use std::thread::Thread;

struct Unpark(Thread);

impl Wake for Unpark {
    fn wake(self: Arc<Self>) {
        self.0.unpark();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.unpark();
    }
}

/// Runs `future` to completion on this thread.
pub(crate) fn block_on<T>(future: impl Future<Output = T>) -> T {
    let mut future = pin!(future);
    let waker = Waker::from(Arc::new(Unpark(std::thread::current())));
    let mut context = Context::from_waker(&waker);
    loop {
        if let Poll::Ready(value) = future.as_mut().poll(&mut context) {
            return value;
        }
        std::thread::park();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_future_woken_from_another_thread_completes() {
        let (sender, receiver) = std::sync::mpsc::channel::<()>();
        let (reply, answer) = tokio::sync::oneshot::channel();
        std::thread::spawn(move || {
            let _ = receiver.recv();
            let _ = reply.send(7);
        });
        let _ = sender.send(());
        assert_eq!(block_on(answer).ok(), Some(7));
    }

    /// A future that is ready at once is never parked on.
    #[test]
    fn a_ready_future_returns_at_once() {
        assert_eq!(block_on(core::future::ready(5)), 5);
    }

    /// A future that wakes itself each time it is pending (as a busy
    /// channel does) is polled again until it is ready.
    #[test]
    fn a_future_woken_many_times_completes() {
        let mut polls = 0;
        let value = block_on(core::future::poll_fn(|context| {
            polls += 1;
            if polls <= 50 {
                context.waker().wake_by_ref();
                Poll::Pending
            } else {
                Poll::Ready(polls)
            }
        }));
        assert_eq!(value, 51);
    }

    /// Wakes from another thread before the future is ready (spurious for
    /// it) only make it poll again.
    #[test]
    fn spurious_wakes_from_another_thread_are_harmless() {
        use core::sync::atomic::{AtomicBool, Ordering};
        use std::sync::Mutex;

        let ready = Arc::new(AtomicBool::new(false));
        let slot: Arc<Mutex<Option<Waker>>> = Arc::default();
        let (flag, registered) = (Arc::clone(&ready), Arc::clone(&slot));
        let waking = std::thread::spawn(move || {
            let waker = loop {
                if let Some(waker) = registered.lock().ok().and_then(|slot| slot.clone()) {
                    break waker;
                }
                std::thread::yield_now();
            };
            for _ in 0..20 {
                waker.wake_by_ref();
            }
            flag.store(true, Ordering::Release);
            waker.wake();
        });
        let value = block_on(core::future::poll_fn(|context| {
            if let Ok(mut slot) = slot.lock() {
                *slot = Some(context.waker().clone());
            }
            if ready.load(Ordering::Acquire) {
                Poll::Ready(true)
            } else {
                Poll::Pending
            }
        }));
        assert!(value);
        assert!(waking.join().is_ok());
    }
}
