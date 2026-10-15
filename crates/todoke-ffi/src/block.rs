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
}
