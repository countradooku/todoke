//! A simulated network for tests: links with latency, bandwidth, and loss,
//! and a connector whose candidates answer slowly, fail, or never answer.
//!
//! Time is tokio's, so tests run with the clock paused
//! (`#[tokio::test(start_paused = true)]`) and are deterministic. Links are
//! ordered and reliable, like TCP: a lost segment is modelled as the
//! retransmission delay it causes, which holds back everything after it.

use core::future::Future;
use core::pin::Pin;
use core::task::{Context, Poll, Waker};
use core::time::Duration;
use std::collections::{BTreeMap, VecDeque};
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use futures_io::{AsyncRead, AsyncWrite};
use tokio::time::{Instant, Sleep};

use crate::link::{Link, LinkInfo, LinkKind};
use crate::race::{Candidate, Connector};

/// A path's behaviour.
#[derive(Clone, Copy, Debug, PartialEq)]
pub(crate) struct Path {
    /// One-way delay.
    pub(crate) latency: Duration,
    /// Bytes per second; `None` for unlimited.
    pub(crate) bandwidth: Option<u64>,
    /// Probability that a write is "lost" and delivered one
    /// retransmission timeout late.
    pub(crate) loss: f64,
    /// The retransmission delay of a lost write.
    pub(crate) retransmit: Duration,
}

impl Path {
    pub(crate) const fn new(latency: Duration) -> Self {
        Self {
            latency,
            bandwidth: None,
            loss: 0.0,
            retransmit: Duration::from_millis(200),
        }
    }

    pub(crate) const fn with_bandwidth(mut self, bytes_per_second: u64) -> Self {
        self.bandwidth = Some(bytes_per_second);
        self
    }

    pub(crate) const fn with_loss(mut self, loss: f64) -> Self {
        self.loss = loss;
        self
    }
}

/// A small deterministic generator (xorshift64*); test scheduling only.
#[derive(Debug)]
struct Rng(u64);

impl Rng {
    fn chance(&mut self, probability: f64) -> bool {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        let value = self.0.wrapping_mul(0x2545_f491_4f6c_dd1d) >> 11;
        #[expect(clippy::cast_precision_loss, reason = "53-bit value into an f64")]
        let unit = value as f64 / (1_u64 << 53) as f64;
        unit < probability
    }
}

#[derive(Debug)]
struct Direction {
    queue: VecDeque<(Instant, Vec<u8>)>,
    queued: usize,
    /// When the last queued byte arrives; later writes arrive after it.
    last: Instant,
    reader: Option<Waker>,
    writer: Option<Waker>,
    closed: bool,
    rng: Rng,
    /// Every byte ever written in this direction.
    carried: u64,
}

impl Direction {
    fn new(seed: u64) -> Self {
        Self {
            queue: VecDeque::new(),
            queued: 0,
            last: Instant::now(),
            reader: None,
            writer: None,
            closed: false,
            rng: Rng(seed | 1),
            carried: 0,
        }
    }
}

/// Bytes a direction holds before writes wait (the "send buffer").
const WINDOW: usize = 1 << 20;

type Shared = Arc<Mutex<Direction>>;

fn lock(shared: &Shared) -> io::Result<std::sync::MutexGuard<'_, Direction>> {
    shared.lock().map_err(|_| io::Error::other("poisoned"))
}

/// One end of a simulated link.
pub(crate) struct SimLink {
    incoming: Shared,
    outgoing: Shared,
    path: Path,
    info: LinkInfo,
    sleep: Option<Pin<Box<Sleep>>>,
}

impl core::fmt::Debug for SimLink {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("SimLink")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

/// Two connected ends over `path` (the same in both directions).
pub(crate) fn link(path: Path, a: SocketAddr, b: SocketAddr, seed: u64) -> (SimLink, SimLink) {
    let ab: Shared = Arc::new(Mutex::new(Direction::new(seed)));
    let ba: Shared = Arc::new(Mutex::new(Direction::new(seed.rotate_left(17))));
    let rtt = path.latency.saturating_mul(2);
    let mut info_a = LinkInfo::new(LinkKind::Simulated)
        .with_addresses(a, b)
        .with_latency(rtt);
    let mut info_b = LinkInfo::new(LinkKind::Simulated)
        .with_addresses(b, a)
        .with_latency(rtt);
    if let Some(bandwidth) = path.bandwidth {
        info_a = info_a.with_bandwidth(bandwidth);
        info_b = info_b.with_bandwidth(bandwidth);
    }
    (
        SimLink {
            incoming: Arc::clone(&ba),
            outgoing: Arc::clone(&ab),
            path,
            info: info_a,
            sleep: None,
        },
        SimLink {
            incoming: ab,
            outgoing: ba,
            path,
            info: info_b,
            sleep: None,
        },
    )
}

impl Link for SimLink {
    fn info(&self) -> &LinkInfo {
        &self.info
    }
}

impl AsyncRead for SimLink {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut [u8],
    ) -> Poll<io::Result<usize>> {
        let now = Instant::now();
        let wait = {
            let mut direction = lock(&self.incoming)?;
            let closed = direction.closed;
            match direction.queue.front_mut() {
                Some((at, bytes)) if *at <= now => {
                    let count = buf.len().min(bytes.len());
                    buf[..count].copy_from_slice(&bytes[..count]);
                    bytes.drain(..count);
                    if bytes.is_empty() {
                        direction.queue.pop_front();
                    }
                    direction.queued = direction.queued.saturating_sub(count);
                    if let Some(writer) = direction.writer.take() {
                        writer.wake();
                    }
                    return Poll::Ready(Ok(count));
                }
                Some((at, _)) => Some(*at),
                None if closed => return Poll::Ready(Ok(0)),
                None => {
                    direction.reader = Some(cx.waker().clone());
                    None
                }
            }
        };
        if let Some(at) = wait {
            let sleep = self
                .sleep
                .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(at)));
            sleep.as_mut().reset(at);
            if sleep.as_mut().poll(cx).is_ready() {
                cx.waker().wake_by_ref();
            }
        }
        Poll::Pending
    }
}

impl AsyncWrite for SimLink {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let path = self.path;
        let mut direction = lock(&self.outgoing)?;
        if direction.closed {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        let room = WINDOW.saturating_sub(direction.queued);
        if room == 0 {
            direction.writer = Some(cx.waker().clone());
            return Poll::Pending;
        }
        let count = room.min(buf.len());
        let now = Instant::now();
        let serialization = path.bandwidth.map_or(Duration::ZERO, |rate| {
            let bytes = u64::try_from(count).unwrap_or(u64::MAX);
            Duration::from_nanos(bytes.saturating_mul(1_000_000_000) / rate.max(1))
        });
        // Bandwidth: this write leaves after the previous one has.
        let departs = direction.last.max(now) + serialization;
        let mut arrives = departs + path.latency;
        if path.loss > 0.0 && direction.rng.chance(path.loss) {
            arrives += path.retransmit;
        }
        // In order: nothing overtakes an earlier write.
        let arrives = arrives.max(direction.last);
        direction.last = departs.max(direction.last);
        direction.queue.push_back((arrives, buf[..count].to_vec()));
        direction.queued += count;
        direction.carried += count as u64;
        if let Some(reader) = direction.reader.take() {
            reader.wake();
        }
        Poll::Ready(Ok(count))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_close(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Ok(mut direction) = lock(&self.outgoing) {
            direction.closed = true;
            if let Some(reader) = direction.reader.take() {
                reader.wake();
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for SimLink {
    fn drop(&mut self) {
        for shared in [&self.incoming, &self.outgoing] {
            if let Ok(mut direction) = lock(shared) {
                direction.closed = true;
                for waker in [direction.reader.take(), direction.writer.take()]
                    .into_iter()
                    .flatten()
                {
                    waker.wake();
                }
            }
        }
    }
}

/// How a simulated candidate answers a connection attempt.
#[derive(Clone, Copy, Debug)]
pub(crate) enum Answer {
    /// Connects after `setup` (one round trip), over `path`.
    Connect { setup: Duration, path: Path },
    /// Fails after `after`.
    Refuse { after: Duration },
    /// Never answers.
    Silent,
}

/// A connector over simulated candidates. The far end of each link it opens
/// is handed to the test through [`Self::accepted`].
#[derive(Clone, Default)]
pub(crate) struct SimConnector {
    answers: Arc<Mutex<BTreeMap<SocketAddr, Answer>>>,
    accepted: Arc<Mutex<Vec<(SocketAddr, SimLink)>>>,
    /// The directions of every link opened, near to far first.
    opened: Arc<Mutex<Vec<(SocketAddr, Shared, Shared)>>>,
    attempts: Arc<Mutex<Vec<(SocketAddr, Instant)>>>,
}

impl SimConnector {
    pub(crate) fn answer(&self, address: SocketAddr, answer: Answer) {
        if let Ok(mut answers) = self.answers.lock() {
            answers.insert(address, answer);
        }
    }

    /// The far ends of the links opened so far, with their addresses.
    pub(crate) fn accepted(&self) -> Vec<(SocketAddr, SimLink)> {
        self.accepted
            .lock()
            .map(|mut accepted| accepted.drain(..).collect())
            .unwrap_or_default()
    }

    /// Bytes carried so far by the links opened to `address`, in each
    /// direction (from the connecting side, to it).
    pub(crate) fn carried(&self, address: SocketAddr) -> (u64, u64) {
        let total = |shared: &Shared| lock(shared).map_or(0, |direction| direction.carried);
        self.opened.lock().map_or((0, 0), |opened| {
            opened
                .iter()
                .filter(|(to, _, _)| *to == address)
                .fold((0, 0), |(out, back), (_, near, far)| {
                    (out + total(near), back + total(far))
                })
        })
    }

    /// Every attempt started, with its address and start time.
    pub(crate) fn attempts(&self) -> Vec<(SocketAddr, Instant)> {
        self.attempts
            .lock()
            .map(|attempts| attempts.clone())
            .unwrap_or_default()
    }
}

impl Connector for SimConnector {
    type Link = SimLink;

    async fn connect(&self, candidate: Candidate) -> io::Result<SimLink> {
        let address = candidate.address();
        if let Ok(mut attempts) = self.attempts.lock() {
            attempts.push((address, Instant::now()));
        }
        let answer = self
            .answers
            .lock()
            .ok()
            .and_then(|answers| answers.get(&address).copied())
            .unwrap_or(Answer::Silent);
        match answer {
            Answer::Connect { setup, path } => {
                tokio::time::sleep(setup).await;
                let local = SocketAddr::from(([192, 168, 1, 1], 50_000));
                let seed = u64::from(address.port()) ^ 0x9e37_79b9_7f4a_7c15;
                let (mut near, far) = link(path, local, address, seed);
                near.info = near.info.with_latency(setup);
                if let Ok(mut opened) = self.opened.lock() {
                    opened.push((
                        address,
                        Arc::clone(&near.outgoing),
                        Arc::clone(&near.incoming),
                    ));
                }
                if let Ok(mut accepted) = self.accepted.lock() {
                    accepted.push((address, far));
                }
                Ok(near)
            }
            Answer::Refuse { after } => {
                tokio::time::sleep(after).await;
                Err(io::ErrorKind::ConnectionRefused.into())
            }
            Answer::Silent => core::future::pending().await,
        }
    }
}
