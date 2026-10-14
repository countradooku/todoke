//! A relay node: the QUIC listener, the §10 room protocol on each stream,
//! and tunnels.
//!
//! Each bidirectional stream is one room: `Register` first, then what §10
//! allows in its order, until both members `Forward` and the two streams
//! are spliced into a tunnel. A connection may hold two streams at once
//! (§10: two rooms per endpoint). Nothing is logged, and nothing about a
//! room or tunnel outlives it; the counters in [`Metrics`] are totals with
//! no per-client data.

use core::time::Duration;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Instant;

use quinn::{RecvStream, SendStream, VarInt};
use todoke_proto::relay::{
    CloseCode, Control, MAX_ROOMS_PER_ENDPOINT, MAX_TUNNEL_BUFFER, MAX_TUNNEL_BYTES,
    MAX_TUNNEL_SECONDS, MAX_WAIT_SECONDS, RoomId,
};
use tokio::sync::{Notify, mpsc};

use crate::rooms::{Forwarded, Limits, RoomEvent, Rooms};
use crate::tls::Identity;

/// The relay's ALPN. §10 fixes the record layout but not the relay's
/// ALPN; this one names the record version.
pub const ALPN: &[u8] = b"todoke-relay/1";

/// How long a new stream has to send `Register`.
const REGISTER_DEADLINE: Duration = Duration::from_secs(10);
/// A connection with nothing in flight for this long is closed.
const IDLE: Duration = Duration::from_secs(30);
/// Bytes read from a stream at once.
const CHUNK: usize = 16 << 10;
/// Flow-control windows: what a tunnel direction can hold at the relay,
/// the receive window plus the send window plus one chunk, stays under
/// §10's 1 MiB.
const STREAM_WINDOW: u32 = 448 << 10;
const SEND_WINDOW: u64 = 512 << 10;
/// Application error codes on QUIC streams and connections.
const QUOTA: VarInt = VarInt::from_u32(1);
const CLOSED: VarInt = VarInt::from_u32(2);

const _: () = assert!(
    STREAM_WINDOW as u64 + SEND_WINDOW + CHUNK as u64 <= MAX_TUNNEL_BUFFER as u64,
    "a tunnel direction must buffer at most 1 MiB"
);

/// How a node is run.
#[derive(Clone, Debug)]
pub struct Config {
    /// The UDP address to listen on.
    pub listen: SocketAddr,
    /// Connections at once.
    pub max_connections: usize,
    /// Connections at once from one IPv4 address or IPv6 /64.
    pub max_connections_per_source: usize,
    /// Rooms open at once.
    pub max_rooms: usize,
    /// Bytes a tunnel forwards in each direction (at most 16 TiB).
    pub tunnel_bytes: u64,
    /// How long a tunnel lasts (at most 24 hours).
    pub tunnel_lifetime: Duration,
    /// New connections a second from one source (bursts of twice that).
    pub connections_per_source_per_second: u32,
    /// Registers a second from one source (bursts of twice that).
    pub registers_per_source_per_second: u32,
    /// How long a new stream has to send `Register`.
    pub register_deadline: Duration,
    /// How long a connection may hold no room before it is closed.
    pub roomless: Duration,
    /// How long a lone member waits for the other endpoint (§10: 30 s).
    pub peer_wait: Duration,
}

impl Config {
    /// The defaults on `listen`: §10's tunnel limits, 20000 connections, 64
    /// from one source (20 new ones a second), 10 registers a second from
    /// one source, 50000 rooms.
    #[must_use]
    pub const fn new(listen: SocketAddr) -> Self {
        Self {
            listen,
            max_connections: 20_000,
            max_connections_per_source: 64,
            max_rooms: 50_000,
            tunnel_bytes: MAX_TUNNEL_BYTES,
            tunnel_lifetime: Duration::from_secs(MAX_TUNNEL_SECONDS),
            connections_per_source_per_second: 20,
            registers_per_source_per_second: 10,
            register_deadline: REGISTER_DEADLINE,
            roomless: ROOMLESS,
            peer_wait: Duration::from_secs(MAX_WAIT_SECONDS as u64),
        }
    }
}

/// Totals since start, for the operator: no client, token, address, or
/// room is ever counted by name.
#[derive(Debug, Default)]
pub struct Metrics {
    /// Connections open.
    pub connections: AtomicUsize,
    /// Rooms open.
    pub rooms: AtomicUsize,
    /// Tunnels open.
    pub tunnels: AtomicUsize,
    /// Registers accepted.
    pub registers: AtomicU64,
    /// Rooms where both endpoints met.
    pub matches: AtomicU64,
    /// Rooms closed before a tunnel, by close code (1..=5).
    pub closes: [AtomicU64; 5],
    /// Connections refused (limits) or sent to address validation.
    pub refused: AtomicU64,
    /// Bytes forwarded through tunnels.
    pub forwarded: AtomicU64,
}

impl Metrics {
    /// The Prometheus text exposition of the totals.
    #[must_use]
    pub fn render(&self) -> String {
        use core::fmt::Write as _;
        let mut out = String::new();
        let gauges = [
            (
                "todoke_relay_connections",
                "Connections open.",
                self.connections.load(Ordering::Relaxed) as u64,
            ),
            (
                "todoke_relay_rooms",
                "Rooms open.",
                self.rooms.load(Ordering::Relaxed) as u64,
            ),
            (
                "todoke_relay_tunnels",
                "Tunnels open.",
                self.tunnels.load(Ordering::Relaxed) as u64,
            ),
        ];
        for (name, help, value) in gauges {
            let _ = writeln!(
                out,
                "# HELP {name} {help}\n# TYPE {name} gauge\n{name} {value}"
            );
        }
        let counters = [
            (
                "todoke_relay_registers_total",
                "Registers accepted.",
                self.registers.load(Ordering::Relaxed),
            ),
            (
                "todoke_relay_matches_total",
                "Rooms where both endpoints met.",
                self.matches.load(Ordering::Relaxed),
            ),
            (
                "todoke_relay_refused_total",
                "Connections refused or asked to validate their address.",
                self.refused.load(Ordering::Relaxed),
            ),
            (
                "todoke_relay_forwarded_bytes_total",
                "Bytes forwarded through tunnels.",
                self.forwarded.load(Ordering::Relaxed),
            ),
        ];
        for (name, help, value) in counters {
            let _ = writeln!(
                out,
                "# HELP {name} {help}\n# TYPE {name} counter\n{name} {value}"
            );
        }
        let _ = writeln!(
            out,
            "# HELP todoke_relay_closes_total Rooms closed before a tunnel, by reason.\n# TYPE todoke_relay_closes_total counter"
        );
        for (reason, count) in ["expired", "full", "quota", "malformed", "unavailable"]
            .iter()
            .zip(&self.closes)
        {
            let _ = writeln!(
                out,
                "todoke_relay_closes_total{{reason=\"{reason}\"}} {}",
                count.load(Ordering::Relaxed)
            );
        }
        out
    }

    fn closed(&self, code: CloseCode) {
        let index = match code {
            CloseCode::Expired => 0,
            CloseCode::Full => 1,
            CloseCode::Quota => 2,
            CloseCode::Malformed => 3,
            CloseCode::Unavailable => 4,
        };
        self.closes[index].fetch_add(1, Ordering::Relaxed);
    }
}

/// A member's streams, and bytes it sent after `Forward` (forwarded first).
struct Streams {
    send: SendStream,
    recv: RecvStream,
    early: Vec<u8>,
    /// The member's connection holds a room as long as these streams live,
    /// in the room table or in a tunnel.
    _room: OpenRoom,
}

/// One room counted on its connection, until dropped: a connection with
/// none is closed after [`ROOMLESS`].
struct OpenRoom(Arc<AtomicUsize>);

impl OpenRoom {
    fn new(open: &Arc<AtomicUsize>) -> Self {
        open.fetch_add(1, Ordering::Relaxed);
        Self(Arc::clone(open))
    }
}

impl Drop for OpenRoom {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

/// A rate limit (the generic cell rate algorithm): one event every
/// `interval`, bursts of `burst` events.
#[derive(Clone, Copy)]
struct Rate {
    interval: Duration,
    burst: u32,
}

impl Rate {
    /// `per_second` events a second, bursts of two seconds' worth.
    fn per_second(per_second: u32) -> Self {
        let per_second = per_second.max(1);
        Self {
            interval: Duration::from_secs(1) / per_second,
            burst: per_second.saturating_mul(2),
        }
    }
}
/// A connection holding no room for this long is closed.
const ROOMLESS: Duration = Duration::from_secs(30);

/// One source's connections and rate state, kept while it has connections
/// or its limits have not recovered: in memory only.
struct Source {
    connections: usize,
    /// When the connection and register allowances are full again.
    connect_full: Instant,
    register_full: Instant,
}

impl Source {
    /// Whether one more event fits `rate`, whose allowance is full again at
    /// `full`; if it does, `full` moves on.
    fn allow(full: &mut Instant, rate: Rate, now: Instant) -> bool {
        // A rate too high to measure is no limit.
        if rate.interval.is_zero() {
            return true;
        }
        let start = (*full).max(now);
        let limit = now + rate.interval * rate.burst;
        if start + rate.interval > limit {
            return false;
        }
        *full = start + rate.interval;
        true
    }
}

struct Shared {
    config: Config,
    rooms: Mutex<Rooms<Streams>>,
    sources: Mutex<HashMap<IpAddr, Source>>,
    metrics: Arc<Metrics>,
    next_endpoint: AtomicU64,
}

/// A running relay node.
pub struct Relay {
    endpoint: quinn::Endpoint,
    shared: Arc<Shared>,
}

impl Relay {
    /// Binds a node.
    ///
    /// # Errors
    ///
    /// If the TLS identity is unusable or the address cannot be bound.
    pub fn bind(config: Config, identity: &Identity) -> std::io::Result<Self> {
        let server = server_config(identity)?;
        let endpoint = quinn::Endpoint::server(server, config.listen)?;
        let limits = Limits {
            max_rooms: config.max_rooms,
            wait: config.peer_wait,
        };
        Ok(Self {
            endpoint,
            shared: Arc::new(Shared {
                config,
                rooms: Mutex::new(Rooms::new(limits)),
                sources: Mutex::new(HashMap::new()),
                metrics: Arc::new(Metrics::default()),
                next_endpoint: AtomicU64::new(1),
            }),
        })
    }

    /// The address it listens on.
    ///
    /// # Errors
    ///
    /// The socket's error.
    pub fn local_addr(&self) -> std::io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    /// Its counters.
    #[must_use]
    pub fn metrics(&self) -> Arc<Metrics> {
        Arc::clone(&self.shared.metrics)
    }

    /// Serves until `stop` is notified.
    pub async fn run(self, stop: Arc<Notify>) {
        let expiry = {
            let shared = Arc::clone(&self.shared);
            tokio::spawn(async move {
                // Rooms whose members stopped reading still expire.
                let mut tick = tokio::time::interval(Duration::from_secs(1));
                loop {
                    tick.tick().await;
                    let now = Instant::now();
                    {
                        let mut rooms = lock(&shared.rooms);
                        rooms.expire(now);
                        shared.metrics.rooms.store(rooms.len(), Ordering::Relaxed);
                    }
                    forget_sources(&shared, now);
                }
            })
        };
        loop {
            let incoming = tokio::select! {
                () = stop.notified() => break,
                incoming = self.endpoint.accept() => incoming,
            };
            let Some(incoming) = incoming else { break };
            let shared = &self.shared;
            // Address validation first: a spoofed source never gets a
            // connection, or more than a Retry packet.
            if !incoming.remote_address_validated() {
                shared.metrics.refused.fetch_add(1, Ordering::Relaxed);
                let _ = incoming.retry();
                continue;
            }
            let source = source_of(incoming.remote_address().ip());
            if !admit(shared, source) {
                shared.metrics.refused.fetch_add(1, Ordering::Relaxed);
                incoming.refuse();
                continue;
            }
            let shared = Arc::clone(shared);
            tokio::spawn(async move {
                if let Ok(connection) = incoming.await {
                    serve_connection(&shared, connection, source).await;
                }
                release(&shared, source);
            });
        }
        expiry.abort();
        self.endpoint.close(CLOSED, b"");
        self.endpoint.wait_idle().await;
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex.lock().unwrap_or_else(PoisonError::into_inner)
}

/// What a client is counted as: its IPv4 address, or its IPv6 /64.
fn source_of(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            if let Some(v4) = v6.to_ipv4_mapped() {
                IpAddr::V4(v4)
            } else {
                let mut octets = v6.octets();
                octets[8..].fill(0);
                IpAddr::V6(octets.into())
            }
        }
        v4 @ IpAddr::V4(_) => v4,
    }
}

fn admit(shared: &Shared, source: IpAddr) -> bool {
    let metrics = &shared.metrics;
    if metrics.connections.load(Ordering::Relaxed) >= shared.config.max_connections {
        return false;
    }
    let mut sources = lock(&shared.sources);
    // Read under the lock: an allowance never moves past a later `now`.
    let now = Instant::now();
    let entry = sources.entry(source).or_insert(Source {
        connections: 0,
        connect_full: now,
        register_full: now,
    });
    if entry.connections >= shared.config.max_connections_per_source
        || !Source::allow(
            &mut entry.connect_full,
            Rate::per_second(shared.config.connections_per_source_per_second),
            now,
        )
    {
        return false;
    }
    entry.connections += 1;
    metrics.connections.fetch_add(1, Ordering::Relaxed);
    true
}

fn release(shared: &Shared, source: IpAddr) {
    let mut sources = lock(&shared.sources);
    if let Some(entry) = sources.get_mut(&source) {
        entry.connections = entry.connections.saturating_sub(1);
    }
    shared.metrics.connections.fetch_sub(1, Ordering::Relaxed);
}

/// Whether `source` may register one more room now.
fn may_register(shared: &Shared, source: IpAddr) -> bool {
    let mut sources = lock(&shared.sources);
    let now = Instant::now();
    sources.get_mut(&source).is_some_and(|entry| {
        Source::allow(
            &mut entry.register_full,
            Rate::per_second(shared.config.registers_per_source_per_second),
            now,
        )
    })
}

/// Forgets sources with no connections whose limits have recovered.
fn forget_sources(shared: &Shared, now: Instant) {
    lock(&shared.sources).retain(|_, entry| {
        entry.connections > 0 || entry.connect_full > now || entry.register_full > now
    });
}

/// Serves a connection's streams, one room each, and closes it once it has
/// held no room for [`ROOMLESS`]: a connection kept alive with nothing to
/// do would hold its slots forever.
async fn serve_connection(shared: &Arc<Shared>, connection: quinn::Connection, source: IpAddr) {
    let endpoint = shared.next_endpoint.fetch_add(1, Ordering::Relaxed);
    let open = Arc::new(AtomicUsize::new(0));
    loop {
        let accepted = tokio::select! {
            accepted = connection.accept_bi() => accepted,
            () = tokio::time::sleep(shared.config.roomless) => {
                if open.load(Ordering::Relaxed) == 0 {
                    connection.close(CLOSED, b"");
                    return;
                }
                continue;
            }
        };
        let Ok((send, recv)) = accepted else {
            return;
        };
        let (shared, room) = (Arc::clone(shared), OpenRoom::new(&open));
        tokio::spawn(async move {
            serve_room(&shared, endpoint, source, room, send, recv).await;
        });
    }
}

/// Reads control records from a stream, keeping bytes past the last one.
struct Reader {
    buffer: Vec<u8>,
}

impl Reader {
    /// The next record; `None` at the end of the stream. Cancel-safe: what
    /// was read stays in the buffer.
    async fn next(&mut self, recv: &mut RecvStream) -> Result<Option<Control>, CloseCode> {
        loop {
            match Control::split(&self.buffer) {
                Ok(Some((control, used))) => {
                    self.buffer.drain(..used);
                    return Ok(Some(control));
                }
                Ok(None) => {}
                Err(_) => return Err(CloseCode::Malformed),
            }
            let mut chunk = [0; 2 + 2048];
            match recv.read(&mut chunk).await {
                Ok(Some(read)) => self.buffer.extend_from_slice(&chunk[..read]),
                Ok(None) | Err(_) => return Ok(None),
            }
        }
    }
}

async fn send(send: &mut SendStream, control: &Control) -> bool {
    match control.encode() {
        Ok(bytes) => send.write_all(&bytes).await.is_ok(),
        Err(_) => false,
    }
}

/// Tells the client why its room closed and ends the stream.
async fn close(stream: &mut SendStream, room: Option<RoomId>, code: CloseCode, metrics: &Metrics) {
    metrics.closed(code);
    let _ = send(stream, &Control::RelayClose { room, code }).await;
    let _ = stream.finish();
}

#[expect(clippy::too_many_lines, reason = "one room's protocol, in order")]
async fn serve_room(
    shared: &Arc<Shared>,
    endpoint: u64,
    source: IpAddr,
    open: OpenRoom,
    mut tx: SendStream,
    mut rx: RecvStream,
) {
    let metrics = &shared.metrics;
    let mut reader = Reader { buffer: Vec::new() };
    let first = tokio::time::timeout(shared.config.register_deadline, reader.next(&mut rx)).await;
    let Ok(Ok(Some(Control::Register {
        token,
        client_nonce,
        ttl_seconds,
    }))) = first
    else {
        close(&mut tx, None, CloseCode::Malformed, metrics).await;
        return;
    };
    if !may_register(shared, source) {
        close(&mut tx, None, CloseCode::Quota, metrics).await;
        return;
    }
    let (events, mut inbox) = mpsc::channel(4);
    let joined = lock(&shared.rooms).register(
        &token,
        client_nonce,
        ttl_seconds,
        endpoint,
        events,
        Instant::now(),
    );
    let joined = match joined {
        Ok(joined) => joined,
        Err(code) => {
            close(&mut tx, None, code, metrics).await;
            return;
        }
    };
    metrics.registers.fetch_add(1, Ordering::Relaxed);
    let ticket = joined.ticket;
    let room = ticket.room;
    let leave = |code: CloseCode| lock(&shared.rooms).close(ticket, code);
    let registered = Control::Registered {
        room,
        client_nonce,
        expires_in: joined.expires_in,
    };
    if !send(&mut tx, &registered).await {
        leave(CloseCode::Unavailable);
        return;
    }
    let mut ready = false;
    if let Some(peer_nonce) = joined.peer {
        metrics.matches.fetch_add(1, Ordering::Relaxed);
        ready = send(&mut tx, &Control::PeerReady { room, peer_nonce }).await;
    }
    let forward_room = loop {
        let deadline = if ready {
            joined.expires
        } else {
            joined.wait_until
        };
        tokio::select! {
            () = tokio::time::sleep_until(deadline.into()) => {
                leave(CloseCode::Expired);
                close(&mut tx, Some(room), CloseCode::Expired, metrics).await;
                return;
            }
            event = inbox.recv() => {
                let written = match event {
                    Some(RoomEvent::PeerReady(peer_nonce)) => {
                        ready = true;
                        send(&mut tx, &Control::PeerReady { room, peer_nonce }).await
                    }
                    Some(RoomEvent::Candidates(candidates)) => {
                        send(&mut tx, &Control::Candidates { room, candidates }).await
                    }
                    Some(RoomEvent::Punch { delay_ms, nonce }) => {
                        send(&mut tx, &Control::Punch { room, delay_ms, punch_nonce: nonce }).await
                    }
                    Some(RoomEvent::Closed(code)) => {
                        close(&mut tx, Some(room), code, metrics).await;
                        return;
                    }
                    None => false,
                };
                if !written {
                    leave(CloseCode::Unavailable);
                    return;
                }
            }
            control = reader.next(&mut rx) => match control {
                Ok(Some(Control::Candidates { room: named, candidates })) => {
                    let passed = lock(&shared.rooms).candidates(ticket, named, candidates);
                    if let Err(code) = passed {
                        close(&mut tx, Some(room), code, metrics).await;
                        return;
                    }
                }
                Ok(Some(Control::Forward { room: named })) => break named,
                Ok(Some(Control::RelayClose { .. }) | None) => {
                    // The client left.
                    leave(CloseCode::Unavailable);
                    let _ = tx.finish();
                    return;
                }
                Ok(Some(_)) | Err(_) => {
                    leave(CloseCode::Malformed);
                    close(&mut tx, Some(room), CloseCode::Malformed, metrics).await;
                    return;
                }
            },
        }
    };
    let mine = Streams {
        send: tx,
        recv: rx,
        early: reader.buffer,
        _room: open,
    };
    let forwarded = lock(&shared.rooms).forward(ticket, forward_room, mine);
    match forwarded {
        Err((code, mut mine)) => close(&mut mine.send, Some(room), code, metrics).await,
        Ok(Forwarded::Tunnel { mine, theirs }) => tunnel(shared, mine, theirs, room).await,
        Ok(Forwarded::Waiting) => {
            // The streams wait in the room for the other Forward; anything
            // but a closure (the other's Candidates or Punch) changes
            // nothing now.
            let deadline = tokio::time::sleep_until(joined.expires.into());
            tokio::pin!(deadline);
            let code = loop {
                tokio::select! {
                    () = &mut deadline => break CloseCode::Expired,
                    event = inbox.recv() => match event {
                        Some(RoomEvent::Closed(code)) => break code,
                        // The room became a tunnel (its channel closed).
                        None => return,
                        Some(_) => {}
                    },
                }
            };
            let mine = lock(&shared.rooms).withdraw(ticket, code);
            if let Some(mut mine) = mine {
                close(&mut mine.send, Some(room), code, metrics).await;
            }
        }
    }
}

/// Splices two members' streams: `ForwardReady` to both, then bytes in
/// order each way until either ends, the byte quota, or the lifetime.
async fn tunnel(shared: &Shared, mut mine: Streams, mut theirs: Streams, room: RoomId) {
    let ready = Control::ForwardReady { room };
    if !(send(&mut mine.send, &ready).await && send(&mut theirs.send, &ready).await) {
        return;
    }
    let metrics = &shared.metrics;
    metrics.tunnels.fetch_add(1, Ordering::Relaxed);
    let quota = shared.config.tunnel_bytes.min(MAX_TUNNEL_BYTES);
    let lifetime = shared
        .config
        .tunnel_lifetime
        .min(Duration::from_secs(MAX_TUNNEL_SECONDS));
    let one = pump(mine.recv, mine.early, theirs.send, quota, metrics);
    let other = pump(theirs.recv, theirs.early, mine.send, quota, metrics);
    let _ = tokio::time::timeout(lifetime, async { tokio::join!(one, other) }).await;
    metrics.tunnels.fetch_sub(1, Ordering::Relaxed);
}

/// Copies one direction: `early` (sent before the tunnel) first. Ends at
/// the source's end, a stream error, or the quota (resetting both ends).
async fn pump(
    mut from: RecvStream,
    early: Vec<u8>,
    mut to: SendStream,
    quota: u64,
    metrics: &Metrics,
) {
    let mut moved = early.len() as u64;
    if moved > quota || (!early.is_empty() && to.write_all(&early).await.is_err()) {
        let _ = to.reset(QUOTA);
        let _ = from.stop(QUOTA);
        return;
    }
    let mut chunk = vec![0; CHUNK];
    loop {
        match from.read(&mut chunk).await {
            Ok(Some(read)) => {
                moved += read as u64;
                if moved > quota {
                    let _ = to.reset(QUOTA);
                    let _ = from.stop(QUOTA);
                    return;
                }
                if to.write_all(&chunk[..read]).await.is_err() {
                    let _ = from.stop(CLOSED);
                    return;
                }
                metrics.forwarded.fetch_add(read as u64, Ordering::Relaxed);
            }
            Ok(None) => {
                let _ = to.finish();
                return;
            }
            Err(_) => {
                let _ = to.reset(CLOSED);
                return;
            }
        }
    }
}

fn server_config(identity: &Identity) -> std::io::Result<quinn::ServerConfig> {
    let invalid = |error: &dyn core::fmt::Display| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, error.to_string())
    };
    let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|error| invalid(&error))?
        .with_no_client_auth()
        .with_single_cert(identity.chain(), identity.key())
        .map_err(|error| invalid(&error))?;
    tls.alpn_protocols = vec![ALPN.to_vec()];
    // No 0-RTT and no resumption: nothing links two connections.
    tls.max_early_data_size = 0;
    tls.send_tls13_tickets = 0;
    let crypto =
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(|error| invalid(&error))?;
    let mut server = quinn::ServerConfig::with_crypto(Arc::new(crypto));
    server.transport_config(Arc::new(transport_config()?));
    Ok(server)
}

/// The QUIC limits: two rooms a connection, nothing unasked, and flow
/// control that bounds what a tunnel direction holds.
fn transport_config() -> std::io::Result<quinn::TransportConfig> {
    let invalid = |error: &dyn core::fmt::Display| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, error.to_string())
    };
    let mut transport = quinn::TransportConfig::default();
    let rooms = VarInt::from_u32(u32::try_from(MAX_ROOMS_PER_ENDPOINT).unwrap_or(2));
    transport
        .max_concurrent_bidi_streams(rooms)
        .max_concurrent_uni_streams(VarInt::from_u32(0))
        .stream_receive_window(VarInt::from_u32(STREAM_WINDOW))
        .receive_window(VarInt::from_u32(2 * STREAM_WINDOW))
        .send_window(SEND_WINDOW)
        .datagram_receive_buffer_size(None)
        .max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(IDLE).map_err(|error| invalid(&error))?,
        ));
    Ok(transport)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_source_is_an_ipv4_address_or_an_ipv6_64() {
        let ip = |text: &str| -> IpAddr { text.parse().unwrap_or(IpAddr::from([0, 0, 0, 0])) };
        // IPv4-mapped IPv6 is the IPv4 address (a dual-stack socket).
        assert_eq!(source_of(ip("::ffff:192.0.2.9")), ip("192.0.2.9"));
        assert_eq!(source_of(ip("192.0.2.9")), ip("192.0.2.9"));
        // One /64 is one source; another /64 is another.
        assert_eq!(
            source_of(ip("2001:db8:1:2:aaaa:bbbb:cccc:dddd")),
            source_of(ip("2001:db8:1:2::1"))
        );
        assert_ne!(
            source_of(ip("2001:db8:1:2::1")),
            source_of(ip("2001:db8:1:3::1"))
        );
    }

    /// What a tunnel direction can hold, the rooms per connection, and what
    /// the relay never accepts unasked: the transport's own debug output.
    #[test]
    fn the_transport_limits_are_the_documented_ones() -> std::io::Result<()> {
        let shown = format!("{:?}", transport_config()?);
        for expected in [
            "max_concurrent_bidi_streams: 2",
            "max_concurrent_uni_streams: 0",
            "stream_receive_window: 458752",
            "receive_window: 917504",
            "send_window: 524288",
            "datagram_receive_buffer_size: None",
        ] {
            assert!(shown.contains(expected), "{expected} not in {shown}");
        }
        Ok(())
    }

    /// A source is remembered only while it has connections or its rate
    /// limits have not recovered: nothing about it outlives that.
    #[tokio::test]
    async fn sources_are_forgotten_once_they_recover() -> std::io::Result<()> {
        let (identity, _, _) = Identity::self_signed(vec!["relay.test".into()])?;
        let mut config = Config::new(([127, 0, 0, 1], 0).into());
        config.max_connections_per_source = 2;
        let relay = Relay::bind(config, &identity)?;
        let shared = &relay.shared;
        let source: IpAddr = [192, 0, 2, 1].into();
        assert!(admit(shared, source));
        assert!(admit(shared, source));
        // At the per-source limit.
        assert!(!admit(shared, source));
        assert_eq!(lock(&shared.sources).len(), 1);
        let later = Instant::now() + Duration::from_secs(60);
        // Still has connections: kept.
        forget_sources(shared, later);
        assert_eq!(lock(&shared.sources).len(), 1);
        release(shared, source);
        release(shared, source);
        forget_sources(shared, Instant::now());
        // Rate state has not recovered yet: kept.
        assert_eq!(lock(&shared.sources).len(), 1);
        forget_sources(shared, later);
        assert!(lock(&shared.sources).is_empty());
        assert_eq!(shared.metrics.connections.load(Ordering::Relaxed), 0);
        Ok(())
    }

    #[test]
    fn the_defaults_are_the_documented_ones() {
        let config = Config::new(([127, 0, 0, 1], 0).into());
        assert_eq!(config.register_deadline, Duration::from_secs(10));
        assert_eq!(config.roomless, Duration::from_secs(30));
        assert_eq!(config.peer_wait, Duration::from_secs(30));
        assert_eq!(config.max_connections_per_source, 64);
        assert_eq!(config.tunnel_lifetime, Duration::from_hours(24));
        assert_eq!(config.tunnel_bytes, 16 << 40);
    }
}
