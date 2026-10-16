//! TCP over Apple peer-to-peer Wi-Fi (AWDL), for PROTOCOL §10.1: Apple
//! supports it only through Network.framework (TN3151; a BSD socket can
//! neither listen nor reliably connect there), so connections are made and
//! accepted with Network.framework's C API and each is bridged to a local
//! stream socket pair: the caller reads and writes its end like any TCP
//! stream, and a pump moves the bytes to and from the connection. The
//! session on top (§4, §5) is the same as on the LAN; the link layer's own
//! security is not relied on.
//!
//! Each connection has its own serial dispatch queue, on which only
//! Network.framework's completions run, and they never wait. A writer
//! thread writes received data to the pair and only then receives again
//! (so a slow reader stops receiving); a sender thread sends what it reads
//! from the pair one buffer at a time, waiting for each send to complete
//! (so a slow link stops the reader). Either side ending ends the other:
//! end of stream becomes TCP's FIN and back; an error cancels; the caller
//! dropping its [`Connection`] cancels once its last bytes are sent.
//! Nothing logs.

#![allow(
    unsafe_code,
    reason = "Network.framework is a C API; each unsafe block states why it is sound"
)]

use std::ffi::{CStr, c_char, c_void};
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::os::fd::AsRawFd;
use std::os::unix::net::UnixStream;
use std::sync::atomic::{AtomicU8, AtomicUsize, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::Duration;

use block2::{Block, RcBlock};
use dispatch2::{DispatchData, DispatchQueue, DispatchRetained, DispatchTime};

/// Bytes read from the pair and sent at once, and received at most at once.
const CHUNK: usize = 64 * 1024;
/// The same, as Network.framework takes it.
const CHUNK_U32: u32 = 64 * 1024;
/// Accepted connections waiting for the caller, and getting ready; more
/// are refused.
const BACKLOG: usize = 16;

type Object = *mut c_void;
/// `nw_parameters_configure_protocol_block_t`, and other one-object blocks.
type ObjectBlock = Block<dyn Fn(Object)>;
/// The state-changed handlers' blocks.
type StateBlock = Block<dyn Fn(u32, Object)>;
/// `nw_connection_receive_completion_t`.
type ReceiveBlock = Block<dyn Fn(Object, Object, u8, Object)>;

const CONNECTION_WAITING: u32 = 1;
const CONNECTION_READY: u32 = 3;
const CONNECTION_FAILED: u32 = 4;
const CONNECTION_CANCELLED: u32 = 5;
const LISTENER_READY: u32 = 2;
const LISTENER_FAILED: u32 = 3;
const LISTENER_CANCELLED: u32 = 4;
const ENDPOINT_ADDRESS: u32 = 1;

/// Network.framework's C API, loaded when first needed (`dlopen`): linking
/// it would ask every consumer of the static library (the Swift package,
/// the JNI glue, the daemon) to name the framework. Without it, nothing
/// here works and every entry point says so.
struct Api {
    protocol_disable: &'static ObjectBlock,
    protocol_default: &'static ObjectBlock,
    context_default_message: Object,
    context_final_send: Object,
    nw_release: unsafe extern "C" fn(Object),
    nw_retain: unsafe extern "C" fn(Object) -> Object,
    nw_parameters_create_secure_tcp: unsafe extern "C" fn(&ObjectBlock, &ObjectBlock) -> Object,
    nw_parameters_set_include_peer_to_peer: unsafe extern "C" fn(Object, bool),
    nw_endpoint_create_address: unsafe extern "C" fn(*const c_void) -> Object,
    nw_endpoint_get_type: unsafe extern "C" fn(Object) -> u32,
    nw_endpoint_get_address: unsafe extern "C" fn(Object) -> *const c_void,
    nw_listener_create: unsafe extern "C" fn(Object) -> Object,
    nw_listener_set_queue: unsafe extern "C" fn(Object, *const DispatchQueue),
    nw_listener_set_state_changed_handler: unsafe extern "C" fn(Object, &StateBlock),
    nw_listener_set_new_connection_handler: unsafe extern "C" fn(Object, &ObjectBlock),
    nw_listener_start: unsafe extern "C" fn(Object),
    nw_listener_cancel: unsafe extern "C" fn(Object),
    nw_listener_get_port: unsafe extern "C" fn(Object) -> u16,
    nw_connection_create: unsafe extern "C" fn(Object, Object) -> Object,
    nw_connection_set_queue: unsafe extern "C" fn(Object, *const DispatchQueue),
    nw_connection_set_state_changed_handler: unsafe extern "C" fn(Object, &StateBlock),
    nw_connection_start: unsafe extern "C" fn(Object),
    nw_connection_cancel: unsafe extern "C" fn(Object),
    nw_connection_copy_endpoint: unsafe extern "C" fn(Object) -> Object,
    nw_connection_send:
        unsafe extern "C" fn(Object, *const DispatchData, Object, bool, &ObjectBlock),
    // `is_complete` is a C `bool`: one byte, read as `u8`.
    nw_connection_receive: unsafe extern "C" fn(Object, u32, u32, &ReceiveBlock),
}

// SAFETY: function pointers and the framework's immutable constants.
unsafe impl Send for Api {}
// SAFETY: as above.
unsafe impl Sync for Api {}

const NETWORK: &CStr = c"/System/Library/Frameworks/Network.framework/Network";
const RTLD_NOW: i32 = 0x2;

unsafe extern "C" {
    fn dlopen(path: *const c_char, mode: i32) -> *mut c_void;
    fn dlsym(handle: *mut c_void, symbol: *const c_char) -> *mut c_void;
}

/// Network.framework's functions, or why not.
fn api() -> io::Result<&'static Api> {
    static API: OnceLock<Option<Api>> = OnceLock::new();
    API.get_or_init(load).as_ref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::Unsupported,
            "Network.framework is unavailable",
        )
    })
}

#[expect(
    clippy::missing_transmute_annotations,
    reason = "each symbol's target type is the field it fills"
)]
fn load() -> Option<Api> {
    // SAFETY: a NUL-terminated path of a system framework; the handle is
    // kept for the process's life (never closed).
    let handle = unsafe { dlopen(NETWORK.as_ptr(), RTLD_NOW) };
    if handle.is_null() {
        return None;
    }
    let symbol = |name: &CStr| {
        // SAFETY: a live handle and a NUL-terminated name.
        let found = unsafe { dlsym(handle, name.as_ptr()) };
        (!found.is_null()).then_some(found)
    };
    macro_rules! function {
        ($name:ident) => {
            // SAFETY: the framework's exported function of that name, whose
            // C prototype the field's type matches.
            unsafe {
                core::mem::transmute::<*mut c_void, _>(symbol(
                    &std::ffi::CString::new(stringify!($name)).ok()?,
                )?)
            }
        };
    }
    // SAFETY: each is the address of the framework's exported constant of
    // that name (a block or context pointer), set before any call and
    // never changed.
    let (protocol_disable, protocol_default, context_default_message, context_final_send) = unsafe {
        (
            *symbol(c"_nw_parameters_configure_protocol_disable")?.cast::<&'static ObjectBlock>(),
            *symbol(c"_nw_parameters_configure_protocol_default_configuration")?
                .cast::<&'static ObjectBlock>(),
            *symbol(c"_nw_content_context_default_message")?.cast::<Object>(),
            *symbol(c"_nw_content_context_final_send")?.cast::<Object>(),
        )
    };
    Some(Api {
        protocol_disable,
        protocol_default,
        context_default_message,
        context_final_send,
        nw_release: function!(nw_release),
        nw_retain: function!(nw_retain),
        nw_parameters_create_secure_tcp: function!(nw_parameters_create_secure_tcp),
        nw_parameters_set_include_peer_to_peer: function!(nw_parameters_set_include_peer_to_peer),
        nw_endpoint_create_address: function!(nw_endpoint_create_address),
        nw_endpoint_get_type: function!(nw_endpoint_get_type),
        nw_endpoint_get_address: function!(nw_endpoint_get_address),
        nw_listener_create: function!(nw_listener_create),
        nw_listener_set_queue: function!(nw_listener_set_queue),
        nw_listener_set_state_changed_handler: function!(nw_listener_set_state_changed_handler),
        nw_listener_set_new_connection_handler: function!(nw_listener_set_new_connection_handler),
        nw_listener_start: function!(nw_listener_start),
        nw_listener_cancel: function!(nw_listener_cancel),
        nw_listener_get_port: function!(nw_listener_get_port),
        nw_connection_create: function!(nw_connection_create),
        nw_connection_set_queue: function!(nw_connection_set_queue),
        nw_connection_set_state_changed_handler: function!(nw_connection_set_state_changed_handler),
        nw_connection_start: function!(nw_connection_start),
        nw_connection_cancel: function!(nw_connection_cancel),
        nw_connection_copy_endpoint: function!(nw_connection_copy_endpoint),
        nw_connection_send: function!(nw_connection_send),
        nw_connection_receive: function!(nw_connection_receive),
    })
}

/// Whether Network.framework could be loaded here.
#[must_use]
pub fn available() -> bool {
    api().is_ok()
}

/// A retained Network.framework object, released when dropped.
struct Retained(Object, &'static Api);

// SAFETY: Network.framework objects are thread-safe reference-counted
// objects; this only retains, releases, and passes them to its functions.
unsafe impl Send for Retained {}
// SAFETY: as above.
unsafe impl Sync for Retained {}

impl Retained {
    /// Takes ownership of a +1 reference, or `None` for null.
    fn new(api: &'static Api, object: Object) -> Option<Self> {
        (!object.is_null()).then_some(Self(object, api))
    }

    /// Retains an object borrowed from a callback.
    fn retain(api: &'static Api, object: Object) -> Option<Self> {
        if object.is_null() {
            return None;
        }
        // SAFETY: a live object the caller lent; one more reference, owned
        // by the result.
        Some(Self(unsafe { (api.nw_retain)(object) }, api))
    }
}

impl Drop for Retained {
    fn drop(&mut self) {
        // SAFETY: the reference this owns.
        unsafe { (self.1.nw_release)(self.0) };
    }
}

/// TCP parameters without TLS (the session encrypts), with peer-to-peer
/// interfaces included or not.
fn parameters(api: &'static Api, peer_to_peer: bool) -> io::Result<Retained> {
    // SAFETY: the two blocks are the framework's own constants.
    let parameters = Retained::new(api, unsafe {
        (api.nw_parameters_create_secure_tcp)(api.protocol_disable, api.protocol_default)
    })
    .ok_or_else(|| io::Error::other("no TCP parameters"))?;
    // SAFETY: a live parameters object.
    unsafe { (api.nw_parameters_set_include_peer_to_peer)(parameters.0, peer_to_peer) };
    Ok(parameters)
}

/// `address` as a `sockaddr_in` or `sockaddr_in6` (scope kept).
fn sockaddr(address: SocketAddr) -> Vec<u8> {
    match address {
        SocketAddr::V4(v4) => {
            let mut out = vec![16_u8, 2];
            out.extend_from_slice(&v4.port().to_be_bytes());
            out.extend_from_slice(&v4.ip().octets());
            out.resize(16, 0);
            out
        }
        SocketAddr::V6(v6) => {
            let mut out = vec![28_u8, 30];
            out.extend_from_slice(&v6.port().to_be_bytes());
            out.extend_from_slice(&v6.flowinfo().to_be_bytes());
            out.extend_from_slice(&v6.ip().octets());
            out.extend_from_slice(&v6.scope_id().to_ne_bytes());
            out
        }
    }
}

/// The address a `sockaddr` holds, if it is IPv4 or IPv6.
///
/// # Safety
///
/// `address` is null or points to a `sockaddr` whose `sa_len` bytes are
/// readable.
unsafe fn socket_address(address: *const c_void) -> Option<SocketAddr> {
    if address.is_null() {
        return None;
    }
    // SAFETY: the caller guarantees `sa_len` readable bytes; the first two
    // (length, family) always are.
    let head = unsafe { core::slice::from_raw_parts(address.cast::<u8>(), 2) };
    let length = usize::from(head[0]);
    // SAFETY: as above, `length` bytes.
    let bytes = unsafe { core::slice::from_raw_parts(address.cast::<u8>(), length) };
    let port = |at: usize| u16::from_be_bytes([bytes[at], bytes[at + 1]]);
    match (head[1], length) {
        (2, 16..) => Some(SocketAddr::V4(SocketAddrV4::new(
            Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]),
            port(2),
        ))),
        (30, 28..) => {
            let mut ip = [0_u8; 16];
            ip.copy_from_slice(&bytes[8..24]);
            let scope = u32::from_ne_bytes([bytes[24], bytes[25], bytes[26], bytes[27]]);
            Some(SocketAddr::V6(SocketAddrV6::new(
                Ipv6Addr::from(ip),
                port(2),
                0,
                scope,
            )))
        }
        _ => None,
    }
}

/// The remote address of a connection.
fn remote(connection: &Retained) -> Option<SocketAddr> {
    let api = connection.1;
    // SAFETY: a live connection; the endpoint is a +1 reference, owned
    // here; its address lives as long as it does.
    unsafe {
        let endpoint = Retained::new(api, (api.nw_connection_copy_endpoint)(connection.0))?;
        if (api.nw_endpoint_get_type)(endpoint.0) != ENDPOINT_ADDRESS {
            return None;
        }
        socket_address((api.nw_endpoint_get_address)(endpoint.0))
    }
}

/// A connection the caller owns: cancelled (then released) when dropped,
/// on every path, started or not (Network.framework asks that every
/// connection be cancelled).
struct Owned(Retained);

impl Owned {
    fn cancel(&self) {
        // SAFETY: a live connection; cancelling twice is harmless.
        unsafe { (self.0.1.nw_connection_cancel)(self.0.0) };
    }
}

impl Drop for Owned {
    fn drop(&mut self) {
        self.cancel();
    }
}

/// A connection bridged to a stream: the caller's end, the peer's address,
/// and the connection, which goes when the caller drops it.
#[derive(Debug)]
pub struct Bridged {
    /// The caller's end of the pair.
    pub stream: UnixStream,
    /// The peer's address.
    pub remote: Option<SocketAddr>,
    /// The connection; keep it as long as the stream.
    pub connection: Connection,
}

/// A bridged connection, kept by the caller with its stream. Dropping it
/// ends the connection once what the caller wrote has been sent (at most
/// [`LINGER`] later), so a peer that goes quiet cannot keep it, its pump,
/// or their descriptors.
pub struct Connection(Arc<Pump>);

impl core::fmt::Debug for Connection {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Connection").finish_non_exhaustive()
    }
}

impl Drop for Connection {
    fn drop(&mut self) {
        let was = self.0.state.fetch_or(ABANDONED, Ordering::AcqRel);
        if was & FINISHED != 0 {
            // Everything the caller wrote is sent.
            self.0.cancel();
            return;
        }
        // The pump sends what is left, then cancels; or this does, in time
        // (unless the pump is gone by then).
        let pump = Arc::downgrade(&self.0);
        let when = DispatchTime::try_from(LINGER).unwrap_or(DispatchTime::NOW);
        let scheduled = self.0.queue.after(when, move || {
            if let Some(pump) = pump.upgrade() {
                pump.cancel();
            }
        });
        if scheduled.is_err() {
            self.0.cancel();
        }
    }
}

/// How long a dropped connection may take to send what was left.
pub const LINGER: Duration = Duration::from_secs(10);
/// [`Pump::state`]: the caller dropped its [`Connection`].
const ABANDONED: u8 = 1;
/// [`Pump::state`]: the caller's end of stream was sent (or sending failed).
const FINISHED: u8 = 2;
/// Each end of a pair buffers this much (the system's default is 8 KiB).
const PAIR_BUFFER: i32 = 4 * 64 * 1024;

/// One bridged connection's pump. Nothing runs on the connection's queue
/// but Network.framework's own completions, which never wait: received
/// bytes go to a writer thread, which receives again only once they are
/// written to the pair (so a slow reader stops receiving); a sender thread
/// reads the pair and sends one buffer at a time, waiting for each send to
/// complete (so a slow link stops the reader).
struct Pump {
    connection: Owned,
    queue: DispatchRetained<DispatchQueue>,
    /// The pump's end of the pair, closed when the connection is
    /// cancelled (once the threads' copies go too, the caller's writes
    /// fail, as after a reset).
    pair: Mutex<Option<UnixStream>>,
    /// [`ABANDONED`] and [`FINISHED`]: whoever sets the second cancels.
    state: AtomicU8,
}

/// What one receive brought.
struct Received {
    bytes: Option<Vec<u8>>,
    /// The peer's end of stream.
    end: bool,
    failed: bool,
}

impl Received {
    const FAILED: Self = Self {
        bytes: None,
        end: false,
        failed: true,
    };
}

impl Pump {
    /// Starts moving bytes both ways between a ready `connection` and a
    /// new pair; returns the caller's end.
    fn start(connection: Owned, queue: DispatchRetained<DispatchQueue>) -> io::Result<Bridged> {
        let (theirs, ours) = UnixStream::pair()?;
        for end in [&theirs, &ours] {
            configure(end)?;
        }
        let writer = ours.try_clone()?;
        let reader = ours.try_clone()?;
        let remote = remote(&connection.0);
        let pump = Arc::new(Self {
            connection,
            queue,
            pair: Mutex::new(Some(ours)),
            state: AtomicU8::new(0),
        });
        // If either thread cannot start, the pump goes and cancels.
        let delivering = Arc::clone(&pump);
        std::thread::Builder::new()
            .name("todoke-p2p-receive".to_owned())
            .spawn(move || delivering.deliver(writer))?;
        let sending = Arc::clone(&pump);
        if let Err(error) = std::thread::Builder::new()
            .name("todoke-p2p-send".to_owned())
            .spawn(move || sending.send_all(reader))
        {
            pump.cancel();
            return Err(error);
        }
        Ok(Bridged {
            stream: theirs,
            remote,
            connection: Connection(pump),
        })
    }

    /// Asks for the next bytes; the answer comes on the returned channel
    /// (disconnected if the framework drops the request unanswered).
    fn receive(&self) -> Receiver<Received> {
        let (answer, answered) = mpsc::sync_channel::<Received>(1);
        let block = RcBlock::new(
            move |content: Object, _context: Object, complete: u8, error: Object| {
                let bytes = (!content.is_null()).then(|| {
                    // SAFETY: the framework lends `content`, a dispatch
                    // data object alive during this call.
                    unsafe { &*content.cast::<DispatchData>() }.to_vec()
                });
                // Never waits: one answer per request, one slot.
                let _ = answer.try_send(Received {
                    bytes,
                    end: complete != 0,
                    failed: !error.is_null(),
                });
            },
        );
        let api = self.connection.0.1;
        // SAFETY: a live connection; the block is copied by the framework.
        unsafe { (api.nw_connection_receive)(self.connection.0.0, 1, CHUNK_U32, &block) };
        answered
    }

    /// Writes what the peer sends to the pair, receiving again after each
    /// write, until the peer's end of stream (then the caller's) or an
    /// error (then the connection goes).
    fn deliver(self: Arc<Self>, mut pair: UnixStream) {
        loop {
            let received = self.receive().recv().unwrap_or(Received::FAILED);
            if let Some(bytes) = received.bytes
                && pair.write_all(&bytes).is_err()
            {
                self.cancel();
                return;
            }
            if received.failed {
                self.cancel();
                return;
            }
            if received.end {
                let _ = pair.shutdown(Shutdown::Write);
                return;
            }
        }
    }

    /// Sends what the caller writes, one buffer at a time, until its end
    /// of stream (then FIN) or an error (then the connection goes).
    fn send_all(self: Arc<Self>, mut reader: UnixStream) {
        let mut buffer = vec![0_u8; CHUNK];
        let sent = loop {
            let read = match reader.read(&mut buffer) {
                Ok(0) => break self.send(None),
                Ok(read) => read,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(_) => break false,
            };
            if !self.send(Some(&buffer[..read])) {
                break false;
            }
        };
        let was = self.state.fetch_or(FINISHED, Ordering::AcqRel);
        if !sent || was & ABANDONED != 0 {
            self.cancel();
        }
    }

    /// Sends `bytes` (or FIN for `None`) and waits until it is sent.
    fn send(&self, bytes: Option<&[u8]>) -> bool {
        let (done, sent) = mpsc::sync_channel::<bool>(1);
        let block = RcBlock::new(move |error: Object| {
            let _ = done.try_send(error.is_null());
        });
        let data = bytes.map(DispatchData::from_bytes);
        let content = data
            .as_ref()
            .map_or(core::ptr::null(), |data| &raw const **data);
        let api = self.connection.0.1;
        // SAFETY: a live connection; `content` (or null for FIN) lives
        // through the call and is retained by the framework; the contexts
        // are the framework's constants; the block is copied.
        unsafe {
            let message = if bytes.is_some() {
                api.context_default_message
            } else {
                api.context_final_send
            };
            (api.nw_connection_send)(
                self.connection.0.0,
                content,
                message,
                bytes.is_none(),
                &block,
            );
        }
        // Disconnected: the framework dropped the send unanswered.
        sent.recv().unwrap_or(false)
    }

    /// Ends the connection (gracefully: what was sent still goes) and both
    /// threads.
    fn cancel(&self) {
        self.connection.cancel();
        let pair = self.pair.lock().ok().and_then(|mut pair| pair.take());
        if let Some(pair) = pair {
            let _ = pair.shutdown(Shutdown::Both);
        }
    }
}

/// A pair end: no `SIGPIPE` when the other end is gone (the library runs
/// in apps that do not ignore it), and room for a few chunks.
fn configure(end: &UnixStream) -> io::Result<()> {
    let set = |option: i32, value: i32| {
        // SAFETY: a live socket, and an `int` option of that size.
        let failed = unsafe {
            setsockopt(
                end.as_raw_fd(),
                SOL_SOCKET,
                option,
                (&raw const value).cast(),
                4,
            )
        } != 0;
        if failed {
            Err(io::Error::last_os_error())
        } else {
            Ok(())
        }
    };
    set(SO_NOSIGPIPE, 1)?;
    // Larger buffers are best effort.
    let _ = set(SO_SNDBUF, PAIR_BUFFER);
    let _ = set(SO_RCVBUF, PAIR_BUFFER);
    Ok(())
}

const SOL_SOCKET: i32 = 0xffff;
const SO_SNDBUF: i32 = 0x1001;
const SO_RCVBUF: i32 = 0x1002;
const SO_NOSIGPIPE: i32 = 0x1022;

unsafe extern "C" {
    fn setsockopt(socket: i32, level: i32, option: i32, value: *const c_void, length: u32) -> i32;
}

/// Starts `connection` on a queue of its own and waits until it is ready
/// (or fails, or `timeout` passes); on any failure it is cancelled.
fn ready(connection: Owned, timeout: Duration) -> io::Result<Bridged> {
    let queue = DispatchQueue::new("org.todoke.p2p", None);
    let (state, changed) = mpsc::sync_channel::<bool>(4);
    let handler = RcBlock::new(move |status: u32, error: Object| match status {
        CONNECTION_READY => {
            let _ = state.try_send(true);
        }
        // Network.framework waits (and retries later) after a refusal: a
        // refusal is a failure here, so the next candidate runs.
        CONNECTION_FAILED | CONNECTION_CANCELLED => {
            let _ = state.try_send(false);
        }
        CONNECTION_WAITING if !error.is_null() => {
            let _ = state.try_send(false);
        }
        _ => {}
    });
    let api = connection.0.1;
    // SAFETY: a live connection and queue; the handler is copied.
    unsafe {
        (api.nw_connection_set_queue)(connection.0.0, &raw const *queue);
        (api.nw_connection_set_state_changed_handler)(connection.0.0, &handler);
        (api.nw_connection_start)(connection.0.0);
    }
    // Every early return drops `connection`, which cancels it.
    match changed.recv_timeout(timeout) {
        Ok(true) => Pump::start(connection, queue),
        Ok(false) => Err(io::ErrorKind::ConnectionRefused.into()),
        Err(_) => Err(io::ErrorKind::TimedOut.into()),
    }
}

/// Opens TCP to `address` (a peer-to-peer one, link-local with its scope)
/// within `timeout`, bridged to a stream.
///
/// # Errors
///
/// The connection failed or timed out.
pub fn connect(address: SocketAddr, peer_to_peer: bool, timeout: Duration) -> io::Result<Bridged> {
    let api = api()?;
    let parameters = parameters(api, peer_to_peer)?;
    let raw = sockaddr(address);
    // SAFETY: `raw` is a complete sockaddr that outlives the call; the
    // endpoint copies it.
    let endpoint = Retained::new(api, unsafe {
        (api.nw_endpoint_create_address)(raw.as_ptr().cast())
    })
    .ok_or_else(|| io::Error::from(io::ErrorKind::InvalidInput))?;
    // SAFETY: live endpoint and parameters; the connection is +1, owned.
    let connection = Retained::new(api, unsafe {
        (api.nw_connection_create)(endpoint.0, parameters.0)
    })
    .ok_or_else(|| io::Error::other("no connection"))?;
    ready(Owned(connection), timeout)
}

/// Which remote addresses a listener takes.
type Admit = dyn Fn(SocketAddr) -> bool + Send + Sync;

/// A TCP listener on every interface, peer-to-peer ones included, whose
/// connections come bridged.
pub struct Listener {
    inner: Retained,
    _queue: DispatchRetained<DispatchQueue>,
    port: u16,
    accepted: Receiver<Bridged>,
}

impl core::fmt::Debug for Listener {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Listener")
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

impl Listener {
    /// Listens on a free port; returns once it is ready (or fails). A
    /// connection whose remote address `admit` refuses is cancelled before
    /// it starts; at most [`BACKLOG`] get ready at once, more are cancelled.
    ///
    /// # Errors
    ///
    /// The listener failed or did not start in time.
    pub fn start(
        peer_to_peer: bool,
        admit: impl Fn(SocketAddr) -> bool + Send + Sync + 'static,
    ) -> io::Result<Self> {
        let api = api()?;
        let parameters = parameters(api, peer_to_peer)?;
        // SAFETY: live parameters; the listener is +1, owned.
        let listener = Retained::new(api, unsafe { (api.nw_listener_create)(parameters.0) })
            .ok_or_else(|| io::Error::other("no listener"))?;
        let queue = DispatchQueue::new("org.todoke.p2p.listener", None);
        let (accept, accepted) = mpsc::sync_channel::<Bridged>(BACKLOG);
        let accept = Arc::new(accept);
        let admit: Arc<Admit> = Arc::new(admit);
        let pending = Arc::new(AtomicUsize::new(0));
        let incoming = RcBlock::new(move |connection: Object| {
            let Some(connection) = Retained::retain(api, connection).map(Owned) else {
                return;
            };
            // Returning drops (cancels) it.
            if !remote(&connection.0).is_some_and(|remote| admit(remote)) {
                return;
            }
            let Some(slot) = Slot::take(&pending) else {
                return;
            };
            let accept = Arc::clone(&accept);
            // Readied off the listener's queue: it waits on its own.
            let _ = std::thread::Builder::new()
                .name("todoke-p2p-accept".to_owned())
                .spawn(move || {
                    offer(&accept, connection);
                    drop(slot);
                });
        });
        let (state, changed) = mpsc::sync_channel::<bool>(4);
        let handler = RcBlock::new(move |status: u32, _error: Object| match status {
            LISTENER_READY => {
                let _ = state.try_send(true);
            }
            LISTENER_FAILED | LISTENER_CANCELLED => {
                let _ = state.try_send(false);
            }
            _ => {}
        });
        // SAFETY: a live listener and queue; the handlers are copied.
        unsafe {
            (api.nw_listener_set_queue)(listener.0, &raw const *queue);
            (api.nw_listener_set_new_connection_handler)(listener.0, &incoming);
            (api.nw_listener_set_state_changed_handler)(listener.0, &handler);
            (api.nw_listener_start)(listener.0);
        }
        if changed.recv_timeout(Duration::from_secs(5)) != Ok(true) {
            // SAFETY: a live listener.
            unsafe { (api.nw_listener_cancel)(listener.0) };
            return Err(io::Error::other("the peer-to-peer listener did not start"));
        }
        // SAFETY: a ready listener.
        let port = unsafe { (api.nw_listener_get_port)(listener.0) };
        Ok(Self {
            inner: listener,
            _queue: queue,
            port,
            accepted,
        })
    }

    /// The port it listens on.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// The next accepted connection, waiting at most `timeout`.
    ///
    /// # Errors
    ///
    /// `TimedOut`; `NotConnected` once the listener is gone.
    pub fn accept(&self, timeout: Duration) -> io::Result<Bridged> {
        self.accepted
            .recv_timeout(timeout)
            .map_err(|error| match error {
                mpsc::RecvTimeoutError::Timeout => io::ErrorKind::TimedOut.into(),
                mpsc::RecvTimeoutError::Disconnected => io::ErrorKind::NotConnected.into(),
            })
    }
}

impl Drop for Listener {
    fn drop(&mut self) {
        // SAFETY: a live listener; no connection is accepted after this.
        unsafe { (self.inner.1.nw_listener_cancel)(self.inner.0) };
    }
}

/// One of [`BACKLOG`] connections getting ready at once, given back when
/// dropped.
struct Slot(Arc<AtomicUsize>);

impl Slot {
    fn take(pending: &Arc<AtomicUsize>) -> Option<Self> {
        pending
            .try_update(Ordering::AcqRel, Ordering::Acquire, |taken| {
                (taken < BACKLOG).then_some(taken + 1)
            })
            .ok()
            .map(|_| Self(Arc::clone(pending)))
    }
}

impl Drop for Slot {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::AcqRel);
    }
}

/// How long an accepted connection may take to get ready.
const ACCEPT_READY: Duration = Duration::from_secs(10);

/// Readies an accepted connection and hands it to the caller; refused
/// (cancelled) when the caller's backlog is full.
fn offer(accept: &SyncSender<Bridged>, connection: Owned) {
    let Ok(bridged) = ready(connection, ACCEPT_READY) else {
        return;
    };
    // A refused one is dropped here: its connection cancels.
    let _ = accept.try_send(bridged);
}

/// Whether the interface `index` is an Apple peer-to-peer Wi-Fi one
/// (`awdl*`, or the low-latency `llw*`). Interface names are not API, but
/// these have been stable since AWDL shipped.
#[must_use]
pub fn is_peer_to_peer(index: u32) -> bool {
    let mut name = [0 as c_char; 16];
    // SAFETY: the buffer has IF_NAMESIZE (16) bytes, as the call requires.
    let found = unsafe { if_indextoname(index, name.as_mut_ptr()) };
    if found.is_null() {
        return false;
    }
    // SAFETY: on success the buffer holds a NUL-terminated name.
    let name = unsafe { CStr::from_ptr(name.as_ptr()) }.to_bytes();
    name.starts_with(b"awdl") || name.starts_with(b"llw")
}

unsafe extern "C" {
    fn if_indextoname(index: u32, name: *mut c_char) -> *mut c_char;
}

#[cfg(test)]
mod tests;
