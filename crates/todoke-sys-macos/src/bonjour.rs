//! Bonjour through `dns_sd` (the system's mDNSResponder), for PROTOCOL §9 on
//! iOS, where an app may not send or receive raw multicast without
//! Apple's restricted multicast entitlement: services declared in the
//! app's `NSBonjourServices` go through mDNSResponder instead.
//!
//! What is advertised is exactly what `mdns-sd` advertises elsewhere: one
//! instance of `_todoke._tcp` per wanted record, labelled with its 16-hex
//! label, with one TXT string, and a host name made of the label too
//! (`<label>.local.`, with its own address records): never the device's
//! host name, which would link every rotating label to one device.
//!
//! One thread owns every `DNSServiceRef` (they are not thread-safe): it
//! waits on the shared connection's socket and processes replies, and the
//! callbacks, called only from inside that processing on that thread, reach
//! the thread's state through the context pointer. Commands come in and
//! findings go out through channels. Nothing here checks what it finds:
//! callers pass it through `todoke_discovery`'s checks like any mDNS
//! answer. Nothing logs.

#![allow(
    unsafe_code,
    reason = "dns_sd is a C API; each unsafe block states why it is sound"
)]

use std::collections::BTreeMap;
use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::mpsc::{self, Receiver, Sender, SyncSender, TryRecvError};
use std::thread::JoinHandle;

/// The service type (PROTOCOL §9).
const SERVICE: &CStr = c"_todoke._tcp";
/// How long the thread waits on the socket before looking at commands.
const POLL_MS: c_int = 200;
/// Findings queued for the caller; more are dropped.
const QUEUE: usize = 256;
/// Address records' time to live (seconds), as `mdns-sd`'s.
const TTL: u32 = 120;
/// Instances resolved at once; more are ignored until some go away.
const RESOLVING: usize = 64;

type DnsServiceRef = *mut c_void;
type DnsRecordRef = *mut c_void;
type Flags = u32;
type ErrorType = i32;

const NO_ERROR: ErrorType = 0;
const FLAG_MORE_COMING: Flags = 0x1;
const FLAG_ADD: Flags = 0x2;
const FLAG_NO_AUTO_RENAME: Flags = 0x8;
const FLAG_UNIQUE: Flags = 0x20;
const FLAG_SHARE_CONNECTION: Flags = 0x4000;
const INTERFACE_ANY: u32 = 0;
const INTERFACE_LOCAL_ONLY: u32 = u32::MAX;
const PROTOCOL_IPV4: u32 = 0x01;
const PROTOCOL_IPV6: u32 = 0x02;
const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;
const AF_INET: u8 = 2;
const AF_INET6: u8 = 30;
const POLLIN: i16 = 0x1;

type RegisterReply = extern "C" fn(
    DnsServiceRef,
    Flags,
    ErrorType,
    *const c_char,
    *const c_char,
    *const c_char,
    *mut c_void,
);
type RecordReply = extern "C" fn(DnsServiceRef, DnsRecordRef, Flags, ErrorType, *mut c_void);
type BrowseReply = extern "C" fn(
    DnsServiceRef,
    Flags,
    u32,
    ErrorType,
    *const c_char,
    *const c_char,
    *const c_char,
    *mut c_void,
);
type ResolveReply = extern "C" fn(
    DnsServiceRef,
    Flags,
    u32,
    ErrorType,
    *const c_char,
    *const c_char,
    u16,
    u16,
    *const u8,
    *mut c_void,
);
type AddrInfoReply =
    extern "C" fn(DnsServiceRef, Flags, u32, ErrorType, *const c_char, *const u8, u32, *mut c_void);

#[repr(C)]
struct PollFd {
    fd: c_int,
    events: i16,
    revents: i16,
}

// SAFETY (for the declarations): these are the `dns_sd.h` and `poll.h`
// prototypes of libSystem, which every Apple process links; the types
// above match their C layouts (refs are opaque pointers, ports are in
// network byte order).
unsafe extern "C" {
    fn DNSServiceCreateConnection(sd_ref: *mut DnsServiceRef) -> ErrorType;
    fn DNSServiceRefSockFD(sd_ref: DnsServiceRef) -> c_int;
    fn DNSServiceProcessResult(sd_ref: DnsServiceRef) -> ErrorType;
    fn DNSServiceRefDeallocate(sd_ref: DnsServiceRef);
    fn DNSServiceRegister(
        sd_ref: *mut DnsServiceRef,
        flags: Flags,
        interface: u32,
        name: *const c_char,
        regtype: *const c_char,
        domain: *const c_char,
        host: *const c_char,
        port: u16,
        txt_len: u16,
        txt: *const c_void,
        reply: Option<RegisterReply>,
        context: *mut c_void,
    ) -> ErrorType;
    fn DNSServiceRegisterRecord(
        sd_ref: DnsServiceRef,
        record: *mut DnsRecordRef,
        flags: Flags,
        interface: u32,
        fullname: *const c_char,
        rrtype: u16,
        rrclass: u16,
        rdlen: u16,
        rdata: *const c_void,
        ttl: u32,
        reply: Option<RecordReply>,
        context: *mut c_void,
    ) -> ErrorType;
    fn DNSServiceRemoveRecord(
        sd_ref: DnsServiceRef,
        record: DnsRecordRef,
        flags: Flags,
    ) -> ErrorType;
    fn DNSServiceBrowse(
        sd_ref: *mut DnsServiceRef,
        flags: Flags,
        interface: u32,
        regtype: *const c_char,
        domain: *const c_char,
        reply: BrowseReply,
        context: *mut c_void,
    ) -> ErrorType;
    fn DNSServiceResolve(
        sd_ref: *mut DnsServiceRef,
        flags: Flags,
        interface: u32,
        name: *const c_char,
        regtype: *const c_char,
        domain: *const c_char,
        reply: ResolveReply,
        context: *mut c_void,
    ) -> ErrorType;
    fn DNSServiceGetAddrInfo(
        sd_ref: *mut DnsServiceRef,
        flags: Flags,
        interface: u32,
        protocol: u32,
        hostname: *const c_char,
        reply: AddrInfoReply,
        context: *mut c_void,
    ) -> ErrorType;
    fn poll(fds: *mut PollFd, nfds: u32, timeout: c_int) -> c_int;
}

/// One instance to advertise.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Instance {
    /// The instance label (16 lowercase hex characters, §9).
    pub label: String,
    /// The value of the one TXT string (`v1=` and this).
    pub txt_value: String,
}

/// An address to publish for the instances' host names, on its interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Address {
    /// The address.
    pub ip: IpAddr,
    /// Its interface's index.
    pub interface: u32,
}

/// What the browser found: unchecked hints.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Found {
    /// An instance resolved, with the addresses its host name has.
    Resolved {
        /// The instance name (the label, if it is one of ours).
        name: String,
        /// Its port.
        port: u16,
        /// Its addresses, each with the interface it was found on.
        addresses: Vec<(IpAddr, u32)>,
        /// Its TXT strings, raw.
        txt: Vec<Vec<u8>>,
    },
    /// An instance went away.
    Removed {
        /// The instance name.
        name: String,
    },
}

enum Command {
    Publish {
        instances: Vec<Instance>,
        port: u16,
        addresses: Vec<Address>,
    },
}

/// The Bonjour responder and browser for `_todoke._tcp`. Dropping it
/// withdraws every advertisement and stops the thread.
pub struct Bonjour {
    commands: Option<Sender<Command>>,
    found: Receiver<Found>,
    thread: Option<JoinHandle<()>>,
}

impl core::fmt::Debug for Bonjour {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Bonjour").finish_non_exhaustive()
    }
}

impl Bonjour {
    /// Starts browsing for `_todoke._tcp` on every interface, or, with
    /// `local_only`, on this device alone (tests).
    ///
    /// # Errors
    ///
    /// mDNSResponder cannot be reached, or the thread cannot start.
    pub fn start(local_only: bool) -> io::Result<Self> {
        let (commands, inbox) = mpsc::channel();
        let (outbox, found) = mpsc::sync_channel(QUEUE);
        let (ready, started) = mpsc::channel();
        let thread = std::thread::Builder::new()
            .name("todoke-bonjour".to_owned())
            .spawn(move || run(local_only, &inbox, &outbox, &ready))
            .map_err(|_| io::Error::other("the Bonjour thread could not start"))?;
        match started.recv() {
            Ok(Ok(())) => Ok(Self {
                commands: Some(commands),
                found,
                thread: Some(thread),
            }),
            Ok(Err(error)) => {
                let _ = thread.join();
                Err(error)
            }
            Err(_) => {
                let _ = thread.join();
                Err(io::Error::other("the Bonjour thread stopped"))
            }
        }
    }

    /// Advertises exactly `instances` on `port` (replacing the previous
    /// set), their host names with `addresses`.
    pub fn publish(&self, instances: Vec<Instance>, port: u16, addresses: Vec<Address>) {
        if let Some(commands) = &self.commands {
            let _ = commands.send(Command::Publish {
                instances,
                port,
                addresses,
            });
        }
    }

    /// The next finding, without waiting.
    #[must_use]
    pub fn try_next(&self) -> Option<Found> {
        self.found.try_recv().ok()
    }
}

impl Drop for Bonjour {
    fn drop(&mut self) {
        // Closing the command channel stops the thread, which releases
        // every ref (and with them every advertisement).
        self.commands = None;
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

/// One advertised instance: its service and its host's address records.
struct Advertised {
    instance: Instance,
    port: u16,
    addresses: Vec<Address>,
    service: DnsServiceRef,
    records: Vec<DnsRecordRef>,
}

/// An instance being resolved, then its host name's addresses gathered.
struct Pending {
    resolve: DnsServiceRef,
    lookup: Option<DnsServiceRef>,
    port: u16,
    txt: Vec<Vec<u8>>,
    addresses: Vec<(IpAddr, u32)>,
    /// Changed since last reported.
    changed: bool,
}

/// The thread's state, which the callbacks reach through their context.
struct State {
    connection: DnsServiceRef,
    interface: u32,
    outbox: SyncSender<Found>,
    advertised: Vec<Advertised>,
    pending: BTreeMap<String, Pending>,
}

fn run(
    local_only: bool,
    inbox: &Receiver<Command>,
    outbox: &SyncSender<Found>,
    ready: &Sender<io::Result<()>>,
) {
    let mut connection: DnsServiceRef = std::ptr::null_mut();
    // SAFETY: `connection` is a valid place for the new ref.
    if unsafe { DNSServiceCreateConnection(&raw mut connection) } != NO_ERROR {
        let _ = ready.send(Err(io::Error::other("mDNSResponder is unavailable")));
        return;
    }
    let mut state = Box::new(State {
        connection,
        interface: if local_only {
            INTERFACE_LOCAL_ONLY
        } else {
            INTERFACE_ANY
        },
        outbox: outbox.clone(),
        advertised: Vec::new(),
        pending: BTreeMap::new(),
    });
    let context: *mut State = &raw mut *state;
    let mut browse = connection;
    // SAFETY: `browse` starts as the shared connection, as
    // kDNSServiceFlagsShareConnection requires; the strings are
    // NUL-terminated literals; `context` is the boxed state, which outlives
    // every ref (they are released below, before it is dropped).
    let browsing = unsafe {
        DNSServiceBrowse(
            &raw mut browse,
            FLAG_SHARE_CONNECTION,
            state.interface,
            SERVICE.as_ptr(),
            std::ptr::null(),
            on_browse,
            context.cast(),
        )
    };
    if browsing != NO_ERROR {
        // SAFETY: the connection is ours and no longer used.
        unsafe { DNSServiceRefDeallocate(connection) };
        let _ = ready.send(Err(io::Error::other("Bonjour browsing failed")));
        return;
    }
    let _ = ready.send(Ok(()));
    // SAFETY: the connection is valid until deallocated below.
    let fd = unsafe { DNSServiceRefSockFD(connection) };
    loop {
        match inbox.try_recv() {
            Ok(Command::Publish {
                instances,
                port,
                addresses,
            }) => publish(&mut state, &instances, port, &addresses),
            Err(TryRecvError::Empty) => {}
            Err(TryRecvError::Disconnected) => break,
        }
        let mut poll_fd = PollFd {
            fd,
            events: POLLIN,
            revents: 0,
        };
        // SAFETY: one valid pollfd, waited on for at most POLL_MS.
        let ready_fds = unsafe { poll(&raw mut poll_fd, 1, POLL_MS) };
        if ready_fds > 0 && poll_fd.revents & POLLIN != 0 {
            // SAFETY: the connection is valid; replies run the callbacks
            // here, on this thread, with the context set above.
            if unsafe { DNSServiceProcessResult(connection) } != NO_ERROR {
                break;
            }
        }
    }
    for advertised in std::mem::take(&mut state.advertised) {
        withdraw(&state, advertised);
    }
    for (_, pending) in std::mem::take(&mut state.pending) {
        release(pending);
    }
    // SAFETY: the browse ref and then the connection are ours; deallocating
    // the connection releases every ref still sharing it.
    unsafe {
        DNSServiceRefDeallocate(browse);
        DNSServiceRefDeallocate(connection);
    }
}

/// Reconciles the advertised instances with `instances`.
fn publish(state: &mut State, instances: &[Instance], port: u16, addresses: &[Address]) {
    let (keep, gone): (Vec<_>, Vec<_>) = std::mem::take(&mut state.advertised)
        .into_iter()
        .partition(|advertised| {
            // The same instance, port, and addresses: kept; anything else
            // (a new network, say) is advertised afresh.
            instances.contains(&advertised.instance)
                && advertised.port == port
                && advertised.addresses == addresses
        });
    for advertised in gone {
        withdraw(state, advertised);
    }
    state.advertised = keep;
    for instance in instances {
        if state
            .advertised
            .iter()
            .any(|advertised| &advertised.instance == instance)
        {
            continue;
        }
        if let Some(advertised) = advertise(state, instance, port, addresses) {
            state.advertised.push(advertised);
        }
    }
}

fn advertise(
    state: &State,
    instance: &Instance,
    port: u16,
    addresses: &[Address],
) -> Option<Advertised> {
    let label = CString::new(instance.label.as_str()).ok()?;
    let host = CString::new(format!("{}.local.", instance.label)).ok()?;
    let txt = txt_record(&instance.txt_value)?;
    let mut records = Vec::new();
    for address in addresses {
        let (rrtype, rdata) = match address.ip {
            IpAddr::V4(ip) => (TYPE_A, ip.octets().to_vec()),
            IpAddr::V6(ip) => (TYPE_AAAA, ip.octets().to_vec()),
        };
        let interface = if state.interface == INTERFACE_LOCAL_ONLY {
            INTERFACE_LOCAL_ONLY
        } else {
            address.interface
        };
        let mut record: DnsRecordRef = std::ptr::null_mut();
        // SAFETY: the shared connection is valid; `host` and `rdata` are
        // valid for the call (dns_sd copies them); `rdata`'s length fits
        // u16 (4 or 16 bytes).
        let added = unsafe {
            DNSServiceRegisterRecord(
                state.connection,
                &raw mut record,
                // The host name is ours alone: probed for conflicts.
                FLAG_UNIQUE,
                interface,
                host.as_ptr(),
                rrtype,
                CLASS_IN,
                u16::try_from(rdata.len()).unwrap_or(0),
                rdata.as_ptr().cast(),
                TTL,
                Some(on_record),
                std::ptr::null_mut(),
            )
        };
        if added == NO_ERROR {
            records.push(record);
        }
    }
    let mut service = state.connection;
    // SAFETY: `service` starts as the shared connection; the strings and
    // the TXT bytes are valid for the call (dns_sd copies them); the TXT
    // length fits u16 (checked when it was built).
    let registered = unsafe {
        DNSServiceRegister(
            &raw mut service,
            FLAG_SHARE_CONNECTION | FLAG_NO_AUTO_RENAME,
            state.interface,
            label.as_ptr(),
            SERVICE.as_ptr(),
            std::ptr::null(),
            host.as_ptr(),
            port.to_be(),
            u16::try_from(txt.len()).unwrap_or(0),
            txt.as_ptr().cast(),
            Some(on_register),
            std::ptr::null_mut(),
        )
    };
    if registered != NO_ERROR {
        for record in records {
            // SAFETY: each record was added on this connection.
            unsafe { DNSServiceRemoveRecord(state.connection, record, 0) };
        }
        return None;
    }
    Some(Advertised {
        instance: instance.clone(),
        port,
        addresses: addresses.to_vec(),
        service,
        records,
    })
}

fn withdraw(state: &State, advertised: Advertised) {
    // SAFETY: the service ref and the records belong to this connection
    // and are released once.
    unsafe {
        DNSServiceRefDeallocate(advertised.service);
        for record in advertised.records {
            DNSServiceRemoveRecord(state.connection, record, 0);
        }
    }
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "taken: the refs it holds are released"
)]
fn release(pending: Pending) {
    // SAFETY: the refs belong to the shared connection and are released
    // once.
    unsafe {
        if let Some(lookup) = pending.lookup {
            DNSServiceRefDeallocate(lookup);
        }
        DNSServiceRefDeallocate(pending.resolve);
    }
}

/// The TXT record holding the one string `v1=<value>`, if it fits a TXT
/// string (255 bytes).
fn txt_record(value: &str) -> Option<Vec<u8>> {
    let string = format!("v1={value}");
    let len = u8::try_from(string.len()).ok()?;
    let mut record = Vec::with_capacity(string.len() + 1);
    record.push(len);
    record.extend_from_slice(string.as_bytes());
    Some(record)
}

/// The TXT record's strings, if it is well formed.
fn txt_strings(record: &[u8]) -> Option<Vec<Vec<u8>>> {
    let mut strings = Vec::new();
    let mut rest = record;
    while let Some((&len, tail)) = rest.split_first() {
        let len = usize::from(len);
        let string = tail.get(..len)?;
        strings.push(string.to_vec());
        rest = tail.get(len..)?;
    }
    Some(strings)
}

/// A `sockaddr` (BSD layout: length, family, then the address).
fn socket_address(address: *const u8) -> Option<IpAddr> {
    if address.is_null() {
        return None;
    }
    // SAFETY: dns_sd passes a valid sockaddr for the call; its first two
    // bytes (sa_len, sa_family) are always present.
    let header = unsafe { std::slice::from_raw_parts(address, 2) };
    let len = usize::from(header[0]);
    match header[1] {
        AF_INET if len >= 8 => {
            // SAFETY: an AF_INET sockaddr of sa_len bytes (at least 8).
            let bytes = unsafe { std::slice::from_raw_parts(address, 8) };
            Some(IpAddr::V4(Ipv4Addr::new(
                bytes[4], bytes[5], bytes[6], bytes[7],
            )))
        }
        AF_INET6 if len >= 24 => {
            // SAFETY: an AF_INET6 sockaddr of sa_len bytes (at least 24).
            let bytes = unsafe { std::slice::from_raw_parts(address, 24) };
            let octets: [u8; 16] = bytes[8..24].try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}

/// A C string from a callback, if it is UTF-8.
fn text(pointer: *const c_char) -> Option<String> {
    if pointer.is_null() {
        return None;
    }
    // SAFETY: dns_sd passes NUL-terminated strings valid for the callback.
    unsafe { CStr::from_ptr(pointer) }
        .to_str()
        .ok()
        .map(str::to_owned)
}

/// The thread's state from a callback's context.
///
/// # Safety
///
/// `context` is the `State` the thread boxed, alive for every callback
/// (callbacks run only inside `DNSServiceProcessResult` on that thread,
/// which holds no other reference to it then).
unsafe fn state<'a>(context: *mut c_void) -> Option<&'a mut State> {
    // SAFETY: as the function's contract says.
    unsafe { context.cast::<State>().as_mut() }
}

extern "C" fn on_register(
    _: DnsServiceRef,
    _: Flags,
    _: ErrorType,
    _: *const c_char,
    _: *const c_char,
    _: *const c_char,
    _: *mut c_void,
) {
    // A name conflict ends the registration (no auto-rename); the next
    // epoch's label replaces it.
}

extern "C" fn on_record(_: DnsServiceRef, _: DnsRecordRef, _: Flags, _: ErrorType, _: *mut c_void) {
}

extern "C" fn on_browse(
    _: DnsServiceRef,
    flags: Flags,
    interface: u32,
    error: ErrorType,
    name: *const c_char,
    regtype: *const c_char,
    domain: *const c_char,
    context: *mut c_void,
) {
    // SAFETY: the browse ref was created with the thread's state.
    let Some(state) = (unsafe { state(context) }) else {
        return;
    };
    let Some(instance) = text(name) else {
        return;
    };
    if error != NO_ERROR {
        return;
    }
    if flags & FLAG_ADD == 0 {
        if let Some(pending) = state.pending.remove(&instance) {
            release(pending);
        }
        let _ = state.outbox.try_send(Found::Removed { name: instance });
        flush(state, flags);
        return;
    }
    if state.pending.contains_key(&instance) || state.pending.len() >= RESOLVING {
        return;
    }
    let mut resolve = state.connection;
    // SAFETY: `resolve` starts as the shared connection; the strings are
    // the callback's own, valid for the call (dns_sd copies them); the
    // context is the thread's state.
    let resolving = unsafe {
        DNSServiceResolve(
            &raw mut resolve,
            FLAG_SHARE_CONNECTION,
            interface,
            name,
            regtype,
            domain,
            on_resolve,
            context,
        )
    };
    if resolving == NO_ERROR {
        state.pending.insert(
            instance,
            Pending {
                resolve,
                lookup: None,
                port: 0,
                txt: Vec::new(),
                addresses: Vec::new(),
                changed: false,
            },
        );
    }
    flush(state, flags);
}

/// Reports every changed, resolved instance once a burst of replies ends:
/// `kDNSServiceFlagsMoreComing` is about the whole shared connection, so
/// the burst may end in another query's reply.
fn flush(state: &mut State, flags: Flags) {
    if flags & FLAG_MORE_COMING != 0 {
        return;
    }
    for (name, pending) in &mut state.pending {
        if pending.changed && !pending.addresses.is_empty() {
            pending.changed = false;
            let _ = state.outbox.try_send(Found::Resolved {
                name: name.clone(),
                port: pending.port,
                addresses: pending.addresses.clone(),
                txt: pending.txt.clone(),
            });
        }
    }
}

extern "C" fn on_resolve(
    _: DnsServiceRef,
    flags: Flags,
    interface: u32,
    error: ErrorType,
    fullname: *const c_char,
    host: *const c_char,
    port: u16,
    txt_len: u16,
    txt: *const u8,
    context: *mut c_void,
) {
    // SAFETY: the resolve ref was created with the thread's state.
    let Some(state) = (unsafe { state(context) }) else {
        return;
    };
    let Some(instance) = text(fullname).and_then(|full| instance_name(&full)) else {
        return;
    };
    if error != NO_ERROR || host.is_null() {
        return;
    }
    let record = if txt.is_null() {
        &[][..]
    } else {
        // SAFETY: dns_sd passes `txt_len` readable bytes for the call.
        unsafe { std::slice::from_raw_parts(txt, usize::from(txt_len)) }
    };
    let Some(strings) = txt_strings(record) else {
        return;
    };
    let connection = state.connection;
    let Some(pending) = state.pending.get_mut(&instance) else {
        return;
    };
    pending.port = u16::from_be(port);
    pending.txt = strings;
    pending.changed = true;
    if pending.lookup.is_some() {
        flush(state, flags);
        return;
    }
    let mut lookup = connection;
    // SAFETY: `lookup` starts as the shared connection; `host` is the
    // callback's own string; the context is the thread's state.
    let looking = unsafe {
        DNSServiceGetAddrInfo(
            &raw mut lookup,
            FLAG_SHARE_CONNECTION,
            interface,
            PROTOCOL_IPV4 | PROTOCOL_IPV6,
            host,
            on_address,
            context,
        )
    };
    if looking == NO_ERROR {
        pending.lookup = Some(lookup);
    }
    flush(state, flags);
}

extern "C" fn on_address(
    lookup: DnsServiceRef,
    flags: Flags,
    interface: u32,
    error: ErrorType,
    _: *const c_char,
    address: *const u8,
    _: u32,
    context: *mut c_void,
) {
    // SAFETY: the lookup ref was created with the thread's state.
    let Some(state) = (unsafe { state(context) }) else {
        return;
    };
    let Some(pending) = state
        .pending
        .values_mut()
        .find(|pending| pending.lookup == Some(lookup))
    else {
        return;
    };
    if error == NO_ERROR
        && let Some(ip) = socket_address(address)
    {
        if flags & FLAG_ADD != 0 {
            if !pending.addresses.contains(&(ip, interface)) && pending.addresses.len() < 16 {
                pending.addresses.push((ip, interface));
                pending.changed = true;
            }
        } else if let Some(at) = pending
            .addresses
            .iter()
            .position(|known| *known == (ip, interface))
        {
            pending.addresses.remove(at);
            pending.changed = true;
        }
    }
    flush(state, flags);
}

/// The instance part of a full service name (`<instance>._todoke._tcp.local.`),
/// unescaped only for the plain labels todoke uses.
fn instance_name(fullname: &str) -> Option<String> {
    let instance = fullname.split_once('.')?.0;
    instance
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric())
        .then(|| instance.to_owned())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::*;

    #[test]
    fn txt_records_hold_one_string() {
        let record = txt_record("ab").unwrap_or_default();
        assert_eq!(record, b"\x05v1=ab");
        assert_eq!(txt_strings(&record), Some(vec![b"v1=ab".to_vec()]));
        assert_eq!(txt_strings(b"\x05v1=a"), None);
        assert_eq!(txt_strings(b""), Some(Vec::new()));
        assert_eq!(txt_record(&"x".repeat(253)), None);
    }

    #[test]
    fn instance_names_are_plain_labels() {
        assert_eq!(
            instance_name("0123456789abcdef._todoke._tcp.local."),
            Some("0123456789abcdef".to_owned())
        );
        assert_eq!(instance_name("a\\.b._todoke._tcp.local."), None);
        assert_eq!(instance_name("nodot"), None);
    }

    /// An instance advertised on this device alone is found, resolved to
    /// its port, TXT string, and address, and reported gone once withdrawn.
    #[test]
    fn an_advertised_instance_is_found_and_withdrawn() -> Result<(), Box<dyn std::error::Error>> {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random)?;
        let label = random.iter().fold(String::new(), |mut label, byte| {
            use core::fmt::Write as _;
            let _ = write!(label, "{byte:02x}");
            label
        });
        let bonjour = Bonjour::start(true)?;
        let instance = Instance {
            label: label.clone(),
            txt_value: "00".repeat(19),
        };
        let address = Address {
            ip: IpAddr::V4(Ipv4Addr::LOCALHOST),
            interface: 0,
        };
        bonjour.publish(vec![instance], 47_123, vec![address]);
        let resolved = wait(
            &bonjour,
            |found| matches!(found, Found::Resolved { name, .. } if *name == label),
        );
        let Some(Found::Resolved {
            port,
            txt,
            addresses,
            ..
        }) = resolved
        else {
            return Err("not found".into());
        };
        assert_eq!(port, 47_123);
        assert_eq!(txt, vec![format!("v1={}", "00".repeat(19)).into_bytes()]);
        assert!(
            addresses
                .iter()
                .any(|(ip, _)| *ip == IpAddr::V4(Ipv4Addr::LOCALHOST))
        );
        bonjour.publish(Vec::new(), 47_123, Vec::new());
        let removed = wait(
            &bonjour,
            |found| matches!(found, Found::Removed { name } if *name == label),
        );
        assert!(removed.is_some(), "not withdrawn");
        Ok(())
    }

    fn wait(bonjour: &Bonjour, wanted: impl Fn(&Found) -> bool) -> Option<Found> {
        for _ in 0..100 {
            while let Some(found) = bonjour.try_next() {
                if wanted(&found) {
                    return Some(found);
                }
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        None
    }
}
