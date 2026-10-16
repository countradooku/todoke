use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr};
use std::time::Duration;

use super::*;

const WAIT: Duration = Duration::from_secs(10);

/// A listener and a connection to it on loopback, bridged both ends.
fn pair(address: impl Fn(u16) -> SocketAddr) -> io::Result<(Bridged, Bridged)> {
    let listener = Listener::start(false, |_| true)?;
    assert_ne!(listener.port(), 0);
    let client = connect(address(listener.port()), false, WAIT)?;
    let server = listener.accept(WAIT)?;
    Ok((client, server))
}

/// Bytes cross both ways intact, in order, through Network.framework, over
/// IPv4 and IPv6; the accepted side knows where the connection came from.
#[test]
fn bytes_cross_both_ways() -> io::Result<()> {
    for address in [
        |port| SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
        |port| SocketAddr::from((Ipv6Addr::LOCALHOST, port)),
    ] {
        let (mut client, mut server) = pair(address)?;
        let remote = server
            .remote
            .ok_or_else(|| io::Error::other("no remote address"))?;
        assert!(remote.ip().is_loopback());
        // More than one chunk each way, written and read concurrently.
        let sent: Vec<u8> = (0..(3 * CHUNK + 17))
            .map(|i| u8::try_from(i % 251).unwrap_or(0))
            .collect();
        let expected = sent.clone();
        let mut writer = client.stream.try_clone()?;
        let writing = std::thread::spawn(move || writer.write_all(&sent));
        let mut received = vec![0_u8; expected.len()];
        server.stream.read_exact(&mut received)?;
        writing
            .join()
            .map_err(|_| io::Error::other("the writer panicked"))??;
        assert_eq!(received, expected);
        server.stream.write_all(b"back")?;
        let mut back = [0_u8; 4];
        client.stream.read_exact(&mut back)?;
        assert_eq!(&back, b"back");
    }
    Ok(())
}

/// One side's end of stream reaches the other as end of stream (TCP's
/// FIN), and the other can still answer.
#[test]
fn end_of_stream_crosses() -> io::Result<()> {
    let (mut client, mut server) = pair(|port| SocketAddr::from((Ipv4Addr::LOCALHOST, port)))?;
    client.stream.write_all(b"last")?;
    client.stream.shutdown(Shutdown::Write)?;
    let mut all = Vec::new();
    server.stream.read_to_end(&mut all)?;
    assert_eq!(all, b"last");
    server.stream.write_all(b"ok")?;
    server.stream.shutdown(Shutdown::Write)?;
    let mut answer = Vec::new();
    client.stream.read_to_end(&mut answer)?;
    assert_eq!(answer, b"ok");
    Ok(())
}

/// Nothing listening: the connection is refused or times out, never
/// bridged; a listener with nothing coming times out its accept.
#[test]
fn failures_are_errors() -> io::Result<()> {
    let listener = Listener::start(false, |_| true)?;
    let port = listener.port();
    drop(listener);
    // Cancelling is asynchronous.
    std::thread::sleep(Duration::from_millis(300));
    let started = std::time::Instant::now();
    assert!(
        connect(
            SocketAddr::from((Ipv4Addr::LOCALHOST, port)),
            false,
            Duration::from_secs(3)
        )
        .is_err()
    );
    // Refused at once, not after the timeout.
    assert!(started.elapsed() < Duration::from_secs(2));
    let idle = Listener::start(false, |_| true)?;
    assert_eq!(
        idle.accept(Duration::from_millis(200))
            .map(|_| ())
            .map_err(|error| error.kind()),
        Err(io::ErrorKind::TimedOut)
    );
    Ok(())
}

#[test]
fn only_peer_to_peer_interfaces_count() {
    // Network.framework loads on every Apple system.
    assert!(available());
    // Loopback (index 1 on Apple systems) is not one.
    assert!(!is_peer_to_peer(1));
    assert!(!is_peer_to_peer(0));
    assert!(!is_peer_to_peer(u32::MAX));
}

#[test]
fn addresses_round_trip_through_sockaddrs() {
    for address in [
        SocketAddr::from((Ipv4Addr::new(192, 168, 49, 1), 40_000)),
        SocketAddr::V6(SocketAddrV6::new(
            "fe80::1".parse().unwrap_or(Ipv6Addr::LOCALHOST),
            40_001,
            0,
            7,
        )),
    ] {
        let raw = sockaddr(address);
        // SAFETY: a complete sockaddr made above.
        let back = unsafe { socket_address(raw.as_ptr().cast()) };
        assert_eq!(back, Some(address));
    }
    // SAFETY: null is allowed.
    let none = unsafe { socket_address(core::ptr::null()) };
    assert_eq!(none, None);
}

/// Both sides sending much more than a chunk at once, neither reading
/// until it is done writing: nothing waits on the connection's queue, so
/// neither stalls (receiving used to write to the pair on that queue, and
/// the sends' completions queued behind it).
#[test]
fn both_ways_at_once_never_stall() -> io::Result<()> {
    const SIZE: usize = 1024 * 1024;
    let (mut client, mut server) = pair(|port| SocketAddr::from((Ipv4Addr::LOCALHOST, port)))?;
    let pattern = |seed: usize| -> Vec<u8> {
        (0..SIZE)
            .map(|i| u8::try_from((i + seed) % 251).unwrap_or(0))
            .collect()
    };
    let mut writers = Vec::new();
    for (stream, seed) in [(&client.stream, 1), (&server.stream, 2)] {
        let mut writer = stream.try_clone()?;
        let bytes = pattern(seed);
        writers.push(std::thread::spawn(move || writer.write_all(&bytes)));
    }
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    while writers.iter().any(|writer| !writer.is_finished()) {
        assert!(
            std::time::Instant::now() < deadline,
            "the writers stalled with nothing reading"
        );
        std::thread::sleep(Duration::from_millis(50));
    }
    for writer in writers {
        writer
            .join()
            .map_err(|_| io::Error::other("a writer panicked"))??;
    }
    let mut received = vec![0_u8; SIZE];
    server.stream.read_exact(&mut received)?;
    assert_eq!(received, pattern(1));
    client.stream.read_exact(&mut received)?;
    assert_eq!(received, pattern(2));
    Ok(())
}

/// Waits until `pump` is gone, at most `within`.
fn gone(pump: &std::sync::Weak<Pump>, within: Duration) -> bool {
    let deadline = std::time::Instant::now() + within;
    while std::time::Instant::now() < deadline {
        if pump.strong_count() == 0 {
            return true;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    false
}

/// The caller dropping its end while the peer stays quiet: what it wrote
/// still arrives, then end of stream, and its pump, threads, and
/// connection go at once (not after the peer speaks, or never).
#[test]
fn dropping_ends_the_connection() -> io::Result<()> {
    let (mut client, mut server) = pair(|port| SocketAddr::from((Ipv4Addr::LOCALHOST, port)))?;
    let pump = Arc::downgrade(&client.connection.0);
    client.stream.write_all(b"bye")?;
    drop(client);
    let mut all = Vec::new();
    server.stream.read_to_end(&mut all)?;
    assert_eq!(all, b"bye");
    assert!(
        gone(&pump, Duration::from_secs(5)),
        "the pump outlived its caller"
    );
    // The server side, quiet, then dropped, goes too.
    let pump = Arc::downgrade(&server.connection.0);
    drop(server);
    assert!(
        gone(&pump, Duration::from_secs(5)),
        "the pump outlived its caller"
    );
    Ok(())
}

/// The caller dropping its end while the peer keeps sending: the peer's
/// writes fail soon (the connection is cancelled), not block forever.
#[test]
fn dropping_stops_a_sending_peer() -> io::Result<()> {
    let (client, mut server) = pair(|port| SocketAddr::from((Ipv4Addr::LOCALHOST, port)))?;
    let pump = Arc::downgrade(&client.connection.0);
    drop(client);
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let chunk = vec![7_u8; CHUNK];
    server
        .stream
        .set_write_timeout(Some(Duration::from_secs(1)))?;
    loop {
        match server.stream.write(&chunk) {
            Ok(_) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) => {}
            // Broken pipe: the server's pump ended with its connection.
            Err(_) => break,
        }
        assert!(
            std::time::Instant::now() < deadline,
            "the peer kept sending into a dropped connection"
        );
    }
    assert!(
        gone(&pump, Duration::from_secs(5)),
        "the pump outlived its caller"
    );
    Ok(())
}

/// A source the listener does not admit is cancelled unaccepted.
#[test]
fn unadmitted_sources_are_cancelled() -> io::Result<()> {
    let listener = Listener::start(false, |_| false)?;
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, listener.port()));
    if let Ok(mut client) = connect(address, false, Duration::from_secs(3)) {
        // The kernel may finish the handshake first: then it ends.
        client
            .stream
            .set_read_timeout(Some(Duration::from_secs(5)))?;
        let mut byte = [0_u8; 1];
        assert!(!matches!(client.stream.read(&mut byte), Ok(1..)));
        assert!(!matches!(
            client.stream.read(&mut byte).map_err(|error| error.kind()),
            Err(io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
        ));
    }
    assert_eq!(
        listener
            .accept(Duration::from_millis(500))
            .map(|_| ())
            .map_err(|error| error.kind()),
        Err(io::ErrorKind::TimedOut)
    );
    Ok(())
}

/// Connections beyond the caller's backlog are cancelled, not queued.
#[test]
fn a_full_backlog_refuses() -> io::Result<()> {
    let listener = Listener::start(false, |_| true)?;
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, listener.port()));
    let mut clients = Vec::new();
    for _ in 0..=BACKLOG {
        let client = connect(address, false, WAIT)?;
        client.stream.set_nonblocking(true)?;
        clients.push(client);
    }
    // Nothing accepted yet: once every server side is ready, one of them
    // found the backlog full and ended.
    let ended = |clients: &[Bridged]| {
        clients
            .iter()
            .filter(|client| {
                let mut byte = [0_u8; 1];
                !matches!(
                    (&client.stream)
                        .read(&mut byte)
                        .map_err(|error| error.kind()),
                    Err(io::ErrorKind::WouldBlock)
                )
            })
            .count()
    };
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while ended(&clients) == 0 && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(50));
    }
    let mut accepted = Vec::new();
    while let Ok(server) = listener.accept(Duration::from_secs(1)) {
        accepted.push(server);
    }
    assert_eq!(accepted.len(), BACKLOG);
    assert_eq!(ended(&clients), 1);
    Ok(())
}

#[test]
fn ready_slots_are_bounded() {
    let pending = Arc::new(AtomicUsize::new(0));
    let mut slots: Vec<Slot> = (0..BACKLOG).filter_map(|_| Slot::take(&pending)).collect();
    assert_eq!(slots.len(), BACKLOG);
    assert!(Slot::take(&pending).is_none());
    slots.pop();
    assert!(Slot::take(&pending).is_some());
    drop(slots);
    assert_eq!(pending.load(Ordering::Acquire), 0);
}
