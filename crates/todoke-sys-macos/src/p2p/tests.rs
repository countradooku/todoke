use std::io::{Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr};
use std::time::Duration;

use super::*;

const WAIT: Duration = Duration::from_secs(10);

/// A listener and a connection to it on loopback, bridged both ends.
fn pair(address: impl Fn(u16) -> SocketAddr) -> io::Result<(Bridged, Bridged)> {
    let listener = Listener::start(false)?;
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
    let listener = Listener::start(false)?;
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
    let idle = Listener::start(false)?;
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
