use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use super::*;
use crate::race::RaceConfig;

type TestResult = Result<(), Box<dyn std::error::Error>>;

async fn read_exact(link: &mut TcpLink, out: &mut [u8]) -> io::Result<()> {
    let mut filled = 0;
    while filled < out.len() {
        let read =
            core::future::poll_fn(|cx| Pin::new(&mut *link).poll_read(cx, &mut out[filled..]))
                .await?;
        if read == 0 {
            return Err(io::ErrorKind::UnexpectedEof.into());
        }
        filled += read;
    }
    Ok(())
}

async fn write_all(link: &mut TcpLink, mut data: &[u8]) -> io::Result<()> {
    while !data.is_empty() {
        let written = core::future::poll_fn(|cx| Pin::new(&mut *link).poll_write(cx, data)).await?;
        data = &data[written..];
    }
    core::future::poll_fn(|cx| Pin::new(&mut *link).poll_flush(cx)).await
}

/// Loopback is refused by the real policy and allowed by the test one.
#[tokio::test]
async fn links_carry_bytes_both_ways_on_loopback() -> TestResult {
    let policy = LanPolicy::new().with_loopback();
    let listener = LanListener::bind(0, policy)?;
    let port = listener.port()?;
    let connector = TcpConnector::new(policy);
    let candidate = Candidate::new(LinkKind::Lan, SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
    let (client, server) = tokio::join!(connector.connect(candidate), listener.accept());
    let (mut client, mut server) = (client?, server?);
    assert!(client.stream.nodelay()?);
    assert!(server.stream.nodelay()?);
    assert_eq!(client.info().kind(), LinkKind::Lan);
    assert!(client.info().latency().is_some());
    assert_eq!(client.info().remote().map(|a| a.port()), Some(port));
    let payload: Vec<u8> = (0..200_000_u32).map(|n| n.to_le_bytes()[0]).collect();
    let (written, read) = tokio::join!(write_all(&mut client, &payload), async {
        let mut out = vec![0; payload.len()];
        read_exact(&mut server, &mut out).await.map(|()| out)
    });
    written?;
    assert_eq!(read?, payload);
    write_all(&mut server, b"pong").await?;
    let mut reply = [0; 4];
    read_exact(&mut client, &mut reply).await?;
    assert_eq!(&reply, b"pong");
    // Closing one end is end-of-stream at the other.
    core::future::poll_fn(|cx| Pin::new(&mut client).poll_close(cx)).await?;
    let mut rest = [0; 1];
    assert_eq!(
        core::future::poll_fn(|cx| Pin::new(&mut server).poll_read(cx, &mut rest)).await?,
        0
    );
    Ok(())
}

/// The listener takes IPv6 and IPv4 on one port (IPv4 alone where the
/// system has no IPv6).
#[tokio::test]
async fn the_listener_is_dual_stack() -> TestResult {
    let policy = LanPolicy::new().with_loopback();
    let listener = LanListener::bind(0, policy)?;
    let port = listener.port()?;
    let connector = TcpConnector::new(policy);
    // Some systems (containers, mostly) have no IPv6 at all.
    let ipv6 = std::net::TcpListener::bind((Ipv6Addr::LOCALHOST, 0)).is_ok();
    let mut ips = vec![std::net::IpAddr::from(Ipv4Addr::LOCALHOST)];
    if ipv6 {
        ips.push(std::net::IpAddr::from(Ipv6Addr::LOCALHOST));
    }
    for ip in ips {
        let candidate = Candidate::new(LinkKind::Lan, SocketAddr::from((ip, port)));
        let (client, server) = tokio::join!(connector.connect(candidate), listener.accept());
        assert!(client.is_ok() && server.is_ok(), "{ip}");
    }
    Ok(())
}

#[tokio::test]
async fn policy_refusals_send_nothing() -> TestResult {
    let connector = TcpConnector::default();
    for address in [
        SocketAddr::from((Ipv4Addr::LOCALHOST, 45_000)),
        SocketAddr::from(([8, 8, 8, 8], 45_000)),
        SocketAddr::from(([192, 168, 1, 1], 80)),
    ] {
        let refused = connector
            .connect(Candidate::new(LinkKind::Lan, address))
            .await;
        assert_eq!(
            refused.map(|_| ()).map_err(|error| error.kind()),
            Err(io::ErrorKind::PermissionDenied),
            "{address}"
        );
    }
    Ok(())
}

/// A listener under the real policy drops a loopback connection unread
/// and keeps accepting.
#[tokio::test]
async fn the_listener_drops_sources_outside_the_policy() -> TestResult {
    let listener = LanListener::bind(0, LanPolicy::new())?;
    let port = listener.port()?;
    let mut client = TcpStream::connect((Ipv4Addr::LOCALHOST, port)).await?;
    let accepted = tokio::time::timeout(Duration::from_millis(300), listener.accept()).await;
    assert!(accepted.is_err(), "a refused source was accepted");
    // The refused connection was closed.
    let mut byte = [0; 1];
    let read = tokio::time::timeout(
        Duration::from_secs(5),
        tokio::io::AsyncReadExt::read(&mut client, &mut byte),
    )
    .await?;
    assert!(matches!(read, Ok(0) | Err(_)));
    Ok(())
}

/// Racing real TCP candidates: a refused port loses to a listening one.
#[tokio::test]
async fn tcp_candidates_race() -> TestResult {
    let policy = LanPolicy::new().with_loopback();
    let listener = LanListener::bind(0, policy)?;
    let port = listener.port()?;
    // A port that was just free: connecting to it is refused.
    let closed = {
        let probe = std::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        probe.local_addr()?.port()
    };
    let candidates = [
        Candidate::new(
            LinkKind::Lan,
            SocketAddr::from((Ipv4Addr::LOCALHOST, closed)),
        ),
        Candidate::new(LinkKind::Lan, SocketAddr::from((Ipv4Addr::LOCALHOST, port))),
    ];
    let connector = TcpConnector::new(policy);
    let config = RaceConfig::default();
    let (link, accepted) = tokio::join!(
        crate::race::race(&connector, &candidates, &config),
        listener.accept()
    );
    assert_eq!(link?.info().remote().map(|a| a.port()), Some(port));
    accepted?;
    Ok(())
}

#[test]
fn debug_output_hides_addresses() -> TestResult {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    runtime.block_on(async {
        let policy = LanPolicy::new().with_loopback();
        let listener = LanListener::bind(0, policy)?;
        let port = listener.port()?;
        let candidate =
            Candidate::new(LinkKind::Lan, SocketAddr::from((Ipv4Addr::LOCALHOST, port)));
        let connector = TcpConnector::new(policy);
        let (client, _server) = tokio::join!(connector.connect(candidate), listener.accept());
        let shown = format!("{:?}", client?);
        assert!(!shown.contains("127.0.0.1"), "{shown}");
        Ok::<_, Box<dyn std::error::Error>>(())
    })
}

/// R3: a candidate of another link kind is refused before any packet,
/// even at an address the policy allows.
#[tokio::test]
async fn only_lan_candidates_are_connected() -> TestResult {
    let policy = LanPolicy::new().with_loopback();
    let listener = LanListener::bind(0, policy)?;
    let address = SocketAddr::from((Ipv4Addr::LOCALHOST, listener.port()?));
    let refused = TcpConnector::new(policy)
        .connect(Candidate::new(LinkKind::Simulated, address))
        .await;
    assert_eq!(
        refused.map(|_| ()).map_err(|error| error.kind()),
        Err(io::ErrorKind::Unsupported)
    );
    let accepted = tokio::time::timeout(Duration::from_millis(200), listener.accept()).await;
    assert!(accepted.is_err(), "a refused candidate was connected");
    Ok(())
}

/// R3: vectored writes reach the far end in order.
#[tokio::test]
async fn vectored_writes_carry_every_slice() -> TestResult {
    let policy = LanPolicy::new().with_loopback();
    let listener = LanListener::bind(0, policy)?;
    let candidate = Candidate::new(
        LinkKind::Lan,
        SocketAddr::from((Ipv4Addr::LOCALHOST, listener.port()?)),
    );
    let connector = TcpConnector::new(policy);
    let (client, server) = tokio::join!(connector.connect(candidate), listener.accept());
    let (mut client, mut server) = (client?, server?);
    let expected = b"vectored write".to_vec();
    let (mut first, mut second): (&[u8], &[u8]) = (b"vectored ", b"write");
    while !first.is_empty() || !second.is_empty() {
        let slices = [io::IoSlice::new(first), io::IoSlice::new(second)];
        let written =
            core::future::poll_fn(|cx| Pin::new(&mut client).poll_write_vectored(cx, &slices))
                .await?;
        assert_ne!(written, 0);
        let from_first = written.min(first.len());
        first = &first[from_first..];
        second = &second[written - from_first..];
    }
    core::future::poll_fn(|cx| Pin::new(&mut client).poll_flush(cx)).await?;
    let mut out = vec![0; expected.len()];
    read_exact(&mut server, &mut out).await?;
    assert_eq!(out, expected);
    Ok(())
}

/// A port another listener holds is refused, never shared: when another
/// socket holds its IPv6 side only, binding it does not fall back to the
/// free IPv4 side (where connections would reach us or it by address
/// family). On Windows the exclusive claim refuses it.
#[tokio::test]
async fn a_taken_port_is_refused_not_shared() -> TestResult {
    let other = Socket::new(Domain::IPV6, Type::STREAM, Some(Protocol::TCP))?;
    other.set_only_v6(true)?;
    other.bind(&SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)).into())?;
    other.listen(1)?;
    let port = other
        .local_addr()?
        .as_socket()
        .ok_or("no socket address")?
        .port();
    let ours = LanListener::bind(port, LanPolicy::new().with_loopback());
    // Windows may report the exclusive claim's refusal as access denied.
    assert!(
        matches!(
            ours.as_ref().map_err(io::Error::kind),
            Err(io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied)
        ),
        "{:?}",
        ours.map(|listener| listener.port().ok())
    );
    Ok(())
}

/// Nobody binds the port's IPv4 side beside a listener (on Windows, the
/// exclusive claim refuses it; elsewhere the dual-stack socket holds it).
#[tokio::test]
async fn nobody_binds_beside_a_listener() -> TestResult {
    let ours = LanListener::bind(0, LanPolicy::new().with_loopback())?;
    let port = ours.port()?;
    let other = std::net::TcpListener::bind((Ipv4Addr::UNSPECIFIED, port));
    assert!(other.is_err(), "{other:?}");
    Ok(())
}

/// A direct link (§10.2): the host listens on its address on the link
/// only, the joiner connects from its own, and both ends are `Direct`
/// links (preferred over the LAN), the joiner's leaving from the given
/// address. The policy still decides where the joiner may connect.
#[tokio::test]
async fn direct_links_listen_and_connect_on_the_link_address() -> TestResult {
    let policy = LanPolicy::new().with_loopback();
    let bound = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let record = {
        let bound = std::sync::Arc::clone(&bound);
        move |handle: i64| {
            if let Ok(mut bound) = bound.lock() {
                bound.push(handle);
            }
            Ok(())
        }
    };
    let host = LanListener::bind_direct((Ipv4Addr::LOCALHOST, 0).into(), policy, Some(&record))?;
    let port = host.port()?;
    let accepting = tokio::spawn(async move { host.accept().await });
    let joiner = TcpConnector::new(policy)
        .connect_direct(
            Ipv4Addr::LOCALHOST.into(),
            (Ipv4Addr::LOCALHOST, port).into(),
            Some(&record),
        )
        .await?;
    let accepted = accepting.await??;
    assert_eq!(joiner.info().kind(), LinkKind::Direct);
    assert_eq!(accepted.info().kind(), LinkKind::Direct);
    assert_eq!(
        joiner.info().local().map(|address| address.ip()),
        Some(Ipv4Addr::LOCALHOST.into())
    );
    assert!(LinkKind::Direct.rank() > LinkKind::Lan.rank());
    // Without loopback in the policy, the same host address is refused
    // before any packet.
    let refused = TcpConnector::new(LanPolicy::new())
        .connect_direct(
            Ipv4Addr::LOCALHOST.into(),
            (Ipv4Addr::LOCALHOST, port).into(),
            Some(&record),
        )
        .await;
    assert_eq!(
        refused.map(|_| ()).map_err(|error| error.kind()),
        Err(io::ErrorKind::PermissionDenied)
    );
    // The listener's and the joiner's sockets were bound to the link, each
    // once and before use; the refused one never reached it.
    let bound = bound.lock().map(|bound| bound.clone()).unwrap_or_default();
    assert_eq!(bound.len(), 2, "{bound:?}");
    assert!(bound.iter().all(|handle| *handle >= 0));
    Ok(())
}

/// A direct link whose address is not known yet (a Wi-Fi Aware data
/// path): the listener takes only link-local IPv6 peers on its interfaces,
/// so a peer anywhere else (loopback here, allowed by the policy) is
/// dropped unread; it needs at least one real interface.
#[tokio::test]
async fn scoped_direct_listeners_take_only_their_interfaces() -> TestResult {
    let policy = LanPolicy::new().with_loopback();
    for scopes in [vec![], vec![0], vec![3, 0]] {
        assert_eq!(
            LanListener::bind_direct_scoped(scopes, policy, None)
                .map(|_| ())
                .map_err(|error| error.kind()),
            Err(io::ErrorKind::InvalidInput)
        );
    }
    let listener = LanListener::bind_direct_scoped(vec![7, 9], policy, None)?;
    let link_local = |scope| {
        SocketAddr::V6(std::net::SocketAddrV6::new(
            Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1),
            40_000,
            0,
            scope,
        ))
    };
    assert!(listener.in_scope(link_local(7)));
    assert!(listener.in_scope(link_local(9)));
    assert!(!listener.in_scope(link_local(8)));
    assert!(!listener.in_scope(link_local(0)));
    assert!(!listener.in_scope((Ipv6Addr::LOCALHOST, 40_000).into()));
    assert!(!listener.in_scope((Ipv4Addr::new(192, 168, 49, 2), 40_000).into()));
    let unique_local = SocketAddr::V6(std::net::SocketAddrV6::new(
        Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1),
        40_000,
        0,
        7,
    ));
    assert!(!listener.in_scope(unique_local));
    let port = listener.port()?;
    let _client = TcpStream::connect((Ipv6Addr::LOCALHOST, port)).await?;
    let accepted = tokio::time::timeout(Duration::from_millis(300), listener.accept()).await;
    assert!(accepted.is_err(), "a peer off the link was accepted");
    // Plain listeners take any source the policy allows.
    let plain = LanListener::bind_direct((Ipv4Addr::LOCALHOST, 0).into(), policy, None)?;
    assert!(plain.in_scope((Ipv4Addr::LOCALHOST, 40_000).into()));
    Ok(())
}

/// Apple peer-to-peer Wi-Fi's path, over loopback: the LAN listener also
/// takes connections Network.framework accepts, bridged, and they carry
/// bytes both ways as LAN links; the policy still decides who may connect.
#[cfg(any(target_os = "macos", target_os = "ios"))]
#[tokio::test(flavor = "multi_thread")]
async fn peer_to_peer_links_are_lan_links() -> TestResult {
    let policy = LanPolicy::new().with_loopback();
    let listener = LanListener::bind(0, policy)?.with_peer_to_peer()?;
    let port = listener.peer_to_peer_port().ok_or("no peer-to-peer port")?;
    assert_ne!(port, listener.port()?);
    let accepting = tokio::spawn(async move {
        let link = listener.accept().await;
        (listener, link)
    });
    let mut client = crate::peer_to_peer::connect((Ipv4Addr::LOCALHOST, port).into()).await?;
    let (listener, server) = accepting.await?;
    let mut server = server?;
    for link in [&client, &server] {
        assert_eq!(link.info().kind(), LinkKind::Lan);
        assert!(link.info().remote().is_some_and(|remote| remote.ip().is_loopback()));
    }
    write_all(&mut client, b"hello over p2p").await?;
    let mut got = [0_u8; 14];
    read_exact(&mut server, &mut got).await?;
    assert_eq!(&got, b"hello over p2p");
    write_all(&mut server, b"back").await?;
    let mut back = [0_u8; 4];
    read_exact(&mut client, &mut back).await?;
    assert_eq!(&back, b"back");
    // Under the real policy, loopback may not connect: dropped unread.
    drop(listener);
    let strict = LanListener::bind(0, LanPolicy::new())?.with_peer_to_peer()?;
    let strict_port = strict.peer_to_peer_port().ok_or("no peer-to-peer port")?;
    let _refused = crate::peer_to_peer::connect((Ipv4Addr::LOCALHOST, strict_port).into()).await?;
    let accepted = tokio::time::timeout(Duration::from_millis(500), strict.accept()).await;
    assert!(accepted.is_err(), "a refused source was accepted");
    // Plain listeners have no peer-to-peer side; addresses off the
    // peer-to-peer interfaces are not reached through it.
    assert_eq!(LanListener::bind(0, policy)?.peer_to_peer_port(), None);
    assert!(!crate::peer_to_peer::reaches((Ipv6Addr::LOCALHOST, 1).into()));
    Ok(())
}
