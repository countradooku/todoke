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
