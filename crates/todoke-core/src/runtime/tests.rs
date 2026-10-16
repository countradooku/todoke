//! Two cores in one process, as two devices: pairing by code, a folder
//! sent and accepted, files and receipt checked. Discovery goes through a
//! shared folder and the LAN policy allows loopback (development only).

use core::time::Duration;
use std::path::{Path, PathBuf};

use super::*;
use crate::api::{ErrorCode, Event, Request, Response, TransferState};
use crate::config::{CoreConfig, LanSettings};
use crate::profile::tests::Scratch;
use crate::storage_key::KeyFile;

type AnyResult<T> = Result<T, Box<dyn std::error::Error>>;

fn device(root: &Path, name: &str, discovery: &Path) -> AnyResult<Core> {
    device_with_links(root, name, discovery, None)
}

fn device_with_links(
    root: &Path,
    name: &str,
    discovery: &Path,
    links: Option<std::sync::Arc<dyn crate::link::LinkPlatform>>,
) -> AnyResult<Core> {
    let state = root.join(name).join("state");
    let config = CoreConfig {
        state_dir: state.clone(),
        downloads_dir: root.join(name).join("downloads"),
        lan: LanSettings {
            enabled: true,
            port: 0,
            allow_loopback: true,
        },
        discovery_folder: Some(discovery.to_owned()),
        relays: Vec::new(),
        relay_presence_seconds: 300,
        hidden: false,
        history_days: 30,
        key_storage: crate::config::KeyStorage::File,
        direct_links: if links.is_some() {
            crate::link::DirectLinks::Always
        } else {
            crate::link::DirectLinks::FromRelay
        },
    };
    std::fs::create_dir_all(root.join(name))?;
    let key = KeyFile::new(root.join(name).join("storage.key"));
    Ok(Core::start_with_links(config, Box::new(key), links)?)
}

/// Waits for an event matching `pick`.
async fn wait_for<T>(
    events: &mut broadcast::Receiver<Event>,
    mut pick: impl FnMut(&Event) -> Option<T>,
) -> AnyResult<T> {
    let found = tokio::time::timeout(Duration::from_secs(60), async {
        loop {
            match events.recv().await {
                Ok(event) => {
                    if let Some(found) = pick(&event) {
                        return Ok(found);
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {}
                Err(error) => return Err(error),
            }
        }
    })
    .await??;
    Ok(found)
}

async fn device_hex(core: &Core) -> AnyResult<String> {
    match core.request(Request::Status).await {
        Response::Status(status) => Ok(status.device),
        other => Err(format!("{other:?}").into()),
    }
}

/// Pairs `entrant` with `displayer` by code.
async fn pair(displayer: &Core, entrant: &Core) -> AnyResult<()> {
    let Response::Code { code, .. } = displayer.request(Request::PairShowCode).await else {
        return Err("no code".into());
    };
    // An advertisement shown before this one disappears within a tick or
    // two; wait until only this one is left.
    tokio::time::sleep(Duration::from_millis(1200)).await;
    let stranger = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Response::Strangers(strangers) = entrant.request(Request::Strangers).await
                && let [only] = strangers.as_slice()
            {
                return only.stranger.clone();
            }
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await?;
    match entrant
        .request(Request::PairEnterCode { code, stranger })
        .await
    {
        Response::Paired { .. } => Ok(()),
        other => Err(format!("pairing failed: {other:?}").into()),
    }
}

fn write_tree(root: &Path) -> AnyResult<Vec<(PathBuf, Vec<u8>)>> {
    let files = vec![
        (
            PathBuf::from("album/one.bin"),
            (0..200_000_u32).map(|n| (n % 251) as u8).collect(),
        ),
        (PathBuf::from("album/deep/two.txt"), b"hello".to_vec()),
        (PathBuf::from("album/empty"), Vec::new()),
    ];
    for (path, bytes) in &files {
        let full = root.join(path);
        std::fs::create_dir_all(full.parent().ok_or("parent")?)?;
        std::fs::write(full, bytes)?;
    }
    Ok(files)
}

/// A QR offer replaced by a code offer can no longer pair, even while
/// `displayer` advertises for pairing.
async fn a_replaced_qr_offer_cannot_pair(displayer: &Core, scanner: &Core) -> AnyResult<()> {
    let Response::Qr { text, .. } = displayer.request(Request::PairShowQr).await else {
        return Err("no QR offer".into());
    };
    let Response::Code { .. } = displayer.request(Request::PairShowCode).await else {
        return Err("no code offer".into());
    };
    tokio::time::timeout(Duration::from_secs(30), async {
        while !matches!(
            scanner.request(Request::Strangers).await,
            Response::Strangers(list) if !list.is_empty()
        ) {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await?;
    assert!(matches!(
        scanner.request(Request::PairScanQr { text }).await,
        Response::Error { .. }
    ));
    Ok(())
}

/// A second offer while the session is still open is served from the
/// same source as the first.
async fn send_again_in_the_session(
    root: &Path,
    source: &Path,
    alice: &Core,
    bob: &Core,
    alice_hex: &str,
) -> AnyResult<()> {
    let mut alice_events = alice.subscribe();
    let mut bob_events = bob.subscribe();
    std::fs::write(source.join("later.txt"), b"sent later")?;
    let Response::Offered {
        transfer: second, ..
    } = bob
        .request(Request::Send {
            contact: alice_hex[..12].to_owned(),
            paths: vec![source.join("later.txt")],
        })
        .await
    else {
        return Err("the second send was not offered".into());
    };
    wait_for(&mut alice_events, |event| match event {
        Event::OfferReceived(offer) if offer.transfer == second => Some(()),
        _ => None,
    })
    .await?;
    assert_eq!(
        alice
            .request(Request::Accept {
                transfer: second.clone(),
                files: None,
            })
            .await,
        Response::Done
    );
    wait_for(&mut bob_events, |event| match event {
        Event::Delivered { transfer: done } if *done == second => Some(Ok(())),
        Event::Ended {
            transfer: ended,
            reason,
            message,
        } if *ended == second && reason.is_finished() => Some(Err(format!(
            "the second transfer ended: {reason:?} {message}"
        ))),
        _ => None,
    })
    .await??;
    assert_eq!(
        std::fs::read(root.join("alice").join("downloads").join("later.txt"))?,
        b"sent later"
    );
    Ok(())
}

#[tokio::test]
async fn two_devices_pair_by_code_and_transfer_a_folder() -> AnyResult<()> {
    let scratch = Scratch::new("two-devices")?;
    let discovery = scratch.0.join("discovery");
    let alice = device(&scratch.0, "alice", &discovery)?;
    let bob = device(&scratch.0, "bob", &discovery)?;
    let (alice_hex, bob_hex) = (device_hex(&alice).await?, device_hex(&bob).await?);
    let mut alice_events = alice.subscribe();
    let mut bob_events = bob.subscribe();
    a_replaced_qr_offer_cannot_pair(&alice, &bob).await?;
    pair(&alice, &bob).await?;
    let paired = wait_for(&mut alice_events, |event| match event {
        Event::Paired { contact } => Some(contact.clone()),
        _ => None,
    })
    .await?;
    assert_eq!(paired, bob_hex);
    let Response::Contacts(contacts) = bob.request(Request::Contacts).await else {
        return Err("contacts".into());
    };
    assert_eq!(contacts.len(), 1);
    assert_eq!(
        contacts.first().map(|c| c.device.clone()),
        Some(alice_hex.clone())
    );

    // Bob sends a folder; Alice accepts it.
    let source = scratch.0.join("to-send");
    let files = write_tree(&source)?;
    let Response::Offered { transfer, skipped } = bob
        .request(Request::Send {
            contact: alice_hex[..12].to_owned(),
            paths: vec![source.join("album")],
        })
        .await
    else {
        return Err("not offered".into());
    };
    let offered = wait_for(&mut alice_events, |event| match event {
        Event::OfferReceived(offer) => Some((
            offer.transfer.clone(),
            offer.entries.len(),
            offer.from.clone(),
        )),
        _ => None,
    })
    .await?;
    assert_eq!(skipped, 0);
    assert_eq!(offered.0, transfer);
    assert_eq!(offered.2, bob_hex);
    assert_eq!(offered.1, 5);
    // An interface that starts now still sees it.
    let Response::Offers(waiting) = alice.request(Request::Offers).await else {
        return Err("no offers".into());
    };
    assert_eq!(waiting.len(), 1);
    assert_eq!(waiting[0].transfer, transfer);
    assert_eq!(
        alice
            .request(Request::Accept {
                transfer: transfer[..10].to_owned(),
                files: None,
            })
            .await,
        Response::Done
    );
    wait_for(&mut alice_events, |event| match event {
        Event::Completed { transfer: done } if *done == transfer => Some(()),
        _ => None,
    })
    .await?;
    wait_for(&mut bob_events, |event| match event {
        Event::Delivered { transfer: done } if *done == transfer => Some(()),
        _ => None,
    })
    .await?;
    for (path, bytes) in &files {
        let received = std::fs::read(scratch.0.join("alice").join("downloads").join(path))?;
        assert_eq!(&received, bytes, "{}", path.display());
    }
    // The session is on the LAN.
    let Response::Contacts(contacts) = bob.request(Request::Contacts).await else {
        return Err("contacts".into());
    };
    assert_eq!(
        contacts.first().and_then(|c| c.route),
        Some(crate::api::Route::Lan)
    );
    history_matches(&alice, &bob, &transfer).await?;
    hiding_withdraws_the_advertisement(&bob, &discovery).await?;
    // In the background (§10.3) Bob still sends in the open session.
    let port = background(&bob, &discovery, true, None).await?;
    send_again_in_the_session(&scratch.0, &source, &alice, &bob, &alice_hex).await?;
    background(&bob, &discovery, false, port).await?;
    // A second request for the same transfer is refused: it is finished.
    assert!(matches!(
        alice
            .request(Request::Decline {
                transfer: transfer.clone(),
            })
            .await,
        Response::Error { .. }
    ));
    let _ = ErrorCode::State;
    Ok(())
}

/// Back from the background with its old port taken meanwhile by another
/// listener (with the same options, so the clash is real everywhere), the
/// listener reopens on a fresh port, which discovery then advertises.
#[tokio::test]
async fn the_listener_reopens_elsewhere_if_its_port_was_taken() -> AnyResult<()> {
    let scratch = Scratch::new("reopen")?;
    let discovery = scratch.0.join("discovery");
    let core = device(&scratch.0, "solo", &discovery)?;
    let port = || async {
        match core.request(Request::Status).await {
            Response::Status(status) => Ok(status.port),
            _ => Err("status"),
        }
    };
    let before = port().await?.ok_or("no listener")?;
    let background = |background| core.request(Request::SetBackground { background });
    assert_eq!(background(true).await, Response::Done);
    // The core loop lets go of the listener on its next turn. The port is
    // taken with the listener's own socket options (dual stack, address
    // reuse), so the clash is the same on every platform.
    let squatter = {
        let mut taken = None;
        for _ in 0..50 {
            taken = todoke_transport::LanListener::bind(
                before,
                todoke_transport::LanPolicy::new().with_loopback(),
            )
            .ok();
            if taken.is_some() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        taken.ok_or("the old port never closed")?
    };
    assert_eq!(background(false).await, Response::Done);
    let after = port().await?.ok_or("no listener after the background")?;
    assert_ne!(after, before);
    assert!(
        std::net::TcpStream::connect_timeout(
            &(std::net::Ipv4Addr::LOCALHOST, after).into(),
            Duration::from_secs(1),
        )
        .is_ok()
    );
    // A code offer's stranger record names the new port.
    assert!(matches!(
        core.request(Request::PairShowCode).await,
        Response::Code { .. }
    ));
    let advertised = || -> AnyResult<bool> {
        Ok(std::fs::read_dir(&discovery)?
            .filter_map(Result::ok)
            .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "rec"))
            .filter_map(|entry| std::fs::read_to_string(entry.path()).ok())
            .any(|record| record.starts_with(&format!("{after} "))))
    };
    let mut found = false;
    for _ in 0..30 {
        if advertised()? {
            found = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    assert!(found, "the new port is not advertised");
    drop(squatter);
    Ok(())
}

/// How many strangers `core` sees.
async fn strangers_seen(core: &Core) -> usize {
    match core.request(Request::Strangers).await {
        Response::Strangers(list) => list.len(),
        _ => 0,
    }
}

/// Two QR pairings in one room at once (§3.1, §9): each scanner sees the
/// other displayer first, recognises its own by the QR's stranger token,
/// and pairs with it.
#[tokio::test]
async fn two_qr_pairings_in_one_room_reach_their_own_displayers() -> AnyResult<()> {
    let scratch = Scratch::new("two-qr-pairings")?;
    let discovery = scratch.0.join("discovery");
    let first = device(&scratch.0, "first", &discovery)?;
    let second = device(&scratch.0, "second", &discovery)?;
    let first_scanner = device(&scratch.0, "first-scanner", &discovery)?;
    let second_scanner = device(&scratch.0, "second-scanner", &discovery)?;
    let (first_hex, second_hex) = (device_hex(&first).await?, device_hex(&second).await?);

    // The second displayer shows its QR first and both scanners see it.
    let Response::Qr {
        text: second_qr, ..
    } = second.request(Request::PairShowQr).await
    else {
        return Err("no second QR offer".into());
    };
    tokio::time::timeout(Duration::from_secs(30), async {
        while strangers_seen(&first_scanner).await == 0
            || strangers_seen(&second_scanner).await == 0
        {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await?;
    // The first shows its QR, and both are scanned at once, before
    // anyone could see the first's advertisement.
    let Response::Qr { text: first_qr, .. } = first.request(Request::PairShowQr).await else {
        return Err("no first QR offer".into());
    };
    let (first_paired, second_paired) = tokio::join!(
        first_scanner.request(Request::PairScanQr { text: first_qr }),
        second_scanner.request(Request::PairScanQr { text: second_qr }),
    );
    assert_eq!(
        first_paired,
        Response::Paired {
            contact: first_hex.clone()
        }
    );
    assert_eq!(
        second_paired,
        Response::Paired {
            contact: second_hex.clone()
        }
    );
    // Each displayer paired with its own scanner only.
    for (displayer, scanner) in [(&first, &first_scanner), (&second, &second_scanner)] {
        let Response::Contacts(contacts) = displayer.request(Request::Contacts).await else {
            return Err("contacts".into());
        };
        let devices: Vec<_> = contacts.into_iter().map(|c| c.device).collect();
        assert_eq!(devices, vec![device_hex(scanner).await?]);
    }
    Ok(())
}

/// A listener that counts the connections it is offered and drops them.
async fn decoy() -> AnyResult<(u16, std::sync::Arc<core::sync::atomic::AtomicUsize>)> {
    let listener = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let port = listener.local_addr()?.port();
    let dialed = std::sync::Arc::new(core::sync::atomic::AtomicUsize::new(0));
    let count = std::sync::Arc::clone(&dialed);
    tokio::spawn(async move {
        while listener.accept().await.is_ok() {
            count.fetch_add(1, core::sync::atomic::Ordering::SeqCst);
        }
    });
    Ok((port, dialed))
}

/// §9: a QR scan sends its `ClientHello` only to advertisements carrying
/// the QR's stranger token. A stranger with another token is never
/// dialed; one that copied the displayer's token is dialed at most once
/// and cannot keep the scanner from its displayer.
#[tokio::test]
async fn a_qr_scan_dials_only_its_displayers_token() -> AnyResult<()> {
    let scratch = Scratch::new("qr-token-only")?;
    let discovery = scratch.0.join("discovery");
    let displayer = device(&scratch.0, "displayer", &discovery)?;
    let scanner = device(&scratch.0, "scanner", &discovery)?;
    let (other_port, other_dialed) = decoy().await?;
    let (copy_port, copy_dialed) = decoy().await?;
    let other = todoke_proto::discovery::DiscoveryRecord::new(
        todoke_proto::discovery::DiscoveryMode::Stranger,
        todoke_proto::discovery::Epoch::of(running::wall()),
        [7; 8],
    )?;
    std::fs::write(
        discovery.join("0123456789abcdef.rec"),
        format!("{other_port} {}", other.txt_value()),
    )?;
    let Response::Qr { text, .. } = displayer.request(Request::PairShowQr).await else {
        return Err("no QR offer".into());
    };
    // The displayer's own record, copied under another label and port.
    let shown = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            for entry in std::fs::read_dir(&discovery)?.filter_map(Result::ok) {
                let name = entry.file_name();
                let name = name.to_string_lossy();
                if name.ends_with(".rec") && name != "0123456789abcdef.rec" {
                    let contents = std::fs::read_to_string(entry.path())?;
                    if let Some((_, value)) = contents.split_once(' ') {
                        return Ok::<_, std::io::Error>(value.to_owned());
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await??;
    std::fs::write(
        discovery.join("fedcba9876543210.rec"),
        format!("{copy_port} {shown}"),
    )?;
    tokio::time::timeout(Duration::from_secs(30), async {
        while strangers_seen(&scanner).await < 2 {
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
    })
    .await?;
    assert_eq!(
        scanner.request(Request::PairScanQr { text }).await,
        Response::Paired {
            contact: device_hex(&displayer).await?
        }
    );
    assert_eq!(other_dialed.load(core::sync::atomic::Ordering::SeqCst), 0);
    assert!(copy_dialed.load(core::sync::atomic::Ordering::SeqCst) <= 1);
    Ok(())
}

/// Both sides keep the finished transfer in their history, naming the
/// same manifest and the same signed receipt; clearing forgets it.
async fn history_matches(alice: &Core, bob: &Core, transfer: &str) -> AnyResult<()> {
    let Response::History(received) = alice.request(Request::History).await else {
        return Err("history".into());
    };
    let Response::History(sent) = bob.request(Request::History).await else {
        return Err("history".into());
    };
    let received = received
        .iter()
        .find(|entry| entry.transfer == transfer)
        .ok_or("no received entry")?;
    let sent = sent
        .iter()
        .find(|entry| entry.transfer == transfer)
        .ok_or("no sent entry")?;
    assert_eq!(received.state, TransferState::Received);
    assert_eq!(sent.state, TransferState::Delivered);
    assert_eq!(received.names, ["album"]);
    assert_eq!(sent.names, ["album"]);
    assert_eq!(received.files, 3);
    assert!(received.manifest_hash.is_some());
    assert_eq!(received.manifest_hash, sent.manifest_hash);
    assert!(received.receipt.is_some());
    assert_eq!(received.receipt, sent.receipt);
    assert_eq!(alice.request(Request::ClearHistory).await, Response::Done);
    assert_eq!(
        alice.request(Request::History).await,
        Response::History(Vec::new())
    );
    Ok(())
}

/// A hidden device stops advertising to its contacts, and starts again.
async fn hiding_withdraws_the_advertisement(bob: &Core, discovery: &Path) -> AnyResult<()> {
    let records = || -> AnyResult<usize> {
        Ok(std::fs::read_dir(discovery)?
            .filter_map(Result::ok)
            .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "rec"))
            .count())
    };
    let settle = || tokio::time::sleep(Duration::from_millis(1500));
    assert_eq!(records()?, 2);
    let hide = |hidden| bob.request(Request::SetHidden { hidden });
    assert_eq!(hide(true).await, Response::Done);
    let Response::Status(status) = bob.request(Request::Status).await else {
        return Err("status".into());
    };
    assert!(status.hidden);
    assert_eq!(status.history_days, 30);
    settle().await;
    assert_eq!(records()?, 1);
    assert_eq!(hide(false).await, Response::Done);
    settle().await;
    assert_eq!(records()?, 2);
    Ok(())
}

/// Puts `bob` in the background (§10.3) or back: in it, its listener is
/// closed (nothing connects), it advertises nothing, and pairing is
/// refused; back, the listener reopens (on a port other than `port`) and it
/// advertises again.
/// Returns the listener's port before going to the background.
async fn background(
    bob: &Core,
    discovery: &Path,
    background: bool,
    port: Option<u16>,
) -> AnyResult<Option<u16>> {
    let records = || -> AnyResult<usize> {
        Ok(std::fs::read_dir(discovery)?
            .filter_map(Result::ok)
            .filter(|entry| entry.path().extension().is_some_and(|ext| ext == "rec"))
            .count())
    };
    let status = || async {
        match bob.request(Request::Status).await {
            Response::Status(status) => Ok(status),
            _ => Err("status"),
        }
    };
    let before = status().await?.port;
    assert_eq!(
        bob.request(Request::SetBackground { background }).await,
        Response::Done
    );
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let reachable = |port: u16| {
        std::net::TcpStream::connect_timeout(
            &(std::net::Ipv4Addr::LOCALHOST, port).into(),
            Duration::from_secs(1),
        )
        .is_ok()
    };
    if background {
        let port = before.ok_or("no listener")?;
        assert_eq!(status().await?.port, None);
        assert!(!reachable(port), "the listener is still open");
        assert_eq!(records()?, 1);
        assert!(matches!(
            bob.request(Request::PairShowQr).await,
            Response::Error {
                code: ErrorCode::Pairing,
                ..
            }
        ));
    } else {
        // A fresh port, as at start.
        let now = status().await?.port.ok_or("no listener")?;
        assert_ne!(Some(now), port);
        assert!(reachable(now));
        assert_eq!(records()?, 2);
        assert!(matches!(
            bob.request(Request::PairShowQr).await,
            Response::Qr { .. }
        ));
        assert_eq!(bob.request(Request::StopPairing).await, Response::Done);
    }
    Ok(before)
}

/// Past `MAX_FINISHED` idle transfers the oldest are forgotten; one that
/// becomes active again leaves the list, and a second idle state does not
/// count twice.
#[test]
fn idle_transfers_are_bounded() {
    use super::running::Idle;
    let id = |n: u32| {
        let mut id = [0; 16];
        id[..4].copy_from_slice(&n.to_le_bytes());
        id
    };
    let mut idle = Idle::default();
    let mut forgotten = Vec::new();
    for n in 0..300 {
        forgotten.extend(idle.update(id(n), false, true));
    }
    assert_eq!(forgotten, (0..44).map(id).collect::<Vec<_>>());
    // Interrupted, then received: idle twice, counted once.
    assert_eq!(idle.update(id(299), true, true), Vec::<[u8; 16]>::new());
    // A resumed transfer is active again; the next idle one fits.
    assert_eq!(idle.update(id(298), true, false), Vec::<[u8; 16]>::new());
    assert_eq!(idle.update(id(1000), false, true), Vec::<[u8; 16]>::new());
    assert_eq!(idle.update(id(1001), false, true), vec![id(44)]);
    idle.forget(&id(1001));
    assert_eq!(idle.update(id(1002), false, true), Vec::<[u8; 16]>::new());
}

/// One `Offers` answer lists at most 40000 entries, but always the first
/// offer, and fits one IPC message.
#[test]
fn listed_offers_are_capped() {
    use crate::api::{EntryInfo, OfferInfo};
    let offer = |n: usize, entries: usize| OfferInfo {
        transfer: format!("{n:032x}"),
        from: "aa".into(),
        entries: (0..entries)
            .map(|id| EntryInfo {
                id: u32::try_from(id + 1).unwrap_or(u32::MAX),
                parent: 0,
                directory: false,
                // The longest name §7.1 allows, in four-byte characters.
                name: "\u{1f600}".repeat(63),
                mime: "application/octet-stream".into(),
                size: u64::MAX,
            })
            .collect(),
        total_bytes: u64::MAX,
        resume: Some((1..=10_000).collect()),
    };
    let five: Vec<OfferInfo> = (0..5).map(|n| offer(n, 10_000)).collect();
    let listed = super::running::capped(five.iter());
    assert_eq!(listed.len(), 4);
    let size = serde_json::to_vec(&Response::Offers(listed)).map_or(usize::MAX, |json| json.len());
    assert!(size < 16 << 20, "{size} bytes");
    let huge = [offer(9, 50_000)];
    assert_eq!(super::running::capped(huge.iter()).len(), 1);
}

/// A queued offer expires with its lifetime and stops being served.
#[test]
fn queued_offers_expire() -> AnyResult<()> {
    use todoke_proto::time::UnixTime;
    let scratch = Scratch::new("expire")?;
    std::fs::create_dir_all(&scratch.0)?;
    std::fs::write(scratch.0.join("f"), b"x")?;
    let hasher = todoke_fs::Preparer::new(&scratch.0.join("prepared"))?;
    let created = UnixTime::new(1_800_000_000).ok_or("time")?;
    let walked = crate::send::walk(&[scratch.0.join("f")])?;
    let mut prepared = crate::send::prepare(&walked, created, &hasher)?;
    let id = *prepared.transfer_id();
    let mut queue = super::running::PeerQueue {
        source: todoke_fs::FsSource::new(&scratch.0.join("source"))?,
        prepared: Vec::new(),
        offers: Vec::new(),
    };
    prepared.install(&mut queue.source);
    queue.prepared.push(prepared);
    let at = |offset: u64| {
        UnixTime::new(created.seconds() + crate::send::OFFER_LIFETIME + offset - 1).ok_or("time")
    };
    assert_eq!(queue.expire(at(0)?), Vec::<[u8; 16]>::new());
    assert!(todoke_transfer::SendSource::open(&mut queue.source, &id, 1).is_ok());
    assert_eq!(queue.expire(at(1)?), vec![id]);
    assert!(queue.prepared.is_empty());
    assert!(todoke_transfer::SendSource::open(&mut queue.source, &id, 1).is_err());
    Ok(())
}

/// Stopping pairing is visible in the status; a decline reaches the
/// sender with its reason; an offer waiting for a session can be
/// cancelled.
#[tokio::test]
async fn declines_and_cancels_reach_both_sides() -> AnyResult<()> {
    let scratch = Scratch::new("decline")?;
    let discovery = scratch.0.join("discovery");
    let alice = device(&scratch.0, "alice", &discovery)?;
    let bob = device(&scratch.0, "bob", &discovery)?;
    let alice_hex = device_hex(&alice).await?;
    let pairing = |core: &Core| {
        let core = core.clone();
        async move {
            match core.request(Request::Status).await {
                Response::Status(status) => Ok(status.pairing),
                other => Err(format!("{other:?}")),
            }
        }
    };
    let Response::Qr { .. } = alice.request(Request::PairShowQr).await else {
        return Err("no QR offer".into());
    };
    assert!(pairing(&alice).await?);
    assert_eq!(alice.request(Request::StopPairing).await, Response::Done);
    assert!(!pairing(&alice).await?);
    pair(&alice, &bob).await?;

    std::fs::write(scratch.0.join("note.txt"), b"no thanks")?;
    let send = || {
        bob.request(Request::Send {
            contact: alice_hex[..12].to_owned(),
            paths: vec![scratch.0.join("note.txt")],
        })
    };
    let mut alice_events = alice.subscribe();
    let mut bob_events = bob.subscribe();
    let Response::Offered { transfer, .. } = send().await else {
        return Err("not offered".into());
    };
    wait_for(&mut alice_events, |event| match event {
        Event::OfferReceived(offer) if offer.transfer == transfer => Some(()),
        _ => None,
    })
    .await?;
    assert_eq!(
        alice
            .request(Request::Decline {
                transfer: transfer.clone(),
            })
            .await,
        Response::Done
    );
    let (reason, message) = wait_for(&mut bob_events, |event| match event {
        Event::Ended {
            transfer: ended,
            reason,
            message,
        } if *ended == transfer => Some((*reason, message.clone())),
        _ => None,
    })
    .await?;
    assert_eq!(reason, crate::api::TransferState::Rejected);
    assert_eq!(message, "declined");
    assert!(matches!(
        alice.request(Request::Offers).await,
        Response::Offers(list) if list.is_empty()
    ));

    // Alice goes away; Bob's next offer waits for a session, and he
    // cancels it.
    drop(alice_events);
    drop(alice);
    tokio::time::timeout(Duration::from_secs(60), async {
        while !matches!(
            bob.request(Request::Status).await,
            Response::Status(status) if status.sessions == 0
        ) {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    })
    .await?;
    let Response::Offered { transfer, .. } = send().await else {
        return Err("not offered".into());
    };
    assert_eq!(
        bob.request(Request::Cancel {
            transfer: transfer.clone(),
        })
        .await,
        Response::Done
    );
    let Response::Transfers(list) = bob.request(Request::Transfers).await else {
        return Err("no transfers".into());
    };
    assert!(list.iter().any(
        |info| info.transfer == transfer && info.state == crate::api::TransferState::Cancelled
    ));
    assert!(matches!(
        bob.request(Request::Cancel {
            transfer: "ffffffffffff".into(),
        })
        .await,
        Response::Error {
            code: ErrorCode::Invalid,
            ..
        }
    ));
    Ok(())
}

/// A relay on this runtime with a self-signed certificate, as devices
/// configure it (pinned).
fn relay() -> AnyResult<crate::config::RelayConfig> {
    let (identity, _, _) = todoke_relay::Identity::self_signed(vec!["relay.test".into()])?;
    let relay = todoke_relay::Relay::bind(
        todoke_relay::Config::new(([127, 0, 0, 1], 0).into()),
        &identity,
    )?;
    let config = crate::config::RelayConfig {
        name: "test".into(),
        address: relay.local_addr()?.to_string(),
        server_name: "relay.test".into(),
        pin: Some(todoke_relay::format_pin(&identity.pin()?)),
    };
    tokio::spawn(relay.run(std::sync::Arc::new(tokio::sync::Notify::new())));
    Ok(config)
}

/// A device with no LAN at all: only the relay.
fn remote_device(root: &Path, name: &str, relay: &crate::config::RelayConfig) -> AnyResult<Core> {
    let mut config = CoreConfig::new(
        root.join(name).join("state"),
        root.join(name).join("downloads"),
    );
    config.lan.enabled = false;
    config.relays = vec![relay.clone()];
    config.relay_presence_seconds = 10;
    std::fs::create_dir_all(root.join(name))?;
    let key = KeyFile::new(root.join(name).join("storage.key"));
    Ok(Core::start(config, Box::new(key))?)
}

/// Two devices that cannot see each other pair by QR through a relay
/// (the scanner initiates, §4), then a file goes through it: the sender
/// waits at the relay, and the receiver comes at its presence window.
#[tokio::test(flavor = "multi_thread")]
async fn two_remote_devices_pair_and_transfer_through_a_relay() -> AnyResult<()> {
    let scratch = Scratch::new("remote")?;
    let relay = relay()?;
    let alice = remote_device(&scratch.0, "alice", &relay)?;
    let bob = remote_device(&scratch.0, "bob", &relay)?;
    let alice_hex = device_hex(&alice).await?;
    let mut alice_events = alice.subscribe();
    let mut bob_events = bob.subscribe();
    let Response::Qr { text, .. } = alice.request(Request::PairShowQr).await else {
        return Err("no QR offer".into());
    };
    let paired = bob.request(Request::PairScanQr { text }).await;
    assert!(matches!(paired, Response::Paired { .. }), "{paired:?}");
    wait_for(&mut alice_events, |event| match event {
        Event::Paired { .. } => Some(()),
        _ => None,
    })
    .await?;
    std::fs::write(scratch.0.join("far.txt"), b"through the relay")?;
    let Response::Offered { transfer, .. } = bob
        .request(Request::Send {
            contact: alice_hex[..12].to_owned(),
            paths: vec![scratch.0.join("far.txt")],
        })
        .await
    else {
        return Err("not offered".into());
    };
    wait_for(&mut alice_events, |event| match event {
        Event::OfferReceived(offer) if offer.transfer == transfer => Some(()),
        _ => None,
    })
    .await?;
    // The offer came through the session, which runs over the relay.
    let Response::Contacts(contacts) = alice.request(Request::Contacts).await else {
        return Err("contacts".into());
    };
    assert_eq!(
        contacts.first().and_then(|c| c.route),
        Some(crate::api::Route::Relay)
    );
    assert_eq!(
        alice
            .request(Request::Accept {
                transfer: transfer.clone(),
                files: None,
            })
            .await,
        Response::Done
    );
    wait_for(&mut bob_events, |event| match event {
        Event::Delivered { transfer: done } if *done == transfer => Some(()),
        _ => None,
    })
    .await?;
    assert_eq!(
        std::fs::read(scratch.0.join("alice").join("downloads").join("far.txt"))?,
        b"through the relay"
    );
    Ok(())
}

/// A hidden device registers no presence at the relay (§10): two paired
/// devices that start hidden never meet over several presence windows,
/// and meet within one more period once both are visible.
#[tokio::test(flavor = "multi_thread")]
async fn hidden_devices_register_no_relay_presence() -> AnyResult<()> {
    let scratch = Scratch::new("remote-hidden")?;
    let relay = relay()?;
    let device = |name: &str| -> AnyResult<Core> {
        let mut config = CoreConfig::new(
            scratch.0.join(name).join("state"),
            scratch.0.join(name).join("downloads"),
        );
        config.lan.enabled = false;
        config.relays = vec![relay.clone()];
        // The shortest period: a window of 5 seconds every 10.
        config.relay_presence_seconds = 10;
        config.hidden = true;
        std::fs::create_dir_all(scratch.0.join(name))?;
        let key = KeyFile::new(scratch.0.join(name).join("storage.key"));
        Ok(Core::start(config, Box::new(key))?)
    };
    let alice = device("alice")?;
    let bob = device("bob")?;
    let mut alice_events = alice.subscribe();
    let Response::Qr { text, .. } = alice.request(Request::PairShowQr).await else {
        return Err("no QR offer".into());
    };
    let paired = bob.request(Request::PairScanQr { text }).await;
    assert!(matches!(paired, Response::Paired { .. }), "{paired:?}");
    wait_for(&mut alice_events, |event| match event {
        Event::Paired { .. } => Some(()),
        _ => None,
    })
    .await?;
    let route = |core: &Core| {
        let core = core.clone();
        async move {
            match core.request(Request::Contacts).await {
                Response::Contacts(contacts) => Ok(contacts.first().and_then(|c| c.route)),
                other => Err(format!("{other:?}")),
            }
        }
    };
    // More than one full period, so every pair's window has come twice.
    tokio::time::sleep(Duration::from_secs(25)).await;
    assert_eq!(route(&alice).await?, None);
    assert_eq!(route(&bob).await?, None);
    for core in [&alice, &bob] {
        assert_eq!(
            core.request(Request::SetHidden { hidden: false }).await,
            Response::Done
        );
    }
    let met = tokio::time::timeout(Duration::from_secs(40), async {
        loop {
            if route(&alice).await? == Some(crate::api::Route::Relay) {
                return Ok::<_, String>(());
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    })
    .await;
    assert!(matches!(met, Ok(Ok(()))), "{met:?}");
    Ok(())
}

/// An in-memory link that claims to be `kind`.
struct Pipe(tokio::io::DuplexStream, todoke_transport::LinkInfo);

impl todoke_transport::Link for Pipe {
    fn info(&self) -> &todoke_transport::LinkInfo {
        &self.1
    }
}

impl futures_io::AsyncRead for Pipe {
    fn poll_read(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
        buf: &mut [u8],
    ) -> core::task::Poll<std::io::Result<usize>> {
        let mut read = tokio::io::ReadBuf::new(buf);
        match tokio::io::AsyncRead::poll_read(core::pin::Pin::new(&mut self.0), cx, &mut read) {
            core::task::Poll::Ready(Ok(())) => core::task::Poll::Ready(Ok(read.filled().len())),
            core::task::Poll::Ready(Err(error)) => core::task::Poll::Ready(Err(error)),
            core::task::Poll::Pending => core::task::Poll::Pending,
        }
    }
}

impl futures_io::AsyncWrite for Pipe {
    fn poll_write(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
        buf: &[u8],
    ) -> core::task::Poll<std::io::Result<usize>> {
        tokio::io::AsyncWrite::poll_write(core::pin::Pin::new(&mut self.0), cx, buf)
    }
    fn poll_flush(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_flush(core::pin::Pin::new(&mut self.0), cx)
    }
    fn poll_close(
        mut self: core::pin::Pin<&mut Self>,
        cx: &mut core::task::Context<'_>,
    ) -> core::task::Poll<std::io::Result<()>> {
        tokio::io::AsyncWrite::poll_shutdown(core::pin::Pin::new(&mut self.0), cx)
    }
}

#[derive(Clone, Copy, Debug)]
enum Forged {
    /// A `CodeOfferRequest` for the shown code (the displayer's stranger
    /// token).
    CodeRequest,
    /// A QR-mode `ClientHello` for the shown QR offer.
    QrHello,
}

/// Whether a device showing the offer that `forged` is for answers it when
/// it arrives on a link from `origin`.
async fn answered(forged: Forged, origin: super::running::Origin) -> AnyResult<bool> {
    use tokio::io::AsyncReadExt as _;
    let scratch = Scratch::new("origin")?;
    let config = CoreConfig::new(scratch.0.join("state"), scratch.0.join("downloads"));
    let key = KeyFile::new(scratch.0.join("storage.key"));
    let (events, _) = broadcast::channel(16);
    let local = tokio::task::LocalSet::new();
    local
        .run_until(async move {
            let state = super::running::State::open(config, &key, events)?;
            let record = match forged {
                Forged::CodeRequest => {
                    assert!(matches!(
                        state.handle(Request::PairShowCode).await,
                        Response::Code { .. }
                    ));
                    let token = state.stranger_token().ok_or("no stranger token")?;
                    let request = todoke_proto::pairing::CodeOfferRequest::new(token)?;
                    todoke_proto::session::encode_prelude_record(
                        todoke_proto::session::PreludeKind::CodeOfferRequest,
                        &request.encode(),
                    )?
                }
                Forged::QrHello => {
                    let Response::Qr { text, .. } = state.handle(Request::PairShowQr).await else {
                        return Err("no QR offer".into());
                    };
                    let payload = todoke_crypto::pairing::QrPayload::from_text(
                        &text,
                        super::running::wall(),
                    )?;
                    let hello = todoke_proto::session::Hello::client(
                        todoke_proto::session::SessionMode::Qr,
                        *payload.pairing_id(),
                        [0x5e; 16],
                    )?;
                    todoke_proto::session::encode_prelude_record(
                        todoke_proto::session::PreludeKind::ClientHello,
                        &hello.encode(),
                    )?
                }
            };
            let (ours, mut theirs) = tokio::io::duplex(1 << 16);
            let link = Pipe(
                ours,
                todoke_transport::LinkInfo::new(todoke_transport::LinkKind::Relay),
            );
            tokio::io::AsyncWriteExt::write_all(&mut theirs, &record).await?;
            let running = tokio::task::spawn_local({
                let state = std::rc::Rc::clone(&state);
                async move { state.incoming(link, origin).await }
            });
            let mut chunk = [0_u8; 4096];
            // What the displayer sends back within a moment, if anything.
            let read = tokio::time::timeout(Duration::from_secs(2), theirs.read(&mut chunk)).await;
            running.abort();
            Ok::<_, Box<dyn std::error::Error>>(matches!(read, Ok(Ok(read)) if read > 0))
        })
        .await
}

/// §10, §16 O8: a relay tunnel is accepted only for what it was opened
/// for. A shown code is never reachable through a relay, a contact's
/// tunnel never carries pairing, and a QR tunnel carries QR pairing only.
#[tokio::test(flavor = "current_thread")]
async fn a_tunnel_carries_only_what_it_was_opened_for() -> AnyResult<()> {
    use super::running::Origin::{Lan, RelayContact, RelayQr};
    // Any contact key: the tunnel's purpose is what matters.
    let mut base = [0x66; 32];
    base[0] = 0x58;
    let contact = todoke_crypto::identity::Ed25519PublicKey::from_bytes(&base)?;
    assert!(answered(Forged::CodeRequest, Lan).await?);
    assert!(!answered(Forged::CodeRequest, RelayContact(contact)).await?);
    assert!(!answered(Forged::CodeRequest, RelayQr).await?);
    assert!(answered(Forged::QrHello, Lan).await?);
    assert!(answered(Forged::QrHello, RelayQr).await?);
    assert!(!answered(Forged::QrHello, RelayContact(contact)).await?);
    Ok(())
}

mod direct_link {
    //! A session moving onto a direct link (§10.2), with a platform that
    //! "brings links up" on loopback.

    use std::net::{IpAddr, Ipv4Addr};
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use super::*;
    use crate::link::{
        HostRequest, JoinRequest, LinkAbilities, LinkKind, LinkLease, LinkPlatform, LinkSecurity,
    };

    struct Teardown(Arc<AtomicUsize>);

    impl Drop for Teardown {
        fn drop(&mut self) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }

    /// Hosts a hotspot (`host`) or joins one; counts what it was asked.
    struct Loopback {
        host: bool,
        /// Joining fails (the network cannot be joined).
        fail_join: bool,
        hosted: AtomicUsize,
        joined: AtomicUsize,
        torn: Arc<AtomicUsize>,
    }

    impl Loopback {
        fn new(host: bool, torn: &Arc<AtomicUsize>) -> Arc<Self> {
            Self::failing(host, false, torn)
        }

        fn failing(host: bool, fail_join: bool, torn: &Arc<AtomicUsize>) -> Arc<Self> {
            Arc::new(Self {
                host,
                fail_join,
                hosted: AtomicUsize::new(0),
                joined: AtomicUsize::new(0),
                torn: Arc::clone(torn),
            })
        }
    }

    const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);

    /// The credentials have the hotspot shapes of §10.2.
    fn shaped(kind: LinkKind, security: LinkSecurity, ssid: &str, secret: &[u8]) -> bool {
        kind == LinkKind::Hotspot
            && security == LinkSecurity::Wpa3
            && ssid.starts_with("todoke-")
            && ssid.len() == 23
            && secret.len() == 63
    }

    impl LinkPlatform for Loopback {
        fn abilities(&self) -> LinkAbilities {
            if self.host {
                LinkAbilities::new(&[LinkKind::Hotspot], &[], &[])
            } else {
                LinkAbilities::new(
                    &[],
                    &[LinkKind::Hotspot],
                    &[LinkSecurity::Wpa3, LinkSecurity::Wpa2],
                )
            }
        }

        fn host(&self, request: &HostRequest) -> std::io::Result<LinkLease> {
            if !shaped(
                request.kind,
                request.security,
                &request.ssid,
                &request.secret,
            ) {
                return Err(std::io::ErrorKind::InvalidInput.into());
            }
            self.hosted.fetch_add(1, Ordering::SeqCst);
            Ok(LinkLease::new(
                LOOPBACK,
                None,
                0,
                Teardown(Arc::clone(&self.torn)),
            ))
        }

        fn join(&self, request: &JoinRequest) -> std::io::Result<LinkLease> {
            if !shaped(
                request.kind,
                request.security,
                &request.ssid,
                &request.secret,
            ) {
                return Err(std::io::ErrorKind::InvalidInput.into());
            }
            self.joined.fetch_add(1, Ordering::SeqCst);
            if self.fail_join {
                return Err(std::io::ErrorKind::TimedOut.into());
            }
            Ok(LinkLease::new(
                LOOPBACK,
                Some(LOOPBACK),
                0,
                Teardown(Arc::clone(&self.torn)),
            ))
        }
    }

    /// Bob sends a large file over the LAN; once Alice accepts, she hosts
    /// a link, Bob joins it, both sessions close, and Bob connects over the
    /// link: the transfer resumes there with Alice's consent kept (she is
    /// asked once) and completes intact. Both links are torn down when the
    /// devices stop.
    #[tokio::test]
    async fn a_transfer_moves_onto_a_direct_link() -> AnyResult<()> {
        let scratch = Scratch::new("direct-link")?;
        let discovery = scratch.0.join("discovery");
        let torn = Arc::new(AtomicUsize::new(0));
        let (alice_links, bob_links) = (Loopback::new(true, &torn), Loopback::new(false, &torn));
        let alice = device_with_links(
            &scratch.0,
            "alice",
            &discovery,
            Some(Arc::clone(&alice_links) as Arc<dyn LinkPlatform>),
        )?;
        let bob = device_with_links(
            &scratch.0,
            "bob",
            &discovery,
            Some(Arc::clone(&bob_links) as Arc<dyn LinkPlatform>),
        )?;
        let alice_hex = device_hex(&alice).await?;
        let mut alice_events = alice.subscribe();
        let mut bob_events = bob.subscribe();
        pair(&alice, &bob).await?;
        wait_for(&mut alice_events, |event| {
            matches!(event, Event::Paired { .. }).then_some(())
        })
        .await?;
        // Large enough to be under way when the link comes up.
        let source = scratch.0.join("to-send");
        std::fs::create_dir_all(&source)?;
        let content: Vec<u8> = (0..48 * 1024 * 1024_u32)
            .map(|n| u8::try_from(n % 251).unwrap_or(0))
            .collect();
        std::fs::write(source.join("big.bin"), &content)?;
        let Response::Offered { transfer, .. } = bob
            .request(Request::Send {
                contact: alice_hex[..12].to_owned(),
                paths: vec![source.join("big.bin")],
            })
            .await
        else {
            return Err("not offered".into());
        };
        wait_for(&mut alice_events, |event| match event {
            Event::OfferReceived(offer) if offer.transfer == transfer => Some(()),
            _ => None,
        })
        .await?;
        assert_eq!(
            alice
                .request(Request::Accept {
                    transfer: transfer.clone(),
                    files: None,
                })
                .await,
            Response::Done
        );
        wait_for(&mut bob_events, |event| match event {
            Event::Delivered { transfer: done } if *done == transfer => Some(()),
            _ => None,
        })
        .await?;
        // No second prompt on Alice's side after the move.
        let mut prompts = 0;
        while let Ok(event) = alice_events.try_recv() {
            if matches!(&event, Event::OfferReceived(offer) if offer.transfer == transfer) {
                prompts += 1;
            }
        }
        assert_eq!(prompts, 0, "alice was asked again after the move");
        assert_eq!(alice_links.hosted.load(Ordering::SeqCst), 1);
        assert_eq!(bob_links.joined.load(Ordering::SeqCst), 1);
        let Response::Contacts(contacts) = bob.request(Request::Contacts).await else {
            return Err("contacts".into());
        };
        assert_eq!(
            contacts.first().and_then(|contact| contact.route),
            Some(crate::api::Route::Direct)
        );
        assert_eq!(
            std::fs::read(scratch.0.join("alice").join("downloads").join("big.bin"))?,
            content
        );
        // Stopping the devices ends the sessions on the link: both links
        // are torn down.
        drop((alice, bob));
        assert_eq!(torn.load(Ordering::SeqCst), 2);
        Ok(())
    }

    /// Joining fails: the joiner answers `failed`, the host tears its link
    /// down at once, and the transfer completes in the session it was in.
    #[tokio::test]
    async fn a_failed_join_keeps_the_session() -> AnyResult<()> {
        let scratch = Scratch::new("direct-link-failed")?;
        let discovery = scratch.0.join("discovery");
        let torn = Arc::new(AtomicUsize::new(0));
        let alice_links = Loopback::new(true, &torn);
        let bob_links = Loopback::failing(false, true, &torn);
        let alice = device_with_links(
            &scratch.0,
            "alice",
            &discovery,
            Some(Arc::clone(&alice_links) as Arc<dyn LinkPlatform>),
        )?;
        let bob = device_with_links(
            &scratch.0,
            "bob",
            &discovery,
            Some(Arc::clone(&bob_links) as Arc<dyn LinkPlatform>),
        )?;
        let alice_hex = device_hex(&alice).await?;
        let mut alice_events = alice.subscribe();
        let mut bob_events = bob.subscribe();
        pair(&alice, &bob).await?;
        wait_for(&mut alice_events, |event| {
            matches!(event, Event::Paired { .. }).then_some(())
        })
        .await?;
        let source = scratch.0.join("to-send");
        std::fs::create_dir_all(&source)?;
        let content: Vec<u8> = (0..16 * 1024 * 1024_u32)
            .map(|n| u8::try_from(n % 241).unwrap_or(0))
            .collect();
        std::fs::write(source.join("big.bin"), &content)?;
        let Response::Offered { transfer, .. } = bob
            .request(Request::Send {
                contact: alice_hex[..12].to_owned(),
                paths: vec![source.join("big.bin")],
            })
            .await
        else {
            return Err("not offered".into());
        };
        wait_for(&mut alice_events, |event| match event {
            Event::OfferReceived(offer) if offer.transfer == transfer => Some(()),
            _ => None,
        })
        .await?;
        assert_eq!(
            alice
                .request(Request::Accept {
                    transfer: transfer.clone(),
                    files: None,
                })
                .await,
            Response::Done
        );
        wait_for(&mut bob_events, |event| match event {
            Event::Delivered { transfer: done } if *done == transfer => Some(()),
            _ => None,
        })
        .await?;
        assert_eq!(bob_links.joined.load(Ordering::SeqCst), 1);
        // The host's link went with the failed answer; nothing moved.
        assert_eq!(alice_links.hosted.load(Ordering::SeqCst), 1);
        assert_eq!(torn.load(Ordering::SeqCst), 1);
        let Response::Contacts(contacts) = bob.request(Request::Contacts).await else {
            return Err("contacts".into());
        };
        assert_eq!(
            contacts.first().and_then(|contact| contact.route),
            Some(crate::api::Route::Lan)
        );
        assert_eq!(
            std::fs::read(scratch.0.join("alice").join("downloads").join("big.bin"))?,
            content
        );
        Ok(())
    }
}
