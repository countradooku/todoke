//! Two cores in one process, as two devices: pairing by code, a folder
//! sent and accepted, files and receipt checked. Discovery goes through a
//! shared folder and the LAN policy allows loopback (development only).

use core::time::Duration;
use std::path::{Path, PathBuf};

use super::*;
use crate::api::{ErrorCode, Event, Request, Response};
use crate::config::{CoreConfig, LanSettings};
use crate::profile::tests::Scratch;
use crate::storage_key::KeyFile;

type AnyResult<T> = Result<T, Box<dyn std::error::Error>>;

fn device(root: &Path, name: &str, discovery: &Path) -> AnyResult<Core> {
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
    };
    std::fs::create_dir_all(root.join(name))?;
    let key = KeyFile::new(root.join(name).join("storage.key"));
    Ok(Core::start(config, Box::new(key))?)
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
    send_again_in_the_session(&scratch.0, &source, &alice, &bob, &alice_hex).await?;
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
