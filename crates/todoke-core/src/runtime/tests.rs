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
    let stranger = tokio::time::timeout(Duration::from_secs(30), async {
        loop {
            if let Response::Strangers(strangers) = entrant.request(Request::Strangers).await
                && let Some(first) = strangers.into_iter().next()
            {
                return first.stranger;
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

#[tokio::test]
async fn two_devices_pair_by_code_and_transfer_a_folder() -> AnyResult<()> {
    let scratch = Scratch::new("two-devices")?;
    let discovery = scratch.0.join("discovery");
    let alice = device(&scratch.0, "alice", &discovery)?;
    let bob = device(&scratch.0, "bob", &discovery)?;
    let (alice_hex, bob_hex) = (device_hex(&alice).await?, device_hex(&bob).await?);
    let mut alice_events = alice.subscribe();
    let mut bob_events = bob.subscribe();
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
    let Response::Offered { transfer } = bob
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
