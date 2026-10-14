//! P10 acceptance: two daemons on loopback pair by code, one sends a
//! folder, the receiver is killed half-way and restarted, the transfer
//! resumes (with a fresh Accept, §7.5), and every file and the signed
//! receipt are checked.
//!
//! `two_daemons_resume_a_folder_after_a_crash` sends 96 MiB in every test
//! run; `two_gigabytes` sends 2 GiB and runs in CI in release mode
//! (`cargo test --release -p todoke-cli --test e2e -- --ignored`).
//!
//! Discovery uses a shared folder and the LAN policy allows loopback:
//! development settings that need the `unaudited-dev` feature.

#![cfg(not(target_family = "wasm"))]

use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use todoke_core::api::{Event, OfferInfo, Request, Response};
use todoke_core::config::{CoreConfig, LanSettings, RelayConfig};
use todoke_daemon::Paths;
use todoke_daemon::ipc::{Client, Events};

type AnyResult<T> = Result<T, Box<dyn std::error::Error>>;

const MIB: u64 = 1 << 20;

struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> AnyResult<Self> {
        let mut random = [0; 8];
        getrandom::fill(&mut random)?;
        let dir =
            std::env::temp_dir().join(format!("todoke-e2e-{name}-{}", u64::from_le_bytes(random)));
        std::fs::create_dir_all(&dir)?;
        Ok(Self(dir))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// One device: its home, and its daemon process while it runs.
struct Device {
    home: PathBuf,
    process: Option<Child>,
}

impl Device {
    fn new(root: &Path, name: &str, discovery: &Path) -> AnyResult<Self> {
        let home = root.join(name);
        let paths = Paths::under(&home);
        std::fs::create_dir_all(&home)?;
        let config = CoreConfig {
            state_dir: paths.state_dir.clone(),
            downloads_dir: paths.downloads_dir.clone(),
            lan: LanSettings {
                enabled: true,
                port: 0,
                allow_loopback: true,
            },
            discovery_folder: Some(discovery.to_owned()),
            relays: Vec::new(),
            relay_presence_seconds: 300,
        };
        std::fs::write(&paths.config_file, serde_json::to_vec_pretty(&config)?)?;
        Ok(Self {
            home,
            process: None,
        })
    }

    /// A device with no LAN, only `relay` (§10).
    fn remote(root: &Path, name: &str, relay: &RelayConfig) -> AnyResult<Self> {
        let home = root.join(name);
        let paths = Paths::under(&home);
        std::fs::create_dir_all(&home)?;
        let mut config = CoreConfig::new(paths.state_dir.clone(), paths.downloads_dir.clone());
        config.lan.enabled = false;
        config.relays = vec![relay.clone()];
        config.relay_presence_seconds = 10;
        std::fs::write(&paths.config_file, serde_json::to_vec_pretty(&config)?)?;
        Ok(Self {
            home,
            process: None,
        })
    }

    fn paths(&self) -> Paths {
        Paths::under(&self.home)
    }

    async fn start(&mut self) -> AnyResult<()> {
        let child = Command::new(env!("CARGO_BIN_EXE_todoke"))
            .args(["daemon", "run"])
            .env("TODOKE_HOME", &self.home)
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()?;
        self.process = Some(child);
        let deadline = Instant::now() + Duration::from_secs(30);
        while Instant::now() < deadline {
            if Client::connect(&self.paths().endpoint()).await.is_ok() {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err("the daemon did not start".into())
    }

    /// Kills the daemon at once (SIGKILL on Unix): a crash.
    fn kill(&mut self) -> AnyResult<()> {
        if let Some(mut child) = self.process.take() {
            child.kill()?;
            child.wait()?;
        }
        Ok(())
    }

    async fn stop(&mut self) -> AnyResult<()> {
        if let Ok(client) = Client::connect(&self.paths().endpoint()).await {
            let _ = client.shutdown().await;
        }
        if let Some(mut child) = self.process.take() {
            let deadline = Instant::now() + Duration::from_secs(10);
            while Instant::now() < deadline {
                if child.try_wait()?.is_some() {
                    return Ok(());
                }
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            child.kill()?;
            child.wait()?;
        }
        Ok(())
    }

    async fn request(&self, request: Request) -> AnyResult<Response> {
        Ok(Client::connect(&self.paths().endpoint())
            .await?
            .request(request)
            .await?)
    }

    async fn events(&self) -> AnyResult<Events> {
        Ok(Client::connect(&self.paths().endpoint())
            .await?
            .subscribe()
            .await?)
    }

    async fn device(&self) -> AnyResult<String> {
        match self.request(Request::Status).await? {
            Response::Status(status) => Ok(status.device),
            other => Err(format!("{other:?}").into()),
        }
    }
}

impl Drop for Device {
    fn drop(&mut self) {
        let _ = self.kill();
    }
}

/// Waits (at most `limit`) for an event `pick` accepts; fails at once
/// when `transfer` ends for good.
async fn wait_for<T>(
    events: &mut Events,
    transfer: &str,
    limit: Duration,
    mut pick: impl FnMut(&Event) -> Option<T>,
) -> AnyResult<T> {
    let found = tokio::time::timeout(limit, async {
        while let Some(event) = events.next().await? {
            if let Event::Ended {
                transfer: ended,
                reason,
                message,
            } = &event
                && ended == transfer
                && reason.is_finished()
            {
                return Err(format!("the transfer ended: {} ({message})", reason.as_str()).into());
            }
            if let Some(found) = pick(&event) {
                return Ok(Some(found));
            }
        }
        Ok::<_, Box<dyn std::error::Error>>(None)
    })
    .await
    .map_err(|_| "timed out")??;
    found.ok_or_else(|| "the daemon stopped".into())
}

/// Waits for `transfer` to be offered to `device`, whose events are
/// `events` (subscribed first: an offer that arrived before is listed).
async fn wait_for_offer(
    device: &Device,
    events: &mut Events,
    transfer: &str,
    limit: Duration,
) -> AnyResult<OfferInfo> {
    if let Response::Offers(waiting) = device.request(Request::Offers).await?
        && let Some(offer) = waiting.into_iter().find(|offer| offer.transfer == transfer)
    {
        return Ok(offer);
    }
    wait_for(events, transfer, limit, |event| match event {
        Event::OfferReceived(offer) if offer.transfer == transfer => Some(offer.clone()),
        _ => None,
    })
    .await
}

/// The folder to send: one large file, a few small ones, an empty file,
/// and a nested folder.
fn make_folder(root: &Path, large: u64) -> AnyResult<Vec<(PathBuf, [u8; 32])>> {
    let folder = root.join("photos");
    std::fs::create_dir_all(folder.join("2026").join("october"))?;
    let mut files = Vec::new();
    // The large file, written in 1 MiB blocks of a cheap pseudo-random
    // pattern, hashed as it is written.
    {
        use std::io::Write as _;
        let path = PathBuf::from("photos/video.bin");
        let mut file = std::io::BufWriter::new(std::fs::File::create(root.join(&path))?);
        let mut hasher = blake3::Hasher::new();
        let mut state = 0x9e37_79b9_7f4a_7c15_u64;
        let mut block = vec![0_u8; usize::try_from(MIB)?];
        let mut left = large;
        while left > 0 {
            for chunk in block.as_chunks_mut::<8>().0 {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                *chunk = state.to_le_bytes();
            }
            let take = usize::try_from(left.min(MIB))?;
            file.write_all(&block[..take])?;
            hasher.update(&block[..take]);
            left -= take as u64;
        }
        file.flush()?;
        files.push((path, *hasher.finalize().as_bytes()));
    }
    for (name, contents) in [
        ("photos/2026/october/a.txt", b"first".to_vec()),
        ("photos/2026/october/b.txt", vec![7_u8; 70_000]),
        ("photos/2026/notes.md", b"# notes\n".to_vec()),
        ("photos/empty", Vec::new()),
    ] {
        std::fs::write(root.join(name), &contents)?;
        files.push((PathBuf::from(name), *blake3::hash(&contents).as_bytes()));
    }
    Ok(files)
}

fn hash_file(path: &Path) -> AnyResult<[u8; 32]> {
    let mut hasher = blake3::Hasher::new();
    hasher.update_reader(std::fs::File::open(path)?)?;
    Ok(*hasher.finalize().as_bytes())
}

async fn pair(displayer: &Device, entrant: &Device) -> AnyResult<()> {
    let Response::Code { code, .. } = displayer.request(Request::PairShowCode).await? else {
        return Err("no code offer".into());
    };
    let deadline = Instant::now() + Duration::from_secs(30);
    let stranger = loop {
        if let Response::Strangers(list) = entrant.request(Request::Strangers).await?
            && let Some(first) = list.into_iter().next()
        {
            break first.stranger;
        }
        if Instant::now() > deadline {
            return Err("no stranger appeared".into());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    };
    match entrant
        .request(Request::PairEnterCode { code, stranger })
        .await?
    {
        Response::Paired { .. } => Ok(()),
        other => Err(format!("pairing failed: {other:?}").into()),
    }
}

/// Every chosen file arrived intact (BLAKE3 of what was written); no other
/// did.
fn check_downloads(
    downloads: &Path,
    files: &[(PathBuf, [u8; 32])],
    chosen: impl Fn(&str) -> bool,
) -> AnyResult<()> {
    for (path, expected) in files {
        let name = path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if !chosen(name) {
            assert!(!downloads.join(path).exists(), "{}", path.display());
            continue;
        }
        assert_eq!(
            &hash_file(&downloads.join(path))?,
            expected,
            "{}",
            path.display()
        );
    }
    Ok(())
}

/// Which files of the folder Alice accepts.
#[derive(Clone, Copy)]
enum Choice {
    All,
    /// Only the large file and `notes.md`: the resumed offer must be
    /// accepted with the same selection (§7.5), which `accept` without
    /// files repeats.
    Some,
}

async fn resume_after_crash(large: u64, limit: Duration, choice: Choice) -> AnyResult<()> {
    let scratch = Scratch::new("resume")?;
    let discovery = scratch.0.join("discovery");
    let mut alice = Device::new(&scratch.0, "alice", &discovery)?;
    let mut bob = Device::new(&scratch.0, "bob", &discovery)?;
    alice.start().await?;
    bob.start().await?;
    let alice_device = alice.device().await?;

    // Pair by code: Alice shows it, Bob enters it.
    pair(&alice, &bob).await?;

    // Bob sends the folder; Alice accepts.
    let files = make_folder(&scratch.0.join("outbox"), large)?;
    let mut alice_events = alice.events().await?;
    let mut bob_events = bob.events().await?;
    let Response::Offered { transfer, .. } = bob
        .request(Request::Send {
            contact: alice_device.clone(),
            paths: vec![scratch.0.join("outbox").join("photos")],
        })
        .await?
    else {
        return Err("not offered".into());
    };
    let offer = wait_for_offer(&alice, &mut alice_events, &transfer, limit).await?;
    let chosen =
        |name: &str| matches!(choice, Choice::All) || ["video.bin", "notes.md"].contains(&name);
    let selection = match choice {
        Choice::All => None,
        Choice::Some => Some(
            offer
                .entries
                .iter()
                .filter(|entry| !entry.directory && chosen(&entry.name))
                .map(|entry| entry.id)
                .collect(),
        ),
    };
    assert_eq!(
        alice
            .request(Request::Accept {
                transfer: transfer.clone(),
                files: selection,
            })
            .await?,
        Response::Done
    );

    // Kill Alice once a fifth has arrived.
    wait_for(&mut alice_events, &transfer, limit, |event| match event {
        Event::Progress {
            transfer: moving,
            done,
            total,
            ..
        } if *moving == transfer && *done >= total / 5 => Some(()),
        _ => None,
    })
    .await?;
    alice.kill()?;
    drop(alice_events);

    // Restart her: the quarantine kept what arrived; Bob reconnects and
    // offers the transfer again, which she must accept again (§7.5).
    alice.start().await?;
    let mut alice_events = alice.events().await?;
    let offer = wait_for_offer(&alice, &mut alice_events, &transfer, limit).await?;
    assert!(
        offer.resume.is_some(),
        "the offer must resume the earlier transfer"
    );
    assert_eq!(
        alice
            .request(Request::Accept {
                transfer: transfer.clone(),
                files: None,
            })
            .await?,
        Response::Done
    );
    wait_for(&mut alice_events, &transfer, limit, |event| match event {
        Event::Completed { transfer: done } if *done == transfer => Some(()),
        _ => None,
    })
    .await?;
    // The sender verified the receiver's signed receipt (§7.7).
    wait_for(&mut bob_events, &transfer, limit, |event| match event {
        Event::Delivered { transfer: done } if *done == transfer => Some(()),
        _ => None,
    })
    .await?;

    check_downloads(&alice.paths().downloads_dir, &files, chosen)?;
    alice.stop().await?;
    bob.stop().await?;
    Ok(())
}

#[tokio::test]
async fn two_daemons_resume_a_folder_after_a_crash() -> AnyResult<()> {
    resume_after_crash(96 * MIB, Duration::from_mins(5), Choice::All).await
}

#[tokio::test]
async fn a_partial_selection_resumes_with_the_same_files() -> AnyResult<()> {
    resume_after_crash(48 * MIB, Duration::from_mins(5), Choice::Some).await
}

#[tokio::test]
#[ignore = "2 GiB: CI runs it in release mode"]
async fn two_gigabytes() -> AnyResult<()> {
    resume_after_crash(2048 * MIB, Duration::from_mins(30), Choice::All).await
}

/// A second daemon for the same home stops at the endpoint, before it
/// opens the identity or the quarantine; so does one whose configuration
/// names another state directory.
#[tokio::test]
async fn a_second_daemon_is_refused() -> AnyResult<()> {
    let scratch = Scratch::new("second")?;
    let discovery = scratch.0.join("discovery");
    let mut alice = Device::new(&scratch.0, "alice", &discovery)?;
    alice.start().await?;
    let second = Command::new(env!("CARGO_BIN_EXE_todoke"))
        .args(["daemon", "run"])
        .env("TODOKE_HOME", &alice.home)
        .stdout(Stdio::null())
        .output()?;
    assert!(!second.status.success());
    let said = String::from_utf8_lossy(&second.stderr);
    assert!(said.contains("another daemon"), "{said}");
    alice.device().await?;
    alice.stop().await?;

    let elsewhere = Device::new(&scratch.0, "elsewhere", &discovery)?;
    let paths = elsewhere.paths();
    let mut config: CoreConfig = serde_json::from_slice(&std::fs::read(&paths.config_file)?)?;
    config.state_dir = scratch.0.join("other-state");
    std::fs::write(&paths.config_file, serde_json::to_vec(&config)?)?;
    let refused = Command::new(env!("CARGO_BIN_EXE_todoke"))
        .args(["daemon", "run"])
        .env("TODOKE_HOME", &elsewhere.home)
        .stdout(Stdio::null())
        .output()?;
    assert!(!refused.status.success());
    assert!(String::from_utf8_lossy(&refused.stderr).contains("state_dir must be"));
    assert!(!scratch.0.join("other-state").exists());
    Ok(())
}

/// The client commands: exit code 3 with no daemon, 2 for a bad argument,
/// and `--json` prints one JSON value per line.
#[tokio::test]
async fn the_cli_reports_with_exit_codes_and_json() -> AnyResult<()> {
    let scratch = Scratch::new("cli")?;
    let discovery = scratch.0.join("discovery");
    let mut alice = Device::new(&scratch.0, "alice", &discovery)?;
    let home = alice.home.clone();
    let todoke = |args: &[&str]| {
        Command::new(env!("CARGO_BIN_EXE_todoke"))
            .args(args)
            .env("TODOKE_HOME", &home)
            .stdin(Stdio::null())
            .output()
    };
    assert_eq!(todoke(&["status"])?.status.code(), Some(3));
    alice.start().await?;
    let status = todoke(&["--json", "status"])?;
    assert!(status.status.success());
    let line = String::from_utf8(status.stdout)?;
    assert_eq!(line.lines().count(), 1);
    assert!(matches!(
        serde_json::from_str::<Response>(&line)?,
        Response::Status(_)
    ));
    let transfers = todoke(&["--json", "transfers"])?;
    assert!(matches!(
        serde_json::from_slice::<Response>(&transfers.stdout)?,
        Response::Transfers(list) if list.is_empty()
    ));
    assert_eq!(todoke(&["accept", "zz"])?.status.code(), Some(2));
    assert_eq!(todoke(&["cancel", "ffffffffffff"])?.status.code(), Some(2));
    let human = todoke(&["status"])?;
    assert!(String::from_utf8(human.stdout)?.contains("sessions  enabled"));
    alice.stop().await?;
    Ok(())
}

/// A relay on this test's runtime with a self-signed certificate, as the
/// daemons configure it (pinned).
fn relay() -> AnyResult<RelayConfig> {
    let (identity, _, _) = todoke_relay::Identity::self_signed(vec!["relay.test".into()])?;
    let node = todoke_relay::Relay::bind(
        todoke_relay::Config::new(([127, 0, 0, 1], 0).into()),
        &identity,
    )?;
    let config = RelayConfig {
        name: "test".into(),
        address: node.local_addr()?.to_string(),
        server_name: "relay.test".into(),
        pin: Some(todoke_relay::format_pin(&identity.pin()?)),
    };
    tokio::spawn(node.run(std::sync::Arc::new(tokio::sync::Notify::new())));
    Ok(config)
}

/// Two daemons that cannot see each other (no LAN) pair by QR through a
/// relay and send a folder through it; every file and the receipt are
/// checked.
#[tokio::test(flavor = "multi_thread")]
async fn two_daemons_pair_and_send_through_a_relay() -> AnyResult<()> {
    let scratch = Scratch::new("relayed")?;
    let relay = relay()?;
    let mut alice = Device::remote(&scratch.0, "alice", &relay)?;
    let mut bob = Device::remote(&scratch.0, "bob", &relay)?;
    alice.start().await?;
    bob.start().await?;
    let alice_device = alice.device().await?;
    let mut alice_events = alice.events().await?;
    let mut bob_events = bob.events().await?;
    let Response::Qr { text, .. } = alice.request(Request::PairShowQr).await? else {
        return Err("no QR offer".into());
    };
    let paired = bob.request(Request::PairScanQr { text }).await?;
    assert!(matches!(paired, Response::Paired { .. }), "{paired:?}");
    let files = make_folder(&scratch.0.join("outbox"), 6 * MIB)?;
    let Response::Offered { transfer, .. } = bob
        .request(Request::Send {
            contact: alice_device,
            paths: vec![scratch.0.join("outbox").join("photos")],
        })
        .await?
    else {
        return Err("not offered".into());
    };
    let limit = Duration::from_mins(2);
    wait_for_offer(&alice, &mut alice_events, &transfer, limit).await?;
    assert_eq!(
        alice
            .request(Request::Accept {
                transfer: transfer.clone(),
                files: None,
            })
            .await?,
        Response::Done
    );
    wait_for(&mut bob_events, &transfer, limit, |event| match event {
        Event::Delivered { transfer: done } if *done == transfer => Some(()),
        _ => None,
    })
    .await?;
    check_downloads(&alice.paths().downloads_dir, &files, |_| true)?;
    alice.stop().await?;
    bob.stop().await?;
    Ok(())
}
