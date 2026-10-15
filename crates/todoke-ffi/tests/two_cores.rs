//! Two cores through the binding's Rust API, as an app drives them: pair
//! by QR, offer a file, see the offer as an event, accept it, see it
//! arrive.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use todoke_ffi::types::{CoreEvent, KeyProtection, KeyStoragePolicy, Settings};
use todoke_ffi::{Core, Events, KeyStore, KeyStoreError, TodokeError};

type TestResult = Result<(), Box<dyn std::error::Error>>;

/// A scratch directory, removed afterwards.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> std::io::Result<Self> {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).map_err(std::io::Error::other)?;
        let path =
            std::env::temp_dir().join(format!("todoke-ffi-{name}-{}", u64::from_le_bytes(random)));
        std::fs::create_dir_all(path.join("downloads"))?;
        Ok(Self(path))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn settings(home: &Path) -> Settings {
    Settings {
        home: home.display().to_string(),
        downloads: home.join("downloads").display().to_string(),
        lan: true,
        allow_loopback: true,
        hidden: false,
        history_days: 7,
        key_storage: KeyStoragePolicy::File,
    }
}

/// A key store in memory, as an app's would keep it in hardware, keyed by
/// profile.
#[derive(Default)]
struct Memory(Mutex<Vec<(String, Vec<u8>)>>);

impl Memory {
    fn keys(&self) -> Vec<(String, Vec<u8>)> {
        self.0.lock().map(|keys| keys.clone()).unwrap_or_default()
    }
}

impl KeyStore for Memory {
    fn protection(&self) -> KeyProtection {
        KeyProtection::StrongBox
    }
    fn load(&self, profile: String) -> Result<Option<Vec<u8>>, KeyStoreError> {
        let keys = self.0.lock().map_err(|_| KeyStoreError::AlreadyExists)?;
        Ok(keys
            .iter()
            .find(|(name, _)| *name == profile)
            .map(|(_, key)| key.clone()))
    }
    fn store(&self, profile: String, key: Vec<u8>) -> Result<(), KeyStoreError> {
        let mut keys = self.0.lock().map_err(|_| KeyStoreError::AlreadyExists)?;
        if keys.iter().any(|(name, _)| *name == profile) {
            return Err(KeyStoreError::AlreadyExists);
        }
        keys.push((profile, key));
        Ok(())
    }
}

/// A key store that hands back a wiped slot.
struct Zeros;

impl KeyStore for Zeros {
    fn protection(&self) -> KeyProtection {
        KeyProtection::Tee
    }
    fn load(&self, _: String) -> Result<Option<Vec<u8>>, KeyStoreError> {
        Ok(Some(vec![0; 32]))
    }
    fn store(&self, _: String, _: Vec<u8>) -> Result<(), KeyStoreError> {
        Err(KeyStoreError::AlreadyExists)
    }
}

/// Waits for the first event `pick` accepts on `events`.
fn wait_for<T>(
    events: &Events,
    mut pick: impl FnMut(CoreEvent) -> Option<T>,
) -> Result<T, Box<dyn std::error::Error>> {
    let deadline = Instant::now() + Duration::from_secs(60);
    while Instant::now() < deadline {
        for event in events.next(64, 500)? {
            if let Some(found) = pick(event) {
                return Ok(found);
            }
        }
    }
    Err("no such event in time".into())
}

#[test]
fn two_cores_pair_offer_accept_and_receive() -> TestResult {
    let (a_home, b_home) = (Scratch::new("a")?, Scratch::new("b")?);
    let a = Core::new(settings(&a_home.0))?;
    let a_events = a.subscribe()?;
    let store = Arc::new(Memory::default());
    let mut b_settings = settings(&b_home.0);
    b_settings.key_storage = KeyStoragePolicy::Platform;
    let b = Core::with_key_store(b_settings, Arc::clone(&store) as Arc<dyn KeyStore>)?;
    // B's storage key went to its key store, under its profile's ID.
    assert_eq!(b.status()?.key_protection, KeyProtection::StrongBox);
    let keys = store.keys();
    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].0.len(), 32);
    assert_eq!(keys[0].1.len(), 32);

    let offer = a.pair_show_qr()?;
    assert_eq!(
        offer.modules().len(),
        (offer.width() * offer.width()) as usize
    );
    let a_contact = b.pair_scan_qr(offer.text())?;
    let a_device = a.status()?.device;
    assert_eq!(a_contact.device(), a_device);

    let file = b_home.0.join("hello.txt");
    std::fs::write(&file, b"hello from b")?;
    let sent = a_contact.send(vec![file.display().to_string()])?;
    let offered = wait_for(&a_events, |event| match event {
        CoreEvent::OfferReceived { offer } => Some(offer),
        _ => None,
    })?;
    assert_eq!(offered.transfer, sent.id());
    assert_eq!(offered.entries.len(), 1);
    assert_eq!(offered.entries[0].name, "hello.txt");

    a.transfer(offered.transfer.clone())?.accept(Vec::new())?;
    wait_for(&a_events, |event| match event {
        CoreEvent::Completed { transfer } if transfer == offered.transfer => Some(()),
        _ => None,
    })?;
    let received = std::fs::read(a_home.0.join("downloads").join("hello.txt"))?;
    assert_eq!(received, b"hello from b");

    // Releasing the core stops it, and its subscription ends once drained.
    drop(a);
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        match a_events.next(64, 500) {
            Err(TodokeError::State { .. }) => break,
            Err(error) => return Err(error.into()),
            Ok(_) if Instant::now() > deadline => return Err("the subscription never ended".into()),
            Ok(_) => {}
        }
    }
    drop((a_contact, sent, b));
    Ok(())
}

#[test]
fn malformed_requests_are_typed_errors() -> TestResult {
    let home = Scratch::new("errors")?;
    let core = Core::new(settings(&home.0))?;
    assert!(matches!(
        core.contact("not hex".into()),
        Err(TodokeError::Invalid { .. })
    ));
    assert!(matches!(
        core.transfer(String::new()),
        Err(TodokeError::Invalid { .. })
    ));
    let unknown = core.transfer("00".repeat(16))?;
    assert!(unknown.accept(Vec::new()).is_err());
    let relative = Settings {
        home: "relative".into(),
        ..settings(&home.0)
    };
    assert!(matches!(
        Core::new(relative),
        Err(TodokeError::Invalid { .. })
    ));
    Ok(())
}

/// With an app key store the key lives only there; a wiped slot is never a
/// key.
#[test]
fn key_store_policy_and_wiped_keys() -> TestResult {
    let home = Scratch::new("keys")?;
    // A key store with a policy that allows a file: refused.
    for policy in [KeyStoragePolicy::File, KeyStoragePolicy::Auto] {
        let mut asked = settings(&home.0);
        asked.key_storage = policy;
        assert!(matches!(
            Core::with_key_store(asked, Arc::new(Memory::default())),
            Err(TodokeError::Invalid { .. })
        ));
    }
    let mut platform = settings(&home.0);
    platform.key_storage = KeyStoragePolicy::Platform;
    assert!(matches!(
        Core::with_key_store(platform, Arc::new(Zeros)),
        Err(TodokeError::KeyStore { .. })
    ));
    Ok(())
}

/// Subscriptions are bounded in number, and each ends when closed.
#[test]
fn subscriptions_are_bounded() -> TestResult {
    let home = Scratch::new("subscriptions")?;
    let core = Core::new(settings(&home.0))?;
    let mut held = Vec::new();
    let refused = loop {
        match core.subscribe() {
            Ok(events) => held.push(events),
            Err(error) => break error,
        }
        if held.len() > 64 {
            return Err("subscriptions are unbounded".into());
        }
    };
    assert!(matches!(refused, TodokeError::State { .. }));
    // A closed subscription frees its place.
    let first = held.remove(0);
    first.stop();
    assert!(matches!(first.next(1, 0), Err(TodokeError::State { .. })));
    drop(first);
    let again = core.subscribe()?;
    assert_eq!(again.next(8, 0)?.len(), 0);
    Ok(())
}

/// A subscription ends when its core stops, even one taken just before.
#[test]
fn subscriptions_end_when_the_core_stops() -> TestResult {
    let home = Scratch::new("stop")?;
    let core = Core::new(settings(&home.0))?;
    let events = core.subscribe()?;
    // Read on another thread while the core is released, as an app does.
    let reader = std::thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(30);
        loop {
            match events.next(64, 250) {
                Err(TodokeError::State { .. }) => return true,
                Err(_) => return false,
                Ok(_) if Instant::now() > deadline => return false,
                Ok(_) => {}
            }
        }
    });
    std::thread::sleep(Duration::from_millis(100));
    let released = Instant::now();
    drop(core);
    assert!(
        released.elapsed() < Duration::from_secs(10),
        "releasing waited for the reader"
    );
    assert!(reader.join().map_err(|_| "the reader panicked")?);
    Ok(())
}
