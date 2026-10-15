//! Two cores through the binding's Rust API, as an app drives them: pair
//! by QR, offer a file, see the offer as an event, accept it, see it
//! arrive.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use todoke_ffi::types::{CoreEvent, KeyProtection, KeyStoragePolicy, Settings};
use todoke_ffi::{
    ContactHandle, Core, Events, KeyStore, KeyStoreError, LinkError, LinkKind, Notifier,
    OfferNotice, RadioLink, TodokeError,
};

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

    let a_contact = {
        let _pairing = pairing();
        let offer = a.pair_show_qr()?;
        assert_eq!(
            offer.modules().len(),
            (offer.width() * offer.width()) as usize
        );
        b.pair_scan_qr(offer.text())?
    };
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

/// What the app's notifier was told, in order.
#[derive(Default)]
struct Told(Mutex<Vec<String>>);

impl Told {
    fn log(&self) -> Vec<String> {
        self.0.lock().map(|log| log.clone()).unwrap_or_default()
    }

    fn push(&self, line: String) {
        if let Ok(mut log) = self.0.lock() {
            log.push(line);
        }
    }
}

/// A notifier that records what it is told and then panics on an offer,
/// as a buggy app callback could.
struct Panicky(Arc<Told>);

impl Notifier for Panicky {
    #[allow(clippy::panic, reason = "a panicking app callback is the point")]
    fn offer_received(&self, notice: OfferNotice) {
        self.0.push(format!(
            "offer {} from {} ({}) {} files {} folders {} bytes",
            notice.transfer,
            notice.from,
            notice.from_name,
            notice.files,
            notice.folders,
            notice.total_bytes
        ));
        panic!("the app's notifier failed");
    }
    fn offer_gone(&self, transfer: String) {
        self.0.push(format!("gone {transfer}"));
    }
    fn transfer_finished(&self, transfer: String, text: String) {
        self.0.push(format!("finished {transfer}: {text}"));
    }
    fn missed(&self) {
        self.0.push("missed".to_owned());
    }
}

/// Held while two cores pair. A scanner dials the first strangers it
/// finds nearby, and an offer allows one attempt (PROTOCOL §3.1): tests
/// pairing at once over loopback would dial each other's displayers and
/// burn their offers.
fn pairing() -> MutexGuard<'static, ()> {
    static PAIRING: Mutex<()> = Mutex::new(());
    PAIRING.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Two cores over loopback, B paired with A by QR; B's handle to A.
fn paired(
    a_home: &Scratch,
    b_home: &Scratch,
) -> Result<(Core, Core, ContactHandle), Box<dyn std::error::Error>> {
    let a = Core::new(settings(&a_home.0))?;
    let b = Core::new(settings(&b_home.0))?;
    let a_contact = {
        let _pairing = pairing();
        b.pair_scan_qr(a.pair_show_qr()?.text())?
    };
    Ok((a, b, a_contact))
}

/// The notifier hears of an offer by its sender and counts (no names),
/// and of its end; one that panics loses that event, not the event thread
/// or its place.
#[test]
fn notifications_survive_a_panicking_notifier() -> TestResult {
    let (a_home, b_home) = (Scratch::new("notify-a")?, Scratch::new("notify-b")?);
    let (a, b, a_contact) = paired(&a_home, &b_home)?;
    let told = Arc::new(Told::default());
    a.set_notifier(Arc::new(Panicky(Arc::clone(&told))));
    let a_events = a.subscribe()?;

    let file = b_home.0.join("secret-plan.txt");
    std::fs::write(&file, b"plans")?;
    let sent = a_contact.send(vec![file.display().to_string()])?;
    let offered = wait_for(&a_events, |event| match event {
        CoreEvent::OfferReceived { offer } => Some(offer),
        _ => None,
    })?;
    a.transfer(offered.transfer.clone())?.accept(Vec::new())?;
    wait_for(&a_events, |event| match event {
        CoreEvent::Completed { transfer } if transfer == offered.transfer => Some(()),
        _ => None,
    })?;
    // The notifier runs after the subscriptions: wait for it to catch up.
    let finished = format!("finished {}: Files received", sent.id());
    let deadline = Instant::now() + Duration::from_secs(30);
    while !told.log().contains(&finished) && Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(20));
    }
    let b_device = b.status()?.device;
    let name = todoke_ffi::types::name_of(&b_device);
    assert_eq!(
        told.log(),
        [
            format!(
                "offer {} from {b_device} ({name}) 1 files 0 folders 5 bytes",
                sent.id()
            ),
            format!("gone {}", sent.id()),
            finished,
        ]
    );
    assert!(told.log().iter().all(|line| !line.contains("secret")));
    // Cleared: nothing more is told.
    a.clear_notifier();
    drop((a_contact, sent, b));
    Ok(())
}

/// What a contact refuses to send before asking the core: nothing, a
/// relative path among absolute ones; what the core refuses: a file that
/// is not there, a path with a NUL.
#[test]
fn sending_checks_its_paths() -> TestResult {
    let (a_home, b_home) = (Scratch::new("paths-a")?, Scratch::new("paths-b")?);
    let (a, b, a_contact) = paired(&a_home, &b_home)?;
    let file = b_home.0.join("there.txt");
    std::fs::write(&file, b"x")?;
    let there = file.display().to_string();
    for paths in [
        Vec::new(),
        vec!["there.txt".to_owned()],
        vec![there.clone(), "./there.txt".to_owned()],
        vec![String::new()],
    ] {
        assert!(
            matches!(
                a_contact.send(paths.clone()),
                Err(TodokeError::Invalid { .. })
            ),
            "{paths:?}"
        );
    }
    let missing = b_home.0.join("missing.txt").display().to_string();
    assert!(matches!(
        a_contact.send(vec![missing]),
        Err(TodokeError::Source { .. })
    ));
    let nul = format!("{there}\0.txt");
    assert!(a_contact.send(vec![nul]).is_err());
    // Nothing was offered.
    assert_eq!(b.transfers()?, Vec::new());
    drop((a, a_contact));
    Ok(())
}

/// Handles to things the core does not know answer with typed errors.
#[test]
fn unknown_handles_are_typed_errors() -> TestResult {
    let home = Scratch::new("unknown")?;
    let core = Core::new(settings(&home.0))?;
    let stranger = core.contact("ab".repeat(32))?;
    assert_eq!(stranger.name(), "Device ABAB ABAB");
    assert!(matches!(
        stranger.send(Vec::new()),
        Err(TodokeError::Invalid { .. })
    ));
    assert!(matches!(
        stranger.send(vec!["relative.txt".into()]),
        Err(TodokeError::Invalid { .. })
    ));
    let transfer = core.transfer("cd".repeat(16))?;
    assert_eq!(transfer.id(), "cd".repeat(16));
    assert!(matches!(transfer.info(), Err(TodokeError::State { .. })));
    assert!(transfer.decline().is_err());
    assert!(transfer.cancel().is_err());
    Ok(())
}

/// A profile reopened with the same key store finds its key under the same
/// ID; another profile in the same store gets its own ID and key.
#[test]
fn key_stores_hold_one_key_per_profile() -> TestResult {
    let (first, second) = (Scratch::new("profile-1")?, Scratch::new("profile-2")?);
    let store = Arc::new(Memory::default());
    let start = |home: &Scratch| {
        let mut asked = settings(&home.0);
        asked.key_storage = KeyStoragePolicy::Platform;
        Core::with_key_store(asked, Arc::clone(&store) as Arc<dyn KeyStore>)
    };
    let device = start(&first)?.status()?.device;
    let keys = store.keys();
    assert_eq!(keys.len(), 1);
    // Released and reopened: the same identity, from the same key.
    assert_eq!(start(&first)?.status()?.device, device);
    assert_eq!(store.keys(), keys);
    // Another profile: its own ID and key.
    let other = start(&second)?.status()?.device;
    assert_ne!(other, device);
    let keys = store.keys();
    assert_eq!(keys.len(), 2);
    assert_ne!(keys[0].0, keys[1].0);
    assert_ne!(keys[0].1, keys[1].1);
    Ok(())
}

/// A key store that answers `load` and `store` as told.
struct Canned {
    load: Result<Option<Vec<u8>>, KeyStoreError>,
    store: Result<(), KeyStoreError>,
}

impl KeyStore for Canned {
    fn protection(&self) -> KeyProtection {
        KeyProtection::Tee
    }
    fn load(&self, _: String) -> Result<Option<Vec<u8>>, KeyStoreError> {
        self.load.clone()
    }
    fn store(&self, _: String, _: Vec<u8>) -> Result<(), KeyStoreError> {
        self.store.clone()
    }
}

/// A key store that fails, refuses, or hands back something that is not a
/// key stops the start with a key store error; nothing falls back to a
/// file.
#[test]
fn failing_key_stores_stop_the_start() -> TestResult {
    let refused = KeyStoreError::Refused {
        message: "denied".into(),
    };
    let locked = KeyStoreError::Unavailable {
        message: "locked".into(),
    };
    let cases = [
        (Ok(None), Err(refused.clone())),
        (Ok(None), Err(locked.clone())),
        (Err(refused), Ok(())),
        (Err(locked), Ok(())),
        (Ok(Some(Vec::new())), Ok(())),
        (Ok(Some(vec![7; 31])), Ok(())),
        (Ok(Some(vec![7; 33])), Ok(())),
    ];
    for (load, store) in cases {
        let home = Scratch::new("failing")?;
        let mut asked = settings(&home.0);
        asked.key_storage = KeyStoragePolicy::Platform;
        let case = format!("{load:?} {store:?}");
        let started = Core::with_key_store(asked, Arc::new(Canned { load, store }));
        assert!(
            matches!(started, Err(TodokeError::KeyStore { .. })),
            "{case}: {started:?}"
        );
        assert!(!home.0.join("state").join("storage.key").exists(), "{case}");
    }
    Ok(())
}

/// A profile whose ID cannot be read does not start (it would otherwise
/// look for its key under another name).
#[test]
fn an_unnamed_profile_does_not_start() -> TestResult {
    let home = Scratch::new("unnamed")?;
    let mut asked = settings(&home.0);
    asked.key_storage = KeyStoragePolicy::Platform;
    let store = Arc::new(Memory::default());
    drop(Core::with_key_store(
        asked.clone(),
        Arc::clone(&store) as Arc<dyn KeyStore>,
    )?);
    std::fs::write(home.0.join("state").join("storage.id"), b"not an id")?;
    assert!(matches!(
        Core::with_key_store(asked, store),
        Err(TodokeError::Profile { .. })
    ));
    Ok(())
}

/// A radio link that records being closed.
#[derive(Default)]
struct Link(std::sync::atomic::AtomicBool);

impl RadioLink for Link {
    fn kind(&self) -> LinkKind {
        LinkKind::Ble
    }
    fn send(&self, _: Vec<u8>) -> Result<(), LinkError> {
        Err(LinkError::Closed)
    }
    fn close(&self) {
        self.0.store(true, std::sync::atomic::Ordering::SeqCst);
    }
}

/// Radio links are refused while §16 O7 keeps them disabled, and the link
/// offered is closed rather than left open in the app.
#[test]
fn radio_links_are_refused_and_closed() -> TestResult {
    let home = Scratch::new("link")?;
    let core = Core::new(settings(&home.0))?;
    let link = Arc::new(Link::default());
    assert!(matches!(
        core.attach_link(Arc::clone(&link) as Arc<dyn RadioLink>),
        Err(TodokeError::Disabled { .. })
    ));
    assert!(link.0.load(std::sync::atomic::Ordering::SeqCst));
    Ok(())
}
