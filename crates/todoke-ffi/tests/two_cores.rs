//! Two cores through the binding's Rust API, as an app drives them: pair
//! by QR, offer a file, see the offer as an event, accept it, see it
//! arrive.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use todoke_ffi::types::{CoreEvent, KeyProtection, KeyStoragePolicy, Settings, UwbController};
use todoke_ffi::{
    ContactHandle, Core, Events, KeyStore, KeyStoreError, LinkAbilities, LinkError, LinkLease,
    LinkRequest, NfcTag, Notifier, OfferNotice, TodokeError, WifiLinks,
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
    let _serial = serial();
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
    a.stop_pairing()?;
    let a_contact = pair(&a, &b)?;
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
    let _serial = serial();
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
    let _serial = serial();
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
    let _serial = serial();
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
    let _serial = serial();
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

/// Held for the whole of every test: one test's cores at a time on the
/// LAN, as in the Swift and Kotlin suites. A scanner dials the first
/// strangers it finds nearby, and an offer allows one attempt (PROTOCOL
/// §3.1): tests pairing at once would dial each other's displayers and
/// burn their offers, and cores starting and stopping beside a pairing
/// made it fail on macOS CI.
fn serial() -> MutexGuard<'static, ()> {
    static SERIAL: Mutex<()> = Mutex::new(());
    SERIAL.lock().unwrap_or_else(PoisonError::into_inner)
}

/// B pairs with A by QR. A scanner gives up when the first strangers it
/// sees (perhaps a dropped core's record still cached) do not answer
/// before A appears; that is the core's discovery, not the binding, so a
/// refused pairing is tried again, after a moment, with a new offer.
fn pair(a: &Core, b: &Core) -> Result<ContactHandle, TodokeError> {
    let mut attempts = 0;
    loop {
        attempts += 1;
        match b.pair_scan_qr(a.pair_show_qr()?.text()) {
            Err(TodokeError::Pairing { .. }) if attempts < 3 => {
                std::thread::sleep(Duration::from_secs(1));
            }
            result => return result,
        }
    }
}

/// Two cores over loopback, B paired with A by QR; B's handle to A.
fn paired(
    a_home: &Scratch,
    b_home: &Scratch,
) -> Result<(Core, Core, ContactHandle), Box<dyn std::error::Error>> {
    let a = Core::new(settings(&a_home.0))?;
    let b = Core::new(settings(&b_home.0))?;
    let a_contact = pair(&a, &b)?;
    Ok((a, b, a_contact))
}

/// The notifier hears of an offer by its sender and counts (no names),
/// and of its end; one that panics loses that event, not the event thread
/// or its place.
#[test]
fn notifications_survive_a_panicking_notifier() -> TestResult {
    let _serial = serial();
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
    let _serial = serial();
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

/// Files handed over as open descriptors (Android documents) arrive under
/// the names given, with their bytes read from the start; descriptors that
/// are not open or are given twice are refused.
#[cfg(unix)]
#[test]
fn open_files_are_sent_under_their_names() -> TestResult {
    use std::io::Read as _;
    use std::os::fd::IntoRawFd as _;
    let _serial = serial();
    let (a_home, b_home) = (Scratch::new("fds-a")?, Scratch::new("fds-b")?);
    let (a, b, a_contact) = paired(&a_home, &b_home)?;
    let a_events = a.subscribe()?;
    let picked = b_home.0.join("content-provider-name");
    std::fs::write(&picked, b"from a document")?;
    let mut file = std::fs::File::open(&picked)?;
    // A provider may hand over a descriptor that was read from already.
    file.read_exact(&mut [0; 4])?;
    let sent = a_contact.send_files(vec!["Holiday.txt".to_owned()], vec![file.into_raw_fd()])?;
    let offered = wait_for(&a_events, |event| match event {
        CoreEvent::OfferReceived { offer } => Some(offer),
        _ => None,
    })?;
    assert_eq!(offered.transfer, sent.id());
    assert_eq!(offered.entries[0].name, "Holiday.txt");
    a.transfer(offered.transfer.clone())?.accept(Vec::new())?;
    wait_for(&a_events, |event| match event {
        CoreEvent::Completed { transfer } if transfer == offered.transfer => Some(()),
        _ => None,
    })?;
    assert_eq!(
        std::fs::read(a_home.0.join("downloads").join("Holiday.txt"))?,
        b"from a document"
    );
    // Refused: no files, a missing name, a closed descriptor, one twice.
    assert!(matches!(
        a_contact.send_files(Vec::new(), Vec::new()),
        Err(TodokeError::Invalid { .. })
    ));
    let fd = std::fs::File::open(&picked)?.into_raw_fd();
    assert!(matches!(
        a_contact.send_files(Vec::new(), vec![fd]),
        Err(TodokeError::Invalid { .. })
    ));
    assert!(matches!(
        a_contact.send_files(vec!["x".to_owned()], vec![fd]),
        Err(TodokeError::Invalid { .. })
    ));
    let fd = std::fs::File::open(&picked)?.into_raw_fd();
    assert!(matches!(
        a_contact.send_files(vec!["x".to_owned(), "y".to_owned()], vec![fd, fd]),
        Err(TodokeError::Invalid { .. })
    ));
    drop((b, sent, a_contact));
    Ok(())
}

/// Handles to things the core does not know answer with typed errors.
#[test]
fn unknown_handles_are_typed_errors() -> TestResult {
    let _serial = serial();
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
    let _serial = serial();
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

/// A key store that fails or hands back something that is not a key stops
/// the start with a key store error, and one that refuses (the user
/// cancelled the unlock) with `Locked`; nothing falls back to a file.
#[test]
fn failing_key_stores_stop_the_start() -> TestResult {
    let _serial = serial();
    let refused = KeyStoreError::Refused {
        message: "denied".into(),
    };
    let locked = KeyStoreError::Unavailable {
        message: "locked".into(),
    };
    let cases = [
        (Ok(None), Err(refused.clone()), true),
        (Ok(None), Err(locked.clone()), false),
        (Err(refused), Ok(()), true),
        (Err(locked), Ok(()), false),
        (Ok(Some(Vec::new())), Ok(()), false),
        (Ok(Some(vec![7; 31])), Ok(()), false),
        (Ok(Some(vec![7; 33])), Ok(()), false),
    ];
    for (load, store, refusal) in cases {
        let home = Scratch::new("failing")?;
        let mut asked = settings(&home.0);
        asked.key_storage = KeyStoragePolicy::Platform;
        let case = format!("{load:?} {store:?}");
        let started = Core::with_key_store(asked, Arc::new(Canned { load, store }));
        if refusal {
            assert!(
                matches!(started, Err(TodokeError::Locked { .. })),
                "{case}: {started:?}"
            );
        } else {
            assert!(
                matches!(started, Err(TodokeError::KeyStore { .. })),
                "{case}: {started:?}"
            );
        }
        assert!(!home.0.join("state").join("storage.key").exists(), "{case}");
    }
    Ok(())
}

/// A key needing the user's presence is only ever the platform's: any
/// other policy could fall back to a file, which needs no one. Refused
/// before anything is opened.
#[test]
fn presence_needs_the_platform_policy() -> TestResult {
    let _serial = serial();
    let home = Scratch::new("presence")?;
    for policy in [KeyStoragePolicy::Auto, KeyStoragePolicy::File] {
        let mut asked = settings(&home.0);
        asked.key_storage = policy;
        let started = Core::with_presence(asked);
        assert!(
            matches!(started, Err(TodokeError::Invalid { .. })),
            "{policy:?}: {started:?}"
        );
    }
    assert!(!home.0.join("state").exists());
    Ok(())
}

/// A profile whose ID cannot be read does not start (it would otherwise
/// look for its key under another name).
#[test]
fn an_unnamed_profile_does_not_start() -> TestResult {
    let _serial = serial();
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

/// An app that can set up no direct link, counting its releases.
#[derive(Default)]
struct NoLinks;

impl WifiLinks for NoLinks {
    fn abilities(&self) -> LinkAbilities {
        LinkAbilities::default()
    }
    fn host(&self, _: LinkRequest) -> Result<LinkLease, LinkError> {
        Err(LinkError::Closed)
    }
    fn join(&self, _: LinkRequest) -> Result<LinkLease, LinkError> {
        Err(LinkError::Closed)
    }
    fn bind_socket(&self, _: u64, _: i64) -> Result<(), LinkError> {
        Err(LinkError::Closed)
    }
    fn release(&self, _: u64) {}
}

/// The app gives the core its links once; a second time is refused.
#[test]
fn links_are_given_once() -> TestResult {
    let _serial = serial();
    let home = Scratch::new("link")?;
    let core = Core::new(settings(&home.0))?;
    core.set_links(Arc::new(NoLinks))?;
    assert!(matches!(
        core.set_links(Arc::new(NoLinks)),
        Err(TodokeError::State { .. })
    ));
    Ok(())
}

/// Pointing through the binding (PROTOCOL §10.4): parameters are checked;
/// A points with a pool of controllers, B accepts at an address of its
/// own, and A's target names both addresses and the same key.
#[test]
fn pointing_between_two_cores() -> TestResult {
    let _serial = serial();
    let (a_home, b_home) = (Scratch::new("point-a")?, Scratch::new("point-b")?);
    let (a, b, _) = paired(&a_home, &b_home)?;
    let (a_events, b_events) = (a.subscribe()?, b.subscribe()?);
    let controller = |address, channel, preamble| UwbController {
        address,
        channel,
        preamble,
    };
    for configs in [0, 2] {
        assert!(matches!(
            b.set_ranging_ready(configs),
            Err(TodokeError::Invalid { .. })
        ));
    }
    for controllers in [
        vec![],
        vec![controller(0, 9, 10)],
        vec![controller(7, 6, 10)],
        vec![controller(7, 9, 13)],
        vec![controller(7, 9, 10), controller(7, 5, 9)],
    ] {
        assert!(matches!(
            a.point_start(controllers),
            Err(TodokeError::Invalid { .. })
        ));
    }
    b.set_ranging_ready(1)?;
    a.point_start(vec![controller(0x1111, 9, 10), controller(0x1112, 5, 9)])?;
    let requested = wait_for(&b_events, |event| match event {
        CoreEvent::RangingRequested { ranging } => Some(ranging),
        _ => None,
    })?;
    assert_eq!(requested.controlee, None);
    assert_eq!(requested.contact, a.status()?.device);
    assert!(matches!(
        b.accept_ranging(requested.contact.clone(), requested.session_id, 0x1111),
        Err(TodokeError::Invalid { .. })
    ));
    b.accept_ranging(requested.contact.clone(), requested.session_id, 0x2222)?;
    let target = wait_for(&a_events, |event| match event {
        CoreEvent::PointTarget { ranging } => Some(ranging),
        _ => None,
    })?;
    assert_eq!(target.contact, b.status()?.device);
    assert_eq!(
        (target.controller, target.controlee),
        (0x1111, Some(0x2222))
    );
    assert_eq!(target.session_id, requested.session_id);
    assert_eq!(target.sts_key.len(), 16);
    assert_eq!(target.sts_key, requested.sts_key);
    a.point_stop()?;
    wait_for(&b_events, |event| match event {
        CoreEvent::RangingStopped { session_id, .. } if session_id == target.session_id => Some(()),
        _ => None,
    })?;
    b.clear_ranging_ready()?;
    Ok(())
}

/// What a phone's NFC reader does with a Type 4 tag: select the NDEF
/// application and file, read the length, then the message.
fn read_tag(tag: &NfcTag) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    const OK: [u8; 2] = [0x90, 0];
    let answer = |apdu: Vec<u8>| -> Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut out = tag.respond(apdu);
        let status = out.split_off(out.len().checked_sub(2).ok_or("no status")?);
        if status == OK {
            Ok(out)
        } else {
            Err(format!("status {status:02x?}").into())
        }
    };
    answer(vec![0, 0xa4, 4, 0, 7, 0xd2, 0x76, 0, 0, 0x85, 1, 1])?;
    answer(vec![0, 0xa4, 0, 0x0c, 2, 0xe1, 0x04])?;
    let length = answer(vec![0, 0xb0, 0, 0, 2])?;
    let length = usize::from(u16::from_be_bytes([length[0], length[1]]));
    let mut message = Vec::with_capacity(length);
    while message.len() < length {
        let [high, low] = u16::try_from(message.len() + 2)?.to_be_bytes();
        let wanted = u8::try_from((length - message.len()).min(255))?;
        message.extend(answer(vec![0, 0xb0, high, low, wanted])?);
    }
    Ok(message)
}

/// B pairs with A by tapping: A's tag serves its QR offer.
#[test]
fn pairing_by_nfc() -> TestResult {
    let _serial = serial();
    let (a_home, b_home) = (Scratch::new("nfc-a")?, Scratch::new("nfc-b")?);
    let a = Core::new(settings(&a_home.0))?;
    let b = Core::new(settings(&b_home.0))?;
    let mut attempts = 0;
    let contact = loop {
        attempts += 1;
        let message = read_tag(&a.pair_show_qr()?.nfc_tag()?)?;
        match b.pair_scan_nfc(message) {
            Err(TodokeError::Pairing { .. }) if attempts < 3 => {
                std::thread::sleep(Duration::from_secs(1));
            }
            result => break result?,
        }
    };
    assert_eq!(contact.device(), a.status()?.device);
    Ok(())
}

/// A tag read that is no pairing offer is refused before anything else.
#[test]
fn nfc_messages_that_are_no_offer_are_refused() -> TestResult {
    let _serial = serial();
    let home = Scratch::new("nfc")?;
    let core = Core::new(settings(&home.0))?;
    for message in [Vec::new(), vec![0xd2, 0, 0], vec![0; 2048]] {
        assert!(matches!(
            core.pair_scan_nfc(message),
            Err(TodokeError::Pairing { .. })
        ));
    }
    Ok(())
}
