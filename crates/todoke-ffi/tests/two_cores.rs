//! Two cores through the binding's Rust API, as an app drives them: pair
//! by QR, offer a file, see the offer as an event, accept it, see it
//! arrive.

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use boltffi::EventSubscription;
use todoke_ffi::types::{CoreEvent, KeyProtection, KeyStoragePolicy, Settings};
use todoke_ffi::{Core, KeyStore, KeyStoreError, TodokeError};

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

/// A key store in memory, as an app's would keep it in hardware.
#[derive(Default)]
struct Memory(Mutex<Option<Vec<u8>>>);

impl KeyStore for Memory {
    fn protection(&self) -> KeyProtection {
        KeyProtection::StrongBox
    }
    fn load(&self) -> Result<Option<Vec<u8>>, KeyStoreError> {
        Ok(self
            .0
            .lock()
            .map_err(|_| KeyStoreError::AlreadyExists)?
            .clone())
    }
    fn store(&self, key: Vec<u8>) -> Result<(), KeyStoreError> {
        let mut slot = self.0.lock().map_err(|_| KeyStoreError::AlreadyExists)?;
        if slot.is_some() {
            return Err(KeyStoreError::AlreadyExists);
        }
        *slot = Some(key);
        Ok(())
    }
}

/// Waits for the first event `pick` accepts on `events`.
async fn wait_for<T>(
    events: &EventSubscription<CoreEvent>,
    mut pick: impl FnMut(CoreEvent) -> Option<T>,
) -> Result<T, Box<dyn std::error::Error>> {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(60);
    loop {
        while let Some(event) = events.pop_event() {
            if let Some(found) = pick(event) {
                return Ok(found);
            }
        }
        if tokio::time::Instant::now() > deadline {
            return Err("no such event in time".into());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn two_cores_pair_offer_accept_and_receive() -> TestResult {
    let (a_home, b_home) = (Scratch::new("a")?, Scratch::new("b")?);
    let a = Core::new(settings(&a_home.0))?;
    let a_events = a.events();
    let store = Arc::new(Memory::default());
    let mut b_settings = settings(&b_home.0);
    b_settings.key_storage = KeyStoragePolicy::Platform;
    let b = Core::with_key_store(b_settings, Arc::clone(&store) as Arc<dyn KeyStore>)?;
    // B's storage key went to its key store.
    assert_eq!(b.status().await?.key_protection, KeyProtection::StrongBox);
    assert!(
        store
            .0
            .lock()
            .map_err(|_| "poisoned")?
            .as_ref()
            .is_some_and(|key| key.len() == 32)
    );

    let offer = a.pair_show_qr().await?;
    assert_eq!(
        offer.modules().len(),
        (offer.width() * offer.width()) as usize
    );
    let a_contact = b.pair_scan_qr(offer.text()).await?;
    let a_device = a.status().await?.device;
    assert_eq!(a_contact.device(), a_device);

    let file = b_home.0.join("hello.txt");
    std::fs::write(&file, b"hello from b")?;
    let sent = a_contact.send(vec![file.display().to_string()]).await?;
    let offered = wait_for(&a_events, |event| match event {
        CoreEvent::OfferReceived { offer } => Some(offer),
        _ => None,
    })
    .await?;
    assert_eq!(offered.transfer, sent.id());
    assert_eq!(offered.entries.len(), 1);
    assert_eq!(offered.entries[0].name, "hello.txt");

    a.transfer(offered.transfer.clone())?
        .accept(Vec::new())
        .await?;
    wait_for(&a_events, |event| match event {
        CoreEvent::Completed { transfer } if transfer == offered.transfer => Some(()),
        _ => None,
    })
    .await?;
    let received = std::fs::read(a_home.0.join("downloads").join("hello.txt"))?;
    assert_eq!(received, b"hello from b");
    Ok(())
}

#[tokio::test]
async fn malformed_requests_are_typed_errors() -> TestResult {
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
    assert!(unknown.accept(Vec::new()).await.is_err());
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
