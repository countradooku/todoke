//! The binding's boundary under random command sequences, as a buggy or
//! hostile app could drive it: malformed IDs, QR text, codes, and paths,
//! handles used after their transfer is gone, pairing started and stopped,
//! subscriptions opened, read, and closed, the notifier set and cleared,
//! and key stores that fail or hand back bad keys. Every outcome must be an
//! answer or a typed error: no panic, no hang. One core runs for the whole
//! process, in a scratch profile with no contacts (nothing can be sent
//! anywhere).
#![no_main]

use std::sync::{Arc, OnceLock};

use libfuzzer_sys::fuzz_target;
use todoke_ffi::types::{KeyProtection, KeyStoragePolicy, Settings};
use todoke_ffi::{Core, KeyStore, KeyStoreError, Notifier, OfferNotice, TodokeError};

struct Harness {
    core: Core,
    scratch: std::path::PathBuf,
}

struct Quiet;

impl Notifier for Quiet {
    fn offer_received(&self, _: OfferNotice) {}
    fn offer_gone(&self, _: String) {}
    fn transfer_finished(&self, _: String, _: String) {}
    fn missed(&self) {}
}

/// A key store that answers as the input says: a key of any length or
/// content, nothing, or an error.
struct Faulty {
    answer: u8,
    key: Vec<u8>,
}

impl KeyStore for Faulty {
    fn protection(&self) -> KeyProtection {
        KeyProtection::Tee
    }
    fn load(&self, _: String) -> Result<Option<Vec<u8>>, KeyStoreError> {
        match self.answer % 4 {
            0 => Ok(Some(self.key.clone())),
            1 => Ok(None),
            2 => Err(KeyStoreError::Refused {
                message: "no".into(),
            }),
            _ => Err(KeyStoreError::Unavailable {
                message: "locked".into(),
            }),
        }
    }
    fn store(&self, _: String, _: Vec<u8>) -> Result<(), KeyStoreError> {
        match self.answer / 4 % 3 {
            0 => Ok(()),
            1 => Err(KeyStoreError::AlreadyExists),
            _ => Err(KeyStoreError::Refused {
                message: "no".into(),
            }),
        }
    }
}

fn settings(home: &std::path::Path, key_storage: KeyStoragePolicy) -> Settings {
    Settings {
        home: home.display().to_string(),
        downloads: home.join("downloads").display().to_string(),
        lan: false,
        allow_loopback: false,
        hidden: true,
        history_days: 0,
        key_storage,
    }
}

fn harness() -> &'static Harness {
    static HARNESS: OnceLock<Harness> = OnceLock::new();
    HARNESS.get_or_init(|| {
        let scratch = std::env::temp_dir().join(format!("todoke-fuzz-ffi-{}", std::process::id()));
        let _ = std::fs::create_dir_all(scratch.join("downloads"));
        let Ok(core) = Core::new(settings(&scratch, KeyStoragePolicy::File)) else {
            std::process::abort();
        };
        Harness { core, scratch }
    })
}

/// Bytes as the commands' arguments.
struct Input<'a>(&'a [u8]);

impl Input<'_> {
    fn byte(&mut self) -> Option<u8> {
        let (&first, rest) = self.0.split_first()?;
        self.0 = rest;
        Some(first)
    }

    fn bytes(&mut self, most: u8) -> Vec<u8> {
        let length = usize::from(self.byte().unwrap_or(0) % most);
        let take = length.min(self.0.len());
        let (bytes, rest) = self.0.split_at(take);
        self.0 = rest;
        bytes.to_vec()
    }

    fn text(&mut self) -> String {
        String::from_utf8_lossy(&self.bytes(80)).into_owned()
    }

    fn hex(&mut self) -> String {
        let length = usize::from(self.byte().unwrap_or(0) % 70);
        (0..length)
            .map(|_| {
                char::from(b"0123456789abcdefABCDEFgz"[usize::from(self.byte().unwrap_or(0) % 24)])
            })
            .collect()
    }
}

fuzz_target!(|data: &[u8]| {
    let harness = harness();
    let core = &harness.core;
    let mut input = Input(data);
    let mut transfers = Vec::new();
    let mut subscriptions = Vec::new();
    let mut steps = 0;
    while let Some(op) = input.byte() {
        steps += 1;
        if steps > 32 {
            break;
        }
        match op % 22 {
            0 => drop(core.status()),
            1 => drop(core.contacts()),
            2 => drop(core.transfers()),
            3 => drop(core.offers()),
            4 => drop(core.history()),
            5 => drop(core.strangers()),
            6 => drop(core.set_hidden(op & 0x80 == 0)),
            7 => {
                if let Ok(offer) = core.pair_show_qr() {
                    assert_eq!(
                        offer.modules().len(),
                        (offer.width() * offer.width()) as usize
                    );
                    assert!(offer.text().starts_with("TODOKE:"));
                }
                drop(core.stop_pairing());
            }
            8 => drop(core.pair_scan_qr(input.text())),
            9 => drop(core.pair_enter_code(input.text(), input.hex())),
            10 => drop(core.stop_pairing()),
            11 => {
                if let Ok(transfer) = core.transfer(input.hex()) {
                    transfers.push(transfer);
                }
            }
            12 => {
                if let Some(transfer) = transfers.last() {
                    let files = (0..input.byte().unwrap_or(0) % 4)
                        .map(|_| u32::from(input.byte().unwrap_or(0)))
                        .collect();
                    assert!(transfer.accept(files).is_err());
                }
            }
            13 => {
                if let Some(transfer) = transfers.pop() {
                    drop(transfer.decline());
                    drop(transfer.cancel());
                    drop(transfer.info());
                }
            }
            14 => {
                if let Ok(contact) = core.contact(input.hex()) {
                    // Paths inside the scratch directory, or relative.
                    let name = input.text().replace(['/', '\\', '\0'], "_");
                    let path = if op & 0x80 == 0 {
                        harness.scratch.join(name).display().to_string()
                    } else {
                        name
                    };
                    assert!(contact.send(vec![path]).is_err());
                }
            }
            15 => core.set_notifier(Arc::new(Quiet)),
            16 => core.clear_notifier(),
            17 => {
                if let Ok(code) = core.pair_show_code() {
                    assert!(!code.code().is_empty());
                }
                drop(core.stop_pairing());
            }
            18 => match core.subscribe() {
                Ok(events) => subscriptions.push(events),
                Err(error) => assert!(matches!(error, TodokeError::State { .. })),
            },
            19 => {
                if let Some(events) = subscriptions.last() {
                    let max = u32::from(input.byte().unwrap_or(0));
                    // Never waits: nothing else feeds the core.
                    drop(events.next(max, 0));
                }
            }
            20 => {
                if let Some(events) = subscriptions.pop() {
                    events.stop();
                    assert!(matches!(events.next(1, 0), Err(TodokeError::State { .. })));
                }
            }
            _ => {
                // A second profile with a key store that misbehaves: a
                // typed error or a core, never a panic, and an all-zero or
                // short key is never used.
                let answer = input.byte().unwrap_or(0);
                let key = input.bytes(40);
                let weak = key.len() != 32 || key.iter().all(|&byte| byte == 0);
                let home = harness.scratch.join("key-store");
                let _ = std::fs::remove_dir_all(&home);
                let store = Arc::new(Faulty { answer, key });
                let started =
                    Core::with_key_store(settings(&home, KeyStoragePolicy::Platform), store);
                if answer % 4 == 0 && weak {
                    assert!(started.is_err());
                }
                drop(started);
                let _ = std::fs::remove_dir_all(&home);
            }
        }
    }
});
