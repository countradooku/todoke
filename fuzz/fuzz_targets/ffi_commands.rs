//! The binding's boundary under random command sequences, as a buggy or
//! hostile app could drive it: malformed IDs, QR text, codes, and paths,
//! handles used after their transfer is gone, pairing started and stopped,
//! the notifier set and cleared. Every outcome must be an answer or a typed
//! error: no panic, no hang. One core runs for the whole process, in a
//! scratch profile with no contacts (nothing can be sent anywhere).
#![no_main]

use std::sync::{Arc, OnceLock};

use libfuzzer_sys::fuzz_target;
use todoke_ffi::types::{KeyStoragePolicy, Settings};
use todoke_ffi::{Core, Notifier, OfferNotice};

struct Harness {
    core: Core,
    runtime: tokio::runtime::Runtime,
    scratch: std::path::PathBuf,
}

struct Quiet;

impl Notifier for Quiet {
    fn offer_received(&self, _: OfferNotice) {}
    fn offer_gone(&self, _: String) {}
    fn transfer_finished(&self, _: String, _: String) {}
}

fn harness() -> &'static Harness {
    static HARNESS: OnceLock<Harness> = OnceLock::new();
    HARNESS.get_or_init(|| {
        let scratch = std::env::temp_dir().join(format!("todoke-fuzz-ffi-{}", std::process::id()));
        let _ = std::fs::create_dir_all(scratch.join("downloads"));
        let settings = Settings {
            home: scratch.display().to_string(),
            downloads: scratch.join("downloads").display().to_string(),
            lan: false,
            allow_loopback: false,
            hidden: true,
            history_days: 0,
            key_storage: KeyStoragePolicy::File,
        };
        let Ok(core) = Core::new(settings) else {
            std::process::abort();
        };
        let Ok(runtime) = tokio::runtime::Builder::new_current_thread().enable_all().build() else {
            std::process::abort();
        };
        Harness {
            core,
            runtime,
            scratch,
        }
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

    fn text(&mut self) -> String {
        let length = usize::from(self.byte().unwrap_or(0) % 80);
        let take = length.min(self.0.len());
        let (text, rest) = self.0.split_at(take);
        self.0 = rest;
        String::from_utf8_lossy(text).into_owned()
    }

    fn hex(&mut self) -> String {
        let length = usize::from(self.byte().unwrap_or(0) % 70);
        (0..length)
            .map(|_| char::from(b"0123456789abcdefABCDEFgz"[usize::from(self.byte().unwrap_or(0) % 24)]))
            .collect()
    }
}

fuzz_target!(|data: &[u8]| {
    let harness = harness();
    let core = &harness.core;
    let mut input = Input(data);
    let mut transfers = Vec::new();
    let mut steps = 0;
    while let Some(op) = input.byte() {
        steps += 1;
        if steps > 32 {
            break;
        }
        harness.runtime.block_on(async {
            match op % 18 {
                0 => drop(core.status().await),
                1 => drop(core.contacts().await),
                2 => drop(core.transfers().await),
                3 => drop(core.offers().await),
                4 => drop(core.history().await),
                5 => drop(core.strangers().await),
                6 => drop(core.set_hidden(op & 0x80 == 0).await),
                7 => {
                    if let Ok(offer) = core.pair_show_qr().await {
                        assert_eq!(offer.modules().len(), (offer.width() * offer.width()) as usize);
                        assert!(offer.text().starts_with("TODOKE:"));
                    }
                    drop(core.stop_pairing().await);
                }
                8 => drop(core.pair_scan_qr(input.text()).await),
                9 => drop(core.pair_enter_code(input.text(), input.hex()).await),
                10 => drop(core.stop_pairing().await),
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
                        assert!(transfer.accept(files).await.is_err());
                    }
                }
                13 => {
                    if let Some(transfer) = transfers.pop() {
                        drop(transfer.decline().await);
                        drop(transfer.cancel().await);
                        drop(transfer.info().await);
                    }
                }
                14 => {
                    if let Ok(contact) = core.contact(input.hex()) {
                        // Paths inside the scratch directory only.
                        let path = harness.scratch.join(input.text().replace(['/', '\\', '\0'], "_"));
                        assert!(contact.send(vec![path.display().to_string()]).await.is_err());
                    }
                }
                15 => core.set_notifier(Arc::new(Quiet)),
                16 => core.clear_notifier(),
                _ => {
                    let events = core.events();
                    while events.pop_event().is_some() {}
                }
            }
        });
    }
});
