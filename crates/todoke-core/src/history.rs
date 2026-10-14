//! The history of finished transfers: sealed at rest under the storage key
//! in `history.bin`, kept for `history_days` (§7.7 leaves receipt retention
//! to local policy), at most [`MAX_ENTRIES`].
//!
//! The history is a convenience, not security state: a blob that does not
//! open (damaged, or sealed under another key) is replaced by an empty
//! history rather than stopping the core.

use std::path::{Path, PathBuf};

use todoke_crypto::identity::{BlobStorage, FileStorage, Sealer};
use todoke_proto::time::UnixTime;

use crate::api::HistoryEntry;

/// The sealing context of `history.bin`.
const CONTEXT: &[u8] = b"todoke/v1/core/history\0";
/// The most entries kept; the oldest go first.
pub const MAX_ENTRIES: usize = 2000;
/// The largest blob read back: [`MAX_ENTRIES`] entries of eight 255-byte
/// names and their hex fields, with room to spare.
const MAX_BLOB: usize = 16 << 20;
const DAY: u64 = 86_400;

/// The history store.
pub struct History<S> {
    path: PathBuf,
    sealer: S,
    days: u32,
    entries: Vec<HistoryEntry>,
}

impl<S: Sealer> History<S> {
    /// Opens the history in `dir`, keeping `days` days at `now`. With
    /// `days` 0 any stored history is deleted.
    #[must_use]
    pub fn open(dir: &Path, sealer: S, days: u32, now: UnixTime) -> Self {
        let path = dir.join("history.bin");
        let mut history = Self {
            path,
            sealer,
            days,
            entries: Vec::new(),
        };
        if days == 0 {
            history.delete();
            return history;
        }
        let storage = FileStorage::new(&history.path);
        if let Ok(Some(sealed)) = storage.load(MAX_BLOB)
            && let Ok(plain) = history.sealer.open(CONTEXT, &sealed)
            && let Ok(entries) = serde_json::from_slice::<Vec<serde_json::Value>>(&plain)
        {
            // An entry this version cannot read (written by a later one,
            // say) is dropped alone, not the whole history.
            history.entries = entries
                .into_iter()
                .filter_map(|entry| serde_json::from_value(entry).ok())
                .collect();
        }
        if history.prune(now) {
            history.persist();
        }
        history
    }

    /// Records a finished transfer at `now`; returns whether it was kept
    /// durably.
    pub fn record(&mut self, entry: HistoryEntry, now: UnixTime) -> bool {
        if self.days == 0 {
            return true;
        }
        self.entries.retain(|old| old.transfer != entry.transfer);
        self.entries.push(entry);
        self.prune(now);
        self.persist()
    }

    /// The entries kept at `now`, newest first.
    #[must_use]
    pub fn list(&self, now: UnixTime) -> Vec<HistoryEntry> {
        let oldest = self.oldest(now);
        self.entries
            .iter()
            .rev()
            .filter(|entry| entry.finished_at >= oldest)
            .cloned()
            .collect()
    }

    /// Forgets every entry; returns whether the stored history is gone.
    pub fn clear(&mut self) -> bool {
        self.entries.clear();
        self.delete()
    }

    /// How many days entries stay.
    #[must_use]
    pub const fn days(&self) -> u32 {
        self.days
    }

    fn oldest(&self, now: UnixTime) -> u64 {
        now.seconds()
            .saturating_sub(u64::from(self.days).saturating_mul(DAY))
    }

    /// Drops expired entries and those past [`MAX_ENTRIES`]; returns
    /// whether any went.
    fn prune(&mut self, now: UnixTime) -> bool {
        let before = self.entries.len();
        let oldest = self.oldest(now);
        self.entries.retain(|entry| entry.finished_at >= oldest);
        let excess = self.entries.len().saturating_sub(MAX_ENTRIES);
        self.entries.drain(..excess);
        self.entries.len() != before
    }

    fn persist(&self) -> bool {
        let Ok(plain) = serde_json::to_vec(&self.entries) else {
            return false;
        };
        let plain = zeroize::Zeroizing::new(plain);
        let Ok(sealed) = self.sealer.seal(CONTEXT, &plain) else {
            return false;
        };
        FileStorage::new(&self.path).store(&sealed).is_ok()
    }

    fn delete(&self) -> bool {
        match std::fs::remove_file(&self.path) {
            Ok(()) => true,
            Err(error) => error.kind() == std::io::ErrorKind::NotFound,
        }
    }
}

#[cfg(test)]
mod tests {
    use todoke_crypto::identity::{SoftwareSealer, StorageKey};

    use super::*;
    use crate::api::{ReceiptInfo, TransferState, Way};
    use crate::profile::tests::Scratch;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn sealer(byte: u8) -> SoftwareSealer {
        SoftwareSealer::new(StorageKey::from_bytes(zeroize::Zeroizing::new([byte; 32])))
    }

    fn at(seconds: u64) -> Result<UnixTime, &'static str> {
        UnixTime::new(seconds).ok_or("time")
    }

    fn entry(transfer: &str, finished_at: u64) -> HistoryEntry {
        HistoryEntry {
            transfer: transfer.into(),
            peer: "aa".into(),
            way: Way::Incoming,
            state: TransferState::Received,
            detail: None,
            finished_at,
            files: 1,
            bytes: 2,
            names: vec!["secret-report.pdf".into()],
            manifest_hash: Some("cd".into()),
            receipt: Some(ReceiptInfo {
                id: "ef".into(),
                completed_at: finished_at,
            }),
        }
    }

    #[test]
    fn entries_survive_a_restart_sealed_newest_first() -> TestResult {
        let dir = Scratch::new("history-restart")?;
        std::fs::create_dir_all(&dir.0)?;
        let now = at(10 * DAY)?;
        let mut history = History::open(dir.0.as_path(), sealer(1), 30, now);
        assert!(history.record(entry("01", now.seconds() - 5), now));
        assert!(history.record(entry("02", now.seconds()), now));
        // The same transfer again replaces its entry.
        assert!(history.record(entry("01", now.seconds() - 1), now));
        let reopened = History::open(dir.0.as_path(), sealer(1), 30, now);
        let listed: Vec<_> = reopened.list(now).into_iter().map(|e| e.transfer).collect();
        assert_eq!(listed, ["01", "02"]);
        // Nothing is stored in the clear.
        let raw = std::fs::read(dir.0.as_path().join("history.bin"))?;
        assert!(!raw.windows(6).any(|window| window == b"secret"));
        // Another key opens nothing, and the core still starts.
        assert_eq!(
            History::open(dir.0.as_path(), sealer(2), 30, now).list(now),
            Vec::<HistoryEntry>::new()
        );
        Ok(())
    }

    #[test]
    fn entries_expire_and_are_bounded() -> TestResult {
        let dir = Scratch::new("history-expire")?;
        std::fs::create_dir_all(&dir.0)?;
        let now = at(100 * DAY)?;
        let mut history = History::open(dir.0.as_path(), sealer(1), 7, now);
        history.record(entry("old", now.seconds() - 8 * DAY), now);
        history.record(entry("new", now.seconds() - 6 * DAY), now);
        assert_eq!(history.list(now).len(), 1);
        // Expiry also applies on open, a day later.
        let later = at(now.seconds() + 2 * DAY)?;
        assert_eq!(
            History::open(dir.0.as_path(), sealer(1), 7, later).list(later),
            Vec::<HistoryEntry>::new()
        );
        let mut history = History::open(dir.0.as_path(), sealer(1), 7, now);
        for index in 0..MAX_ENTRIES + 5 {
            history
                .entries
                .push(entry(&format!("{index:04x}"), now.seconds()));
        }
        history.record(entry("last", now.seconds()), now);
        let listed = history.list(now);
        assert_eq!(listed.len(), MAX_ENTRIES);
        assert_eq!(listed[0].transfer, "last");
        Ok(())
    }

    /// An unreadable entry costs only itself.
    #[test]
    fn unreadable_entries_are_dropped_alone() -> TestResult {
        let dir = Scratch::new("history-unreadable")?;
        std::fs::create_dir_all(&dir.0)?;
        let now = at(DAY)?;
        let mut good = serde_json::to_value(entry("01", now.seconds()))?;
        let mut bad = good.clone();
        bad["state"] = "teleported".into();
        good["transfer"] = "02".into();
        let plain = serde_json::to_vec(&vec![bad, good])?;
        let sealed = sealer(1).seal(CONTEXT, &plain)?;
        FileStorage::new(dir.0.join("history.bin")).store(&sealed)?;
        let history = History::open(dir.0.as_path(), sealer(1), 30, now);
        let listed: Vec<_> = history.list(now).into_iter().map(|e| e.transfer).collect();
        assert_eq!(listed, ["02"]);
        Ok(())
    }

    #[test]
    fn zero_days_and_clear_delete_the_stored_history() -> TestResult {
        let dir = Scratch::new("history-clear")?;
        std::fs::create_dir_all(&dir.0)?;
        let now = at(DAY)?;
        let mut history = History::open(dir.0.as_path(), sealer(1), 30, now);
        history.record(entry("01", now.seconds()), now);
        assert!(dir.0.as_path().join("history.bin").exists());
        assert!(history.clear());
        assert!(!dir.0.as_path().join("history.bin").exists());
        assert_eq!(history.list(now), Vec::<HistoryEntry>::new());
        history.record(entry("02", now.seconds()), now);
        let mut off = History::open(dir.0.as_path(), sealer(1), 0, now);
        assert!(!dir.0.as_path().join("history.bin").exists());
        assert!(off.record(entry("03", now.seconds()), now));
        assert_eq!(off.list(now), Vec::<HistoryEntry>::new());
        assert!(!dir.0.as_path().join("history.bin").exists());
        Ok(())
    }
}
