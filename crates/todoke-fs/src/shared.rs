//! [`SharedSink`]: one [`FsSink`] serving several sessions' engines.

use core::fmt;
use std::sync::{Arc, Mutex, MutexGuard};

use todoke_crypto::consent::{CanonicalManifest, VerifiedAccept};
use todoke_crypto::content::{AcceptedFile, FileMaster, VerifiedSegment};
use todoke_crypto::identity::{Ed25519PublicKey, Sealer};
use todoke_proto::time::UnixTime;
use todoke_transfer::{ReceiveSink, Retained, SinkError, SinkRefusal, TransferId};

use crate::FsSink;
use crate::dest::Destination;

/// A cloneable handle to one [`FsSink`]: a state directory has exactly one
/// writer, so concurrent sessions (one engine each) share it through this
/// handle. Every call takes the lock for its duration. If a thread
/// panicked while holding it, the sink fails closed: writes fail with
/// `STORAGE`, transfers count as tombstoned and not retained, and no new
/// transfer is taken.
pub struct SharedSink<D: Destination, S: Sealer>(Arc<Mutex<FsSink<D, S>>>);

impl<D: Destination, S: Sealer> SharedSink<D, S> {
    /// Shares `sink`.
    #[must_use]
    pub fn new(sink: FsSink<D, S>) -> Self {
        Self(Arc::new(Mutex::new(sink)))
    }

    /// Locks the sink for direct use (plans, published paths, reports).
    ///
    /// # Errors
    ///
    /// [`SinkError::Storage`] if the lock is poisoned.
    pub fn lock(&self) -> Result<MutexGuard<'_, FsSink<D, S>>, SinkError> {
        self.0.lock().map_err(|_| SinkError::Storage)
    }
}

impl<D: Destination, S: Sealer> Clone for SharedSink<D, S> {
    fn clone(&self) -> Self {
        Self(Arc::clone(&self.0))
    }
}

impl<D: Destination, S: Sealer> fmt::Debug for SharedSink<D, S> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SharedSink")
    }
}

impl<D: Destination, S: Sealer> ReceiveSink for SharedSink<D, S> {
    fn check_offer(&mut self, manifest: &CanonicalManifest) -> Result<(), SinkRefusal> {
        self.lock()
            .map_err(|_| SinkRefusal::UnsupportedDestination)?
            .check_offer(manifest)
    }

    fn is_tombstoned(&self, transfer_id: &TransferId, now: UnixTime) -> bool {
        self.lock()
            .map_or(true, |sink| sink.is_tombstoned(transfer_id, now))
    }

    fn tombstone(&mut self, transfer_id: &TransferId, until: UnixTime) {
        if let Ok(mut sink) = self.lock() {
            sink.tombstone(transfer_id, until);
        }
    }

    fn tombstone_room(&mut self, now: UnixTime) -> bool {
        self.lock().is_ok_and(|mut sink| sink.tombstone_room(now))
    }

    fn retained(&self, transfer_id: &TransferId, now: UnixTime) -> Option<Retained> {
        self.lock().ok()?.retained(transfer_id, now)
    }

    fn record_accept(
        &mut self,
        manifest: &CanonicalManifest,
        accept: &VerifiedAccept,
    ) -> Result<(), SinkError> {
        self.lock()?.record_accept(manifest, accept)
    }

    fn record_file_key(
        &mut self,
        file: &AcceptedFile,
        master: &FileMaster,
    ) -> Result<(), SinkError> {
        self.lock()?.record_file_key(file, master)
    }

    fn retained_segment(
        &mut self,
        transfer_id: &TransferId,
        file_id: u32,
        index: u32,
    ) -> Result<Option<Vec<u8>>, SinkError> {
        self.lock()?.retained_segment(transfer_id, file_id, index)
    }

    fn drop_segment(&mut self, transfer_id: &TransferId, file_id: u32, index: u32) {
        if let Ok(mut sink) = self.lock() {
            sink.drop_segment(transfer_id, file_id, index);
        }
    }

    fn store_segment(
        &mut self,
        segment: &VerifiedSegment,
        ciphertext: &[u8],
    ) -> Result<(), SinkError> {
        self.lock()?.store_segment(segment, ciphertext)
    }

    fn publish(&mut self, manifest: &CanonicalManifest, file_id: u32) -> Result<(), SinkError> {
        self.lock()?.publish(manifest, file_id)
    }

    fn published_intact(&mut self, manifest: &CanonicalManifest, file_id: u32) -> bool {
        self.lock()
            .is_ok_and(|mut sink| sink.published_intact(manifest, file_id))
    }

    fn finish(&mut self, transfer_id: &TransferId) {
        if let Ok(mut sink) = self.lock() {
            sink.finish(transfer_id);
        }
    }

    fn revoke_sender(&mut self, sender: &Ed25519PublicKey, until: UnixTime) {
        if let Ok(mut sink) = self.lock() {
            sink.revoke_sender(sender, until);
        }
    }
}
