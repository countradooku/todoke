//! The §13 timers and budgets the engine enforces. All are upper bounds
//! from the protocol; none is configurable upward.

use core::time::Duration;

/// Each peer's `Capabilities` must arrive within 5 seconds of the ratchet
/// gate opening (§6, §13).
pub const CAPABILITIES_TIMEOUT: Duration = Duration::from_secs(5);
/// A manifest must be complete within 30 seconds of `ManifestStart`
/// (§7.1, §13).
pub const MANIFEST_ASSEMBLY_TIMEOUT: Duration = Duration::from_secs(30);
/// The consent prompt lasts at most 300 seconds from the complete manifest,
/// then the offer is rejected as expired (§13).
pub const CONSENT_PROMPT_TIMEOUT: Duration = Duration::from_secs(300);
/// An outstanding `ChunkRequest` times out after 30 seconds; the session
/// closes and the transfer resumes later (§13).
pub const CHUNK_REQUEST_TIMEOUT: Duration = Duration::from_secs(30);
/// A `Cancel` must be acknowledged within 5 seconds or the session closes
/// (§7.6, §13).
pub const CANCEL_ACK_TIMEOUT: Duration = Duration::from_secs(5);
/// The delivery receipt must follow `Complete` within 10 seconds; otherwise
/// delivery is shown as unconfirmed (§7.7, §13).
pub const RECEIPT_TIMEOUT: Duration = Duration::from_secs(10);
/// At most 2 concurrent incoming transfers per endpoint (§7, §13).
pub const MAX_INCOMING_TRANSFERS: usize = 2;
/// At most 2 active incoming files per endpoint (§7, §13).
pub const MAX_ACTIVE_INCOMING_FILES: usize = 2;
/// At most one incomplete incoming manifest per endpoint (§7.1, §13).
pub const MAX_INCOMPLETE_MANIFESTS: usize = 1;
/// At most 64 forwarded `Revoke` records per session (§2, §13).
pub const MAX_REVOCATIONS: usize = 64;
/// Per-session resume metadata in memory: at most 8 MiB (§7.5).
pub const RESUME_METADATA_BUDGET: usize = 8 << 20;
/// Application buffers per session, excluding manifest and resume
/// metadata: at most 16 MiB (§13). The engine takes no more input while
/// this many bytes of frames wait to be sent.
pub const APP_BUFFER_BUDGET: usize = 16 << 20;
/// A cancel tombstone outlives the manifest by at least 120 seconds (§7.6).
pub const TOMBSTONE_GRACE_SECONDS: u64 = 120;
/// Retained segments revalidated per engine call, so that a large resumed
/// file does not stall the session (§7.5 revalidation before advertising).
pub const REVALIDATION_BUDGET: u32 = 64;
/// How often progress events are emitted at most.
pub const PROGRESS_INTERVAL: Duration = Duration::from_millis(250);
/// The window over which transfer speed is measured.
pub const SPEED_WINDOW: Duration = Duration::from_secs(5);
