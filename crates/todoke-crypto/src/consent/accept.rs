//! The signed `Accept` (`AcceH`, §7.2, §7.3).

use core::fmt;

use todoke_proto::time::UnixTime;
use todoke_proto::transfer::{ACCEPT_HASH_DOMAIN, Accept, AcceptBody, DecodeError, TransferId};

use super::{CLOCK_SKEW_SECONDS, CanonicalManifest, SessionBinding, Side, add_seconds, random_id};
use crate::content::AcceptedFile;
use crate::identity::{KeyId, KeyStore, KeyStoreError, Signature, SigningDomain};

/// The longest Accept lifetime: 24 hours (§7.3, §13).
pub const ACCEPT_LIFETIME_SECONDS: u64 = 24 * 3600;

/// `accept_hash = B3("todoke/v1/accept-hash\0" || complete_signed_AcceH)`
/// (§7.3).
#[must_use]
pub fn accept_hash(signed_record: &[u8]) -> [u8; 32] {
    let mut hasher = blake3::Hasher::new();
    hasher.update(ACCEPT_HASH_DOMAIN);
    hasher.update(signed_record);
    *hasher.finalize().as_bytes()
}

/// Why an Accept was refused or could not be issued. Carries no peer data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AcceptError {
    /// The record's layout is invalid (`MALFORMED`).
    Malformed(DecodeError),
    /// It names another session (§7.3: "excludes use in another session").
    Session,
    /// It names another transfer.
    Transfer,
    /// It names another manifest hash.
    ManifestHash,
    /// Its sender is not this session's sender and the manifest's.
    Sender,
    /// Its receiver is not this session's receiver and the manifest's.
    Receiver,
    /// `expires_at` has passed, or is beyond the manifest's expiry or 24
    /// hours from now (§7.3).
    Expiry,
    /// A selected ID is not a regular file of the manifest (§7.3).
    Selection,
    /// The receiver's signature does not verify.
    Signature,
    /// The signing key is not this session's receiver key, or this device
    /// is not the manifest's recipient.
    Role,
    /// The key store could not sign.
    KeyStore(KeyStoreError),
    /// OS randomness was unavailable for the nonce.
    Random,
}

impl fmt::Display for AcceptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(error) => write!(f, "malformed accept: {error}"),
            Self::Session => f.write_str("accept is for another session"),
            Self::Transfer => f.write_str("accept is for another transfer"),
            Self::ManifestHash => f.write_str("accept is for another manifest"),
            Self::Sender => f.write_str("accept names the wrong sender"),
            Self::Receiver => f.write_str("accept names the wrong receiver"),
            Self::Expiry => f.write_str("accept expiry is invalid or passed"),
            Self::Selection => f.write_str("accept selects an entry that is not a file"),
            Self::Signature => f.write_str("accept signature does not verify"),
            Self::Role => f.write_str("this device cannot issue this accept"),
            Self::KeyStore(error) => write!(f, "key store: {error}"),
            Self::Random => f.write_str("randomness unavailable"),
        }
    }
}

impl std::error::Error for AcceptError {}

/// An Accept this crate verified for one session and one canonical
/// manifest (§7.3), and the [`AcceptedFile`] of each selected file.
///
/// The only way to obtain one is [`verify_accept`] (the sender) or
/// [`sign_accept`] (the receiver, which verifies its own record before
/// returning it). It does not expire by itself: the transfer engine must
/// stop using it at [`Self::expires_at`] and on cancel, reject, failure, or
/// the end of the session.
pub struct VerifiedAccept {
    accept: Accept,
    encoded: Vec<u8>,
    hash: [u8; 32],
    /// Accepted files in selection (ID) order.
    files: Vec<AcceptedFile>,
    selected_bytes: u64,
}

impl VerifiedAccept {
    /// The complete signed record, as sent on the wire.
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// `accept_hash` (§7.3): every `ChunkRequest`, `Chunk`, `FileKey`,
    /// resume record, `Complete`, and receipt of this authorization names it.
    #[must_use]
    pub const fn accept_hash(&self) -> &[u8; 32] {
        &self.hash
    }

    /// The decoded record.
    #[must_use]
    pub const fn record(&self) -> &Accept {
        &self.accept
    }

    /// The session it is bound to.
    #[must_use]
    pub const fn session_id(&self) -> &[u8; 32] {
        self.accept.body().session_id()
    }

    /// The accepted transfer.
    #[must_use]
    pub const fn transfer_id(&self) -> &TransferId {
        self.accept.body().transfer_id()
    }

    /// The accepted manifest's hash.
    #[must_use]
    pub const fn manifest_hash(&self) -> &[u8; 32] {
        self.accept.body().manifest_hash()
    }

    /// The per-session nonce.
    #[must_use]
    pub const fn nonce(&self) -> &[u8; 16] {
        self.accept.body().accept_nonce()
    }

    /// When this authorization ends; content pauses then (§7.3).
    #[must_use]
    pub const fn expires_at(&self) -> UnixTime {
        self.accept.body().expires_at()
    }

    /// The selected regular-file IDs, strictly increasing.
    #[must_use]
    pub fn selection(&self) -> &[u32] {
        self.accept.body().selection()
    }

    /// How many files are selected (1..=10000).
    #[must_use]
    pub fn selected_count(&self) -> u32 {
        // At most 10000 by the record layout.
        u32::try_from(self.files.len()).unwrap_or(u32::MAX)
    }

    /// The sum of the selected files' sizes.
    #[must_use]
    pub const fn selected_bytes(&self) -> u64 {
        self.selected_bytes
    }

    /// The accepted file `file_id`, or `None` if it is not selected.
    #[must_use]
    pub fn file(&self, file_id: u32) -> Option<AcceptedFile> {
        self.files
            .binary_search_by_key(&file_id, |file| file.binding().file_id())
            .ok()
            .and_then(|index| self.files.get(index).copied())
    }

    /// Every accepted file, in ID order.
    #[must_use]
    pub fn files(&self) -> &[AcceptedFile] {
        &self.files
    }
}

impl fmt::Debug for VerifiedAccept {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedAccept")
            .field("accept_hash", &crate::identity::Hex(&self.hash))
            .field("expires_at", &self.expires_at())
            .field("selected", &self.files.len())
            .finish_non_exhaustive()
    }
}

/// Verifies an Accept received from the peer, on the sender (§7.3).
///
/// `now` is the trusted wall-clock time. Checks, in order: the layout; the
/// session ID; the transfer ID and manifest hash against `manifest`; that
/// this device is the manifest's and the record's sender and the peer its
/// receiver; that `expires_at` is in the future, no later than the
/// manifest's expiry, and no more than 24 hours (plus the 120-second skew
/// allowance) from now; that every selected ID is a regular file of the
/// manifest; and the receiver's strict Ed25519 signature.
///
/// The caller must still reject a replayed nonce or a conflicting second
/// Accept in the same session, and check revocation (§7.3).
///
/// # Errors
///
/// Any [`AcceptError`] except [`AcceptError::Role`],
/// [`AcceptError::KeyStore`], and [`AcceptError::Random`].
pub fn verify_accept(
    record: &[u8],
    session: &SessionBinding,
    manifest: &CanonicalManifest,
    now: UnixTime,
) -> Result<VerifiedAccept, AcceptError> {
    let accept = Accept::decode(record).map_err(AcceptError::Malformed)?;
    check(
        accept,
        record.to_vec(),
        Side::Sender,
        session,
        manifest,
        now,
    )
}

/// Issues the receiver's Accept for `selection` and returns it verified
/// (§7.2, §7.3).
///
/// **Call only on locally authorized user intent** for this validated
/// manifest and this explicit selection: a UI boolean, discovery match,
/// trusted contact, or connection is not consent (§7.2). The nonce is
/// fresh from the OS CSPRNG. `expires_at` must be in the future and no
/// later than both the manifest's expiry and 24 hours from `now`.
///
/// The record is checked with the same rules a sender applies before it is
/// returned, so a receiver never sends an Accept its peer must refuse.
///
/// # Errors
///
/// [`AcceptError::Role`] if `device_key` is not this session's local
/// device key or this device is not the manifest's recipient;
/// [`AcceptError::Malformed`] for an empty, unsorted, or oversized
/// selection; [`AcceptError::Selection`] for an ID that is not a regular
/// file; [`AcceptError::Expiry`]; [`AcceptError::KeyStore`];
/// [`AcceptError::Random`].
pub fn sign_accept<K: KeyStore>(
    keys: &K,
    device_key: &KeyId,
    session: &SessionBinding,
    manifest: &CanonicalManifest,
    selection: Vec<u32>,
    expires_at: UnixTime,
    now: UnixTime,
) -> Result<VerifiedAccept, AcceptError> {
    let nonce = random_id().map_err(|_| AcceptError::Random)?;
    sign_accept_with_nonce(
        keys, device_key, session, manifest, selection, nonce, expires_at, now,
    )
}

#[expect(
    clippy::too_many_arguments,
    reason = "sign_accept plus the explicit nonce the fixture test needs"
)]
pub(crate) fn sign_accept_with_nonce<K: KeyStore>(
    keys: &K,
    device_key: &KeyId,
    session: &SessionBinding,
    manifest: &CanonicalManifest,
    selection: Vec<u32>,
    nonce: [u8; 16],
    expires_at: UnixTime,
    now: UnixTime,
) -> Result<VerifiedAccept, AcceptError> {
    let public = keys.public_key(device_key).map_err(AcceptError::KeyStore)?;
    if public != *session.local_device() || public != *manifest.recipient() {
        return Err(AcceptError::Role);
    }
    let body = AcceptBody::new(
        *session.session_id(),
        *manifest.transfer_id(),
        *manifest.hash(),
        *manifest.sender().as_bytes(),
        *public.as_bytes(),
        nonce,
        expires_at,
        selection,
    )
    .map_err(AcceptError::Malformed)?;
    // Check everything a sender will check before spending a signature.
    check_body(&body, Side::Receiver, session, manifest, now)?;
    let signature = keys
        .sign(device_key, SigningDomain::Accept, &body.encode())
        .map_err(AcceptError::KeyStore)?;
    let accept = Accept::new(body, signature.to_bytes());
    let encoded = accept.encode();
    check(accept, encoded, Side::Receiver, session, manifest, now)
}

/// Everything except the signature.
fn check_body(
    body: &AcceptBody,
    side: Side,
    session: &SessionBinding,
    manifest: &CanonicalManifest,
    now: UnixTime,
) -> Result<u64, AcceptError> {
    if body.session_id() != session.session_id() {
        return Err(AcceptError::Session);
    }
    if body.transfer_id() != manifest.transfer_id() {
        return Err(AcceptError::Transfer);
    }
    if body.manifest_hash() != manifest.hash() {
        return Err(AcceptError::ManifestHash);
    }
    let (sender, receiver) = side.keys(session);
    if body.sender_public() != sender.as_bytes() || sender != manifest.sender() {
        return Err(AcceptError::Sender);
    }
    if body.receiver_public() != receiver.as_bytes() || receiver != manifest.recipient() {
        return Err(AcceptError::Receiver);
    }
    let expires = body.expires_at();
    // Future at receipt (strictly: an expired authorization pauses content
    // at once); no later than the manifest; within 24 hours of now, allowing
    // the signer's clock to be up to 120 seconds ahead of ours (§1).
    if expires <= now
        || expires > manifest.expires_at()
        || expires.seconds() > add_seconds(now, ACCEPT_LIFETIME_SECONDS + CLOCK_SKEW_SECONDS)
    {
        return Err(AcceptError::Expiry);
    }
    let mut selected_bytes: u64 = 0;
    for &id in body.selection() {
        let file = manifest.file(id).ok_or(AcceptError::Selection)?;
        // At most 16 TiB by the manifest's checked sum.
        selected_bytes = selected_bytes.saturating_add(file.layout().size());
    }
    Ok(selected_bytes)
}

fn check(
    accept: Accept,
    encoded: Vec<u8>,
    side: Side,
    session: &SessionBinding,
    manifest: &CanonicalManifest,
    now: UnixTime,
) -> Result<VerifiedAccept, AcceptError> {
    let selected_bytes = check_body(accept.body(), side, session, manifest, now)?;
    let (_, receiver) = side.keys(session);
    receiver
        .verify(
            SigningDomain::Accept,
            &accept.body().encode(),
            &Signature::from_bytes(*accept.signature()),
        )
        .map_err(|_| AcceptError::Signature)?;
    let mut files = Vec::with_capacity(accept.body().selection().len());
    for &id in accept.body().selection() {
        let binding = manifest.file(id).ok_or(AcceptError::Selection)?;
        files.push(AcceptedFile::from_verified_accept(*binding));
    }
    let hash = accept_hash(&encoded);
    Ok(VerifiedAccept {
        accept,
        encoded,
        hash,
        files,
        selected_bytes,
    })
}
