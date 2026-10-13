//! The signed `DeliveryReceipt` (§7.7).

use core::fmt;

use todoke_proto::time::UnixTime;
use todoke_proto::transfer::{
    DELIVERY_RECEIPT_LEN, DecodeError, DeliveryReceipt, ReceiptBody, TransferId,
};

use super::{CLOCK_SKEW_SECONDS, SessionBinding, Side, VerifiedAccept, add_seconds, random_id};
use crate::identity::{KeyId, KeyStore, KeyStoreError, Signature, SigningDomain};

/// Why a delivery receipt was refused or could not be issued. Carries no
/// peer data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ReceiptError {
    /// The record's layout is invalid (`MALFORMED`).
    Malformed(DecodeError),
    /// It names another session, transfer, manifest, or Accept.
    Binding,
    /// Its sender or receiver is not this session's.
    Parties,
    /// `completed_count` or `total_plaintext_bytes` differ from the
    /// accepted selection.
    Totals,
    /// `completed_at` predates the session, follows the Accept's expiry, or
    /// is more than 120 seconds ahead of the verifier's clock (§7.7).
    Time,
    /// The receiver's signature does not verify.
    Signature,
    /// The signing key is not this session's local device key.
    Role,
    /// The key store could not sign.
    KeyStore(KeyStoreError),
    /// OS randomness was unavailable for the receipt ID.
    Random,
}

impl fmt::Display for ReceiptError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed(error) => write!(f, "malformed receipt: {error}"),
            Self::Binding => f.write_str("receipt is for another session or transfer"),
            Self::Parties => f.write_str("receipt names the wrong devices"),
            Self::Totals => f.write_str("receipt totals differ from the accepted selection"),
            Self::Time => f.write_str("receipt completion time is invalid"),
            Self::Signature => f.write_str("receipt signature does not verify"),
            Self::Role => f.write_str("this device cannot issue this receipt"),
            Self::KeyStore(error) => write!(f, "key store: {error}"),
            Self::Random => f.write_str("randomness unavailable"),
        }
    }
}

impl std::error::Error for ReceiptError {}

/// A delivery receipt this crate verified against the session and the
/// Accept it confirms (§7.7). An authenticated receiver claim, not proof
/// that a person read a file.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct VerifiedReceipt {
    receipt: DeliveryReceipt,
}

impl VerifiedReceipt {
    /// The complete signed record, as sent on the wire.
    #[must_use]
    pub fn encode(&self) -> [u8; DELIVERY_RECEIPT_LEN] {
        self.receipt.encode()
    }

    /// The decoded record.
    #[must_use]
    pub const fn record(&self) -> &DeliveryReceipt {
        &self.receipt
    }

    /// The confirmed transfer.
    #[must_use]
    pub const fn transfer_id(&self) -> &TransferId {
        self.receipt.body().transfer_id()
    }

    /// The receipt's random ID.
    #[must_use]
    pub const fn receipt_id(&self) -> &[u8; 16] {
        self.receipt.body().receipt_id()
    }

    /// When the receiver finished publication, on its clock.
    #[must_use]
    pub const fn completed_at(&self) -> UnixTime {
        self.receipt.body().completed_at()
    }
}

impl fmt::Debug for VerifiedReceipt {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("VerifiedReceipt")
            .field("completed_at", &self.completed_at())
            .field("completed_count", &self.receipt.body().completed_count())
            .finish_non_exhaustive()
    }
}

/// Verifies the receiver's delivery receipt on the sender (§7.7): every
/// binding against the session and `accept`, the totals against the
/// accepted selection, the completion time, and the signature.
///
/// `now` is the trusted wall-clock time. `completed_at` must be no earlier
/// than the session's establishment (less the 120-second skew allowance),
/// no later than the Accept's expiry, and no later than `now` plus 120
/// seconds.
///
/// # Errors
///
/// Any [`ReceiptError`] except [`ReceiptError::Role`],
/// [`ReceiptError::KeyStore`], and [`ReceiptError::Random`].
pub fn verify_receipt(
    record: &[u8],
    session: &SessionBinding,
    accept: &VerifiedAccept,
    now: UnixTime,
) -> Result<VerifiedReceipt, ReceiptError> {
    let receipt = DeliveryReceipt::decode(record).map_err(ReceiptError::Malformed)?;
    check(&receipt, Side::Sender, session, accept, now)
}

/// Issues the receiver's delivery receipt for `accept`, completed at
/// `completed_at`, and returns it verified (§7.7). Call only after every
/// selected file was verified, published, and made durable while consent
/// was valid; a storage error must never produce a receipt.
///
/// # Errors
///
/// [`ReceiptError::Role`] if `device_key` is not this session's local
/// device key; [`ReceiptError::Time`] if `completed_at` is outside the
/// permitted window; [`ReceiptError::KeyStore`]; [`ReceiptError::Random`].
pub fn sign_receipt<K: KeyStore>(
    keys: &K,
    device_key: &KeyId,
    session: &SessionBinding,
    accept: &VerifiedAccept,
    completed_at: UnixTime,
    now: UnixTime,
) -> Result<VerifiedReceipt, ReceiptError> {
    let public = keys
        .public_key(device_key)
        .map_err(ReceiptError::KeyStore)?;
    if public != *session.local_device() {
        return Err(ReceiptError::Role);
    }
    let receipt_id = random_id().map_err(|_| ReceiptError::Random)?;
    let body = ReceiptBody::new(
        *session.session_id(),
        *accept.transfer_id(),
        *accept.manifest_hash(),
        *accept.accept_hash(),
        *session.peer_device().as_bytes(),
        *public.as_bytes(),
        receipt_id,
        completed_at,
        accept.selected_count(),
        accept.selected_bytes(),
    )
    .map_err(ReceiptError::Malformed)?;
    check_body(&body, Side::Receiver, session, accept, now)?;
    let signature = keys
        .sign(device_key, SigningDomain::DeliveryReceipt, &body.encode())
        .map_err(ReceiptError::KeyStore)?;
    check(
        &DeliveryReceipt::new(body, signature.to_bytes()),
        Side::Receiver,
        session,
        accept,
        now,
    )
}

fn check_body(
    body: &ReceiptBody,
    side: Side,
    session: &SessionBinding,
    accept: &VerifiedAccept,
    now: UnixTime,
) -> Result<(), ReceiptError> {
    check_identity(body, side, session, accept)?;
    check_values(body, session, accept, now)
}

/// The session, transfer, manifest, Accept, and both parties.
fn check_identity(
    body: &ReceiptBody,
    side: Side,
    session: &SessionBinding,
    accept: &VerifiedAccept,
) -> Result<(), ReceiptError> {
    if body.session_id() != session.session_id()
        || body.session_id() != accept.session_id()
        || body.transfer_id() != accept.transfer_id()
        || body.manifest_hash() != accept.manifest_hash()
        || body.accept_hash() != accept.accept_hash()
    {
        return Err(ReceiptError::Binding);
    }
    let (sender, receiver) = side.keys(session);
    if body.sender_public() != sender.as_bytes() || body.receiver_public() != receiver.as_bytes() {
        return Err(ReceiptError::Parties);
    }
    Ok(())
}

/// The totals and the completion-time window. Checked only after the
/// signature, so a forged receipt is always reported as a forgery.
fn check_values(
    body: &ReceiptBody,
    session: &SessionBinding,
    accept: &VerifiedAccept,
    now: UnixTime,
) -> Result<(), ReceiptError> {
    if body.completed_count() != accept.selected_count()
        || body.total_plaintext_bytes() != accept.selected_bytes()
    {
        return Err(ReceiptError::Totals);
    }
    let completed = body.completed_at();
    if add_seconds(completed, CLOCK_SKEW_SECONDS) < session.established_at().seconds()
        || completed > accept.expires_at()
        || completed.seconds() > add_seconds(now, CLOCK_SKEW_SECONDS)
    {
        return Err(ReceiptError::Time);
    }
    Ok(())
}

fn check(
    receipt: &DeliveryReceipt,
    side: Side,
    session: &SessionBinding,
    accept: &VerifiedAccept,
    now: UnixTime,
) -> Result<VerifiedReceipt, ReceiptError> {
    // Identity, then signature, then values: a receipt that is not genuinely
    // from this session's receiver is always reported as a forgery, never as
    // a mere time or totals mismatch that would leave the session open.
    check_identity(receipt.body(), side, session, accept)?;
    let (_, receiver) = side.keys(session);
    receiver
        .verify(
            SigningDomain::DeliveryReceipt,
            &receipt.body().encode(),
            &Signature::from_bytes(*receipt.signature()),
        )
        .map_err(|_| ReceiptError::Signature)?;
    check_values(receipt.body(), session, accept, now)?;
    Ok(VerifiedReceipt { receipt: *receipt })
}
