//! Root-signed device revocations and the retained revocation set (PROTOCOL §2).

use core::fmt;
use core::num::NonZeroU64;
use std::collections::BTreeMap;

use todoke_proto::identity::{REVOKE_LEN, RevocationReason, Revoke, RevokeBody};
use todoke_proto::time::UnixTime;

use super::binding::{IssueError, PersonIdentity};
use super::codec::{LocalFormatError, Reader};
use super::ed25519::{Ed25519PublicKey, Signature, SigningDomain};
use super::keystore::{KeyId, KeyRole, KeyStore};
use crate::rng;

/// Local quota: retained records per root. Exceeding it disables the root
/// rather than silently dropping a revocation (§13: no hidden weakening).
pub const MAX_RECORDS_PER_ROOT: usize = 256;
/// Local quota: retained records across all roots. Same failure behavior.
pub const MAX_TOTAL_RECORDS: usize = 16_384;
/// Local quota: roots with retained state. Equal to the contact quota, so
/// every root a contact store trusts has a slot.
pub const MAX_ROOTS: usize = super::contacts::MAX_CONTACTS;

/// A `Revoke` record whose signature was verified against a trusted root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RevocationRecord {
    record: Revoke,
    root: Ed25519PublicKey,
}

impl RevocationRecord {
    /// Verifies `record` against `issuer`, which must be a root the caller
    /// already trusts (§2: "previously trusted root").
    ///
    /// # Errors
    ///
    /// [`RevocationError`] if the record names another root, contains an
    /// invalid device key, or its signature does not verify.
    pub fn verify(record: Revoke, issuer: &PersonIdentity) -> Result<Self, RevocationError> {
        let body = record.body();
        if body.person_root() != issuer.root().as_bytes() {
            return Err(RevocationError::UntrustedRoot);
        }
        Ed25519PublicKey::from_bytes(body.device_public())
            .map_err(|_| RevocationError::InvalidKey)?;
        issuer
            .root()
            .verify_input(
                &body.signing_input(),
                &Signature::from_bytes(*record.signature()),
            )
            .map_err(|_| RevocationError::InvalidSignature)?;
        Ok(Self {
            record,
            root: *issuer.root(),
        })
    }

    /// Wraps a record without verifying its signature, so quota tests can
    /// build thousands of records cheaply. Test builds only.
    #[cfg(test)]
    pub(crate) fn unverified_for_tests(record: Revoke, root: Ed25519PublicKey) -> Self {
        Self { record, root }
    }

    /// The verified wire record.
    #[must_use]
    pub fn record(&self) -> &Revoke {
        &self.record
    }

    /// The exact 172-byte encoding, for durable storage or forwarding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        self.record.encode()
    }
}

/// Fields of a new revocation.
#[derive(Clone, Copy, Debug)]
pub struct RevocationRequest {
    /// The full device key to revoke.
    pub device_public: Ed25519PublicKey,
    /// Monotonically issued sequence for this root. The caller must persist
    /// and never reuse it: reuse with different content disables the root at
    /// every peer that sees both records.
    pub sequence: NonZeroU64,
    /// Issue time.
    pub issued_at: UnixTime,
    /// Revoke bindings for the device with `serial <= through_serial`.
    pub through_serial: NonZeroU64,
    /// Reason; no free text.
    pub reason: RevocationReason,
}

/// Signs a revocation with a person root held in `store`. The record ID is
/// drawn from the OS CSPRNG.
///
/// # Errors
///
/// [`IssueError`] if the key is missing or not a person root, randomness is
/// unavailable, or signing fails.
pub fn issue_revocation<K: KeyStore>(
    store: &K,
    root: &KeyId,
    request: RevocationRequest,
) -> Result<RevocationRecord, IssueError> {
    if store.role(root)? != KeyRole::PersonRoot {
        return Err(IssueError::WrongRole);
    }
    let root_public = store.public_key(root)?;
    let record_id = rng::nonzero_id().map_err(|_| IssueError::Random)?;
    let body = RevokeBody::new(
        *root_public.as_bytes(),
        record_id,
        request.sequence,
        request.issued_at,
        *request.device_public.as_bytes(),
        request.through_serial,
        request.reason,
    )
    .map_err(|_| IssueError::SelfCheck)?;
    let signature = store
        .sign(root, SigningDomain::Revoke, &body.encode())?
        .to_bytes();
    RevocationRecord::verify(
        Revoke::from_parts(body, signature),
        &PersonIdentity::new(root_public),
    )
    .map_err(|_| IssueError::SelfCheck)
}

/// Result of [`RevocationSet::apply`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApplyOutcome {
    /// A new record was retained.
    Added,
    /// An identical record (same sequence and body) was already retained.
    Duplicate,
    /// A different record with the same sequence exists. The root is now
    /// disabled pending local resolution (§2). The new record is retained as
    /// evidence (see [`RevocationSet::conflicting_records_for`]) unless a
    /// quota is full.
    Conflict,
    /// A local quota was reached. The root is now disabled (fail closed).
    QuotaExceeded,
}

/// Orders conflict evidence by sequence, then by body encoding.
type ConflictKey = (NonZeroU64, Vec<u8>);

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct RootRevocations {
    /// The first record retained for each sequence.
    records: BTreeMap<NonZeroU64, Revoke>,
    /// Further root-signed records whose sequence matches a retained record
    /// but whose body differs: the evidence for local resolution (§2).
    conflicts: BTreeMap<ConflictKey, Revoke>,
    disabled: bool,
}

impl RootRevocations {
    fn len(&self) -> usize {
        self.records.len() + self.conflicts.len()
    }

    fn all(&self) -> impl Iterator<Item = &Revoke> {
        self.records.values().chain(self.conflicts.values())
    }
}

fn conflict_key(record: &Revoke) -> ConflictKey {
    (record.body().sequence(), record.body().encode())
}

/// Every revocation retained for trusted roots, plus disabled-root state.
///
/// Records are irrevocable: there is no API to remove one while its root is
/// trusted. Older records are applied even after newer ones, because a high
/// sequence does not prove earlier records were received (§2). Conflicting
/// records (same sequence, different body) are retained as well, count toward
/// the same quotas, and are honoured by [`Self::is_revoked`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RevocationSet {
    roots: BTreeMap<Ed25519PublicKey, RootRevocations>,
    total: usize,
}

impl RevocationSet {
    /// An empty set.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Retains a verified record.
    pub fn apply(&mut self, record: RevocationRecord) -> ApplyOutcome {
        let root = record.root;
        let new_root = !self.roots.contains_key(&root);
        if new_root && self.roots.len() >= MAX_ROOTS {
            // No slot even to record the disabled state, so the record is not
            // retained. The contact store trusts at most MAX_ROOTS roots, so
            // this only affects standalone use; such callers must stop
            // trusting the root.
            return ApplyOutcome::QuotaExceeded;
        }
        let total = self.total;
        let entry = self.roots.entry(root).or_default();
        let full = entry.len() >= MAX_RECORDS_PER_ROOT || total >= MAX_TOTAL_RECORDS;
        let sequence = record.record.body().sequence();
        match entry.records.get(&sequence) {
            Some(existing) if existing.body() == record.record.body() => ApplyOutcome::Duplicate,
            Some(_) => {
                let key = conflict_key(&record.record);
                if entry.conflicts.contains_key(&key) {
                    return ApplyOutcome::Duplicate;
                }
                entry.disabled = true;
                // Over quota the root is disabled all the same; only the extra
                // evidence is not kept.
                if !full {
                    entry.conflicts.insert(key, record.record);
                    self.total += 1;
                }
                ApplyOutcome::Conflict
            }
            None if full => {
                entry.disabled = true;
                ApplyOutcome::QuotaExceeded
            }
            None => {
                entry.records.insert(sequence, record.record);
                self.total += 1;
                ApplyOutcome::Added
            }
        }
    }

    /// Whether a retained record revokes `device`'s binding with `serial`
    /// under `root`.
    #[must_use]
    pub fn is_revoked(
        &self,
        root: &Ed25519PublicKey,
        device: &Ed25519PublicKey,
        serial: NonZeroU64,
    ) -> bool {
        self.roots.get(root).is_some_and(|entry| {
            entry.all().any(|record| {
                record.body().device_public() == device.as_bytes()
                    && record.body().through_serial() >= serial
            })
        })
    }

    /// Whether `root` is disabled pending local resolution.
    #[must_use]
    pub fn is_root_disabled(&self, root: &Ed25519PublicKey) -> bool {
        self.roots.get(root).is_some_and(|entry| entry.disabled)
    }

    /// Retained records for `root` in sequence order, for durable storage or
    /// forwarding (at most 64 per session, §13): the first record retained for
    /// each sequence. Conflicting records are in
    /// [`Self::conflicting_records_for`].
    pub fn records_for(&self, root: &Ed25519PublicKey) -> impl Iterator<Item = &Revoke> {
        self.roots
            .get(root)
            .into_iter()
            .flat_map(|entry| entry.records.values())
    }

    /// Retained root-signed records that conflict with a record in
    /// [`Self::records_for`] (same sequence, different body), ordered by
    /// sequence and then body encoding. They are the evidence for local
    /// resolution of a disabled root and may be forwarded like other records.
    pub fn conflicting_records_for(
        &self,
        root: &Ed25519PublicKey,
    ) -> impl Iterator<Item = &Revoke> {
        self.roots
            .get(root)
            .into_iter()
            .flat_map(|entry| entry.conflicts.values())
    }

    /// Total retained records.
    #[must_use]
    pub fn len(&self) -> usize {
        self.total
    }

    /// Whether no records or disabled roots are retained.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.roots.is_empty()
    }

    /// Drops state for roots that are no longer trusted. Only for callers that
    /// stop trusting a root entirely (§2 retention lasts while it is trusted).
    pub(crate) fn retain_roots(&mut self, mut trusted: impl FnMut(&Ed25519PublicKey) -> bool) {
        self.roots.retain(|root, _| trusted(root));
        self.total = self.roots.values().map(RootRevocations::len).sum();
    }

    pub(crate) fn roots(&self) -> impl Iterator<Item = &Ed25519PublicKey> {
        self.roots.keys()
    }

    /// Local format v2:
    /// `root_count:u32 || root_count × (root[32] || flags:u8 || count:u16 ||
    /// count × Revoke[172] || conflict_count:u16 || conflict_count × Revoke[172])`
    /// with strictly increasing roots and sequences; `flags` bit 0 is
    /// "disabled", other bits are zero; empty, enabled roots are omitted.
    /// Conflicts are strictly increasing by (sequence, body encoding); each
    /// matches the sequence of a record above with a different body, and any
    /// conflict requires the disabled flag.
    pub(crate) fn encode_into(&self, out: &mut Vec<u8>) {
        // Counts are bounded by MAX_ROOTS and MAX_RECORDS_PER_ROOT.
        let roots = u32::try_from(self.roots.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&roots.to_be_bytes());
        for (root, entry) in &self.roots {
            out.extend_from_slice(root.as_bytes());
            out.push(u8::from(entry.disabled));
            for records in [
                entry.records.values().collect::<Vec<_>>(),
                entry.conflicts.values().collect(),
            ] {
                let count = u16::try_from(records.len()).unwrap_or(u16::MAX);
                out.extend_from_slice(&count.to_be_bytes());
                for record in records {
                    out.extend_from_slice(&record.encode());
                }
            }
        }
    }

    pub(crate) fn decode(reader: &mut Reader<'_>) -> Result<Self, LocalFormatError> {
        let root_count = usize::try_from(reader.u32()?).map_err(|_| LocalFormatError::Malformed)?;
        if root_count > MAX_ROOTS {
            return Err(LocalFormatError::Malformed);
        }
        let mut set = Self::new();
        let mut previous_root: Option<Ed25519PublicKey> = None;
        for _ in 0..root_count {
            let root = Ed25519PublicKey::from_bytes(&reader.array()?)
                .map_err(|_| LocalFormatError::Malformed)?;
            if previous_root.is_some_and(|previous| previous >= root) {
                return Err(LocalFormatError::Malformed);
            }
            previous_root = Some(root);
            let disabled = match reader.u8()? {
                0 => false,
                1 => true,
                _ => return Err(LocalFormatError::Malformed),
            };
            let count = usize::from(reader.u16()?);
            let total = set
                .total
                .checked_add(count)
                .ok_or(LocalFormatError::Malformed)?;
            if count > MAX_RECORDS_PER_ROOT
                || total > MAX_TOTAL_RECORDS
                || (count == 0 && !disabled)
                || reader.remaining() < count * REVOKE_LEN
            {
                return Err(LocalFormatError::Malformed);
            }
            let mut entry = RootRevocations {
                records: BTreeMap::new(),
                conflicts: BTreeMap::new(),
                disabled,
            };
            let mut previous_sequence: Option<NonZeroU64> = None;
            for _ in 0..count {
                let record = Revoke::decode(reader.bytes(REVOKE_LEN)?)
                    .map_err(|_| LocalFormatError::Malformed)?;
                let sequence = record.body().sequence();
                if record.body().person_root() != root.as_bytes()
                    || previous_sequence.is_some_and(|previous| previous >= sequence)
                {
                    return Err(LocalFormatError::Malformed);
                }
                previous_sequence = Some(sequence);
                entry.records.insert(sequence, record);
            }
            let conflict_count = usize::from(reader.u16()?);
            let total = total
                .checked_add(conflict_count)
                .ok_or(LocalFormatError::Malformed)?;
            if count + conflict_count > MAX_RECORDS_PER_ROOT
                || total > MAX_TOTAL_RECORDS
                || (conflict_count > 0 && !disabled)
                || reader.remaining() < conflict_count * REVOKE_LEN
            {
                return Err(LocalFormatError::Malformed);
            }
            let mut previous_conflict: Option<ConflictKey> = None;
            for _ in 0..conflict_count {
                let record = Revoke::decode(reader.bytes(REVOKE_LEN)?)
                    .map_err(|_| LocalFormatError::Malformed)?;
                let key = conflict_key(&record);
                let conflicts_with_retained = entry
                    .records
                    .get(&key.0)
                    .is_some_and(|retained| retained.body() != record.body());
                if record.body().person_root() != root.as_bytes()
                    || !conflicts_with_retained
                    || previous_conflict
                        .as_ref()
                        .is_some_and(|previous| *previous >= key)
                {
                    return Err(LocalFormatError::Malformed);
                }
                previous_conflict = Some(key.clone());
                entry.conflicts.insert(key, record);
            }
            set.total = total;
            set.roots.insert(root, entry);
        }
        Ok(set)
    }
}

/// Why a revocation was rejected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum RevocationError {
    /// The record names a root that is not trusted.
    UntrustedRoot,
    /// The revoked device key is invalid.
    InvalidKey,
    /// The signature does not verify.
    InvalidSignature,
}

impl fmt::Display for RevocationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::UntrustedRoot => "revocation names an untrusted root",
            Self::InvalidKey => "revocation names an invalid device key",
            Self::InvalidSignature => "revocation signature is invalid",
        })
    }
}

impl std::error::Error for RevocationError {}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use proptest::prelude::*;

    use super::*;
    use crate::identity::test_support::{T0, nz, time};

    fn fail(error: impl fmt::Display) -> TestCaseError {
        TestCaseError::fail(error.to_string())
    }

    /// A valid Ed25519 public key from a fixed public seed.
    fn key(seed: u8) -> Result<Ed25519PublicKey, TestCaseError> {
        let public = ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes();
        Ed25519PublicKey::from_bytes(&public).map_err(fail)
    }

    /// The varying fields of a record body; equal specs give equal bodies.
    #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
    struct Spec {
        sequence: u64,
        device: u8,
        through: u64,
    }

    /// An unsigned record for `root` (the state machine is about retention,
    /// not signatures, which are covered elsewhere).
    fn record(root: &Ed25519PublicKey, spec: Spec) -> Result<Revoke, TestCaseError> {
        let mut record_id = [0x7e; 16];
        record_id[0] = spec.device;
        record_id[1..9].copy_from_slice(&spec.through.to_be_bytes());
        let body = RevokeBody::new(
            *root.as_bytes(),
            record_id,
            nz(spec.sequence).map_err(fail)?,
            time(T0).map_err(fail)?,
            *key(100 + spec.device)?.as_bytes(),
            nz(spec.through).map_err(fail)?,
            RevocationReason::Lost,
        )
        .map_err(fail)?;
        Ok(Revoke::from_parts(body, [0; 64]))
    }

    #[derive(Clone, Copy, Debug)]
    enum SetOp {
        Apply {
            root: usize,
            spec: Spec,
        },
        /// Keep the roots whose bit is set.
        Retain(u8),
        RoundTrip,
    }

    fn arb_set_op() -> impl Strategy<Value = SetOp> {
        prop_oneof![
            8 => (0..3usize, 1..5u64, 0..2u8, 1..5u64).prop_map(
                |(root, sequence, device, through)| SetOp::Apply {
                    root,
                    spec: Spec { sequence, device, through },
                }
            ),
            1 => (0..8u8).prop_map(SetOp::Retain),
            1 => Just(SetOp::RoundTrip),
        ]
    }

    #[derive(Debug, Default)]
    struct ModelRoot {
        records: BTreeMap<u64, Spec>,
        conflicts: BTreeSet<Spec>,
        disabled: bool,
    }

    impl ModelRoot {
        fn apply(&mut self, spec: Spec) -> ApplyOutcome {
            match self.records.get(&spec.sequence) {
                Some(existing) if *existing == spec => ApplyOutcome::Duplicate,
                Some(_) if self.conflicts.contains(&spec) => ApplyOutcome::Duplicate,
                Some(_) => {
                    self.disabled = true;
                    self.conflicts.insert(spec);
                    ApplyOutcome::Conflict
                }
                None => {
                    self.records.insert(spec.sequence, spec);
                    ApplyOutcome::Added
                }
            }
        }

        fn all(&self) -> impl Iterator<Item = &Spec> {
            self.records.values().chain(&self.conflicts)
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(64))]

        /// Model-based state-machine test of `RevocationSet` below its quotas:
        /// apply outcomes, retention of first records and conflict evidence,
        /// disabling, revocation decisions, dropping untrusted roots, and the
        /// local-format round trip.
        #[test]
        fn revocation_set_state_machine(ops in proptest::collection::vec(arb_set_op(), 1..40)) {
            let roots = [key(1)?, key(2)?, key(3)?];
            let mut set = RevocationSet::new();
            let mut model: BTreeMap<usize, ModelRoot> = BTreeMap::new();
            for op in ops {
                match op {
                    SetOp::Apply { root, spec } => {
                        let expected = model.entry(root).or_default().apply(spec);
                        let verified = RevocationRecord::unverified_for_tests(
                            record(&roots[root], spec)?,
                            roots[root],
                        );
                        prop_assert_eq!(set.apply(verified), expected);
                    }
                    SetOp::Retain(mask) => {
                        let keep = |index: usize| mask & (1 << index) != 0;
                        set.retain_roots(|root| {
                            roots.iter().position(|candidate| candidate == root).is_some_and(keep)
                        });
                        model.retain(|index, _| keep(*index));
                    }
                    SetOp::RoundTrip => {
                        let mut bytes = Vec::new();
                        set.encode_into(&mut bytes);
                        let mut reader = Reader::new(&bytes);
                        let decoded = RevocationSet::decode(&mut reader)
                            .map_err(|error| fail(format!("{error:?}")))?;
                        prop_assert_eq!(reader.remaining(), 0);
                        prop_assert_eq!(&decoded, &set);
                    }
                }

                let total: usize = model.values().map(|entry| entry.all().count()).sum();
                prop_assert_eq!(set.len(), total);
                prop_assert_eq!(set.is_empty(), model.is_empty());
                for (index, root) in roots.iter().enumerate() {
                    let entry = model.get(&index);
                    prop_assert_eq!(set.is_root_disabled(root), entry.is_some_and(|entry| entry.disabled));
                    let mut records = Vec::new();
                    let mut conflicts = Vec::new();
                    if let Some(entry) = entry {
                        for spec in entry.records.values() {
                            records.push(record(root, *spec)?);
                        }
                        for spec in &entry.conflicts {
                            conflicts.push(record(root, *spec)?);
                        }
                    }
                    conflicts.sort_by_key(|record| (record.body().sequence(), record.body().encode()));
                    prop_assert!(set.records_for(root).eq(records.iter()));
                    prop_assert!(set.conflicting_records_for(root).eq(conflicts.iter()));
                    for device in 0..2u8 {
                        let device_key = key(100 + device)?;
                        for serial in 1..6u64 {
                            let expected = entry.is_some_and(|entry| {
                                entry.all().any(|spec| spec.device == device && spec.through >= serial)
                            });
                            prop_assert_eq!(
                                set.is_revoked(root, &device_key, nz(serial).map_err(fail)?),
                                expected
                            );
                        }
                    }
                }
            }
        }
    }
}
