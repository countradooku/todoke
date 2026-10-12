use std::collections::BTreeSet;

use proptest::prelude::*;

use super::*;
use crate::identity::contacts::{Contact, HistoryKind, Unavailable};
use crate::identity::storage::MemoryStorage;
use crate::identity::test_support::{
    Enrolled, SwitchableStorage, T0, TestResult, nz, sealer, time,
};
use crate::identity::{BindingError, RevocationRequest, SoftwareSealer, issue_revocation};
use todoke_proto::identity::RevocationReason;

type Store = ContactStore<SoftwareSealer, MemoryStorage>;
type AnyResult<T> = Result<T, Box<dyn std::error::Error>>;

const HASH: [u8; 32] = [0x4a; 32];
const PSK_NEXT: [u8; 32] = [0x6b; 32];
const ID: [u8; 16] = [0xa1; 16];
const EXPIRES: u64 = T0 + 300;

fn empty() -> AnyResult<Store> {
    Ok(ContactStore::open(sealer(9), MemoryStorage::new())?)
}

fn reopen(store: &Store) -> AnyResult<Store> {
    let mut storage = MemoryStorage::new();
    storage.set_blob(store.storage().blob().map(<[u8]>::to_vec));
    Ok(ContactStore::open(sealer(9), storage)?)
}

fn journal(peer: &VerifiedDeviceBinding, pairing_id: [u8; 16]) -> AnyResult<PairingJournal<'_>> {
    Ok(PairingJournal {
        pairing_id,
        expires_at: time(EXPIRES)?,
        origin: TrustOrigin::QrPairing,
        peer,
        handshake_hash: &HASH,
        psk_next: &PSK_NEXT,
    })
}

fn usable<S: Sealer, B: BlobStorage>(
    store: &ContactStore<S, B>,
    device: &Ed25519PublicKey,
) -> bool {
    store
        .availability(device)
        .is_ok_and(|availability| availability.is_ok())
}

#[test]
fn journal_commit_clear_creates_a_contact_at_generation_one() -> TestResult {
    let peer = Enrolled::new()?.bind(1)?;
    let device = *peer.device_public();
    let mut store = empty()?;
    store.journal_pairing(&journal(&peer, ID)?, time(T0)?)?;
    assert!(store.pairing_burned(&ID));
    assert!(store.pairing_pending());
    assert!(store.contact(&device).is_none());
    // The burn and the journal are durable together.
    let durable = reopen(&store)?;
    assert!(durable.pairing_burned(&ID));

    let outcome = store.commit_pairing(&peer, &HASH, time(T0 + 1)?)?;
    assert_eq!(outcome, PairOutcome::New);
    assert!(!store.pairing_pending());
    let contact = store.contact(&device).ok_or("contact")?;
    assert_eq!(contact.generation(), 1);
    assert_eq!(contact.psk().expose(), &PSK_NEXT);
    assert_eq!(contact.origin(), TrustOrigin::QrPairing);
    assert!(contact.ratchet_pending());
    assert!(!usable(&store, &device));
    assert_eq!(
        contact
            .history()
            .map(|event| event.kind)
            .collect::<Vec<_>>(),
        [HistoryKind::Paired]
    );

    store.clear_ratchet(&device, &HASH)?;
    assert!(usable(&store, &device));
    let reopened = reopen(&store)?;
    assert!(usable(&reopened, &device));
    assert!(reopened.pairing_burned(&ID));
    assert_eq!(reopened.contact(&device).map(Contact::generation), Some(1));
    Ok(())
}

#[test]
fn crash_after_journal_creates_nothing_and_keeps_the_burn() -> TestResult {
    let peer = Enrolled::new()?.bind(1)?;
    let mut store = empty()?;
    store.journal_pairing(&journal(&peer, ID)?, time(T0)?)?;
    let reopened = reopen(&store)?;
    assert!(reopened.contact(peer.device_public()).is_none());
    assert!(!reopened.pairing_pending());
    assert!(reopened.pairing_burned(&ID));
    Ok(())
}

#[test]
fn crash_after_commit_blocks_the_new_contact() -> TestResult {
    let peer = Enrolled::new()?.bind(1)?;
    let device = *peer.device_public();
    let mut store = empty()?;
    store.journal_pairing(&journal(&peer, ID)?, time(T0)?)?;
    store.commit_pairing(&peer, &HASH, time(T0)?)?;
    let reopened = reopen(&store)?;
    let contact = reopened.contact(&device).ok_or("contact")?;
    assert_eq!(contact.state(), VerificationState::RatchetUncertain);
    assert_eq!(
        reopened.availability(&device)?.err(),
        Some(Unavailable::RatchetUncertain)
    );
    Ok(())
}

#[test]
fn re_pairing_blocks_the_old_contact_while_journaled_and_after_a_crash() -> TestResult {
    let enrolled = Enrolled::new()?;
    let old = enrolled.bind(1)?;
    let new = enrolled.bind(2)?;
    let device = *old.device_public();
    let mut store = empty()?;
    store.pair(
        &old,
        TrustOrigin::QrPairing,
        PairPsk::new([0x77; 32]),
        9,
        time(T0)?,
    )?;
    assert!(usable(&store, &device));
    store.journal_pairing(&journal(&new, ID)?, time(T0)?)?;
    assert_eq!(
        store.availability(&device)?.err(),
        Some(Unavailable::RatchetUncertain)
    );
    // A crash now never restores the old pairing (§4.4).
    let crashed = reopen(&store)?;
    assert_eq!(
        crashed.contact(&device).map(Contact::state),
        Some(VerificationState::RatchetUncertain)
    );
    // Completing instead replaces it at generation 1.
    assert_eq!(
        store.commit_pairing(&new, &HASH, time(T0)?)?,
        PairOutcome::RePaired
    );
    store.clear_ratchet(&device, &HASH)?;
    let contact = store.contact(&device).ok_or("contact")?;
    assert_eq!(contact.generation(), 1);
    assert_eq!(contact.binding_serial().get(), 2);
    assert!(matches!(
        contact.history().last().map(|event| event.kind),
        Some(HistoryKind::RePaired { .. })
    ));
    Ok(())
}

#[test]
fn abandon_before_and_after_commit() -> TestResult {
    let peer = Enrolled::new()?.bind(1)?;
    let device = *peer.device_public();
    let mut store = empty()?;
    store.journal_pairing(&journal(&peer, ID)?, time(T0)?)?;
    store.abandon_pairing(&ID, &device)?;
    assert!(!store.pairing_pending());
    assert!(store.contact(&device).is_none());
    assert!(store.pairing_burned(&ID));
    assert!(reopen(&store)?.pairing_burned(&ID));

    let other = [0xa2; 16];
    store.journal_pairing(&journal(&peer, other)?, time(T0)?)?;
    store.commit_pairing(&peer, &HASH, time(T0)?)?;
    store.abandon_pairing(&other, &device)?;
    let contact = store.contact(&device).ok_or("contact")?;
    assert_eq!(contact.state(), VerificationState::RatchetUncertain);
    assert!(!contact.ratchet_pending());
    assert_eq!(
        reopen(&store)?.contact(&device).map(Contact::state),
        Some(VerificationState::RatchetUncertain)
    );
    Ok(())
}

#[test]
fn journal_refuses_conflicts() -> TestResult {
    let peer = Enrolled::new()?.bind(1)?;
    let other_peer = Enrolled::new()?.bind(1)?;
    let mut store = empty()?;
    assert_eq!(
        store.journal_pairing(&journal(&peer, [0; 16])?, time(T0)?),
        Err(ContactError::RatchetMismatch)
    );
    store.journal_pairing(&journal(&peer, ID)?, time(T0)?)?;
    // One pending pairing at a time.
    assert_eq!(
        store.journal_pairing(&journal(&other_peer, [0xa2; 16])?, time(T0)?),
        Err(ContactError::RatchetMismatch)
    );
    store.abandon_pairing(&ID, peer.device_public())?;
    // A burned pairing ID never journals again.
    assert_eq!(
        store.journal_pairing(&journal(&other_peer, ID)?, time(T0)?),
        Err(ContactError::RatchetMismatch)
    );
    // Nor does a device whose contact is mid-ratchet.
    store.pair(
        &other_peer,
        TrustOrigin::QrPairing,
        PairPsk::new([0x77; 32]),
        3,
        time(T0)?,
    )?;
    store.journal_ratchet(other_peer.device_public(), 4, &[1; 32], &[2; 32])?;
    assert_eq!(
        store.journal_pairing(&journal(&other_peer, [0xa3; 16])?, time(T0)?),
        Err(ContactError::RatchetMismatch)
    );
    Ok(())
}

#[test]
fn commit_requires_the_journaled_transaction() -> TestResult {
    let peer = Enrolled::new()?.bind(1)?;
    let renewed = peer.clone();
    let stranger = Enrolled::new()?.bind(1)?;
    let mut store = empty()?;
    assert_eq!(
        store.commit_pairing(&peer, &HASH, time(T0)?),
        Err(ContactError::RatchetMismatch)
    );
    store.journal_pairing(&journal(&peer, ID)?, time(T0)?)?;
    assert_eq!(
        store.commit_pairing(&peer, &[0x4b; 32], time(T0)?),
        Err(ContactError::RatchetMismatch)
    );
    assert_eq!(
        store.commit_pairing(&stranger, &HASH, time(T0)?),
        Err(ContactError::RatchetMismatch)
    );
    assert!(store.pairing_pending());
    assert_eq!(
        store.commit_pairing(&renewed, &HASH, time(T0)?),
        Ok(PairOutcome::New)
    );
    Ok(())
}

#[test]
fn ledger_expires_entries_and_has_a_quota() -> TestResult {
    let peer = Enrolled::new()?.bind(1)?;
    let mut store = empty()?;
    for index in 0..MAX_BURNED_PAIRINGS {
        let mut id = [0xb0; 16];
        id[15] = u8::try_from(index)?;
        store.journal_pairing(&journal(&peer, id)?, time(T0)?)?;
        store.abandon_pairing(&id, peer.device_public())?;
    }
    assert_eq!(
        store.journal_pairing(&journal(&peer, ID)?, time(T0)?),
        Err(ContactError::Capacity)
    );
    // Entries stay until expiry plus twice the skew.
    let last_kept = EXPIRES + 2 * CLOCK_SKEW_SECONDS - 1;
    assert_eq!(
        store.journal_pairing(&journal(&peer, ID)?, time(last_kept)?),
        Err(ContactError::Capacity)
    );
    store.journal_pairing(&journal(&peer, ID)?, time(last_kept + 1)?)?;
    assert!(store.pairing_burned(&ID));
    assert!(!store.pairing_burned(&[0xb0; 16]));
    assert_eq!(reopen(&store)?.pairing.burned.len(), 1);
    Ok(())
}

#[test]
fn write_failures_fail_closed() -> TestResult {
    let peer = Enrolled::new()?.bind(1)?;
    let device = *peer.device_public();
    let (storage, failing) = SwitchableStorage::new();
    let mut store = ContactStore::open(sealer(9), storage)?;
    failing.set(true);
    assert!(matches!(
        store.journal_pairing(&journal(&peer, ID)?, time(T0)?),
        Err(ContactError::Storage(_))
    ));
    // In memory the offer stays burned and the pairing pending.
    assert!(store.pairing_burned(&ID));
    assert!(store.pairing_pending());
    // Abandoning drops it in memory even though the write fails again.
    assert!(store.abandon_pairing(&ID, &device).is_err());
    assert!(!store.pairing_pending());
    assert!(store.storage().blob().is_none());

    failing.set(false);
    let other = [0xa2; 16];
    store.journal_pairing(&journal(&peer, other)?, time(T0)?)?;
    failing.set(true);
    assert!(store.commit_pairing(&peer, &HASH, time(T0)?).is_err());
    // The new contact exists in memory only with its marker: unusable.
    assert!(!usable(&store, &device));
    // What is durable is the journal, which a restart discards.
    let mut storage = MemoryStorage::new();
    storage.set_blob(store.storage().blob().map(<[u8]>::to_vec));
    let reopened = ContactStore::open(sealer(9), storage)?;
    assert!(reopened.contact(&device).is_none());
    assert!(reopened.pairing_burned(&other));
    Ok(())
}

#[test]
fn commit_applies_the_pair_checks() -> TestResult {
    let enrolled = Enrolled::new()?;
    let peer = enrolled.bind(1)?;
    let device = *peer.device_public();
    let mut store = empty()?;
    store.pair(
        &peer,
        TrustOrigin::QrPairing,
        PairPsk::new([0x77; 32]),
        5,
        time(T0)?,
    )?;
    let revocation = issue_revocation(
        &enrolled.store,
        &enrolled.root,
        RevocationRequest {
            device_public: device,
            sequence: nz(1)?,
            issued_at: time(T0)?,
            through_serial: nz(1)?,
            reason: RevocationReason::Lost,
        },
    )?;
    store.apply_revocation(revocation.record().clone())?;
    // Re-pairing with the revoked serial journals (the peer was
    // authenticated) but cannot commit (§2).
    store.journal_pairing(&journal(&peer, ID)?, time(T0)?)?;
    assert_eq!(
        store.commit_pairing(&peer, &HASH, time(T0)?),
        Err(ContactError::Binding(BindingError::Revoked))
    );
    assert!(!store.pairing_pending());
    store.abandon_pairing(&ID, &device)?;
    assert_eq!(
        store.contact(&device).map(Contact::state),
        Some(VerificationState::RatchetUncertain)
    );
    Ok(())
}

#[test]
fn pairing_section_layout_round_trips() -> TestResult {
    let peer = Enrolled::new()?.bind(1)?;
    let mut store = empty()?;
    store.journal_pairing(&journal(&peer, ID)?, time(T0)?)?;
    let encoded = super::super::encode_all(&store.contacts, &store.revocations, &store.pairing);
    let decoded = super::super::decode(&encoded).map_err(|_| "decode")?;
    let reencoded = super::super::encode_all(&decoded.0, &decoded.1, &decoded.2);
    assert_eq!(encoded.as_slice(), reencoded.as_slice());
    // count:u32 = 0, empty revocation set, then the pairing section.
    let section = encoded
        .len()
        .checked_sub(PENDING_PAIRING_LEN + 1 + BURNED_LEN)
        .ok_or("short")?;
    let block = &encoded[section..];
    assert_eq!(block[0], 1);
    assert_eq!(&block[1..17], &ID);
    assert_eq!(&block[17..25], &EXPIRES.to_be_bytes());
    assert_eq!(block[25], TrustOrigin::QrPairing.to_u8());
    assert_eq!(&block[26..58], peer.device_public().as_bytes());
    assert_eq!(&block[90..122], &HASH);
    assert_eq!(&block[122..154], &PSK_NEXT);
    assert_eq!(block[154], 1);
    assert_eq!(&block[155..171], &ID);
    assert_eq!(&block[171..179], &EXPIRES.to_be_bytes());
    Ok(())
}

fn section_offset(encoded: &[u8], burned: usize) -> Result<usize, &'static str> {
    encoded
        .len()
        .checked_sub(PENDING_PAIRING_LEN + 1 + burned * BURNED_LEN)
        .ok_or("short")
}

#[test]
fn decode_rejects_malformed_pairing_sections() -> TestResult {
    let peer = Enrolled::new()?.bind(1)?;
    let mut store = empty()?;
    store.journal_pairing(&journal(&peer, ID)?, time(T0)?)?;
    store.abandon_pairing(&ID, peer.device_public())?;
    store.journal_pairing(&journal(&peer, [0xa2; 16])?, time(T0)?)?;
    let valid = super::super::encode_all(&store.contacts, &store.revocations, &store.pairing);
    assert!(super::super::decode(&valid).is_ok());
    let base = section_offset(&valid, 2)?;
    let ledger = base + PENDING_PAIRING_LEN + 1;
    let mutations: Vec<(&str, usize, Vec<u8>)> = vec![
        ("state 2", base, vec![2]),
        ("zero pending ID", base + 1, vec![0; 16]),
        ("pending ID not in ledger", base + 1, vec![0xa3; 16]),
        ("expiry differs from ledger", base + 24, vec![0x01]),
        ("bad origin", base + 25, vec![9]),
        ("bad device key", base + 26, vec![0xff; 32]),
        ("count over quota", ledger - 1, vec![65]),
        ("count too large for input", ledger - 1, vec![3]),
        ("unsorted ledger", ledger, vec![0xa3; 16]),
        ("zero ledger ID", ledger + BURNED_LEN, vec![0; 16]),
        ("time beyond range", ledger + 16, vec![0xff; 8]),
    ];
    for (label, offset, bytes) in mutations {
        let mut changed = valid.to_vec();
        changed[offset..offset + bytes.len()].copy_from_slice(&bytes);
        assert!(super::super::decode(&changed).is_err(), "{label}");
    }
    // Duplicate ledger entries.
    let mut duplicate = valid.to_vec();
    let (first, second) = (ledger, ledger + BURNED_LEN);
    let entry = duplicate[first..first + BURNED_LEN].to_vec();
    duplicate[second..second + BURNED_LEN].copy_from_slice(&entry);
    assert!(super::super::decode(&duplicate).is_err());
    // An empty pending block must be all zero.
    let empty_store = empty()?;
    let none = super::super::encode_all(
        &empty_store.contacts,
        &empty_store.revocations,
        &empty_store.pairing,
    );
    let offset = section_offset(&none, 0)?;
    for position in 1..PENDING_PAIRING_LEN {
        let mut changed = none.to_vec();
        changed[offset + position] = 1;
        assert!(super::super::decode(&changed).is_err(), "{position}");
    }
    // Truncation and trailing bytes.
    assert!(super::super::decode(&valid[..valid.len() - 1]).is_err());
    let mut trailing = valid.to_vec();
    trailing.push(0);
    assert!(super::super::decode(&trailing).is_err());
    Ok(())
}

#[test]
fn debug_shows_counts_only() -> TestResult {
    let peer = Enrolled::new()?.bind(1)?;
    let mut store = empty()?;
    store.journal_pairing(&journal(&peer, ID)?, time(T0)?)?;
    let debug = format!("{store:?}");
    assert!(debug.contains("pairing_pending: true, burned_pairings: 1"));
    let pending = format!("{:?}", store.pairing.pending.as_ref().ok_or("pending")?);
    assert!(pending.starts_with("PendingPairing { origin: QrPairing, device: "));
    assert!(!pending.contains("6b6b") && !pending.contains("a1a1"));
    Ok(())
}

/// Operations of the pairing journal state machine, including crashes.
#[derive(Clone, Debug)]
enum Op {
    /// Journal a new pairing of peer `0..3` with pairing ID `0..4`.
    Journal(usize, u8),
    /// Commit the pending pairing, with the right or a wrong handshake hash.
    Commit(bool),
    /// Clear the committed marker of peer `0..3`.
    Clear(usize),
    /// Abandon the transaction of peer `0..3`.
    Abandon(usize),
    /// The process dies; the store is reopened from its durable blob.
    Crash,
    /// Writes start or stop failing.
    Writes(bool),
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => (0..3_usize, 0..4_u8).prop_map(|(peer, id)| Op::Journal(peer, id)),
        3 => any::<bool>().prop_map(Op::Commit),
        2 => (0..3_usize).prop_map(Op::Clear),
        1 => (0..3_usize).prop_map(Op::Abandon),
        2 => Just(Op::Crash),
        1 => any::<bool>().prop_map(Op::Writes),
    ]
}

fn id(index: u8) -> [u8; 16] {
    [index + 1; 16]
}

fn fail(error: &dyn core::fmt::Display) -> TestCaseError {
    TestCaseError::fail(error.to_string())
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(64))]

    /// Invariants under any sequence of journal, commit, clear, abandon,
    /// crash, and write failures:
    /// - the device of an unfinished transaction is never usable;
    /// - an ID once journaled stays burned in memory, and an ID burned by a
    ///   successful write stays burned across crashes; a burned ID never
    ///   journals again;
    /// - after a crash nothing is pending, and every usable contact was
    ///   created by a cleared pairing: generation 1 and the journaled PSK.
    #[test]
    fn journal_state_machine(ops in proptest::collection::vec(op(), 1..40)) {
        let peers: Vec<VerifiedDeviceBinding> = (0..3)
            .map(|_| -> AnyResult<VerifiedDeviceBinding> { Enrolled::new()?.bind(1) })
            .collect::<Result<_, _>>()
            .map_err(|e| fail(&e))?;
        let now = time(T0).map_err(|e| fail(&e))?;
        let (storage, failing) = SwitchableStorage::new();
        let mut store = ContactStore::open(sealer(9), storage).map_err(|e| fail(&e))?;
        // Journaled, not committed: (peer, id).
        let mut pending: Option<(usize, u8)> = None;
        // Committed in memory, not cleared: peer -> id.
        let mut committed = std::collections::BTreeMap::new();
        let mut burned_memory = BTreeSet::new();
        let mut burned_durable = BTreeSet::new();
        let mut cleared_ever = BTreeSet::new();
        for op in ops {
            let blob_before = store.storage().blob().map(<[u8]>::to_vec);
            match op {
                Op::Journal(peer, index) => {
                    let entry = journal(&peers[peer], id(index)).map_err(|e| fail(&e))?;
                    let result = store.journal_pairing(&entry, now);
                    if pending.is_some() || burned_memory.contains(&index) || committed.contains_key(&peer) {
                        prop_assert!(result.is_err());
                    } else {
                        prop_assert_eq!(result.is_ok(), !failing.get());
                        burned_memory.insert(index);
                        pending = Some((peer, index));
                    }
                }
                Op::Commit(right) => {
                    let hash = if right { HASH } else { [0x4b; 32] };
                    let target = pending.map_or(0, |(peer, _)| peer);
                    let result = store.commit_pairing(&peers[target], &hash, now);
                    match pending {
                        Some((peer, index)) if right => {
                            prop_assert_eq!(result.is_ok(), !failing.get());
                            committed.insert(peer, index);
                            pending = None;
                        }
                        _ => prop_assert!(result.is_err()),
                    }
                }
                Op::Clear(peer) => {
                    let result = store.clear_ratchet(peers[peer].device_public(), &HASH);
                    if committed.contains_key(&peer) {
                        prop_assert_eq!(result.is_ok(), !failing.get());
                        if result.is_ok() {
                            committed.remove(&peer);
                            cleared_ever.insert(peer);
                        }
                    } else {
                        prop_assert!(result.is_err());
                    }
                }
                Op::Abandon(peer) => {
                    let index = match pending {
                        Some((p, index)) if p == peer => {
                            pending = None;
                            Some(index)
                        }
                        _ => committed.remove(&peer),
                    };
                    if let Some(index) = index {
                        let result = store.abandon_pairing(&id(index), peers[peer].device_public());
                        prop_assert_eq!(result.is_ok(), !failing.get());
                        prop_assert!(!usable(&store, peers[peer].device_public()));
                    }
                }
                Op::Crash => {
                    let blob = store.storage().blob().map(<[u8]>::to_vec);
                    let storage = SwitchableStorage::restarted(blob, failing.clone());
                    store = ContactStore::open(sealer(9), storage).map_err(|e| fail(&e))?;
                    prop_assert!(!store.pairing_pending());
                    for index in &burned_durable {
                        prop_assert!(store.pairing_burned(&id(*index)));
                    }
                    burned_memory = (0..4).filter(|index| store.pairing_burned(&id(*index))).collect();
                    burned_durable.clone_from(&burned_memory);
                    pending = None;
                    for peer in committed.keys() {
                        prop_assert!(!usable(&store, peers[*peer].device_public()));
                    }
                    committed.clear();
                    for (position, peer) in peers.iter().enumerate() {
                        if usable(&store, peer.device_public()) {
                            prop_assert!(cleared_ever.contains(&position));
                        }
                    }
                }
                Op::Writes(on) => failing.set(on),
            }
            // Any successful write makes the whole in-memory state durable.
            if store.storage().blob().map(<[u8]>::to_vec) != blob_before {
                burned_durable.clone_from(&burned_memory);
            }
            for peer in pending.iter().map(|(peer, _)| peer).chain(committed.keys()) {
                prop_assert!(!usable(&store, peers[*peer].device_public()));
            }
            for index in &burned_memory {
                prop_assert!(store.pairing_burned(&id(*index)));
            }
            for peer in &peers {
                if usable(&store, peer.device_public()) {
                    let contact = store.contact(peer.device_public());
                    prop_assert_eq!(contact.map(Contact::generation), Some(1));
                    prop_assert_eq!(contact.map(|c| *c.psk().expose()), Some(PSK_NEXT));
                }
            }
        }
    }
}

/// The committed fuzz seeds follow the current local format: the valid
/// ones decode and re-encode exactly, the malformed ones are rejected.
#[test]
fn committed_fuzz_seeds_decode_as_expected() -> TestResult {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../fuzz/seeds/crypto_contact_store_plaintext");
    for (name, valid) in [
        ("empty", true),
        ("one-contact", true),
        ("one-contact-conflict", true),
        ("root-without-contact", false),
        ("one-contact-pending-pairing", true),
        ("pending-pairing-not-in-ledger", false),
    ] {
        let bytes = std::fs::read(dir.join(name))?;
        let decoded = super::super::decode(&bytes);
        assert_eq!(decoded.is_ok(), valid, "{name}");
        if let Ok(decoded) = decoded {
            assert_eq!(
                super::super::encode_all(&decoded.0, &decoded.1, &decoded.2).as_slice(),
                bytes.as_slice(),
                "{name}"
            );
        }
    }
    Ok(())
}
