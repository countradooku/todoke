use proptest::prelude::*;

use super::manifest::{MAX_DEPTH, MAX_PATH_LEN, validate_mime, validate_name};
use super::*;
use crate::time::UnixTime;

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn fixture(name: &str) -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/test-vectors")
        .join(name);
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

fn hex_field(
    value: &serde_json::Value,
    pointer: &str,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let text = value
        .pointer(pointer)
        .and_then(serde_json::Value::as_str)
        .ok_or("missing fixture field")?;
    Ok(hex::decode(text)?)
}

fn u64_field(value: &serde_json::Value, pointer: &str) -> Result<u64, Box<dyn std::error::Error>> {
    Ok(value
        .pointer(pointer)
        .and_then(serde_json::Value::as_u64)
        .ok_or("missing fixture field")?)
}

fn time(seconds: u64) -> Result<UnixTime, &'static str> {
    UnixTime::new(seconds).ok_or("time")
}

const T0: u64 = 1_760_000_000;

fn header() -> Result<ManifestHeader, &'static str> {
    Ok(ManifestHeader {
        transfer_id: [0xa3; 16],
        sender_public: [0xd0; 32],
        recipient_public: [0xa0; 32],
        created_at: time(T0)?,
        expires_at: time(T0 + 300)?,
    })
}

fn file(id: u32, parent: u32, name: &str, size: u64) -> ManifestEntry {
    ManifestEntry::file(
        id,
        parent,
        name.to_owned(),
        "application/octet-stream".to_owned(),
        size,
        [0x11; 32],
        2,
    )
}

fn dir(id: u32, parent: u32, name: &str) -> ManifestEntry {
    ManifestEntry::directory(id, parent, name.to_owned())
}

fn build(entries: Vec<ManifestEntry>) -> Result<Manifest, ManifestError> {
    Manifest::new(
        header().map_err(|_| ManifestError::Time)?,
        entries,
        &ManifestLimits::SPEC,
    )
}

/// The committed manifest fixture decodes, its fields match, and it
/// re-encodes to the same bytes and hash (§7.1).
#[test]
fn manifest_fixture_decodes_and_reencodes() -> TestResult {
    let vector = fixture("manifest-hash.json")?;
    let canonical = hex_field(&vector, "/canonical_hex")?;
    assert_eq!(
        u64::try_from(canonical.len())?,
        u64_field(&vector, "/canonical_length")?
    );
    let manifest = Manifest::decode(&canonical, &ManifestLimits::SPEC)?;
    let header = manifest.header();
    assert_eq!(
        header.transfer_id.as_slice(),
        hex_field(&vector, "/transfer_id_hex")?
    );
    assert_eq!(
        header.sender_public.as_slice(),
        hex_field(&vector, "/sender_ed25519_public_key_hex")?
    );
    assert_eq!(
        header.recipient_public.as_slice(),
        hex_field(&vector, "/recipient_ed25519_public_key_hex")?
    );
    assert_eq!(
        header.created_at.seconds(),
        u64_field(&vector, "/created_at")?
    );
    assert_eq!(
        header.expires_at.seconds(),
        u64_field(&vector, "/expires_at")?
    );
    let entry = manifest.entry(1).ok_or("entry")?;
    assert_eq!(entry.name(), "hello.txt");
    assert_eq!(entry.mime(), "text/plain");
    assert_eq!(entry.size(), u64_field(&vector, "/entries/0/size")?);
    assert_eq!(
        entry.root().as_slice(),
        hex_field(&vector, "/entries/0/plaintext_blake3_root_hex")?
    );
    assert_eq!(
        u64::from(entry.content_suite()),
        u64_field(&vector, "/entries/0/content_suite")?
    );
    assert_eq!(manifest.file_count(), 1);
    assert_eq!(manifest.total_file_bytes(), 6);
    assert_eq!(manifest.encode(), canonical);
    let mut input = MANIFEST_HASH_DOMAIN.to_vec();
    assert_eq!(input, hex_field(&vector, "/hash_domain_hex")?);
    input.extend_from_slice(&canonical);
    assert_eq!(
        blake3::hash(&input).as_bytes().as_slice(),
        hex_field(&vector, "/manifest_hash_hex")?
    );
    // Rebuilding the same entries reproduces the bytes.
    let rebuilt = Manifest::new(*header, manifest.entries().to_vec(), &ManifestLimits::SPEC)?;
    assert_eq!(rebuilt.encode(), canonical);
    // Debug output carries no name or MIME label.
    let debug = format!("{manifest:?} {entry:?}");
    assert!(!debug.contains("hello.txt") && !debug.contains("text/plain"));
    Ok(())
}

/// The committed Accept fixture decodes and re-encodes; its signed
/// payload and domain match the record layout (§7.3).
#[test]
fn accept_fixture_decodes_and_reencodes() -> TestResult {
    let vector = fixture("accept-signature.json")?;
    let record = hex_field(&vector, "/signed_record_hex")?;
    assert_eq!(
        u64::try_from(record.len())?,
        u64_field(&vector, "/signed_record_length")?
    );
    let accept = Accept::decode(&record)?;
    let body = accept.body();
    assert_eq!(body.encode(), hex_field(&vector, "/signed_payload_hex")?);
    assert_eq!(accept.encode(), record);
    assert_eq!(
        body.session_id().as_slice(),
        hex_field(&vector, "/session_id_hex")?
    );
    assert_eq!(
        body.transfer_id().as_slice(),
        hex_field(&vector, "/transfer_id_hex")?
    );
    assert_eq!(
        body.manifest_hash().as_slice(),
        hex_field(&vector, "/manifest_hash_hex")?
    );
    assert_eq!(
        body.sender_public().as_slice(),
        hex_field(&vector, "/sender_ed25519_public_key_hex")?
    );
    assert_eq!(
        body.receiver_public().as_slice(),
        hex_field(&vector, "/receiver_ed25519_public_key_hex")?
    );
    assert_eq!(
        body.accept_nonce().as_slice(),
        hex_field(&vector, "/accept_nonce_hex")?
    );
    assert_eq!(
        body.expires_at().seconds(),
        u64_field(&vector, "/expires_at")?
    );
    assert_eq!(body.selection(), &[1]);
    assert_eq!(
        accept.signature().as_slice(),
        hex_field(&vector, "/signature_hex")?
    );
    assert_eq!(ACCEPT_DOMAIN, hex_field(&vector, "/signing_domain_hex")?);
    assert_eq!(
        ACCEPT_HASH_DOMAIN,
        hex_field(&vector, "/accept_hash_domain_hex")?
    );
    let mut message = ACCEPT_DOMAIN.to_vec();
    message.extend_from_slice(&body.encode());
    assert_eq!(message, hex_field(&vector, "/signing_message_hex")?);
    Ok(())
}

#[test]
fn accept_layout_negatives() -> TestResult {
    let vector = fixture("accept-signature.json")?;
    let record = hex_field(&vector, "/signed_record_hex")?;
    // Truncated, extended, misaligned.
    for len in [0, MIN_ACCEPT_LEN - 1, record.len() - 1] {
        assert_eq!(Accept::decode(&record[..len]), Err(DecodeError::Length));
    }
    let mut longer = record.clone();
    longer.extend_from_slice(&[0; 4]);
    assert_eq!(Accept::decode(&longer), Err(DecodeError::Length));
    // Count disagreeing with the length.
    let mut count = record.clone();
    count[173] = 2;
    assert_eq!(Accept::decode(&count), Err(DecodeError::Length));
    // Version.
    let mut version = record.clone();
    version[1] = 2;
    assert_eq!(Accept::decode(&version), Err(DecodeError::Version));
    // Zero session ID, transfer ID, nonce.
    for range in [2..34, 34..50, 146..162] {
        let mut zero = record.clone();
        zero[range].fill(0);
        assert_eq!(Accept::decode(&zero), Err(DecodeError::ZeroIdentifier));
    }
    // Expiry past the protocol range.
    let mut expiry = record.clone();
    expiry[162..170].fill(0xff);
    assert_eq!(Accept::decode(&expiry), Err(DecodeError::Range));
    // Selection of file 0, then a nonincreasing pair.
    let mut zero_id = record.clone();
    zero_id[174..178].fill(0);
    assert_eq!(Accept::decode(&zero_id), Err(DecodeError::Range));
    let body = Accept::decode(&record)?.body().clone();
    let pair = |selection: Vec<u32>| {
        AcceptBody::new(
            *body.session_id(),
            *body.transfer_id(),
            *body.manifest_hash(),
            *body.sender_public(),
            *body.receiver_public(),
            *body.accept_nonce(),
            body.expires_at(),
            selection,
        )
    };
    assert_eq!(pair(vec![2, 2]), Err(DecodeError::Order));
    assert_eq!(pair(vec![3, 2]), Err(DecodeError::Order));
    assert_eq!(pair(vec![]), Err(DecodeError::Range));
    let max = pair((1..=MAX_ENTRIES).collect())?;
    let signed = Accept::new(max, [7; 64]).encode();
    assert_eq!(signed.len(), MAX_ACCEPT_LEN);
    assert_eq!(Accept::decode(&signed)?.encode(), signed);
    assert_eq!(
        pair((1..=MAX_ENTRIES + 1).collect()),
        Err(DecodeError::Range)
    );
    Ok(())
}

#[test]
fn capabilities_ranges() -> TestResult {
    let caps = Capabilities::new(
        0b11,
        MAX_MANIFEST_BYTES,
        MAX_ENTRIES,
        MAX_FILE_BYTES,
        MAX_TRANSFER_BYTES,
        16,
    )?;
    let bytes = caps.encode();
    assert_eq!(Capabilities::decode(&bytes)?, caps);
    assert_eq!(&bytes[..2], &[0, 1]);
    assert_eq!(&bytes[30..], &[0; 8]);
    let minimal = Capabilities::new(0b10, MIN_MANIFEST_BYTES, 1, 0, 0, 1)?;
    assert_eq!(Capabilities::decode(&minimal.encode())?, minimal);
    let bad = [
        Capabilities::new(0b100, MAX_MANIFEST_BYTES, 1, 0, 0, 1),
        Capabilities::new(0b10, MIN_MANIFEST_BYTES - 1, 1, 0, 0, 1),
        Capabilities::new(0b10, MAX_MANIFEST_BYTES + 1, 1, 0, 0, 1),
        Capabilities::new(0b10, MAX_MANIFEST_BYTES, 0, 0, 0, 1),
        Capabilities::new(0b10, MAX_MANIFEST_BYTES, MAX_ENTRIES + 1, 0, 0, 1),
        Capabilities::new(0b10, MAX_MANIFEST_BYTES, 1, MAX_FILE_BYTES + 1, 0, 1),
        Capabilities::new(0b10, MAX_MANIFEST_BYTES, 1, 0, MAX_TRANSFER_BYTES + 1, 1),
        Capabilities::new(0b10, MAX_MANIFEST_BYTES, 1, 0, 0, 0),
        Capabilities::new(0b10, MAX_MANIFEST_BYTES, 1, 0, 0, 17),
    ];
    assert_eq!(bad[0], Err(DecodeError::Reserved));
    assert!(
        bad[1..]
            .iter()
            .all(|result| *result == Err(DecodeError::Range))
    );
    let mut extension = bytes;
    extension[37] = 1;
    assert_eq!(Capabilities::decode(&extension), Err(DecodeError::Reserved));
    let mut version = bytes;
    version[1] = 2;
    assert_eq!(Capabilities::decode(&version), Err(DecodeError::Version));
    assert_eq!(Capabilities::decode(&bytes[..37]), Err(DecodeError::Length));
    Ok(())
}

#[test]
fn manifest_start_and_part() -> TestResult {
    let start = ManifestStart::new([1; 16], [2; 32], 200)?;
    assert_eq!(ManifestStart::decode(&start.encode())?, start);
    assert_eq!(
        ManifestStart::new([0; 16], [2; 32], 200),
        Err(DecodeError::ZeroIdentifier)
    );
    assert_eq!(
        ManifestStart::new([1; 16], [2; 32], 107),
        Err(DecodeError::Range)
    );
    assert_eq!(
        ManifestStart::new([1; 16], [2; 32], MAX_MANIFEST_BYTES + 1),
        Err(DecodeError::Range)
    );
    assert_eq!(ManifestStart::decode(&[0; 51]), Err(DecodeError::Length));

    let data = vec![9; MAX_MANIFEST_PART_DATA];
    let part = ManifestPart::new([1; 16], 5, &data)?;
    let encoded = part.encode();
    assert_eq!(encoded.len(), MANIFEST_PART_HEADER_LEN + data.len());
    assert_eq!(ManifestPart::decode(&encoded)?, part);
    assert_eq!(ManifestPart::new([1; 16], 0, &[]), Err(DecodeError::Range));
    let too_long = vec![9; MAX_MANIFEST_PART_DATA + 1];
    assert_eq!(
        ManifestPart::new([1; 16], 0, &too_long),
        Err(DecodeError::Range)
    );
    assert_eq!(
        ManifestPart::decode(&encoded[..encoded.len() - 1]),
        Err(DecodeError::Length)
    );
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(ManifestPart::decode(&trailing), Err(DecodeError::Length));
    assert!(!format!("{part:?}").contains("09"));
    Ok(())
}

#[test]
fn chunk_records() -> TestResult {
    let request = ChunkRequest::new([1; 16], [2; 32], 7, 3, 9)?;
    assert_eq!(ChunkRequest::decode(&request.encode())?, request);
    assert_eq!(
        ChunkRequest::new([1; 16], [2; 32], 0, 3, 9),
        Err(DecodeError::Range)
    );
    assert_eq!(
        ChunkRequest::new([1; 16], [2; 32], 1, 0, 9),
        Err(DecodeError::Range)
    );
    assert_eq!(
        ChunkRequest::new([0; 16], [2; 32], 1, 1, 9),
        Err(DecodeError::ZeroIdentifier)
    );

    for len in [MIN_CONTENT_LEN, MAX_CONTENT_LEN] {
        let content = vec![5; len];
        let chunk = Chunk::new([1; 16], [2; 32], 7, 3, 9, &content)?;
        let encoded = chunk.encode();
        assert_eq!(encoded.len(), CHUNK_HEADER_LEN + len);
        assert_eq!(Chunk::decode(&encoded)?, chunk);
        assert_eq!(Chunk::peek_transfer_id(&encoded)?, [1; 16]);
        assert_eq!(
            Chunk::decode(&encoded[..encoded.len() - 1]),
            Err(DecodeError::Length)
        );
    }
    for len in [MIN_CONTENT_LEN - 1, MAX_CONTENT_LEN + 1] {
        let content = vec![5; len];
        assert_eq!(
            Chunk::new([1; 16], [2; 32], 7, 3, 9, &content),
            Err(DecodeError::Range)
        );
    }
    assert_eq!(Chunk::peek_transfer_id(&[1; 61]), Err(DecodeError::Length));
    Ok(())
}

#[test]
fn resume_records() -> TestResult {
    let query = ResumeQuery::new([1; 16], [2; 32], 3, 0)?;
    assert_eq!(ResumeQuery::decode(&query.encode())?, query);
    assert_eq!(
        ResumeQuery::new([1; 16], [2; 32], 0, 0),
        Err(DecodeError::Range)
    );

    let status = ResumeStatus::new([1; 16], [2; 32], 3, 4, 20, vec![(4, 2), (7, 1), (10, 10)])?;
    assert_eq!(ResumeStatus::decode(&status.encode())?, status);
    let empty_final = ResumeStatus::new([1; 16], [2; 32], 3, 9, 9, vec![])?;
    assert_eq!(ResumeStatus::decode(&empty_final.encode())?, empty_final);
    let make = |from, next, ranges| ResumeStatus::new([1; 16], [2; 32], 3, from, next, ranges);
    assert_eq!(make(5, 4, vec![]), Err(DecodeError::Range));
    assert_eq!(make(0, 10, vec![(0, 0)]), Err(DecodeError::Range));
    assert_eq!(make(2, 10, vec![(1, 1)]), Err(DecodeError::Range));
    assert_eq!(make(0, 10, vec![(8, 3)]), Err(DecodeError::Range));
    assert_eq!(make(0, 10, vec![(0, 2), (2, 1)]), Err(DecodeError::Order));
    assert_eq!(make(0, 10, vec![(4, 1), (0, 1)]), Err(DecodeError::Order));
    assert_eq!(make(0, 10, vec![(0, 3), (1, 1)]), Err(DecodeError::Order));
    assert_eq!(
        make(0, u32::MAX, vec![(u32::MAX - 1, 2)]),
        Err(DecodeError::Range)
    );
    let full = make(0, 4096, (0..1024).map(|i| (i * 4, 1)).collect())?;
    assert_eq!(ResumeStatus::decode(&full.encode())?, full);
    assert_eq!(
        make(0, 4096, (0..1025).map(|i| (i * 3, 1)).collect()),
        Err(DecodeError::Range)
    );
    let mut bad_count = status.encode();
    bad_count[61] = 2;
    assert_eq!(ResumeStatus::decode(&bad_count), Err(DecodeError::Length));
    let mut huge_count = status.encode();
    huge_count[60..62].copy_from_slice(&1025_u16.to_be_bytes());
    assert_eq!(ResumeStatus::decode(&huge_count), Err(DecodeError::Range));
    Ok(())
}

#[test]
fn cancel_reject_complete_receipt() -> TestResult {
    for reason in 1..=6 {
        let cancel = Cancel::new([1; 16], [2; 32], [3; 16], CancelReason::from_u16(reason)?)?;
        assert_eq!(Cancel::decode(&cancel.encode())?, cancel);
        assert_eq!(cancel.reason().to_u16(), reason);
    }
    let mut unknown = Cancel::new([1; 16], [2; 32], [3; 16], CancelReason::User)?.encode();
    unknown[65] = 7;
    assert_eq!(Cancel::decode(&unknown), Err(DecodeError::UnknownEnum));
    unknown[65] = 0;
    assert_eq!(Cancel::decode(&unknown), Err(DecodeError::UnknownEnum));
    assert_eq!(
        Cancel::new([1; 16], [2; 32], [0; 16], CancelReason::User),
        Err(DecodeError::ZeroIdentifier)
    );

    for reason in 1..=4 {
        let reject = Reject::new([1; 16], [2; 32], RejectReason::from_u16(reason)?)?;
        assert_eq!(Reject::decode(&reject.encode())?, reject);
    }
    assert_eq!(RejectReason::from_u16(5), Err(DecodeError::UnknownEnum));

    let complete = Complete::new([1; 16], [2; 32], [3; 32], 2, 100)?;
    assert_eq!(Complete::decode(&complete.encode())?, complete);
    assert_eq!(
        Complete::new([1; 16], [2; 32], [3; 32], 0, 100),
        Err(DecodeError::Range)
    );
    assert_eq!(
        Complete::new([1; 16], [2; 32], [3; 32], 1, MAX_TRANSFER_BYTES + 1),
        Err(DecodeError::Range)
    );

    let body = ReceiptBody::new(
        [4; 32],
        [1; 16],
        [2; 32],
        [3; 32],
        [5; 32],
        [6; 32],
        [7; 16],
        time(T0)?,
        2,
        100,
    )?;
    let receipt = DeliveryReceipt::new(body, [8; 64]);
    let encoded = receipt.encode();
    assert_eq!(encoded.len(), DELIVERY_RECEIPT_LEN);
    assert_eq!(encoded[RECEIPT_PREFIX_LEN - 1], 1);
    assert_eq!(DeliveryReceipt::decode(&encoded)?, receipt);
    let mut status = encoded;
    status[RECEIPT_PREFIX_LEN - 1] = 2;
    assert_eq!(
        DeliveryReceipt::decode(&status),
        Err(DecodeError::UnknownEnum)
    );
    let mut version = encoded;
    version[1] = 0;
    assert_eq!(DeliveryReceipt::decode(&version), Err(DecodeError::Version));
    let mut zero_receipt = encoded;
    zero_receipt[178..194].fill(0);
    assert_eq!(
        DeliveryReceipt::decode(&zero_receipt),
        Err(DecodeError::ZeroIdentifier)
    );
    assert_eq!(
        DeliveryReceipt::decode(&encoded[1..]),
        Err(DecodeError::Length)
    );
    Ok(())
}

#[test]
fn manifest_tree_rules() -> TestResult {
    // A folder tree: two directories, files at several levels, the same
    // name in different directories, an empty file.
    let manifest = build(vec![
        dir(1, 0, "photos"),
        file(2, 1, "a.jpg", 10),
        dir(3, 1, "2026"),
        file(4, 3, "a.jpg", 0),
        file(5, 0, "a.jpg", 7),
    ])?;
    assert_eq!(manifest.file_count(), 3);
    assert_eq!(manifest.total_file_bytes(), 17);
    assert_eq!(
        manifest.path_components(4).ok_or("path")?,
        ["photos", "2026", "a.jpg"]
    );
    assert_eq!(
        manifest.files().map(ManifestEntry::id).collect::<Vec<_>>(),
        [2, 4, 5]
    );
    assert!(
        manifest.file(3).is_none() && manifest.entry(6).is_none() && manifest.entry(0).is_none()
    );
    let decoded = Manifest::decode(&manifest.encode(), &ManifestLimits::SPEC)?;
    assert_eq!(decoded, manifest);

    let cases: Vec<(Vec<ManifestEntry>, ManifestError)> = vec![
        (vec![], ManifestError::EntryCount),
        (vec![file(2, 0, "a", 1)], ManifestError::EntryId),
        (
            vec![file(1, 0, "a", 1), file(1, 0, "b", 1)],
            ManifestError::EntryId,
        ),
        (vec![file(1, 1, "a", 1)], ManifestError::Parent),
        (
            vec![file(1, 0, "a", 1), file(2, 1, "b", 1)],
            ManifestError::Parent,
        ),
        (
            vec![dir(1, 0, "d"), file(2, 3, "b", 1)],
            ManifestError::Parent,
        ),
        (
            vec![file(1, 0, "a", 1), file(2, 0, "a", 1)],
            ManifestError::DuplicateName,
        ),
        (
            vec![dir(1, 0, "a"), file(2, 0, "a", 1)],
            ManifestError::DuplicateName,
        ),
        (
            vec![file(1, 0, "a", MAX_FILE_BYTES + 1)],
            ManifestError::Size,
        ),
    ];
    for (entries, error) in cases {
        assert_eq!(build(entries).map(|_| ()), Err(error));
    }
    // Directory fields that must be zero or empty.
    let mut bad_dir = dir(1, 0, "d");
    bad_dir.mime = "text/plain".to_owned();
    assert_eq!(build(vec![bad_dir]), Err(ManifestError::Mime));
    let mut bad_dir = dir(1, 0, "d");
    bad_dir.size = 1;
    assert_eq!(build(vec![bad_dir]), Err(ManifestError::Size));
    let mut bad_dir = dir(1, 0, "d");
    bad_dir.root = [1; 32];
    assert_eq!(build(vec![bad_dir]), Err(ManifestError::Root));
    let mut bad_dir = dir(1, 0, "d");
    bad_dir.content_suite = 2;
    assert_eq!(build(vec![bad_dir]), Err(ManifestError::Suite));
    // File fields.
    let mut bad_file = file(1, 0, "f", 1);
    bad_file.root = [0; 32];
    assert_eq!(build(vec![bad_file]), Err(ManifestError::Root));
    for suite in [0, 3] {
        let mut bad_file = file(1, 0, "f", 1);
        bad_file.content_suite = suite;
        assert_eq!(build(vec![bad_file]), Err(ManifestError::Suite));
    }
    let mut bad_file = file(1, 0, "f", 1);
    bad_file.mime = String::new();
    assert_eq!(build(vec![bad_file]), Err(ManifestError::Mime));
    Ok(())
}

#[test]
fn manifest_limits_and_header() -> TestResult {
    let limits = ManifestLimits::new(2, 10, 15);
    let entries = vec![file(1, 0, "a", 10), file(2, 0, "b", 5)];
    let header = header()?;
    assert!(Manifest::new(header, entries.clone(), &limits).is_ok());
    let mut three = entries.clone();
    three.push(file(3, 0, "c", 0));
    assert_eq!(
        Manifest::new(header, three, &limits),
        Err(ManifestError::EntryCount)
    );
    let big = vec![file(1, 0, "a", 11)];
    assert_eq!(
        Manifest::new(header, big, &limits),
        Err(ManifestError::Size)
    );
    let sum = vec![file(1, 0, "a", 10), file(2, 0, "b", 6)];
    assert_eq!(
        Manifest::new(header, sum, &limits),
        Err(ManifestError::TotalSize)
    );
    // Decoding applies the same limits.
    let encoded = Manifest::new(header, entries, &ManifestLimits::SPEC)?.encode();
    assert!(Manifest::decode(&encoded, &limits).is_ok());
    assert_eq!(
        Manifest::decode(&encoded, &ManifestLimits::new(1, 10, 15)),
        Err(ManifestError::EntryCount)
    );
    // Header rules.
    let one = vec![file(1, 0, "a", 1)];
    let mut zero_id = header;
    zero_id.transfer_id = [0; 16];
    assert_eq!(
        Manifest::new(zero_id, one.clone(), &limits),
        Err(ManifestError::TransferId)
    );
    let mut same_time = header;
    same_time.expires_at = header.created_at;
    assert_eq!(
        Manifest::new(same_time, one.clone(), &limits),
        Err(ManifestError::Time)
    );
    let mut long = header;
    long.expires_at = time(T0 + 7 * 86_400 + 1)?;
    assert_eq!(
        Manifest::new(long, one.clone(), &limits),
        Err(ManifestError::Time)
    );
    long.expires_at = time(T0 + 7 * 86_400)?;
    assert!(Manifest::new(long, one, &limits).is_ok());
    // Byte-level header checks.
    let mut magic = encoded.clone();
    magic[0] = b'X';
    assert_eq!(Manifest::decode(&magic, &limits), Err(ManifestError::Magic));
    let mut version = encoded.clone();
    version[5] = 2;
    assert_eq!(
        Manifest::decode(&version, &limits),
        Err(ManifestError::Version)
    );
    let mut flags = encoded.clone();
    flags[107] = 1;
    assert_eq!(Manifest::decode(&flags, &limits), Err(ManifestError::Flags));
    let mut kind = encoded.clone();
    kind[116] = 3;
    assert_eq!(Manifest::decode(&kind, &limits), Err(ManifestError::Kind));
    let mut trailing = encoded.clone();
    trailing.push(0);
    assert_eq!(
        Manifest::decode(&trailing, &limits),
        Err(ManifestError::Length)
    );
    assert_eq!(
        Manifest::decode(&encoded[..encoded.len() - 1], &limits),
        Err(ManifestError::Length)
    );
    assert_eq!(
        Manifest::decode(&encoded[..107], &limits),
        Err(ManifestError::Length)
    );
    // A huge count is refused before allocation.
    let mut count = encoded;
    count[102..106].copy_from_slice(&MAX_ENTRIES.to_be_bytes());
    assert_eq!(
        Manifest::decode(&count, &ManifestLimits::SPEC),
        Err(ManifestError::Length)
    );
    Ok(())
}

#[test]
fn manifest_depth_and_path_length() -> TestResult {
    let max_depth = usize::try_from(MAX_DEPTH)?;
    let mut deep: Vec<ManifestEntry> = (1..MAX_DEPTH).map(|id| dir(id, id - 1, "d")).collect();
    deep.push(file(MAX_DEPTH, MAX_DEPTH - 1, "f", 1));
    assert_eq!(deep.len(), max_depth);
    assert!(build(deep.clone()).is_ok());
    let mut deeper: Vec<ManifestEntry> = (1..=MAX_DEPTH).map(|id| dir(id, id - 1, "d")).collect();
    deeper.push(file(MAX_DEPTH + 1, MAX_DEPTH, "f", 1));
    assert_eq!(build(deeper), Err(ManifestError::Depth));

    // 15 directories of 255 bytes and one of 200, with separators, leave
    // 55 bytes for a file name in a 4096-byte path; 56 is one too many.
    let long = "x".repeat(255);
    let mut path: Vec<ManifestEntry> = (1..=15).map(|id| dir(id, id - 1, &long)).collect();
    path.push(dir(16, 15, &"m".repeat(200)));
    let used = 15 * 256 + 201;
    let mut exact = path.clone();
    exact.push(file(17, 16, &"y".repeat(MAX_PATH_LEN - used), 1));
    assert!(build(exact).is_ok());
    path.push(file(17, 16, &"y".repeat(MAX_PATH_LEN - used + 1), 1));
    assert_eq!(build(path), Err(ManifestError::PathLength));
    Ok(())
}

#[test]
fn name_rules() {
    for good in [
        "a",
        "file.txt",
        ".hidden",
        "conx.txt",
        "COM0",
        "LPT10",
        "naïve café",
        "日本語",
        "a b",
        "a.b.c",
    ] {
        assert_eq!(validate_name(good.as_bytes()), Ok(good), "{good}");
    }
    let too_long = "x".repeat(256);
    let max = "x".repeat(255);
    assert!(validate_name(max.as_bytes()).is_ok());
    for bad in [
        "",
        ".",
        "..",
        "a/b",
        "a\\b",
        "a:b",
        "a*b",
        "a?b",
        "a\"b",
        "a<b",
        "a>b",
        "a|b",
        "a\0b",
        "a\u{1}b",
        "a\u{1f}b",
        "a\u{7f}b",
        "a\nb",
        "trailing ",
        "trailing.",
        "CON",
        "con",
        "Prn.txt",
        "con.d",
        "aux.tar.gz",
        "NUL",
        "com1",
        "COM9.log",
        "lpt1",
        "LPT9",
        "e\u{301}", // decomposed é: not NFC
        too_long.as_str(),
    ] {
        assert_eq!(
            validate_name(bad.as_bytes()),
            Err(ManifestError::Name),
            "{bad:?}"
        );
    }
    assert_eq!(validate_name(&[0xff, 0xfe]), Err(ManifestError::Name));
}

#[test]
fn mime_rules() {
    let max = format!("a/{}", "b".repeat(125));
    for good in [
        "text/plain",
        "application/octet-stream",
        "image/svg+xml",
        "a/b",
        "x-a.b/c_d^e&f$g#h!i",
        max.as_str(),
    ] {
        assert_eq!(validate_mime(good.as_bytes()), Ok(good), "{good}");
    }
    let too_long = format!("a/{}", "b".repeat(126));
    for bad in [
        "",
        "text",
        "/plain",
        "text/",
        "text/plain/x",
        "Text/plain",
        "text/plain; charset=utf-8",
        "text/ plain",
        "text/pl@in",
        too_long.as_str(),
    ] {
        assert_eq!(
            validate_mime(bad.as_bytes()),
            Err(ManifestError::Mime),
            "{bad:?}"
        );
    }
}

fn arb_entries() -> impl Strategy<Value = Vec<(bool, u32, String, u64)>> {
    proptest::collection::vec(
        (any::<bool>(), any::<u32>(), "[a-z]{1,8}", 0..1_000_000_u64),
        1..30,
    )
}

proptest! {
    /// Any manifest the validator accepts re-decodes to itself, and every
    /// single-byte truncation is rejected.
    #[test]
    fn built_manifests_roundtrip(raw in arb_entries()) {
        let mut entries = Vec::new();
        let mut directories = vec![0_u32];
        for (index, (is_dir, parent_pick, name, size)) in raw.into_iter().enumerate() {
            let id = u32::try_from(index + 1).map_err(|_| TestCaseError::fail("id"))?;
            let parent = directories[usize::try_from(parent_pick).unwrap_or(0) % directories.len()];
            let name = format!("{name}-{id}");
            if is_dir {
                entries.push(dir(id, parent, &name));
                directories.push(id);
            } else {
                entries.push(file(id, parent, &name, size));
            }
        }
        let manifest = build(entries).map_err(|e| TestCaseError::fail(e.to_string()))?;
        let encoded = manifest.encode();
        prop_assert_eq!(Manifest::decode(&encoded, &ManifestLimits::SPEC), Ok(manifest));
        for cut in [encoded.len() - 1, MANIFEST_HEADER_LEN] {
            prop_assert!(Manifest::decode(&encoded[..cut], &ManifestLimits::SPEC).is_err());
        }
    }

    /// Decoders never panic, and anything accepted re-encodes exactly.
    #[test]
    fn decoders_are_canonical(bytes in proptest::collection::vec(any::<u8>(), 0..400)) {
        if let Ok(record) = Capabilities::decode(&bytes) { prop_assert_eq!(record.encode().to_vec(), bytes.clone()); }
        if let Ok(record) = ManifestStart::decode(&bytes) { prop_assert_eq!(record.encode().to_vec(), bytes.clone()); }
        if let Ok(record) = ManifestPart::decode(&bytes) { prop_assert_eq!(record.encode(), bytes.clone()); }
        if let Ok(record) = Accept::decode(&bytes) { prop_assert_eq!(record.encode(), bytes.clone()); }
        if let Ok(record) = Reject::decode(&bytes) { prop_assert_eq!(record.encode().to_vec(), bytes.clone()); }
        if let Ok(record) = ChunkRequest::decode(&bytes) { prop_assert_eq!(record.encode().to_vec(), bytes.clone()); }
        if let Ok(record) = Chunk::decode(&bytes) { prop_assert_eq!(record.encode(), bytes.clone()); }
        if let Ok(record) = ResumeQuery::decode(&bytes) { prop_assert_eq!(record.encode().to_vec(), bytes.clone()); }
        if let Ok(record) = ResumeStatus::decode(&bytes) { prop_assert_eq!(record.encode(), bytes.clone()); }
        if let Ok(record) = Cancel::decode(&bytes) { prop_assert_eq!(record.encode().to_vec(), bytes.clone()); }
        if let Ok(record) = Complete::decode(&bytes) { prop_assert_eq!(record.encode().to_vec(), bytes.clone()); }
        if let Ok(record) = DeliveryReceipt::decode(&bytes) { prop_assert_eq!(record.encode().to_vec(), bytes.clone()); }
        if let Ok(record) = Manifest::decode(&bytes, &ManifestLimits::SPEC) { prop_assert_eq!(record.encode(), bytes.clone()); }
    }
}

/// Zero identifiers are refused by the decoders themselves, not only by
/// the constructors (§1: transfer and cancel IDs are random and nonzero).
#[test]
fn decoders_refuse_zero_identifiers() -> TestResult {
    let reject = Reject::new([1; 16], [2; 32], RejectReason::Declined)?.encode();
    let mut zero = reject;
    zero[..16].fill(0);
    assert_eq!(Reject::decode(&zero), Err(DecodeError::ZeroIdentifier));
    let cancel = Cancel::new([1; 16], [2; 32], [3; 16], CancelReason::User)?.encode();
    for range in [0..16, 48..64] {
        let mut zero = cancel;
        zero[range].fill(0);
        assert_eq!(Cancel::decode(&zero), Err(DecodeError::ZeroIdentifier));
    }
    Ok(())
}

/// The record constructors refuse what their decoders refuse: request and
/// file ID 0 in a `Chunk`, file ID 0 in a `ResumeStatus`, a part offset
/// at or past the 4 MiB manifest maximum, a zero session ID in a receipt,
/// and undefined content-suite bits.
#[test]
fn constructors_check_every_range() -> TestResult {
    let content = [5; MIN_CONTENT_LEN];
    assert_eq!(
        Chunk::new([1; 16], [2; 32], 0, 3, 9, &content),
        Err(DecodeError::Range)
    );
    assert_eq!(
        Chunk::new([1; 16], [2; 32], 7, 0, 9, &content),
        Err(DecodeError::Range)
    );
    let mut zero_request = Chunk::new([1; 16], [2; 32], 7, 3, 9, &content)?.encode();
    zero_request[48..52].fill(0);
    assert_eq!(Chunk::decode(&zero_request), Err(DecodeError::Range));
    let mut zero_file = Chunk::new([1; 16], [2; 32], 7, 3, 9, &content)?.encode();
    zero_file[52..56].fill(0);
    assert_eq!(Chunk::decode(&zero_file), Err(DecodeError::Range));

    assert_eq!(
        ResumeStatus::new([1; 16], [2; 32], 0, 0, 1, vec![]),
        Err(DecodeError::Range)
    );

    let data = [9; 10];
    assert!(ManifestPart::new([1; 16], MAX_MANIFEST_BYTES - 1, &data).is_ok());
    assert_eq!(
        ManifestPart::new([1; 16], MAX_MANIFEST_BYTES, &data),
        Err(DecodeError::Range)
    );

    let receipt = |session_id| {
        ReceiptBody::new(
            session_id,
            [1; 16],
            [2; 32],
            [3; 32],
            [5; 32],
            [6; 32],
            [7; 16],
            time(T0)?,
            2,
            100,
        )
        .map_err(Box::<dyn std::error::Error>::from)
    };
    assert!(receipt([4; 32]).is_ok());
    assert_eq!(
        receipt([0; 32])
            .err()
            .and_then(|error| error.downcast_ref::<DecodeError>().copied()),
        Some(DecodeError::ZeroIdentifier)
    );

    for bits in [0b01, 0b10, 0b11] {
        assert_eq!(
            Capabilities::PROTOCOL_MAXIMUMS
                .with_content_suites(bits)?
                .content_suites(),
            bits
        );
    }
    for bits in [0b100, 0x8000] {
        assert_eq!(
            Capabilities::PROTOCOL_MAXIMUMS.with_content_suites(bits),
            Err(DecodeError::Reserved)
        );
    }
    Ok(())
}

/// The 4 MiB manifest bound (§7.1) holds when building and when decoding,
/// and a zero `entry_count` is refused by the decoder.
#[test]
fn manifest_size_bound_and_zero_count() -> TestResult {
    // 10000 files with 255-byte names and 127-byte MIME labels encode to
    // more than 4 MiB although every field is within its own limit.
    let mime = format!("a/{}", "b".repeat(125));
    let entries: Vec<ManifestEntry> = (1..=MAX_ENTRIES)
        .map(|id| {
            ManifestEntry::file(
                id,
                0,
                format!("{id:05}{}", "n".repeat(250)),
                mime.clone(),
                1,
                [0x11; 32],
                2,
            )
        })
        .collect();
    assert_eq!(build(entries), Err(ManifestError::Length));
    // Decoding refuses more than 4 MiB before reading anything.
    let oversized = vec![0; MAX_MANIFEST_BYTES as usize + 1];
    assert_eq!(
        Manifest::decode(&oversized, &ManifestLimits::SPEC),
        Err(ManifestError::Length)
    );
    let mut zero_count = build(vec![file(1, 0, "a", 1)])?.encode();
    zero_count[102..106].fill(0);
    assert_eq!(
        Manifest::decode(&zero_count, &ManifestLimits::SPEC),
        Err(ManifestError::EntryCount)
    );
    Ok(())
}

/// Digits are allowed in MIME labels (§7.1: `a-z`, `0-9`, and
/// `!#$&^_.+-`), for example `video/mp4`.
#[test]
fn mime_labels_may_contain_digits() {
    for good in [
        "video/mp4",
        "audio/3gpp",
        "application/x-7z-compressed",
        "0/9",
    ] {
        assert_eq!(validate_mime(good.as_bytes()), Ok(good), "{good}");
    }
}
