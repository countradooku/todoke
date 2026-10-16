use super::*;
use crate::identity::{DeviceBindingBody, KEM_STATIC_LEN};
use crate::time::UnixTime;
use core::num::NonZeroU64;
use proptest::prelude::*;

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

const FIXTURES: [(&str, SessionMode); 3] = [
    ("handshake-ikpsk2.json", SessionMode::Qr),
    ("handshake-kkpsk2.json", SessionMode::Contact),
    ("handshake-xxpsk3.json", SessionMode::Code),
];

#[test]
fn fixture_hellos_and_records_decode_and_reencode() -> TestResult {
    for (name, mode) in FIXTURES {
        let vector = fixture(name)?;
        let client_bytes = hex_field(&vector, "/inputs/prelude/client_hello_body_hex")?;
        let server_bytes = hex_field(&vector, "/inputs/prelude/server_hello_body_hex")?;
        let client = Hello::decode_client(&client_bytes)?;
        let server = Hello::decode_server(&server_bytes, &client)?;
        assert_eq!(client.mode(), mode);
        assert_eq!(client.encode().as_slice(), client_bytes.as_slice());
        assert_eq!(server.encode().as_slice(), server_bytes.as_slice());
        assert_eq!(client.server_reply(*server.server_nonce())?, server);
        let messages = vector
            .get("messages")
            .and_then(serde_json::Value::as_array)
            .ok_or("missing messages")?;
        assert_eq!(messages.len(), mode.noise_message_lens().len());
        for (position, message) in messages.iter().enumerate() {
            let framed = hex_field(message, "/prelude_record_hex")?;
            let inner = hex_field(message, "/noise_message_hex")?;
            let prefix = framed.first_chunk::<2>().ok_or("short record")?;
            let length = prelude_record_len(*prefix)?;
            assert_eq!(length + 2, framed.len());
            let record = PreludeRecord::decode(&framed[2..])?;
            assert_eq!(record.kind(), PreludeKind::NoiseHandshake);
            let noise = NoiseHandshakeRecord::decode(record.body(), mode)?;
            assert_eq!(usize::from(noise.message_index()), position + 1);
            assert_eq!(noise.token_bytes(), inner.as_slice());
            let index = u8::try_from(position + 1)?;
            assert_eq!(
                NoiseHandshakeRecord::encode_record(mode, index, &inner)?,
                framed
            );
        }
    }
    Ok(())
}

/// The §4.2.5 wire record sizes, length prefix included: IK 1300/1156,
/// KK 1252/1156, XX 1252/1204/68; `length` is two less.
#[test]
fn noise_record_lengths_match_the_spec_table() -> TestResult {
    for (mode, expected) in [
        (SessionMode::Qr, &[1300, 1156][..]),
        (SessionMode::Contact, &[1252, 1156][..]),
        (SessionMode::Code, &[1252, 1204, 68][..]),
    ] {
        for (position, length) in expected.iter().enumerate() {
            let index = u8::try_from(position + 1)?;
            let inner = NoiseHandshakeRecord::inner_len(mode, index).ok_or("index")?;
            let record = NoiseHandshakeRecord::encode_record(mode, index, &vec![0; inner])?;
            assert_eq!(record.len(), *length);
            assert_eq!(prelude_record_len([record[0], record[1]])?, length - 2);
        }
        let past = u8::try_from(expected.len() + 1)?;
        assert_eq!(NoiseHandshakeRecord::inner_len(mode, 0), None);
        assert_eq!(NoiseHandshakeRecord::inner_len(mode, past), None);
        assert_eq!(
            NoiseHandshakeRecord::decode(&[past], mode),
            Err(DecodeError::Index)
        );
        assert_eq!(
            NoiseHandshakeRecord::decode(&[0], mode),
            Err(DecodeError::Index)
        );
        assert_eq!(
            NoiseHandshakeRecord::encode_record(mode, past, &[]),
            Err(DecodeError::Index)
        );
    }
    Ok(())
}

#[test]
fn noise_records_reject_every_wrong_inner_size() -> TestResult {
    for mode in [SessionMode::Qr, SessionMode::Contact, SessionMode::Code] {
        for (position, &inner) in mode.noise_message_lens().iter().enumerate() {
            let index = u8::try_from(position + 1)?;
            for wrong in [0, inner - 1, inner + 1] {
                let mut body = vec![index];
                body.resize(1 + wrong, 0);
                assert_eq!(
                    NoiseHandshakeRecord::decode(&body, mode),
                    Err(DecodeError::Length)
                );
                assert_eq!(
                    NoiseHandshakeRecord::encode_record(mode, index, &body[1..]),
                    Err(DecodeError::Length)
                );
            }
        }
        assert_eq!(
            NoiseHandshakeRecord::decode(&[], mode),
            Err(DecodeError::Length)
        );
    }
    Ok(())
}

#[test]
fn prelude_length_prefix_bounds() {
    assert_eq!(prelude_record_len([0, 0]), Err(DecodeError::Length));
    assert_eq!(prelude_record_len([0, 1]), Ok(1));
    assert_eq!(prelude_record_len([0x20, 0x00]), Ok(8192));
    assert_eq!(prelude_record_len([0x20, 0x01]), Err(DecodeError::Length));
    assert_eq!(prelude_record_len([0xff, 0xff]), Err(DecodeError::Length));
}

#[test]
fn prelude_kinds_and_reserved_values() -> TestResult {
    for value in 0..=u8::MAX {
        let kind = PreludeKind::from_u8(value);
        assert_eq!(kind.is_some(), (1..=7).contains(&value));
        if let Some(kind) = kind {
            assert_eq!(kind.to_u8(), value);
        }
        let record = [value, 1, 2];
        match PreludeRecord::decode(&record) {
            Ok(decoded) => {
                assert_eq!(Some(decoded.kind()), kind);
                assert_eq!(decoded.body(), &[1, 2]);
            }
            Err(error) => {
                assert_eq!(error, DecodeError::UnknownEnum);
                assert!(kind.is_none());
            }
        }
    }
    assert_eq!(PreludeRecord::decode(&[]), Err(DecodeError::Length));
    let mut oversized = vec![1; PRELUDE_MAX_LEN + 1];
    assert_eq!(PreludeRecord::decode(&oversized), Err(DecodeError::Length));
    oversized.pop();
    assert!(PreludeRecord::decode(&oversized).is_ok());
    let encoded = encode_prelude_record(PreludeKind::ServerHello, &[9; PRELUDE_MAX_BODY_LEN])?;
    assert_eq!(&encoded[..3], &[0x20, 0x00, 0x02]);
    assert_eq!(
        encode_prelude_record(PreludeKind::ServerHello, &[9; PRELUDE_MAX_BODY_LEN + 1]),
        Err(DecodeError::Length)
    );
    Ok(())
}

fn sample_client(mode: SessionMode) -> Result<Hello, DecodeError> {
    Hello::client(mode, [0xa1; 16], [0xa5; 16])
}

#[test]
fn hello_field_validation() -> TestResult {
    let client = sample_client(SessionMode::Contact)?;
    let bytes = client.encode();
    let mutate = |offset: usize, value: u8| {
        let mut changed = bytes;
        changed[offset] = value;
        changed
    };
    assert_eq!(
        Hello::decode_client(&mutate(0, b'X')),
        Err(DecodeError::Magic)
    );
    assert_eq!(
        Hello::decode_client(&mutate(5, 2)),
        Err(DecodeError::Version)
    );
    assert_eq!(
        Hello::decode_client(&mutate(4, 1)),
        Err(DecodeError::Version)
    );
    assert_eq!(Hello::decode_client(&mutate(7, 2)), Err(DecodeError::Suite));
    assert_eq!(Hello::decode_client(&mutate(6, 1)), Err(DecodeError::Suite));
    for mode in [0, 4, 0xff] {
        assert_eq!(
            Hello::decode_client(&mutate(8, mode)),
            Err(DecodeError::UnknownEnum)
        );
    }
    assert_eq!(
        Hello::decode_client(&mutate(9, 1)),
        Err(DecodeError::Reserved)
    );
    assert_eq!(
        Hello::decode_client(&mutate(42, 1)),
        Err(DecodeError::Reserved)
    );
    assert_eq!(Hello::decode_client(&bytes[..57]), Err(DecodeError::Length));
    // The 66-byte layout that carried a generation (before §16 O12).
    assert_eq!(
        Hello::decode_client(&[bytes.as_slice(), &[0; 8]].concat()),
        Err(DecodeError::Length)
    );
    let mut long = bytes.to_vec();
    long.push(0);
    assert_eq!(Hello::decode_client(&long), Err(DecodeError::Length));
    let mut zero_locator = bytes;
    zero_locator[10..26].fill(0);
    assert_eq!(
        Hello::decode_client(&zero_locator),
        Err(DecodeError::ZeroIdentifier)
    );
    let mut zero_nonce = bytes;
    zero_nonce[26..42].fill(0);
    assert_eq!(
        Hello::decode_client(&zero_nonce),
        Err(DecodeError::ZeroIdentifier)
    );
    assert!(Hello::client(SessionMode::Contact, [1; 16], [1; 16]).is_ok());
    assert_eq!(
        Hello::client(SessionMode::Contact, [0; 16], [1; 16]),
        Err(DecodeError::ZeroIdentifier)
    );
    Ok(())
}

#[test]
fn server_hello_must_echo_every_field() -> TestResult {
    let client = sample_client(SessionMode::Contact)?;
    let server = client.server_reply([0xa6; 16])?;
    let bytes = server.encode();
    assert_eq!(Hello::decode_server(&bytes, &client)?, server);
    assert_eq!(
        client.server_reply([0; 16]),
        Err(DecodeError::ZeroIdentifier)
    );
    let mut zero = bytes;
    zero[42..].fill(0);
    assert_eq!(
        Hello::decode_server(&zero, &client),
        Err(DecodeError::ZeroIdentifier)
    );
    // Every echoed byte (mode, locator, client nonce) is checked.
    for offset in 8..42 {
        if offset == 9 {
            continue;
        }
        let mut changed = bytes;
        changed[offset] ^= 0x01;
        assert!(Hello::decode_server(&changed, &client).is_err(), "{offset}");
    }
    // A client hello is not a server hello and vice versa.
    assert!(Hello::decode_server(&client.encode(), &client).is_err());
    assert_eq!(Hello::decode_client(&bytes), Err(DecodeError::Reserved));
    Ok(())
}

#[test]
fn ciphertext_prefix_bounds() {
    assert_eq!(ciphertext_len([0, 19]), Err(DecodeError::Length));
    assert_eq!(ciphertext_len([0, 0]), Err(DecodeError::Length));
    assert_eq!(ciphertext_len([0, 20]), Ok(20));
    assert_eq!(ciphertext_len([0xff, 0xff]), Ok(65_535));
}

#[test]
fn frame_type_registry() {
    let class = |value| FrameType::new(value).class();
    for value in [1, 2, 3, 4, 6, 7, 8, 9] {
        assert_eq!(class(value), FrameClass::Session, "{value}");
    }
    for value in [
        5, 0x10, 0x15, 0x1c, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x40,
    ] {
        assert_eq!(class(value), FrameClass::Application, "{value}");
    }
    for value in [
        0, 0x0a, 0x0f, 0x1d, 0x1f, 0x27, 0x3f, 0x41, 0x100, 0x6ff, 0x7fff,
    ] {
        assert_eq!(class(value), FrameClass::UnsupportedCritical, "{value}");
    }
    for value in [0x8000, 0x9abc, 0xbfff] {
        assert_eq!(class(value), FrameClass::Noncritical, "{value}");
    }
    for value in [0xc000, 0xffff] {
        assert_eq!(class(value), FrameClass::Experimental, "{value}");
    }
    assert_eq!(format!("{:?}", FrameType::KEY_UPDATE), "FrameType(0x0006)");
}

#[test]
fn frame_header_rules() -> TestResult {
    let mut out = Vec::new();
    encode_frame_into(FrameType::PING, &[1, 2, 3], &mut out)?;
    assert_eq!(out, [0, 7, 0, 0, 1, 2, 3]);
    assert_eq!(decode_frame(&out)?, (FrameType::PING, &[1, 2, 3][..]));
    assert_eq!(decode_frame(&[0, 7, 0]), Err(DecodeError::Length));
    assert_eq!(decode_frame(&[0, 7, 0, 1]), Err(DecodeError::Reserved));
    assert_eq!(decode_frame(&[0, 7, 1, 0]), Err(DecodeError::Reserved));
    let max = vec![0; MAX_PLAINTEXT_LEN];
    assert!(decode_frame(&max).is_ok());
    let over = vec![0; MAX_PLAINTEXT_LEN + 1];
    assert_eq!(decode_frame(&over), Err(DecodeError::Length));
    let mut out = Vec::new();
    encode_frame_into(FrameType::PING, &vec![0; MAX_BODY_LEN], &mut out)?;
    assert_eq!(out.len(), MAX_PLAINTEXT_LEN);
    assert_eq!(
        encode_frame_into(FrameType::PING, &vec![0; MAX_BODY_LEN + 1], &mut Vec::new()),
        Err(DecodeError::Length)
    );
    Ok(())
}

fn sample_binding() -> Result<DeviceBinding, Box<dyn std::error::Error>> {
    let body = DeviceBindingBody::new(
        [1; 32],
        [2; 32],
        [3; 32],
        Box::new([4; KEM_STATIC_LEN]),
        NonZeroU64::new(7).ok_or("zero")?,
        UnixTime::new(1_760_000_000).ok_or("time")?,
        UnixTime::new(1_760_086_400).ok_or("time")?,
    )?;
    Ok(DeviceBinding::from_parts(body, [5; 64], [6; 64]))
}

#[test]
fn identity_layout() -> TestResult {
    let identity = Identity::new(sample_binding()?, [8; 32], [9; 64]);
    let bytes = identity.encode();
    assert_eq!(bytes.len(), IDENTITY_LEN);
    assert_eq!(IDENTITY_LEN, 1536);
    assert_eq!(&bytes[..2], &[0x05, 0x9e]);
    assert_eq!(Identity::decode(&bytes)?, identity);
    assert_eq!(identity.handshake_hash(), &[8; 32]);
    assert_eq!(identity.signature(), &[9; 64]);
    assert_eq!(identity.binding(), &sample_binding()?);
    let mut wrong_len = bytes.clone();
    wrong_len[1] = 0x9d;
    assert_eq!(Identity::decode(&wrong_len), Err(DecodeError::Length));
    assert_eq!(Identity::decode(&bytes[1..]), Err(DecodeError::Length));
    let mut bad_binding = bytes.clone();
    bad_binding[3] = 2; // binding version
    assert_eq!(
        Identity::decode(&bad_binding),
        Err(DecodeError::Binding(identity::DecodeError::Version))
    );
    let debug = format!("{identity:?}");
    assert!(debug.contains(&"08".repeat(32)) && debug.contains(&"09".repeat(64)));
    Ok(())
}

#[test]
fn ratchet_layout() -> TestResult {
    let record = Ratchet::new([1; 32], 8, [2; 32])?;
    let bytes = record.encode();
    assert_eq!(bytes.len(), 72);
    assert_eq!(&bytes[32..40], &8_u64.to_be_bytes());
    assert_eq!(Ratchet::decode(&bytes)?, record);
    assert_eq!(record.session_id(), &[1; 32]);
    assert_eq!(record.generation_next(), 8);
    assert_eq!(record.confirmation(), &[2; 32]);
    assert_eq!(Ratchet::new([1; 32], 0, [2; 32]), Err(DecodeError::Range));
    let mut zero = bytes;
    zero[32..40].fill(0);
    assert_eq!(Ratchet::decode(&zero), Err(DecodeError::Range));
    assert_eq!(Ratchet::decode(&bytes[1..]), Err(DecodeError::Length));
    assert!(format!("{record:?}").contains("generation_next: 8"));
    Ok(())
}

#[test]
fn key_update_and_ping_layouts() {
    assert_eq!(decode_key_update(&1_u64.to_be_bytes()), Ok(1));
    assert_eq!(decode_key_update(&u64::MAX.to_be_bytes()), Ok(u64::MAX));
    assert_eq!(decode_key_update(&[0; 8]), Err(DecodeError::Range));
    assert_eq!(decode_key_update(&[0; 7]), Err(DecodeError::Length));
    assert_eq!(decode_key_update(&[0; 9]), Err(DecodeError::Length));
    assert_eq!(decode_ping(&5_u64.to_be_bytes()), Ok(5));
    assert_eq!(decode_ping(&[0; 8]), Err(DecodeError::ZeroIdentifier));
    assert_eq!(decode_ping(&[1; 9]), Err(DecodeError::Length));
}

#[test]
fn error_record_layout() -> TestResult {
    let session = ErrorRecord::new(ErrorScope::Session, ErrorCode::STATE)?;
    let bytes = session.encode();
    assert_eq!(
        bytes,
        [0, 0, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
    );
    assert_eq!(ErrorRecord::decode(&bytes)?, session);
    let transfer = ErrorRecord::new(ErrorScope::Transfer([3; 16]), ErrorCode::INTEGRITY)?;
    let bytes = transfer.encode();
    assert_eq!(bytes[0], 1);
    assert_eq!(&bytes[1..3], &[0, 8]);
    assert_eq!(ErrorRecord::decode(&bytes)?, transfer);
    assert_eq!(transfer.scope(), ErrorScope::Transfer([3; 16]));
    assert_eq!(transfer.code(), ErrorCode::INTEGRITY);
    assert_eq!(
        ErrorRecord::new(ErrorScope::Transfer([0; 16]), ErrorCode::STATE),
        Err(DecodeError::ZeroIdentifier)
    );
    let mut zero_code = bytes;
    zero_code[1..3].fill(0);
    assert_eq!(
        ErrorRecord::decode(&zero_code),
        Err(DecodeError::UnknownEnum)
    );
    let mut bad_scope = bytes;
    bad_scope[0] = 2;
    assert_eq!(
        ErrorRecord::decode(&bad_scope),
        Err(DecodeError::UnknownEnum)
    );
    let mut session_with_id = session.encode();
    session_with_id[18] = 1;
    assert_eq!(
        ErrorRecord::decode(&session_with_id),
        Err(DecodeError::Reserved)
    );
    let mut transfer_zero = transfer.encode();
    transfer_zero[3..].fill(0);
    assert_eq!(
        ErrorRecord::decode(&transfer_zero),
        Err(DecodeError::ZeroIdentifier)
    );
    assert_eq!(ErrorRecord::decode(&bytes[1..]), Err(DecodeError::Length));
    // Unknown nonzero codes are kept as raw values (generic failure).
    assert_eq!(ErrorCode::new(0x1234)?.get(), 0x1234);
    assert_eq!(format!("{:?}", ErrorCode::RATCHET), "ErrorCode(0x000d)");
    Ok(())
}

#[test]
fn errors_have_distinct_messages() -> TestResult {
    let messages: Vec<String> = [
        DecodeError::Length,
        DecodeError::Magic,
        DecodeError::Version,
        DecodeError::Suite,
        DecodeError::Reserved,
        DecodeError::Range,
        DecodeError::ZeroIdentifier,
        DecodeError::UnknownEnum,
        DecodeError::Index,
        DecodeError::Binding(identity::DecodeError::Length),
    ]
    .iter()
    .map(ToString::to_string)
    .collect();
    for (index, message) in messages.iter().enumerate() {
        assert_ne!(message, "");
        assert!(!messages[..index].contains(message), "{message}");
    }
    let hello = format!("{:?}", sample_client(SessionMode::Qr)?);
    // The locator is redacted (see hello_debug_redacts_locator_and_nonces).
    assert!(!hello.contains(&"a1".repeat(16)) && hello.contains("Qr"));
    let record = NoiseHandshakeRecord::decode(&[2; 1153], SessionMode::Qr)?;
    assert!(format!("{record:?}").contains("[1152 bytes]"));
    Ok(())
}

fn arb_mode() -> impl Strategy<Value = SessionMode> {
    prop_oneof![
        Just(SessionMode::Qr),
        Just(SessionMode::Code),
        Just(SessionMode::Contact)
    ]
}

proptest! {
    #[test]
    fn hellos_round_trip(
        mode in arb_mode(),
        locator in any::<[u8; 16]>(),
        client_nonce in any::<[u8; 16]>(),
        server_nonce in any::<[u8; 16]>(),
    ) {
        if let Ok(client) = Hello::client(mode, locator, client_nonce) {
            let bytes = client.encode();
            prop_assert_eq!(Hello::decode_client(&bytes), Ok(client));
            if let Ok(server) = client.server_reply(server_nonce) {
                prop_assert_eq!(Hello::decode_server(&server.encode(), &client), Ok(server));
            }
        }
    }

    #[test]
    fn ratchet_and_error_round_trip(
        session_id in any::<[u8; 32]>(),
        generation in 1..=u64::MAX,
        confirmation in any::<[u8; 32]>(),
        code in 1..=u16::MAX,
        transfer in proptest::option::of(any::<[u8; 16]>()),
    ) {
        let record = Ratchet::new(session_id, generation, confirmation)?;
        prop_assert_eq!(Ratchet::decode(&record.encode()), Ok(record));
        let scope = transfer.map_or(ErrorScope::Session, ErrorScope::Transfer);
        if let Ok(error) = ErrorRecord::new(scope, ErrorCode::new(code)?) {
            prop_assert_eq!(ErrorRecord::decode(&error.encode()), Ok(error));
        }
    }

    // Accepted inputs are canonical: re-encoding reproduces them exactly.
    #[test]
    fn decoders_are_canonical_and_never_panic(
        bytes in proptest::collection::vec(any::<u8>(), 0..1600),
        mode in arb_mode(),
    ) {
        if let Ok(hello) = Hello::decode_client(&bytes) {
            prop_assert_eq!(hello.encode().to_vec(), bytes.clone());
        }
        if let Ok(record) = Ratchet::decode(&bytes) {
            prop_assert_eq!(record.encode().to_vec(), bytes.clone());
        }
        if let Ok(error) = ErrorRecord::decode(&bytes) {
            prop_assert_eq!(error.encode().to_vec(), bytes.clone());
        }
        if let Ok(identity) = Identity::decode(&bytes) {
            prop_assert_eq!(identity.encode(), bytes.clone());
        }
        if let Ok(record) = PreludeRecord::decode(&bytes) {
            let encoded = encode_prelude_record(record.kind(), record.body())?;
            prop_assert_eq!(&encoded[2..], bytes.as_slice());
            if let Ok(noise) = NoiseHandshakeRecord::decode(record.body(), mode) {
                let encoded = NoiseHandshakeRecord::encode_record(
                    mode,
                    noise.message_index(),
                    noise.token_bytes(),
                )?;
                prop_assert_eq!(&encoded[3..], record.body());
            }
        }
        if let Ok((frame_type, body)) = decode_frame(&bytes) {
            let mut encoded = Vec::new();
            encode_frame_into(frame_type, body, &mut encoded)?;
            prop_assert_eq!(encoded, bytes.clone());
        }
        let _ = decode_key_update(&bytes);
        let _ = decode_ping(&bytes);
    }
}

/// §14.2: contact tokens are not logged. The locator is a pairing ID or a
/// contact rendezvous-token prefix and the nonces identify the attempt, so
/// `Debug` shows only their sizes.
#[test]
fn hello_debug_redacts_locator_and_nonces() -> TestResult {
    let client = Hello::client(SessionMode::Contact, [0xa1; 16], [0xa5; 16])?;
    let server = client.server_reply([0xa6; 16])?;
    for hello in [client, server] {
        let debug = format!("{hello:?}");
        for byte in ["a1", "a5", "a6"] {
            assert!(!debug.contains(&byte.repeat(4)), "{debug}");
        }
        assert!(!debug.contains("161"), "{debug}");
        assert!(
            debug.contains("[16 bytes]") && debug.contains("Contact"),
            "{debug}"
        );
        assert!(!debug.contains("generation"), "{debug}");
    }
    Ok(())
}
