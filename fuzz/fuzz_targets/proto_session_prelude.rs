//! Prelude framing, Hellos, and `NoiseHandshake` records on arbitrary bytes;
//! accepted input must be canonical.
#![no_main]

use libfuzzer_sys::fuzz_target;
use todoke_proto::session::{
    HELLO_LEN, Hello, NoiseHandshakeRecord, PreludeRecord, SessionMode, encode_prelude_record,
    prelude_record_len,
};

fuzz_target!(|data: &[u8]| {
    if let Some((prefix, rest)) = data.split_first_chunk::<2>() {
        if let Ok(length) = prelude_record_len(*prefix) {
            assert!((1..=8192).contains(&length));
            if let Some(record) = rest.get(..length) {
                check_record(record);
            }
        }
    }
    check_record(data);
    if let Ok(client) = Hello::decode_client(data) {
        assert_eq!(client.encode().as_slice(), data);
    }
    // A server hello needs the client hello it echoes: split the input.
    if data.len() >= 2 * HELLO_LEN {
        let (first, second) = data.split_at(HELLO_LEN);
        if let Ok(client) = Hello::decode_client(first) {
            if let Ok(server) = Hello::decode_server(&second[..HELLO_LEN], &client) {
                assert_eq!(server.encode().as_slice(), &second[..HELLO_LEN]);
                assert_eq!(server.mode(), client.mode());
            }
        }
    }
});

fn check_record(record: &[u8]) {
    let Ok(decoded) = PreludeRecord::decode(record) else {
        return;
    };
    let Ok(encoded) = encode_prelude_record(decoded.kind(), decoded.body()) else {
        panic!("decoded record must re-encode");
    };
    assert_eq!(&encoded[2..], record);
    for mode in [SessionMode::Qr, SessionMode::Code, SessionMode::Contact] {
        if let Ok(noise) = NoiseHandshakeRecord::decode(decoded.body(), mode) {
            let Ok(encoded) = NoiseHandshakeRecord::encode_record(
                mode,
                noise.message_index(),
                noise.token_bytes(),
            ) else {
                panic!("decoded noise record must re-encode");
            };
            assert_eq!(&encoded[3..], decoded.body());
        }
    }
}
