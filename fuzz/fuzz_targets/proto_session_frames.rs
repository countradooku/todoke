//! Transport frame header and session frame bodies on arbitrary bytes;
//! accepted input must be canonical.
#![no_main]

use libfuzzer_sys::fuzz_target;
use todoke_proto::session::{
    ErrorRecord, Identity, Ratchet, ciphertext_len, decode_frame, decode_key_update,
    decode_ping, encode_frame_into,
};

fuzz_target!(|data: &[u8]| {
    if let Some(prefix) = data.first_chunk::<2>() {
        if let Ok(length) = ciphertext_len(*prefix) {
            assert!((20..=65_535).contains(&length));
        }
    }
    let Ok((frame_type, body)) = decode_frame(data) else {
        return;
    };
    let _ = frame_type.class();
    let mut encoded = Vec::new();
    assert!(encode_frame_into(frame_type, body, &mut encoded).is_ok());
    assert_eq!(encoded, data);
    if let Ok(identity) = Identity::decode(body) {
        assert_eq!(identity.encode(), body);
    }
    if let Ok(ratchet) = Ratchet::decode(body) {
        assert_eq!(ratchet.encode().as_slice(), body);
    }
    if let Ok(error) = ErrorRecord::decode(body) {
        assert_eq!(error.encode().as_slice(), body);
    }
    if let Ok(epoch) = decode_key_update(body) {
        assert_eq!(epoch.to_be_bytes().as_slice(), body);
    }
    if let Ok(nonce) = decode_ping(body) {
        assert_eq!(nonce.to_be_bytes().as_slice(), body);
    }
});
