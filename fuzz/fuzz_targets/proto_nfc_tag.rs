//! The NFC carrier of QR pairing (PROTOCOL §3.1.1) on arbitrary bytes. With
//! a first byte of 0, the rest is a received NDEF message: an accepted one
//! must be exactly the pairing message of its text. Otherwise the rest is a
//! reader's command APDUs, each prefixed by its length, sent to a tag
//! serving a fixed QR text: every response is at most 255 bytes of data
//! and a status word, and data comes only with success.
#![no_main]

use libfuzzer_sys::fuzz_target;
use todoke_proto::nfc::{QR_TEXT_LEN, Type4Tag, pairing_message, pairing_text};

fuzz_target!(|data: &[u8]| {
    let Some((&kind, rest)) = data.split_first() else {
        return;
    };
    if kind == 0 {
        if let Ok(text) = pairing_text(rest) {
            let again = pairing_message(&text).expect("an accepted text makes a message");
            assert_eq!(again.as_slice(), rest);
        }
        return;
    }
    let mut text = String::from("TODOKE:");
    text.push_str(&"0".repeat(QR_TEXT_LEN - 7));
    let mut tag = Type4Tag::new(&text).expect("a well-shaped text");
    let mut commands = rest;
    while let Some((&length, tail)) = commands.split_first() {
        let Some((apdu, after)) = tail.split_at_checked(usize::from(length)) else {
            break;
        };
        commands = after;
        let response = tag.respond(apdu);
        assert!(response.len() >= 2 && response.len() <= 255 + 2);
        let status = &response[response.len() - 2..];
        if status != [0x90, 0x00] {
            assert_eq!(response.len(), 2);
        }
    }
});
