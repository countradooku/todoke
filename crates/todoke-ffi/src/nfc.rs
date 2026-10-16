//! NFC tap-to-pair (PROTOCOL §3.1.1): the tag a displayer emulates while
//! its QR offer shows. The scanner's side is `Core::pair_scan_nfc`.

#![allow(
    clippy::needless_pass_by_value,
    clippy::must_use_candidate,
    reason = "exported to foreign callers: arguments arrive owned, and must_use means nothing there"
)]

use std::sync::Mutex;

use boltffi::export;
use todoke_proto::nfc::Type4Tag;

/// The read-only NFC Forum Type 4 Tag serving a shown QR offer, for the
/// platform's host card emulation (Android `HostApduService`). It serves
/// the offer's secret text to any reader in range: emulate it only while
/// the offer shows, and only in the foreground.
pub struct NfcTag {
    tag: Mutex<Type4Tag>,
}

impl NfcTag {
    pub(crate) fn new(tag: Type4Tag) -> Self {
        Self {
            tag: Mutex::new(tag),
        }
    }
}

impl core::fmt::Debug for NfcTag {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("NfcTag")
    }
}

#[export]
impl NfcTag {
    /// The response to one command APDU from a reader (data, then the
    /// status word). Never log either: the reads carry the offer.
    pub fn respond(&self, apdu: Vec<u8>) -> Vec<u8> {
        match self.tag.lock() {
            Ok(mut tag) => tag.respond(&apdu).to_vec(),
            // A panic while answering: refuse (status "not allowed").
            Err(_) => vec![0x69, 0x86],
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_reader_gets_the_message_and_nothing_else() -> Result<(), todoke_proto::nfc::NfcError> {
        let text = format!("TODOKE:{}", "A".repeat(todoke_proto::nfc::QR_TEXT_LEN - 7));
        let tag = NfcTag::new(Type4Tag::new(&text)?);
        // An unknown application: not found.
        assert_eq!(tag.respond(vec![0, 0xa4, 4, 0, 1, 0xaa]), [0x6a, 0x82]);
        // Reads before any selection: not allowed.
        assert_eq!(tag.respond(vec![0, 0xb0, 0, 0, 15]), [0x69, 0x86]);
        let mut aid = vec![0, 0xa4, 4, 0, 7];
        aid.extend_from_slice(&[0xd2, 0x76, 0, 0, 0x85, 1, 1]);
        assert_eq!(tag.respond(aid), [0x90, 0]);
        assert_eq!(
            tag.respond(vec![0, 0xa4, 0, 0x0c, 2, 0xe1, 0x04]),
            [0x90, 0]
        );
        let first = tag.respond(vec![0, 0xb0, 0, 0, 2]);
        assert_eq!(first.len(), 4);
        let length = usize::from(u16::from_be_bytes([first[0], first[1]]));
        assert_eq!(length, todoke_proto::nfc::MESSAGE_LEN);
        Ok(())
    }
}
