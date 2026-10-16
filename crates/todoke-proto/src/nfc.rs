//! The NFC carrier of QR pairing (PROTOCOL §3.1.1): the exact NDEF message
//! that holds the QR text, and the read-only NFC Forum Type 4 Tag a
//! displayer emulates to serve it (host card emulation).
//!
//! The message is one long record (TNF media type, no ID) of type
//! `application/vnd.todoke.pair` whose payload is exactly the QR text. The
//! tag answers only what a reader needs: SELECT of the NDEF application,
//! SELECT of its capability container and NDEF file, and READ BINARY
//! within them; anything else is refused. Every read is bounded by the file
//! it reads. The payload is the QR's secret: it is kept in zeroizing
//! memory.

use zeroize::Zeroizing;

/// The record type (§3.1.1).
pub const RECORD_TYPE: &[u8] = b"application/vnd.todoke.pair";
/// The QR text's length (§3.1).
pub const QR_TEXT_LEN: usize = 1975;
/// The QR text's prefix.
const PREFIX: &[u8] = b"TODOKE:";
/// Header: message begin, message end, long record, TNF 2 (media type).
const HEADER: u8 = 0x80 | 0x40 | 0x02;
/// The message's length: header, type length, 4-byte payload length, type,
/// payload.
pub const MESSAGE_LEN: usize = 1 + 1 + 4 + RECORD_TYPE.len() + QR_TEXT_LEN;

/// The NDEF application (NFC Forum Type 4 Tag, version 2).
const NDEF_AID: [u8; 7] = [0xd2, 0x76, 0x00, 0x00, 0x85, 0x01, 0x01];
const CC_FILE: [u8; 2] = [0xe1, 0x03];
const NDEF_FILE: [u8; 2] = [0xe1, 0x04];
/// The most a reader may read at once.
const MAX_READ: u16 = 0xff;

/// Status words.
const OK: [u8; 2] = [0x90, 0x00];
const NOT_FOUND: [u8; 2] = [0x6a, 0x82];
const WRONG_LENGTH: [u8; 2] = [0x67, 0x00];
const WRONG_OFFSET: [u8; 2] = [0x6b, 0x00];
const NOT_SUPPORTED: [u8; 2] = [0x6d, 0x00];
const NOT_ALLOWED: [u8; 2] = [0x69, 0x86];

/// Why a message is not a pairing message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NfcError {
    /// Not exactly one record of the pairing type with a QR text's length.
    NotPairing,
}

impl core::fmt::Display for NfcError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("not a todoke pairing message")
    }
}

impl core::error::Error for NfcError {}

/// The NDEF message for `qr_text`.
///
/// # Errors
///
/// [`NfcError::NotPairing`] if `qr_text` does not have the QR text's
/// length and prefix.
pub fn pairing_message(qr_text: &str) -> Result<Zeroizing<Vec<u8>>, NfcError> {
    let text = qr_text.as_bytes();
    if text.len() != QR_TEXT_LEN || !text.starts_with(PREFIX) || !text.is_ascii() {
        return Err(NfcError::NotPairing);
    }
    let mut message = Zeroizing::new(Vec::with_capacity(MESSAGE_LEN));
    message.push(HEADER);
    message.push(u8::try_from(RECORD_TYPE.len()).map_err(|_| NfcError::NotPairing)?);
    message.extend_from_slice(
        &u32::try_from(QR_TEXT_LEN)
            .map_err(|_| NfcError::NotPairing)?
            .to_be_bytes(),
    );
    message.extend_from_slice(RECORD_TYPE);
    message.extend_from_slice(text);
    Ok(message)
}

/// The QR text in `message`, if it is exactly a pairing message (§3.1.1);
/// the caller still validates it as QR text.
///
/// # Errors
///
/// [`NfcError::NotPairing`] for anything else.
pub fn pairing_text(message: &[u8]) -> Result<Zeroizing<String>, NfcError> {
    let not = || NfcError::NotPairing;
    if message.len() != MESSAGE_LEN {
        return Err(not());
    }
    let (&header, rest) = message.split_first().ok_or_else(not)?;
    let (&type_len, rest) = rest.split_first().ok_or_else(not)?;
    let (length, rest) = rest.split_at_checked(4).ok_or_else(not)?;
    let (record_type, payload) = rest.split_at_checked(RECORD_TYPE.len()).ok_or_else(not)?;
    let length = u32::from_be_bytes(length.try_into().map_err(|_| not())?);
    if header != HEADER
        || usize::from(type_len) != RECORD_TYPE.len()
        || record_type != RECORD_TYPE
        || usize::try_from(length).ok() != Some(QR_TEXT_LEN)
        || !payload.starts_with(PREFIX)
        || !payload.is_ascii()
    {
        return Err(not());
    }
    let text = core::str::from_utf8(payload).map_err(|_| not())?;
    Ok(Zeroizing::new(text.to_owned()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Selected {
    Nothing,
    Application,
    Container,
    Ndef,
}

/// A read-only NFC Forum Type 4 Tag serving one pairing message.
pub struct Type4Tag {
    /// The NDEF file: its 2-byte length, then the message.
    ndef: Zeroizing<Vec<u8>>,
    selected: Selected,
}

impl core::fmt::Debug for Type4Tag {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Type4Tag")
            .field("selected", &self.selected)
            .finish_non_exhaustive()
    }
}

impl Type4Tag {
    /// A tag serving the pairing message of `qr_text`.
    ///
    /// # Errors
    ///
    /// As [`pairing_message`].
    pub fn new(qr_text: &str) -> Result<Self, NfcError> {
        let message = pairing_message(qr_text)?;
        let length = u16::try_from(message.len()).map_err(|_| NfcError::NotPairing)?;
        let mut ndef = Zeroizing::new(Vec::with_capacity(message.len() + 2));
        ndef.extend_from_slice(&length.to_be_bytes());
        ndef.extend_from_slice(&message);
        Ok(Self {
            ndef,
            selected: Selected::Nothing,
        })
    }

    /// The capability container: version 2.0, reads of at most 255 bytes,
    /// no writes, one NDEF file (E104) of the message's size, read-only.
    fn container(&self) -> [u8; 15] {
        let [size_high, size_low] = u16::try_from(self.ndef.len())
            .unwrap_or(u16::MAX)
            .to_be_bytes();
        let [mle_high, mle_low] = MAX_READ.to_be_bytes();
        [
            0x00,
            0x0f, // CC length
            0x20, // mapping version 2.0
            mle_high,
            mle_low, // MLe
            0x00,
            0x00, // MLc: no writes
            0x04,
            0x06, // NDEF file control TLV
            NDEF_FILE[0],
            NDEF_FILE[1],
            size_high,
            size_low, // maximum NDEF file size
            0x00,     // read access: granted
            0xff,     // write access: none
        ]
    }

    /// The response to one command APDU (data, then a status word).
    #[must_use]
    pub fn respond(&mut self, apdu: &[u8]) -> Zeroizing<Vec<u8>> {
        let mut out = Zeroizing::new(Vec::new());
        match self.command(apdu, &mut out) {
            Ok(()) => out.extend_from_slice(&OK),
            Err(status) => {
                out.clear();
                out.extend_from_slice(&status);
            }
        }
        out
    }

    fn command(&mut self, apdu: &[u8], out: &mut Vec<u8>) -> Result<(), [u8; 2]> {
        let [class, instruction, p1, p2, rest @ ..] = apdu else {
            return Err(WRONG_LENGTH);
        };
        if *class != 0x00 {
            return Err(NOT_SUPPORTED);
        }
        match instruction {
            // SELECT
            0xa4 => {
                let (&lc, data) = rest.split_first().ok_or(WRONG_LENGTH)?;
                let data = data.get(..usize::from(lc)).ok_or(WRONG_LENGTH)?;
                match (p1, p2, data) {
                    (0x04, 0x00, aid) if aid == NDEF_AID => self.selected = Selected::Application,
                    (0x00, 0x0c, file) if self.selected != Selected::Nothing => {
                        self.selected = match file {
                            f if f == CC_FILE => Selected::Container,
                            f if f == NDEF_FILE => Selected::Ndef,
                            _ => return Err(NOT_FOUND),
                        };
                    }
                    _ => return Err(NOT_FOUND),
                }
                Ok(())
            }
            // READ BINARY
            0xb0 => {
                let offset = usize::from(u16::from_be_bytes([*p1, *p2]));
                let wanted = match rest {
                    [] | [0] => usize::from(MAX_READ),
                    [le] => usize::from(*le),
                    _ => return Err(WRONG_LENGTH),
                };
                let container = self.container();
                let file: &[u8] = match self.selected {
                    Selected::Container => &container,
                    Selected::Ndef => &self.ndef,
                    Selected::Application | Selected::Nothing => return Err(NOT_ALLOWED),
                };
                if offset > file.len() {
                    return Err(WRONG_OFFSET);
                }
                let end = offset
                    .saturating_add(wanted.min(usize::from(MAX_READ)))
                    .min(file.len());
                out.extend_from_slice(&file[offset..end]);
                Ok(())
            }
            // Writes and everything else: refused.
            0xd6 => Err(NOT_ALLOWED),
            _ => Err(NOT_SUPPORTED),
        }
    }
}

#[cfg(test)]
mod tests;
