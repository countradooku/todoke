use super::*;

/// A QR text of the right shape (the content is not checked here).
fn text() -> String {
    let mut text = String::from("TODOKE:");
    text.push_str(&"0".repeat(QR_TEXT_LEN - PREFIX.len()));
    text
}

#[test]
fn the_message_round_trips_and_nothing_else_parses() -> Result<(), NfcError> {
    let message = pairing_message(&text())?;
    assert_eq!(message.len(), MESSAGE_LEN);
    assert_eq!(message[0], 0xc2);
    assert_eq!(message[1], 27);
    assert_eq!(&*pairing_text(&message)?, &text());
    // One byte off anywhere in the framing, a short or long message, or
    // another type: not a pairing message.
    for at in [0, 1, 2, 5, 6, 6 + RECORD_TYPE.len()] {
        let mut changed = message.to_vec();
        changed[at] ^= 0x01;
        assert_eq!(
            pairing_text(&changed),
            Err(NfcError::NotPairing),
            "byte {at}"
        );
    }
    assert!(pairing_text(&message[..MESSAGE_LEN - 1]).is_err());
    let mut longer = message.to_vec();
    longer.push(b'0');
    assert!(pairing_text(&longer).is_err());
    let mut non_ascii = message.to_vec();
    non_ascii[MESSAGE_LEN - 1] = 0xc3;
    assert!(pairing_text(&non_ascii).is_err());
    assert!(pairing_message("TODOKE:short").is_err());
    assert!(pairing_message(&text().replacen("TODOKE", "todoke", 1)).is_err());
    Ok(())
}

fn select(aid: &[u8]) -> Vec<u8> {
    let mut apdu = vec![0x00, 0xa4, 0x04, 0x00, u8::try_from(aid.len()).unwrap_or(0)];
    apdu.extend_from_slice(aid);
    apdu.push(0x00);
    apdu
}

fn select_file(file: [u8; 2]) -> Vec<u8> {
    vec![0x00, 0xa4, 0x00, 0x0c, 0x02, file[0], file[1]]
}

fn read(offset: u16, length: u8) -> Vec<u8> {
    let [high, low] = offset.to_be_bytes();
    vec![0x00, 0xb0, high, low, length]
}

/// A reader's sequence reads the message back exactly; the tag refuses
/// reads before selection, writes, other applications, and reads past the
/// file, and never answers more than 255 bytes.
#[test]
fn a_reader_reads_the_message_and_nothing_more() -> Result<(), NfcError> {
    let mut tag = Type4Tag::new(&text())?;
    assert_eq!(&*tag.respond(&read(0, 15)), &NOT_ALLOWED);
    assert_eq!(&*tag.respond(&select_file(CC_FILE)), &NOT_FOUND);
    assert_eq!(&*tag.respond(&select(&[0xa0, 0, 0, 0, 1])), &NOT_FOUND);
    assert_eq!(&*tag.respond(&select(&NDEF_AID)), &OK);
    assert_eq!(&*tag.respond(&select_file(CC_FILE)), &OK);
    let container = tag.respond(&read(0, 15));
    assert_eq!(container.len(), 17);
    assert_eq!(&container[..3], &[0x00, 0x0f, 0x20]);
    assert_eq!(container[14], 0xff, "write access: none");
    assert_eq!(&*tag.respond(&select_file([0xe1, 0x05])), &NOT_FOUND);
    assert_eq!(&*tag.respond(&select_file(NDEF_FILE)), &OK);
    let head = tag.respond(&read(0, 2));
    let length = usize::from(u16::from_be_bytes([head[0], head[1]]));
    assert_eq!(length, MESSAGE_LEN);
    let mut message = Vec::new();
    let mut offset = 2_u16;
    while usize::from(offset) < length + 2 {
        let chunk = tag.respond(&read(offset, 0));
        assert!(chunk.len() <= 255 + 2);
        assert_eq!(&chunk[chunk.len() - 2..], &OK);
        let data = &chunk[..chunk.len() - 2];
        assert_ne!(data.len(), 0);
        message.extend_from_slice(data);
        offset += u16::try_from(data.len()).unwrap_or(u16::MAX);
    }
    assert_eq!(&*pairing_text(&message)?, &text());
    // Past the end, a write, an unknown instruction, a short APDU.
    assert_eq!(&*tag.respond(&read(4000, 1)), &WRONG_OFFSET);
    assert_eq!(&*tag.respond(&[0x00, 0xd6, 0, 0, 1, 0]), &NOT_ALLOWED);
    assert_eq!(&*tag.respond(&[0x00, 0x88, 0, 0]), &NOT_SUPPORTED);
    assert_eq!(&*tag.respond(&[0x00, 0xa4]), &WRONG_LENGTH);
    assert_eq!(&*tag.respond(&[0x80, 0xb0, 0, 0, 1]), &NOT_SUPPORTED);
    // A SELECT whose length says more than it carries.
    assert_eq!(
        &*tag.respond(&[0x00, 0xa4, 0x04, 0x00, 0x09, 0xd2]),
        &WRONG_LENGTH
    );
    Ok(())
}

#[test]
fn the_tag_never_prints_the_message() -> Result<(), NfcError> {
    let tag = Type4Tag::new(&text())?;
    assert!(!format!("{tag:?}").contains("TODOKE"));
    Ok(())
}
