use proptest::prelude::*;

use super::*;

fn room(byte: u8) -> RoomId {
    Random16([byte; 16])
}

fn all_records() -> Vec<Control> {
    vec![
        Control::Register {
            token: RendezvousToken([7; 32]),
            client_nonce: room(1),
            ttl_seconds: 120,
        },
        Control::Registered {
            room: room(2),
            client_nonce: room(1),
            expires_in: 30,
        },
        Control::PeerReady {
            room: room(2),
            peer_nonce: room(3),
        },
        Control::Candidates {
            room: room(2),
            candidates: vec![
                Candidate(SocketAddr::from(([198, 51, 100, 7], 4433))),
                Candidate(SocketAddr::from(([0x2001, 0xdb8, 0, 0, 0, 0, 0, 1], 443))),
            ],
        },
        Control::Candidates {
            room: room(2),
            candidates: Vec::new(),
        },
        Control::Punch {
            room: room(2),
            delay_ms: 2000,
            punch_nonce: room(4),
        },
        Control::Forward { room: room(2) },
        Control::ForwardReady { room: room(2) },
        Control::RelayClose {
            room: Some(room(2)),
            code: CloseCode::Quota,
        },
        Control::RelayClose {
            room: None,
            code: CloseCode::Full,
        },
    ]
}

#[test]
fn every_record_round_trips_with_its_exact_size() -> Result<(), DecodeError> {
    // Envelope sizes: length field, type, and the §10 body totals.
    let sizes = [
        2 + 1 + 52,
        2 + 1 + 34,
        2 + 1 + 32,
        2 + 1 + 17 + 2 * 19,
        2 + 1 + 17,
        2 + 1 + 34,
        2 + 1 + 16,
        2 + 1 + 16,
        2 + 1 + 18,
        2 + 1 + 18,
    ];
    for (record, size) in all_records().into_iter().zip(sizes) {
        let bytes = record.encode()?;
        assert_eq!(bytes.len(), size, "{record:?}");
        assert_eq!(Control::split(&bytes)?, Some((record, size)));
        // Incomplete input waits for more.
        assert_eq!(Control::split(&bytes[..size - 1])?, None);
    }
    Ok(())
}

#[test]
fn a_register_is_laid_out_as_specified() -> Result<(), DecodeError> {
    let bytes = Control::Register {
        token: RendezvousToken([0xaa; 32]),
        client_nonce: room(0xbb),
        ttl_seconds: 100,
    }
    .encode()?;
    let mut expected = vec![0, 53, 0x01, 0, 1];
    expected.extend_from_slice(&[0xaa; 32]);
    expected.extend_from_slice(&[0xbb; 16]);
    expected.extend_from_slice(&100_u16.to_be_bytes());
    assert_eq!(bytes, expected);
    Ok(())
}

#[test]
fn malformed_records_are_refused() {
    let register = |version: u16, ttl: u16| {
        let mut body = version.to_be_bytes().to_vec();
        body.extend_from_slice(&[7; 32]);
        body.extend_from_slice(&[1; 16]);
        body.extend_from_slice(&ttl.to_be_bytes());
        Control::decode(0x01, &body)
    };
    assert_eq!(register(2, 10), Err(DecodeError::Version));
    assert_eq!(register(1, 0), Err(DecodeError::Range));
    assert_eq!(register(1, 121), Err(DecodeError::Range));
    assert!(register(1, 1).is_ok());
    // Zero tokens, nonces, and rooms.
    let mut zero_token = 1_u16.to_be_bytes().to_vec();
    zero_token.extend_from_slice(&[0; 32]);
    zero_token.extend_from_slice(&[1; 16]);
    zero_token.extend_from_slice(&10_u16.to_be_bytes());
    assert_eq!(
        Control::decode(0x01, &zero_token),
        Err(DecodeError::ZeroIdentifier)
    );
    assert_eq!(
        Control::decode(0x06, &[0; 16]),
        Err(DecodeError::ZeroIdentifier)
    );
    // Wrong body sizes, reserved types, and envelope lengths.
    assert_eq!(Control::decode(0x07, &[1; 15]), Err(DecodeError::Length));
    assert_eq!(Control::decode(0x07, &[1; 17]), Err(DecodeError::Length));
    for kind in [0x00, 0x09, 0xff] {
        assert_eq!(Control::decode(kind, &[]), Err(DecodeError::UnknownEnum));
    }
    assert_eq!(Control::split(&[0, 0, 1]), Err(DecodeError::Length));
    assert_eq!(Control::split(&[0x08, 0x01]), Err(DecodeError::Length));
    // Expiry, delay, and close code ranges.
    let mut registered = [1; 34];
    registered[32..].copy_from_slice(&0_u16.to_be_bytes());
    assert_eq!(Control::decode(0x02, &registered), Err(DecodeError::Range));
    let mut punch = [1; 34];
    punch[16..18].copy_from_slice(&2001_u16.to_be_bytes());
    assert_eq!(Control::decode(0x05, &punch), Err(DecodeError::Range));
    // Registered expiry above the room lifetime.
    let mut long = [1; 34];
    long[32..].copy_from_slice(&121_u16.to_be_bytes());
    assert_eq!(Control::decode(0x02, &long), Err(DecodeError::Range));
    // Zero rooms and nonces, wherever they are random.
    let zeroed = |kind: u8, len: usize, zero: core::ops::Range<usize>| {
        let mut body = vec![1; len];
        if kind == 0x02 {
            // A valid expiry, so only the zero field is wrong.
            body[32..].copy_from_slice(&30_u16.to_be_bytes());
        }
        body[zero].fill(0);
        Control::decode(kind, &body)
    };
    for (kind, len, zero) in [
        (0x02, 34, 0..16),
        (0x02, 34, 16..32),
        (0x03, 32, 0..16),
        (0x03, 32, 16..32),
        (0x05, 34, 0..16),
        (0x05, 34, 18..34),
    ] {
        assert_eq!(
            zeroed(kind, len, zero.clone()),
            Err(DecodeError::ZeroIdentifier),
            "{kind:#x} {zero:?}"
        );
    }
    let mut zero_nonce = 1_u16.to_be_bytes().to_vec();
    zero_nonce.extend_from_slice(&[7; 32]);
    zero_nonce.extend_from_slice(&[0; 16]);
    zero_nonce.extend_from_slice(&10_u16.to_be_bytes());
    assert_eq!(
        Control::decode(0x01, &zero_nonce),
        Err(DecodeError::ZeroIdentifier)
    );
    let mut close = [0; 18];
    close[16..].copy_from_slice(&6_u16.to_be_bytes());
    assert_eq!(Control::decode(0x08, &close), Err(DecodeError::UnknownEnum));
}

#[test]
fn candidates_are_bounded_exact_and_distinct() {
    let candidate = |family: u8, last: u8, port: u16| {
        let mut record = vec![family];
        let mut address = [0_u8; 16];
        address[0] = 10;
        address[3] = last;
        record.extend_from_slice(&address);
        record.extend_from_slice(&port.to_be_bytes());
        record
    };
    let body = |records: &[Vec<u8>], count: u8| {
        let mut body = vec![1; 16];
        body.push(count);
        for record in records {
            body.extend_from_slice(record);
        }
        body
    };
    let four: Vec<Vec<u8>> = (1..=4).map(|n| candidate(4, n, 1000)).collect();
    assert!(Control::decode(0x04, &body(&four, 4)).is_ok());
    let five: Vec<Vec<u8>> = (1..=5).map(|n| candidate(4, n, 1000)).collect();
    assert_eq!(
        Control::decode(0x04, &body(&five, 5)),
        Err(DecodeError::Range)
    );
    // The count must match the records.
    assert_eq!(
        Control::decode(0x04, &body(&four, 3)),
        Err(DecodeError::Length)
    );
    // Duplicates, port 0, an unknown family, IPv4 padding.
    let twice = [candidate(4, 1, 1000), candidate(4, 1, 1000)];
    assert_eq!(
        Control::decode(0x04, &body(&twice, 2)),
        Err(DecodeError::Range)
    );
    assert_eq!(
        Control::decode(0x04, &body(&[candidate(4, 1, 0)], 1)),
        Err(DecodeError::Range)
    );
    assert_eq!(
        Control::decode(0x04, &body(&[candidate(5, 1, 1)], 1)),
        Err(DecodeError::UnknownEnum)
    );
    let mut padded = candidate(4, 1, 1);
    padded[10] = 1;
    assert_eq!(
        Control::decode(0x04, &body(&[padded], 1)),
        Err(DecodeError::Reserved)
    );
}

#[test]
fn records_that_would_not_decode_are_never_encoded() {
    let too_many = Control::Candidates {
        room: room(1),
        candidates: (1..=5)
            .map(|n| Candidate(SocketAddr::from(([10, 0, 0, n], 1))))
            .collect(),
    };
    assert_eq!(too_many.encode(), Err(DecodeError::Range));
    let long_ttl = Control::Register {
        token: RendezvousToken([1; 32]),
        client_nonce: room(1),
        ttl_seconds: 121,
    };
    assert_eq!(long_ttl.encode(), Err(DecodeError::Range));
}

#[test]
fn tokens_never_reach_debug_output() {
    let shown = format!(
        "{:?}",
        Control::Register {
            token: RendezvousToken([0xab; 32]),
            client_nonce: room(1),
            ttl_seconds: 1,
        }
    );
    assert!(!shown.contains("171"), "{shown}");
}

proptest! {
    #[test]
    fn arbitrary_input_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..2100)) {
        if let Ok(Some((control, used))) = Control::split(&bytes) {
            prop_assert!(used <= bytes.len());
            prop_assert_eq!(control.encode().ok(), Some(bytes[..used].to_vec()));
        }
    }
}
