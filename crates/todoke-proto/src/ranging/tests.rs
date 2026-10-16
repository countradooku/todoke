use super::*;

fn start() -> RangingStart {
    RangingStart {
        session_id: 0x0102_0304,
        controller: 0xabcd,
        channel: 9,
        preamble: 10,
        config: CONFIG_PROVISIONED_DS_TWR,
        sts_key: Zeroizing::new([7; STS_KEY_LEN]),
    }
}

#[test]
fn records_round_trip() -> Result<(), DecodeError> {
    let ready = RangingReady {
        configs: CONFIG_PROVISIONED_DS_TWR,
    };
    assert_eq!(ready.encode(), [1]);
    assert_eq!(RangingReady::decode(&ready.encode())?, ready);
    let accept = RangingAccept {
        session_id: 0x0102_0304,
        controlee: 0x1234,
    };
    assert_eq!(accept.encode(), [1, 2, 3, 4, 0x12, 0x34]);
    assert_eq!(RangingAccept::decode(&accept.encode())?, accept);
    let body = start().encode();
    assert_eq!(body.len(), START_LEN);
    assert_eq!(&body[..9], &[1, 2, 3, 4, 0xab, 0xcd, 9, 10, 1]);
    assert_eq!(RangingStart::decode(&body)?, start());
    let stop = RangingStop { session_id: 9 };
    assert_eq!(RangingStop::decode(&stop.encode())?, stop);
    Ok(())
}

/// Every field outside its limits is refused, as is any other length.
#[test]
fn fields_outside_their_limits_are_refused() {
    for address in [[0, 0], [0xff, 0xff]] {
        assert_eq!(
            RangingAccept::decode(&[1, 2, 3, 4, address[0], address[1]]),
            Err(DecodeError::Range)
        );
    }
    assert_eq!(
        RangingAccept::decode(&[0, 0, 0, 0, 1, 2]),
        Err(DecodeError::ZeroIdentifier)
    );
    assert_eq!(
        RangingAccept::decode(&[1, 2, 3, 4, 5]),
        Err(DecodeError::Length)
    );
    for configs in [0, 0b10, 0b11, 0x80] {
        assert_eq!(RangingReady::decode(&[configs]), Err(DecodeError::Reserved));
    }
    assert_eq!(RangingReady::decode(&[1, 2]), Err(DecodeError::Length));
    assert_eq!(RangingReady::decode(&[]), Err(DecodeError::Length));
    let edit = |at: usize, value: u8| {
        let mut body = start().encode().to_vec();
        body[at] = value;
        RangingStart::decode(&body)
    };
    let zero = {
        let mut body = start().encode().to_vec();
        body[..4].fill(0);
        RangingStart::decode(&body)
    };
    assert_eq!(zero, Err(DecodeError::ZeroIdentifier));
    for channel in [0, 4, 6, 8, 10] {
        assert_eq!(
            edit(6, channel),
            Err(DecodeError::Range),
            "channel {channel}"
        );
    }
    for preamble in [0, 8, 13, 24, 33] {
        assert_eq!(
            edit(7, preamble),
            Err(DecodeError::Range),
            "preamble {preamble}"
        );
    }
    for config in [0, 0b10, 0b11] {
        assert_eq!(
            edit(8, config),
            Err(DecodeError::Reserved),
            "config {config}"
        );
    }
    for controller in [[0, 0], [0xff, 0xff]] {
        let mut body = start().encode().to_vec();
        body[4..6].copy_from_slice(&controller);
        assert_eq!(RangingStart::decode(&body), Err(DecodeError::Range));
    }
    assert!(RangingStart::decode(&start().encode()[..START_LEN - 1]).is_err());
    assert_eq!(
        RangingStop::decode(&[0; 4]),
        Err(DecodeError::ZeroIdentifier)
    );
    assert_eq!(RangingStop::decode(&[0; 5]), Err(DecodeError::Length));
}

#[test]
fn the_key_is_never_printed() {
    let printed = format!("{:?}", start());
    assert!(!printed.contains("7, 7"));
}
