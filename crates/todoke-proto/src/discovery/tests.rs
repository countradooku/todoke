use super::*;
use proptest::prelude::*;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const TOKEN: [u8; 8] = [0x3a, 0xbe, 0x80, 0x6d, 0x9b, 0x82, 0x1c, 0xfc];

fn fixture() -> Result<serde_json::Value, Box<dyn std::error::Error>> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../spec/test-vectors/discovery-token.json");
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}

fn record() -> Result<DiscoveryRecord, DecodeError> {
    DiscoveryRecord::new(DiscoveryMode::Paired, Epoch::new(1_955_555)?, TOKEN)
}

#[test]
fn spec_lengths() {
    assert_eq!(DISCOVERY_RECORD_LEN, 1 + 1 + 8 + 8 + 1);
    assert_eq!(MDNS_TXT_LEN, 41);
    assert_eq!(MDNS_SERVICE, "_todoke._tcp.local.");
}

/// Every record and TXT string of the committed chain decodes and
/// re-encodes byte for byte.
#[test]
fn fixture_records_and_txt_strings_round_trip() -> TestResult {
    let fixture = fixture()?;
    let epochs = fixture
        .pointer("/derived_chain/epochs")
        .and_then(serde_json::Value::as_array)
        .ok_or("epochs")?;
    assert_eq!(epochs.len(), 3);
    for entry in epochs {
        let field = |name: &str| {
            entry
                .get(name)
                .and_then(serde_json::Value::as_str)
                .ok_or("field")
        };
        let bytes = hex::decode(field("discovery_record_hex")?)?;
        let decoded = DiscoveryRecord::decode(&bytes)?;
        assert_eq!(decoded.encode().as_slice(), bytes.as_slice());
        assert_eq!(decoded.mode(), DiscoveryMode::Paired);
        let epoch = entry
            .get("epoch")
            .and_then(serde_json::Value::as_u64)
            .ok_or("epoch")?;
        assert_eq!(decoded.epoch().get(), epoch);
        assert_eq!(
            decoded.token().as_slice(),
            hex::decode(field("token_hex")?)?
        );
        let txt = field("mdns_txt")?;
        assert_eq!(decoded.to_txt(), txt);
        assert_eq!(DiscoveryRecord::from_txt(txt.as_bytes())?, decoded);
    }
    Ok(())
}

#[test]
fn layout() -> TestResult {
    let encoded = record()?.encode();
    assert_eq!(encoded[0], 1);
    assert_eq!(encoded[1], 0);
    assert_eq!(encoded[2..10], 1_955_555_u64.to_be_bytes());
    assert_eq!(encoded[10..18], TOKEN);
    assert_eq!(encoded[18], 0);
    let stranger = DiscoveryRecord::new(DiscoveryMode::Stranger, Epoch::new(0)?, TOKEN)?;
    assert_eq!(stranger.encode()[1], 1);
    Ok(())
}

/// Each malformed field is refused with its own error.
#[test]
fn malformed_records_are_refused() -> TestResult {
    let good = record()?.encode();
    let with = |index: usize, value: u8| {
        let mut bytes = good;
        bytes[index] = value;
        DiscoveryRecord::decode(&bytes)
    };
    assert_eq!(with(0, 0), Err(DecodeError::Version));
    assert_eq!(with(0, 2), Err(DecodeError::Version));
    assert_eq!(with(1, 2), Err(DecodeError::UnknownEnum));
    assert_eq!(with(1, 0xff), Err(DecodeError::UnknownEnum));
    assert_eq!(with(18, 1), Err(DecodeError::Reserved));
    let mut zero_token = good;
    zero_token[10..18].fill(0);
    assert_eq!(
        DiscoveryRecord::decode(&zero_token),
        Err(DecodeError::ZeroIdentifier)
    );
    assert_eq!(
        DiscoveryRecord::decode(&good[..18]),
        Err(DecodeError::Length)
    );
    let mut long = good.to_vec();
    long.push(0);
    assert_eq!(DiscoveryRecord::decode(&long), Err(DecodeError::Length));
    assert_eq!(DiscoveryRecord::decode(&[]), Err(DecodeError::Length));
    Ok(())
}

/// The last epoch of the protocol time range is the largest accepted.
#[test]
fn epochs_stay_in_the_protocol_time_range() -> TestResult {
    let last = MAX_UNIX_TIME / EPOCH_SECONDS;
    assert_eq!(Epoch::new(last)?.get(), last);
    assert_eq!(Epoch::new(last + 1), Err(DecodeError::Range));
    assert_eq!(Epoch::new(u64::MAX), Err(DecodeError::Range));
    let mut bytes = record()?.encode();
    bytes[2..10].copy_from_slice(&(last + 1).to_be_bytes());
    assert_eq!(DiscoveryRecord::decode(&bytes), Err(DecodeError::Range));
    assert_eq!(
        Epoch::of(UnixTime::new(MAX_UNIX_TIME).ok_or("time")?).get(),
        last
    );
    assert_eq!(Epoch::new(last)?.next_boundary(), None);
    assert_eq!(
        Epoch::new(1)?.next_boundary(),
        Some(UnixTime::new(1800).ok_or("time")?)
    );
    Ok(())
}

#[test]
fn adjacent_epochs_are_bounded_at_both_ends() -> TestResult {
    let collect = |epoch: u64| -> Result<Vec<u64>, DecodeError> {
        Ok(Epoch::new(epoch)?.adjacent().map(Epoch::get).collect())
    };
    assert_eq!(collect(0)?, vec![0, 1]);
    assert_eq!(collect(5)?, vec![4, 5, 6]);
    let last = MAX_UNIX_TIME / EPOCH_SECONDS;
    assert_eq!(collect(last)?, vec![last - 1, last]);
    Ok(())
}

/// The TXT string is exact: key, length, and lowercase hex only.
#[test]
fn malformed_txt_strings_are_refused() -> TestResult {
    let good = record()?.to_txt();
    assert_eq!(good.len(), MDNS_TXT_LEN);
    assert_eq!(DiscoveryRecord::from_txt(good.as_bytes())?, record()?);
    let upper = format!("v1={}", record()?.txt_value().to_uppercase());
    assert_eq!(
        DiscoveryRecord::from_txt(upper.as_bytes()),
        Err(DecodeError::Reserved)
    );
    for bad in [
        good.replacen("v1=", "v2=", 1),
        good.replacen("v1=", "V1=", 1),
        good.replacen("v1=", "v1:", 1),
        format!("{good}0"),
        good[..good.len() - 1].to_owned(),
        format!(" {}", &good[1..]),
    ] {
        assert!(DiscoveryRecord::from_txt(bad.as_bytes()).is_err(), "{bad}");
    }
    let mut non_hex = good.into_bytes();
    non_hex[10] = b'g';
    assert_eq!(
        DiscoveryRecord::from_txt(&non_hex),
        Err(DecodeError::Reserved)
    );
    Ok(())
}

#[test]
fn instance_labels_are_sixteen_lowercase_hex_characters() -> TestResult {
    let label = InstanceLabel::from_random([0x0a, 0xb1, 0, 0, 0, 0, 0, 0xff])?;
    assert_eq!(label.as_str(), "0ab10000000000ff");
    assert_eq!(InstanceLabel::parse(label.as_str())?, label);
    assert_eq!(
        InstanceLabel::from_random([0; 8]),
        Err(DecodeError::ZeroIdentifier)
    );
    for bad in [
        "0AB10000000000FF",
        "0ab10000000000f",
        "0ab10000000000ff0",
        "my-macbook-pro.l",
        "0000000000000000",
        "",
    ] {
        assert!(InstanceLabel::parse(bad).is_err(), "{bad}");
    }
    Ok(())
}

#[test]
fn debug_output_hides_tokens_and_labels() -> TestResult {
    let shown = format!("{:?}", record()?);
    assert!(!shown.contains("3abe806d9b821cfc"));
    assert!(!shown.contains(&format!("{TOKEN:?}")));
    let label = InstanceLabel::from_random([0x5c; 8])?;
    assert!(!format!("{label:?}").contains(label.as_str()));
    Ok(())
}

/// R3: every byte value at every hex position of a TXT string and an
/// instance label: only `0-9` and `a-f` are accepted.
#[test]
fn only_lowercase_hex_digits_are_accepted() -> TestResult {
    let good = record()?.to_txt().into_bytes();
    let label = InstanceLabel::from_random([0x5c; 8])?;
    for byte in 0..=u8::MAX {
        let hex = byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte);
        for position in 3..good.len() {
            let mut txt = good.clone();
            txt[position] = byte;
            if !hex {
                assert_eq!(
                    DiscoveryRecord::from_txt(&txt),
                    Err(DecodeError::Reserved),
                    "{byte} at {position}"
                );
            }
        }
        let value = char::from(byte)
            .to_digit(16)
            .and_then(|v| u8::try_from(v).ok());
        assert_eq!(nibble(byte).ok(), value.filter(|_| hex), "{byte}");
        for position in 0..INSTANCE_LABEL_LEN {
            let mut text = label.as_str().as_bytes().to_vec();
            text[position] = byte;
            if let Ok(text) = core::str::from_utf8(&text) {
                assert_eq!(
                    InstanceLabel::parse(text).is_ok(),
                    hex,
                    "{byte} at {position}"
                );
            }
        }
    }
    Ok(())
}

proptest! {
    #[test]
    fn records_round_trip(
        stranger in any::<bool>(),
        epoch in 0..=MAX_UNIX_TIME / EPOCH_SECONDS,
        token in any::<[u8; 8]>(),
    ) {
        let mode = if stranger { DiscoveryMode::Stranger } else { DiscoveryMode::Paired };
        let Ok(record) = DiscoveryRecord::new(mode, Epoch::new(epoch)?, token) else {
            prop_assert_eq!(token, [0; 8]);
            return Ok(());
        };
        prop_assert_eq!(DiscoveryRecord::decode(&record.encode())?, record);
        prop_assert_eq!(DiscoveryRecord::from_txt(record.to_txt().as_bytes())?, record);
    }

    /// Arbitrary bytes never panic, and whatever decodes re-encodes to the
    /// same bytes.
    #[test]
    fn arbitrary_input_is_canonical_or_refused(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
        if let Ok(record) = DiscoveryRecord::decode(&bytes) {
            prop_assert_eq!(record.encode().to_vec(), bytes.clone());
        }
        if let Ok(record) = DiscoveryRecord::from_txt(&bytes) {
            prop_assert_eq!(record.to_txt().into_bytes(), bytes.clone());
        }
        if let Ok(text) = core::str::from_utf8(&bytes)
            && let Ok(label) = InstanceLabel::parse(text)
        {
            prop_assert_eq!(label.as_str(), text);
        }
    }
}
