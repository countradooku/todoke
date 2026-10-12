//! RFC 9285 Base45, as used by the QR text (PROTOCOL §3.1).
//!
//! An encoding, not a cryptographic primitive. It is implemented here rather
//! than taken from the `base45` crate so that decoding writes straight into
//! a caller-owned (zeroizing) buffer with no intermediate allocation of the
//! secret-bearing payload, and so that every non-canonical form is rejected:
//! a three-character group above 65535 and a two-character group above 255
//! (RFC 9285 §4). Tests cross-check it against the `base45` crate and the
//! RFC's examples.

/// The 45-character alphabet of RFC 9285 §4, in value order. The space is
/// significant.
const ALPHABET: &[u8; 45] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ $%*+-./:";

/// The input is not canonical RFC 9285 Base45. Carries no detail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Base45Error;

/// The encoded length of `n` bytes: three characters per pair, two for a
/// trailing single byte.
pub(crate) const fn encoded_len(n: usize) -> usize {
    n / 2 * 3 + (n % 2) * 2
}

/// Appends the encoding of `input` to `out`.
pub(crate) fn encode_into(input: &[u8], out: &mut String) {
    out.reserve(encoded_len(input.len()));
    let (pairs, remainder) = input.as_chunks::<2>();
    for pair in pairs {
        push_digits(u32::from(u16::from_be_bytes(*pair)), 3, out);
    }
    if let [last] = remainder {
        push_digits(u32::from(*last), 2, out);
    }
}

fn push_digits(mut value: u32, count: usize, out: &mut String) {
    for _ in 0..count {
        // value % 45 < 45 by construction.
        let digit = (value % 45) as usize;
        out.push(char::from(ALPHABET[digit]));
        value /= 45;
    }
}

fn digit(character: u8) -> Result<u32, Base45Error> {
    ALPHABET
        .iter()
        .position(|&candidate| candidate == character)
        .and_then(|position| u32::try_from(position).ok())
        .ok_or(Base45Error)
}

/// Decodes `text` into `out`, whose length must be exactly the decoded
/// length: `text.len()` must equal [`encoded_len`]`(out.len())`. On error
/// `out` may hold partial output; callers wipe or discard it.
pub(crate) fn decode_into(text: &[u8], out: &mut [u8]) -> Result<(), Base45Error> {
    if text.len() != encoded_len(out.len()) {
        return Err(Base45Error);
    }
    let (groups, text_rest) = text.as_chunks::<3>();
    let (pairs, out_rest) = out.as_chunks_mut::<2>();
    for (&[first, second, third], pair) in groups.iter().zip(pairs.iter_mut()) {
        let value = digit(first)? + digit(second)? * 45 + digit(third)? * 45 * 45;
        *pair = u16::try_from(value).map_err(|_| Base45Error)?.to_be_bytes();
    }
    match (text_rest, out_rest) {
        ([], []) => Ok(()),
        ([first, second], [last]) => {
            let value = digit(*first)? + digit(*second)? * 45;
            *last = u8::try_from(value).map_err(|_| Base45Error)?;
            Ok(())
        }
        _ => Err(Base45Error),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn decode(text: &str) -> Result<Vec<u8>, Base45Error> {
        // The decoded length follows from the text length when it is valid.
        let n = text.len() / 3 * 2 + usize::from(text.len() % 3 == 2);
        let mut out = vec![0; n];
        decode_into(text.as_bytes(), &mut out)?;
        Ok(out)
    }

    fn encode(input: &[u8]) -> String {
        let mut out = String::new();
        encode_into(input, &mut out);
        out
    }

    /// RFC 9285 §4.3 and §4.4 examples.
    #[test]
    fn rfc_9285_examples() -> Result<(), Base45Error> {
        for (plain, text) in [
            (&b"AB"[..], "BB8"),
            (b"Hello!!", "%69 VD92EX0"),
            (b"base-45", "UJCLQE7W581"),
            (b"ietf!", "QED8WEX0"),
        ] {
            assert_eq!(encode(plain), text);
            assert_eq!(decode(text)?, plain);
        }
        assert_eq!(encode(&[]), "");
        assert_eq!(decode("")?, Vec::<u8>::new());
        Ok(())
    }

    /// RFC 9285 §4: "GGW" is 65536 and must be rejected; so must a
    /// two-character group above 255 and any character outside the
    /// alphabet, including lowercase letters.
    #[test]
    fn non_canonical_input_is_rejected() {
        assert_eq!(decode("GGW"), Err(Base45Error));
        assert_eq!(decode("FGW").map(|bytes| bytes.len()), Ok(2));
        assert_eq!(decode(":::"), Err(Base45Error));
        assert_eq!(decode("V5"), Err(Base45Error));
        assert_eq!(decode("U5"), Ok(vec![255]));
        for bad in ["bb8", "BB\u{0}", "BB#", "BB=", "BB\n", "BB_"] {
            assert_eq!(decode(bad), Err(Base45Error), "{bad:?}");
        }
        let mut out = [0; 2];
        assert_eq!(decode_into(b"BB", &mut out), Err(Base45Error));
        assert_eq!(decode_into(b"BB8B", &mut out), Err(Base45Error));
        let mut odd = [0; 1];
        assert_eq!(decode_into(b"BB8", &mut odd), Err(Base45Error));
    }

    #[test]
    fn lengths() {
        assert_eq!(encoded_len(0), 0);
        assert_eq!(encoded_len(1), 2);
        assert_eq!(encoded_len(2), 3);
        assert_eq!(encoded_len(1312), 1968);
    }

    proptest! {
        /// Matches the independent `base45` crate and round-trips.
        #[test]
        fn matches_reference_crate(input in proptest::collection::vec(any::<u8>(), 0..200)) {
            let text = encode(&input);
            prop_assert_eq!(&text, &::base45::encode(&input));
            prop_assert_eq!(decode(&text), Ok(input));
        }

        /// Anything accepted is canonical: re-encoding reproduces it.
        #[test]
        fn accepted_text_is_canonical(text in "[0-9A-Z $%*+./:-]{0,30}") {
            if let Ok(bytes) = decode(&text) {
                prop_assert_eq!(encode(&bytes), text);
            }
        }
    }
}
