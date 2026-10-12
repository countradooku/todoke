//! The human pairing code (PROTOCOL §3.2): a uniformly random 10-digit
//! ASCII decimal string, leading zeroes included. It is the `CPace`
//! password; it must never be hashed into a Noise PSK directly.

use core::fmt;

use zeroize::Zeroizing;

use crate::rng::{self, RandomError};

/// Number of digits.
pub const CODE_DIGITS: usize = 10;
/// 10^10: the number of distinct codes.
const CODE_SPACE: u64 = 10_000_000_000;
/// The largest multiple of [`CODE_SPACE`] that fits in a u64; draws at or
/// above it are rejected so that every code is equally likely.
const ACCEPT_BELOW: u64 = u64::MAX - u64::MAX % CODE_SPACE;

/// A 10-digit pairing code. Zeroized on drop and redacted in `Debug`.
///
/// The displayer shows it ([`Self::as_str`]); the entrant types it
/// ([`Self::parse`]). Its bytes are exactly the ten ASCII digits, with no
/// Unicode or integer normalization (§3.2).
#[derive(Clone)]
pub struct HumanCode(Zeroizing<[u8; CODE_DIGITS]>);

/// The input is not exactly ten ASCII digits. Carries no detail.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidCode;

impl fmt::Display for InvalidCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a pairing code is exactly ten ASCII digits")
    }
}

impl std::error::Error for InvalidCode {}

impl HumanCode {
    /// A fresh uniformly random code from the OS CSPRNG.
    ///
    /// # Errors
    ///
    /// [`RandomError`] if randomness is unavailable.
    pub fn generate() -> Result<Self, RandomError> {
        // Rejection sampling: the chance of a retry is below 2^-30, so 32
        // rounds only guard against a broken source, which fails closed.
        for _ in 0..32 {
            let mut bytes = Zeroizing::new([0; 8]);
            rng::fill(bytes.as_mut_slice())?;
            let value = Zeroizing::new(u64::from_be_bytes(*bytes));
            if *value < ACCEPT_BELOW {
                return Ok(Self::from_value(*value % CODE_SPACE));
            }
        }
        Err(RandomError)
    }

    fn from_value(mut value: u64) -> Self {
        let mut digits = Zeroizing::new([b'0'; CODE_DIGITS]);
        for digit in digits.iter_mut().rev() {
            *digit = b'0' + u8::try_from(value % 10).unwrap_or(0);
            value /= 10;
        }
        Self(digits)
    }

    /// Parses an entered code: exactly ten ASCII digits `0`–`9`, nothing
    /// else (no spaces, separators, or non-ASCII digits).
    ///
    /// # Errors
    ///
    /// [`InvalidCode`] for any other input.
    pub fn parse(input: &str) -> Result<Self, InvalidCode> {
        let bytes: &[u8; CODE_DIGITS] = input.as_bytes().try_into().map_err(|_| InvalidCode)?;
        if !bytes.iter().all(u8::is_ascii_digit) {
            return Err(InvalidCode);
        }
        Ok(Self(Zeroizing::new(*bytes)))
    }

    /// The ten digits, for display to the local user only. Never log it or
    /// send it anywhere (§14.2).
    #[must_use]
    pub fn as_str(&self) -> &str {
        // Always ten ASCII digits by construction.
        core::str::from_utf8(self.0.as_slice()).unwrap_or_default()
    }

    /// The `CPace` password bytes (§3.2).
    #[cfg_attr(
        not(test),
        expect(dead_code, reason = "the CPace password, read by code pairing")
    )]
    pub(crate) fn password(&self) -> &[u8; CODE_DIGITS] {
        &self.0
    }
}

impl fmt::Debug for HumanCode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("HumanCode([REDACTED])")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_accepts_exactly_ten_ascii_digits() -> Result<(), InvalidCode> {
        assert_eq!(HumanCode::parse("0000000000")?.as_str(), "0000000000");
        assert_eq!(HumanCode::parse("0123456789")?.password(), b"0123456789");
        for bad in [
            "",
            "012345678",
            "01234567890",
            "012345678a",
            "01234 6789",
            "0123-56789",
            "+123456789",
            " 0123456789",
            "٠١٢٣٤٥٦٧٨٩",
            "０１２３４５６７８９",
            "01234５",
        ] {
            assert_eq!(HumanCode::parse(bad).err(), Some(InvalidCode), "{bad:?}");
        }
        Ok(())
    }

    #[test]
    fn values_map_to_zero_padded_digits() {
        assert_eq!(HumanCode::from_value(0).as_str(), "0000000000");
        assert_eq!(HumanCode::from_value(42).as_str(), "0000000042");
        assert_eq!(HumanCode::from_value(CODE_SPACE - 1).as_str(), "9999999999");
        const { assert!(ACCEPT_BELOW.is_multiple_of(CODE_SPACE)) };
        const { assert!(u64::MAX - ACCEPT_BELOW < CODE_SPACE) };
    }

    #[test]
    fn generated_codes_are_valid_and_vary() -> Result<(), Box<dyn std::error::Error>> {
        let codes: Vec<String> = (0..64)
            .map(|_| HumanCode::generate().map(|code| code.as_str().to_owned()))
            .collect::<Result<_, _>>()?;
        for code in &codes {
            assert_eq!(HumanCode::parse(code)?.as_str(), code);
        }
        // 64 draws from 10^10 values: a repeat means a broken generator.
        let mut unique = codes.clone();
        unique.sort();
        unique.dedup();
        assert_eq!(unique.len(), codes.len());
        // Every digit position takes several values across the draws.
        for position in 0..CODE_DIGITS {
            let mut seen: Vec<u8> = codes.iter().map(|code| code.as_bytes()[position]).collect();
            seen.sort_unstable();
            seen.dedup();
            assert!(seen.len() > 3, "position {position}");
        }
        Ok(())
    }

    #[test]
    fn debug_is_redacted() -> Result<(), InvalidCode> {
        let code = HumanCode::parse("1234567890")?;
        assert_eq!(format!("{code:?}"), "HumanCode([REDACTED])");
        assert_eq!(
            InvalidCode.to_string(),
            "a pairing code is exactly ten ASCII digits"
        );
        Ok(())
    }
}
