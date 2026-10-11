//! `DeviceBinding` and `Revoke` wire records (PROTOCOL §2).
//!
//! These types check only the fixed layout: exact length, version, reserved
//! fields, nonzero identifiers, enum values, and time ranges. They do **not**
//! check that keys are valid, that signatures verify, or that a root is trusted.
//! A decoded record is untrusted until `todoke-crypto` verifies it.

use core::fmt;
use core::num::NonZeroU64;

use crate::time::UnixTime;

/// Root signature domain for a [`DeviceBinding`].
pub const DEVICE_BINDING_DOMAIN: &[u8] = b"todoke/v1/device-binding\0";
/// Device possession signature domain for a [`DeviceBinding`].
pub const DEVICE_POSSESSION_DOMAIN: &[u8] = b"todoke/v1/device-possession\0";
/// Root signature domain for a [`Revoke`] record.
pub const REVOKE_DOMAIN: &[u8] = b"todoke/v1/revoke\0";

/// The only defined `DeviceBinding` and `Revoke` version.
pub const IDENTITY_VERSION: u16 = 1;
/// Ed25519 or X25519 public key length.
pub const PUBLIC_KEY_LEN: usize = 32;
/// ML-KEM-768 encapsulation key length.
pub const KEM_STATIC_LEN: usize = 1184;
/// Ed25519 signature length.
pub const SIGNATURE_LEN: usize = 64;
/// Longest permitted binding lifetime: 366 days.
pub const MAX_BINDING_LIFETIME_SECONDS: u64 = 366 * 86_400;

/// Bytes covered by the root signature of a binding.
pub const DEVICE_BINDING_BODY_LEN: usize = 1310;
/// Bytes covered by the device possession signature (body and root signature).
pub const DEVICE_BINDING_POSSESSION_LEN: usize = DEVICE_BINDING_BODY_LEN + SIGNATURE_LEN;
/// Encoded `DeviceBinding` length.
pub const DEVICE_BINDING_LEN: usize = DEVICE_BINDING_POSSESSION_LEN + SIGNATURE_LEN;
/// Bytes covered by the root signature of a `Revoke` record.
pub const REVOKE_BODY_LEN: usize = 108;
/// Encoded `Revoke` length.
pub const REVOKE_LEN: usize = REVOKE_BODY_LEN + SIGNATURE_LEN;

/// Why a wire record was rejected. Variants carry no peer data.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum DecodeError {
    /// The input is not exactly the record length.
    Length,
    /// The version is not [`IDENTITY_VERSION`].
    Version,
    /// A reserved field is nonzero.
    Reserved,
    /// A serial, sequence, or time is outside its permitted range.
    Range,
    /// A random identifier is all zero.
    ZeroIdentifier,
    /// An enum value is not defined.
    UnknownEnum,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Length => "record has the wrong length",
            Self::Version => "unsupported record version",
            Self::Reserved => "reserved field is nonzero",
            Self::Range => "field is out of range",
            Self::ZeroIdentifier => "identifier is zero",
            Self::UnknownEnum => "unknown enum value",
        })
    }
}

impl std::error::Error for DecodeError {}

/// The signed fields of a `DeviceBinding`, before either signature.
#[derive(Clone, PartialEq, Eq)]
pub struct DeviceBindingBody {
    person_root: [u8; PUBLIC_KEY_LEN],
    device_public: [u8; PUBLIC_KEY_LEN],
    noise_static: [u8; PUBLIC_KEY_LEN],
    kem_static: Box<[u8; KEM_STATIC_LEN]>,
    serial: NonZeroU64,
    not_before: UnixTime,
    not_after: UnixTime,
}

impl DeviceBindingBody {
    /// Builds a body, enforcing `not_before < not_after` and the 366-day limit.
    ///
    /// # Errors
    ///
    /// [`DecodeError::Range`] if the validity window is empty or too long.
    pub fn new(
        person_root: [u8; PUBLIC_KEY_LEN],
        device_public: [u8; PUBLIC_KEY_LEN],
        noise_static: [u8; PUBLIC_KEY_LEN],
        kem_static: Box<[u8; KEM_STATIC_LEN]>,
        serial: NonZeroU64,
        not_before: UnixTime,
        not_after: UnixTime,
    ) -> Result<Self, DecodeError> {
        let lifetime = not_after
            .seconds()
            .checked_sub(not_before.seconds())
            .ok_or(DecodeError::Range)?;
        if lifetime == 0 || lifetime > MAX_BINDING_LIFETIME_SECONDS {
            return Err(DecodeError::Range);
        }
        Ok(Self {
            person_root,
            device_public,
            noise_static,
            kem_static,
            serial,
            not_before,
            not_after,
        })
    }

    /// The person's Ed25519 root public key (unvalidated).
    #[must_use]
    pub fn person_root(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.person_root
    }

    /// The device's Ed25519 public key (unvalidated).
    #[must_use]
    pub fn device_public(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.device_public
    }

    /// The device's X25519 Noise static public key (unvalidated).
    #[must_use]
    pub fn noise_static(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.noise_static
    }

    /// The retained ML-KEM-768 credential (unvalidated; unused by HFS, see O11).
    #[must_use]
    pub fn kem_static(&self) -> &[u8; KEM_STATIC_LEN] {
        &self.kem_static
    }

    /// Binding serial, unique and increasing per root and device.
    #[must_use]
    pub fn serial(&self) -> NonZeroU64 {
        self.serial
    }

    /// Start of validity, inclusive.
    #[must_use]
    pub fn not_before(&self) -> UnixTime {
        self.not_before
    }

    /// End of validity, exclusive.
    #[must_use]
    pub fn not_after(&self) -> UnixTime {
        self.not_after
    }

    /// The exact 1310 bytes that follow the domain in the root signature input.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(DEVICE_BINDING_LEN);
        self.encode_into(&mut out);
        out
    }

    /// `todoke/v1/device-binding\0 || body`, the root signature input.
    #[must_use]
    pub fn root_signing_input(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(DEVICE_BINDING_DOMAIN.len() + DEVICE_BINDING_BODY_LEN);
        out.extend_from_slice(DEVICE_BINDING_DOMAIN);
        self.encode_into(&mut out);
        out
    }

    /// `todoke/v1/device-possession\0 || body || root_signature`, the device
    /// possession signature input.
    #[must_use]
    pub fn possession_signing_input(&self, root_signature: &[u8; SIGNATURE_LEN]) -> Vec<u8> {
        let mut out =
            Vec::with_capacity(DEVICE_POSSESSION_DOMAIN.len() + DEVICE_BINDING_POSSESSION_LEN);
        out.extend_from_slice(DEVICE_POSSESSION_DOMAIN);
        self.encode_into(&mut out);
        out.extend_from_slice(root_signature);
        out
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&IDENTITY_VERSION.to_be_bytes());
        out.extend_from_slice(&self.person_root);
        out.extend_from_slice(&self.device_public);
        out.extend_from_slice(&self.noise_static);
        out.extend_from_slice(&self.kem_static[..]);
        out.extend_from_slice(&self.serial.get().to_be_bytes());
        out.extend_from_slice(&self.not_before.seconds().to_be_bytes());
        out.extend_from_slice(&self.not_after.seconds().to_be_bytes());
        out.extend_from_slice(&0u32.to_be_bytes());
    }
}

impl fmt::Debug for DeviceBindingBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceBindingBody")
            .field("person_root", &Hex(&self.person_root))
            .field("device_public", &Hex(&self.device_public))
            .field("noise_static", &Hex(&self.noise_static))
            .field("kem_static", &format_args!("[{KEM_STATIC_LEN} bytes]"))
            .field("serial", &self.serial)
            .field("not_before", &self.not_before.seconds())
            .field("not_after", &self.not_after.seconds())
            .finish()
    }
}

/// A complete `DeviceBinding`: a person root certifying a device's keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceBinding {
    body: DeviceBindingBody,
    root_signature: [u8; SIGNATURE_LEN],
    device_signature: [u8; SIGNATURE_LEN],
}

impl DeviceBinding {
    /// Assembles a binding from a body and both signatures without checking them.
    #[must_use]
    pub fn from_parts(
        body: DeviceBindingBody,
        root_signature: [u8; SIGNATURE_LEN],
        device_signature: [u8; SIGNATURE_LEN],
    ) -> Self {
        Self {
            body,
            root_signature,
            device_signature,
        }
    }

    /// Parses exactly [`DEVICE_BINDING_LEN`] bytes.
    ///
    /// # Errors
    ///
    /// Any layout violation from PROTOCOL §1–§2.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != DEVICE_BINDING_LEN {
            return Err(DecodeError::Length);
        }
        let mut reader = Reader(bytes);
        if reader.u16()? != IDENTITY_VERSION {
            return Err(DecodeError::Version);
        }
        let person_root = reader.array()?;
        let device_public = reader.array()?;
        let noise_static = reader.array()?;
        let kem_static = Box::new(reader.array::<KEM_STATIC_LEN>()?);
        let serial = NonZeroU64::new(reader.u64()?).ok_or(DecodeError::Range)?;
        let not_before = reader.time()?;
        let not_after = reader.time()?;
        if reader.u32()? != 0 {
            return Err(DecodeError::Reserved);
        }
        let root_signature = reader.array()?;
        let device_signature = reader.array()?;
        reader.finish()?;
        let body = DeviceBindingBody::new(
            person_root,
            device_public,
            noise_static,
            kem_static,
            serial,
            not_before,
            not_after,
        )?;
        Ok(Self::from_parts(body, root_signature, device_signature))
    }

    /// The exact [`DEVICE_BINDING_LEN`]-byte encoding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(DEVICE_BINDING_LEN);
        self.body.encode_into(&mut out);
        out.extend_from_slice(&self.root_signature);
        out.extend_from_slice(&self.device_signature);
        out
    }

    /// The signed fields.
    #[must_use]
    pub fn body(&self) -> &DeviceBindingBody {
        &self.body
    }

    /// Root signature over [`DeviceBindingBody::root_signing_input`].
    #[must_use]
    pub fn root_signature(&self) -> &[u8; SIGNATURE_LEN] {
        &self.root_signature
    }

    /// Device signature over [`DeviceBindingBody::possession_signing_input`].
    #[must_use]
    pub fn device_signature(&self) -> &[u8; SIGNATURE_LEN] {
        &self.device_signature
    }
}

/// Revocation reason. There is no free text.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum RevocationReason {
    /// The device was lost.
    Lost = 1,
    /// The device key is believed compromised.
    Compromised = 2,
    /// The device was retired.
    Retired = 3,
}

impl RevocationReason {
    /// Maps a wire value; `None` for unassigned values.
    #[must_use]
    pub const fn from_u16(value: u16) -> Option<Self> {
        match value {
            1 => Some(Self::Lost),
            2 => Some(Self::Compromised),
            3 => Some(Self::Retired),
            _ => None,
        }
    }

    /// The wire value.
    #[must_use]
    pub const fn to_u16(self) -> u16 {
        self as u16
    }
}

/// The signed fields of a `Revoke` record (transport type 0x0040).
#[derive(Clone, PartialEq, Eq)]
pub struct RevokeBody {
    person_root: [u8; PUBLIC_KEY_LEN],
    record_id: [u8; 16],
    sequence: NonZeroU64,
    issued_at: UnixTime,
    device_public: [u8; PUBLIC_KEY_LEN],
    through_serial: NonZeroU64,
    reason: RevocationReason,
}

impl RevokeBody {
    /// Builds a body.
    ///
    /// # Errors
    ///
    /// [`DecodeError::ZeroIdentifier`] if `record_id` is all zero.
    pub fn new(
        person_root: [u8; PUBLIC_KEY_LEN],
        record_id: [u8; 16],
        sequence: NonZeroU64,
        issued_at: UnixTime,
        device_public: [u8; PUBLIC_KEY_LEN],
        through_serial: NonZeroU64,
        reason: RevocationReason,
    ) -> Result<Self, DecodeError> {
        if record_id == [0; 16] {
            return Err(DecodeError::ZeroIdentifier);
        }
        Ok(Self {
            person_root,
            record_id,
            sequence,
            issued_at,
            device_public,
            through_serial,
            reason,
        })
    }

    /// The issuing person root (unvalidated).
    #[must_use]
    pub fn person_root(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.person_root
    }

    /// Random record identifier.
    #[must_use]
    pub fn record_id(&self) -> &[u8; 16] {
        &self.record_id
    }

    /// Root-issued sequence number.
    #[must_use]
    pub fn sequence(&self) -> NonZeroU64 {
        self.sequence
    }

    /// Issue time.
    #[must_use]
    pub fn issued_at(&self) -> UnixTime {
        self.issued_at
    }

    /// The revoked full device key (unvalidated).
    #[must_use]
    pub fn device_public(&self) -> &[u8; PUBLIC_KEY_LEN] {
        &self.device_public
    }

    /// Bindings for this device with `serial <= through_serial` are revoked.
    #[must_use]
    pub fn through_serial(&self) -> NonZeroU64 {
        self.through_serial
    }

    /// Revocation reason.
    #[must_use]
    pub fn reason(&self) -> RevocationReason {
        self.reason
    }

    /// The exact 108 bytes that follow the domain in the signature input.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(REVOKE_LEN);
        self.encode_into(&mut out);
        out
    }

    /// `todoke/v1/revoke\0 || body`, the root signature input.
    #[must_use]
    pub fn signing_input(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(REVOKE_DOMAIN.len() + REVOKE_BODY_LEN);
        out.extend_from_slice(REVOKE_DOMAIN);
        self.encode_into(&mut out);
        out
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&IDENTITY_VERSION.to_be_bytes());
        out.extend_from_slice(&self.person_root);
        out.extend_from_slice(&self.record_id);
        out.extend_from_slice(&self.sequence.get().to_be_bytes());
        out.extend_from_slice(&self.issued_at.seconds().to_be_bytes());
        out.extend_from_slice(&self.device_public);
        out.extend_from_slice(&self.through_serial.get().to_be_bytes());
        out.extend_from_slice(&self.reason.to_u16().to_be_bytes());
    }
}

impl fmt::Debug for RevokeBody {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RevokeBody")
            .field("person_root", &Hex(&self.person_root))
            .field("record_id", &Hex(&self.record_id))
            .field("sequence", &self.sequence)
            .field("issued_at", &self.issued_at.seconds())
            .field("device_public", &Hex(&self.device_public))
            .field("through_serial", &self.through_serial)
            .field("reason", &self.reason)
            .finish()
    }
}

/// A complete `Revoke` record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Revoke {
    body: RevokeBody,
    signature: [u8; SIGNATURE_LEN],
}

impl Revoke {
    /// Assembles a record without checking the signature.
    #[must_use]
    pub fn from_parts(body: RevokeBody, signature: [u8; SIGNATURE_LEN]) -> Self {
        Self { body, signature }
    }

    /// Parses exactly [`REVOKE_LEN`] bytes.
    ///
    /// # Errors
    ///
    /// Any layout violation from PROTOCOL §1–§2.
    pub fn decode(bytes: &[u8]) -> Result<Self, DecodeError> {
        if bytes.len() != REVOKE_LEN {
            return Err(DecodeError::Length);
        }
        let mut reader = Reader(bytes);
        if reader.u16()? != IDENTITY_VERSION {
            return Err(DecodeError::Version);
        }
        let person_root = reader.array()?;
        let record_id = reader.array()?;
        let sequence = NonZeroU64::new(reader.u64()?).ok_or(DecodeError::Range)?;
        let issued_at = reader.time()?;
        let device_public = reader.array()?;
        let through_serial = NonZeroU64::new(reader.u64()?).ok_or(DecodeError::Range)?;
        let reason = RevocationReason::from_u16(reader.u16()?).ok_or(DecodeError::UnknownEnum)?;
        let signature = reader.array()?;
        reader.finish()?;
        let body = RevokeBody::new(
            person_root,
            record_id,
            sequence,
            issued_at,
            device_public,
            through_serial,
            reason,
        )?;
        Ok(Self::from_parts(body, signature))
    }

    /// The exact [`REVOKE_LEN`]-byte encoding.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(REVOKE_LEN);
        self.body.encode_into(&mut out);
        out.extend_from_slice(&self.signature);
        out
    }

    /// The signed fields.
    #[must_use]
    pub fn body(&self) -> &RevokeBody {
        &self.body
    }

    /// Root signature over [`RevokeBody::signing_input`].
    #[must_use]
    pub fn signature(&self) -> &[u8; SIGNATURE_LEN] {
        &self.signature
    }
}

/// Bounded big-endian reader over a length-checked slice.
struct Reader<'a>(&'a [u8]);

impl Reader<'_> {
    fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let (head, rest) = self.0.split_first_chunk::<N>().ok_or(DecodeError::Length)?;
        self.0 = rest;
        Ok(*head)
    }

    fn u16(&mut self) -> Result<u16, DecodeError> {
        self.array().map(u16::from_be_bytes)
    }

    fn u32(&mut self) -> Result<u32, DecodeError> {
        self.array().map(u32::from_be_bytes)
    }

    fn u64(&mut self) -> Result<u64, DecodeError> {
        self.array().map(u64::from_be_bytes)
    }

    fn time(&mut self) -> Result<UnixTime, DecodeError> {
        UnixTime::new(self.u64()?).ok_or(DecodeError::Range)
    }

    fn finish(self) -> Result<(), DecodeError> {
        if self.0.is_empty() {
            Ok(())
        } else {
            Err(DecodeError::Length)
        }
    }
}

struct Hex<'a>(&'a [u8]);

impl fmt::Debug for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for byte in self.0 {
            write!(f, "{byte:02x}")?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::time::MAX_UNIX_TIME;
    use proptest::prelude::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const T0: u64 = 1_760_000_000;

    fn time(seconds: u64) -> Result<UnixTime, DecodeError> {
        UnixTime::new(seconds).ok_or(DecodeError::Range)
    }

    fn nz(value: u64) -> Result<NonZeroU64, DecodeError> {
        NonZeroU64::new(value).ok_or(DecodeError::Range)
    }

    fn sample_binding() -> Result<DeviceBinding, DecodeError> {
        let body = DeviceBindingBody::new(
            [1; 32],
            [2; 32],
            [3; 32],
            Box::new([4; KEM_STATIC_LEN]),
            nz(7)?,
            time(T0)?,
            time(T0 + 86_400)?,
        )?;
        Ok(DeviceBinding::from_parts(body, [5; 64], [6; 64]))
    }

    fn sample_revoke() -> Result<Revoke, DecodeError> {
        let body = RevokeBody::new(
            [1; 32],
            [9; 16],
            nz(3)?,
            time(T0)?,
            [2; 32],
            nz(7)?,
            RevocationReason::Compromised,
        )?;
        Ok(Revoke::from_parts(body, [8; 64]))
    }

    #[test]
    fn layout_constants_match_spec_totals() -> TestResult {
        assert_eq!(DEVICE_BINDING_BODY_LEN, 1310);
        assert_eq!(DEVICE_BINDING_POSSESSION_LEN, 1374);
        assert_eq!(DEVICE_BINDING_LEN, 1438);
        assert_eq!(REVOKE_BODY_LEN, 108);
        assert_eq!(REVOKE_LEN, 172);
        let binding = sample_binding()?;
        assert_eq!(binding.body().encode().len(), DEVICE_BINDING_BODY_LEN);
        assert_eq!(binding.encode().len(), DEVICE_BINDING_LEN);
        assert_eq!(sample_revoke()?.encode().len(), REVOKE_LEN);
        Ok(())
    }

    #[test]
    fn binding_field_offsets() -> TestResult {
        let bytes = sample_binding()?.encode();
        assert_eq!(bytes[..2], [0, 1]);
        assert_eq!(bytes[2..34], [1; 32]);
        assert_eq!(bytes[34..66], [2; 32]);
        assert_eq!(bytes[66..98], [3; 32]);
        assert_eq!(bytes[98..1282], [4; KEM_STATIC_LEN]);
        assert_eq!(bytes[1282..1290], 7u64.to_be_bytes());
        assert_eq!(bytes[1290..1298], T0.to_be_bytes());
        assert_eq!(bytes[1298..1306], (T0 + 86_400).to_be_bytes());
        assert_eq!(bytes[1306..1310], [0; 4]);
        assert_eq!(bytes[1310..1374], [5; 64]);
        assert_eq!(bytes[1374..1438], [6; 64]);
        Ok(())
    }

    #[test]
    fn revoke_field_offsets() -> TestResult {
        let bytes = sample_revoke()?.encode();
        assert_eq!(bytes[..2], [0, 1]);
        assert_eq!(bytes[2..34], [1; 32]);
        assert_eq!(bytes[34..50], [9; 16]);
        assert_eq!(bytes[50..58], 3u64.to_be_bytes());
        assert_eq!(bytes[58..66], T0.to_be_bytes());
        assert_eq!(bytes[66..98], [2; 32]);
        assert_eq!(bytes[98..106], 7u64.to_be_bytes());
        assert_eq!(bytes[106..108], [0, 2]);
        assert_eq!(bytes[108..172], [8; 64]);
        Ok(())
    }

    #[test]
    fn signing_inputs_are_domain_prefixed() -> TestResult {
        let binding = sample_binding()?;
        let root = binding.body().root_signing_input();
        assert_eq!(&root[..DEVICE_BINDING_DOMAIN.len()], DEVICE_BINDING_DOMAIN);
        assert_eq!(
            root[DEVICE_BINDING_DOMAIN.len()..],
            binding.encode()[..1310]
        );
        let possession = binding
            .body()
            .possession_signing_input(binding.root_signature());
        assert_eq!(
            &possession[..DEVICE_POSSESSION_DOMAIN.len()],
            DEVICE_POSSESSION_DOMAIN
        );
        assert_eq!(
            possession[DEVICE_POSSESSION_DOMAIN.len()..],
            binding.encode()[..1374]
        );
        let revoke = sample_revoke()?;
        let input = revoke.body().signing_input();
        assert_eq!(&input[..REVOKE_DOMAIN.len()], REVOKE_DOMAIN);
        assert_eq!(input[REVOKE_DOMAIN.len()..], revoke.encode()[..108]);
        assert_eq!(revoke.body().encode(), revoke.encode()[..108]);
        Ok(())
    }

    #[test]
    fn binding_rejects_each_field_violation() -> TestResult {
        let good = sample_binding()?.encode();
        let mutate = |offset: usize, value: &[u8]| {
            let mut bytes = good.clone();
            bytes[offset..offset + value.len()].copy_from_slice(value);
            DeviceBinding::decode(&bytes)
        };
        assert_eq!(mutate(0, &[0, 2]), Err(DecodeError::Version));
        assert_eq!(mutate(0, &[0, 0]), Err(DecodeError::Version));
        assert_eq!(mutate(1282, &[0; 8]), Err(DecodeError::Range));
        // Empty window: not_before == not_after.
        assert_eq!(
            mutate(1290, &(T0 + 86_400).to_be_bytes()),
            Err(DecodeError::Range)
        );
        // Inverted window.
        assert_eq!(
            mutate(1290, &(T0 + 86_401).to_be_bytes()),
            Err(DecodeError::Range)
        );
        let over = T0 + MAX_BINDING_LIFETIME_SECONDS + 1;
        assert_eq!(mutate(1298, &over.to_be_bytes()), Err(DecodeError::Range));
        assert!(mutate(1298, &(over - 1).to_be_bytes()).is_ok());
        assert_eq!(
            mutate(1298, &(MAX_UNIX_TIME + 1).to_be_bytes()),
            Err(DecodeError::Range)
        );
        assert_eq!(
            mutate(1290, &(MAX_UNIX_TIME + 1).to_be_bytes()),
            Err(DecodeError::Range)
        );
        assert_eq!(mutate(1309, &[1]), Err(DecodeError::Reserved));
        assert_eq!(mutate(1306, &[0x80]), Err(DecodeError::Reserved));
        assert_eq!(
            DeviceBinding::decode(&good[..1437]),
            Err(DecodeError::Length)
        );
        let mut long = good.clone();
        long.push(0);
        assert_eq!(DeviceBinding::decode(&long), Err(DecodeError::Length));
        assert_eq!(DeviceBinding::decode(&[]), Err(DecodeError::Length));
        Ok(())
    }

    #[test]
    fn revoke_rejects_each_field_violation() -> TestResult {
        let good = sample_revoke()?.encode();
        let mutate = |offset: usize, value: &[u8]| {
            let mut bytes = good.clone();
            bytes[offset..offset + value.len()].copy_from_slice(value);
            Revoke::decode(&bytes)
        };
        assert_eq!(mutate(0, &[0, 2]), Err(DecodeError::Version));
        assert_eq!(mutate(34, &[0; 16]), Err(DecodeError::ZeroIdentifier));
        assert_eq!(mutate(50, &[0; 8]), Err(DecodeError::Range));
        assert_eq!(
            mutate(58, &(MAX_UNIX_TIME + 1).to_be_bytes()),
            Err(DecodeError::Range)
        );
        assert_eq!(mutate(98, &[0; 8]), Err(DecodeError::Range));
        for reason in [0u16, 4, 0xffff] {
            assert_eq!(
                mutate(106, &reason.to_be_bytes()),
                Err(DecodeError::UnknownEnum)
            );
        }
        assert_eq!(Revoke::decode(&good[..171]), Err(DecodeError::Length));
        let mut long = good.clone();
        long.push(0);
        assert_eq!(Revoke::decode(&long), Err(DecodeError::Length));
        Ok(())
    }

    #[test]
    fn revocation_reason_values() {
        for (value, reason) in [
            (1, RevocationReason::Lost),
            (2, RevocationReason::Compromised),
            (3, RevocationReason::Retired),
        ] {
            assert_eq!(RevocationReason::from_u16(value), Some(reason));
            assert_eq!(reason.to_u16(), value);
        }
        assert_eq!(RevocationReason::from_u16(0), None);
        assert_eq!(RevocationReason::from_u16(4), None);
    }

    fn arb_binding() -> impl Strategy<Value = DeviceBinding> {
        (
            any::<([u8; 32], [u8; 32], [u8; 32])>(),
            any::<(u8, u8)>(),
            1..=u64::MAX,
            0..=(MAX_UNIX_TIME - MAX_BINDING_LIFETIME_SECONDS),
            1..=MAX_BINDING_LIFETIME_SECONDS,
            any::<([u8; 32], [u8; 32])>(),
        )
            .prop_filter_map(
                "valid binding",
                |((root, device, noise), kem, serial, start, lifetime, sigs)| {
                    let mut kem_static = Box::new([kem.0; KEM_STATIC_LEN]);
                    kem_static[KEM_STATIC_LEN - 1] = kem.1;
                    let body = DeviceBindingBody::new(
                        root,
                        device,
                        noise,
                        kem_static,
                        nz(serial).ok()?,
                        time(start).ok()?,
                        time(start + lifetime).ok()?,
                    )
                    .ok()?;
                    let mut root_signature = [0x5a; 64];
                    root_signature[..32].copy_from_slice(&sigs.0);
                    let mut device_signature = [0xa5; 64];
                    device_signature[32..].copy_from_slice(&sigs.1);
                    Some(DeviceBinding::from_parts(
                        body,
                        root_signature,
                        device_signature,
                    ))
                },
            )
    }

    fn arb_revoke() -> impl Strategy<Value = Revoke> {
        (
            any::<([u8; 32], [u8; 16], [u8; 32])>(),
            (1..=u64::MAX, 0..=MAX_UNIX_TIME, 1..=u64::MAX),
            1..=3u16,
            any::<[u8; 32]>(),
        )
            .prop_filter_map(
                "valid revoke",
                |((root, record_id, device), (sequence, issued, through), reason, sig)| {
                    let body = RevokeBody::new(
                        root,
                        record_id,
                        nz(sequence).ok()?,
                        time(issued).ok()?,
                        device,
                        nz(through).ok()?,
                        RevocationReason::from_u16(reason)?,
                    )
                    .ok()?;
                    let mut signature = [0x3c; 64];
                    signature[..32].copy_from_slice(&sig);
                    Some(Revoke::from_parts(body, signature))
                },
            )
    }

    proptest! {
        #[test]
        fn binding_round_trips(binding in arb_binding()) {
            let bytes = binding.encode();
            prop_assert_eq!(bytes.len(), DEVICE_BINDING_LEN);
            prop_assert_eq!(DeviceBinding::decode(&bytes), Ok(binding));
        }

        #[test]
        fn revoke_round_trips(revoke in arb_revoke()) {
            let bytes = revoke.encode();
            prop_assert_eq!(bytes.len(), REVOKE_LEN);
            prop_assert_eq!(Revoke::decode(&bytes), Ok(revoke));
        }

        // Accepted inputs are canonical: re-encoding reproduces them exactly.
        #[test]
        fn binding_decode_is_canonical(
            mut bytes in proptest::collection::vec(any::<u8>(), DEVICE_BINDING_LEN),
            start in 0..=(MAX_UNIX_TIME - MAX_BINDING_LIFETIME_SECONDS),
            lifetime in 1..=MAX_BINDING_LIFETIME_SECONDS,
        ) {
            // Make the constrained fields valid so most cases reach full decoding.
            bytes[..2].copy_from_slice(&IDENTITY_VERSION.to_be_bytes());
            bytes[1290..1298].copy_from_slice(&start.to_be_bytes());
            bytes[1298..1306].copy_from_slice(&(start + lifetime).to_be_bytes());
            bytes[1306..1310].fill(0);
            if let Ok(binding) = DeviceBinding::decode(&bytes) {
                prop_assert_eq!(binding.encode(), bytes);
            }
        }

        #[test]
        fn revoke_decode_is_canonical(
            mut bytes in proptest::collection::vec(any::<u8>(), REVOKE_LEN),
            issued in 0..=MAX_UNIX_TIME,
            reason in 1..=3u16,
        ) {
            bytes[..2].copy_from_slice(&IDENTITY_VERSION.to_be_bytes());
            bytes[58..66].copy_from_slice(&issued.to_be_bytes());
            bytes[106..108].copy_from_slice(&reason.to_be_bytes());
            if let Ok(revoke) = Revoke::decode(&bytes) {
                prop_assert_eq!(revoke.encode(), bytes);
            }
        }

        #[test]
        fn decoders_never_panic(bytes in proptest::collection::vec(any::<u8>(), 0..1600)) {
            let _ = DeviceBinding::decode(&bytes);
            let _ = Revoke::decode(&bytes);
        }
    }
}
