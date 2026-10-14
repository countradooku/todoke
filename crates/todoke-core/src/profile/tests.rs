use super::*;
use crate::storage_key::FixedKey;

type TestResult = Result<(), Box<dyn std::error::Error>>;

const T0: u64 = 1_760_000_000;

fn time(seconds: u64) -> Result<UnixTime, &'static str> {
    UnixTime::new(seconds).ok_or("time")
}

/// A scratch directory under the system temp dir, removed on drop.
pub(crate) struct Scratch(pub(crate) PathBuf);

impl Scratch {
    pub(crate) fn new(name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let mut random = [0; 8];
        getrandom::fill(&mut random)?;
        let suffix: String = random.iter().fold(String::new(), |mut out, byte| {
            use core::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
            out
        });
        Ok(Self(
            std::env::temp_dir().join(format!("todoke-core-{name}-{suffix}")),
        ))
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn a_new_identity_is_created_once_and_restored() -> TestResult {
    let scratch = Scratch::new("restore")?;
    let key = FixedKey([7; 32]);
    let first = Profile::open(&scratch.0, &key, time(T0)?)?;
    let device = *first.binding().device_public();
    let noise = *first.noise().public_key();
    assert_eq!(first.binding().serial(), NonZeroU64::MIN);
    assert!(first.local(time(T0)?).is_ok());
    drop(first);
    let again = Profile::open(&scratch.0, &key, time(T0 + 60)?)?;
    assert_eq!(*again.binding().device_public(), device);
    assert_eq!(*again.noise().public_key(), noise);
    assert_eq!(again.binding().serial(), NonZeroU64::MIN);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        assert_eq!(
            std::fs::metadata(&scratch.0)?.permissions().mode() & 0o777,
            0o700
        );
    }
    Ok(())
}

/// Another storage key opens nothing and overwrites nothing.
#[test]
fn a_wrong_storage_key_is_refused_without_damage() -> TestResult {
    let scratch = Scratch::new("wrong-key")?;
    drop(Profile::open(&scratch.0, &FixedKey([7; 32]), time(T0)?)?);
    let before = std::fs::read(scratch.0.join("device.bin"))?;
    assert!(matches!(
        Profile::open(&scratch.0, &FixedKey([8; 32]), time(T0)?),
        Err(ProfileError::Corrupt(_))
    ));
    assert_eq!(std::fs::read(scratch.0.join("device.bin"))?, before);
    assert!(Profile::open(&scratch.0, &FixedKey([7; 32]), time(T0)?).is_ok());
    Ok(())
}

/// Close to expiry (or after it) the binding is renewed with the next
/// serial; the device and Noise keys stay.
#[test]
fn bindings_are_renewed_before_they_expire() -> TestResult {
    let scratch = Scratch::new("renew")?;
    let key = FixedKey([7; 32]);
    let first = Profile::open(&scratch.0, &key, time(T0)?)?;
    let device = *first.binding().device_public();
    drop(first);
    let early = Profile::open(
        &scratch.0,
        &key,
        time(T0 + BINDING_LIFETIME - BINDING_RENEWAL - 1_000)?,
    )?;
    assert_eq!(early.binding().serial(), NonZeroU64::MIN);
    drop(early);
    let late = T0 + BINDING_LIFETIME + 86_400;
    let renewed = Profile::open(&scratch.0, &key, time(late)?)?;
    assert_eq!(renewed.binding().serial().get(), 2);
    assert_eq!(*renewed.binding().device_public(), device);
    assert!(renewed.local(time(late)?).is_ok());
    drop(renewed);
    let kept = Profile::open(&scratch.0, &key, time(late)?)?;
    assert_eq!(kept.binding().serial().get(), 2);
    Ok(())
}

#[test]
fn damaged_device_records_are_refused() -> TestResult {
    let scratch = Scratch::new("damage")?;
    drop(Profile::open(&scratch.0, &FixedKey([7; 32]), time(T0)?)?);
    let mut bytes = std::fs::read(scratch.0.join("device.bin"))?;
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    std::fs::write(scratch.0.join("device.bin"), &bytes)?;
    assert!(matches!(
        Profile::open(&scratch.0, &FixedKey([7; 32]), time(T0)?),
        Err(ProfileError::Corrupt("device.bin"))
    ));
    Ok(())
}

#[cfg(unix)]
#[test]
fn a_state_directory_others_can_read_is_refused() -> TestResult {
    use std::os::unix::fs::PermissionsExt as _;
    let scratch = Scratch::new("open-dir")?;
    std::fs::create_dir_all(&scratch.0)?;
    std::fs::set_permissions(&scratch.0, std::fs::Permissions::from_mode(0o755))?;
    assert!(matches!(
        Profile::open(&scratch.0, &FixedKey([7; 32]), time(T0)?),
        Err(ProfileError::Io(std::io::ErrorKind::PermissionDenied))
    ));
    Ok(())
}

#[test]
fn the_device_record_round_trips() -> TestResult {
    let record = DeviceRecord {
        root: KeyId::from_bytes([1; 16]).ok_or("id")?,
        device: KeyId::from_bytes([2; 16]).ok_or("id")?,
        noise_secret: Zeroizing::new([3; 32]),
        binding: vec![4; 300],
    };
    let bytes = record.encode()?;
    let decoded = DeviceRecord::decode(&bytes).ok_or("decode")?;
    assert_eq!(decoded.binding, record.binding);
    assert_eq!(*decoded.noise_secret, [3; 32]);
    for cut in 0..bytes.len() {
        assert!(DeviceRecord::decode(&bytes[..cut]).is_none());
    }
    let mut long = bytes.to_vec();
    long.push(0);
    assert!(DeviceRecord::decode(&long).is_none());
    Ok(())
}
