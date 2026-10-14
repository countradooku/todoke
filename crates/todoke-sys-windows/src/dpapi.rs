//! The storage key protected by Windows (§16 O9): DPAPI under this user's
//! credentials, and, where a TPM is present, wrapped first by a
//! non-exportable RSA-2048 key of the Microsoft Platform Crypto Provider
//! (OAEP, SHA-256). The protected blob is a file beside the state
//! (`storage.key.dpapi`); without this user's logon (and the TPM, when
//! used) it opens nothing.
//!
//! The only unsafe code is the Win32 calls below; each block says why it
//! is sound. Buffers the system allocates are freed with `LocalFree`.

#![allow(
    unsafe_code,
    reason = "Win32 DPAPI and NCrypt calls; each block is justified"
)]

use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use windows_sys::Win32::Foundation::LocalFree;
use windows_sys::Win32::Security::Cryptography::{
    BCRYPT_OAEP_PADDING_INFO, BCRYPT_RSA_ALGORITHM, BCRYPT_SHA256_ALGORITHM, CRYPT_INTEGER_BLOB,
    CRYPTPROTECT_UI_FORBIDDEN, CryptProtectData, CryptUnprotectData, MS_PLATFORM_CRYPTO_PROVIDER,
    NCRYPT_KEY_HANDLE, NCRYPT_LENGTH_PROPERTY, NCRYPT_PAD_OAEP_FLAG, NCRYPT_PROV_HANDLE,
    NCRYPT_SILENT_FLAG, NCryptCreatePersistedKey, NCryptDecrypt, NCryptDeleteKey, NCryptEncrypt,
    NCryptFinalizeKey, NCryptFreeObject, NCryptOpenKey, NCryptOpenStorageProvider,
    NCryptSetProperty,
};
use zeroize::Zeroizing;

/// A stored payload: one format byte, then the key or its TPM wrapping.
const RAW: u8 = 1;
const TPM_WRAPPED: u8 = 2;
/// `NTE_BAD_KEYSET`: no key of that name.
const BAD_KEYSET: i32 = 0x8009_0016_u32.cast_signed();
/// The largest blob read back.
const MAX_BLOB: u64 = 4096;

/// What protects a stored key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KeyProtection {
    /// DPAPI under this user's credentials.
    Dpapi,
    /// DPAPI, the key wrapped first by a TPM key.
    Tpm,
}

/// The storage key of one profile, protected by DPAPI (and the TPM).
pub struct Dpapi {
    path: PathBuf,
    entropy: Vec<u8>,
    tpm_key_name: Vec<u16>,
    protection: Mutex<KeyProtection>,
}

impl core::fmt::Debug for Dpapi {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Dpapi")
            .field("path", &self.path)
            .finish_non_exhaustive()
    }
}

fn wide(text: &str) -> Vec<u16> {
    text.encode_utf16().chain(Some(0)).collect()
}

fn hresult(code: i32) -> io::Result<()> {
    if code >= 0 {
        Ok(())
    } else {
        Err(io::Error::other(format!("Windows error {code:#010x}")))
    }
}

/// An `NCrypt` handle, freed when dropped.
struct Handle(usize);

impl Drop for Handle {
    fn drop(&mut self) {
        if self.0 != 0 {
            // SAFETY: the handle came from NCryptOpenStorageProvider,
            // NCryptOpenKey, or NCryptCreatePersistedKey, and is freed once.
            unsafe {
                NCryptFreeObject(self.0);
            }
        }
    }
}

impl Dpapi {
    /// The protected key of the profile with ID `profile` (random, kept
    /// beside the state), whose state is in `state_dir`.
    #[must_use]
    pub fn new(state_dir: &Path, profile: &str) -> Self {
        let mut entropy = b"todoke/v1/storage-key\0".to_vec();
        entropy.extend_from_slice(profile.as_bytes());
        Self {
            path: state_dir.join("storage.key.dpapi"),
            entropy,
            tpm_key_name: wide(&format!("todoke-storage-{profile}")),
            protection: Mutex::new(KeyProtection::Dpapi),
        }
    }

    fn set_protection(&self, protection: KeyProtection) {
        if let Ok(mut current) = self.protection.lock() {
            *current = protection;
        }
    }

    /// The TPM provider, if this machine has a usable TPM.
    fn tpm() -> Option<Handle> {
        let mut provider: NCRYPT_PROV_HANDLE = 0;
        // SAFETY: `provider` is a valid out pointer; the provider name is a
        // static NUL-terminated wide string.
        let code =
            unsafe { NCryptOpenStorageProvider(&raw mut provider, MS_PLATFORM_CRYPTO_PROVIDER, 0) };
        (code >= 0).then_some(Handle(provider))
    }

    /// This profile's TPM key; created when `create` is set.
    fn tpm_key(&self, provider: &Handle, create: bool) -> io::Result<Option<Handle>> {
        let mut key: NCRYPT_KEY_HANDLE = 0;
        // SAFETY: valid provider handle and out pointer; the name is
        // NUL-terminated and outlives the call.
        let code = unsafe {
            NCryptOpenKey(
                provider.0,
                &raw mut key,
                self.tpm_key_name.as_ptr(),
                0,
                NCRYPT_SILENT_FLAG,
            )
        };
        if code >= 0 {
            return Ok(Some(Handle(key)));
        }
        if code != BAD_KEYSET || !create {
            return if code == BAD_KEYSET {
                Ok(None)
            } else {
                hresult(code).map(|()| None)
            };
        }
        // SAFETY: as above; the algorithm name is a static wide string.
        hresult(unsafe {
            NCryptCreatePersistedKey(
                provider.0,
                &raw mut key,
                BCRYPT_RSA_ALGORITHM,
                self.tpm_key_name.as_ptr(),
                0,
                NCRYPT_SILENT_FLAG,
            )
        })?;
        let key = Handle(key);
        let bits: u32 = 2048;
        let length = bits.to_le_bytes();
        // SAFETY: valid key handle; the property name is static; the input
        // is 4 readable bytes.
        hresult(unsafe {
            NCryptSetProperty(
                key.0,
                NCRYPT_LENGTH_PROPERTY,
                length.as_ptr(),
                4,
                NCRYPT_SILENT_FLAG,
            )
        })?;
        // SAFETY: valid, not yet finalized key handle.
        hresult(unsafe { NCryptFinalizeKey(key.0, NCRYPT_SILENT_FLAG) })?;
        Ok(Some(key))
    }

    fn oaep() -> BCRYPT_OAEP_PADDING_INFO {
        BCRYPT_OAEP_PADDING_INFO {
            pszAlgId: BCRYPT_SHA256_ALGORITHM,
            pbLabel: core::ptr::null_mut(),
            cbLabel: 0,
        }
    }

    /// RSA-OAEP with the TPM key: `encrypt` or decrypt `input`.
    fn tpm_crypt(key: &Handle, input: &[u8], encrypt: bool) -> io::Result<Zeroizing<Vec<u8>>> {
        let padding = Self::oaep();
        let length = u32::try_from(input.len()).map_err(|_| io::ErrorKind::InvalidInput)?;
        let mut output = Zeroizing::new(vec![0_u8; 512]);
        let capacity = u32::try_from(output.len()).map_err(|_| io::ErrorKind::InvalidInput)?;
        let mut written = 0_u32;
        let flags = NCRYPT_PAD_OAEP_FLAG | NCRYPT_SILENT_FLAG;
        let padding_ptr = (&raw const padding).cast::<core::ffi::c_void>();
        // SAFETY: valid key handle; `input` is `length` readable bytes;
        // `output` is `capacity` writable bytes; `padding` outlives the
        // call; `written` is a valid out pointer.
        let code = unsafe {
            if encrypt {
                NCryptEncrypt(
                    key.0,
                    input.as_ptr(),
                    length,
                    padding_ptr,
                    output.as_mut_ptr(),
                    capacity,
                    &raw mut written,
                    flags,
                )
            } else {
                NCryptDecrypt(
                    key.0,
                    input.as_ptr(),
                    length,
                    padding_ptr,
                    output.as_mut_ptr(),
                    capacity,
                    &raw mut written,
                    flags,
                )
            }
        };
        hresult(code)?;
        output.truncate(usize::try_from(written).map_err(|_| io::ErrorKind::InvalidData)?);
        Ok(output)
    }

    /// DPAPI under this user: protect or unprotect `input`.
    fn dpapi(&self, input: &[u8], protect: bool) -> io::Result<Zeroizing<Vec<u8>>> {
        let data = CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(input.len()).map_err(|_| io::ErrorKind::InvalidInput)?,
            pbData: input.as_ptr().cast_mut(),
        };
        let entropy = CRYPT_INTEGER_BLOB {
            cbData: u32::try_from(self.entropy.len()).map_err(|_| io::ErrorKind::InvalidInput)?,
            pbData: self.entropy.as_ptr().cast_mut(),
        };
        let mut out = CRYPT_INTEGER_BLOB {
            cbData: 0,
            pbData: core::ptr::null_mut(),
        };
        // SAFETY: `data` and `entropy` point at live buffers of the stated
        // sizes, only read; `out` is a valid out structure the system fills
        // with a LocalAlloc'd buffer, freed below.
        let ok = unsafe {
            if protect {
                CryptProtectData(
                    &raw const data,
                    core::ptr::null(),
                    &raw const entropy,
                    core::ptr::null(),
                    core::ptr::null(),
                    CRYPTPROTECT_UI_FORBIDDEN,
                    &raw mut out,
                )
            } else {
                CryptUnprotectData(
                    &raw const data,
                    core::ptr::null_mut(),
                    &raw const entropy,
                    core::ptr::null(),
                    core::ptr::null(),
                    CRYPTPROTECT_UI_FORBIDDEN,
                    &raw mut out,
                )
            }
        };
        if ok == 0 {
            return Err(io::Error::last_os_error());
        }
        let length = usize::try_from(out.cbData).map_err(|_| io::ErrorKind::InvalidData)?;
        // SAFETY: on success `out.pbData` points at `out.cbData` bytes the
        // system allocated; they are copied before being freed.
        let copied =
            Zeroizing::new(unsafe { core::slice::from_raw_parts(out.pbData, length) }.to_vec());
        // SAFETY: the buffer is wiped (it may hold the key) and freed once,
        // with LocalFree as DPAPI requires.
        unsafe {
            core::ptr::write_bytes(out.pbData, 0, length);
            LocalFree(out.pbData.cast());
        }
        Ok(copied)
    }

    /// Removes the stored blob and this profile's TPM key (tests; removing a
    /// profile).
    ///
    /// # Errors
    ///
    /// An I/O or TPM error.
    pub fn delete(&self) -> io::Result<()> {
        match std::fs::remove_file(&self.path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        if let Some(provider) = Self::tpm()
            && let Some(key) = self.tpm_key(&provider, false)?
        {
            let mut key = key;
            // SAFETY: valid key handle; NCryptDeleteKey frees it, so the
            // handle is cleared to keep Drop from freeing it twice.
            hresult(unsafe { NCryptDeleteKey(key.0, NCRYPT_SILENT_FLAG) })?;
            key.0 = 0;
        }
        Ok(())
    }
}

impl Dpapi {
    /// What protects the stored key (after [`Self::load`] or [`Self::store`]).
    #[must_use]
    pub fn protection(&self) -> KeyProtection {
        self.protection
            .lock()
            .map_or(KeyProtection::Dpapi, |current| *current)
    }

    /// The stored key, or `None` if none is stored.
    ///
    /// # Errors
    ///
    /// The store is unavailable or refused (never "no key").
    pub fn load(&self) -> io::Result<Option<Zeroizing<[u8; 32]>>> {
        let mut file = match std::fs::File::open(&self.path) {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        let mut sealed = Vec::new();
        (&mut file).take(MAX_BLOB).read_to_end(&mut sealed)?;
        let payload = self.dpapi(&sealed, false)?;
        let (&format, rest) = payload
            .split_first()
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "empty key blob"))?;
        let plain = match format {
            RAW => Zeroizing::new(rest.to_vec()),
            TPM_WRAPPED => {
                let provider =
                    Self::tpm().ok_or_else(|| io::Error::other("the TPM is unavailable"))?;
                let key = self.tpm_key(&provider, false)?.ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "the TPM key is gone")
                })?;
                Self::tpm_crypt(&key, rest, false)?
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unknown key blob format",
                ));
            }
        };
        let key: [u8; 32] = plain.as_slice().try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "the stored key has the wrong size",
            )
        })?;
        self.set_protection(if format == TPM_WRAPPED {
            KeyProtection::Tpm
        } else {
            KeyProtection::Dpapi
        });
        Ok(Some(Zeroizing::new(key)))
    }

    /// Stores `key`; never replaces a stored one.
    ///
    /// # Errors
    ///
    /// `AlreadyExists` if a key is stored; the platform's error.
    pub fn store(&self, key: &[u8; 32]) -> io::Result<()> {
        if self.path.exists() {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        let mut payload = Zeroizing::new(Vec::with_capacity(300));
        let wrapped = Self::tpm()
            .and_then(|provider| self.tpm_key(&provider, true).ok().flatten())
            .and_then(|tpm| Self::tpm_crypt(&tpm, key, true).ok());
        let protection = if let Some(ciphertext) = wrapped {
            payload.push(TPM_WRAPPED);
            payload.extend_from_slice(&ciphertext);
            KeyProtection::Tpm
        } else {
            payload.push(RAW);
            payload.extend_from_slice(key);
            KeyProtection::Dpapi
        };
        let sealed = self.dpapi(&payload, true)?;
        // Written aside, then linked into place: a crash never leaves a
        // torn blob under the real name, and a blob there is never
        // replaced.
        // Unique per writer: concurrent stores never share or delete it.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_nanos());
        let partial = self
            .path
            .with_extension(format!("dpapi.{}.{nanos}.tmp", std::process::id()));
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&partial)?;
        let written = file.write_all(&sealed).and_then(|()| file.sync_all());
        drop(file);
        let linked = written.and_then(|()| std::fs::hard_link(&partial, &self.path));
        let _ = std::fs::remove_file(&partial);
        linked?;
        self.set_protection(protection);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// A key stored is the key loaded, under DPAPI (and the TPM where the
    /// machine has one); a second store is refused.
    #[test]
    fn a_key_round_trips_through_dpapi() -> TestResult {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random)?;
        let state =
            std::env::temp_dir().join(format!("todoke-dpapi-{}", u64::from_le_bytes(random)));
        std::fs::create_dir_all(&state)?;
        let store = Dpapi::new(&state, "0123456789abcdef0123456789abcdef");
        assert!(store.load()?.is_none());
        let key = [0x3c; 32];
        store.store(&key)?;
        let raw = std::fs::read(state.join("storage.key.dpapi"))?;
        assert!(!raw.windows(32).any(|window| window == key));
        assert_eq!(store.load()?.map(|k| *k), Some(key));
        assert!(matches!(
            store.protection(),
            KeyProtection::Dpapi | KeyProtection::Tpm
        ));
        assert_eq!(
            store.store(&[1; 32]).map_err(|e| e.kind()),
            Err(io::ErrorKind::AlreadyExists)
        );
        // Another profile's entropy opens nothing.
        let other = Dpapi::new(&state.join("other"), "fedcba9876543210fedcba9876543210");
        std::fs::create_dir_all(state.join("other"))?;
        std::fs::copy(
            state.join("storage.key.dpapi"),
            state.join("other").join("storage.key.dpapi"),
        )?;
        assert!(other.load().is_err());
        store.delete()?;
        let _ = std::fs::remove_dir_all(&state);
        Ok(())
    }
}
