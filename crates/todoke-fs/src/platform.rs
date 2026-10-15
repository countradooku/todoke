//! What this crate needs to know about the platform and cannot find out
//! safely by itself.
//!
//! **Android and `renameat2`.** A system call that the app seccomp filter
//! does not allow kills the process, and no call can ask the filter. The
//! filter allows what bionic's `SYSCALLS.TXT` lists for that release, and
//! bionic added `renameat2` there in Android 11 (API level 30); P16 checked
//! it on Android 16. So rename-without-replace is used only once the app
//! has told this crate the device's API level ([`set_android_api_level`],
//! which `todoke-ffi` does when the core starts) and that level is 30 or
//! more. Until then, publication links or copies instead (and apps cannot
//! link: Android's security policy refuses them hard links in their own
//! data, so on Android before 11 publication copies).

#[cfg(target_os = "android")]
use core::sync::atomic::{AtomicU32, Ordering};

/// The device's Android API level, 0 until it is known.
#[cfg(target_os = "android")]
static ANDROID_API_LEVEL: AtomicU32 = AtomicU32::new(0);

/// The first Android API level whose app seccomp filter allows `renameat2`.
#[cfg(target_os = "android")]
const ANDROID_RENAMEAT2: u32 = 30;

/// Records the device's Android API level (`ro.build.version.sdk`).
#[cfg(target_os = "android")]
pub fn set_android_api_level(level: u32) {
    ANDROID_API_LEVEL.store(level, Ordering::Relaxed);
}

/// Whether this process may rename without replacing
/// (`renameat2(RENAME_NOREPLACE)`, `renameatx_np(RENAME_EXCL)`). The file
/// system may still not support it, which the call itself reports.
#[must_use]
pub fn rename_noreplace() -> bool {
    #[cfg(target_os = "android")]
    {
        ANDROID_API_LEVEL.load(Ordering::Relaxed) >= ANDROID_RENAMEAT2
    }
    #[cfg(not(target_os = "android"))]
    {
        true
    }
}
