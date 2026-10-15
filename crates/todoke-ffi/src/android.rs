//! The Android release the core runs on, which decides how files are
//! published (`todoke_fs::platform`): an app's seccomp filter kills the
//! process on a system call it does not allow, so `renameat2` is used only
//! where the release is known to allow it.
//!
//! Unsafe code: one call to bionic's `__system_property_get`, which every
//! Android release has.

#![allow(
    unsafe_code,
    reason = "reading a system property is a C call; the block states why it is sound"
)]

use std::ffi::{c_char, c_int};

/// The longest property value, its terminating NUL included
/// (`PROP_VALUE_MAX` in `<sys/system_properties.h>`).
const PROP_VALUE_MAX: usize = 92;

unsafe extern "C" {
    /// Copies the value of the property `name` into `value` (at most
    /// `PROP_VALUE_MAX` bytes, NUL included) and returns its length, 0
    /// when the property is not set.
    fn __system_property_get(name: *const c_char, value: *mut c_char) -> c_int;
}

/// Tells the file layer the device's API level, once per process.
pub(crate) fn record_api_level() {
    static ONCE: std::sync::Once = std::sync::Once::new();
    ONCE.call_once(|| {
        if let Some(level) = api_level() {
            todoke_fs::platform::set_android_api_level(level);
        }
    });
}

/// The device's API level (`ro.build.version.sdk`), if it reads as one.
fn api_level() -> Option<u32> {
    let mut value = [0_u8; PROP_VALUE_MAX];
    // SAFETY: the name is a NUL-terminated literal, and `value` has room
    // for the most the call writes (PROP_VALUE_MAX bytes, NUL included);
    // both outlive the call, which keeps neither pointer.
    let length = unsafe {
        __system_property_get(
            c"ro.build.version.sdk".as_ptr(),
            value.as_mut_ptr().cast::<c_char>(),
        )
    };
    let length = usize::try_from(length)
        .ok()
        .filter(|&length| length < PROP_VALUE_MAX)?;
    std::str::from_utf8(value.get(..length)?).ok()?.parse().ok()
}

#[cfg(test)]
mod tests {
    /// Android 7 is the oldest the app supports.
    #[test]
    fn the_api_level_reads_as_a_release() {
        assert!(super::api_level().is_some_and(|level| level >= 24));
    }
}
