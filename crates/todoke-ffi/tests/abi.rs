//! The C entry points `BoltFFI` generates, called as Swift, Kotlin, or JNI
//! glue call them: buffers returned and freed, records decoded from foreign
//! bytes, errors encoded. CI runs this under Miri (it reaches no C crypto:
//! every settings input here is refused before a core starts).

#![allow(
    unsafe_code,
    reason = "calling the exported C ABI is the point of this test"
)]

// Links the library, whose exported entry points the calls below reach.
use todoke_ffi as _;

/// `BoltFFI`'s buffer: its own type, so the calls below match the exported
/// signatures exactly (the generated headers declare the same layout).
use boltffi::__private::FfiBuf as Buf;

unsafe extern "C" {
    fn boltffi_free_buf(buf: Buf);
    fn boltffi_method_class_todoke_ffi_engine_core_version() -> Buf;
    fn boltffi_init_class_todoke_ffi_engine_core_new(
        settings_ptr: *const u8,
        settings_len: usize,
        return_out: *mut u64,
    ) -> Buf;
}

#[test]
fn the_version_crosses_as_a_buffer_and_is_freed() {
    // SAFETY: no arguments; the returned buffer is ours to free once.
    let buf = unsafe { boltffi_method_class_todoke_ffi_engine_core_version() };
    assert!(!buf.as_ptr().is_null());
    assert!(!buf.is_empty() && buf.len() <= buf.cap());
    // SAFETY: the buffer's initialised bytes, read while it lives.
    let bytes = unsafe { buf.as_byte_slice() };
    assert!(
        bytes
            .windows(env!("CARGO_PKG_VERSION").len())
            .any(|w| w == env!("CARGO_PKG_VERSION").as_bytes())
    );
    // SAFETY: a buffer the library returned, freed once.
    unsafe { boltffi_free_buf(buf) };
}

#[test]
fn malformed_settings_bytes_are_refused_without_a_core() {
    let inputs: [&[u8]; 5] = [
        &[],
        &[0],
        &[0xff; 3],
        &[8, 0, 0, 0, b'r', b'e', b'l'],
        &[0x7f, 0xff, 0xff, 0xff, 0, 1, 2, 3, 4, 5, 6, 7],
    ];
    for input in inputs {
        let mut handle = 0_u64;
        // SAFETY: a valid pointer and length for `input`, and a writable
        // out slot; the returned error buffer is ours to free.
        let error = unsafe {
            boltffi_init_class_todoke_ffi_engine_core_new(
                input.as_ptr(),
                input.len(),
                &raw mut handle,
            )
        };
        // No core comes of it (the generated bindings encode settings
        // themselves; only broken glue sends bytes like these).
        assert_eq!(handle, 0, "{input:?} made a core");
        // SAFETY: a buffer the library returned (an error, or empty), freed
        // once.
        unsafe { boltffi_free_buf(error) };
    }
}
