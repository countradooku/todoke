//! The COM server: `DllGetClassObject`, a class factory, and the command.

#![allow(
    unsafe_code,
    reason = "COM exports and shell calls; each block is justified"
)]
#![allow(
    clippy::ref_as_ptr,
    clippy::inline_always,
    reason = "in the code windows' implement macro generates"
)]

use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicPtr, AtomicUsize, Ordering};

use windows::Win32::Foundation::{
    CLASS_E_CLASSNOTAVAILABLE, CLASS_E_NOAGGREGATION, E_NOTIMPL, E_POINTER, HINSTANCE, HMODULE,
    S_FALSE, S_OK,
};
use windows::Win32::System::Com::{CoTaskMemFree, IBindCtx, IClassFactory, IClassFactory_Impl};
use windows::Win32::System::LibraryLoader::GetModuleFileNameW;
use windows::Win32::System::SystemServices::DLL_PROCESS_ATTACH;
use windows::Win32::UI::Shell::{
    ECF_DEFAULT, ECS_ENABLED, IEnumExplorerCommand, IExplorerCommand, IExplorerCommand_Impl,
    IShellItemArray, SHStrDupW, SIGDN_FILESYSPATH,
};
use windows_core::{BOOL, GUID, HRESULT, IUnknown, Interface as _, PCWSTR, PWSTR, Ref, implement};

/// The command's class ID.
pub const CLSID: GUID = GUID::from_u128(0x346A_1ED9_A65C_4480_B1DE_A792_C182_93C8);

/// This DLL's module handle, from `DllMain`.
static MODULE: AtomicPtr<core::ffi::c_void> = AtomicPtr::new(core::ptr::null_mut());

/// Commands alive and server locks held: the surrogate may unload this DLL
/// (and an upgrade replace it) only when both are none.
static OBJECTS: AtomicUsize = AtomicUsize::new(0);
static LOCKS: AtomicUsize = AtomicUsize::new(0);

/// At most this many items are handed over (the app's own limit).
const MAX_ITEMS: u32 = 10_000;

/// Records the module handle when the DLL is loaded.
///
/// # Safety
///
/// Called by the loader only.
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllMain(
    module: HINSTANCE,
    reason: u32,
    _reserved: *mut core::ffi::c_void,
) -> BOOL {
    if reason == DLL_PROCESS_ATTACH {
        MODULE.store(module.0, Ordering::Relaxed);
    }
    BOOL::from(true)
}

/// Hands out the class factory of [`CLSID`].
///
/// # Safety
///
/// Called by COM with valid pointers (checked for null).
#[unsafe(no_mangle)]
pub unsafe extern "system" fn DllGetClassObject(
    class: *const GUID,
    interface: *const GUID,
    object: *mut *mut core::ffi::c_void,
) -> HRESULT {
    if class.is_null() || interface.is_null() || object.is_null() {
        return E_POINTER;
    }
    // SAFETY: checked non-null; COM passes writable out pointers.
    unsafe { *object = core::ptr::null_mut() };
    // SAFETY: checked non-null; COM passes a valid GUID.
    if unsafe { *class } != CLSID {
        return CLASS_E_CLASSNOTAVAILABLE;
    }
    let factory: IClassFactory = Factory.into();
    // SAFETY: valid interface ID and out pointer, as above.
    unsafe { factory.query(interface, object) }
}

/// The DLL may unload once no command is alive and no lock is held.
#[unsafe(no_mangle)]
pub extern "system" fn DllCanUnloadNow() -> HRESULT {
    if OBJECTS.load(Ordering::SeqCst) == 0 && LOCKS.load(Ordering::SeqCst) == 0 {
        S_OK
    } else {
        S_FALSE
    }
}

#[implement(IClassFactory)]
struct Factory;

impl IClassFactory_Impl for Factory_Impl {
    fn CreateInstance(
        &self,
        outer: Ref<IUnknown>,
        interface: *const GUID,
        object: *mut *mut core::ffi::c_void,
    ) -> windows_core::Result<()> {
        if object.is_null() || interface.is_null() {
            return Err(E_POINTER.into());
        }
        // SAFETY: checked non-null; COM passes a writable out pointer.
        unsafe { *object = core::ptr::null_mut() };
        if outer.is_some() {
            return Err(CLASS_E_NOAGGREGATION.into());
        }
        let command: IExplorerCommand = SendCommand::new().into();
        // SAFETY: valid interface ID and out pointer, as above.
        unsafe { command.query(interface, object) }.ok()
    }

    fn LockServer(&self, lock: BOOL) -> windows_core::Result<()> {
        if lock.as_bool() {
            LOCKS.fetch_add(1, Ordering::SeqCst);
        } else {
            // Never below zero, whatever a caller does.
            let mut held = LOCKS.load(Ordering::SeqCst);
            while held > 0 {
                match LOCKS.compare_exchange_weak(
                    held,
                    held - 1,
                    Ordering::SeqCst,
                    Ordering::SeqCst,
                ) {
                    Ok(_) => break,
                    Err(now) => held = now,
                }
            }
        }
        Ok(())
    }
}

#[implement(IExplorerCommand)]
struct SendCommand(());

impl SendCommand {
    /// A command, counted until it is dropped.
    fn new() -> Self {
        OBJECTS.fetch_add(1, Ordering::SeqCst);
        Self(())
    }
}

impl Drop for SendCommand {
    fn drop(&mut self) {
        OBJECTS.fetch_sub(1, Ordering::SeqCst);
    }
}

/// A string the shell frees (`CoTaskMemFree`).
fn shell_string(text: &str) -> windows_core::Result<PWSTR> {
    let wide: Vec<u16> = text.encode_utf16().chain(core::iter::once(0)).collect();
    // SAFETY: a NUL-terminated UTF-16 string that outlives the call; the
    // copy is the caller's to free.
    unsafe { SHStrDupW(PCWSTR(wide.as_ptr())) }
}

/// This DLL's directory, where the package puts the app too.
fn directory() -> Option<PathBuf> {
    let module = HMODULE(MODULE.load(Ordering::Relaxed));
    if module.0.is_null() {
        return None;
    }
    let mut buffer = vec![0_u16; 32_768];
    // SAFETY: the module handle is this DLL's; the buffer is writable for
    // its length.
    let length = unsafe { GetModuleFileNameW(Some(module), &mut buffer) } as usize;
    if length == 0 || length >= buffer.len() {
        return None;
    }
    let path = PathBuf::from(String::from_utf16(&buffer[..length]).ok()?);
    path.parent().map(Path::to_path_buf)
}

/// The paths as `--send-stdin` reads them: UTF-8, each ended by a NUL.
#[must_use]
pub fn paths_message(paths: &[PathBuf]) -> Vec<u8> {
    let mut message = Vec::new();
    for path in paths {
        if let Some(text) = path.to_str() {
            message.extend_from_slice(text.as_bytes());
            message.push(0);
        }
    }
    message
}

/// The file-system paths of `items` (virtual items have none).
fn paths(items: &IShellItemArray) -> windows_core::Result<Vec<PathBuf>> {
    // SAFETY: a live array Explorer passed in.
    let count = unsafe { items.GetCount() }?.min(MAX_ITEMS);
    let mut paths = Vec::new();
    for index in 0..count {
        // SAFETY: the index is below the count.
        let item = unsafe { items.GetItemAt(index) }?;
        // SAFETY: a live item; the string returned is ours to free.
        let Ok(name) = (unsafe { item.GetDisplayName(SIGDN_FILESYSPATH) }) else {
            continue;
        };
        // SAFETY: the shell returns a NUL-terminated string.
        let text = unsafe { name.to_string() };
        // SAFETY: allocated by the shell with the COM allocator; freed once.
        unsafe { CoTaskMemFree(Some(name.0.cast_const().cast())) };
        if let Ok(text) = text {
            paths.push(PathBuf::from(text));
        }
    }
    Ok(paths)
}

impl IExplorerCommand_Impl for SendCommand_Impl {
    fn GetTitle(&self, _items: Ref<IShellItemArray>) -> windows_core::Result<PWSTR> {
        shell_string("Send with todoke")
    }

    fn GetIcon(&self, _items: Ref<IShellItemArray>) -> windows_core::Result<PWSTR> {
        let app = directory()
            .map(|dir| dir.join("todoke-desktop.exe"))
            .ok_or_else(|| windows_core::Error::from(E_NOTIMPL))?;
        shell_string(&format!("{},0", app.display()))
    }

    fn GetToolTip(&self, _items: Ref<IShellItemArray>) -> windows_core::Result<PWSTR> {
        Err(E_NOTIMPL.into())
    }

    fn GetCanonicalName(&self) -> windows_core::Result<GUID> {
        Ok(CLSID)
    }

    fn GetState(&self, _items: Ref<IShellItemArray>, _slow: BOOL) -> windows_core::Result<u32> {
        Ok(u32::try_from(ECS_ENABLED.0).unwrap_or_default())
    }

    fn Invoke(
        &self,
        items: Ref<IShellItemArray>,
        _bind: Ref<IBindCtx>,
    ) -> windows_core::Result<()> {
        let items = items.ok()?;
        let paths = paths(items)?;
        if paths.is_empty() {
            return Ok(());
        }
        let app = directory()
            .map(|dir| dir.join("todoke-desktop.exe"))
            .ok_or_else(|| windows_core::Error::from(E_NOTIMPL))?;
        let mut child = Command::new(app)
            .arg("--send-stdin")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|_| windows_core::Error::from(E_NOTIMPL))?;
        if let Some(mut stdin) = child.stdin.take() {
            // The app reads until the pipe closes (dropping it).
            let _ = stdin.write_all(&paths_message(&paths));
        }
        Ok(())
    }

    fn GetFlags(&self) -> windows_core::Result<u32> {
        Ok(u32::try_from(ECF_DEFAULT.0).unwrap_or_default())
    }

    fn EnumSubCommands(&self) -> windows_core::Result<IEnumExplorerCommand> {
        Err(E_NOTIMPL.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths_are_nul_terminated_utf8() {
        let message = paths_message(&[PathBuf::from(r"C:\a b"), PathBuf::from(r"D:\c")]);
        assert_eq!(message, b"C:\\a b\0D:\\c\0");
    }
}
