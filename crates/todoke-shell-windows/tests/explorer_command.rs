//! Drives the installed Explorer command the way Explorer does: activates
//! it through COM (the package's surrogate), and invokes it on a file. Run
//! in CI after the MSIX is installed and the app is running with
//! `TODOKE_HANDOFF_LOG` set; the job then checks the log. Elsewhere (no
//! `TODOKE_SHELL_E2E_FILE`) it does nothing.

#![cfg(windows)]
#![allow(unsafe_code, reason = "COM calls, as Explorer makes them")]

use windows::Win32::System::Com::{
    CLSCTX_LOCAL_SERVER, COINIT_APARTMENTTHREADED, CoCreateInstance, CoInitializeEx,
};
use windows::Win32::UI::Shell::{
    IExplorerCommand, IShellItem, IShellItemArray, SHCreateItemFromParsingName,
    SHCreateShellItemArrayFromShellItem,
};
use windows_core::HSTRING;

#[test]
fn the_installed_command_hands_a_file_to_the_app() -> windows_core::Result<()> {
    let Some(file) = std::env::var_os("TODOKE_SHELL_E2E_FILE") else {
        return Ok(());
    };
    let file = HSTRING::from(file.as_os_str());
    // SAFETY: once per test thread, before any COM call.
    unsafe { CoInitializeEx(None, COINIT_APARTMENTTHREADED) }.ok()?;
    // SAFETY: the class the package registers; out-of-process.
    let command: IExplorerCommand =
        unsafe { CoCreateInstance(&todoke_shell::CLSID, None, CLSCTX_LOCAL_SERVER) }?;
    // SAFETY: a NUL-terminated path; no bind context.
    let item: IShellItem = unsafe { SHCreateItemFromParsingName(&file, None) }?;
    // SAFETY: a live item.
    let items: IShellItemArray = unsafe { SHCreateShellItemArrayFromShellItem(&item) }?;
    // SAFETY: live interfaces, as Explorer passes them.
    let title = unsafe { command.GetTitle(&items) }?;
    // SAFETY: the command returns a NUL-terminated string.
    let title = unsafe { title.to_string() }.unwrap_or_default();
    assert_eq!(title, "Send with todoke");
    // SAFETY: as above; no bind context.
    unsafe { command.Invoke(&items, None) }
}
