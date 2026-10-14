//! Starting todoke when the user logs in: a launch agent inside the bundle
//! (`Contents/Library/LaunchAgents/org.todoke.todoke.agent.plist`, starting
//! `todoke-desktop --background`), registered with `SMAppService` (macOS
//! 13). The user sees it in System Settings → General → Login Items, and
//! can turn it off there. No admin rights.
//!
//! The only unsafe code is the `ServiceManagement` calls below; each block
//! says why it is sound.

#![allow(
    unsafe_code,
    reason = "ServiceManagement calls; each block is justified"
)]

use std::io;

use objc2::rc::Retained;
use objc2_foundation::NSString;
use objc2_service_management::{SMAppService, SMAppServiceStatus};

/// The agent's property list in the bundle.
const PLIST: &str = "org.todoke.todoke.agent.plist";

/// Whether todoke starts at login.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    /// It does.
    On,
    /// It does not.
    Off,
    /// It is registered, and waits for the user's approval in System
    /// Settings.
    NeedsApproval,
    /// Not available: not running from the app bundle.
    Unavailable,
}

fn agent() -> Retained<SMAppService> {
    // SAFETY: a class method taking a string; it returns a service object
    // whether or not the plist exists (status says which).
    unsafe { SMAppService::agentServiceWithPlistName(&NSString::from_str(PLIST)) }
}

/// The login item's state.
#[must_use]
pub fn state() -> State {
    // SAFETY: reads the service's status; no preconditions.
    let status = unsafe { agent().status() };
    match status {
        SMAppServiceStatus::Enabled => State::On,
        SMAppServiceStatus::NotRegistered => State::Off,
        SMAppServiceStatus::RequiresApproval => State::NeedsApproval,
        _ => State::Unavailable,
    }
}

/// Registers or unregisters the login item.
///
/// # Errors
///
/// `Unsupported` outside the bundle; the system's error.
pub fn set(on: bool) -> io::Result<()> {
    if state() == State::Unavailable {
        return Err(io::ErrorKind::Unsupported.into());
    }
    let agent = agent();
    // SAFETY: register and unregister take no arguments; errors come back
    // as values.
    let done = unsafe {
        if on {
            agent.registerAndReturnError()
        } else {
            agent.unregisterAndReturnError()
        }
    };
    done.map_err(|error| io::Error::other(format!("login item: {error}")))
}

/// Opens System Settings at Login Items, where the user approves it.
pub fn open_settings() {
    // SAFETY: a class method with no arguments.
    unsafe { SMAppService::openSystemSettingsLoginItems() };
}
