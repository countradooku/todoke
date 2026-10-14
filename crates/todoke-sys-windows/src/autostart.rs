//! Starting todoke when the user logs in, without admin rights: the
//! package's startup task (MSIX), or this user's `Run` key. Both honor the
//! user's choice in Task Manager's Startup apps.

use std::io;
use std::path::PathBuf;

use windows::ApplicationModel::{StartupTask, StartupTaskState};
use windows::core::HSTRING;
use windows_registry::CURRENT_USER;

use crate::package;

const RUN: &str = r"Software\Microsoft\Windows\CurrentVersion\Run";
const APPROVED: &str = r"Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run";
const NAME: &str = "todoke";
/// The `TaskId` the package manifest declares.
const TASK: &str = "todoke";

#[expect(clippy::needless_pass_by_value, reason = "used as map_err(os)")]
fn os(error: windows::core::Error) -> io::Error {
    io::Error::other(format!("Windows error {:#010x}", error.code().0))
}

/// The login item of the app at `exec`.
#[derive(Debug)]
pub struct Autostart {
    exec: PathBuf,
}

impl Autostart {
    /// The login item that starts `exec` (used when unpackaged).
    #[must_use]
    pub fn new(exec: PathBuf) -> Self {
        Self { exec }
    }

    fn command(&self) -> String {
        format!("\"{}\" --background", self.exec.display())
    }

    fn task() -> io::Result<StartupTask> {
        StartupTask::GetAsync(&HSTRING::from(TASK))
            .and_then(|operation| operation.join())
            .map_err(os)
    }

    /// Whether todoke starts at login.
    ///
    /// # Errors
    ///
    /// The system's error.
    pub fn enabled(&self) -> io::Result<bool> {
        if package::packaged() {
            let state = Self::task()?.State().map_err(os)?;
            return Ok(matches!(
                state,
                StartupTaskState::Enabled | StartupTaskState::EnabledByPolicy
            ));
        }
        let Ok(run) = CURRENT_USER.open(RUN) else {
            return Ok(false);
        };
        if run.get_string(NAME).ok().as_deref() != Some(self.command().as_str()) {
            return Ok(false);
        }
        // Task Manager turns an item off with an odd first byte here.
        let off = CURRENT_USER
            .open(APPROVED)
            .and_then(|approved| approved.get_value(NAME))
            .is_ok_and(|value| value.first().is_some_and(|byte| byte & 1 == 1));
        Ok(!off)
    }

    /// Starts todoke at login, or stops doing so.
    ///
    /// # Errors
    ///
    /// The system's error; `PermissionDenied` when the user or a policy
    /// turned the task off (only Task Manager turns it back on).
    pub fn set(&self, on: bool) -> io::Result<()> {
        if package::packaged() {
            let task = Self::task()?;
            if !on {
                return task.Disable().map_err(os);
            }
            let state = task
                .RequestEnableAsync()
                .and_then(|op| op.join())
                .map_err(os)?;
            return match state {
                StartupTaskState::Enabled | StartupTaskState::EnabledByPolicy => Ok(()),
                _ => Err(io::ErrorKind::PermissionDenied.into()),
            };
        }
        let run = CURRENT_USER.create(RUN).map_err(os)?;
        if on {
            run.set_string(NAME, self.command()).map_err(os)?;
            // A choice made in Task Manager before would keep it off.
            if let Ok(approved) = CURRENT_USER.open(APPROVED) {
                let _ = approved.remove_value(NAME);
            }
            Ok(())
        } else {
            match run.remove_value(NAME) {
                Ok(()) => Ok(()),
                Err(error)
                    if error.code()
                        == windows::Win32::Foundation::ERROR_FILE_NOT_FOUND.to_hresult() =>
                {
                    Ok(())
                }
                Err(error) => Err(os(error)),
            }
        }
    }
}
