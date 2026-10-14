//! The Share target (MSIX): Windows starts the app with share activation;
//! the files shared become a "Send to…" request. The share sheet closes as
//! soon as the paths are taken; the window asks who to send them to.

use std::path::PathBuf;

use windows::ApplicationModel::Activation::{ActivationKind, ShareTargetActivatedEventArgs};
use windows::ApplicationModel::AppInstance;
use windows::ApplicationModel::DataTransfer::StandardDataFormats;
use windows::core::Interface as _;

use crate::package;

/// The files shared, when this launch is a share activation; `None`
/// otherwise (and always when unpackaged).
#[must_use]
pub fn shared_files() -> Option<Vec<PathBuf>> {
    if !package::packaged() {
        return None;
    }
    let activated = AppInstance::GetActivatedEventArgs().ok()?;
    if activated.Kind().ok()? != ActivationKind::ShareTarget {
        return None;
    }
    let share = activated
        .cast::<ShareTargetActivatedEventArgs>()
        .ok()?
        .ShareOperation()
        .ok()?;
    let data = share.Data().ok()?;
    let mut paths = Vec::new();
    if data
        .Contains(&StandardDataFormats::StorageItems().ok()?)
        .unwrap_or(false)
        && let Ok(items) = data.GetStorageItemsAsync().and_then(|op| op.join())
    {
        for item in &items {
            if let Ok(path) = item.Path() {
                // Items without a path (virtual ones) cannot be sent.
                if !path.is_empty() {
                    paths.push(PathBuf::from(path.to_os_string()));
                }
            }
        }
    }
    let _ = share.ReportCompleted();
    Some(paths)
}
