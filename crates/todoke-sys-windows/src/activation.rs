//! How Windows started the packaged app (MSIX): by the startup task at
//! login (which cannot pass `--background`), by the Share sheet with
//! files, or otherwise. Shared files become a "Send to…" request; the
//! share sheet closes as soon as their paths are taken.

use std::path::PathBuf;

use windows::ApplicationModel::Activation::{ActivationKind, ShareTargetActivatedEventArgs};
use windows::ApplicationModel::AppInstance;
use windows::ApplicationModel::DataTransfer::StandardDataFormats;
use windows::core::Interface as _;

use crate::package;

/// How this launch was activated.
#[derive(Debug, PartialEq, Eq)]
pub enum Activation {
    /// By the startup task at login: start in the background.
    Startup,
    /// By the Share sheet, with the files shared (those with a path).
    Share(Vec<PathBuf>),
    /// Any other way (and always when unpackaged).
    Other,
}

/// How this launch was activated.
#[must_use]
pub fn activation() -> Activation {
    if !package::packaged() {
        return Activation::Other;
    }
    let Ok(activated) = AppInstance::GetActivatedEventArgs() else {
        return Activation::Other;
    };
    match activated.Kind() {
        Ok(ActivationKind::StartupTask) => Activation::Startup,
        Ok(ActivationKind::ShareTarget) => activated
            .cast::<ShareTargetActivatedEventArgs>()
            .map_or(Activation::Other, |share| Activation::Share(shared(&share))),
        _ => Activation::Other,
    }
}

fn shared(activated: &ShareTargetActivatedEventArgs) -> Vec<PathBuf> {
    let Ok(share) = activated.ShareOperation() else {
        return Vec::new();
    };
    let mut paths = Vec::new();
    if let Ok(data) = share.Data()
        && let Ok(kind) = StandardDataFormats::StorageItems()
        && data.Contains(&kind).unwrap_or(false)
        && let Ok(items) = data.GetStorageItemsAsync().and_then(|op| op.join())
    {
        for item in &items {
            // Items without a path (virtual ones) cannot be sent.
            if let Ok(path) = item.Path()
                && !path.is_empty()
            {
                paths.push(PathBuf::from(path.to_os_string()));
            }
        }
    }
    let _ = share.ReportCompleted();
    paths
}
