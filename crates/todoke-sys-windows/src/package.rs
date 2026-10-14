//! Whether todoke runs from its MSIX package: the package declares the
//! login task, the Explorer command, and the Share target; an unpackaged
//! install (Scoop, a zip) registers per-user equivalents itself.

use windows::ApplicationModel::Package;

/// Whether this process has package identity.
#[must_use]
pub fn packaged() -> bool {
    Package::Current().is_ok()
}
