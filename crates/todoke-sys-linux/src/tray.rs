//! Whether a `StatusNotifierItem` host runs: a tray item registered without
//! one shows nowhere (GNOME without the `AppIndicator` extension), and an app
//! that keeps running with its window closed would be lost to the user.

use zbus::blocking::{Connection, Proxy};

/// Whether the session has a `StatusNotifierWatcher` with a host registered.
#[must_use]
pub fn host_available() -> bool {
    let Ok(connection) = Connection::session() else {
        return false;
    };
    let Ok(watcher) = Proxy::new(
        &connection,
        "org.kde.StatusNotifierWatcher",
        "/StatusNotifierWatcher",
        "org.kde.StatusNotifierWatcher",
    ) else {
        return false;
    };
    watcher
        .get_property::<bool>("IsStatusNotifierHostRegistered")
        .unwrap_or(false)
}
