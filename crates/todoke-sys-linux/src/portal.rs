//! Calls to XDG desktop portals that answer through a request object
//! (`org.freedesktop.portal.Request`): the call returns at once, and the
//! answer (often after the user decides in a dialog) comes as a signal.

use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU32, Ordering};

use zbus::blocking::{Connection, MessageIterator, Proxy};
use zbus::zvariant::{OwnedObjectPath, OwnedValue};

/// The portal service.
pub(crate) const DESKTOP: &str = "org.freedesktop.portal.Desktop";
/// Its object.
pub(crate) const PATH: &str = "/org/freedesktop/portal/desktop";

#[expect(clippy::needless_pass_by_value, reason = "used as map_err(bus)")]
pub(crate) fn bus(error: zbus::Error) -> io::Error {
    io::Error::other(format!("portal: {error}"))
}

/// Whether this process runs in a Flatpak sandbox.
#[must_use]
pub fn sandboxed() -> bool {
    std::path::Path::new("/.flatpak-info").exists()
}

/// A token unique in this process (the request path names the caller too).
pub(crate) fn token() -> String {
    static NEXT: AtomicU32 = AtomicU32::new(0);
    format!(
        "todoke_{}_{}",
        std::process::id(),
        NEXT.fetch_add(1, Ordering::Relaxed)
    )
}

/// The unique bus name of the portal service now: answers and signals are
/// matched against it on the bus and here, so another program cannot
/// answer for the portal.
pub(crate) fn owner(connection: &Connection) -> io::Result<zbus::names::OwnedUniqueName> {
    let name = zbus::names::BusName::try_from(DESKTOP).map_err(|error| bus(error.into()))?;
    zbus::blocking::fdo::DBusProxy::new(connection)
        .map_err(bus)?
        .get_name_owner(name)
        .map_err(|error| bus(error.into()))
}

/// A proxy for `interface` of the portal.
pub(crate) fn proxy<'a>(connection: &'a Connection, interface: &'a str) -> io::Result<Proxy<'a>> {
    Proxy::new(connection, DESKTOP, PATH, interface).map_err(bus)
}

/// Calls `call` with a handle token and waits for the request's answer.
/// Blocks until the portal answers (maybe after a dialog): call it off the
/// UI thread.
///
/// # Errors
///
/// The bus's error; `PermissionDenied` when the user (or the portal)
/// refused; `Interrupted` when the request ended another way.
pub(crate) fn request(
    connection: &Connection,
    call: impl FnOnce(&str) -> zbus::Result<OwnedObjectPath>,
) -> io::Result<HashMap<String, OwnedValue>> {
    let token = token();
    let sender = connection
        .unique_name()
        .ok_or_else(|| io::Error::other("portal: no bus name"))?
        .trim_start_matches(':')
        .replace('.', "_");
    let path = format!("{PATH}/request/{sender}/{token}");
    // Listen before calling: the answer may come before the call returns.
    let rule = zbus::MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .sender(owner(connection)?)
        .map_err(bus)?
        .interface("org.freedesktop.portal.Request")
        .map_err(bus)?
        .member("Response")
        .map_err(bus)?
        .path(path.as_str())
        .map_err(bus)?
        .build();
    let answers = MessageIterator::for_match_rule(rule, connection, Some(4)).map_err(bus)?;
    let handle = call(&token).map_err(bus)?;
    if handle.as_str() != path {
        // A portal older than the handle_token option: the answer comes on
        // the path it returned, which this does not follow.
        return Err(io::Error::other(
            "portal: the request path is not the one asked for",
        ));
    }
    let mut answers = answers;
    let message = answers
        .next()
        .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?
        .map_err(bus)?;
    let (code, results): (u32, HashMap<String, OwnedValue>) =
        message.body().deserialize().map_err(bus)?;
    match code {
        0 => Ok(results),
        1 => Err(io::ErrorKind::PermissionDenied.into()),
        _ => Err(io::ErrorKind::Interrupted.into()),
    }
}
