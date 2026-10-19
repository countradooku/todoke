//! Calls to XDG desktop portals that answer through a request object
//! (`org.freedesktop.portal.Request`): the call returns at once, and the
//! answer (often after the user decides in a dialog) comes as a signal.
//!
//! Like the rest of this crate, these are zbus's async calls, run to
//! completion by one `zbus::block_on` in each public function.

use core::num::NonZeroUsize;
use core::pin::Pin;
use std::collections::HashMap;
use std::io;
use std::sync::atomic::{AtomicU32, Ordering};

use futures_core::Stream as _;
use zbus::{Connection, Message, MessageStream, OwnedObjectPath, OwnedVariant, Proxy};

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

/// The unique bus name that owns `name` now: answers and signals are
/// matched against it on the bus and here, so another program cannot
/// answer for that service.
pub(crate) async fn owner_of(
    connection: &Connection,
    name: &str,
) -> zbus::Result<zbus::names::OwnedUniqueName> {
    let name = zbus::names::BusName::try_from(name)?;
    zbus::fdo::DBusProxy::new(connection)
        .await?
        .get_name_owner(name)
        .await
        .map_err(zbus::Error::from)
}

/// The unique bus name of the portal service now.
pub(crate) async fn owner(connection: &Connection) -> io::Result<zbus::names::OwnedUniqueName> {
    owner_of(connection, DESKTOP).await.map_err(bus)
}

/// A proxy for `interface` of the portal.
pub(crate) async fn proxy<'a>(
    connection: &'a Connection,
    interface: &'a str,
) -> io::Result<Proxy<'a>> {
    Proxy::new(connection, DESKTOP, PATH, interface)
        .await
        .map_err(bus)
}

/// The signals that match `rule`, at most `queued` waiting.
pub(crate) async fn signals(
    connection: &Connection,
    rule: zbus::match_rule::Builder<'_>,
    queued: usize,
) -> zbus::Result<MessageStream> {
    MessageStream::for_match_rule(rule.build()?, connection, NonZeroUsize::new(queued)).await
}

/// The next message of `stream`; `None` once it ends.
pub(crate) async fn next(stream: &mut MessageStream) -> Option<zbus::Result<Message>> {
    core::future::poll_fn(|cx| Pin::new(&mut *stream).poll_next(cx)).await
}

/// Calls `call` with a handle token and waits for the request's answer,
/// which may come after a dialog.
///
/// # Errors
///
/// The bus's error; `PermissionDenied` when the user (or the portal)
/// refused; `Interrupted` when the request ended another way.
pub(crate) async fn request(
    connection: &Connection,
    call: impl AsyncFnOnce(&str) -> zbus::Result<OwnedObjectPath>,
) -> io::Result<HashMap<String, OwnedVariant>> {
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
        .sender(owner(connection).await?)
        .interface("org.freedesktop.portal.Request")
        .member("Response")
        .path(path.as_str());
    let mut answers = signals(connection, rule, 4).await.map_err(bus)?;
    let handle = call(&token).await.map_err(bus)?;
    if handle.as_str() != path {
        // A portal older than the handle_token option: the answer comes on
        // the path it returned, which this does not follow.
        return Err(io::Error::other(
            "portal: the request path is not the one asked for",
        ));
    }
    let message = next(&mut answers)
        .await
        .ok_or_else(|| io::Error::from(io::ErrorKind::UnexpectedEof))?
        .map_err(bus)?;
    let (code, results): (u32, HashMap<String, OwnedVariant>) =
        message.body().deserialize().map_err(bus)?;
    match code {
        0 => Ok(results),
        1 => Err(io::ErrorKind::PermissionDenied.into()),
        _ => Err(io::ErrorKind::Interrupted.into()),
    }
}
