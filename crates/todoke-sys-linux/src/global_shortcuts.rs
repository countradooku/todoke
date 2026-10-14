//! A global shortcut on Wayland, through the `GlobalShortcuts` portal (KDE
//! Plasma, GNOME 48 and later): the desktop asks the user to confirm it and
//! lets them choose the keys; this process never sees other keystrokes.

use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use zbus::blocking::{Connection, MessageIterator, Proxy};
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};

use crate::portal;

const INTERFACE: &str = "org.freedesktop.portal.GlobalShortcuts";

/// A bound shortcut; dropping it releases it.
pub struct GlobalShortcut {
    connection: Connection,
    session: OwnedObjectPath,
    stopped: Arc<AtomicBool>,
}

impl core::fmt::Debug for GlobalShortcut {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("GlobalShortcut")
            .field("session", &self.session.as_str())
            .finish_non_exhaustive()
    }
}

impl Drop for GlobalShortcut {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::SeqCst);
        if let Ok(session) = Proxy::new(
            &self.connection,
            portal::DESKTOP,
            self.session.as_str(),
            "org.freedesktop.portal.Session",
        ) {
            let _: Result<(), _> = session.call("Close", &());
        }
    }
}

/// Whether the session has the portal (so `bind` can work).
#[must_use]
pub fn available() -> bool {
    let Ok(connection) = Connection::session() else {
        return false;
    };
    portal::proxy(&connection, INTERFACE)
        .and_then(|proxy| proxy.get_property::<u32>("version").map_err(portal::bus))
        .is_ok()
}

/// Binds the shortcut `id` (`preferred` in the portal's syntax, such as
/// `CTRL+ALT+SHIFT+T`; the user may choose other keys), calling `on` from a
/// thread of its own each time it is pressed. Blocks while the desktop asks
/// the user: call it off the UI thread.
///
/// # Errors
///
/// No portal or session bus; `PermissionDenied` when the user refused.
pub fn bind(
    id: &str,
    description: &str,
    preferred: &str,
    on: impl Fn() + Send + 'static,
) -> io::Result<GlobalShortcut> {
    let connection = Connection::session().map_err(portal::bus)?;
    let shortcuts = portal::proxy(&connection, INTERFACE)?;
    let session_token = portal::token();
    let created = portal::request(&connection, |token| {
        let options: HashMap<&str, Value<'_>> = HashMap::from([
            ("handle_token", Value::from(token)),
            ("session_handle_token", Value::from(session_token.as_str())),
        ]);
        shortcuts.call("CreateSession", &(options,))
    })?;
    let session = created
        .get("session_handle")
        .and_then(|value: &OwnedValue| {
            // A string in the specification; some portals send a path.
            String::try_from(value.clone()).ok().or_else(|| {
                OwnedObjectPath::try_from(value.clone())
                    .ok()
                    .map(|path| path.as_str().to_owned())
            })
        })
        .and_then(|path| OwnedObjectPath::try_from(path).ok())
        .ok_or_else(|| io::Error::other("portal: no session"))?;
    let properties: HashMap<&str, Value<'_>> = HashMap::from([
        ("description", Value::from(description)),
        ("preferred_trigger", Value::from(preferred)),
    ]);
    portal::request(&connection, |token| {
        let options: HashMap<&str, Value<'_>> =
            HashMap::from([("handle_token", Value::from(token))]);
        shortcuts.call(
            "BindShortcuts",
            &(
                ObjectPath::from(&session),
                vec![(id, properties)],
                "",
                options,
            ),
        )
    })?;
    let rule = zbus::MatchRule::builder()
        .msg_type(zbus::message::Type::Signal)
        .interface(INTERFACE)
        .map_err(portal::bus)?
        .member("Activated")
        .map_err(portal::bus)?
        .build();
    let pressed =
        MessageIterator::for_match_rule(rule, &connection, Some(16)).map_err(portal::bus)?;
    let stopped = Arc::new(AtomicBool::new(false));
    let (ours, wanted, stopping) = (session.clone(), id.to_owned(), Arc::clone(&stopped));
    // The thread ends with the connection; after a release it ignores
    // what still arrives.
    std::thread::Builder::new()
        .name("todoke-shortcut".into())
        .spawn(move || {
            for message in pressed {
                if stopping.load(Ordering::SeqCst) {
                    return;
                }
                let Ok(message) = message else {
                    return;
                };
                let activated: Result<
                    (OwnedObjectPath, String, u64, HashMap<String, OwnedValue>),
                    _,
                > = message.body().deserialize();
                if let Ok((session, shortcut, _, _)) = activated
                    && session == ours
                    && shortcut == wanted
                {
                    on();
                }
            }
        })?;
    Ok(GlobalShortcut {
        connection: connection.clone(),
        session,
        stopped,
    })
}
