//! A global shortcut on Wayland, through the `GlobalShortcuts` portal (KDE
//! Plasma, GNOME 48 and later): the desktop asks the user to confirm it and
//! lets them choose the keys; this process never sees other keystrokes.

use std::collections::HashMap;
use std::io;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use zbus::{Connection, ObjectPath, OwnedObjectPath, OwnedVariant, Proxy, Variant};

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
        zbus::block_on(async {
            if let Ok(session) = Proxy::new(
                &self.connection,
                portal::DESKTOP,
                self.session.as_str(),
                "org.freedesktop.portal.Session",
            )
            .await
            {
                let _: Result<(), _> = session.call("Close", &()).await;
            }
        });
    }
}

/// Whether the session has the portal (so `bind` can work).
#[must_use]
pub fn available() -> bool {
    zbus::block_on(async {
        let Ok(connection) = Connection::session().await else {
            return false;
        };
        let Ok(proxy) = portal::proxy(&connection, INTERFACE).await else {
            return false;
        };
        proxy.get_property::<u32>("version").await.is_ok()
    })
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
    let (connection, session, mut pressed) = zbus::block_on(async {
        let connection = Connection::session().await.map_err(portal::bus)?;
        let shortcuts = portal::proxy(&connection, INTERFACE).await?;
        let session_token = portal::token();
        let created = portal::request(&connection, async |token| {
            let options: HashMap<&str, Variant<'_>> = HashMap::from([
                ("handle_token", Variant::from(token)),
                (
                    "session_handle_token",
                    Variant::from(session_token.as_str()),
                ),
            ]);
            shortcuts.call("CreateSession", &(options,)).await
        })
        .await?;
        let session = created
            .get("session_handle")
            .and_then(|value: &OwnedVariant| {
                // A string in the specification; some portals send a path.
                String::try_from(value.clone()).ok().or_else(|| {
                    OwnedObjectPath::try_from(value.clone())
                        .ok()
                        .map(|path| path.as_str().to_owned())
                })
            })
            .and_then(|path| OwnedObjectPath::try_from(path).ok())
            .ok_or_else(|| io::Error::other("portal: no session"))?;
        let properties: HashMap<&str, Variant<'_>> = HashMap::from([
            ("description", Variant::from(description)),
            ("preferred_trigger", Variant::from(preferred)),
        ]);
        portal::request(&connection, async |token| {
            let options: HashMap<&str, Variant<'_>> =
                HashMap::from([("handle_token", Variant::from(token))]);
            shortcuts
                .call(
                    "BindShortcuts",
                    &(
                        ObjectPath::from(&session),
                        vec![(id, properties)],
                        "",
                        options,
                    ),
                )
                .await
        })
        .await?;
        // Only the portal's signals: another program on the bus cannot
        // press the shortcut.
        let rule = zbus::MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .sender(portal::owner(&connection).await?)
            .interface(INTERFACE)
            .member("Activated");
        let pressed = portal::signals(&connection, rule, 16)
            .await
            .map_err(portal::bus)?;
        Ok::<_, io::Error>((connection, session, pressed))
    })?;
    let stopped = Arc::new(AtomicBool::new(false));
    let (ours, wanted, stopping) = (session.clone(), id.to_owned(), Arc::clone(&stopped));
    // The thread ends with the connection; after a release it ignores
    // what still arrives.
    std::thread::Builder::new()
        .name("todoke-shortcut".into())
        .spawn(move || {
            zbus::block_on(async {
                while let Some(message) = portal::next(&mut pressed).await {
                    if stopping.load(Ordering::SeqCst) {
                        return;
                    }
                    let Ok(message) = message else {
                        return;
                    };
                    let activated: Result<
                        (OwnedObjectPath, String, u64, HashMap<String, OwnedVariant>),
                        _,
                    > = message.body().deserialize();
                    if let Ok((session, shortcut, _, _)) = activated
                        && session == ours
                        && shortcut == wanted
                    {
                        on();
                    }
                }
            });
        })?;
    Ok(GlobalShortcut {
        connection,
        session,
        stopped,
    })
}
