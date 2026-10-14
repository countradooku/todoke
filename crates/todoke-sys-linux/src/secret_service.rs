//! The storage key in the freedesktop Secret Service (§16 O9): GNOME
//! Keyring, `KWallet`, or `KeePassXC`, over the session bus. The keyring
//! encrypts it at rest under the user's login and locks with the session.
//!
//! The session uses the specification's "plain" transfer: the bus is this
//! user's, and a process of this user could ask the keyring for the secret
//! anyway. Without a session bus (a server) the store is unavailable and
//! the daemon keeps a key file (docs/adr/0011-os-integration.md).

use std::collections::HashMap;
use std::io;
use std::path::Path;

use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::{ObjectPath, OwnedObjectPath, OwnedValue, Value};
use zeroize::Zeroizing;

const BUS_NAME: &str = "org.freedesktop.secrets";
const SERVICE_PATH: &str = "/org/freedesktop/secrets";
const SERVICE: &str = "org.freedesktop.Secret.Service";
const COLLECTION: &str = "org.freedesktop.Secret.Collection";
const ITEM: &str = "org.freedesktop.Secret.Item";
const PROMPT: &str = "org.freedesktop.Secret.Prompt";

/// A secret as the API carries it: session, parameters, value, type.
type Secret = (OwnedObjectPath, Vec<u8>, Vec<u8>, String);

#[expect(clippy::needless_pass_by_value, reason = "used as map_err(bus)")]
fn bus(error: zbus::Error) -> io::Error {
    io::Error::other(format!("Secret Service: {error}"))
}

/// The storage key of one profile in the Secret Service.
#[derive(Debug)]
pub struct SecretService {
    profile: String,
}

/// An open session with the service.
struct Session {
    connection: Connection,
    path: OwnedObjectPath,
}

impl Drop for Session {
    fn drop(&mut self) {
        if let Ok(proxy) = Proxy::new(
            &self.connection,
            BUS_NAME,
            self.path.as_str(),
            "org.freedesktop.Secret.Session",
        ) {
            let _: Result<(), _> = proxy.call("Close", &());
        }
    }
}

impl SecretService {
    /// The item for the profile whose state is in `state_dir`.
    #[must_use]
    pub fn for_state(state_dir: &Path) -> Self {
        Self {
            profile: state_dir.display().to_string(),
        }
    }

    fn attributes(&self) -> HashMap<&str, &str> {
        HashMap::from([
            ("application", "org.todoke.todoke"),
            ("profile", self.profile.as_str()),
        ])
    }

    fn open() -> io::Result<Session> {
        let connection = Connection::session().map_err(bus)?;
        let service = Proxy::new(&connection, BUS_NAME, SERVICE_PATH, SERVICE).map_err(bus)?;
        let (_, path): (OwnedValue, OwnedObjectPath) = service
            .call("OpenSession", &("plain", Value::from("")))
            .map_err(bus)?;
        Ok(Session { connection, path })
    }

    /// Unlocks `objects` (the keyring may ask the user).
    fn unlock(session: &Session, objects: &[OwnedObjectPath]) -> io::Result<()> {
        if objects.is_empty() {
            return Ok(());
        }
        let service =
            Proxy::new(&session.connection, BUS_NAME, SERVICE_PATH, SERVICE).map_err(bus)?;
        let (_, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) =
            service.call("Unlock", &(objects,)).map_err(bus)?;
        Self::prompt(session, &prompt)
    }

    /// Runs a prompt (unless there is none: "/") and waits for its answer.
    fn prompt(session: &Session, prompt: &ObjectPath<'_>) -> io::Result<()> {
        if prompt.as_str() == "/" {
            return Ok(());
        }
        let proxy =
            Proxy::new(&session.connection, BUS_NAME, prompt.as_str(), PROMPT).map_err(bus)?;
        let mut completed = proxy.receive_signal("Completed").map_err(bus)?;
        let _: () = proxy.call("Prompt", &("",)).map_err(bus)?;
        let message = completed
            .next()
            .ok_or_else(|| io::Error::other("the keyring prompt went away"))?;
        let (dismissed, _): (bool, OwnedValue) = message.body().deserialize().map_err(bus)?;
        if dismissed {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the keyring was not unlocked",
            ));
        }
        Ok(())
    }

    /// This profile's item, unlocked; `None` if there is none.
    fn item(&self, session: &Session) -> io::Result<Option<OwnedObjectPath>> {
        let service =
            Proxy::new(&session.connection, BUS_NAME, SERVICE_PATH, SERVICE).map_err(bus)?;
        let (unlocked, locked): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) = service
            .call("SearchItems", &(self.attributes(),))
            .map_err(bus)?;
        if let Some(item) = unlocked.into_iter().next() {
            return Ok(Some(item));
        }
        let Some(item) = locked.into_iter().next() else {
            return Ok(None);
        };
        Self::unlock(session, std::slice::from_ref(&item))?;
        Ok(Some(item))
    }

    /// The stored key, or `None` if none is stored.
    ///
    /// # Errors
    ///
    /// No Secret Service (no session bus, no keyring), or it refused.
    pub fn load(&self) -> io::Result<Option<Zeroizing<[u8; 32]>>> {
        let session = Self::open()?;
        let Some(item) = self.item(&session)? else {
            return Ok(None);
        };
        let proxy = Proxy::new(&session.connection, BUS_NAME, item.as_str(), ITEM).map_err(bus)?;
        let (_, _, value, _): Secret = proxy.call("GetSecret", &(&session.path,)).map_err(bus)?;
        let value = Zeroizing::new(value);
        let key: [u8; 32] = value.as_slice().try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "the stored key has the wrong size",
            )
        })?;
        Ok(Some(Zeroizing::new(key)))
    }

    /// Stores `key` in the default collection; never replaces a stored one.
    ///
    /// # Errors
    ///
    /// `AlreadyExists` if a key is stored; no Secret Service, or it refused.
    pub fn store(&self, key: &[u8; 32]) -> io::Result<()> {
        let session = Self::open()?;
        if self.item(&session)?.is_some() {
            return Err(io::ErrorKind::AlreadyExists.into());
        }
        let service =
            Proxy::new(&session.connection, BUS_NAME, SERVICE_PATH, SERVICE).map_err(bus)?;
        let collection: OwnedObjectPath = service.call("ReadAlias", &("default",)).map_err(bus)?;
        if collection.as_str() == "/" {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "the keyring has no default collection",
            ));
        }
        Self::unlock(&session, std::slice::from_ref(&collection))?;
        let proxy = Proxy::new(
            &session.connection,
            BUS_NAME,
            collection.as_str(),
            COLLECTION,
        )
        .map_err(bus)?;
        let label = format!("todoke storage key ({})", self.profile);
        let properties = HashMap::from([
            ("org.freedesktop.Secret.Item.Label", Value::from(label)),
            (
                "org.freedesktop.Secret.Item.Attributes",
                Value::from(self.attributes()),
            ),
        ]);
        let mut secret: Secret = (
            session.path.clone(),
            Vec::new(),
            key.to_vec(),
            "application/octet-stream".to_owned(),
        );
        let created: Result<(OwnedObjectPath, OwnedObjectPath), _> =
            proxy.call("CreateItem", &(properties, &secret, false));
        zeroize::Zeroize::zeroize(&mut secret.2);
        let (_, prompt) = created.map_err(bus)?;
        Self::prompt(&session, &prompt)
    }

    /// Removes this profile's item (tests; removing a profile).
    ///
    /// # Errors
    ///
    /// No Secret Service, or it refused.
    pub fn delete(&self) -> io::Result<()> {
        let session = Self::open()?;
        let Some(item) = self.item(&session)? else {
            return Ok(());
        };
        let proxy = Proxy::new(&session.connection, BUS_NAME, item.as_str(), ITEM).map_err(bus)?;
        let prompt: OwnedObjectPath = proxy.call("Delete", &()).map_err(bus)?;
        Self::prompt(&session, &prompt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    /// Needs a Secret Service on the session bus: CI runs it under
    /// `dbus-run-session` with an unlocked GNOME Keyring and sets
    /// `TODOKE_SECRET_SERVICE_TEST`; elsewhere it checks only that a missing
    /// service is an error, never "no key".
    #[test]
    fn a_key_round_trips_through_the_secret_service() -> TestResult {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random)?;
        let store = SecretService::for_state(Path::new(&format!(
            "/nonexistent/todoke-secret-service-test-{}",
            u64::from_le_bytes(random)
        )));
        if std::env::var_os("TODOKE_SECRET_SERVICE_TEST").is_none() {
            if let Ok(loaded) = store.load() {
                assert!(loaded.is_none());
            }
            return Ok(());
        }
        assert!(store.load()?.is_none());
        let key = [0x6b; 32];
        store.store(&key)?;
        assert_eq!(store.load()?.map(|k| *k), Some(key));
        assert_eq!(
            store.store(&[1; 32]).map_err(|e| e.kind()),
            Err(io::ErrorKind::AlreadyExists)
        );
        store.delete()?;
        assert!(store.load()?.is_none());
        Ok(())
    }
}
