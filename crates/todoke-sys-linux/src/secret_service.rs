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

use zbus::{Connection, ObjectPath, OwnedObjectPath, OwnedVariant, Proxy, Variant};
use zeroize::Zeroizing;

use crate::portal;

const BUS_NAME: &str = "org.freedesktop.secrets";
const SERVICE_PATH: &str = "/org/freedesktop/secrets";
const SERVICE: &str = "org.freedesktop.Secret.Service";
const COLLECTION: &str = "org.freedesktop.Secret.Collection";
const ITEM: &str = "org.freedesktop.Secret.Item";
const PROMPT: &str = "org.freedesktop.Secret.Prompt";
/// How long a keyring prompt may wait for the user.
const PROMPT_DEADLINE: std::time::Duration = std::time::Duration::from_secs(120);

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

impl Session {
    /// Opens a session, runs `work` in it, and closes it whatever the
    /// outcome (zbus 6 has no blocking call a `Drop` could make).
    async fn with<T>(work: impl AsyncFnOnce(&Self) -> io::Result<T>) -> io::Result<T> {
        let connection = Connection::session().await.map_err(bus)?;
        let service = Proxy::new(&connection, BUS_NAME, SERVICE_PATH, SERVICE)
            .await
            .map_err(bus)?;
        let (_, path): (OwnedVariant, OwnedObjectPath) = service
            .call("OpenSession", &("plain", Variant::from("")))
            .await
            .map_err(bus)?;
        let session = Self { connection, path };
        let result = work(&session).await;
        session.close().await;
        result
    }

    async fn close(&self) {
        if let Ok(proxy) = Proxy::new(
            &self.connection,
            BUS_NAME,
            self.path.as_str(),
            "org.freedesktop.Secret.Session",
        )
        .await
        {
            let _: Result<(), _> = proxy.call("Close", &()).await;
        }
    }

    async fn service(&self) -> io::Result<Proxy<'_>> {
        Proxy::new(&self.connection, BUS_NAME, SERVICE_PATH, SERVICE)
            .await
            .map_err(bus)
    }

    /// A proxy for `interface` of the object at `path`.
    async fn object<'a>(&'a self, path: &'a str, interface: &'a str) -> io::Result<Proxy<'a>> {
        Proxy::new(&self.connection, BUS_NAME, path, interface)
            .await
            .map_err(bus)
    }

    /// Unlocks `objects` (the keyring may ask the user).
    async fn unlock(&self, objects: &[OwnedObjectPath]) -> io::Result<()> {
        if objects.is_empty() {
            return Ok(());
        }
        let (_, prompt): (Vec<OwnedObjectPath>, OwnedObjectPath) = self
            .service()
            .await?
            .call("Unlock", &(objects,))
            .await
            .map_err(bus)?;
        self.prompt(&prompt).await
    }

    /// Runs a prompt (unless there is none: "/") and waits for its answer,
    /// at most [`PROMPT_DEADLINE`]: an unanswered prompt (a locked keyring
    /// early in the session, a dialog no one sees) dismisses it, and the
    /// store counts as unavailable.
    async fn prompt(&self, prompt: &ObjectPath<'_>) -> io::Result<()> {
        if prompt.as_str() == "/" {
            return Ok(());
        }
        let proxy = self.object(prompt.as_str(), PROMPT).await?;
        // Listen before prompting: the answer may come first. Only the
        // service's signals: another program cannot answer for it.
        let owner = portal::owner_of(&self.connection, BUS_NAME)
            .await
            .map_err(bus)?;
        let rule = zbus::MatchRule::builder()
            .msg_type(zbus::message::Type::Signal)
            .sender(owner)
            .interface(PROMPT)
            .member("Completed")
            .path(prompt.as_str());
        let mut completed = portal::signals(&self.connection, rule, 4)
            .await
            .map_err(bus)?;
        let _: () = proxy.call("Prompt", &("",)).await.map_err(bus)?;
        let runtime = zruntime::Runtime::<zruntime::Shared>::current()?;
        let message = match runtime
            .timeout(PROMPT_DEADLINE, portal::next(&mut completed))
            .await
        {
            Ok(Some(message)) => message.map_err(bus)?,
            Ok(None) => return Err(io::Error::other("the keyring prompt went away")),
            Err(_timed_out) => {
                let _: Result<(), _> = proxy.call("Dismiss", &()).await;
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "the keyring prompt was not answered",
                ));
            }
        };
        let (dismissed, _): (bool, OwnedVariant) = message.body().deserialize().map_err(bus)?;
        if dismissed {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the keyring was not unlocked",
            ));
        }
        Ok(())
    }

    /// The collection new items go to: the default one, else GNOME's login
    /// keyring, else a new default collection (as libsecret does; the
    /// keyring asks the user for its password).
    async fn collection(&self) -> io::Result<OwnedObjectPath> {
        let service = self.service().await?;
        for alias in ["default", "login"] {
            let collection: OwnedObjectPath =
                service.call("ReadAlias", &(alias,)).await.map_err(bus)?;
            if collection.as_str() != "/" {
                return Ok(collection);
            }
        }
        let properties = HashMap::from([(
            "org.freedesktop.Secret.Collection.Label",
            Variant::from("Login"),
        )]);
        let (_, prompt): (OwnedObjectPath, OwnedObjectPath) = service
            .call("CreateCollection", &(properties, "default"))
            .await
            .map_err(bus)?;
        self.prompt(&prompt).await?;
        let collection: OwnedObjectPath = service
            .call("ReadAlias", &("default",))
            .await
            .map_err(bus)?;
        if collection.as_str() == "/" {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "the keyring has no collection to keep the key in",
            ));
        }
        Ok(collection)
    }
}

impl SecretService {
    /// The item for the profile with ID `profile` (random, kept beside the
    /// state: moving the state keeps its key).
    #[must_use]
    pub fn for_profile(profile: &str) -> Self {
        Self {
            profile: profile.to_owned(),
        }
    }

    fn attributes(&self) -> HashMap<&str, &str> {
        HashMap::from([
            ("application", "org.todoke.todoke"),
            ("profile", self.profile.as_str()),
        ])
    }

    /// This profile's item, unlocked; `None` if there is none.
    async fn item(&self, session: &Session) -> io::Result<Option<OwnedObjectPath>> {
        let (unlocked, locked): (Vec<OwnedObjectPath>, Vec<OwnedObjectPath>) = session
            .service()
            .await?
            .call("SearchItems", &(self.attributes(),))
            .await
            .map_err(bus)?;
        if let Some(item) = unlocked.into_iter().next() {
            return Ok(Some(item));
        }
        let Some(item) = locked.into_iter().next() else {
            return Ok(None);
        };
        session.unlock(std::slice::from_ref(&item)).await?;
        Ok(Some(item))
    }

    /// The stored key, or `None` if none is stored.
    ///
    /// # Errors
    ///
    /// No Secret Service (no session bus, no keyring), or it refused.
    pub fn load(&self) -> io::Result<Option<Zeroizing<[u8; 32]>>> {
        zbus::block_on(Session::with(async |session| {
            let Some(item) = self.item(session).await? else {
                return Ok(None);
            };
            let (_, _, value, _): Secret = session
                .object(item.as_str(), ITEM)
                .await?
                .call("GetSecret", &(&session.path,))
                .await
                .map_err(bus)?;
            let value = Zeroizing::new(value);
            let key: [u8; 32] = value.as_slice().try_into().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "the stored key has the wrong size",
                )
            })?;
            Ok(Some(Zeroizing::new(key)))
        }))
    }

    /// Stores `key` in the default collection; never replaces a stored one.
    ///
    /// # Errors
    ///
    /// `AlreadyExists` if a key is stored; no Secret Service, or it refused.
    pub fn store(&self, key: &[u8; 32]) -> io::Result<()> {
        zbus::block_on(Session::with(async |session| {
            if self.item(session).await?.is_some() {
                return Err(io::ErrorKind::AlreadyExists.into());
            }
            let collection = session.collection().await?;
            session.unlock(std::slice::from_ref(&collection)).await?;
            let proxy = session.object(collection.as_str(), COLLECTION).await?;
            let label = format!("todoke storage key ({})", self.profile);
            let properties = HashMap::from([
                ("org.freedesktop.Secret.Item.Label", Variant::from(label)),
                (
                    "org.freedesktop.Secret.Item.Attributes",
                    Variant::from(self.attributes()),
                ),
            ]);
            let mut secret: Secret = (
                session.path.clone(),
                Vec::new(),
                key.to_vec(),
                "application/octet-stream".to_owned(),
            );
            let created: Result<(OwnedObjectPath, OwnedObjectPath), _> = proxy
                .call("CreateItem", &(properties, &secret, false))
                .await;
            zeroize::Zeroize::zeroize(&mut secret.2);
            let (_, prompt) = created.map_err(bus)?;
            session.prompt(&prompt).await
        }))
    }

    /// Removes this profile's item (tests; removing a profile).
    ///
    /// # Errors
    ///
    /// No Secret Service, or it refused.
    pub fn delete(&self) -> io::Result<()> {
        zbus::block_on(Session::with(async |session| {
            let Some(item) = self.item(session).await? else {
                return Ok(());
            };
            let prompt: OwnedObjectPath = session
                .object(item.as_str(), ITEM)
                .await?
                .call("Delete", &())
                .await
                .map_err(bus)?;
            session.prompt(&prompt).await
        }))
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
        let store = SecretService::for_profile(&format!(
            "todoke-secret-service-test-{}",
            u64::from_le_bytes(random)
        ));
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
