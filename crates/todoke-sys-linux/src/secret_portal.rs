//! The app's secret from the XDG Secret portal (Flatpak): the desktop's
//! keyring keeps one random secret per sandboxed app and hands it only to
//! that app, so the sandbox needs no access to the keyring itself (no
//! `org.freedesktop.secrets`, which would expose every item in it). The
//! storage key is sealed under it (`todoke_core::storage_key::SealedFile`).

use std::collections::HashMap;
use std::io::{self, Read as _};
use std::os::fd::AsFd as _;
use std::os::unix::net::UnixStream;

use zbus::{Connection, Fd, Variant};
use zeroize::Zeroizing;

use crate::portal;

/// At most this much secret is read.
const MAX_SECRET: u64 = 1024;

/// The app's secret.
///
/// # Errors
///
/// No portal (not sandboxed, or an old desktop); it refused.
pub fn retrieve() -> io::Result<Zeroizing<Vec<u8>>> {
    let (mut ours, theirs) = UnixStream::pair()?;
    zbus::block_on(async {
        let connection = Connection::session().await.map_err(portal::bus)?;
        let secret = portal::proxy(&connection, "org.freedesktop.portal.Secret").await?;
        portal::request(&connection, async |token| {
            let options: HashMap<&str, Variant<'_>> =
                HashMap::from([("handle_token", Variant::from(token))]);
            secret
                .call("RetrieveSecret", &(Fd::from(theirs.as_fd()), options))
                .await
        })
        .await
    })?;
    // The portal wrote the secret and closed its copy; close ours to read
    // to the end.
    drop(theirs);
    let mut bytes = Zeroizing::new(Vec::with_capacity(64));
    (&mut ours).take(MAX_SECRET).read_to_end(&mut bytes)?;
    if bytes.len() < 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "the portal's secret is too short",
        ));
    }
    Ok(bytes)
}
