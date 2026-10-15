//! Settings from the app, checked, as the core's configuration.

use std::path::PathBuf;

use todoke_core::config::{CoreConfig, KeyStorage, MAX_HISTORY_DAYS};

use crate::error::TodokeError;
use crate::types::{KeyStoragePolicy, Settings};

/// The core's configuration for `settings`, for a core started with an app
/// key store (`with_key_store`) or without one.
///
/// # Errors
///
/// [`TodokeError::Invalid`] for a relative directory, a history longer
/// than the core keeps, loopback outside a test build, or a key storage
/// policy that could leave the key in a file unasked: with the app's key
/// store the key lives there only (`Platform`); on Android and iOS without
/// one, only an explicit `File` is accepted.
pub(crate) fn core_config(
    settings: &Settings,
    with_key_store: bool,
) -> Result<CoreConfig, TodokeError> {
    if settings.allow_loopback && !cfg!(feature = "test-support") {
        return Err(TodokeError::Invalid {
            message: "loopback is for tests only".to_owned(),
        });
    }
    let policy = settings.key_storage;
    if with_key_store && policy != KeyStoragePolicy::Platform {
        return Err(TodokeError::Invalid {
            message: "with a key store, the key lives only there: use KeyStoragePolicy::Platform"
                .to_owned(),
        });
    }
    if !with_key_store
        && cfg!(any(target_os = "android", target_os = "ios"))
        && policy != KeyStoragePolicy::File
    {
        return Err(TodokeError::Invalid {
            message: "give a key store (Core::with_key_store), or ask for a file key explicitly"
                .to_owned(),
        });
    }
    let home = absolute(&settings.home, "the app's directory")?;
    let downloads = absolute(&settings.downloads, "the downloads directory")?;
    if settings.history_days > MAX_HISTORY_DAYS {
        return Err(TodokeError::Invalid {
            message: format!("history is kept at most {MAX_HISTORY_DAYS} days"),
        });
    }
    let mut config = CoreConfig::new(home.join("state"), downloads);
    config.lan.enabled = settings.lan;
    config.lan.allow_loopback = settings.allow_loopback;
    config.hidden = settings.hidden;
    config.history_days = settings.history_days;
    config.key_storage = match settings.key_storage {
        KeyStoragePolicy::Auto => KeyStorage::Auto,
        KeyStoragePolicy::Platform => KeyStorage::Platform,
        KeyStoragePolicy::File => KeyStorage::File,
    };
    Ok(config)
}

fn absolute(path: &str, what: &str) -> Result<PathBuf, TodokeError> {
    let path = PathBuf::from(path);
    if path.is_absolute() && !path.as_os_str().is_empty() {
        Ok(path)
    } else {
        Err(TodokeError::Invalid {
            message: format!("{what} must be an absolute path"),
        })
    }
}

/// Why the core did not start, for the app.
#[cfg(not(target_family = "wasm"))]
#[expect(
    clippy::needless_pass_by_value,
    reason = "used as map_err(start_error)"
)]
pub(crate) fn start_error(error: todoke_core::runtime::StartError) -> TodokeError {
    use todoke_core::runtime::StartError;
    let message = error.to_string();
    match error {
        StartError::Disabled => TodokeError::Disabled { message },
        // The key store refused or failed: the app's own concern.
        StartError::Profile(todoke_core::profile::ProfileError::StorageKey) => {
            TodokeError::KeyStore { message }
        }
        StartError::Profile(_) | StartError::Quarantine(_) => TodokeError::Profile { message },
        StartError::Io(_) | StartError::Thread => TodokeError::Internal { message },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings(home: &str) -> Settings {
        Settings {
            home: home.to_owned(),
            downloads: if cfg!(windows) { "C:\\d" } else { "/d" }.to_owned(),
            lan: false,
            allow_loopback: false,
            hidden: true,
            history_days: 7,
            key_storage: KeyStoragePolicy::File,
        }
    }

    #[test]
    fn settings_become_a_checked_configuration() -> Result<(), TodokeError> {
        let home = if cfg!(windows) { "C:\\h" } else { "/h" };
        let config = core_config(&settings(home), false)?;
        assert_eq!(config.state_dir, PathBuf::from(home).join("state"));
        assert!(!config.lan.enabled);
        assert!(config.hidden);
        assert_eq!(config.history_days, 7);
        assert_eq!(config.key_storage, KeyStorage::File);
        assert!(matches!(
            core_config(&settings("relative"), false),
            Err(TodokeError::Invalid { .. })
        ));
        let mut long = settings(home);
        long.history_days = MAX_HISTORY_DAYS + 1;
        assert!(matches!(
            core_config(&long, false),
            Err(TodokeError::Invalid { .. })
        ));
        // A key store means the key lives there only.
        assert!(matches!(
            core_config(&settings(home), true),
            Err(TodokeError::Invalid { .. })
        ));
        let mut platform = settings(home);
        platform.key_storage = KeyStoragePolicy::Platform;
        assert!(core_config(&platform, true).is_ok());
        // Loopback only in test-support builds.
        let mut loopback = settings(home);
        loopback.allow_loopback = true;
        assert_eq!(
            core_config(&loopback, false).is_ok(),
            cfg!(feature = "test-support")
        );
        Ok(())
    }
}
