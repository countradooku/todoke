//! Settings from the app, checked, as the core's configuration.

use std::path::PathBuf;

use todoke_core::config::{CoreConfig, KeyStorage, MAX_HISTORY_DAYS};

use crate::error::TodokeError;
use crate::types::{KeyStoragePolicy, Settings};

/// The core's configuration for `settings`.
///
/// # Errors
///
/// [`TodokeError::Invalid`] for a relative directory or a history longer
/// than the core keeps.
pub(crate) fn core_config(settings: &Settings) -> Result<CoreConfig, TodokeError> {
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
        let config = core_config(&settings(home))?;
        assert_eq!(config.state_dir, PathBuf::from(home).join("state"));
        assert!(!config.lan.enabled);
        assert!(config.hidden);
        assert_eq!(config.history_days, 7);
        assert_eq!(config.key_storage, KeyStorage::File);
        assert!(matches!(
            core_config(&settings("relative")),
            Err(TodokeError::Invalid { .. })
        ));
        let mut long = settings(home);
        long.history_days = MAX_HISTORY_DAYS + 1;
        assert!(matches!(
            core_config(&long),
            Err(TodokeError::Invalid { .. })
        ));
        Ok(())
    }
}
