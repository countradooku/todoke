//! Settings on disk: the core's `config.json` (shared with the daemon and
//! the CLI), relay lists the user imports, and the app's own preferences
//! (`desktop.json` next to it: only the theme). Nothing here is secret.

use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use todoke_core::config::{CoreConfig, MAX_HISTORY_DAYS, RelayConfig, RelayList};
use todoke_daemon::Paths;

/// Which theme to show.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ThemeChoice {
    /// Follow the system's appearance.
    #[default]
    System,
    /// Always light.
    Light,
    /// Always dark.
    Dark,
}

/// The app's own preferences.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Prefs {
    /// The theme.
    #[serde(default)]
    pub theme: ThemeChoice,
}

fn prefs_file(paths: &Paths) -> PathBuf {
    paths.config_file.parent().map_or_else(
        || PathBuf::from("desktop.json"),
        |dir| dir.join("desktop.json"),
    )
}

/// The preferences, or the defaults when none are stored or they do not
/// parse.
#[must_use]
pub fn load_prefs(paths: &Paths) -> Prefs {
    std::fs::read(prefs_file(paths))
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

/// Stores the preferences.
///
/// # Errors
///
/// An I/O error.
pub fn save_prefs(paths: &Paths, prefs: &Prefs) -> std::io::Result<()> {
    let text = serde_json::to_vec_pretty(prefs).map_err(std::io::Error::other)?;
    replace(&prefs_file(paths), &text)
}

/// Why a configuration change was refused.
#[derive(Debug, PartialEq, Eq)]
pub enum Invalid {
    /// The state directory cannot move (the endpoint and the key derive
    /// from it).
    StateDir,
    /// The relay presence period is below 10 seconds.
    Presence,
    /// History retention beyond [`MAX_HISTORY_DAYS`].
    HistoryDays,
    /// A relay is malformed: why.
    Relay(String),
}

impl core::fmt::Display for Invalid {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::StateDir => f.write_str("the state directory cannot be changed here"),
            Self::Presence => f.write_str("relay presence must be at least 10 seconds"),
            Self::HistoryDays => write!(f, "history is kept at most {MAX_HISTORY_DAYS} days"),
            Self::Relay(why) => write!(f, "relay list: {why}"),
        }
    }
}

/// Checks `config` before it is written: what the core would refuse at
/// start is refused here, with a reason.
///
/// # Errors
///
/// [`Invalid`].
pub fn check(paths: &Paths, config: &CoreConfig) -> Result<(), Invalid> {
    let normal = |path: &Path| path.components().collect::<PathBuf>();
    if normal(&config.state_dir) != normal(&paths.state_dir) {
        return Err(Invalid::StateDir);
    }
    if config.relay_presence_seconds < 10 {
        return Err(Invalid::Presence);
    }
    if config.history_days > MAX_HISTORY_DAYS {
        return Err(Invalid::HistoryDays);
    }
    check_relays(&config.relays)
}

/// Checks relay entries: names unique and non-empty, an address and a
/// server name, and pins well formed.
///
/// # Errors
///
/// [`Invalid::Relay`].
pub fn check_relays(relays: &[RelayConfig]) -> Result<(), Invalid> {
    for (index, relay) in relays.iter().enumerate() {
        if relay.name.trim().is_empty() {
            return Err(Invalid::Relay(format!("entry {} has no name", index + 1)));
        }
        if relays[..index].iter().any(|other| other.name == relay.name) {
            return Err(Invalid::Relay("two relays share a name".to_owned()));
        }
        if relay.address.trim().is_empty() || relay.server_name.trim().is_empty() {
            return Err(Invalid::Relay(format!(
                "entry {} needs an address and a server name",
                index + 1
            )));
        }
        if let Some(pin) = &relay.pin {
            let digits = pin.strip_prefix("spki-sha256:").unwrap_or_default();
            if digits.len() != 64 || !digits.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(Invalid::Relay(format!(
                    "entry {} has a malformed pin",
                    index + 1
                )));
            }
        }
    }
    Ok(())
}

/// Writes `config` (after [`check`]).
///
/// # Errors
///
/// An I/O error, or `InvalidInput` with the reason.
pub fn save_config(paths: &Paths, config: &CoreConfig) -> std::io::Result<()> {
    check(paths, config)
        .map_err(|why| std::io::Error::new(std::io::ErrorKind::InvalidInput, why.to_string()))?;
    let text = serde_json::to_vec_pretty(config).map_err(std::io::Error::other)?;
    replace(&paths.config_file, &text)
}

/// Reads a relay list the user chose (`{"version": 1, "relays": [...]}`)
/// and checks it. At most 1 MiB is read; nothing is fetched.
///
/// # Errors
///
/// An I/O error, or `InvalidData` with the reason.
pub fn import_relays(file: &Path) -> std::io::Result<Vec<RelayConfig>> {
    use std::io::Read as _;
    let mut text = Vec::new();
    std::fs::File::open(file)?
        .take(1 << 20)
        .read_to_end(&mut text)?;
    let list: RelayList = serde_json::from_slice(&text)
        .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
    if list.version != 1 {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "only version 1 relay lists are understood",
        ));
    }
    check_relays(&list.relays)
        .map_err(|why| std::io::Error::new(std::io::ErrorKind::InvalidData, why.to_string()))?;
    Ok(list.relays)
}

/// Replaces `path` with `bytes`: written beside it, synced, then renamed,
/// so a crash leaves the old file or the new one.
fn replace(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write as _;
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(dir)?;
    let partial = path.with_extension("json.tmp");
    let _ = std::fs::remove_file(&partial);
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&partial)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    drop(file);
    std::fs::rename(&partial, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Scratch(PathBuf);

    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn scratch(name: &str) -> Scratch {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |since| since.as_nanos());
        Scratch(std::env::temp_dir().join(format!("todoke-desktop-{name}-{nanos}")))
    }

    fn relay(name: &str, pin: Option<&str>) -> RelayConfig {
        RelayConfig {
            name: name.into(),
            address: "relay.example:4433".into(),
            server_name: "relay.example".into(),
            pin: pin.map(Into::into),
        }
    }

    #[test]
    fn preferences_round_trip_and_default_when_missing() -> std::io::Result<()> {
        let home = scratch("prefs");
        let paths = Paths::under(&home.0);
        assert_eq!(load_prefs(&paths), Prefs::default());
        let prefs = Prefs {
            theme: ThemeChoice::Dark,
        };
        save_prefs(&paths, &prefs)?;
        assert_eq!(load_prefs(&paths), prefs);
        std::fs::write(prefs_file(&paths), b"{not json")?;
        assert_eq!(load_prefs(&paths), Prefs::default());
        Ok(())
    }

    #[test]
    fn configurations_are_checked_before_writing() -> std::io::Result<()> {
        let home = scratch("config");
        let paths = Paths::under(&home.0);
        let mut config = CoreConfig::new(paths.state_dir.clone(), paths.downloads_dir.clone());
        config.history_days = 7;
        save_config(&paths, &config)?;
        assert_eq!(paths.config()?.history_days, 7);
        let mut moved = config.clone();
        moved.state_dir = home.0.join("elsewhere");
        assert_eq!(check(&paths, &moved), Err(Invalid::StateDir));
        let mut fast = config.clone();
        fast.relay_presence_seconds = 5;
        assert_eq!(check(&paths, &fast), Err(Invalid::Presence));
        let mut long = config.clone();
        long.history_days = MAX_HISTORY_DAYS + 1;
        assert!(save_config(&paths, &long).is_err());
        // The refused change left the file as it was.
        assert_eq!(paths.config()?.history_days, 7);
        Ok(())
    }

    #[test]
    fn relay_entries_are_checked() {
        let pin = format!("spki-sha256:{}", "ab".repeat(32));
        assert_eq!(
            check_relays(&[relay("a", Some(&pin)), relay("b", None)]),
            Ok(())
        );
        assert!(check_relays(&[relay("a", None), relay("a", None)]).is_err());
        assert!(check_relays(&[relay(" ", None)]).is_err());
        assert!(check_relays(&[relay("a", Some("spki-sha256:abc"))]).is_err());
        assert!(check_relays(&[relay("a", Some(&"x".repeat(76)))]).is_err());
    }

    #[test]
    fn relay_lists_are_imported_from_files() -> std::io::Result<()> {
        let home = scratch("relays");
        std::fs::create_dir_all(&home.0)?;
        let file = home.0.join("relays.json");
        let pin = format!("spki-sha256:{}", "0f".repeat(32));
        std::fs::write(
            &file,
            format!(
                r#"{{"version":1,"relays":[{{"name":"eu","address":"eu.example:4433","server_name":"eu.example","pin":"{pin}"}}]}}"#
            ),
        )?;
        let relays = import_relays(&file)?;
        assert_eq!(relays.len(), 1);
        assert_eq!(relays[0].pin.as_deref(), Some(pin.as_str()));
        std::fs::write(&file, r#"{"version":2,"relays":[]}"#)?;
        assert!(import_relays(&file).is_err());
        std::fs::write(&file, r#"{"version":1,"relays":[],"telemetry":true}"#)?;
        assert!(import_relays(&file).is_err());
        Ok(())
    }
}
