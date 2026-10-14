//! The core's configuration: where it keeps state, where received files go,
//! and how it uses the local network. Stored as JSON in the platform
//! configuration directory by the daemon; nothing here is secret.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// Local network settings.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LanSettings {
    /// Whether to advertise, browse, and accept on the local network.
    pub enabled: bool,
    /// The TCP port to listen on; 0 for any free port.
    pub port: u16,
    /// Also allow loopback peers: for running two instances on one machine
    /// (development and tests), never for real use.
    #[serde(default)]
    pub allow_loopback: bool,
}

impl Default for LanSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            port: 0,
            allow_loopback: false,
        }
    }
}

/// The core's configuration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CoreConfig {
    /// The private state directory (identity, contacts, quarantine).
    pub state_dir: PathBuf,
    /// Where accepted files are published.
    pub downloads_dir: PathBuf,
    /// Local network settings.
    #[serde(default)]
    pub lan: LanSettings,
    /// Development and tests only: exchange discovery records through files
    /// in this directory instead of mDNS. Ignored unless the build has the
    /// `unaudited-dev` feature.
    #[serde(default)]
    pub discovery_folder: Option<PathBuf>,
}

impl CoreConfig {
    /// A configuration with default network settings.
    #[must_use]
    pub fn new(state_dir: PathBuf, downloads_dir: PathBuf) -> Self {
        Self {
            state_dir,
            downloads_dir,
            lan: LanSettings::default(),
            discovery_folder: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn configurations_round_trip_and_reject_unknown_fields() -> Result<(), serde_json::Error> {
        let config = CoreConfig::new("/state".into(), "/downloads".into());
        let text = serde_json::to_string(&config)?;
        assert_eq!(serde_json::from_str::<CoreConfig>(&text)?, config);
        let minimal: CoreConfig =
            serde_json::from_str(r#"{"state_dir":"/s","downloads_dir":"/d"}"#)?;
        assert_eq!(minimal.lan, LanSettings::default());
        assert!(!minimal.lan.allow_loopback);
        assert!(
            serde_json::from_str::<CoreConfig>(
                r#"{"state_dir":"/s","downloads_dir":"/d","telemetry":true}"#
            )
            .is_err()
        );
        Ok(())
    }
}
