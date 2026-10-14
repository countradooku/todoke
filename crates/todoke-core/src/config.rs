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

/// A relay this device may use (§10). The same entries make up a shareable
/// relay list ([`RelayList`]). A relay is untrusted: it only matches and
/// forwards ciphertext.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayConfig {
    /// Its name: unique in a list, and the rendezvous-hashing key, so
    /// devices with the same list meet on the same relay.
    pub name: String,
    /// `host:port` of its UDP listener.
    pub address: String,
    /// The TLS server name.
    pub server_name: String,
    /// Its key pin (`spki-sha256:` and 64 hex digits). Without one the
    /// platform validates its certificate; validation is never skipped.
    #[serde(default)]
    pub pin: Option<String>,
}

/// A relay list as a file (`{"version": 1, "relays": [...]}`): how
/// operators of federated relays publish them. It is only ever read from a
/// local file the user chose; nothing is fetched.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RelayList {
    /// The format version, 1.
    pub version: u16,
    /// The relays.
    pub relays: Vec<RelayConfig>,
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
    /// The relays to meet contacts through when they are not nearby (§10);
    /// none means no relay is used.
    #[serde(default)]
    pub relays: Vec<RelayConfig>,
    /// How often, in seconds, two idle devices meet at a relay so that
    /// either can reach the other: at least 10, by default 300. Shorter is
    /// faster to reach and costs more sessions.
    #[serde(default = "default_presence")]
    pub relay_presence_seconds: u32,
    /// Start hidden from contacts (see `Request::SetHidden`).
    #[serde(default)]
    pub hidden: bool,
    /// How many days finished transfers stay in the sealed history: at
    /// most [`MAX_HISTORY_DAYS`], by default 30; 0 keeps none (§7.7 leaves
    /// receipt retention to local policy).
    #[serde(default = "default_history_days")]
    pub history_days: u32,
}

/// The longest history retention, in days.
pub const MAX_HISTORY_DAYS: u32 = 3650;

const fn default_presence() -> u32 {
    300
}

const fn default_history_days() -> u32 {
    30
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
            relays: Vec::new(),
            relay_presence_seconds: default_presence(),
            hidden: false,
            history_days: default_history_days(),
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
        assert!(!minimal.hidden);
        assert_eq!(minimal.history_days, 30);
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
