//! How the core advertises and browses: mDNS (through the system's Bonjour
//! on iOS, where raw multicast needs a restricted entitlement), or
//! (development and tests only) a folder of records two instances on one
//! machine share.

use core::time::Duration;
use std::path::PathBuf;

use todoke_crypto::discovery::DiscoveryTable;
#[cfg(target_os = "ios")]
pub(crate) use todoke_discovery::Bonjour as Mdns;
#[cfg(not(target_os = "ios"))]
pub(crate) use todoke_discovery::Mdns;
use todoke_discovery::{Directory, Plan};
use todoke_proto::discovery::InstanceLabel;
use todoke_transport::LanPolicy;

/// The discovery backend.
pub(crate) enum Backend {
    /// mDNS on the local network (§9): `mdns-sd`, or the system's Bonjour
    /// on iOS.
    Mdns(Mdns),
    /// Records as files in a shared folder; development and tests only.
    Folder(Folder),
    /// No discovery (the LAN is disabled).
    Off,
}

impl Backend {
    /// Advertises `plan`.
    pub(crate) fn apply(&mut self, plan: &Plan) {
        match self {
            Self::Mdns(mdns) => {
                let _ = mdns.apply(plan);
            }
            Self::Folder(folder) => folder.apply(plan),
            Self::Off => {}
        }
    }

    /// Feeds what was found into `directory`.
    pub(crate) fn drain(
        &mut self,
        directory: &mut Directory,
        table: &DiscoveryTable,
        now: Duration,
    ) {
        match self {
            Self::Mdns(mdns) => {
                mdns.drain(directory, table, now);
            }
            Self::Folder(folder) => folder.drain(directory, table, now),
            Self::Off => {}
        }
    }
}

/// Discovery through files: each instance writes `<label>.rec` with its
/// port and TXT value and reads the others'. Every record still passes
/// [`todoke_discovery::Sighting::check`] and the LAN policy.
pub(crate) struct Folder {
    dir: PathBuf,
    port: u16,
    policy: LanPolicy,
    written: Vec<PathBuf>,
    /// The labels found by the last drain: a record that disappears is a
    /// goodbye, as in mDNS.
    present: Vec<InstanceLabel>,
}

impl Folder {
    /// The folder `dir` (created if needed), advertising `port`.
    pub(crate) fn new(dir: PathBuf, port: u16, policy: LanPolicy) -> std::io::Result<Self> {
        std::fs::create_dir_all(&dir)?;
        Ok(Self {
            dir,
            port,
            policy,
            written: Vec::new(),
            present: Vec::new(),
        })
    }

    fn apply(&mut self, plan: &Plan) {
        let wanted: Vec<(PathBuf, String)> = plan
            .paired
            .iter()
            .chain(plan.stranger.iter())
            .map(|advertisement| {
                (
                    self.dir
                        .join(format!("{}.rec", advertisement.label.as_str())),
                    format!("{} {}", self.port, advertisement.record.txt_value()),
                )
            })
            .collect();
        for path in &self.written {
            if !wanted.iter().any(|(wanted, _)| wanted == path) {
                let _ = std::fs::remove_file(path);
            }
        }
        for (path, contents) in &wanted {
            // Written whole, then renamed: readers never see half a record.
            let partial = path.with_extension("tmp");
            if std::fs::write(&partial, contents).is_ok() {
                let _ = std::fs::rename(&partial, path);
            }
        }
        self.written = wanted.into_iter().map(|(path, _)| path).collect();
    }

    fn drain(&mut self, directory: &mut Directory, table: &DiscoveryTable, now: Duration) {
        let Ok(entries) = std::fs::read_dir(&self.dir) else {
            return;
        };
        let mut present = Vec::new();
        for entry in entries.filter_map(Result::ok).take(256) {
            let path = entry.path();
            let Some(label) = path
                .file_name()
                .and_then(|name| name.to_str())
                .and_then(|name| name.strip_suffix(".rec"))
            else {
                continue;
            };
            let Ok(contents) = std::fs::read_to_string(&path) else {
                continue;
            };
            let Some((port, value)) = contents.split_once(' ') else {
                continue;
            };
            let Ok(port) = port.parse::<u16>() else {
                continue;
            };
            let fullname = format!("{label}.{}", todoke_proto::discovery::MDNS_SERVICE);
            let addresses = [(std::net::IpAddr::from([127, 0, 0, 1]), 0)];
            if let Ok(sighting) = todoke_discovery::Sighting::check(
                &fullname,
                port,
                addresses,
                [("v1", Some(value.as_bytes()))],
                self.policy,
            ) {
                present.push(*sighting.label());
                directory.observe(sighting, table, now);
            }
        }
        for gone in self.present.iter().filter(|label| !present.contains(label)) {
            directory.remove(gone);
        }
        self.present = present;
    }
}

impl Drop for Folder {
    fn drop(&mut self) {
        for path in &self.written {
            let _ = std::fs::remove_file(path);
        }
    }
}
