//! Where the daemon keeps its configuration, state, and IPC endpoint.
//!
//! By default the platform's directories: configuration in the
//! configuration directory, state (identity, contacts, quarantine) in the
//! local data directory, received files in `~/Downloads`.
//!
//! | Platform | Configuration | State |
//! | --- | --- | --- |
//! | Linux and other Unix | `$XDG_CONFIG_HOME/todoke` (`~/.config/todoke`) | `$XDG_DATA_HOME/todoke` (`~/.local/share/todoke`) |
//! | macOS | `~/Library/Application Support/org.todoke.todoke` | the same, `state/` |
//! | Windows | `%APPDATA%\todoke` | `%LOCALAPPDATA%\todoke` |
//!
//! XDG variables are used only when they hold absolute paths, as the XDG
//! specification requires.
//! With `TODOKE_HOME` set, everything lives under that directory instead
//! (tests, portable installs). Nothing is ever sent anywhere: there is no
//! telemetry.

use std::path::{Path, PathBuf};

use todoke_core::config::CoreConfig;

/// The environment variable that puts everything under one directory.
pub const HOME_VARIABLE: &str = "TODOKE_HOME";

/// The daemon's file locations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Paths {
    /// `config.json`.
    pub config_file: PathBuf,
    /// The private state directory.
    pub state_dir: PathBuf,
    /// The default destination for received files.
    pub downloads_dir: PathBuf,
}

impl Paths {
    /// Everything under `home`.
    #[must_use]
    pub fn under(home: &Path) -> Self {
        Self {
            config_file: home.join("config.json"),
            state_dir: home.join("state"),
            downloads_dir: home.join("downloads"),
        }
    }

    /// From `TODOKE_HOME` if set, else the platform's directories.
    ///
    /// # Errors
    ///
    /// `NotFound` if the platform has no home directory.
    pub fn discover() -> std::io::Result<Self> {
        if let Some(home) = std::env::var_os(HOME_VARIABLE) {
            // Absolute, so every working directory finds the same daemon.
            return Ok(Self::under(&std::path::absolute(home)?));
        }
        let home = std::env::home_dir()
            .filter(|home| home.is_absolute())
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
        let (config, data) = platform_dirs(&home)?;
        Ok(Self {
            config_file: config.join("config.json"),
            state_dir: data.join("state"),
            downloads_dir: home.join("Downloads"),
        })
    }

    /// The daemon's IPC endpoint: a Unix socket, or (Windows) a file with
    /// the loopback port and the access token.
    ///
    /// A Unix socket path must be short (`sun_path` holds 104 bytes on
    /// macOS, 108 on Linux). The socket lives in the private state
    /// directory when the path fits; otherwise in the user's private runtime
    /// directory (`$XDG_RUNTIME_DIR`, or `$TMPDIR` on macOS), used only if
    /// this user owns it and nobody else can enter it, or in
    /// `/tmp/todoke-<uid>`, which the daemon creates 0700 and refuses to use
    /// unless it owns it. The name is derived from the state
    /// directory, so two homes never share a socket, and spellings of one
    /// path (repeated or trailing separators) share it.
    #[must_use]
    pub fn endpoint(&self) -> PathBuf {
        if !cfg!(unix) {
            return self.state_dir.join("daemon.endpoint");
        }
        let inside = self.state_dir.join("daemon.sock");
        if fits(&inside) {
            return inside;
        }
        // Hashed by components: `a//b` and `a/b/` name the same directory.
        let normal: PathBuf = self.state_dir.components().collect();
        let name = format!(
            "todoke-{:016x}.sock",
            fnv1a(normal.as_os_str().as_encoded_bytes())
        );
        for variable in ["XDG_RUNTIME_DIR", "TMPDIR"] {
            if let Some(dir) = std::env::var_os(variable).map(PathBuf::from)
                && dir.is_absolute()
                && fits(&dir.join(&name))
                && private_to_us(&dir)
            {
                return dir.join(name);
            }
        }
        shared_tmp().join(name)
    }

    /// The storage key file (until platform secret storage, §16 O9).
    #[must_use]
    pub fn storage_key(&self) -> PathBuf {
        self.state_dir.join("storage.key")
    }

    /// The configuration: `config.json` if it exists, else the defaults
    /// (which are then written, so the user can edit them).
    ///
    /// # Errors
    ///
    /// An I/O error, or `InvalidData` for a configuration that does not
    /// parse (it is never overwritten).
    pub fn config(&self) -> std::io::Result<CoreConfig> {
        match std::fs::read(&self.config_file) {
            Ok(bytes) => serde_json::from_slice(&bytes)
                .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                let config = CoreConfig::new(self.state_dir.clone(), self.downloads_dir.clone());
                if let Some(parent) = self.config_file.parent() {
                    std::fs::create_dir_all(parent)?;
                }
                let text = serde_json::to_vec_pretty(&config)
                    .map_err(|error| std::io::Error::new(std::io::ErrorKind::InvalidData, error))?;
                std::fs::write(&self.config_file, text)?;
                Ok(config)
            }
            Err(error) => Err(error),
        }
    }
}

/// The longest socket path used: under both platforms' `sun_path` limits.
const MAX_SOCKET_PATH: usize = 100;

fn fits(path: &Path) -> bool {
    path.as_os_str().len() < MAX_SOCKET_PATH
}

/// `/tmp/todoke-<uid>`: checked for ownership before use (see
/// `endpoint::private_socket_dir`).
#[must_use]
pub fn shared_tmp() -> PathBuf {
    #[cfg(unix)]
    let uid = rustix::process::getuid().as_raw();
    #[cfg(not(unix))]
    let uid = 0;
    PathBuf::from("/tmp").join(format!("todoke-{uid}"))
}

/// Whether `dir` is a directory this user owns that nobody else can enter
/// (a shared `/tmp` is not: another user could plant a socket in it).
fn private_to_us(dir: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        std::fs::metadata(dir).is_ok_and(|metadata| {
            let shared = metadata.permissions().mode() & 0o077 != 0;
            metadata.is_dir() && metadata.uid() == rustix::process::getuid().as_raw() && !shared
        })
    }
    #[cfg(not(unix))]
    {
        let _ = dir;
        false
    }
}

/// FNV-1a: a stable, short name for a path (not a security measure).
fn fnv1a(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0xcbf2_9ce4_8422_2325_u64, |hash, byte| {
        (hash ^ u64::from(*byte)).wrapping_mul(0x0000_0100_0000_01b3)
    })
}

/// The configuration and data directories for this platform.
fn platform_dirs(home: &Path) -> std::io::Result<(PathBuf, PathBuf)> {
    if cfg!(target_os = "macos") {
        let base = home
            .join("Library")
            .join("Application Support")
            .join("org.todoke.todoke");
        return Ok((base.clone(), base));
    }
    if cfg!(windows) {
        let variable = |name: &str| {
            std::env::var_os(name)
                .map(PathBuf::from)
                .filter(|path| path.is_absolute())
                .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))
        };
        return Ok((
            variable("APPDATA")?.join("todoke"),
            variable("LOCALAPPDATA")?.join("todoke"),
        ));
    }
    let xdg = |name: &str, fallback: PathBuf| {
        std::env::var_os(name)
            .map(PathBuf::from)
            .filter(|path| path.is_absolute())
            .unwrap_or(fallback)
            .join("todoke")
    };
    Ok((
        xdg("XDG_CONFIG_HOME", home.join(".config")),
        xdg("XDG_DATA_HOME", home.join(".local").join("share")),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn everything_lives_under_one_home() {
        let paths = Paths::under(Path::new("/home/me/.todoke"));
        assert_eq!(paths.config_file, Path::new("/home/me/.todoke/config.json"));
        assert!(paths.endpoint().starts_with("/home/me/.todoke/state"));
        assert!(paths.storage_key().starts_with(&paths.state_dir));
    }

    #[cfg(unix)]
    #[test]
    fn socket_paths_stay_short_and_distinct() {
        let short = Paths::under(Path::new("/h"));
        assert_eq!(short.endpoint(), Path::new("/h/state/daemon.sock"));
        let long_a = Paths::under(&Path::new("/").join("a".repeat(120)));
        let long_b = Paths::under(&Path::new("/").join("b".repeat(120)));
        assert!(long_a.endpoint().as_os_str().len() < MAX_SOCKET_PATH);
        assert_ne!(long_a.endpoint(), long_b.endpoint());
        assert_eq!(long_a.endpoint(), long_a.endpoint());
        // Another spelling of the same directory finds the same socket.
        let spelled = Paths::under(Path::new(&format!("//{}//", "a".repeat(120))));
        assert_eq!(spelled.endpoint(), long_a.endpoint());
    }

    #[test]
    fn platform_directories_are_under_home() -> std::io::Result<()> {
        let home = Path::new("/home/me");
        let (config, data) = platform_dirs(home)?;
        if cfg!(any(target_os = "macos", not(windows))) {
            assert!(config.starts_with(home) || std::env::var_os("XDG_CONFIG_HOME").is_some());
            assert!(data.starts_with(home) || std::env::var_os("XDG_DATA_HOME").is_some());
        }
        assert!(config.ends_with("todoke") || config.ends_with("org.todoke.todoke"));
        Ok(())
    }

    #[test]
    fn a_missing_configuration_is_written_with_defaults() -> Result<(), Box<dyn std::error::Error>>
    {
        let mut random = [0; 8];
        getrandom::fill(&mut random)?;
        let home =
            std::env::temp_dir().join(format!("todoke-paths-{}", u64::from_le_bytes(random)));
        let paths = Paths::under(&home);
        let config = paths.config()?;
        assert_eq!(config.state_dir, paths.state_dir);
        assert_eq!(paths.config()?, config);
        std::fs::write(&paths.config_file, b"{not json")?;
        assert_eq!(
            paths.config().map(|_| ()).map_err(|error| error.kind()),
            Err(std::io::ErrorKind::InvalidData)
        );
        std::fs::remove_dir_all(&home)?;
        Ok(())
    }
}
