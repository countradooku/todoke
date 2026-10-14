//! The IPC endpoint per platform (see [`crate::ipc`] for who may connect).

use std::path::{Path, PathBuf};

use crate::ipc::Stream;

/// How a client proved it is this user.
pub(crate) enum Proof {
    /// Its peer user ID was checked at accept (Unix): no token expected.
    #[cfg_attr(
        not(unix),
        allow(dead_code, reason = "Unix endpoints only; tested everywhere")
    )]
    PeerChecked,
    /// It must present this token (Windows).
    #[cfg_attr(
        unix,
        allow(dead_code, reason = "Windows endpoints only; tested everywhere")
    )]
    Token(zeroize::Zeroizing<String>),
}

/// The listening endpoint.
pub(crate) struct Listener {
    #[cfg(unix)]
    unix: tokio::net::UnixListener,
    #[cfg(not(unix))]
    tcp: tokio::net::TcpListener,
    #[cfg(not(unix))]
    token: zeroize::Zeroizing<String>,
    path: PathBuf,
}

impl Listener {
    /// Binds the endpoint at `path`.
    ///
    /// # Errors
    ///
    /// `AddrInUse` if a daemon already answers there; other I/O errors.
    pub(crate) async fn bind(path: &Path) -> std::io::Result<Self> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
            if let Some(parent) = path.parent()
                && parent == crate::paths::shared_tmp()
            {
                private_socket_dir(parent)?;
            }
            match std::fs::symlink_metadata(path) {
                Ok(metadata) if metadata.file_type().is_socket() => {
                    if tokio::net::UnixStream::connect(path).await.is_ok() {
                        return Err(std::io::ErrorKind::AddrInUse.into());
                    }
                    std::fs::remove_file(path)?;
                }
                Ok(_) => return Err(std::io::ErrorKind::AlreadyExists.into()),
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
                Err(error) => return Err(error),
            }
            let unix = tokio::net::UnixListener::bind(path)?;
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
            Ok(Self {
                unix,
                path: path.to_owned(),
            })
        }
        #[cfg(not(unix))]
        {
            if let Ok((_, Some(_))) = connect(path).await {
                return Err(std::io::ErrorKind::AddrInUse.into());
            }
            let tcp = tokio::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
            let mut raw = [0; 32];
            getrandom::fill(&mut raw).map_err(|_| std::io::Error::other("randomness"))?;
            let token = zeroize::Zeroizing::new(todoke_core::api::hex(raw));
            let port = tcp.local_addr()?.port();
            std::fs::write(path, format!("{port} {}", token.as_str()))?;
            Ok(Self {
                tcp,
                token,
                path: path.to_owned(),
            })
        }
    }

    /// The next connection and how it must prove itself. On Unix a
    /// connection from another user is closed here.
    ///
    /// # Errors
    ///
    /// An accept error.
    pub(crate) async fn accept(&self) -> std::io::Result<(Box<dyn Stream>, Proof)> {
        loop {
            #[cfg(unix)]
            {
                let (stream, _) = self.unix.accept().await?;
                let ours = rustix::process::getuid().as_raw();
                if stream.peer_cred().is_ok_and(|cred| cred.uid() == ours) {
                    return Ok((Box::new(stream), Proof::PeerChecked));
                }
            }
            #[cfg(not(unix))]
            {
                let (stream, peer) = self.tcp.accept().await?;
                if peer.ip().is_loopback() {
                    return Ok((Box::new(stream), Proof::Token(self.token.clone())));
                }
            }
        }
    }
}

/// Creates `dir` (0700) if missing and refuses it unless it is a real
/// directory this user owns that nobody else can enter: a directory under
/// `/tmp` could have been created by someone else first.
#[cfg(unix)]
fn private_socket_dir(dir: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _};
    match std::fs::DirBuilder::new().mode(0o700).create(dir) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error),
    }
    let metadata = std::fs::symlink_metadata(dir)?;
    let ours = rustix::process::getuid().as_raw();
    if !metadata.is_dir() || metadata.uid() != ours || metadata.permissions().mode() & 0o077 != 0 {
        return Err(std::io::ErrorKind::PermissionDenied.into());
    }
    Ok(())
}

impl Drop for Listener {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(&self.path);
    }
}

/// Connects to the endpoint at `path`; returns the token to present.
///
/// # Errors
///
/// `NotFound` or `ConnectionRefused` if no daemon runs.
pub(crate) async fn connect(path: &Path) -> std::io::Result<(Box<dyn Stream>, Option<String>)> {
    #[cfg(unix)]
    {
        let stream = tokio::net::UnixStream::connect(path).await?;
        Ok((Box::new(stream), None))
    }
    #[cfg(not(unix))]
    {
        let text = zeroize::Zeroizing::new(std::fs::read_to_string(path)?);
        let (port, token) = text
            .split_once(' ')
            .ok_or_else(|| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
        let port: u16 = port
            .parse()
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidData))?;
        let stream = tokio::net::TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port)).await?;
        Ok((Box::new(stream), Some(token.trim().to_owned())))
    }
}

/// Whether a client's hello `token` satisfies `proof` (constant time).
pub(crate) fn check(proof: &Proof, token: Option<&str>) -> bool {
    match (proof, token) {
        (Proof::PeerChecked, None) => true,
        (Proof::Token(expected), Some(given)) => {
            use subtle::ConstantTimeEq as _;
            expected.len() == given.len() && bool::from(expected.as_bytes().ct_eq(given.as_bytes()))
        }
        _ => false,
    }
}
