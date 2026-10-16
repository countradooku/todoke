//! The app's [`WifiLinks`] as the core's link platform (PROTOCOL §10.2).
//!
//! The app's leases are checked here before the core uses them: addresses
//! that parse, a host address for every join. A lease whose link the core
//! no longer wants (it gave up meanwhile) is released at once.

use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::Ordering;

use todoke_core::link as proto;
use todoke_core::link::{HostRequest, JoinRequest, LinkPlatform};

use crate::hooks::{
    LinkAbilities, LinkError, LinkKind, LinkLease, LinkRequest, LinkSecurity, WifiLinks,
};

/// The app's links, for the core.
pub(crate) struct AppLinks {
    links: Arc<dyn WifiLinks>,
}

impl AppLinks {
    pub(crate) fn new(links: Arc<dyn WifiLinks>) -> Self {
        Self { links }
    }

    /// The core's lease for the app's: released when the core drops it.
    fn lease(
        &self,
        lease: &LinkLease,
        joining: bool,
        cancel: &std::sync::atomic::AtomicBool,
    ) -> io::Result<todoke_core::link::LinkLease> {
        let release = Release {
            links: Arc::clone(&self.links),
            id: lease.id,
        };
        if cancel.load(Ordering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::Interrupted,
                "the link is no longer wanted",
            ));
        }
        let invalid = |what| io::Error::new(io::ErrorKind::InvalidData, what);
        let local: IpAddr = lease
            .local
            .parse()
            .map_err(|_| invalid("the app gave no address on the link"))?;
        let host = match lease.host.as_deref() {
            Some(host) if joining => Some(
                host.parse::<IpAddr>()
                    .map_err(|_| invalid("the app gave no host address on the link"))?,
            ),
            // Apple platforms name no router for a joined network: the
            // routing table does (the joined interface's default gateway).
            None if joining => Some(
                gateway(lease.interface)
                    .ok_or_else(|| invalid("the app gave no host address on the link"))?,
            ),
            _ => None,
        };
        // Unspecified only for a host that names the link's interfaces.
        let unspecified = local == IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED);
        if unspecified && (joining || lease.scopes.is_empty() || lease.scopes.contains(&0)) {
            return Err(invalid("the app gave no address or interfaces on the link"));
        }
        let mut core = todoke_core::link::LinkLease::new(local, host, lease.interface, release);
        if unspecified {
            core = core.with_scopes(lease.scopes.clone());
        }
        if !lease.bind_sockets {
            return Ok(core);
        }
        let links = Arc::clone(&self.links);
        let id = lease.id;
        Ok(core.with_bind(Arc::new(move |handle| {
            links.bind_socket(id, handle).map_err(io_error)
        })))
    }
}

impl LinkPlatform for AppLinks {
    fn abilities(&self) -> proto::LinkAbilities {
        let LinkAbilities {
            host,
            join,
            join_security,
        } = self.links.abilities();
        let kinds = |kinds: Vec<LinkKind>| {
            kinds
                .into_iter()
                .map(proto::LinkKind::from)
                .collect::<Vec<_>>()
        };
        let security: Vec<_> = join_security
            .into_iter()
            .map(proto::LinkSecurity::from)
            .collect();
        proto::LinkAbilities::new(&kinds(host), &kinds(join), &security)
    }

    fn host(&self, request: &HostRequest) -> io::Result<todoke_core::link::LinkLease> {
        let lease = self
            .links
            .host(LinkRequest {
                kind: request.kind.into(),
                security: request.security.into(),
                ssid: request.ssid.clone(),
                secret: request.secret.to_vec(),
                service_info: service_info(request.kind, request.service_info),
                within_ms: 0,
            })
            .map_err(io_error)?;
        self.lease(&lease, false, &request.cancel)
    }

    fn join(&self, request: &JoinRequest) -> io::Result<todoke_core::link::LinkLease> {
        let lease = self
            .links
            .join(LinkRequest {
                kind: request.kind.into(),
                security: request.security.into(),
                ssid: request.ssid.clone(),
                secret: request.secret.to_vec(),
                service_info: service_info(request.kind, request.service_info),
                within_ms: u64::try_from(request.within.as_millis()).unwrap_or(u64::MAX),
            })
            .map_err(io_error)?;
        self.lease(&lease, true, &request.cancel)
    }
}

/// The default gateway of `interface`, where the platform has no API for a
/// joined network's router (Apple's).
#[cfg(any(target_os = "macos", target_os = "ios"))]
fn gateway(interface: u32) -> Option<IpAddr> {
    (interface != 0)
        .then(|| todoke_sys_macos::route::gateway(interface))
        .flatten()
        .map(IpAddr::V4)
}

#[cfg(not(any(target_os = "macos", target_os = "ios")))]
const fn gateway(_: u32) -> Option<IpAddr> {
    None
}

/// The service information to publish or match: Wi-Fi Aware only.
fn service_info(kind: proto::LinkKind, info: [u8; 8]) -> Vec<u8> {
    if kind == proto::LinkKind::WifiAware {
        info.to_vec()
    } else {
        Vec::new()
    }
}

fn io_error(error: LinkError) -> io::Error {
    match error {
        LinkError::Closed => io::Error::from(io::ErrorKind::NotConnected),
        LinkError::Failed { message } => io::Error::other(message),
    }
}

/// Releases the app's link when dropped, off the dropping thread (the
/// core's: releasing calls into the app and may block).
struct Release {
    links: Arc<dyn WifiLinks>,
    id: u64,
}

impl Drop for Release {
    fn drop(&mut self) {
        let links = Arc::clone(&self.links);
        let id = self.id;
        let spawned = std::thread::Builder::new()
            .name("todoke-link-release".to_owned())
            .spawn(move || links.release(id));
        if spawned.is_err() {
            // No thread: released here rather than never.
            self.links.release(id);
        }
    }
}

impl From<LinkKind> for proto::LinkKind {
    fn from(kind: LinkKind) -> Self {
        match kind {
            LinkKind::WifiAware => Self::WifiAware,
            LinkKind::WifiDirect => Self::WifiDirect,
            LinkKind::Hotspot => Self::Hotspot,
        }
    }
}

impl From<proto::LinkKind> for LinkKind {
    fn from(kind: proto::LinkKind) -> Self {
        match kind {
            proto::LinkKind::WifiAware => Self::WifiAware,
            proto::LinkKind::WifiDirect => Self::WifiDirect,
            proto::LinkKind::Hotspot => Self::Hotspot,
        }
    }
}

impl From<LinkSecurity> for proto::LinkSecurity {
    fn from(security: LinkSecurity) -> Self {
        match security {
            LinkSecurity::Wpa3 => Self::Wpa3,
            LinkSecurity::Wpa3Transition => Self::Wpa3Transition,
            LinkSecurity::Wpa2 => Self::Wpa2,
            LinkSecurity::AwareSk256 => Self::AwareSk256,
            LinkSecurity::AwareSk128 => Self::AwareSk128,
        }
    }
}

impl From<proto::LinkSecurity> for LinkSecurity {
    fn from(security: proto::LinkSecurity) -> Self {
        match security {
            proto::LinkSecurity::Wpa3 => Self::Wpa3,
            proto::LinkSecurity::Wpa3Transition => Self::Wpa3Transition,
            proto::LinkSecurity::Wpa2 => Self::Wpa2,
            proto::LinkSecurity::AwareSk256 => Self::AwareSk256,
            proto::LinkSecurity::AwareSk128 => Self::AwareSk128,
        }
    }
}

#[cfg(test)]
mod tests;
