//! Which addresses the LAN transport may contact or accept (PROTOCOL §9,
//! §10).
//!
//! mDNS addresses and SRV ports are untrusted (§9): anyone on the network
//! can answer with any address. Without a policy, a hostile record could
//! make this device open connections to the internet, to its own loopback
//! services, or to a router's administration port. Only private and
//! link-local addresses on unprivileged ports are allowed (§10: loopback,
//! unspecified, multicast, broadcast, and privileged or administrative
//! service endpoints MUST NOT be contacted).

use core::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// The lowest port a LAN peer may use: ports below are privileged service
/// endpoints (§10).
pub const MIN_PEER_PORT: u16 = 1024;

/// Why an address was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// Not a private or link-local address: a global, loopback, multicast,
    /// broadcast, unspecified, shared, or reserved one.
    NotLocal,
    /// A privileged port (below [`MIN_PEER_PORT`]).
    PrivilegedPort,
    /// An IPv6 link-local address without an interface (scope) ID.
    NoScope,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::NotLocal => "not a local network address",
            Self::PrivilegedPort => "privileged port",
            Self::NoScope => "link-local address without an interface",
        })
    }
}

impl std::error::Error for Refusal {}

/// The LAN address policy. The default allows only private (RFC 1918,
/// RFC 4193) and link-local addresses.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct LanPolicy {
    loopback: bool,
}

impl LanPolicy {
    /// The policy for a real network.
    #[must_use]
    pub const fn new() -> Self {
        Self { loopback: false }
    }

    /// Also allows loopback, for running two instances on one machine
    /// (development and tests). Never the default.
    #[must_use]
    pub const fn with_loopback(mut self) -> Self {
        self.loopback = true;
        self
    }

    /// Whether this device may connect to `address`.
    ///
    /// # Errors
    ///
    /// The [`Refusal`].
    pub fn check_peer(self, address: SocketAddr) -> Result<(), Refusal> {
        self.check_ip(address)?;
        if address.port() < MIN_PEER_PORT {
            return Err(Refusal::PrivilegedPort);
        }
        Ok(())
    }

    /// Whether a connection from `address` may be accepted. Its source port
    /// is whatever the peer's system chose, so only the address counts.
    ///
    /// # Errors
    ///
    /// The [`Refusal`].
    pub fn check_source(self, address: SocketAddr) -> Result<(), Refusal> {
        self.check_ip(address)
    }

    fn check_ip(self, address: SocketAddr) -> Result<(), Refusal> {
        match address {
            SocketAddr::V4(v4) => self.check_v4(*v4.ip()),
            SocketAddr::V6(v6) => {
                let ip = *v6.ip();
                if let Some(mapped) = ip.to_ipv4_mapped() {
                    return self.check_v4(mapped);
                }
                if ip.is_unicast_link_local() && v6.scope_id() == 0 {
                    return Err(Refusal::NoScope);
                }
                self.check_v6(ip)
            }
        }
    }

    fn check_v4(self, ip: Ipv4Addr) -> Result<(), Refusal> {
        if ip.is_loopback() {
            return if self.loopback {
                Ok(())
            } else {
                Err(Refusal::NotLocal)
            };
        }
        // 169.254.169.254 and its neighbours are cloud metadata services,
        // not peers.
        let metadata = ip.octets()[..3] == [169, 254, 169];
        if (ip.is_private() || ip.is_link_local()) && !metadata && !ip.is_broadcast() {
            Ok(())
        } else {
            Err(Refusal::NotLocal)
        }
    }

    fn check_v6(self, ip: Ipv6Addr) -> Result<(), Refusal> {
        if ip.is_loopback() {
            return if self.loopback {
                Ok(())
            } else {
                Err(Refusal::NotLocal)
            };
        }
        if ip.is_unicast_link_local() || ip.is_unique_local() {
            Ok(())
        } else {
            Err(Refusal::NotLocal)
        }
    }
}

/// Whether `ip` is an address the policy could ever allow (loopback
/// aside); used to pick which local interfaces to advertise.
#[must_use]
pub fn is_local_network(ip: IpAddr) -> bool {
    let probe = match ip {
        IpAddr::V4(v4) => SocketAddr::from((v4, MIN_PEER_PORT)),
        // Advertised link-local addresses get their scope from the
        // receiving interface; assume one here.
        IpAddr::V6(v6) => SocketAddr::V6(std::net::SocketAddrV6::new(v6, MIN_PEER_PORT, 0, 1)),
    };
    LanPolicy::new().check_peer(probe).is_ok()
}

#[cfg(test)]
mod tests;
