//! Direct Wi-Fi links (PROTOCOL §10.2): what a platform does to host and
//! join them, and the credentials the host makes for each offer.
//!
//! The core decides everything protocol-side: whether to take part (only
//! with a platform, as configured), when to host (only for a transfer the
//! user started or accepted on this device, pending or running), what to
//! offer, and how the session moves onto the link. A [`LinkPlatform`]
//! only brings a link up and down with the operating system's app-scoped,
//! temporary mechanisms. Secrets reach it in zeroized buffers; it must keep
//! no copy once the link is up, and it tears the link down (leaving or
//! removing the group, hotspot, or data path and any configuration it
//! created) when the [`LinkLease`] is dropped.

use core::fmt;
use core::time::Duration;
use std::io;
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::AtomicBool;

pub use todoke_proto::link::{LinkAbilities, LinkKind, LinkSecurity};
use todoke_proto::link::{PASSPHRASE_LEN, PMK_LEN};
use zeroize::Zeroizing;

/// The 64 characters a passphrase is drawn from (§10.2), so that one
/// random byte's low six bits pick one uniformly.
const PASSPHRASE_ALPHABET: &[u8; 64] =
    b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// A link to host (§10.2): its kind, security, and the credentials this
/// device made for the offer.
pub struct HostRequest {
    /// The kind.
    pub kind: LinkKind,
    /// The security, the strongest the joiner can join.
    pub security: LinkSecurity,
    /// The network name (empty for a Wi-Fi Aware data path).
    pub ssid: String,
    /// The passphrase, or for Wi-Fi Aware the PMK.
    pub secret: Zeroizing<Vec<u8>>,
    /// For Wi-Fi Aware: the service-specific information to publish
    /// (`offer_id[..8]`).
    pub service_info: [u8; 8],
    /// Set once the core no longer wants the link: stop and fail.
    pub cancel: Arc<AtomicBool>,
}

/// A link offered by the host, to join (§10.2).
pub struct JoinRequest {
    /// The kind.
    pub kind: LinkKind,
    /// The security the host offers.
    pub security: LinkSecurity,
    /// The network name (empty for a Wi-Fi Aware data path).
    pub ssid: String,
    /// The passphrase, or for Wi-Fi Aware the PMK.
    pub secret: Zeroizing<Vec<u8>>,
    /// For Wi-Fi Aware: the publisher's service-specific information to
    /// match (`offer_id[..8]`).
    pub service_info: [u8; 8],
    /// How long the offer stands: give up after this.
    pub within: Duration,
    /// Set once the core no longer wants the link (the device stops):
    /// stop and fail.
    pub cancel: Arc<AtomicBool>,
}

impl fmt::Debug for HostRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HostRequest")
            .field("kind", &self.kind)
            .field("security", &self.security)
            .finish_non_exhaustive()
    }
}

impl fmt::Debug for JoinRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("JoinRequest")
            .field("kind", &self.kind)
            .field("security", &self.security)
            .finish_non_exhaustive()
    }
}

/// Binds a socket to a link before it listens or connects, given its raw
/// handle: the same type as the transport's (every target has it here, the
/// browser too, where no transport exists).
pub type BindSocket = dyn Fn(i64) -> io::Result<()> + Send + Sync;

/// A link that is up, until dropped: dropping it tears the link down.
pub struct LinkLease {
    /// This device's address on the link: the host listens on it, the
    /// joiner connects from it. A host whose address comes only once the
    /// joiner sets the link up (a Wi-Fi Aware data path) gives the IPv6
    /// unspecified address and the link's possible interfaces in
    /// [`LinkLease::scopes`].
    pub local: IpAddr,
    /// The host's address on the link (the group owner, the hotspot's
    /// gateway, the Wi-Fi Aware peer), for the joiner to connect to; `None`
    /// on the host.
    pub host: Option<IpAddr>,
    /// The link's interface index (the scope of link-local IPv6
    /// addresses); 0 if unknown.
    pub interface: u32,
    /// Binds a socket to the link before it listens or connects, where the
    /// link is a network of its own (Android).
    pub bind: Option<Arc<BindSocket>>,
    /// With an unspecified `local`: the interfaces the link may come up
    /// on; the host accepts only link-local peers arriving on them.
    pub scopes: Vec<u32>,
    _teardown: Box<dyn Send>,
}

impl LinkLease {
    /// A lease on a link that is up; `teardown` is dropped (and so tears
    /// the link down) when the lease is.
    pub fn new(
        local: IpAddr,
        host: Option<IpAddr>,
        interface: u32,
        teardown: impl Send + 'static,
    ) -> Self {
        Self {
            local,
            host,
            interface,
            bind: None,
            scopes: Vec::new(),
            _teardown: Box::new(teardown),
        }
    }

    /// For a host whose address comes once the link is up: accepting only
    /// link-local peers on `scopes`.
    #[must_use]
    pub fn with_scopes(mut self, scopes: Vec<u32>) -> Self {
        self.scopes = scopes;
        self
    }

    /// With sockets bound to the link by `bind`.
    #[must_use]
    pub fn with_bind(mut self, bind: Arc<BindSocket>) -> Self {
        self.bind = Some(bind);
        self
    }
}

impl fmt::Debug for LinkLease {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LinkLease")
            .field("local", &self.local)
            .field("host", &self.host)
            .field("interface", &self.interface)
            .field("scopes", &self.scopes)
            .finish_non_exhaustive()
    }
}

/// What a platform can do to set up direct links. Every method may block
/// (bringing a hotspot up takes seconds); the core calls them off its
/// thread.
pub trait LinkPlatform: Send + Sync {
    /// What this device can host and join now (a probe of the hardware,
    /// the permissions, and the platform). Empty abilities take no part.
    /// Cheap: called once per session that may set up a link.
    fn abilities(&self) -> LinkAbilities;

    /// Hosts `request`: a group, hotspot, or data path with exactly these
    /// credentials, offering no default route and no DNS and forwarding
    /// nothing between the link and other networks.
    ///
    /// # Errors
    ///
    /// The link could not be brought up; no offer is made then.
    fn host(&self, request: &HostRequest) -> io::Result<LinkLease>;

    /// Joins `request` with the platform's app-scoped, temporary mechanism
    /// (never a saved or suggested network, never WPS or an open network),
    /// within its deadline.
    ///
    /// # Errors
    ///
    /// The link could not be joined; the answer is `failed` then.
    fn join(&self, request: &JoinRequest) -> io::Result<LinkLease>;
}

/// Fresh credentials for an offer of `kind` (§10.2), from the system's
/// CSPRNG: the network name (`todoke-` and 16 hexadecimal digits for a
/// hotspot; `DIRECT-`, 2 digits, `-tdk-`, and 16 digits for a Wi-Fi
/// Direct group; none for Wi-Fi Aware) and the secret (a 63-character
/// passphrase drawn uniformly from `A-Z a-z 0-9 - _`, or a 32-byte PMK).
///
/// # Errors
///
/// The system's random source failed.
pub fn credentials(kind: LinkKind) -> Result<(String, Zeroizing<Vec<u8>>), getrandom::Error> {
    let hex = |bytes: &[u8]| {
        bytes.iter().fold(String::new(), |mut out, byte| {
            use core::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
            out
        })
    };
    let mut name = [0_u8; 9];
    getrandom::fill(&mut name)?;
    let ssid = match kind {
        LinkKind::WifiAware => String::new(),
        LinkKind::Hotspot => format!("todoke-{}", hex(&name[1..])),
        LinkKind::WifiDirect => format!("DIRECT-{}-tdk-{}", hex(&name[..1]), hex(&name[1..])),
    };
    let secret = if kind == LinkKind::WifiAware {
        let mut pmk = Zeroizing::new(vec![0_u8; PMK_LEN]);
        getrandom::fill(&mut pmk)?;
        pmk
    } else {
        let mut random = Zeroizing::new([0_u8; PASSPHRASE_LEN]);
        getrandom::fill(&mut *random)?;
        Zeroizing::new(
            random
                .iter()
                .map(|byte| PASSPHRASE_ALPHABET[usize::from(byte & 63)])
                .collect(),
        )
    };
    Ok((ssid, secret))
}

/// When the core sets up direct links (§10.2).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DirectLinks {
    /// Never.
    Off,
    /// Only to move a session off a relay: devices that share a network
    /// already have a direct path, and joining another network takes this
    /// one off its own.
    #[default]
    FromRelay,
    /// From any session (development and tests; also for devices whose
    /// shared network is slow).
    Always,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every credential has the shape §10.2 gives it, and the passphrase
    /// draws on the whole alphabet (each character a uniform pick).
    #[test]
    fn credentials_have_their_exact_shapes() -> Result<(), Box<dyn std::error::Error>> {
        let lower_hex = |text: &str| {
            text.bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        };
        let mut seen = std::collections::BTreeSet::new();
        for _ in 0..64 {
            let (ssid, secret) = credentials(LinkKind::Hotspot)?;
            assert_eq!(ssid.len(), 23);
            let rest = ssid.strip_prefix("todoke-").ok_or("prefix")?;
            assert!(lower_hex(rest) && rest.len() == 16);
            assert_eq!(secret.len(), PASSPHRASE_LEN);
            assert!(secret.iter().all(|byte| PASSPHRASE_ALPHABET.contains(byte)));
            seen.extend(secret.iter().copied());
            let (ssid, secret) = credentials(LinkKind::WifiDirect)?;
            assert_eq!(ssid.len(), 30);
            let (two, sixteen) = ssid
                .strip_prefix("DIRECT-")
                .and_then(|rest| rest.split_once("-tdk-"))
                .ok_or("shape")?;
            assert!(lower_hex(two) && two.len() == 2);
            assert!(lower_hex(sixteen) && sixteen.len() == 16);
            assert_eq!(secret.len(), PASSPHRASE_LEN);
            let (ssid, pmk) = credentials(LinkKind::WifiAware)?;
            assert_eq!(ssid, "");
            assert_eq!(pmk.len(), PMK_LEN);
        }
        // 4032 draws from 64 characters: every one turns up.
        assert_eq!(seen.len(), 64);
        // Two offers never share credentials.
        assert_ne!(
            credentials(LinkKind::Hotspot)?.0,
            credentials(LinkKind::Hotspot)?.0
        );
        Ok(())
    }

    /// Requests and leases never print their secrets.
    #[test]
    fn nothing_secret_is_printed() -> Result<(), Box<dyn std::error::Error>> {
        let (ssid, secret) = credentials(LinkKind::Hotspot)?;
        let passphrase = String::from_utf8(secret.to_vec())?;
        let request = HostRequest {
            kind: LinkKind::Hotspot,
            security: LinkSecurity::Wpa3,
            ssid: ssid.clone(),
            secret,
            service_info: [0; 8],
            cancel: Arc::default(),
        };
        let printed = format!("{request:?}");
        assert!(!printed.contains(&passphrase) && !printed.contains(&ssid));
        Ok(())
    }
}
