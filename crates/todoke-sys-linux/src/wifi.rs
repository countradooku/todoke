//! Joining a Wi-Fi network another device hosts for a direct link
//! (PROTOCOL §10.2), through `NetworkManager` on the system bus.
//!
//! The connection is `NetworkManager`'s in-memory kind: `volatile` (never
//! written to disk, destroyed when it goes down) and bound to this process
//! (`bind-activation`: `NetworkManager` takes it down if the process exits).
//! It is visible to this user alone (`permissions`), which polkit allows
//! for the active session without an administrator. Nothing about it is
//! saved or suggested to the system. The host's default route, routes, and
//! DNS servers are ignored: the link carries only the session to the host.
//! The host gets no host name and a random MAC address, and its address
//! must be on the link.
//! WPS and open networks are never used.
//!
//! `NetworkManager` 1.16 or later (in-memory connections and SAE). Hosting
//! is not offered here: `NetworkManager`'s access-point mode with DHCP for
//! clients always shares (NAT, forwarding, and a DNS server), which §10.2
//! forbids a host (docs/adr/0018-desktop-links.md).

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use zbus::blocking::{Connection, Proxy};
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zeroize::Zeroizing;

const NM: &str = "org.freedesktop.NetworkManager";
const NM_PATH: &str = "/org/freedesktop/NetworkManager";
const DEVICE: &str = "org.freedesktop.NetworkManager.Device";
const ACTIVE: &str = "org.freedesktop.NetworkManager.Connection.Active";
const DHCP4: &str = "org.freedesktop.NetworkManager.DHCP4Config";
const IP4: &str = "org.freedesktop.NetworkManager.IP4Config";
const SUPPLICANT: &str = "fi.w1.wpa_supplicant1";
const SUPPLICANT_PATH: &str = "/fi/w1/wpa_supplicant1";
const SUPPLICANT_INTERFACE: &str = "fi.w1.wpa_supplicant1.Interface";
/// `NM_DEVICE_TYPE_WIFI`.
const TYPE_WIFI: u32 = 2;
/// `NM_DEVICE_STATE_UNAVAILABLE`: below it the device is not managed.
const STATE_UNAVAILABLE: u32 = 20;
/// `NM_ACTIVE_CONNECTION_STATE_ACTIVATED` and `_DEACTIVATED`.
const ACTIVATED: u32 = 2;
const DEACTIVATED: u32 = 4;
/// How often activation is checked.
const POLL: Duration = Duration::from_millis(200);

/// The security to join with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Security {
    /// WPA3-Personal, SAE only.
    Wpa3,
    /// WPA2-PSK.
    Wpa2,
}

#[expect(clippy::needless_pass_by_value, reason = "used as map_err(bus)")]
fn bus(error: zbus::Error) -> io::Error {
    io::Error::other(format!("NetworkManager: {error}"))
}

/// The Wi-Fi device this machine can join with, and whether it can join
/// WPA3 (SAE).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WifiDevice {
    path: OwnedObjectPath,
    interface: String,
    /// Whether it can join WPA3-Personal (SAE): `None` when
    /// `wpa_supplicant` would not say (its bus API is often root's only).
    pub sae: Option<bool>,
}

/// The first Wi-Fi device `NetworkManager` manages, if any (no
/// `NetworkManager`, no system bus, or no Wi-Fi: `None`).
#[must_use]
pub fn probe() -> Option<WifiDevice> {
    let connection = Connection::system().ok()?;
    let manager = Proxy::new(&connection, NM, NM_PATH, NM).ok()?;
    let devices: Vec<OwnedObjectPath> = manager.call("GetDevices", &()).ok()?;
    devices.into_iter().find_map(|path| {
        let device = Proxy::new(&connection, NM, path.clone(), DEVICE).ok()?;
        let kind: u32 = device.get_property("DeviceType").ok()?;
        let state: u32 = device.get_property("State").ok()?;
        if kind != TYPE_WIFI || state <= STATE_UNAVAILABLE {
            return None;
        }
        let interface: String = device.get_property("Interface").ok()?;
        let sae = supports_sae(&connection, &interface);
        Some(WifiDevice {
            path,
            interface,
            sae,
        })
    })
}

/// Whether `wpa_supplicant` reports SAE for `interface` (`NetworkManager`'s
/// own capabilities do not say); `None` if it would not answer.
fn supports_sae(connection: &Connection, interface: &str) -> Option<bool> {
    let check = || -> Option<bool> {
        let supplicant = Proxy::new(connection, SUPPLICANT, SUPPLICANT_PATH, SUPPLICANT).ok()?;
        let path: OwnedObjectPath = supplicant.call("GetInterface", &(interface,)).ok()?;
        let iface = Proxy::new(connection, SUPPLICANT, path.as_str(), SUPPLICANT_INTERFACE).ok()?;
        let capabilities: HashMap<String, OwnedValue> = iface.get_property("Capabilities").ok()?;
        let key_mgmt: Vec<String> = capabilities
            .get("KeyMgmt")?
            .try_clone()
            .ok()?
            .try_into()
            .ok()?;
        Some(key_mgmt.iter().any(|value| value == "sae"))
    };
    check()
}

/// A joined network: taken down (and, being volatile, deleted) when
/// dropped.
pub struct Joined {
    connection: Connection,
    active: OwnedObjectPath,
    /// This machine's address on the network.
    pub local: IpAddr,
    /// The host's address (its DHCP router option, or the gateway).
    pub host: IpAddr,
    /// The interface's index.
    pub interface: u32,
}

impl core::fmt::Debug for Joined {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Joined")
            .field("local", &self.local)
            .field("host", &self.host)
            .field("interface", &self.interface)
            .finish_non_exhaustive()
    }
}

impl Drop for Joined {
    fn drop(&mut self) {
        if let Ok(manager) = Proxy::new(&self.connection, NM, NM_PATH, NM) {
            let _: zbus::Result<()> = manager.call("DeactivateConnection", &(&self.active,));
        }
    }
}

/// Joins `ssid` with `passphrase` on `device`, within `within`.
///
/// # Errors
///
/// `NetworkManager`'s refusal, a network that does not come up in time, or
/// one that gives no address.
pub fn join(
    device: &WifiDevice,
    ssid: &str,
    passphrase: &Zeroizing<Vec<u8>>,
    security: Security,
    within: Duration,
    cancel: &AtomicBool,
) -> io::Result<Joined> {
    let deadline = Instant::now() + within;
    let passphrase = core::str::from_utf8(passphrase)
        .map_err(|_| io::Error::from(io::ErrorKind::InvalidInput))?;
    let user = std::env::var("USER")
        .or_else(|_| std::env::var("LOGNAME"))
        .map_err(|_| io::Error::other("no user name for the connection's permissions"))?;
    let connection = Connection::system().map_err(bus)?;
    let manager = Proxy::new(&connection, NM, NM_PATH, NM).map_err(bus)?;
    let id = uuid()?;
    let settings = settings(&device.interface, ssid, passphrase, security, &user, &id);
    let options: HashMap<&str, Value<'_>> = HashMap::from([
        ("persist", Value::from("volatile")),
        ("bind-activation", Value::from("dbus-client")),
    ]);
    let root = OwnedObjectPath::try_from("/").map_err(|error| bus(error.into()))?;
    let (_, active, _): (
        OwnedObjectPath,
        OwnedObjectPath,
        HashMap<String, OwnedValue>,
    ) = manager
        .call(
            "AddAndActivateConnection2",
            &(settings, &device.path, &root, options),
        )
        .map_err(bus)?;
    // From here the connection is ours to take down, whatever happens.
    let mut joined = Joined {
        connection,
        active,
        local: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        host: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        interface: interface_index(&device.interface)?,
    };
    let active = Proxy::new(&joined.connection, NM, joined.active.clone(), ACTIVE).map_err(bus)?;
    loop {
        let state: u32 = active.get_property("State").map_err(bus)?;
        match state {
            ACTIVATED => break,
            DEACTIVATED => return Err(io::Error::other("the network did not come up")),
            _ if Instant::now() >= deadline => return Err(io::ErrorKind::TimedOut.into()),
            _ if cancel.load(Ordering::SeqCst) => return Err(io::ErrorKind::Interrupted.into()),
            _ => std::thread::sleep(POLL),
        }
    }
    let (local, host) = addresses(&joined.connection, &active)?;
    drop(active);
    joined.local = local;
    joined.host = host;
    Ok(joined)
}

/// This machine's IPv4 address on the activated connection and the host's
/// (the DHCP router, else the IPv4 gateway).
fn addresses(connection: &Connection, active: &Proxy<'_>) -> io::Result<(IpAddr, IpAddr)> {
    let ip4: OwnedObjectPath = active.get_property("Ip4Config").map_err(bus)?;
    let config = Proxy::new(connection, NM, ip4.as_str(), IP4).map_err(bus)?;
    let data: Vec<HashMap<String, OwnedValue>> = config.get_property("AddressData").map_err(bus)?;
    let (local, prefix) = data
        .iter()
        .find_map(|entry| {
            let address: String = entry.get("address")?.try_clone().ok()?.try_into().ok()?;
            let prefix: u32 = entry.get("prefix")?.try_clone().ok()?.try_into().ok()?;
            Some((address.parse::<Ipv4Addr>().ok()?, prefix))
        })
        .ok_or_else(|| io::Error::other("the network gave no address"))?;
    let dhcp: Option<Ipv4Addr> = (|| {
        let path: OwnedObjectPath = active.get_property("Dhcp4Config").ok()?;
        let dhcp = Proxy::new(connection, NM, path.as_str(), DHCP4).ok()?;
        let options: HashMap<String, OwnedValue> = dhcp.get_property("Options").ok()?;
        let routers: String = options.get("routers")?.try_clone().ok()?.try_into().ok()?;
        routers.split_whitespace().next()?.parse().ok()
    })();
    let host = dhcp
        .or_else(|| {
            let gateway: String = config.get_property("Gateway").ok()?;
            gateway.parse().ok()
        })
        .ok_or_else(|| io::Error::other("the network named no host"))?;
    // The host is on the link: its address within ours, never one that
    // only a route would reach.
    if host == local || !on_link(local, prefix, host) {
        return Err(io::Error::other("the network's host is not on the link"));
    }
    Ok((IpAddr::V4(local), IpAddr::V4(host)))
}

/// Whether `host` is inside `local`'s network of `prefix` bits.
fn on_link(local: Ipv4Addr, prefix: u32, host: Ipv4Addr) -> bool {
    if !(8..=30).contains(&prefix) {
        return false;
    }
    let mask = u32::MAX << (32 - prefix);
    u32::from(local) & mask == u32::from(host) & mask
}

/// The settings of the connection: an app-scoped, unsaved network that
/// takes no default route, routes, or DNS from the host.
fn settings<'a>(
    interface: &'a str,
    ssid: &'a str,
    passphrase: &'a str,
    security: Security,
    user: &str,
    uuid: &'a str,
) -> HashMap<&'static str, HashMap<&'static str, Value<'a>>> {
    let strings = |values: &[&str]| {
        Value::from(
            values
                .iter()
                .map(|value| (*value).to_owned())
                .collect::<Vec<_>>(),
        )
    };
    let connection = HashMap::from([
        ("id", Value::from("todoke direct link")),
        ("uuid", Value::from(uuid)),
        ("type", Value::from("802-11-wireless")),
        ("interface-name", Value::from(interface)),
        ("autoconnect", Value::from(false)),
        ("permissions", strings(&[&format!("user:{user}")])),
    ]);
    let wireless = HashMap::from([
        ("ssid", Value::from(ssid.as_bytes().to_vec())),
        ("mode", Value::from("infrastructure")),
        // A random address for this network: the host learns nothing that
        // identifies this machine elsewhere.
        ("cloned-mac-address", Value::from("random")),
    ]);
    let mut wireless_security = HashMap::from([
        (
            "key-mgmt",
            Value::from(match security {
                Security::Wpa3 => "sae",
                Security::Wpa2 => "wpa-psk",
            }),
        ),
        ("psk", Value::from(passphrase)),
        ("proto", strings(&["rsn"])),
        ("pairwise", strings(&["ccmp"])),
        ("group", strings(&["ccmp"])),
    ]);
    if security == Security::Wpa3 {
        // Protected management frames: required.
        wireless_security.insert("pmf", Value::from(3_i32));
    }
    let ipv4 = HashMap::from([
        ("method", Value::from("auto")),
        ("never-default", Value::from(true)),
        ("dhcp-send-hostname", Value::from(false)),
        ("ignore-auto-dns", Value::from(true)),
        ("ignore-auto-routes", Value::from(true)),
    ]);
    let ipv6 = HashMap::from([("method", Value::from("link-local"))]);
    HashMap::from([
        ("connection", connection),
        ("802-11-wireless", wireless),
        ("802-11-wireless-security", wireless_security),
        ("ipv4", ipv4),
        ("ipv6", ipv6),
    ])
}

/// A random (version 4) UUID for the connection.
fn uuid() -> io::Result<String> {
    let mut bytes = [0_u8; 16];
    getrandom::fill(&mut bytes).map_err(|_| io::Error::other("no randomness"))?;
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    let hex = |range: core::ops::Range<usize>| {
        bytes[range].iter().fold(String::new(), |mut out, byte| {
            use core::fmt::Write as _;
            let _ = write!(out, "{byte:02x}");
            out
        })
    };
    Ok(format!(
        "{}-{}-{}-{}-{}",
        hex(0..4),
        hex(4..6),
        hex(6..8),
        hex(8..10),
        hex(10..16)
    ))
}

/// The index of the network interface `name`.
fn interface_index(name: &str) -> io::Result<u32> {
    if name.is_empty() || name.contains(['/', '.']) {
        return Err(io::ErrorKind::InvalidInput.into());
    }
    std::fs::read_to_string(format!("/sys/class/net/{name}/ifindex"))?
        .trim()
        .parse()
        .map_err(|_| io::ErrorKind::InvalidData.into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn string(value: &Value<'_>) -> Option<String> {
        value.try_clone().ok()?.try_into().ok()
    }

    /// The connection is unsaved, this user's, takes nothing from the host
    /// but an address, and joins with exactly the security asked.
    #[test]
    fn the_connection_takes_nothing_from_the_host() {
        let wpa3 = settings(
            "wlan0",
            "todoke-0123456789abcdef",
            "pass",
            Security::Wpa3,
            "alice",
            "u",
        );
        let ipv4 = &wpa3["ipv4"];
        for key in ["never-default", "ignore-auto-dns", "ignore-auto-routes"] {
            assert_eq!(ipv4[key], Value::from(true), "{key}");
        }
        assert_eq!(wpa3["connection"]["autoconnect"], Value::from(false));
        assert_eq!(ipv4["dhcp-send-hostname"], Value::from(false));
        assert_eq!(
            string(&wpa3["802-11-wireless"]["cloned-mac-address"]).as_deref(),
            Some("random")
        );
        assert_eq!(
            wpa3["connection"]["permissions"],
            Value::from(vec!["user:alice".to_owned()])
        );
        assert_eq!(
            string(&wpa3["802-11-wireless-security"]["key-mgmt"]).as_deref(),
            Some("sae")
        );
        assert_eq!(wpa3["802-11-wireless-security"]["pmf"], Value::from(3_i32));
        assert_eq!(
            wpa3["802-11-wireless"]["ssid"],
            Value::from(b"todoke-0123456789abcdef".to_vec())
        );
        let wpa2 = settings("wlan0", "s", "pass", Security::Wpa2, "alice", "u");
        assert_eq!(
            string(&wpa2["802-11-wireless-security"]["key-mgmt"]).as_deref(),
            Some("wpa-psk")
        );
        assert!(!wpa2["802-11-wireless-security"].contains_key("pmf"));
    }

    /// Only a host inside this machine's own network is taken.
    #[test]
    fn the_host_is_on_the_link() {
        let local = Ipv4Addr::new(192, 168, 49, 23);
        assert!(on_link(local, 24, Ipv4Addr::new(192, 168, 49, 1)));
        assert!(!on_link(local, 24, Ipv4Addr::new(192, 168, 50, 1)));
        assert!(!on_link(local, 24, Ipv4Addr::new(10, 0, 0, 1)));
        // Absurd prefixes name no link.
        assert!(!on_link(local, 0, Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!on_link(local, 32, local));
    }

    #[test]
    fn uuids_are_version_4() -> io::Result<()> {
        let id = uuid()?;
        assert_eq!(id.len(), 36);
        assert_eq!(id.as_bytes()[14], b'4');
        assert!(matches!(id.as_bytes()[19], b'8' | b'9' | b'a' | b'b'));
        assert_ne!(uuid()?, id);
        Ok(())
    }

    #[test]
    fn interface_names_cannot_leave_sysfs() {
        for name in ["", "../etc", "wlan0/..", "a.b"] {
            assert!(interface_index(name).is_err(), "{name}");
        }
    }
}
