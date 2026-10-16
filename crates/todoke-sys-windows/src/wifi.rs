//! Joining a Wi-Fi network another device hosts for a direct link
//! (PROTOCOL §10.2), with the Native Wifi API.
//!
//! The network is joined with a temporary profile: the profile goes to
//! `WlanConnect` only and is never saved (nothing calls
//! `WlanSaveTemporaryProfile`), so Windows keeps no network, password, or
//! suggestion once the link is down. WPA3-Personal (SAE, transition mode
//! off) or WPA2-PSK, AES; never open, WEP, or WPS. The SSID goes in its
//! hexadecimal form, so no text reaches the profile's XML unescaped; the
//! passphrase is checked to be the §10.2 alphabet first.
//!
//! Hosting is in [`crate::wifi_host`] (the Wi-Fi Direct legacy access
//! point), never Mobile Hotspot: that is Internet Connection Sharing (NAT
//! and a DNS proxy, which §10.2 forbids a host).
//!
//! The only unsafe code is the Win32 calls below; each block says why it
//! is sound. Buffers the system allocates are freed with `WlanFreeMemory`.

#![allow(
    unsafe_code,
    reason = "Native Wifi and IP Helper calls; each block is justified"
)]

use core::ffi::c_void;
use std::ffi::CStr;
use std::io;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use windows_sys::Win32::Foundation::{ERROR_ACCESS_DENIED, HANDLE, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    GAA_FLAG_INCLUDE_GATEWAYS, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
    GAA_FLAG_SKIP_MULTICAST, GetAdaptersAddresses, IP_ADAPTER_ADDRESSES_LH,
};
use windows_sys::Win32::NetworkManagement::WiFi::{
    DOT11_AUTH_ALGO_WPA3_SAE, DOT11_AUTH_CIPHER_PAIR, WLAN_AUTH_CIPHER_PAIR_LIST,
    WLAN_CONNECTION_ATTRIBUTES, WLAN_CONNECTION_PARAMETERS, WLAN_INTERFACE_INFO,
    WLAN_INTERFACE_INFO_LIST, WlanCloseHandle, WlanConnect, WlanDisconnect, WlanEnumInterfaces,
    WlanFreeMemory, WlanOpenHandle, WlanQueryInterface, dot11_BSS_type_infrastructure,
    wlan_connection_mode_temporary_profile, wlan_interface_state_connected,
    wlan_interface_state_not_ready, wlan_intf_opcode_current_connection,
    wlan_intf_opcode_interface_state, wlan_intf_opcode_supported_infrastructure_auth_cipher_pairs,
};
use windows_sys::Win32::Networking::WinSock::AF_INET;
use windows_sys::core::GUID;
use zeroize::Zeroizing;

/// The Native Wifi client version (Windows Vista and later).
const CLIENT_VERSION: u32 = 2;
/// `ERROR_BUFFER_OVERFLOW`.
const BUFFER_OVERFLOW: u32 = 111;
/// How often the connection and its address are checked.
const POLL: Duration = Duration::from_millis(200);

/// The security to join with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Security {
    /// WPA3-Personal, SAE only.
    Wpa3,
    /// WPA2-PSK.
    Wpa2,
}

fn win32(code: u32) -> io::Error {
    io::Error::from_raw_os_error(i32::try_from(code).unwrap_or(i32::MAX))
}

/// A Native Wifi client handle, closed when dropped.
struct Client(HANDLE);

impl Client {
    fn open() -> io::Result<Self> {
        let mut negotiated = 0_u32;
        let mut handle: HANDLE = core::ptr::null_mut();
        // SAFETY: both out-pointers are valid for the call; the reserved
        // argument is null as required.
        let status = unsafe {
            WlanOpenHandle(
                CLIENT_VERSION,
                core::ptr::null(),
                &raw mut negotiated,
                &raw mut handle,
            )
        };
        if status == NO_ERROR {
            Ok(Self(handle))
        } else {
            Err(win32(status))
        }
    }
}

// SAFETY: a Native Wifi client handle is a value the API accepts from any
// thread (the API is thread-safe); it is closed once, on drop.
unsafe impl Send for Client {}

impl Drop for Client {
    fn drop(&mut self) {
        // SAFETY: the handle came from `WlanOpenHandle` and is closed once.
        unsafe { WlanCloseHandle(self.0, core::ptr::null()) };
    }
}

/// Memory Native Wifi allocated, freed when dropped.
struct WlanMemory(*mut c_void);

impl Drop for WlanMemory {
    fn drop(&mut self) {
        if !self.0.is_null() {
            // SAFETY: the pointer came from a Native Wifi call and is freed
            // once.
            unsafe { WlanFreeMemory(self.0) };
        }
    }
}

/// The Wi-Fi interface this machine can join with, and whether it can
/// join WPA3 (SAE).
#[derive(Clone, Copy)]
pub struct WifiDevice {
    guid: GUID,
    /// Whether it can join WPA3-Personal (SAE): `None` when the driver
    /// would not say.
    pub sae: Option<bool>,
}

impl core::fmt::Debug for WifiDevice {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WifiDevice")
            .field("sae", &self.sae)
            .finish_non_exhaustive()
    }
}

/// The first Wi-Fi interface, if any.
#[must_use]
pub fn probe() -> Option<WifiDevice> {
    let client = Client::open().ok()?;
    let mut list: *mut WLAN_INTERFACE_INFO_LIST = core::ptr::null_mut();
    // SAFETY: the handle is open; `list` receives memory freed below.
    let status = unsafe { WlanEnumInterfaces(client.0, core::ptr::null(), &raw mut list) };
    let _memory = WlanMemory(list.cast());
    if status != NO_ERROR || list.is_null() {
        return None;
    }
    // SAFETY: on success `list` points at a list whose `InterfaceInfo`
    // holds `dwNumberOfItems` entries (a flexible array).
    let interfaces: &[WLAN_INTERFACE_INFO] = unsafe {
        let count = (*list).dwNumberOfItems as usize;
        core::slice::from_raw_parts((&raw const (*list).InterfaceInfo).cast(), count)
    };
    let guid = interfaces
        .iter()
        .find(|interface| interface.isState != wlan_interface_state_not_ready)?
        .InterfaceGuid;
    Some(WifiDevice {
        guid,
        sae: supports_sae(&client, &guid),
    })
}

/// Whether the driver lists SAE among its infrastructure auth/cipher
/// pairs; `None` if it would not say.
fn supports_sae(client: &Client, guid: &GUID) -> Option<bool> {
    let mut size = 0_u32;
    let mut data: *mut c_void = core::ptr::null_mut();
    // SAFETY: the handle is open and `guid` is valid; the out-pointers are
    // valid; `data` is freed below.
    let status = unsafe {
        WlanQueryInterface(
            client.0,
            guid,
            wlan_intf_opcode_supported_infrastructure_auth_cipher_pairs,
            core::ptr::null(),
            &raw mut size,
            &raw mut data,
            core::ptr::null_mut(),
        )
    };
    let _memory = WlanMemory(data);
    if status != NO_ERROR || data.is_null() || (size as usize) < size_of::<u32>() {
        return None;
    }
    let list = data.cast::<WLAN_AUTH_CIPHER_PAIR_LIST>();
    // SAFETY: on success `data` is a pair list of `size` bytes (checked to
    // hold at least the count) whose array holds `dwNumberOfItems` pairs;
    // the count read is bounded by the size.
    let pairs: &[DOT11_AUTH_CIPHER_PAIR] = unsafe {
        let fits = (size as usize).saturating_sub(4) / size_of::<DOT11_AUTH_CIPHER_PAIR>();
        let count = ((*list).dwNumberOfItems as usize).min(fits);
        core::slice::from_raw_parts((&raw const (*list).pAuthCipherPairList).cast(), count)
    };
    Some(
        pairs
            .iter()
            .any(|pair| pair.AuthAlgoId == DOT11_AUTH_ALGO_WPA3_SAE),
    )
}

/// A joined network, disconnected when dropped (its temporary profile
/// goes with it).
pub struct Joined {
    client: Client,
    guid: GUID,
    /// This machine's address on the network.
    pub local: IpAddr,
    /// The host's address (the network's gateway).
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
        // SAFETY: the handle is open and the GUID is the interface's.
        unsafe { WlanDisconnect(self.client.0, &raw const self.guid, core::ptr::null()) };
    }
}

/// Joins `ssid` with `passphrase` on `device`, within `within`.
///
/// The joined network is checked to be this one: the interface's current
/// connection is this temporary profile with this SSID, or, where Windows
/// will not say (no location consent), its address and gateway are no
/// longer the network it was on, and the gateway is on the link.
///
/// # Errors
///
/// An SSID or passphrase of the wrong shape (`InvalidInput`); the Native
/// Wifi error; `Interrupted` once `cancel` is set; a network that does not
/// come up or give an address in time.
pub fn join(
    device: &WifiDevice,
    ssid: &str,
    passphrase: &Zeroizing<Vec<u8>>,
    security: Security,
    within: Duration,
    cancel: &AtomicBool,
) -> io::Result<Joined> {
    let deadline = Instant::now() + within;
    let profile = profile(ssid, passphrase, security)?;
    // Sized once: no reallocation leaves a copy of the passphrase behind.
    let mut wide = Zeroizing::new(Vec::with_capacity(profile.len() + 1));
    wide.extend(profile.encode_utf16());
    wide.push(0);
    let client = Client::open()?;
    // The network the interface is on now, if any: never taken for the
    // new one.
    let before = adapter(&device.guid);
    let parameters = WLAN_CONNECTION_PARAMETERS {
        wlanConnectionMode: wlan_connection_mode_temporary_profile,
        strProfile: wide.as_ptr(),
        pDot11Ssid: core::ptr::null_mut(),
        pDesiredBssidList: core::ptr::null_mut(),
        dot11BssType: dot11_BSS_type_infrastructure,
        dwFlags: 0,
    };
    // SAFETY: the handle is open; the GUID is the interface's; the
    // parameters and the NUL-terminated profile outlive the call.
    let status = unsafe {
        WlanConnect(
            client.0,
            &raw const device.guid,
            &raw const parameters,
            core::ptr::null(),
        )
    };
    if status != NO_ERROR {
        return Err(win32(status));
    }
    let mut joined = Joined {
        client,
        guid: device.guid,
        local: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        host: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        interface: 0,
    };
    // Associated with this network, then addressed (DHCP takes a moment).
    loop {
        std::thread::sleep(POLL);
        if cancel.load(Ordering::SeqCst) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let ours = current_is(&joined.client, &joined.guid, ssid.as_bytes());
        if ours != Some(false)
            && connected(&joined.client, &joined.guid)
            && let Some(found) = adapter(&joined.guid)
            && (ours == Some(true) || Some(found) != before)
        {
            let (local, host, index) = found;
            joined.local = IpAddr::V4(local);
            joined.host = IpAddr::V4(host);
            joined.interface = index;
            return Ok(joined);
        }
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
    }
}

/// Whether the interface's current connection is this temporary profile
/// on `ssid`; `None` when Windows will not say (without location consent).
fn current_is(client: &Client, guid: &GUID, ssid: &[u8]) -> Option<bool> {
    let mut size = 0_u32;
    let mut data: *mut c_void = core::ptr::null_mut();
    // SAFETY: as in `supports_sae`.
    let status = unsafe {
        WlanQueryInterface(
            client.0,
            guid,
            wlan_intf_opcode_current_connection,
            core::ptr::null(),
            &raw mut size,
            &raw mut data,
            core::ptr::null_mut(),
        )
    };
    let _memory = WlanMemory(data);
    if status == ERROR_ACCESS_DENIED {
        return None;
    }
    if status != NO_ERROR
        || data.is_null()
        || (size as usize) < size_of::<WLAN_CONNECTION_ATTRIBUTES>()
    {
        return Some(false);
    }
    // SAFETY: on success `data` holds connection attributes, checked to fit
    // `size`; read unaligned to be safe.
    let attributes = unsafe { data.cast::<WLAN_CONNECTION_ATTRIBUTES>().read_unaligned() };
    let current = &attributes.wlanAssociationAttributes.dot11Ssid;
    let length = (current.uSSIDLength as usize).min(current.ucSSID.len());
    Some(
        attributes.isState == wlan_interface_state_connected
            && attributes.wlanConnectionMode == wlan_connection_mode_temporary_profile
            && &current.ucSSID[..length] == ssid,
    )
}

/// Whether the interface is connected.
fn connected(client: &Client, guid: &GUID) -> bool {
    let mut size = 0_u32;
    let mut data: *mut c_void = core::ptr::null_mut();
    // SAFETY: as in `supports_sae`.
    let status = unsafe {
        WlanQueryInterface(
            client.0,
            guid,
            wlan_intf_opcode_interface_state,
            core::ptr::null(),
            &raw mut size,
            &raw mut data,
            core::ptr::null_mut(),
        )
    };
    let _memory = WlanMemory(data);
    if status != NO_ERROR || data.is_null() || (size as usize) < size_of::<i32>() {
        return false;
    }
    // SAFETY: the interface state is one i32, checked to fit `size`.
    let state = unsafe { data.cast::<i32>().read_unaligned() };
    state == wlan_interface_state_connected
}

/// The interface's IPv4 address (not link-local), its gateway, and its
/// index, once DHCP gave them.
fn adapter(guid: &GUID) -> Option<(Ipv4Addr, Ipv4Addr, u32)> {
    let name = guid_text(guid);
    let flags = GAA_FLAG_INCLUDE_GATEWAYS
        | GAA_FLAG_SKIP_ANYCAST
        | GAA_FLAG_SKIP_MULTICAST
        | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size = 16 * 1024_u32;
    let mut buffer: Vec<u64>;
    loop {
        buffer = vec![0; (size as usize).div_ceil(8)];
        // SAFETY: the buffer holds `size` bytes, 8-byte aligned (u64), as
        // the call requires; `size` is updated on overflow.
        let status = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_INET),
                flags,
                core::ptr::null(),
                buffer.as_mut_ptr().cast(),
                &raw mut size,
            )
        };
        match status {
            NO_ERROR => break,
            BUFFER_OVERFLOW if size <= 1 << 20 => {}
            _ => return None,
        }
    }
    let mut next = buffer.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    while !next.is_null() {
        // SAFETY: `next` points into `buffer` (the list the call wrote),
        // alive here; each node's pointers are into the same buffer.
        let adapter = unsafe { &*next };
        next = adapter.Next;
        if adapter.AdapterName.is_null() {
            continue;
        }
        // SAFETY: `AdapterName` is a NUL-terminated string in the buffer.
        let adapter_name = unsafe { CStr::from_ptr(adapter.AdapterName.cast()) };
        if !adapter_name
            .to_str()
            .is_ok_and(|text| text.eq_ignore_ascii_case(&name))
        {
            continue;
        }
        let mut local = None;
        let mut unicast = adapter.FirstUnicastAddress;
        while !unicast.is_null() {
            // SAFETY: a node of the list in `buffer`.
            let node = unsafe { &*unicast };
            unicast = node.Next;
            if let Some(ip) = ipv4(node.Address.lpSockaddr.cast(), node.Address.iSockaddrLength)
                && !ip.is_link_local()
            {
                local = Some((ip, node.OnLinkPrefixLength));
                break;
            }
        }
        let mut host = None;
        let mut gateway = adapter.FirstGatewayAddress;
        while !gateway.is_null() {
            // SAFETY: a node of the list in `buffer`.
            let node = unsafe { &*gateway };
            gateway = node.Next;
            if let Some(ip) = ipv4(node.Address.lpSockaddr.cast(), node.Address.iSockaddrLength) {
                host = Some(ip);
                break;
            }
        }
        // SAFETY: the union's first member is the length and the IPv4
        // interface index, written by the call for every adapter.
        let index = unsafe { adapter.Anonymous1.Anonymous.IfIndex };
        let ((local, prefix), host) = (local?, host?);
        // The host is on the link: inside this machine's network.
        return (host != local && on_link(local, prefix, host)).then_some((local, host, index));
    }
    None
}

#[cfg(feature = "host")]
/// `IF_TYPE_IEEE80211`.
const IEEE80211: u32 = 71;
#[cfg(feature = "host")]
/// `IfOperStatusUp`.
const UP: i32 = 1;

#[cfg(feature = "host")]
/// The Wi-Fi Direct virtual adapters that are up with an IPv4 address
/// (not link-local): each address and the adapter's index.
pub(crate) fn direct_adapters() -> Vec<(Ipv4Addr, u32)> {
    let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
    let mut size = 16 * 1024_u32;
    let mut buffer: Vec<u64>;
    loop {
        buffer = vec![0; (size as usize).div_ceil(8)];
        // SAFETY: as in `adapter`.
        let status = unsafe {
            GetAdaptersAddresses(
                u32::from(AF_INET),
                flags,
                core::ptr::null(),
                buffer.as_mut_ptr().cast(),
                &raw mut size,
            )
        };
        match status {
            NO_ERROR => break,
            BUFFER_OVERFLOW if size <= 1 << 20 => {}
            _ => return Vec::new(),
        }
    }
    let mut found = Vec::new();
    let mut next = buffer.as_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
    while !next.is_null() {
        // SAFETY: as in `adapter`.
        let adapter = unsafe { &*next };
        next = adapter.Next;
        if adapter.IfType != IEEE80211
            || adapter.OperStatus != UP
            || !wide_contains(adapter.Description, "Wi-Fi Direct")
        {
            continue;
        }
        let mut unicast = adapter.FirstUnicastAddress;
        while !unicast.is_null() {
            // SAFETY: a node of the list in `buffer`.
            let node = unsafe { &*unicast };
            unicast = node.Next;
            if let Some(ip) = ipv4(node.Address.lpSockaddr.cast(), node.Address.iSockaddrLength)
                && !ip.is_link_local()
            {
                // SAFETY: as in `adapter`.
                let index = unsafe { adapter.Anonymous1.Anonymous.IfIndex };
                found.push((ip, index));
                break;
            }
        }
    }
    found
}

#[cfg(feature = "host")]
/// Whether the NUL-terminated wide string `text` (at most 256 units read)
/// contains `needle`.
fn wide_contains(text: *const u16, needle: &str) -> bool {
    if text.is_null() {
        return false;
    }
    let mut units = Vec::new();
    for at in 0..256 {
        // SAFETY: `text` is NUL-terminated (the system wrote it); reading
        // stops at the NUL or the bound.
        let unit = unsafe { *text.add(at) };
        if unit == 0 {
            break;
        }
        units.push(unit);
    }
    String::from_utf16_lossy(&units).contains(needle)
}

/// Whether `host` is inside `local`'s network of `prefix` bits.
fn on_link(local: Ipv4Addr, prefix: u8, host: Ipv4Addr) -> bool {
    if !(8..=30).contains(&prefix) {
        return false;
    }
    let mask = u32::MAX << (32 - u32::from(prefix));
    u32::from(local) & mask == u32::from(host) & mask
}

/// An IPv4 address from a `SOCKADDR_IN` of `length` bytes.
fn ipv4(address: *const u8, length: i32) -> Option<Ipv4Addr> {
    if address.is_null() || length < 8 {
        return None;
    }
    // SAFETY: a sockaddr of `length` bytes (at least 8): the family (u16),
    // the port (u16), then for AF_INET the address.
    let bytes = unsafe { core::slice::from_raw_parts(address, 8) };
    let family = u16::from_le_bytes([bytes[0], bytes[1]]);
    (family == AF_INET).then(|| Ipv4Addr::new(bytes[4], bytes[5], bytes[6], bytes[7]))
}

/// A GUID as an adapter name: `{XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX}`.
fn guid_text(guid: &GUID) -> String {
    let d = guid.data4;
    format!(
        "{{{:08X}-{:04X}-{:04X}-{:02X}{:02X}-{:02X}{:02X}{:02X}{:02X}{:02X}{:02X}}}",
        guid.data1, guid.data2, guid.data3, d[0], d[1], d[2], d[3], d[4], d[5], d[6], d[7]
    )
}

/// The temporary profile: the SSID in hexadecimal, the passphrase checked
/// to hold only the §10.2 alphabet (nothing to escape), AES, no 802.1X.
fn profile(ssid: &str, passphrase: &[u8], security: Security) -> io::Result<Zeroizing<String>> {
    let invalid = || io::Error::from(io::ErrorKind::InvalidInput);
    if ssid.is_empty() || ssid.len() > 32 {
        return Err(invalid());
    }
    if !(8..=63).contains(&passphrase.len())
        || !passphrase
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
    {
        return Err(invalid());
    }
    let passphrase = core::str::from_utf8(passphrase).map_err(|_| invalid())?;
    let hex = ssid.bytes().fold(String::new(), |mut out, byte| {
        use core::fmt::Write as _;
        let _ = write!(out, "{byte:02X}");
        out
    });
    let authentication = match security {
        Security::Wpa3 => {
            "<authentication>WPA3SAE</authentication><encryption>AES</encryption>\
             <useOneX>false</useOneX>\
             <transitionMode xmlns=\"http://www.microsoft.com/networking/WLAN/profile/v4\">false</transitionMode>"
        }
        Security::Wpa2 => {
            "<authentication>WPA2PSK</authentication><encryption>AES</encryption>\
             <useOneX>false</useOneX>"
        }
    };
    Ok(Zeroizing::new(format!(
        "<?xml version=\"1.0\"?>\
         <WLANProfile xmlns=\"http://www.microsoft.com/networking/WLAN/profile/v1\">\
         <name>todoke direct link</name>\
         <SSIDConfig><SSID><hex>{hex}</hex></SSID></SSIDConfig>\
         <connectionType>ESS</connectionType>\
         <connectionMode>manual</connectionMode>\
         <MSM><security><authEncryption>{authentication}</authEncryption>\
         <sharedKey><keyType>passPhrase</keyType><protected>false</protected>\
         <keyMaterial>{passphrase}</keyMaterial></sharedKey></security></MSM>\
         </WLANProfile>"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The profile is manual, AES, no 802.1X, the SSID in hexadecimal, and
    /// the security asked; a passphrase outside the §10.2 alphabet (which
    /// could break out of the XML) or of the wrong length is refused.
    #[test]
    fn profiles_are_exact_and_inert() -> io::Result<()> {
        let wpa3 = profile("todoke-01", b"Abc-_123", Security::Wpa3)?;
        assert!(wpa3.contains("<hex>746F646F6B652D3031</hex>"));
        assert!(wpa3.contains("<authentication>WPA3SAE</authentication>"));
        assert!(wpa3.contains(">false</transitionMode>"));
        assert!(wpa3.contains("<connectionMode>manual</connectionMode>"));
        assert!(wpa3.contains("<useOneX>false</useOneX>"));
        assert!(wpa3.contains("<keyMaterial>Abc-_123</keyMaterial>"));
        let wpa2 = profile("x", b"abcdefgh", Security::Wpa2)?;
        assert!(wpa2.contains("<authentication>WPA2PSK</authentication>"));
        assert!(!wpa2.contains("transitionMode"));
        for bad in [
            &b"short"[..],
            b"</keyMaterial><x>",
            b"abcdefg h",
            &[b'a'; 64],
        ] {
            assert!(profile("x", bad, Security::Wpa2).is_err());
        }
        assert!(profile("", b"abcdefgh", Security::Wpa2).is_err());
        assert!(profile(&"s".repeat(33), b"abcdefgh", Security::Wpa2).is_err());
        Ok(())
    }

    #[test]
    fn the_host_is_on_the_link() {
        let local = Ipv4Addr::new(192, 168, 49, 23);
        assert!(on_link(local, 24, Ipv4Addr::new(192, 168, 49, 1)));
        assert!(!on_link(local, 24, Ipv4Addr::new(192, 168, 50, 1)));
        assert!(!on_link(local, 0, Ipv4Addr::new(10, 0, 0, 1)));
        assert!(!on_link(local, 32, local));
    }

    #[test]
    fn guids_are_written_as_adapter_names() {
        let guid = GUID {
            data1: 0x0123_4567,
            data2: 0x89ab,
            data3: 0xcdef,
            data4: [1, 2, 3, 4, 5, 6, 7, 8],
        };
        assert_eq!(guid_text(&guid), "{01234567-89AB-CDEF-0102-030405060708}");
    }
}
