//! Hosting a Wi-Fi Direct group for a direct link (PROTOCOL §10.2 kind 2):
//! the Wi-Fi Direct legacy access point, with exactly the offer's network
//! name and passphrase (WPA2-PSK, the only security §10.2 gives Wi-Fi
//! Direct groups), through the `WinRT` advertisement publisher.
//!
//! Windows' own DHCP on the group may name this machine as router and DNS
//! server (§10.2 allows what a platform offers regardless): nothing here
//! enables routing or Internet Connection Sharing, so nothing is forwarded
//! or answered for them, and the group is not discoverable as a Wi-Fi
//! Direct device (only the legacy network beacons). The publisher stops,
//! and the network goes, when the [`Hosted`] is dropped.

use std::io;
use std::net::IpAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use windows::Devices::WiFiDirect::{
    WiFiDirectAdvertisementListenStateDiscoverability, WiFiDirectAdvertisementPublisher,
    WiFiDirectAdvertisementPublisherStatus,
};
use windows::Security::Credentials::PasswordCredential;
use windows::core::HSTRING;
use zeroize::Zeroizing;

/// How often the publisher and its address are checked.
const POLL: Duration = Duration::from_millis(200);

/// A hosted group, stopped when dropped.
pub struct Hosted {
    publisher: WiFiDirectAdvertisementPublisher,
    /// This machine's address on the group.
    pub local: IpAddr,
    /// The group's interface index.
    pub interface: u32,
}

impl core::fmt::Debug for Hosted {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Hosted")
            .field("local", &self.local)
            .field("interface", &self.interface)
            .finish_non_exhaustive()
    }
}

// The core keeps the group in its lease, which moves between threads.
const _: fn() = || {
    fn send<T: Send>() {}
    send::<Hosted>();
};

impl Drop for Hosted {
    fn drop(&mut self) {
        let _ = self.publisher.Stop();
    }
}

/// Whether this machine can publish a Wi-Fi Direct legacy access point.
#[must_use]
pub fn available() -> bool {
    WiFiDirectAdvertisementPublisher::new().is_ok()
}

/// Hosts `ssid` with `passphrase`, up and addressed within `within`.
///
/// # Errors
///
/// An SSID or passphrase of the wrong shape (`InvalidInput`); the
/// publisher's error or abort; `Interrupted` once `cancel` is set; a group
/// that does not come up or get an address in time.
pub fn host(
    ssid: &str,
    passphrase: &Zeroizing<Vec<u8>>,
    within: Duration,
    cancel: &AtomicBool,
) -> io::Result<Hosted> {
    let invalid = || io::Error::from(io::ErrorKind::InvalidInput);
    if !ssid.starts_with("DIRECT-") || ssid.len() > 32 {
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
    let deadline = Instant::now() + within;
    let publisher = WiFiDirectAdvertisementPublisher::new().map_err(winrt)?;
    let advertisement = publisher.Advertisement().map_err(winrt)?;
    advertisement
        .SetListenStateDiscoverability(WiFiDirectAdvertisementListenStateDiscoverability::None)
        .map_err(winrt)?;
    let legacy = advertisement.LegacySettings().map_err(winrt)?;
    legacy.SetIsEnabled(true).map_err(winrt)?;
    legacy.SetSsid(&HSTRING::from(ssid)).map_err(winrt)?;
    let credential = PasswordCredential::new().map_err(winrt)?;
    credential
        .SetPassword(&HSTRING::from(passphrase))
        .map_err(winrt)?;
    legacy.SetPassphrase(&credential).map_err(winrt)?;
    // The groups addressed before this one are never taken for it.
    let before = crate::wifi::direct_adapters();
    publisher.Start().map_err(winrt)?;
    let mut hosted = Hosted {
        publisher,
        local: IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
        interface: 0,
    };
    loop {
        std::thread::sleep(POLL);
        if cancel.load(Ordering::SeqCst) {
            return Err(io::ErrorKind::Interrupted.into());
        }
        let status = hosted.publisher.Status().map_err(winrt)?;
        if status == WiFiDirectAdvertisementPublisherStatus::Aborted {
            return Err(io::Error::other("the Wi-Fi Direct group was aborted"));
        }
        if status == WiFiDirectAdvertisementPublisherStatus::Started
            && let Some((local, index)) = crate::wifi::direct_adapters()
                .into_iter()
                .find(|adapter| !before.contains(adapter))
        {
            hosted.local = IpAddr::V4(local);
            hosted.interface = index;
            return Ok(hosted);
        }
        if Instant::now() >= deadline {
            return Err(io::ErrorKind::TimedOut.into());
        }
    }
}

#[expect(
    clippy::needless_pass_by_value,
    reason = "taken by value to serve as `map_err(winrt)`"
)]
fn winrt(error: windows::core::Error) -> io::Error {
    io::Error::other(error.message())
}
