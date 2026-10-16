//! This machine's part in direct Wi-Fi links (PROTOCOL §10.2), for the
//! core: joining a Wi-Fi Direct group or a hotspot another device hosts,
//! through `NetworkManager` on Linux and Native Wifi on Windows, with the
//! security the device supports (WPA3 where it has SAE), and on Windows
//! hosting Wi-Fi Direct groups (the legacy access point, which forwards
//! nothing). Linux hosts nothing (`NetworkManager`'s shared mode is NAT and
//! DNS); no desktop joins a Wi-Fi Aware data path; macOS takes no part (its
//! public join API saves the network). docs/adr/0018-desktop-links.md and
//! docs/adr/0019-android-radios.md say why.

use std::sync::Arc;

use todoke_core::link::LinkPlatform;

/// This machine's link platform, if it can join anything.
#[must_use]
pub fn platform() -> Option<Arc<dyn LinkPlatform>> {
    imp::platform()
}

#[cfg(any(target_os = "linux", windows))]
mod imp {
    use std::io;
    use std::sync::Arc;

    use todoke_core::link::{
        HostRequest, JoinRequest, LinkAbilities, LinkKind, LinkLease, LinkPlatform, LinkSecurity,
    };

    #[cfg(target_os = "linux")]
    use todoke_sys_linux::wifi;
    #[cfg(windows)]
    use todoke_sys_windows::wifi;

    /// How long a group may take to come up and get its address.
    #[cfg(windows)]
    const HOST_WITHIN: std::time::Duration = std::time::Duration::from_secs(30);

    struct Joiner {
        device: wifi::WifiDevice,
        /// Hosts Wi-Fi Direct groups (Windows).
        hosts: bool,
    }

    pub(super) fn platform() -> Option<Arc<dyn LinkPlatform>> {
        let device = wifi::probe()?;
        #[cfg(windows)]
        let hosts = todoke_sys_windows::wifi_host::available();
        #[cfg(not(windows))]
        let hosts = false;
        Some(Arc::new(Joiner { device, hosts }))
    }

    impl Joiner {
        /// The securities to try for `offered`, in order: SAE where the
        /// device has it or may (a transition network then also takes
        /// WPA2), WPA2 otherwise.
        fn securities(&self, offered: LinkSecurity) -> io::Result<Vec<wifi::Security>> {
            use wifi::Security::{Wpa2, Wpa3};
            Ok(match (offered, self.device.sae) {
                (LinkSecurity::Wpa3, Some(true) | None)
                | (LinkSecurity::Wpa3Transition, Some(true)) => vec![Wpa3],
                (LinkSecurity::Wpa3Transition, None) => vec![Wpa3, Wpa2],
                (LinkSecurity::Wpa3Transition, Some(false)) | (LinkSecurity::Wpa2, _) => {
                    vec![Wpa2]
                }
                _ => return Err(io::ErrorKind::Unsupported.into()),
            })
        }
    }

    impl LinkPlatform for Joiner {
        fn abilities(&self) -> LinkAbilities {
            let mut security = vec![LinkSecurity::Wpa3Transition, LinkSecurity::Wpa2];
            // Unknown (the system would not say): most devices have SAE;
            // a failed WPA3 join is answered and backed off.
            if self.device.sae != Some(false) {
                security.insert(0, LinkSecurity::Wpa3);
            }
            let host: &[LinkKind] = if self.hosts {
                &[LinkKind::WifiDirect]
            } else {
                &[]
            };
            LinkAbilities::new(host, &[LinkKind::WifiDirect, LinkKind::Hotspot], &security)
        }

        #[cfg(windows)]
        fn host(&self, request: &HostRequest) -> io::Result<LinkLease> {
            if !self.hosts
                || request.kind != LinkKind::WifiDirect
                || request.security != LinkSecurity::Wpa2
            {
                return Err(io::ErrorKind::Unsupported.into());
            }
            let hosted = todoke_sys_windows::wifi_host::host(
                &request.ssid,
                &request.secret,
                HOST_WITHIN,
                &request.cancel,
            )?;
            Ok(LinkLease::new(hosted.local, None, hosted.interface, hosted))
        }

        #[cfg(not(windows))]
        fn host(&self, _: &HostRequest) -> io::Result<LinkLease> {
            Err(io::ErrorKind::Unsupported.into())
        }

        fn join(&self, request: &JoinRequest) -> io::Result<LinkLease> {
            if request.kind == LinkKind::WifiAware {
                return Err(io::ErrorKind::Unsupported.into());
            }
            let started = std::time::Instant::now();
            let mut last = io::Error::from(io::ErrorKind::Unsupported);
            for security in self.securities(request.security)? {
                let left = request.within.saturating_sub(started.elapsed());
                match wifi::join(
                    &self.device,
                    &request.ssid,
                    &request.secret,
                    security,
                    left,
                    &request.cancel,
                ) {
                    Ok(joined) => {
                        return Ok(LinkLease::new(
                            joined.local,
                            Some(joined.host),
                            joined.interface,
                            joined,
                        ));
                    }
                    Err(error) => last = error,
                }
            }
            Err(last)
        }
    }
}

#[cfg(not(any(target_os = "linux", windows)))]
mod imp {
    use std::sync::Arc;

    use todoke_core::link::LinkPlatform;

    pub(super) const fn platform() -> Option<Arc<dyn LinkPlatform>> {
        None
    }
}
