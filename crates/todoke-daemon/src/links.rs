//! This machine's part in direct Wi-Fi links (PROTOCOL §10.2), for the
//! core: joining a Wi-Fi Direct group or a hotspot another device hosts,
//! through `NetworkManager` on Linux and Native Wifi on Windows, with the
//! security the device supports (WPA3 where it has SAE). Desktops host
//! nothing and join no Wi-Fi Aware data path; macOS takes no part (its
//! public join API saves the network). docs/adr/0018-desktop-links.md
//! says why.

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

    struct Joiner {
        device: wifi::WifiDevice,
    }

    pub(super) fn platform() -> Option<Arc<dyn LinkPlatform>> {
        let device = wifi::probe()?;
        Some(Arc::new(Joiner { device }))
    }

    impl Joiner {
        /// The security to join `offered` with: SAE where the device has
        /// it (a transition network takes either), WPA2 otherwise.
        fn security(&self, offered: LinkSecurity) -> io::Result<wifi::Security> {
            match offered {
                LinkSecurity::Wpa3 | LinkSecurity::Wpa3Transition if self.device.sae => {
                    Ok(wifi::Security::Wpa3)
                }
                LinkSecurity::Wpa3Transition | LinkSecurity::Wpa2 => Ok(wifi::Security::Wpa2),
                _ => Err(io::ErrorKind::Unsupported.into()),
            }
        }
    }

    impl LinkPlatform for Joiner {
        fn abilities(&self) -> LinkAbilities {
            let mut security = vec![LinkSecurity::Wpa3Transition, LinkSecurity::Wpa2];
            if self.device.sae {
                security.insert(0, LinkSecurity::Wpa3);
            }
            LinkAbilities::new(&[], &[LinkKind::WifiDirect, LinkKind::Hotspot], &security)
        }

        fn host(&self, _: &HostRequest) -> io::Result<LinkLease> {
            Err(io::ErrorKind::Unsupported.into())
        }

        fn join(&self, request: &JoinRequest) -> io::Result<LinkLease> {
            if request.kind == LinkKind::WifiAware {
                return Err(io::ErrorKind::Unsupported.into());
            }
            let security = self.security(request.security)?;
            let joined = wifi::join(
                &self.device,
                &request.ssid,
                &request.secret,
                security,
                request.within,
            )?;
            Ok(LinkLease::new(
                joined.local,
                Some(joined.host),
                joined.interface,
                joined,
            ))
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
