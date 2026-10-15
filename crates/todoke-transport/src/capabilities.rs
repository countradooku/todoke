//! Which link kinds this build can use.
//!
//! A transport is available only when it is implemented for the platform.
//! PROTOCOL §10.1 defines every direct link as TCP carrying the unchanged
//! session, and v1 has no Bluetooth, USB, or direct QUIC transport at all,
//! so none is listed here.

/// The transports `docs/DESIGN.md` assigns to this crate (PROTOCOL §9, §10).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Transport {
    /// TCP on the local network, found through mDNS.
    LanTcp,
    /// TCP over a Wi-Fi Aware data path, a Wi-Fi Direct group, or a hotspot
    /// set up inside a session (§10.2).
    WifiP2p,
    /// TCP over Apple peer-to-peer Wi-Fi (AWDL) or Apple Wi-Fi Aware.
    Awdl,
    /// QUIC to a relay that forwards opaque traffic (§10).
    Relay,
}

impl Transport {
    /// Every transport, in a fixed order.
    pub const ALL: [Self; 4] = [Self::LanTcp, Self::WifiP2p, Self::Awdl, Self::Relay];
}

/// Whether a transport can be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Availability {
    /// Implemented and allowed on this platform.
    Available,
    /// Defined by the protocol but not implemented yet (the Wi-Fi adapters
    /// come with the mobile and desktop radio steps).
    NotImplemented,
    /// This platform has no such facility (for example, sockets on
    /// `wasm32-unknown-unknown`).
    Unsupported,
}

/// What this build can do with `transport` on this platform.
#[must_use]
pub const fn availability(transport: Transport) -> Availability {
    match transport {
        Transport::LanTcp => {
            if cfg!(target_family = "wasm") {
                Availability::Unsupported
            } else {
                Availability::Available
            }
        }
        Transport::Relay => {
            if cfg!(target_family = "wasm") {
                Availability::Unsupported
            } else if cfg!(feature = "relay") {
                Availability::Available
            } else {
                Availability::NotImplemented
            }
        }
        Transport::WifiP2p | Transport::Awdl => Availability::NotImplemented,
    }
}

/// The transports this build can use now.
#[must_use]
pub fn available() -> Vec<Transport> {
    Transport::ALL
        .into_iter()
        .filter(|transport| availability(*transport) == Availability::Available)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lan_and_relay_are_available_and_wifi_links_are_not_built_yet() {
        let expected = if cfg!(target_family = "wasm") {
            Vec::new()
        } else if cfg!(feature = "relay") {
            vec![Transport::LanTcp, Transport::Relay]
        } else {
            vec![Transport::LanTcp]
        };
        assert_eq!(available(), expected);
        for transport in [Transport::WifiP2p, Transport::Awdl] {
            assert_eq!(availability(transport), Availability::NotImplemented);
        }
    }
}
