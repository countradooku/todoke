//! Which link kinds this build can use.
//!
//! A transport is available only when it is implemented for the platform
//! and the protocol assigns everything it needs. PROTOCOL §16 (O7) leaves
//! BLE, Wi-Fi P2P, AWDL, USB, and direct QUIC unassigned and requires
//! those adapters to stay disabled, whatever the platform could do.

/// The transports `docs/DESIGN.md` assigns to this crate (PROTOCOL §9, §10).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Transport {
    /// TCP on the local network, found through mDNS.
    LanTcp,
    /// QUIC directly between devices (on a LAN or after hole punching).
    DirectQuic,
    /// Bluetooth Low Energy.
    Ble,
    /// Wi-Fi Direct / Wi-Fi Aware.
    WifiP2p,
    /// Apple Wireless Direct Link.
    Awdl,
    /// USB.
    Usb,
    /// QUIC to a relay that forwards opaque traffic (§10).
    Relay,
}

impl Transport {
    /// Every transport, in a fixed order.
    pub const ALL: [Self; 7] = [
        Self::LanTcp,
        Self::DirectQuic,
        Self::Ble,
        Self::WifiP2p,
        Self::Awdl,
        Self::Usb,
        Self::Relay,
    ];
}

/// Whether a transport can be used.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Availability {
    /// Implemented and allowed on this platform.
    Available,
    /// The protocol does not assign what it needs yet (§16, O7): disabled
    /// everywhere until a spec revision does.
    SpecGated,
    /// Allowed by the protocol but not implemented yet.
    NotImplemented,
    /// This platform has no such facility (for example, sockets on
    /// `wasm32-unknown-unknown`).
    Unsupported,
}

/// What this build can do with `transport` on this platform.
#[must_use]
pub const fn availability(transport: Transport) -> Availability {
    match transport {
        Transport::LanTcp | Transport::Relay => {
            if cfg!(target_family = "wasm") {
                Availability::Unsupported
            } else {
                Availability::Available
            }
        }
        Transport::DirectQuic
        | Transport::Ble
        | Transport::WifiP2p
        | Transport::Awdl
        | Transport::Usb => Availability::SpecGated,
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
    fn lan_and_relay_are_available_and_o7_transports_stay_gated() {
        let expected = if cfg!(target_family = "wasm") {
            Vec::new()
        } else {
            vec![Transport::LanTcp, Transport::Relay]
        };
        assert_eq!(available(), expected);
        for transport in [
            Transport::DirectQuic,
            Transport::Ble,
            Transport::WifiP2p,
            Transport::Awdl,
            Transport::Usb,
        ] {
            assert_eq!(availability(transport), Availability::SpecGated);
        }
    }
}
