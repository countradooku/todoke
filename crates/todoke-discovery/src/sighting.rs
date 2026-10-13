//! One resolved mDNS service instance, checked against PROTOCOL §9.
//!
//! Everything in an mDNS answer is untrusted: anyone on the network can
//! send any instance name, TXT strings, port, and addresses. A sighting is
//! kept only if it has exactly the §9 shape (the service type, a 16-hex
//! instance label, one `v1=` TXT string with a valid record, a port) and at
//! least one address the [`LanPolicy`] allows; everything else is dropped
//! with a reason, never an error that stops discovery.

use core::fmt;
use std::net::{IpAddr, SocketAddr, SocketAddrV6};

use todoke_proto::discovery::{
    DISCOVERY_RECORD_LEN, DiscoveryRecord, INSTANCE_LABEL_LEN, InstanceLabel, MDNS_SERVICE,
    MDNS_TXT_KEY,
};
use todoke_transport::LanPolicy;

/// At most this many addresses of one instance are kept, as §10 bounds
/// the candidates of one endpoint.
pub const MAX_ADDRESSES: usize = 4;

/// Why a sighting was dropped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dropped {
    /// Not an instance of `_todoke._tcp.local.`, or not a 16-hex label.
    Name,
    /// Not exactly one TXT string `v1=` with 38 lowercase hex characters
    /// encoding a valid record.
    Txt,
    /// Port 0.
    Port,
    /// No address the LAN policy allows.
    NoAddress,
}

impl fmt::Display for Dropped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Name => "not a todoke instance name",
            Self::Txt => "not a valid todoke TXT record",
            Self::Port => "no port",
            Self::NoAddress => "no allowed address",
        })
    }
}

impl std::error::Error for Dropped {}

/// A checked sighting: an untrusted claim that `record` is reachable at
/// `addresses`.
#[derive(Clone, PartialEq, Eq)]
pub struct Sighting {
    label: InstanceLabel,
    record: DiscoveryRecord,
    addresses: Vec<SocketAddr>,
}

impl Sighting {
    /// Checks one resolved instance. `txt` is every TXT string's key and
    /// value; `addresses` are the A/AAAA addresses with the receiving
    /// interface's index (for IPv6 link-local scope).
    ///
    /// # Errors
    ///
    /// The [`Dropped`] reason.
    pub fn check<'a>(
        fullname: &str,
        port: u16,
        addresses: impl IntoIterator<Item = (IpAddr, u32)>,
        txt: impl IntoIterator<Item = (&'a str, Option<&'a [u8]>)>,
        policy: LanPolicy,
    ) -> Result<Self, Dropped> {
        let label = instance_label(fullname).ok_or(Dropped::Name)?;
        let record = record(txt).ok_or(Dropped::Txt)?;
        if port == 0 {
            return Err(Dropped::Port);
        }
        let mut kept: Vec<SocketAddr> = Vec::with_capacity(MAX_ADDRESSES);
        for (ip, interface) in addresses {
            let address = match ip {
                IpAddr::V4(v4) => SocketAddr::from((v4, port)),
                IpAddr::V6(v6) => {
                    let scope = if v6.is_unicast_link_local() {
                        interface
                    } else {
                        0
                    };
                    SocketAddr::V6(SocketAddrV6::new(v6, port, 0, scope))
                }
            };
            if policy.check_peer(address).is_ok() && !kept.contains(&address) {
                kept.push(address);
                if kept.len() == MAX_ADDRESSES {
                    break;
                }
            }
        }
        if kept.is_empty() {
            return Err(Dropped::NoAddress);
        }
        // Stable order: the same answer always gives the same candidates.
        kept.sort();
        Ok(Self {
            label,
            record,
            addresses: kept,
        })
    }

    /// The instance label.
    #[must_use]
    pub const fn label(&self) -> &InstanceLabel {
        &self.label
    }

    /// The advertised record; untrusted.
    #[must_use]
    pub const fn record(&self) -> &DiscoveryRecord {
        &self.record
    }

    /// The allowed addresses, with the SRV port; untrusted.
    #[must_use]
    pub fn addresses(&self) -> &[SocketAddr] {
        &self.addresses
    }
}

/// Addresses are left out: they identify devices on the user's network.
impl fmt::Debug for Sighting {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sighting")
            .field("record", &self.record)
            .field("addresses", &self.addresses.len())
            .finish_non_exhaustive()
    }
}

/// `<label>._todoke._tcp.local.`, label compared exactly (lowercase hex).
fn instance_label(fullname: &str) -> Option<InstanceLabel> {
    let rest = fullname.get(INSTANCE_LABEL_LEN..)?;
    if rest.strip_prefix('.')? != MDNS_SERVICE {
        return None;
    }
    InstanceLabel::parse(fullname.get(..INSTANCE_LABEL_LEN)?).ok()
}

/// Exactly one TXT string, `v1=` and the record in lowercase hex (§9).
fn record<'a>(
    txt: impl IntoIterator<Item = (&'a str, Option<&'a [u8]>)>,
) -> Option<DiscoveryRecord> {
    let mut strings = txt.into_iter();
    let (key, value) = strings.next()?;
    if strings.next().is_some() || key != MDNS_TXT_KEY {
        return None;
    }
    let value = value?;
    if value.len() != 2 * DISCOVERY_RECORD_LEN {
        return None;
    }
    let mut string = Vec::with_capacity(3 + value.len());
    string.extend_from_slice(MDNS_TXT_KEY.as_bytes());
    string.push(b'=');
    string.extend_from_slice(value);
    DiscoveryRecord::from_txt(&string).ok()
}

#[cfg(test)]
mod tests;
