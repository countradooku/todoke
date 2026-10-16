//! §9 discovery through the system's Bonjour (`dns_sd`, mDNSResponder) on
//! Apple platforms, used on iOS, where an app may not send or receive raw
//! multicast (and so cannot run `mdns-sd`) without Apple's restricted
//! multicast entitlement.
//!
//! The same records as [`crate::mdns`]: one instance per wanted
//! advertisement, labelled with its rotating label, whose host name is the
//! label too (never the device's), published only on interfaces with a
//! private or link-local address (and loopback when the policy allows it).
//! Every answer goes through [`Sighting::check`] like an mDNS one. A
//! stranger advertisement is withdrawn after [`STRANGER_MAX`] whatever
//! plans the caller applies.

use core::time::Duration;
use std::net::IpAddr;
use std::time::Instant;

use todoke_proto::discovery::{InstanceLabel, MDNS_SERVICE};
use todoke_sys_macos::bonjour::{self as sys, Address, Found, Instance};
use todoke_transport::LanPolicy;
use todoke_transport::policy::is_local_network;

use crate::advertise::{Advertisement, Plan};
use crate::backend::{MdnsError, STRANGER_MAX};
use crate::directory::{Directory, Observed};
use crate::sighting::Sighting;

/// How often the local addresses are read again.
const ADDRESSES_EVERY: Duration = Duration::from_secs(5);
/// The least time between two restarts of a stopped responder.
const RESTART_EVERY: Duration = Duration::from_secs(5);

/// The Bonjour responder and browser for `_todoke._tcp.local.`.
pub struct Bonjour {
    sys: sys::Bonjour,
    port: u16,
    policy: LanPolicy,
    /// What was last published (the stranger with when it started).
    paired: Option<Advertisement>,
    stranger: Option<(Advertisement, Instant)>,
    addresses: Vec<Address>,
    /// When the addresses were read.
    addresses_at: Option<Instant>,
    /// What the responder advertises now, to publish only changes.
    published: Option<(Vec<Instance>, Vec<Address>)>,
    /// When the responder last (re)started.
    started: Instant,
}

impl core::fmt::Debug for Bonjour {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Bonjour")
            .field("port", &self.port)
            .finish_non_exhaustive()
    }
}

impl Bonjour {
    /// Starts browsing; advertises `port` once [`Self::apply`] gives
    /// records. With a policy that allows loopback (development), on this
    /// device only.
    ///
    /// # Errors
    ///
    /// [`MdnsError`] if mDNSResponder cannot be reached.
    pub fn start(port: u16, policy: LanPolicy) -> Result<Self, MdnsError> {
        let sys = sys::Bonjour::start(allows_loopback(policy)).map_err(|_| MdnsError)?;
        Ok(Self {
            sys,
            port,
            policy,
            paired: None,
            stranger: None,
            addresses: Vec::new(),
            addresses_at: None,
            published: None,
            started: Instant::now(),
        })
    }

    /// Advertises `plan`: exactly its records, on this device's local
    /// addresses (read again every few seconds). Only changes reach
    /// mDNSResponder. A responder whose connection broke is started again.
    ///
    /// # Errors
    ///
    /// None today; the signature matches [`crate::Mdns::apply`].
    pub fn apply(&mut self, plan: &Plan) -> Result<(), MdnsError> {
        let now = Instant::now();
        if self.sys.stopped() && now.saturating_duration_since(self.started) >= RESTART_EVERY {
            self.started = now;
            if let Ok(sys) = sys::Bonjour::start(allows_loopback(self.policy)) {
                self.sys = sys;
                self.published = None;
            }
        }
        self.stranger = match (plan.stranger, self.stranger) {
            (Some(wanted), Some((current, since))) if wanted.label == current.label => {
                Some((wanted, since))
            }
            (Some(wanted), _) => Some((wanted, now)),
            (None, _) => None,
        };
        // Withdrawn after STRANGER_MAX, whatever the caller still asks.
        if let Some((_, since)) = self.stranger
            && now.saturating_duration_since(since) > STRANGER_MAX
        {
            self.stranger = None;
        }
        self.paired = plan.paired;
        if self
            .addresses_at
            .is_none_or(|at| now.saturating_duration_since(at) >= ADDRESSES_EVERY)
        {
            self.addresses = local_addresses(self.policy);
            self.addresses_at = Some(now);
        }
        let instances: Vec<Instance> = self
            .paired
            .iter()
            .chain(self.stranger.iter().map(|(advertisement, _)| advertisement))
            .map(|advertisement| Instance {
                label: advertisement.label.as_str().to_owned(),
                txt_value: advertisement.record.txt_value(),
            })
            .collect();
        let wanted = (instances, self.addresses.clone());
        if self.published.as_ref() != Some(&wanted) {
            self.sys
                .publish(wanted.0.clone(), self.port, wanted.1.clone());
            self.published = Some(wanted);
        }
        Ok(())
    }

    /// Feeds what was found into `directory`, matched against `table` at
    /// monotonic time `now`. Returns how many sightings were kept.
    pub fn drain(
        &mut self,
        directory: &mut Directory,
        table: &todoke_crypto::discovery::DiscoveryTable,
        now: Duration,
    ) -> usize {
        directory.set_own(self.own_labels());
        let mut kept = 0;
        while let Some(found) = self.sys.try_next() {
            match found {
                Found::Resolved {
                    name,
                    port,
                    addresses,
                    txt,
                } => {
                    let fullname = format!("{name}.{MDNS_SERVICE}");
                    let properties = txt.iter().map(|string| property(string));
                    if let Ok(sighting) =
                        Sighting::check(&fullname, port, addresses, properties, self.policy)
                        && directory.observe(sighting, table, now) == Observed::Kept
                    {
                        kept += 1;
                    }
                }
                Found::Removed { name } => {
                    if let Ok(label) = InstanceLabel::parse(&name) {
                        directory.remove(&label);
                    }
                }
            }
        }
        kept
    }

    /// This device's own instance labels, which the directory ignores.
    #[must_use]
    pub fn own_labels(&self) -> Vec<InstanceLabel> {
        self.paired
            .iter()
            .chain(self.stranger.iter().map(|(advertisement, _)| advertisement))
            .map(|advertisement| advertisement.label)
            .collect()
    }
}

/// A TXT string as a key and value (`key=value`, or a bare key).
fn property(string: &[u8]) -> (&str, Option<&[u8]>) {
    let (key, value) = match string.iter().position(|&byte| byte == b'=') {
        Some(at) => (&string[..at], Some(&string[at + 1..])),
        None => (string, None),
    };
    // A key that is not UTF-8 is no todoke key: it never matches `v1`.
    (core::str::from_utf8(key).unwrap_or(""), value)
}

/// This device's addresses that §9 records may name: private or
/// link-local (and loopback when the policy allows it), with their
/// interfaces.
fn local_addresses(policy: LanPolicy) -> Vec<Address> {
    let Ok(interfaces) = if_addrs::get_if_addrs() else {
        return Vec::new();
    };
    let loopback = allows_loopback(policy);
    let mut addresses: Vec<Address> = interfaces
        .into_iter()
        .filter_map(|interface| {
            let ip: IpAddr = interface.ip();
            let allowed = is_local_network(ip) || (loopback && ip.is_loopback());
            // Without its index an address could only go on every
            // interface: skipped.
            let index = interface.index.filter(|&index| index != 0)?;
            allowed.then_some(Address {
                ip,
                interface: index,
            })
        })
        .collect();
    addresses.sort_by_key(|address| (address.ip, address.interface));
    addresses.dedup();
    addresses
}

/// Whether `policy` allows loopback peers (development and tests).
fn allows_loopback(policy: LanPolicy) -> bool {
    policy.check_peer(([127, 0, 0, 1], 49_152).into()).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn txt_strings_split_at_the_first_equals_sign() {
        assert_eq!(property(b"v1=ab=c"), ("v1", Some(&b"ab=c"[..])));
        assert_eq!(property(b"v1"), ("v1", None));
        assert_eq!(property(b"v1="), ("v1", Some(&b""[..])));
        assert_eq!(property(b"\xff=x"), ("", Some(&b"x"[..])));
    }

    #[test]
    fn only_local_addresses_are_published() {
        for address in local_addresses(LanPolicy::new()) {
            assert!(is_local_network(address.ip), "{:?}", address.ip);
        }
    }

    /// Two devices paired by QR: Alice advertises through Bonjour on this
    /// device alone, and Bob finds her among the answers (on her port, at
    /// a loopback address) while ignoring his own record. Runs wherever
    /// mDNSResponder does (no multicast needed).
    #[tokio::test]
    async fn contacts_find_each_other_over_bonjour() -> Result<(), Box<dyn std::error::Error>> {
        use crate::advertise::{Advertiser, OsRandom};
        use crate::support::{WALL, paired, time};

        let (alice, bob) = paired().await?;
        let policy = LanPolicy::new().with_loopback();
        let (alice_table, bob_table) = (alice.table(WALL)?, bob.table(WALL)?);
        let mut alice_bonjour = Bonjour::start(47_011, policy)?;
        let mut bob_bonjour = Bonjour::start(47_012, policy)?;
        let plan = Advertiser::new().plan(&alice_table, time(WALL)?, Duration::ZERO, &mut OsRandom);
        assert!(plan.paired.is_some());
        alice_bonjour.apply(&plan)?;
        bob_bonjour.apply(&Advertiser::new().plan(
            &bob_table,
            time(WALL)?,
            Duration::ZERO,
            &mut OsRandom,
        ))?;
        let mut directory = Directory::new();
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(10) {
            let now = started.elapsed();
            bob_bonjour.drain(&mut directory, &bob_table, now);
            if let Some(found) = directory.contact(&alice.key(), now) {
                assert!(found.addresses().iter().all(|a| a.port() == 47_011));
                assert!(directory.contact(&bob.key(), now).is_none());
                // Withdrawn: Bob is told she is gone.
                alice_bonjour.apply(&Plan::default())?;
                let gone = Instant::now();
                while gone.elapsed() < Duration::from_secs(10) {
                    bob_bonjour.drain(&mut directory, &bob_table, started.elapsed());
                    if directory.contact(&alice.key(), started.elapsed()).is_none() {
                        return Ok(());
                    }
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                return Err("Alice's withdrawal was not seen".into());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err("Alice was not found over Bonjour".into())
    }
}
