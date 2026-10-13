//! mDNS on the local network through `mdns-sd` (PROTOCOL §9).
//!
//! Built without `mdns-sd`'s `logging` feature: nothing here or in it logs,
//! so no token, label, or address reaches a log. Loopback interfaces are
//! off unless the policy allows loopback (development), and only
//! interfaces with a private or link-local address announce anything.
//!
//! `mdns-sd` caches non-host records for their announced TTL (75 minutes
//! for PTR and TXT records); the [`Directory`] applies the §9 limit of 120
//! seconds on top, and the caller should rebuild the table and call
//! [`Directory::expire`] at least that often.

use core::fmt;
use std::collections::BTreeMap;

use mdns_sd::{IfKind, IfPredicate, ServiceDaemon, ServiceEvent, ServiceInfo};
use todoke_proto::discovery::{INSTANCE_LABEL_LEN, InstanceLabel, MDNS_SERVICE, MDNS_TXT_KEY};
use todoke_transport::LanPolicy;
use todoke_transport::policy::is_local_network;

use crate::advertise::{Advertisement, Plan};
use crate::directory::{Directory, Observed};
use crate::sighting::Sighting;

/// An mDNS failure; the daemon's own message is not kept (it may name
/// addresses or instances).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MdnsError;

impl fmt::Display for MdnsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("mDNS failed")
    }
}

impl std::error::Error for MdnsError {}

impl From<mdns_sd::Error> for MdnsError {
    fn from(_: mdns_sd::Error) -> Self {
        Self
    }
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Slot {
    Paired,
    Stranger,
}

/// The mDNS responder and browser for `_todoke._tcp.local.`.
pub struct Mdns {
    daemon: ServiceDaemon,
    browse: mdns_sd::Receiver<ServiceEvent>,
    policy: LanPolicy,
    port: u16,
    advertised: BTreeMap<Slot, (String, Advertisement)>,
}

impl fmt::Debug for Mdns {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Mdns")
            .field("advertising", &self.advertised.len())
            .finish_non_exhaustive()
    }
}

impl Mdns {
    /// Starts the responder and browses for todoke instances. `port` is the
    /// LAN listener's, for the SRV record.
    ///
    /// # Errors
    ///
    /// [`MdnsError`] if the daemon cannot start (no multicast socket).
    pub fn start(port: u16, policy: LanPolicy) -> Result<Self, MdnsError> {
        let daemon = ServiceDaemon::new()?;
        if policy.check_peer(([127, 0, 0, 1], port).into()).is_err() {
            daemon.disable_interface(vec![IfKind::LoopbackV4, IfKind::LoopbackV6])?;
        }
        let browse = daemon.browse(MDNS_SERVICE)?;
        Ok(Self {
            daemon,
            browse,
            policy,
            port,
            advertised: BTreeMap::new(),
        })
    }

    /// Advertises exactly `plan`: registers what is new or changed (a new
    /// label or record) and unregisters what is gone, which sends goodbye
    /// packets so peers drop it from their caches.
    ///
    /// # Errors
    ///
    /// [`MdnsError`]; whatever was applied before the failure stays.
    pub fn apply(&mut self, plan: &Plan) -> Result<(), MdnsError> {
        for (slot, wanted) in [(Slot::Paired, plan.paired), (Slot::Stranger, plan.stranger)] {
            let current = self
                .advertised
                .get(&slot)
                .map(|(_, advertisement)| *advertisement);
            if current == wanted {
                continue;
            }
            if let Some((fullname, old)) = self.advertised.remove(&slot)
                && wanted.is_none_or(|new| new.label != old.label)
            {
                // A new label: say goodbye to the old instance first.
                let _ = self.daemon.unregister(&fullname)?;
            }
            if let Some(advertisement) = wanted {
                let info = self.service_info(&advertisement)?;
                let fullname = info.get_fullname().to_owned();
                self.daemon.register(info)?;
                self.advertised.insert(slot, (fullname, advertisement));
            }
        }
        Ok(())
    }

    fn service_info(&self, advertisement: &Advertisement) -> Result<ServiceInfo, MdnsError> {
        let label = advertisement.label.as_str();
        // The host name is the label too: never the device name (§9).
        let host = format!("{label}.local.");
        let txt = [(MDNS_TXT_KEY, advertisement.record.txt_value())];
        let mut info = ServiceInfo::new(MDNS_SERVICE, label, &host, (), self.port, &txt[..])?
            .enable_addr_auto();
        let loopback = self
            .policy
            .check_peer(([127, 0, 0, 1], self.port).into())
            .is_ok();
        info.set_interfaces(vec![IfKind::Predicate(IfPredicate::new(
            move |interface| {
                is_local_network(interface.ip()) || (loopback && interface.ip().is_loopback())
            },
        ))]);
        Ok(info)
    }

    /// The next browser event, without waiting: `None` once nothing is
    /// queued. Answers that are not valid todoke instances are skipped.
    #[must_use]
    pub fn try_next(&self) -> Option<Event> {
        loop {
            let event = self.browse.try_recv().ok()?;
            if let Some(event) = self.event(event) {
                return Some(event);
            }
        }
    }

    /// Waits for the next browser event.
    ///
    /// # Errors
    ///
    /// [`MdnsError`] if the daemon stopped.
    pub async fn next(&self) -> Result<Event, MdnsError> {
        loop {
            let event = self.browse.recv_async().await.map_err(|_| MdnsError)?;
            if let Some(event) = self.event(event) {
                return Ok(event);
            }
        }
    }

    /// Feeds every queued event into `directory`, matched against `table`
    /// at monotonic time `now`. Returns how many sightings were kept.
    pub fn drain(
        &self,
        directory: &mut Directory,
        table: &todoke_crypto::discovery::DiscoveryTable,
        now: core::time::Duration,
    ) -> usize {
        directory.set_own(self.own_labels());
        let mut kept = 0;
        while let Some(event) = self.try_next() {
            match event {
                Event::Seen(sighting) => {
                    if directory.observe(sighting, table, now) == Observed::Kept {
                        kept += 1;
                    }
                }
                Event::Gone(label) => directory.remove(&label),
            }
        }
        kept
    }

    fn event(&self, event: ServiceEvent) -> Option<Event> {
        match event {
            ServiceEvent::ServiceResolved(service) => Sighting::check(
                &service.fullname,
                service.port,
                service.addresses.iter().map(|scoped| {
                    let scope = match scoped {
                        mdns_sd::ScopedIp::V6(v6) => v6.scope_id().index,
                        _ => 0,
                    };
                    (scoped.to_ip_addr(), scope)
                }),
                service
                    .txt_properties
                    .iter()
                    .map(|property| (property.key(), property.val())),
                self.policy,
            )
            .ok()
            .map(Event::Seen),
            ServiceEvent::ServiceRemoved(_, fullname) => fullname
                .get(..INSTANCE_LABEL_LEN)
                .and_then(|label| InstanceLabel::parse(label).ok())
                .map(Event::Gone),
            _ => None,
        }
    }

    /// This device's own instance labels, which the directory must ignore
    /// ([`Directory::set_own`]).
    #[must_use]
    pub fn own_labels(&self) -> Vec<InstanceLabel> {
        self.advertised
            .values()
            .map(|(_, advertisement)| advertisement.label)
            .collect()
    }
}

/// A browser event about a todoke instance.
#[derive(Debug)]
pub enum Event {
    /// A valid instance was resolved (again).
    Seen(Sighting),
    /// An instance said goodbye.
    Gone(InstanceLabel),
}

impl Drop for Mdns {
    fn drop(&mut self) {
        for (fullname, _) in self.advertised.values() {
            let _ = self.daemon.unregister(fullname);
        }
        let _ = self.daemon.shutdown();
    }
}

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use super::*;
    use crate::advertise::{Advertiser, OsRandom};
    use crate::support::{WALL, paired, time};

    /// Real multicast between two responders on this machine: Alice
    /// advertises, Bob finds her among the answers and ignores his own.
    /// Needs a network that carries mDNS (CI runners often do not).
    #[tokio::test]
    #[ignore = "needs multicast on the local machine"]
    async fn contacts_find_each_other_over_mdns() -> Result<(), Box<dyn std::error::Error>> {
        let (alice, bob) = paired().await?;
        let policy = LanPolicy::new().with_loopback();
        let (alice_table, bob_table) = (alice.table(WALL)?, bob.table(WALL)?);
        let mut alice_mdns = Mdns::start(47_001, policy)?;
        let bob_mdns = Mdns::start(47_002, policy)?;
        let mut advertiser = Advertiser::new();
        let plan = advertiser.plan(
            &alice_table,
            None,
            time(WALL)?,
            Duration::ZERO,
            &mut OsRandom,
        );
        assert!(plan.paired.is_some());
        alice_mdns.apply(&plan)?;
        let mut bob_plan = Advertiser::new();
        let mut bob_mdns = bob_mdns;
        bob_mdns.apply(&bob_plan.plan(
            &bob_table,
            None,
            time(WALL)?,
            Duration::ZERO,
            &mut OsRandom,
        ))?;
        let mut directory = Directory::new();
        let started = std::time::Instant::now();
        while started.elapsed() < Duration::from_secs(10) {
            let now = started.elapsed();
            bob_mdns.drain(&mut directory, &bob_table, now);
            if let Some(found) = directory.contact(&alice.key(), now) {
                assert!(found.addresses().iter().all(|a| a.port() == 47_001));
                // Bob's own advertisement never shows up as a contact.
                assert!(directory.contact(&bob.key(), now).is_none());
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err("Alice was not found over mDNS".into())
    }
}
