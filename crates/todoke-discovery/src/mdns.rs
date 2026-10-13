//! mDNS on the local network through `mdns-sd` (PROTOCOL §9).
//!
//! Built without `mdns-sd`'s `logging` feature: nothing here or in it logs,
//! so no token, label, or address reaches a log. Loopback interfaces are
//! off unless the policy allows loopback (development), and only
//! interfaces with a private or link-local address announce anything.
//!
//! A background thread owns the browser:
//!
//! - it checks every answer ([`Sighting::check`]) and queues the result in
//!   a bounded queue that drops when full, so neither a slow consumer nor a
//!   flood of answers can block `mdns-sd`'s own (bounded, blocking) event
//!   channel and with it the responder;
//! - every [`REFRESH`] it browses afresh and asks `mdns-sd` to verify the
//!   instances it reported (RFC 6762 §10.4): an instance that no longer
//!   answers is flushed from `mdns-sd`'s cache, which caches PTR and TXT
//!   records for as long as their sender says, and reported gone. With the
//!   [`Directory`]'s own 120-second expiry, nothing outlives the §9 limit by
//!   more than the verification timeout;
//! - it unregisters any stranger advertisement older than [`STRANGER_MAX`],
//!   whether or not the caller keeps applying plans.

use core::fmt;
use core::time::Duration;
use std::collections::{BTreeMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::JoinHandle;
use std::time::Instant;

use mdns_sd::{IfKind, IfPredicate, ServiceDaemon, ServiceEvent, ServiceInfo};
use todoke_proto::discovery::{INSTANCE_LABEL_LEN, InstanceLabel, MDNS_SERVICE, MDNS_TXT_KEY};
use todoke_transport::LanPolicy;
use todoke_transport::policy::{MIN_PEER_PORT, is_local_network};
use tokio::sync::mpsc;

use crate::advertise::{Advertisement, Plan, STRANGER_ROTATION};
use crate::directory::{Directory, Observed};
use crate::sighting::Sighting;

/// How often the browser starts afresh and verifies what it found.
pub const REFRESH: Duration = Duration::from_secs(50);
/// The longest a stranger advertisement stays registered, whatever plans
/// the caller applies: one rotation and some slack (§9).
pub const STRANGER_MAX: Duration = Duration::from_secs(STRANGER_ROTATION.as_secs() + 10);
/// Checked events queued for the caller; more are dropped.
const QUEUE: usize = 256;
/// Instances whose liveness is verified at each refresh (most recent).
const VERIFIED: usize = 64;
/// How long the thread waits for an event before its periodic checks.
const POLL: Duration = Duration::from_millis(250);

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

/// A browser event about a todoke instance.
#[derive(Debug)]
pub enum Event {
    /// A valid instance was resolved (again).
    Seen(Sighting),
    /// An instance said goodbye or stopped answering.
    Gone(InstanceLabel),
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
enum Slot {
    Paired,
    Stranger,
}

/// What the browser thread shares with the handle.
#[derive(Default)]
struct Shared {
    stop: AtomicBool,
    /// The registered stranger instance and when it was registered.
    stranger: Mutex<Option<(String, Instant)>>,
}

/// The mDNS responder and browser for `_todoke._tcp.local.`.
pub struct Mdns {
    daemon: ServiceDaemon,
    events: mpsc::Receiver<Event>,
    shared: Arc<Shared>,
    thread: Option<JoinHandle<()>>,
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
    /// [`MdnsError`] for a port below 1024 (peers would refuse it) or if
    /// the daemon cannot start (no multicast socket, no thread).
    pub fn start(port: u16, policy: LanPolicy) -> Result<Self, MdnsError> {
        if port < MIN_PEER_PORT {
            return Err(MdnsError);
        }
        let daemon = ServiceDaemon::new()?;
        if policy.check_peer(([127, 0, 0, 1], port).into()).is_err() {
            daemon.disable_interface(vec![IfKind::LoopbackV4, IfKind::LoopbackV6])?;
        }
        let browse = daemon.browse(MDNS_SERVICE)?;
        let (sender, events) = mpsc::channel(QUEUE);
        let shared = Arc::new(Shared::default());
        let thread = {
            let (daemon, shared) = (daemon.clone(), Arc::clone(&shared));
            std::thread::Builder::new()
                .name("todoke-mdns".into())
                .spawn(move || browse_loop(&daemon, browse, &sender, &shared, policy))
                .map_err(|_| MdnsError)?
        };
        Ok(Self {
            daemon,
            events,
            shared,
            thread: Some(thread),
            policy,
            port,
            advertised: BTreeMap::new(),
        })
    }

    /// Advertises exactly `plan`: registers what is new or changed (a new
    /// label or record) and unregisters what is gone, which sends goodbye
    /// packets so peers drop it from their caches. On an error, what could
    /// not be withdrawn is still tracked, so a later call retries it.
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
            if let Some((fullname, old)) = self.advertised.get(&slot).cloned()
                && wanted.is_none_or(|new| new.label != old.label)
            {
                // A new label: say goodbye to the old instance first, and
                // forget it only once that was sent.
                self.daemon.unregister(&fullname)?;
                self.advertised.remove(&slot);
                if slot == Slot::Stranger {
                    *lock(&self.shared.stranger) = None;
                }
            }
            if let Some(advertisement) = wanted {
                let info = self.service_info(&advertisement)?;
                let fullname = info.get_fullname().to_owned();
                self.daemon.register(info)?;
                if slot == Slot::Stranger
                    && self
                        .advertised
                        .get(&slot)
                        .is_none_or(|(name, _)| *name != fullname)
                {
                    *lock(&self.shared.stranger) = Some((fullname.clone(), Instant::now()));
                }
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

    /// The next checked event, without waiting: `None` once nothing is
    /// queued.
    pub fn try_next(&mut self) -> Option<Event> {
        self.events.try_recv().ok()
    }

    /// Waits for the next checked event.
    ///
    /// # Errors
    ///
    /// [`MdnsError`] if the browser stopped.
    pub async fn next(&mut self) -> Result<Event, MdnsError> {
        self.events.recv().await.ok_or(MdnsError)
    }

    /// Feeds every queued event into `directory`, matched against `table`
    /// at monotonic time `now`. Returns how many sightings were kept.
    pub fn drain(
        &mut self,
        directory: &mut Directory,
        table: &todoke_crypto::discovery::DiscoveryTable,
        now: Duration,
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

impl Drop for Mdns {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Relaxed);
        for (fullname, _) in self.advertised.values() {
            let _ = self.daemon.unregister(fullname);
        }
        let _ = self.daemon.shutdown();
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}

fn lock<T>(mutex: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// The browser thread (see the module notes).
fn browse_loop(
    daemon: &ServiceDaemon,
    mut browse: mdns_sd::Receiver<ServiceEvent>,
    sender: &mpsc::Sender<Event>,
    shared: &Shared,
    policy: LanPolicy,
) {
    let mut refreshed = Instant::now();
    let mut reported: VecDeque<String> = VecDeque::with_capacity(VERIFIED);
    while !shared.stop.load(Ordering::Relaxed) {
        match browse.recv_timeout(POLL) {
            Ok(event) => {
                if let ServiceEvent::ServiceResolved(service) = &event
                    && !reported.contains(&service.fullname)
                {
                    if reported.len() == VERIFIED {
                        reported.pop_front();
                    }
                    reported.push_back(service.fullname.clone());
                }
                if let Some(event) = to_event(event, policy) {
                    // Full: drop it; the instance is seen again later.
                    let _ = sender.try_send(event);
                }
            }
            Err(mdns_sd::RecvTimeoutError::Timeout) => {}
            Err(mdns_sd::RecvTimeoutError::Disconnected) => {
                if shared.stop.load(Ordering::Relaxed) {
                    return;
                }
                // Browse again at once.
                refreshed = Instant::now().checked_sub(REFRESH).unwrap_or(refreshed);
            }
        }
        if refreshed.elapsed() >= REFRESH {
            let _ = daemon.stop_browse(MDNS_SERVICE);
            if let Ok(fresh) = daemon.browse(MDNS_SERVICE) {
                browse = fresh;
            }
            for fullname in &reported {
                let _ = daemon.verify(fullname.clone(), mdns_sd::VERIFY_TIMEOUT_DEFAULT);
            }
            refreshed = Instant::now();
        }
        let mut stranger = lock(&shared.stranger);
        if stranger
            .as_ref()
            .is_some_and(|(_, registered)| registered.elapsed() >= STRANGER_MAX)
            && let Some((fullname, _)) = stranger.take()
        {
            let _ = daemon.unregister(&fullname);
        }
    }
}

fn to_event(event: ServiceEvent, policy: LanPolicy) -> Option<Event> {
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
            policy,
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

#[cfg(test)]
mod tests {
    use core::time::Duration;

    use super::*;
    use crate::advertise::{Advertiser, OsRandom};
    use crate::support::{WALL, paired, time};

    #[test]
    fn privileged_ports_are_refused() {
        assert!(Mdns::start(80, LanPolicy::new()).is_err());
        assert!(Mdns::start(0, LanPolicy::new()).is_err());
    }

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
        let mut bob_mdns = Mdns::start(47_002, policy)?;
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
