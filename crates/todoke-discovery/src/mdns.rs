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

    use todoke_proto::discovery::{DiscoveryMode, DiscoveryRecord, Epoch};

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const LABEL: &str = "0ab10000000000ff";

    fn record(token: u8) -> Result<DiscoveryRecord, Box<dyn std::error::Error>> {
        Ok(DiscoveryRecord::new(
            DiscoveryMode::Paired,
            Epoch::new(1_955_555)?,
            [token; 8],
        )?)
    }

    fn resolved(label: &str, ips: &str, txt: &str) -> Result<ServiceEvent, mdns_sd::Error> {
        let txt = [(MDNS_TXT_KEY, txt.to_owned())];
        let info = ServiceInfo::new(
            MDNS_SERVICE,
            label,
            &format!("{label}.local."),
            ips,
            47_000,
            &txt[..],
        )?;
        Ok(ServiceEvent::ServiceResolved(Box::new(
            info.as_resolved_service(),
        )))
    }

    /// R3: `mdns-sd` events become checked events: a valid instance is
    /// seen with only its allowed addresses, an invalid one is dropped, a
    /// removal names its label, and other events are ignored.
    #[test]
    fn daemon_events_are_checked() -> TestResult {
        let value = record(0x3a)?.txt_value();
        let policy = LanPolicy::new();
        let Some(Event::Seen(sighting)) = to_event(
            resolved(LABEL, "192.168.1.20,8.8.8.8,fd00::1", &value)?,
            policy,
        ) else {
            return Err("expected a sighting".into());
        };
        assert_eq!(sighting.label().as_str(), LABEL);
        assert_eq!(sighting.record(), &record(0x3a)?);
        let mut addresses = sighting.addresses().to_vec();
        addresses.sort();
        assert_eq!(
            addresses,
            vec![
                std::net::SocketAddr::from(([192, 168, 1, 20], 47_000)),
                "[fd00::1]:47000".parse()?,
            ]
        );
        assert!(to_event(resolved(LABEL, "8.8.8.8", &value)?, policy).is_none());
        assert!(to_event(resolved(LABEL, "192.168.1.20", "nonsense")?, policy).is_none());
        assert!(to_event(resolved("my-laptop", "192.168.1.20", &value)?, policy).is_none());
        let Some(Event::Gone(label)) = to_event(
            ServiceEvent::ServiceRemoved(MDNS_SERVICE.into(), format!("{LABEL}.{MDNS_SERVICE}")),
            policy,
        ) else {
            return Err("expected a removal".into());
        };
        assert_eq!(label.as_str(), LABEL);
        for name in ["short", "0AB10000000000FF._todoke._tcp.local.", ""] {
            let removed = ServiceEvent::ServiceRemoved(MDNS_SERVICE.into(), name.into());
            assert!(to_event(removed, policy).is_none(), "{name}");
        }
        assert!(to_event(ServiceEvent::SearchStarted(MDNS_SERVICE.into()), policy).is_none());
        assert!(
            to_event(
                ServiceEvent::ServiceFound(MDNS_SERVICE.into(), LABEL.into()),
                policy
            )
            .is_none()
        );
        Ok(())
    }

    /// An `Mdns` whose daemon has every interface disabled (so nothing is
    /// sent on the network) and whose event queue the test fills.
    fn offline() -> Result<(Mdns, mpsc::Sender<Event>), Box<dyn std::error::Error>> {
        let daemon = ServiceDaemon::new()?;
        daemon.disable_interface(IfKind::All)?;
        let (sender, events) = mpsc::channel(QUEUE);
        Ok((
            Mdns {
                daemon,
                events,
                shared: Arc::default(),
                thread: None,
                policy: LanPolicy::new(),
                port: 47_010,
                advertised: BTreeMap::new(),
            },
            sender,
        ))
    }

    fn advertisement(label: u8, token: u8) -> Result<Advertisement, Box<dyn std::error::Error>> {
        Ok(Advertisement {
            label: InstanceLabel::from_random([label; 8])?,
            record: record(token)?,
        })
    }

    fn stranger(mdns: &Mdns) -> Option<(String, Instant)> {
        lock(&mdns.shared.stranger).clone()
    }

    /// R3: applying plans registers what is new, keeps what is unchanged,
    /// re-registers a changed record under the same label, withdraws what
    /// is gone, and tracks the stranger instance (and when it was first
    /// registered under its label) for the browser thread's 70-second cut.
    #[test]
    fn plans_are_applied_exactly() -> TestResult {
        let (mut mdns, _sender) = offline()?;
        mdns.apply(&Plan::default())?;
        assert_eq!(mdns.own_labels(), Vec::new());
        let paired = advertisement(1, 0x11)?;
        let plan = Plan {
            paired: Some(paired),
            stranger: None,
        };
        mdns.apply(&plan)?;
        mdns.apply(&plan)?;
        assert_eq!(mdns.own_labels(), vec![paired.label]);
        let fullname = format!("{}.{MDNS_SERVICE}", paired.label.as_str());
        assert_eq!(
            mdns.advertised.get(&Slot::Paired),
            Some(&(fullname.clone(), paired))
        );
        // A new record under the same label.
        let renewed = Advertisement {
            record: record(0x12)?,
            ..paired
        };
        mdns.apply(&Plan {
            paired: Some(renewed),
            stranger: None,
        })?;
        assert_eq!(
            mdns.advertised.get(&Slot::Paired),
            Some(&(fullname, renewed))
        );
        assert_eq!(stranger(&mdns), None);
        // Stranger mode: tracked from its first registration.
        let first = advertisement(2, 0x21)?;
        mdns.apply(&Plan {
            paired: Some(renewed),
            stranger: Some(first),
        })?;
        let (name, registered) = stranger(&mdns).ok_or("stranger")?;
        assert_eq!(name, format!("{}.{MDNS_SERVICE}", first.label.as_str()));
        std::thread::sleep(Duration::from_millis(5));
        let same_label = Advertisement {
            record: record(0x22)?,
            ..first
        };
        mdns.apply(&Plan {
            paired: Some(renewed),
            stranger: Some(same_label),
        })?;
        assert_eq!(stranger(&mdns), Some((name, registered)));
        let rotated = advertisement(3, 0x23)?;
        mdns.apply(&Plan {
            paired: Some(renewed),
            stranger: Some(rotated),
        })?;
        let (name, again) = stranger(&mdns).ok_or("stranger")?;
        assert_eq!(name, format!("{}.{MDNS_SERVICE}", rotated.label.as_str()));
        assert!(again > registered);
        let mut labels = mdns.own_labels();
        labels.sort_by(|a, b| a.as_str().cmp(b.as_str()));
        assert_eq!(labels, vec![renewed.label, rotated.label]);
        // Everything withdrawn.
        mdns.apply(&Plan::default())?;
        assert!(mdns.advertised.is_empty());
        assert_eq!(stranger(&mdns), None);
        let shown = format!("{mdns:?}");
        assert!(!shown.contains(paired.label.as_str()), "{shown}");
        Ok(())
    }

    /// R3: draining feeds sightings to the directory (counting those kept),
    /// applies goodbyes, and never matches this device's own labels.
    #[tokio::test]
    async fn drained_events_reach_the_directory() -> TestResult {
        let (alice, bob) = paired().await?;
        let table = alice.table(WALL)?;
        let bob_record = bob
            .table(WALL)?
            .advertisement(&alice.key())
            .ok_or("record")?;
        let (mut mdns, sender) = offline()?;
        let own = Advertisement {
            label: InstanceLabel::from_random([9; 8])?,
            record: bob_record,
        };
        mdns.apply(&Plan {
            paired: Some(own),
            stranger: None,
        })?;
        let seen = |label: &str| {
            Sighting::check(
                &format!("{label}.{MDNS_SERVICE}"),
                47_000,
                [(std::net::IpAddr::from([192, 168, 1, 5]), 1)],
                [(MDNS_TXT_KEY, Some(bob_record.txt_value().as_bytes()))],
                LanPolicy::new(),
            )
        };
        sender.try_send(Event::Seen(seen(LABEL)?))?;
        sender.try_send(Event::Seen(seen(own.label.as_str())?))?;
        let mut directory = Directory::new();
        let now = Duration::from_secs(100);
        assert_eq!(mdns.drain(&mut directory, &table, now), 1);
        assert!(directory.contact(&bob.key(), now).is_some());
        sender.try_send(Event::Gone(InstanceLabel::parse(LABEL)?))?;
        assert_eq!(mdns.drain(&mut directory, &table, now), 0);
        assert!(directory.contact(&bob.key(), now).is_none());
        assert!(mdns.try_next().is_none());
        sender.try_send(Event::Gone(InstanceLabel::parse(LABEL)?))?;
        assert!(matches!(mdns.next().await, Ok(Event::Gone(_))));
        drop(sender);
        assert_eq!(mdns.next().await.err(), Some(MdnsError));
        assert_ne!(MdnsError.to_string(), "");
        Ok(())
    }

    /// R3: when the daemon refuses a withdrawal, the advertisement stays
    /// tracked so a later `apply` (or the drop) retries it, and a new one
    /// is not recorded as advertised.
    #[test]
    fn failed_withdrawals_stay_tracked() -> TestResult {
        let (mut mdns, _sender) = offline()?;
        let paired = advertisement(1, 0x11)?;
        mdns.apply(&Plan {
            paired: Some(paired),
            stranger: None,
        })?;
        let _ = mdns.daemon.shutdown();
        assert!(eventually(|| mdns
            .daemon
            .unregister("x._todoke._tcp.local.")
            .is_err()));
        assert_eq!(mdns.apply(&Plan::default()), Err(MdnsError));
        assert_eq!(mdns.own_labels(), vec![paired.label]);
        let stranger = advertisement(2, 0x21)?;
        assert_eq!(
            mdns.apply(&Plan {
                paired: Some(paired),
                stranger: Some(stranger),
            }),
            Err(MdnsError)
        );
        assert_eq!(mdns.own_labels(), vec![paired.label]);
        assert_eq!(lock(&mdns.shared.stranger).clone(), None);
        Ok(())
    }

    /// Waits (polling) up to five seconds for `done`.
    fn eventually(mut done: impl FnMut() -> bool) -> bool {
        let started = Instant::now();
        while started.elapsed() < Duration::from_secs(5) {
            if done() {
                return true;
            }
            std::thread::sleep(Duration::from_millis(20));
        }
        done()
    }

    /// R3: the browser thread withdraws a stranger advertisement once it is
    /// `STRANGER_MAX` old, whatever the caller does, and leaves a younger
    /// one alone; it keeps running when the daemon's channel closes and
    /// stops when asked. The daemon has every interface disabled, so
    /// nothing is sent on the network.
    #[test]
    fn the_browser_thread_cuts_old_stranger_advertisements() -> TestResult {
        let daemon = ServiceDaemon::new()?;
        daemon.disable_interface(IfKind::All)?;
        let browse = daemon.browse(MDNS_SERVICE)?;
        let (sender, mut events) = mpsc::channel(QUEUE);
        let shared = Arc::new(Shared::default());
        let young = format!("{LABEL}.{MDNS_SERVICE}");
        *lock(&shared.stranger) = Some((young.clone(), Instant::now()));
        let thread = {
            let (daemon, shared) = (daemon.clone(), Arc::clone(&shared));
            std::thread::spawn(move || {
                browse_loop(&daemon, browse, &sender, &shared, LanPolicy::new());
            })
        };
        std::thread::sleep(POLL * 3);
        assert_eq!(
            lock(&shared.stranger)
                .as_ref()
                .map(|(name, _)| name.clone()),
            Some(young.clone())
        );
        let old = Instant::now()
            .checked_sub(STRANGER_MAX)
            .ok_or("uptime too short")?;
        *lock(&shared.stranger) = Some((young, old));
        assert!(eventually(|| lock(&shared.stranger).is_none()));
        // The daemon goes away: the thread browses again and keeps going
        // until it is stopped.
        let _ = daemon.shutdown();
        std::thread::sleep(POLL * 2);
        assert!(!thread.is_finished());
        shared.stop.store(true, Ordering::Relaxed);
        assert!(eventually(|| thread.is_finished()));
        assert!(thread.join().is_ok());
        // Nothing but search bookkeeping happened: no event for the caller.
        assert!(events.try_recv().is_err());
        Ok(())
    }

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
        let plan = advertiser.plan(&alice_table, time(WALL)?, Duration::ZERO, &mut OsRandom);
        assert!(plan.paired.is_some());
        alice_mdns.apply(&plan)?;
        let mut bob_plan = Advertiser::new();
        bob_mdns.apply(&bob_plan.plan(&bob_table, time(WALL)?, Duration::ZERO, &mut OsRandom))?;
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
