use core::time::Duration;
use std::sync::Mutex;
use std::sync::atomic::AtomicBool;
use std::sync::mpsc;

use zeroize::Zeroizing;

use super::*;

/// An app's links: answers with `lease`, records what it was asked.
struct Fake {
    lease: LinkLease,
    asked: Mutex<Vec<LinkRequest>>,
    bound: Mutex<Vec<(u64, i64)>>,
    released: Mutex<mpsc::Sender<u64>>,
}

impl WifiLinks for Fake {
    fn abilities(&self) -> LinkAbilities {
        LinkAbilities {
            host: vec![LinkKind::WifiDirect],
            join: vec![LinkKind::WifiAware, LinkKind::Hotspot],
            join_security: vec![LinkSecurity::Wpa2, LinkSecurity::AwareSk128],
        }
    }

    fn host(&self, request: LinkRequest) -> Result<LinkLease, LinkError> {
        self.asked
            .lock()
            .map_err(|_| LinkError::Closed)?
            .push(request);
        Ok(self.lease.clone())
    }

    fn join(&self, request: LinkRequest) -> Result<LinkLease, LinkError> {
        self.host(request)
    }

    fn bind_socket(&self, lease: u64, socket: i64) -> Result<(), LinkError> {
        self.bound
            .lock()
            .map_err(|_| LinkError::Closed)?
            .push((lease, socket));
        Ok(())
    }

    fn release(&self, lease: u64) {
        if let Ok(released) = self.released.lock() {
            let _ = released.send(lease);
        }
    }
}

fn fake(lease: LinkLease) -> (Arc<Fake>, mpsc::Receiver<u64>) {
    let (send, receive) = mpsc::channel();
    let fake = Arc::new(Fake {
        lease,
        asked: Mutex::new(Vec::new()),
        bound: Mutex::new(Vec::new()),
        released: Mutex::new(send),
    });
    (fake, receive)
}

fn lease(host: Option<&str>) -> LinkLease {
    LinkLease {
        id: 7,
        local: "192.168.49.10".to_owned(),
        host: host.map(str::to_owned),
        interface: 3,
        bind_sockets: false,
        scopes: Vec::new(),
    }
}

fn join(kind: proto::LinkKind) -> JoinRequest {
    JoinRequest {
        kind,
        security: proto::LinkSecurity::Wpa2,
        ssid: "DIRECT-ab-tdk-0011223344556677".to_owned(),
        secret: Zeroizing::new(b"secret".to_vec()),
        service_info: [1, 2, 3, 4, 5, 6, 7, 8],
        within: Duration::from_secs(30),
        cancel: Arc::new(AtomicBool::new(false)),
    }
}

const RELEASED_WITHIN: Duration = Duration::from_secs(10);

#[test]
fn abilities_cross_as_the_core_reads_them() {
    let (app, _released) = fake(lease(None));
    let abilities = AppLinks::new(app).abilities();
    assert!(abilities.hosts(proto::LinkKind::WifiDirect));
    assert!(!abilities.hosts(proto::LinkKind::Hotspot));
    assert!(abilities.joins(proto::LinkKind::WifiAware));
    assert!(abilities.joins(proto::LinkKind::Hotspot));
    assert!(!abilities.joins(proto::LinkKind::WifiDirect));
    assert_eq!(
        abilities.strongest(proto::LinkKind::Hotspot),
        Some(proto::LinkSecurity::Wpa2)
    );
}

/// A joined link reaches the core with its addresses, and goes when the
/// core drops it.
#[test]
fn a_joined_link_is_released_when_dropped() -> Result<(), Box<dyn std::error::Error>> {
    let (app, released) = fake(lease(Some("192.168.49.1")));
    let links = AppLinks::new(Arc::clone(&app) as Arc<dyn WifiLinks>);
    let joined = links.join(&join(proto::LinkKind::WifiDirect))?;
    assert_eq!(joined.local, "192.168.49.10".parse::<IpAddr>()?);
    assert_eq!(joined.host, Some("192.168.49.1".parse::<IpAddr>()?));
    assert_eq!(joined.interface, 3);
    assert!(joined.bind.is_none());
    let asked = app.asked.lock().map_err(|_| "poisoned")?.clone();
    assert_eq!(asked.len(), 1);
    assert_eq!(asked[0].kind, LinkKind::WifiDirect);
    assert_eq!(asked[0].secret, b"secret");
    assert_eq!(asked[0].within_ms, 30_000);
    // Only Wi-Fi Aware publishes or matches service information.
    assert_eq!(asked[0].service_info, Vec::<u8>::new());
    assert!(released.try_recv().is_err());
    drop(joined);
    assert_eq!(released.recv_timeout(RELEASED_WITHIN)?, 7);
    Ok(())
}

#[test]
fn wifi_aware_carries_the_service_information() -> Result<(), Box<dyn std::error::Error>> {
    let (app, _released) = fake(lease(Some("fe80::1")));
    let links = AppLinks::new(Arc::clone(&app) as Arc<dyn WifiLinks>);
    drop(links.join(&join(proto::LinkKind::WifiAware))?);
    let asked = app.asked.lock().map_err(|_| "poisoned")?.clone();
    assert_eq!(asked[0].service_info, [1, 2, 3, 4, 5, 6, 7, 8]);
    Ok(())
}

/// A lease the core cannot use is released at once, never kept.
#[test]
fn unusable_leases_are_released() -> Result<(), Box<dyn std::error::Error>> {
    let mut bad_local = lease(Some("192.168.49.1"));
    bad_local.local = "not an address".to_owned();
    // A joiner never listens unscoped; a host only with real interfaces.
    let mut unscoped = lease(Some("192.168.49.1"));
    unscoped.local = "::".to_owned();
    unscoped.scopes = vec![5];
    for (lease, cancelled) in [
        (unscoped, false),
        (lease(None), false),
        (lease(Some("192.168.49")), false),
        (bad_local, false),
        (lease(Some("192.168.49.1")), true),
    ] {
        let (app, released) = fake(lease);
        let links = AppLinks::new(app);
        let request = join(proto::LinkKind::Hotspot);
        request.cancel.store(cancelled, Ordering::Release);
        assert!(links.join(&request).is_err());
        assert_eq!(released.recv_timeout(RELEASED_WITHIN)?, 7);
    }
    Ok(())
}

/// The host gives no host address; one it gives anyway is ignored.
#[test]
fn a_hosted_link_has_no_host_address() -> Result<(), Box<dyn std::error::Error>> {
    let (app, _released) = fake(lease(Some("192.168.49.1")));
    let links = AppLinks::new(Arc::clone(&app) as Arc<dyn WifiLinks>);
    let hosted = links.host(&HostRequest {
        kind: proto::LinkKind::WifiDirect,
        security: proto::LinkSecurity::Wpa2,
        ssid: "DIRECT-ab-tdk-0011223344556677".to_owned(),
        secret: Zeroizing::new(b"secret".to_vec()),
        service_info: [0; 8],
        cancel: Arc::new(AtomicBool::new(false)),
    })?;
    assert_eq!(hosted.host, None);
    assert_eq!(app.asked.lock().map_err(|_| "poisoned")?[0].within_ms, 0);
    Ok(())
}

/// A link that is a network of its own binds every socket to it, by the
/// app's lease.
#[test]
fn sockets_are_bound_through_the_app() -> Result<(), Box<dyn std::error::Error>> {
    let mut own_network = lease(Some("192.168.49.1"));
    own_network.bind_sockets = true;
    let (app, _released) = fake(own_network);
    let links = AppLinks::new(Arc::clone(&app) as Arc<dyn WifiLinks>);
    let joined = links.join(&join(proto::LinkKind::WifiDirect))?;
    let bind = joined.bind.as_ref().ok_or("no binder")?;
    bind(42)?;
    assert_eq!(*app.bound.lock().map_err(|_| "poisoned")?, [(7, 42)]);
    Ok(())
}

#[test]
fn errors_cross_as_io_errors() {
    assert_eq!(
        io_error(LinkError::Closed).kind(),
        io::ErrorKind::NotConnected
    );
    let failed = io_error(LinkError::Failed {
        message: "no radio".to_owned(),
    });
    assert_eq!(failed.to_string(), "no radio");
}

#[test]
fn kinds_and_securities_round_trip() {
    for kind in proto::LinkKind::ALL {
        assert_eq!(proto::LinkKind::from(LinkKind::from(kind)), kind);
    }
    for security in [
        LinkSecurity::Wpa3,
        LinkSecurity::Wpa3Transition,
        LinkSecurity::Wpa2,
        LinkSecurity::AwareSk256,
        LinkSecurity::AwareSk128,
    ] {
        assert_eq!(
            LinkSecurity::from(proto::LinkSecurity::from(security)),
            security
        );
    }
}

/// A Wi-Fi Aware publisher learns its address only once the joiner sets
/// the data path up: it names the link's interfaces instead, never none.
#[test]
fn an_aware_host_names_its_interfaces() -> Result<(), Box<dyn std::error::Error>> {
    let request = || HostRequest {
        kind: proto::LinkKind::WifiAware,
        security: proto::LinkSecurity::AwareSk128,
        ssid: String::new(),
        secret: Zeroizing::new(vec![9; 32]),
        service_info: [1; 8],
        cancel: Arc::new(AtomicBool::new(false)),
    };
    let mut aware = lease(None);
    aware.local = "::".to_owned();
    aware.bind_sockets = true;
    for scopes in [vec![], vec![0], vec![4, 0]] {
        aware.scopes = scopes;
        let (app, released) = fake(aware.clone());
        assert!(AppLinks::new(app).host(&request()).is_err());
        assert_eq!(released.recv_timeout(RELEASED_WITHIN)?, 7);
    }
    aware.scopes = vec![4, 5];
    let (app, _released) = fake(aware);
    let hosted = AppLinks::new(Arc::clone(&app) as Arc<dyn WifiLinks>).host(&request())?;
    assert!(hosted.local.is_unspecified());
    assert_eq!(hosted.scopes, [4, 5]);
    assert!(hosted.bind.is_some());
    let asked = app.asked.lock().map_err(|_| "poisoned")?.clone();
    assert_eq!(asked[0].service_info, [1; 8]);
    assert_eq!(asked[0].secret, [9; 32]);
    Ok(())
}
