//! Test fixtures: two devices paired by QR over loopback TCP, so their
//! contact stores hold real committed pair PSKs, and discovery tables
//! built from them.

use std::net::{Ipv4Addr, SocketAddr};

use todoke_crypto::discovery::DiscoveryTable;
use todoke_crypto::identity::{
    BindingRequest, ContactStore, Ed25519PublicKey, ExportPolicy, KeyId, KeyRole, KeyStore,
    MemoryStorage, SoftwareKeyStore, SoftwareSealer, StorageKey, VerifiedDeviceBinding,
    issue_device_binding,
};
use todoke_crypto::pairing::{PairingOffers, QrPayload};
use todoke_crypto::session::{
    Accepted, IncomingSession, LocalIdentity, NoiseStaticKey, Session, UnauditedSuite0001,
};
use todoke_proto::time::UnixTime;
use todoke_transport::{
    Candidate, Connector as _, LanListener, LanPolicy, LinkKind, TcpConnector, TokioTimer,
};
use zeroize::Zeroizing;

pub(crate) type AnyResult<T> = Result<T, Box<dyn std::error::Error>>;
type Keys = SoftwareKeyStore<MemoryStorage>;
type Store = ContactStore<SoftwareSealer, MemoryStorage>;

pub(crate) const T0: u64 = 1_760_000_000;
pub(crate) const WALL: u64 = T0 + 60;
const GATE: UnauditedSuite0001 = UnauditedSuite0001::acknowledge_not_production_ready();

pub(crate) fn time(seconds: u64) -> Result<UnixTime, &'static str> {
    UnixTime::new(seconds).ok_or("time")
}

fn sealer(byte: u8) -> SoftwareSealer {
    SoftwareSealer::new(StorageKey::from_bytes(Zeroizing::new([byte; 32])))
}

pub(crate) struct Device {
    keys: Keys,
    signing_key: KeyId,
    noise: NoiseStaticKey,
    binding: VerifiedDeviceBinding,
    pub(crate) store: Store,
}

impl Device {
    fn new(kem_seed: u8) -> AnyResult<Self> {
        let mut keys = SoftwareKeyStore::open(sealer(1), MemoryStorage::new())?;
        let root = keys.generate(KeyRole::PersonRoot, ExportPolicy::NonExportable)?;
        let device = keys.generate(KeyRole::Device, ExportPolicy::NonExportable)?;
        let noise = NoiseStaticKey::generate()?;
        let pair = libcrux_ml_kem::mlkem768::generate_key_pair([kem_seed; 64]);
        let kem_static: [u8; 1184] = *pair.public_key().as_slice();
        let request = BindingRequest {
            noise_static: *noise.public_key(),
            kem_static: Box::new(kem_static),
            serial: core::num::NonZeroU64::new(1).ok_or("serial")?,
            not_before: time(T0)?,
            not_after: time(T0 + 30 * 86_400)?,
        };
        let binding = issue_device_binding(&keys, &root, &device, request)?;
        Ok(Self {
            keys,
            signing_key: device,
            noise,
            binding,
            store: ContactStore::open(sealer(kem_seed), MemoryStorage::new())?,
        })
    }

    pub(crate) fn key(&self) -> Ed25519PublicKey {
        *self.binding.device_public()
    }

    fn local(&self) -> AnyResult<LocalIdentity<'_, Keys>> {
        Ok(LocalIdentity::new(
            &self.keys,
            self.signing_key,
            &self.binding,
            &self.noise,
            time(WALL)?,
        )?)
    }

    pub(crate) fn table(&self, wall: u64) -> AnyResult<DiscoveryTable> {
        Ok(self.store.discovery_table(time(wall)?)?)
    }
}

/// Alice scans Bob's QR code; both end up with each other as contacts.
/// Bounded: a stalled pairing fails the test instead of hanging it.
pub(crate) async fn paired() -> AnyResult<(Device, Device)> {
    tokio::time::timeout(core::time::Duration::from_secs(60), pair())
        .await
        .map_err(|_| "pairing over loopback stalled")?
}

async fn pair() -> AnyResult<(Device, Device)> {
    let mut alice = Device::new(0x41)?;
    let mut bob = Device::new(0x42)?;
    let offers = PairingOffers::new();
    let timer = TokioTimer::new();
    let wall = time(WALL)?;
    let text = offers
        .create_qr(
            &bob.local()?,
            wall,
            todoke_crypto::session::Timer::now(&timer),
        )?
        .to_text();
    let payload = QrPayload::from_text(&text, wall)?;
    let policy = LanPolicy::new().with_loopback();
    let listener = LanListener::bind(0, policy)?;
    let candidate = Candidate::new(
        LinkKind::Lan,
        SocketAddr::from((Ipv4Addr::LOCALHOST, listener.port()?)),
    );
    let connector = TcpConnector::new(policy);
    let (a, b) = tokio::join!(connector.connect(candidate), listener.accept());
    let (a, b) = (a?, b?);
    let alice_local = LocalIdentity::new(
        &alice.keys,
        alice.signing_key,
        &alice.binding,
        &alice.noise,
        wall,
    )?;
    let bob_local = LocalIdentity::new(&bob.keys, bob.signing_key, &bob.binding, &bob.noise, wall)?;
    let alice_store = &mut alice.store;
    let bob_store = &mut bob.store;
    let (plan, mut initiator) = alice_store.begin_qr_pairing(&payload, wall)?;
    let initiate = Session::initiate(a, timer, GATE, &alice_local, wall, plan, &mut initiator);
    let respond = async {
        let Accepted::Hello(mut incoming) =
            IncomingSession::accept_any(b, timer, GATE, &offers).await?
        else {
            return Err::<_, Box<dyn std::error::Error>>("expected a ClientHello".into());
        };
        let reservation = incoming.reserve_offer(&offers, wall)?;
        let (plan, mut authority) = reservation.into_qr_responder(bob_store)?;
        Ok(incoming
            .respond(&bob_local, wall, plan, &mut authority)
            .await?)
    };
    let (initiated, responded) = tokio::join!(initiate, respond);
    drop((initiated?, responded?));
    Ok((alice, bob))
}
