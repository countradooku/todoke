//! Test fixtures: two devices paired by QR over loopback TCP, so their
//! contact stores hold real committed pair PSKs, and discovery tables
//! built from them.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::OnceLock;

use todoke_crypto::discovery::DiscoveryTable;
use todoke_crypto::identity::{
    BindingRequest, ContactStore, Ed25519PublicKey, ExportPolicy, KeyId, KeyRole, KeyStore,
    MemoryStorage, SoftwareKeyStore, SoftwareSealer, StorageKey, VerifiedDeviceBinding,
    issue_device_binding,
};
use todoke_crypto::pairing::{PairingOffers, QrPayload, QrStrangerKey, QrStrangerTokens};
use todoke_crypto::session::{
    Accepted, IncomingSession, LocalIdentity, NoiseStaticKey, Session, UnauditedSuite0001,
};
use todoke_proto::discovery::{DiscoveryRecord, EPOCH_SECONDS, Epoch};
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

/// A QR offer shown at `wall` by a device without contacts: the scanner's
/// stranger key, the displayer's token schedule, and its (empty) table.
pub(crate) fn qr_stranger(
    wall: u64,
) -> AnyResult<(QrStrangerKey, QrStrangerTokens, DiscoveryTable)> {
    let device = Device::new(0x43)?;
    let at = time(wall)?;
    let payload =
        PairingOffers::new().create_qr(&device.local()?, at, core::time::Duration::ZERO)?;
    let key = payload.stranger_key()?;
    let tokens = key.schedule(at, payload.expires_at())?;
    Ok((key, tokens, device.table(wall)?))
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
    // Boxed: a handshake's state is large, and every test awaits this.
    Box::pin(pair_into(&mut alice, &mut bob)).await?;
    Ok((alice, bob))
}

/// Alice and `count` other devices, each paired with her by QR (she scans
/// each one's code), so her table holds `count` contacts. Bounded like
/// [`paired`].
pub(crate) async fn with_contacts(count: u8) -> AnyResult<(Device, Vec<Device>)> {
    tokio::time::timeout(core::time::Duration::from_secs(120), async {
        let mut alice = Device::new(0x41)?;
        let mut contacts = Vec::new();
        for n in 0..count {
            let mut contact = Device::new(0x50_u8.wrapping_add(n))?;
            Box::pin(pair_into(&mut alice, &mut contact)).await?;
            contacts.push(contact);
        }
        Ok((alice, contacts))
    })
    .await
    .map_err(|_| "pairing over loopback stalled")?
}

/// Alice scans Bob's QR code over loopback TCP.
async fn pair_into(alice: &mut Device, bob: &mut Device) -> AnyResult<()> {
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
    Ok(())
}

/// Discovery state of Alice and three contacts, built once per test binary
/// (one QR pairing each) for the model-based property tests.
pub(crate) struct Fixture {
    /// Her contacts' device keys, in pairing order.
    pub(crate) contacts: Vec<Ed25519PublicKey>,
    /// The first second of each epoch in `tables`.
    pub(crate) walls: Vec<u64>,
    /// Alice's table at each of `walls`: `WALL`'s epoch and the next two.
    pub(crate) tables: Vec<DiscoveryTable>,
    /// What each contact advertises for Alice in `WALL`'s epoch.
    pub(crate) records: Vec<DiscoveryRecord>,
    /// Alice's table at `WALL` once contact 0 is ratchet-uncertain.
    pub(crate) reduced: DiscoveryTable,
    /// A table with no contacts at `WALL`.
    pub(crate) empty: DiscoveryTable,
}

static FIXTURE: OnceLock<Result<Fixture, String>> = OnceLock::new();

/// The shared [`Fixture`]. Call it outside any tokio runtime.
pub(crate) fn fixture() -> Result<&'static Fixture, String> {
    FIXTURE
        .get_or_init(|| build_fixture().map_err(|error| error.to_string()))
        .as_ref()
        .map_err(Clone::clone)
}

fn build_fixture() -> AnyResult<Fixture> {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (mut alice, contacts) = runtime.block_on(with_contacts(3))?;
    let first = Epoch::of(time(WALL)?).get();
    let walls: Vec<u64> = (first..first + 3)
        .map(|epoch| epoch * EPOCH_SECONDS)
        .collect();
    let tables = walls
        .iter()
        .map(|wall| alice.table(*wall))
        .collect::<AnyResult<Vec<_>>>()?;
    let records = contacts
        .iter()
        .map(|contact| {
            contact
                .table(WALL)?
                .advertisement(&alice.key())
                .ok_or_else(|| "no record".into())
        })
        .collect::<AnyResult<Vec<_>>>()?;
    let keys: Vec<Ed25519PublicKey> = contacts.iter().map(Device::key).collect();
    let empty = Device::new(0x60)?.table(WALL)?;
    alice
        .store
        .mark_ratchet_uncertain(keys.first().ok_or("contact")?)?;
    let reduced = alice.table(WALL)?;
    Ok(Fixture {
        contacts: keys,
        walls,
        tables,
        records,
        reduced,
        empty,
    })
}
