//! LAN throughput: raw TCP and an authenticated suite 0x0001 session over
//! the same kind of link (PROTOCOL §5 framing, transport encryption, and
//! rekey every GiB), for 1 GiB and 10 GiB by default.
//!
//! Modes (arguments after `--`):
//!
//! - default: both ends in this process, over loopback;
//! - `--listen <port>` on the receiving machine and
//!   `--connect <ip:port>` on the sending one: a real network. The
//!   receiver shows a QR pairing offer in-band, in the clear, over the
//!   first connection (benchmark only: these are throwaway identities),
//!   and the sender pairs with it; the pairing session then carries the
//!   data.
//! - `--bytes <n>[K|M|G]` (repeatable) replaces the default sizes.
//!
//! Only whole-session data frames are measured: no manifest, consent,
//! content encryption, or disk I/O (those are measured in
//! `benches/content.rs` or not yet). See `bench/RESULTS.md`.

#[cfg(not(target_family = "wasm"))]
mod lan {
    use core::time::Duration;
    use std::io;
    use std::net::{Ipv4Addr, SocketAddr};
    use std::time::Instant;

    use futures_io::{AsyncRead, AsyncWrite};
    use todoke_crypto::identity::{
        BindingRequest, ContactStore, ExportPolicy, KeyId, KeyRole, KeyStore, MemoryStorage,
        SoftwareKeyStore, SoftwareSealer, StorageKey, VerifiedDeviceBinding, issue_device_binding,
    };
    use todoke_crypto::pairing::{PairingOffers, QrPayload};
    use todoke_crypto::session::{
        Accepted, FrameType, IncomingSession, LocalIdentity, NoiseStaticKey, Session, Timer,
        UnauditedSuite0001,
    };
    use todoke_proto::session::MAX_BODY_LEN;
    use todoke_proto::time::UnixTime;
    use todoke_transport::{
        Candidate, Connector as _, LanListener, LanPolicy, LinkKind, TcpConnector, TcpLink,
        TokioTimer,
    };
    use zeroize::Zeroizing;

    type AnyResult<T> = Result<T, Box<dyn std::error::Error>>;
    type Keys = SoftwareKeyStore<MemoryStorage>;

    const GATE: UnauditedSuite0001 = UnauditedSuite0001::acknowledge_not_production_ready();
    const GIB: u64 = 1 << 30;
    /// Raw TCP writes are this large, like the session's largest frame.
    const RAW_WRITE: usize = 64 * 1024;

    /// The wall clock for bindings and sessions (the benchmark's own
    /// identities are valid for a day around it).
    fn wall() -> AnyResult<UnixTime> {
        let seconds = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_secs();
        Ok(UnixTime::new(seconds).ok_or("time")?)
    }

    fn sealer(byte: u8) -> SoftwareSealer {
        SoftwareSealer::new(StorageKey::from_bytes(Zeroizing::new([byte; 32])))
    }

    struct Device {
        keys: Keys,
        signing_key: KeyId,
        noise: NoiseStaticKey,
        binding: VerifiedDeviceBinding,
    }

    impl Device {
        fn new(kem_seed: u8) -> AnyResult<Self> {
            let mut keys = SoftwareKeyStore::open(sealer(1), MemoryStorage::new())?;
            let root = keys.generate(KeyRole::PersonRoot, ExportPolicy::NonExportable)?;
            let device = keys.generate(KeyRole::Device, ExportPolicy::NonExportable)?;
            let noise = NoiseStaticKey::generate()?;
            let pair = libcrux_ml_kem::mlkem768::generate_key_pair([kem_seed; 64]);
            let kem_static: [u8; 1184] = *pair.public_key().as_slice();
            let now = wall()?.seconds();
            let request = BindingRequest {
                noise_static: *noise.public_key(),
                kem_static: Box::new(kem_static),
                serial: core::num::NonZeroU64::new(1).ok_or("serial")?,
                not_before: UnixTime::new(now - 3600).ok_or("time")?,
                not_after: UnixTime::new(now + 86_400).ok_or("time")?,
            };
            let binding = issue_device_binding(&keys, &root, &device, request)?;
            Ok(Self {
                keys,
                signing_key: device,
                noise,
                binding,
            })
        }

        fn local(&self) -> AnyResult<LocalIdentity<'_, Keys>> {
            Ok(LocalIdentity::new(
                &self.keys,
                self.signing_key,
                &self.binding,
                &self.noise,
                wall()?,
            )?)
        }
    }

    async fn write_all(link: &mut TcpLink, mut data: &[u8]) -> io::Result<()> {
        while !data.is_empty() {
            let written =
                core::future::poll_fn(|cx| core::pin::Pin::new(&mut *link).poll_write(cx, data))
                    .await?;
            data = &data[written..];
        }
        Ok(())
    }

    async fn read_some(link: &mut TcpLink, buf: &mut [u8]) -> io::Result<usize> {
        core::future::poll_fn(|cx| core::pin::Pin::new(&mut *link).poll_read(cx, buf)).await
    }

    async fn read_exact(link: &mut TcpLink, out: &mut [u8]) -> io::Result<()> {
        let mut filled = 0;
        while filled < out.len() {
            let read = read_some(link, &mut out[filled..]).await?;
            if read == 0 {
                return Err(io::ErrorKind::UnexpectedEof.into());
            }
            filled += read;
        }
        Ok(())
    }

    async fn raw_send(link: &mut TcpLink, total: u64) -> AnyResult<()> {
        let block = vec![0x5a; RAW_WRITE];
        let mut left = total;
        while left > 0 {
            let len = usize::try_from(left.min(RAW_WRITE as u64))?;
            write_all(link, &block[..len]).await?;
            left -= len as u64;
        }
        core::future::poll_fn(|cx| core::pin::Pin::new(&mut *link).poll_flush(cx)).await?;
        Ok(())
    }

    async fn raw_receive(link: &mut TcpLink, total: u64) -> AnyResult<()> {
        let mut buf = vec![0; RAW_WRITE * 4];
        let mut got = 0_u64;
        while got < total {
            let read = read_some(link, &mut buf).await?;
            if read == 0 {
                return Err("the sender closed early".into());
            }
            got += read as u64;
        }
        // One byte back, so the sender's clock stops when all arrived.
        write_all(link, &[1]).await?;
        Ok(())
    }

    /// The receiver acknowledges every this many bytes...
    const ACK_EVERY: u64 = 4 << 20;
    /// ...and the sender waits for an acknowledgement once it is this far
    /// ahead, as the transfer engine's pipelined chunk requests would make
    /// it. Both ends then read and write throughout, so keepalives (§13)
    /// work at any speed.
    const WINDOW: u64 = 16 << 20;

    async fn session_send<IO: AsyncRead + AsyncWrite + Unpin, T: Timer>(
        session: &mut Session<IO, T>,
        total: u64,
    ) -> AnyResult<()> {
        let body = vec![0x5a; MAX_BODY_LEN];
        let (mut sent, mut acked) = (0_u64, 0_u64);
        while sent < total {
            while sent - acked >= WINDOW {
                acked = acknowledged(&session.recv().await?)?;
            }
            let len = usize::try_from((total - sent).min(MAX_BODY_LEN as u64))?;
            session.send(FrameType::CHUNK, &body[..len]).await?;
            sent += len as u64;
        }
        while acked < total {
            acked = acknowledged(&session.recv().await?)?;
        }
        Ok(())
    }

    fn acknowledged(frame: &todoke_crypto::session::Frame) -> AnyResult<u64> {
        let bytes: [u8; 8] = frame.body().try_into()?;
        if frame.frame_type() != FrameType::CHUNK_REQUEST {
            return Err("unexpected frame".into());
        }
        Ok(u64::from_be_bytes(bytes))
    }

    async fn session_receive<IO: AsyncRead + AsyncWrite + Unpin, T: Timer>(
        session: &mut Session<IO, T>,
        total: u64,
    ) -> AnyResult<()> {
        let (mut got, mut acked) = (0_u64, 0_u64);
        while got < total {
            let frame = session.recv().await?;
            got += frame.body().len() as u64;
            if got - acked >= ACK_EVERY || got >= total {
                session
                    .send(FrameType::CHUNK_REQUEST, &got.to_be_bytes())
                    .await?;
                acked = got;
            }
        }
        Ok(())
    }

    #[expect(clippy::cast_precision_loss, reason = "throughput figures")]
    fn report(what: &str, bytes: u64, elapsed: Duration) {
        let seconds = elapsed.as_secs_f64();
        let mib_per_second = bytes as f64 / (1024.0 * 1024.0) / seconds;
        let gbit_per_second = bytes as f64 * 8.0 / 1e9 / seconds;
        let gib = bytes as f64 / GIB as f64;
        println!(
            "{what:<10} {gib:>6.2} GiB  {seconds:>8.3} s  {mib_per_second:>9.1} MiB/s  {gbit_per_second:>6.2} Gbit/s"
        );
    }

    struct Args {
        listen: Option<u16>,
        connect: Option<SocketAddr>,
        sizes: Vec<u64>,
    }

    fn parse_size(text: &str) -> AnyResult<u64> {
        let (number, unit) = text.split_at(text.trim_end_matches(['K', 'M', 'G']).len());
        let number: u64 = number.parse()?;
        let factor = match unit {
            "" => 1,
            "K" => 1 << 10,
            "M" => 1 << 20,
            "G" => GIB,
            _ => return Err("size unit must be K, M, or G".into()),
        };
        Ok(number.checked_mul(factor).ok_or("size too large")?)
    }

    fn args() -> AnyResult<Args> {
        let mut parsed = Args {
            listen: None,
            connect: None,
            sizes: Vec::new(),
        };
        let mut args = std::env::args().skip(1);
        while let Some(arg) = args.next() {
            match arg.as_str() {
                "--listen" => parsed.listen = Some(args.next().ok_or("--listen PORT")?.parse()?),
                "--connect" => {
                    parsed.connect = Some(args.next().ok_or("--connect IP:PORT")?.parse()?);
                }
                "--bytes" => parsed
                    .sizes
                    .push(parse_size(&args.next().ok_or("--bytes N")?)?),
                // cargo bench passes `--bench`; anything else is ignored too.
                _ => {}
            }
        }
        if parsed.sizes.is_empty() {
            parsed.sizes = if std::env::args().any(|arg| arg == "--bench") {
                vec![GIB, 10 * GIB]
            } else {
                // `cargo test --benches` (CI): one quick run in a debug build.
                vec![1 << 20]
            };
        }
        Ok(parsed)
    }

    /// The receiving side: two connections, raw then session.
    async fn receiver(listener: LanListener, sizes: &[u64]) -> AnyResult<()> {
        let mut raw = listener.accept().await?;
        for &size in sizes {
            raw_receive(&mut raw, size).await?;
        }
        let mut link = listener.accept().await?;
        let bob = Device::new(0x42)?;
        let offers = PairingOffers::new();
        let timer = TokioTimer::new();
        let text = offers
            .create_qr(&bob.local()?, wall()?, timer.now())?
            .to_text();
        let length = u16::try_from(text.len())?.to_be_bytes();
        write_all(&mut link, &length).await?;
        write_all(&mut link, text.as_bytes()).await?;
        let Accepted::Hello(mut incoming) =
            IncomingSession::accept_any(link, timer, GATE, &offers).await?
        else {
            return Err("expected a ClientHello".into());
        };
        let mut store = ContactStore::open(sealer(8), MemoryStorage::new())?;
        let reservation = incoming.reserve_offer(&offers, wall()?)?;
        let (plan, mut authority) = reservation.into_qr_responder(&mut store)?;
        let mut session = incoming
            .respond(&bob.local()?, wall()?, plan, &mut authority)
            .await?;
        for &size in sizes {
            session_receive(&mut session, size).await?;
        }
        Ok(())
    }

    /// The sending side: measures both phases.
    async fn sender(connector: TcpConnector, target: SocketAddr, sizes: &[u64]) -> AnyResult<()> {
        let candidate = Candidate::new(LinkKind::Lan, target);
        let mut raw = connector.connect(candidate).await?;
        for &size in sizes {
            let started = Instant::now();
            raw_send(&mut raw, size).await?;
            let mut done = [0];
            read_exact(&mut raw, &mut done).await?;
            report("tcp", size, started.elapsed());
        }
        let mut link = connector.connect(candidate).await?;
        let mut length = [0; 2];
        read_exact(&mut link, &mut length).await?;
        let mut text = vec![0; usize::from(u16::from_be_bytes(length))];
        read_exact(&mut link, &mut text).await?;
        let payload = QrPayload::from_text(core::str::from_utf8(&text)?, wall()?)?;
        let alice = Device::new(0x41)?;
        let mut store = ContactStore::open(sealer(9), MemoryStorage::new())?;
        let (plan, mut authority) = store.begin_qr_pairing(&payload, wall()?)?;
        let local = alice.local()?;
        let mut session = Box::pin(Session::initiate(
            link,
            TokioTimer::new(),
            GATE,
            &local,
            wall()?,
            plan,
            &mut authority,
        ))
        .await?;
        for &size in sizes {
            let started = Instant::now();
            session_send(&mut session, size).await?;
            report("session", size, started.elapsed());
        }
        Ok(())
    }

    fn runtime() -> io::Result<tokio::runtime::Runtime> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
    }

    pub fn main() -> AnyResult<()> {
        let args = args()?;
        match (args.listen, args.connect) {
            (Some(port), None) => runtime()?.block_on(async {
                let listener = LanListener::bind(port, LanPolicy::new())?;
                println!("listening on port {}", listener.port()?);
                receiver(listener, &args.sizes).await
            }),
            (None, Some(target)) => runtime()?.block_on(sender(
                TcpConnector::new(LanPolicy::new()),
                target,
                &args.sizes,
            )),
            (None, None) => {
                // Each end on its own thread, as on two machines.
                let policy = LanPolicy::new().with_loopback();
                let (ready, port) = std::sync::mpsc::channel();
                let sizes = args.sizes.clone();
                let receiving = std::thread::spawn(move || {
                    runtime()
                        .map_err(|error| error.to_string())?
                        .block_on(async {
                            let listener = LanListener::bind(0, policy)?;
                            ready.send(listener.port()?)?;
                            receiver(listener, &sizes).await
                        })
                        .map_err(|error| error.to_string())
                });
                let target = SocketAddr::from((Ipv4Addr::LOCALHOST, port.recv()?));
                runtime()?.block_on(sender(TcpConnector::new(policy), target, &args.sizes))?;
                receiving
                    .join()
                    .map_err(|_| "the receiver panicked")?
                    .map_err(Box::<dyn std::error::Error>::from)
            }
            (Some(_), Some(_)) => Err("use --listen or --connect, not both".into()),
        }
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    #[cfg(not(target_family = "wasm"))]
    lan::main()?;
    Ok(())
}
