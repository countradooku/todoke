//! `todoke-relay`: runs one relay node (PROTOCOL §10).
//!
//! With `--cert` and `--key` it serves that certificate (clients validate
//! it with the platform's roots). Without them it serves a self-signed
//! certificate kept in `--state` and prints its key pin, which clients
//! configure. It prints its address and pin at start and nothing else.

#![forbid(unsafe_code)]

#[cfg(not(target_family = "wasm"))]
mod app {
    use std::net::SocketAddr;
    use std::path::{Path, PathBuf};
    use std::process::ExitCode;
    use std::sync::Arc;
    use std::time::Duration;

    use clap::Parser;
    use todoke_relay::{Config, Identity, Relay, format_pin, serve_metrics};

    /// Run a todoke relay node.
    #[derive(Parser)]
    #[command(name = "todoke-relay", version, about)]
    struct Args {
        /// The UDP address to listen on.
        #[arg(long, default_value = "[::]:4433")]
        listen: SocketAddr,
        /// A PEM certificate chain, leaf first (with --key).
        #[arg(long, requires = "key")]
        cert: Option<PathBuf>,
        /// The PEM private key of --cert.
        #[arg(long, requires = "cert")]
        key: Option<PathBuf>,
        /// Where a self-signed certificate is kept when no --cert is given.
        #[arg(long, default_value = "relay-state")]
        state: PathBuf,
        /// Names for a self-signed certificate.
        #[arg(long = "name", default_value = "localhost")]
        names: Vec<String>,
        /// Serve /metrics and /healthz on this TCP address (off by default;
        /// totals only).
        #[arg(long)]
        metrics: Option<SocketAddr>,
        /// Connections at once.
        #[arg(long, default_value_t = 20_000)]
        max_connections: usize,
        /// Connections at once from one IPv4 address or IPv6 /64.
        #[arg(long, default_value_t = 64)]
        max_connections_per_source: usize,
        /// Rooms open at once.
        #[arg(long, default_value_t = 50_000)]
        max_rooms: usize,
        /// New connections a second from one source.
        #[arg(long, default_value_t = 20)]
        connections_per_source_per_second: u32,
        /// Registers a second from one source.
        #[arg(long, default_value_t = 10)]
        registers_per_source_per_second: u32,
        /// Bytes each tunnel direction may carry (at most 16 TiB).
        #[arg(long)]
        tunnel_bytes: Option<u64>,
        /// Seconds a tunnel may last (at most 86400).
        #[arg(long)]
        tunnel_seconds: Option<u64>,
    }

    pub(crate) fn main() -> ExitCode {
        let args = Args::parse();
        match run(&args) {
            Ok(()) => ExitCode::SUCCESS,
            Err(error) => {
                eprintln!("todoke-relay: {error}");
                ExitCode::FAILURE
            }
        }
    }

    fn run(args: &Args) -> std::io::Result<()> {
        let identity = match (&args.cert, &args.key) {
            (Some(cert), Some(key)) => {
                Identity::from_pem(&std::fs::read(cert)?, &std::fs::read(key)?)?
            }
            _ => self_signed(&args.state, &args.names)?,
        };
        let mut config = Config::new(args.listen);
        config.max_connections = args.max_connections;
        config.max_connections_per_source = args.max_connections_per_source;
        config.max_rooms = args.max_rooms;
        config.connections_per_source_per_second = args.connections_per_source_per_second;
        config.registers_per_source_per_second = args.registers_per_source_per_second;
        if let Some(bytes) = args.tunnel_bytes {
            config.tunnel_bytes = config.tunnel_bytes.min(bytes);
        }
        if let Some(seconds) = args.tunnel_seconds {
            config.tunnel_lifetime = config.tunnel_lifetime.min(Duration::from_secs(seconds));
        }
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;
        runtime.block_on(async {
            let relay = Relay::bind(config, &identity)?;
            println!("listening on {}", relay.local_addr()?);
            println!("pin {}", format_pin(&identity.pin()?));
            let stop = Arc::new(tokio::sync::Notify::new());
            if let Some(address) = args.metrics {
                let (metrics, stop) = (relay.metrics(), Arc::clone(&stop));
                tokio::spawn(serve_metrics(address, metrics, stop));
            }
            let signals = {
                let stop = Arc::clone(&stop);
                async move {
                    shutdown_signal().await;
                    stop.notify_waiters();
                }
            };
            tokio::select! {
                () = relay.run(Arc::clone(&stop)) => {}
                () = signals => {}
            }
            Ok(())
        })
    }

    /// Ctrl-C, or SIGTERM from a container runtime or service manager.
    async fn shutdown_signal() {
        #[cfg(unix)]
        if let Ok(mut terminate) =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        {
            tokio::select! {
                _ = tokio::signal::ctrl_c() => {}
                _ = terminate.recv() => {}
            }
            return;
        }
        let _ = tokio::signal::ctrl_c().await;
    }

    /// The self-signed certificate in `state`, made on first use (its key
    /// readable by this user only).
    fn self_signed(state: &Path, names: &[String]) -> std::io::Result<Identity> {
        let (cert, key) = (state.join("cert.pem"), state.join("key.pem"));
        if let (Ok(cert), Ok(key)) = (std::fs::read(&cert), std::fs::read(&key)) {
            return Identity::from_pem(&cert, &key);
        }
        // A missing half (a crash between the two writes) means a new pair:
        // each file is written whole under a temporary name, then renamed.
        std::fs::create_dir_all(state)?;
        let (identity, cert_pem, key_pem) = Identity::self_signed(names.to_vec())?;
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        std::os::unix::fs::OpenOptionsExt::mode(&mut options, 0o600);
        let key_partial = state.join("key.pem.partial");
        let mut file = options.open(&key_partial)?;
        std::io::Write::write_all(&mut file, key_pem.as_bytes())?;
        file.sync_all()?;
        std::fs::rename(&key_partial, &key)?;
        let cert_partial = state.join("cert.pem.partial");
        std::fs::write(&cert_partial, cert_pem)?;
        std::fs::rename(&cert_partial, &cert)?;
        Ok(identity)
    }
}

#[cfg(not(target_family = "wasm"))]
fn main() -> std::process::ExitCode {
    app::main()
}

#[cfg(target_family = "wasm")]
fn main() {}
