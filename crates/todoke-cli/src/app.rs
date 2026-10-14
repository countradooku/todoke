//! The command line (not built for wasm32, which has no terminal).

use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{CommandFactory as _, Parser, Subcommand, ValueEnum};
use todoke_cli::{bytes, contacts, entries, escape, event, qr, short, status, transfers};
use todoke_core::api::{ErrorCode, Event, OfferInfo, Request, Response};
use todoke_daemon::Paths;
use todoke_daemon::ipc::Client;
use todoke_daemon::service::{self, Kind};

/// Send files between your devices, end-to-end encrypted.
#[derive(Parser)]
#[command(name = "todoke", version, about)]
struct Cli {
    /// Machine-readable output: one JSON value (or one per line for streams).
    #[arg(long, global = true)]
    json: bool,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// What the daemon is doing.
    Status,
    /// Paired devices.
    Contacts,
    /// Transfers in progress or awaiting a decision.
    Transfers,
    /// Pair with another device.
    #[command(subcommand)]
    Pair(Pair),
    /// Nearby devices waiting to pair by code.
    Strangers,
    /// Offer files and folders to a contact.
    Send {
        /// The contact (at least 8 hex digits of its device key).
        contact: String,
        /// Files and folders to send.
        #[arg(required = true)]
        paths: Vec<PathBuf>,
        /// Wait until the receiver confirms delivery.
        #[arg(long)]
        wait: bool,
    },
    /// Wait for offers and decide on each (Ctrl-C to stop).
    Receive {
        /// Accept every offer without asking.
        #[arg(long)]
        yes: bool,
    },
    /// Accept an offer.
    Accept {
        /// The transfer (at least 8 hex digits).
        transfer: String,
        /// Only these file IDs (comma-separated); all files by default.
        #[arg(long, value_delimiter = ',')]
        files: Option<Vec<u32>>,
    },
    /// Decline an offer.
    Decline {
        /// The transfer.
        transfer: String,
    },
    /// Cancel a transfer.
    Cancel {
        /// The transfer.
        transfer: String,
    },
    /// Print events as they happen (for notifiers: `--json`).
    Events,
    /// Run or install the background daemon.
    #[command(subcommand)]
    Daemon(Daemon),
    /// Shell completions.
    Completions {
        /// The shell.
        shell: clap_complete::Shell,
    },
}

#[derive(Subcommand)]
enum Pair {
    /// Show a pairing offer for another device to use (this device answers).
    Show {
        /// A ten-digit code instead of a QR code.
        #[arg(long)]
        code: bool,
    },
    /// Use a QR offer's text (from the other device's screen; `-` or nothing
    /// reads it from standard input).
    Scan {
        /// The text, starting `TODOKE:`.
        text: Option<String>,
    },
    /// Enter the code another device shows.
    Code {
        /// The ten digits.
        code: String,
        /// Which nearby device (from `todoke strangers`); needed only if
        /// several are waiting.
        #[arg(long)]
        stranger: Option<String>,
    },
    /// Stop showing a pairing offer.
    Stop,
}

#[derive(Subcommand)]
enum Daemon {
    /// Run the daemon in this terminal.
    Run,
    /// Stop the running daemon.
    Stop,
    /// Print a service definition that starts the daemon at login.
    Service {
        /// The service manager.
        kind: ServiceKind,
    },
}

#[derive(Clone, Copy, ValueEnum)]
enum ServiceKind {
    Systemd,
    Launchd,
    Windows,
}

/// A failure to report and its exit code.
struct Failure {
    message: String,
    code: u8,
}

impl Failure {
    fn new(message: impl Into<String>, code: u8) -> Self {
        Self {
            message: message.into(),
            code,
        }
    }
}

impl From<std::io::Error> for Failure {
    fn from(error: std::io::Error) -> Self {
        match error.kind() {
            std::io::ErrorKind::NotFound | std::io::ErrorKind::ConnectionRefused => Self::new(
                "the daemon is not running: start it with `todoke daemon run`",
                3,
            ),
            std::io::ErrorKind::PermissionDenied => {
                Self::new("the daemon refused this client (another user's daemon?)", 3)
            }
            _ => Self::new(format!("talking to the daemon failed: {error}"), 3),
        }
    }
}

pub(crate) fn main() -> ExitCode {
    let cli = Cli::parse();
    let result = match cli.command {
        Command::Completions { shell } => {
            clap_complete::generate(shell, &mut Cli::command(), "todoke", &mut std::io::stdout());
            Ok(())
        }
        Command::Daemon(Daemon::Run) => {
            Paths::discover().map_err(Failure::from).and_then(|paths| {
                todoke_daemon::run(&paths).map_err(|error| Failure::new(error.to_string(), 1))
            })
        }
        Command::Daemon(Daemon::Service { kind }) => {
            let kind = match kind {
                ServiceKind::Systemd => Kind::Systemd,
                ServiceKind::Launchd => Kind::Launchd,
                ServiceKind::Windows => Kind::WindowsTask,
            };
            std::env::current_exe()
                .map_err(|error| Failure::new(error.to_string(), 1))
                .map(|exe| {
                    eprintln!("# install as {}", kind.location());
                    print!("{}", service::definition(kind, &exe));
                })
        }
        command => match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime.block_on(client(cli.json, command)),
            Err(error) => Err(Failure::new(error.to_string(), 1)),
        },
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(failure) => {
            eprintln!("todoke: {}", failure.message);
            ExitCode::from(failure.code)
        }
    }
}

async fn connect() -> Result<Client, Failure> {
    let paths = Paths::discover()?;
    Ok(Client::connect(&paths.endpoint()).await?)
}

/// Prints a response, or turns an error response into a failure.
fn show(
    json: bool,
    response: &Response,
    human: impl FnOnce(&Response) -> Option<String>,
) -> Result<(), Failure> {
    if let Response::Error { code, message } = response {
        let exit = match code {
            ErrorCode::Invalid | ErrorCode::Ambiguous => 2,
            ErrorCode::Disabled => 4,
            _ => 1,
        };
        if json {
            println!("{}", serde_json::to_string(response).unwrap_or_default());
        }
        return Err(Failure::new(escape(message), exit));
    }
    if json {
        println!("{}", serde_json::to_string(response).unwrap_or_default());
    } else if let Some(text) = human(response) {
        print!("{text}");
    }
    Ok(())
}

async fn client(json: bool, command: Command) -> Result<(), Failure> {
    let mut daemon = connect().await?;
    match command {
        Command::Status => show(json, &daemon.request(Request::Status).await?, |r| match r {
            Response::Status(info) => Some(status(info)),
            _ => None,
        }),
        Command::Contacts => show(
            json,
            &daemon.request(Request::Contacts).await?,
            |r| match r {
                Response::Contacts(list) => Some(contacts(list)),
                _ => None,
            },
        ),
        Command::Transfers => show(
            json,
            &daemon.request(Request::Transfers).await?,
            |r| match r {
                Response::Transfers(list) => Some(transfers(list)),
                _ => None,
            },
        ),
        Command::Strangers => show(
            json,
            &daemon.request(Request::Strangers).await?,
            |r| match r {
                Response::Strangers(list) if list.is_empty() => Some(
                    "no device nearby is waiting to pair (try again in a few seconds)\n".to_owned(),
                ),
                Response::Strangers(list) => {
                    Some(list.iter().fold(String::new(), |mut out, stranger| {
                        out.push_str(&stranger.stranger);
                        out.push('\n');
                        out
                    }))
                }
                _ => None,
            },
        ),
        Command::Pair(pair) => pairing(json, daemon, pair).await,
        Command::Send {
            contact,
            paths,
            wait,
        } => send(json, &mut daemon, contact, paths, wait).await,
        Command::Receive { yes } => receive(json, yes).await,
        Command::Accept { transfer, files } => show(
            json,
            &daemon.request(Request::Accept { transfer, files }).await?,
            |_| Some("accepted\n".to_owned()),
        ),
        Command::Decline { transfer } => show(
            json,
            &daemon.request(Request::Decline { transfer }).await?,
            |_| Some("declined\n".to_owned()),
        ),
        Command::Cancel { transfer } => show(
            json,
            &daemon.request(Request::Cancel { transfer }).await?,
            |_| Some("cancelled\n".to_owned()),
        ),
        Command::Events => {
            let mut events = daemon.subscribe().await?;
            while let Some(next) = events.next().await? {
                print_event(json, &next);
            }
            Ok(())
        }
        Command::Daemon(Daemon::Stop) => {
            daemon.shutdown().await?;
            Ok(())
        }
        Command::Daemon(Daemon::Run | Daemon::Service { .. }) | Command::Completions { .. } => {
            Ok(())
        }
    }
}

async fn send(
    json: bool,
    daemon: &mut Client,
    contact: String,
    paths: Vec<PathBuf>,
    wait: bool,
) -> Result<(), Failure> {
    let paths = paths
        .into_iter()
        .map(|path| std::path::absolute(&path).unwrap_or(path))
        .collect();
    // Subscribed before sending, so no event of it is missed.
    let events = if wait {
        Some(connect().await?.subscribe().await?)
    } else {
        None
    };
    let response = daemon.request(Request::Send { contact, paths }).await?;
    let transfer = match &response {
        Response::Offered { transfer } => Some(transfer.clone()),
        _ => None,
    };
    show(json, &response, |r| match r {
        Response::Offered { transfer } => Some(format!(
            "offered as {}; it is sent when the contact accepts\n",
            short(transfer)
        )),
        _ => None,
    })?;
    match (events, transfer) {
        (Some(events), Some(transfer)) => wait_for_delivery(json, events, &transfer).await,
        _ => Ok(()),
    }
}

fn print_event(json: bool, next: &Event) {
    if json {
        println!("{}", serde_json::to_string(next).unwrap_or_default());
    } else {
        println!("{}", event(next));
    }
    let _ = std::io::stdout().flush();
}

async fn pairing(json: bool, mut daemon: Client, pair: Pair) -> Result<(), Failure> {
    match pair {
        Pair::Show { code } => {
            let request = if code {
                Request::PairShowCode
            } else {
                Request::PairShowQr
            };
            let events = connect().await?.subscribe().await?;
            let response = daemon.request(request).await?;
            show(json, &response, |r| match r {
                Response::Qr { text, .. } => {
                    let drawn = qr(text).unwrap_or_default();
                    Some(format!(
                        "{drawn}\nOn the other device run `todoke pair scan` and paste:\n\n{text}\n\nKeep this private until it is used; it expires in 5 minutes. Waiting...\n"
                    ))
                }
                Response::Code { code, .. } => Some(format!(
                    "Code: {} {}\nOn the other device run `todoke pair code {code}`.\nIt expires in 5 minutes. Waiting...\n",
                    &code[..5.min(code.len())],
                    code.get(5..).unwrap_or_default()
                )),
                _ => None,
            })?;
            let _ = std::io::stdout().flush();
            wait_for_pairing(json, events).await
        }
        Pair::Scan { text } => {
            let text = if let Some(text) = text.filter(|text| text != "-") {
                zeroize::Zeroizing::new(text)
            } else {
                let mut line = zeroize::Zeroizing::new(String::new());
                std::io::stdin()
                    .read_line(&mut line)
                    .map_err(|error| Failure::new(error.to_string(), 2))?;
                line
            };
            let request = Request::PairScanQr {
                text: text.trim().to_owned(),
            };
            show(json, &daemon.request(request).await?, paired)
        }
        Pair::Code { code, stranger } => {
            let stranger = match stranger {
                Some(stranger) => stranger,
                None => only_stranger(&mut daemon).await?,
            };
            let request = Request::PairEnterCode {
                code: code.chars().filter(char::is_ascii_digit).collect(),
                stranger,
            };
            show(json, &daemon.request(request).await?, paired)
        }
        Pair::Stop => show(json, &daemon.request(Request::StopPairing).await?, |_| None),
    }
}

fn paired(response: &Response) -> Option<String> {
    match response {
        Response::Paired { contact } => Some(format!("paired with {}\n", short(contact))),
        _ => None,
    }
}

/// The one nearby stranger, waiting up to 15 seconds for one to appear.
async fn only_stranger(daemon: &mut Client) -> Result<String, Failure> {
    for _ in 0..30 {
        if let Response::Strangers(list) = daemon.request(Request::Strangers).await? {
            match list.as_slice() {
                [one] => return Ok(one.stranger.clone()),
                [] => {}
                _ => {
                    return Err(Failure::new(
                        "several devices are waiting to pair: choose one with --stranger (see `todoke strangers`)",
                        2,
                    ));
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    Err(Failure::new("no device nearby is waiting to pair", 1))
}

async fn wait_for_pairing(
    json: bool,
    mut events: todoke_daemon::ipc::Events,
) -> Result<(), Failure> {
    let wait = tokio::time::timeout(std::time::Duration::from_secs(300), async {
        while let Some(next) = events.next().await? {
            if let Event::Paired { .. } = next {
                print_event(json, &next);
                return Ok(());
            }
        }
        Err(Failure::new("the daemon stopped", 1))
    });
    match wait.await {
        Ok(result) => result,
        Err(_) => Err(Failure::new("the offer expired unused", 1)),
    }
}

async fn wait_for_delivery(
    json: bool,
    mut events: todoke_daemon::ipc::Events,
    transfer: &str,
) -> Result<(), Failure> {
    while let Some(next) = events.next().await? {
        match &next {
            Event::Delivered { transfer: done } if done == transfer => {
                print_event(json, &next);
                return Ok(());
            }
            Event::Ended {
                transfer: ended,
                reason,
                ..
            } if ended == transfer && reason.is_finished() => {
                print_event(json, &next);
                return Err(Failure::new("the transfer did not complete", 1));
            }
            Event::Progress {
                transfer: moving, ..
            }
            | Event::Ended {
                transfer: moving, ..
            } if moving == transfer => {
                print_event(json, &next);
            }
            _ => {}
        }
    }
    Err(Failure::new("the daemon stopped", 1))
}

async fn receive(json: bool, yes: bool) -> Result<(), Failure> {
    // Subscribe, then list what already waits: no offer falls between.
    let mut events = connect().await?.subscribe().await?;
    let response = connect().await?.request(Request::Offers).await?;
    let Response::Offers(waiting) = response else {
        return show(json, &response, |_| None);
    };
    if !json {
        println!("waiting for offers (Ctrl-C to stop)");
    }
    // Listed offers whose event may still be on its way.
    let mut listed: Vec<String> = Vec::new();
    for offer in waiting {
        print_event(json, &Event::OfferReceived(offer.clone()));
        decide(json, yes, &offer).await?;
        listed.push(offer.transfer);
    }
    while let Some(next) = events.next().await? {
        match &next {
            Event::OfferReceived(offer) => {
                if let Some(at) = listed.iter().position(|id| *id == offer.transfer) {
                    listed.swap_remove(at);
                    continue;
                }
                print_event(json, &next);
                decide(json, yes, offer).await?;
            }
            Event::Ended { transfer, .. } => {
                // A later offer of it is a new decision (§7.5).
                listed.retain(|id| id != transfer);
                print_event(json, &next);
            }
            _ => print_event(json, &next),
        }
    }
    Ok(())
}

/// Shows an offer's entries and accepts or declines it.
async fn decide(json: bool, yes: bool, offer: &OfferInfo) -> Result<(), Failure> {
    if !json {
        print!("{}", entries(&offer.entries));
    }
    let accept = yes
        || ask(&format!(
            "accept {} ({})? [y/N] ",
            short(&offer.transfer),
            bytes(offer.total_bytes)
        ))
        .await;
    let request = if accept {
        Request::Accept {
            transfer: offer.transfer.clone(),
            files: None,
        }
    } else {
        Request::Decline {
            transfer: offer.transfer.clone(),
        }
    };
    let response = connect().await?.request(request).await?;
    show(json, &response, |_| {
        Some(if accept { "accepted\n" } else { "declined\n" }.to_owned())
    })
}

/// Asks a yes/no question on the terminal; anything but y or yes is no.
async fn ask(question: &str) -> bool {
    print!("{question}");
    let _ = std::io::stdout().flush();
    let answer = tokio::task::spawn_blocking(|| {
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).map(|_| line)
    })
    .await;
    matches!(
        answer
            .ok()
            .and_then(Result::ok)
            .map(|line| line.trim().to_ascii_lowercase())
            .as_deref(),
        Some("y" | "yes")
    )
}
