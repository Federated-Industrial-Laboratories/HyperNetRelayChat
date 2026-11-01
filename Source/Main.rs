//! HyperNet Relay Chat command-line interface.
#[path = "Presentation/Commands.rs"]
mod commands;
#[path = "Cli.rs"]
mod conversation;
#[path = "Presentation/Display.rs"]
mod display;
#[path = "Gui/Mod.rs"]
mod gui;
#[path = "Presentation/Interaction.rs"]
mod interaction;
#[path = "Tui/Mod.rs"]
mod tui;
use clap::{Args, Parser, Subcommand};
use hrc::hypernet::{Companion, Peer};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{io::Write, path::PathBuf, process::ExitCode, time::Duration};

const PROTOCOL: &str = "hrc-probe/1";
const REQUEST: &[u8; 8] = b"HRCreq01";
const RESPONSE: &[u8; 8] = b"HRCack01";
const ACTION: &[u8] = b"HRC transport diagnostic reply v1\0";

#[derive(Parser)]
#[command(version, about = "HyperNet Relay Chat")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Open the graphical conversation client.
    Gui(Interactive),
    /// Open the interactive terminal client.
    Tui(Interactive),
    /// Run a bounded deterministic room-help bot with a separately enrolled agent profile.
    Bot(Bot),
    /// Stop automatic retries of an exact pending operation while retaining its unknown outcome.
    Abandon(conversation::Abandon),
    /// Administer a home HRC service.
    Service {
        #[command(subcommand)]
        command: conversation::Service,
    },
    /// Create and authenticate an endpoint.
    Profile {
        #[command(subcommand)]
        command: conversation::Profile,
    },
    /// Join and manage conversations.
    Room {
        #[command(subcommand)]
        command: conversation::Room,
    },
    /// Inspect and manage endpoint encryption, contact trust and private-group epochs.
    Crypto {
        #[command(subcommand)]
        command: conversation::encryption_cli::Command,
    },
    Send(conversation::Send),
    History(conversation::History),
    Search(conversation::Search),
    /// Inspect and control explicit agent permissions.
    Agent {
        #[command(subcommand)]
        command: conversation::Agent,
    },
    Api(conversation::Api),
    /// Read or preserve a local draft without a network connection.
    Draft {
        #[command(subcommand)]
        command: conversation::Draft,
    },
    /// List uncertain operation identities without revealing message content.
    Outbox {
        #[arg(long)]
        profile: PathBuf,
    },
    /// Submit an exact previously prepared candidate after its required approval.
    Submit {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        candidate: PathBuf,
    },
    /// Resolve uncertain operations without assigning replacement message IDs.
    Resolve {
        #[arg(long)]
        profile: PathBuf,
    },
    /// Inspect and qualify an explicitly configured HyperNet companion.
    Transport {
        #[command(subcommand)]
        command: Transport,
    },
}

#[derive(Args)]
struct Interactive {
    /// Existing encrypted endpoint profile directory.
    #[arg(long)]
    profile: PathBuf,
    /// Open retained history and drafts without attempting a connection.
    #[arg(long)]
    offline: bool,
}

#[derive(Args)]
struct Bot {
    #[arg(long)]
    profile: PathBuf,
    /// Joined rooms; repeat for at most eight rooms.
    #[arg(long, required = true)]
    room: Vec<hrc::protocol::RoomId>,
    /// Exact bounded response to a new direct human !help message.
    #[arg(long)]
    help_text: String,
    #[arg(long, default_value_t=5000, value_parser=clap::value_parser!(u64).range(1000..=60000))]
    poll_interval_ms: u64,
    /// Explicit current autonomous delegation; otherwise participate independently.
    #[arg(long)]
    grant: Option<hrc::protocol::Id>,
    /// Replace a stale cursor and catch up without triggering historical messages.
    #[arg(long)]
    resynchronise: bool,
}
fn bot(options: Bot) -> Result<(), Failure> {
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let interrupt = signal_hook::flag::register(signal_hook::consts::SIGINT, stop.clone())
        .map_err(|_| Failure("SignalControlUnavailable"))?;
    let terminate = match signal_hook::flag::register(signal_hook::consts::SIGTERM, stop.clone()) {
        Ok(id) => id,
        Err(_) => {
            signal_hook::low_level::unregister(interrupt);
            return Err(Failure("SignalControlUnavailable"));
        }
    };
    let ready_stop = stop.clone();
    let result = hrc::bot::run_observed(
        hrc::bot::Config {
            profile: options.profile,
            rooms: options.room,
            help: options.help_text,
            poll_interval_ms: options.poll_interval_ms,
            grant: options.grant,
            resynchronise: options.resynchronise,
        },
        stop,
        move || {
            if output(&json!({"status":"BotReady","meaning":"InitialAuthorisedCatchUpComplete"}))
                .is_err()
            {
                ready_stop.store(true, std::sync::atomic::Ordering::Release);
            }
        },
    );
    signal_hook::low_level::unregister(interrupt);
    signal_hook::low_level::unregister(terminate);
    result.map_err(|error| {
        Failure(match error {
            hrc::bot::Error::Configuration => "InvalidBotConfiguration",
            hrc::bot::Error::AgentRequired => "BotAgentRequired",
            hrc::bot::Error::State => "BotStateUnavailable",
            hrc::bot::Error::Grant => "BotGrantUnavailable",
            hrc::bot::Error::ResynchronisationRequired => "BotResynchronisationRequired",
            hrc::bot::Error::PendingOutcome => "BotOutcomeUnknown",
            hrc::bot::Error::Denied => "BotPermissionDenied",
            hrc::bot::Error::Client(error) => error.code(),
            hrc::bot::Error::RetryLater { .. } => "BotTemporarilyUnavailable",
        })
    })?;
    output(&json!({"status":"BotStopped"}))
}

#[derive(Subcommand)]
enum Transport {
    /// Show bounded version-2 capability and directional privacy metadata.
    Status(Connection),
    /// Send one fixed diagnostic challenge through a configured HyperNet target.
    Probe {
        #[command(flatten)]
        connection: Connection,
        /// Exact registered diagnostic service identifier (64 lowercase hex digits).
        #[arg(long, value_parser = identifier)]
        service: String,
    },
    /// Accept one diagnostic challenge; check fresh authority before replying.
    ProbeServe {
        #[command(flatten)]
        connection: Connection,
        /// Only this authenticated principal may receive a diagnostic reply.
        #[arg(long, value_parser = identifier)]
        allow_principal: String,
    },
}

#[derive(Args)]
struct Connection {
    /// Absolute canonical private directory of a running Suite 0.10.0 companion.
    #[arg(long)]
    companion: PathBuf,
    /// Maximum preparation or payload wait, in milliseconds (100..60000).
    #[arg(long, default_value_t = 10000, value_parser = clap::value_parser!(u64).range(100..=60000))]
    timeout_ms: u64,
    /// Fresh authority wait, in milliseconds (100..5000).
    #[arg(long, default_value_t = 1000, value_parser = clap::value_parser!(u64).range(100..=5000))]
    authority_timeout_ms: u64,
}

fn identifier(value: &str) -> Result<String, String> {
    if value.len() == 64
        && value
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && value.bytes().any(|b| b != b'0')
    {
        Ok(value.to_owned())
    } else {
        Err("expected a nonzero 32-byte lowercase hexadecimal identifier".into())
    }
}

#[derive(Debug)]
struct Failure(&'static str);
impl From<hrc::hypernet::Error> for Failure {
    fn from(error: hrc::hypernet::Error) -> Self {
        Self(error.code())
    }
}

fn output(value: &Value) -> Result<(), Failure> {
    let mut stdout = std::io::stdout().lock();
    serde_json::to_writer(&mut stdout, value).map_err(|_| Failure("OutputFailed"))?;
    writeln!(stdout).map_err(|_| Failure("OutputFailed"))
}

fn run(command: Transport) -> Result<(), Failure> {
    let connection = match &command {
        Transport::Status(connection)
        | Transport::Probe { connection, .. }
        | Transport::ProbeServe { connection, .. } => connection,
    };
    let agent = Companion::new(&connection.companion)?;
    let timeout = Duration::from_millis(connection.timeout_ms);
    match &command {
        Transport::Status(_) => {
            let status = agent.status()?;
            output(&json!({"status":"Observed", "companion":status}))
        }
        Transport::Probe { service, .. } => {
            let mut frame = [0u8; 40];
            frame[..8].copy_from_slice(REQUEST);
            getrandom::fill(&mut frame[8..]).map_err(|_| Failure("RandomUnavailable"))?;
            let stream = agent.connect(service, PROTOCOL, timeout)?;
            if stream.peer().protocol() != PROTOCOL || stream.peer().service() != service {
                return Err(Failure("UnexpectedPeer"));
            }
            stream.send_all(&frame, timeout)?;
            stream.shutdown_write()?;
            let mut response = [0u8; 40];
            stream.recv_exact(&mut response, timeout)?;
            if &response[..8] != RESPONSE || response[8..] != frame[8..] {
                return Err(Failure("InvalidProbeResponse"));
            }
            // A diagnostic acknowledgement is never an HRC durable message receipt.
            output(&json!({"status":"ProbeAcknowledged", "protocol":PROTOCOL,
                "connection":stream.id(), "peer":stream.peer(), "privacy":stream.privacy(),
                "messageEncryption":"none", "chatCommitted":false}))
        }
        Transport::ProbeServe {
            allow_principal, ..
        } => {
            output(&json!({"status":"Waiting", "protocol":PROTOCOL}))?;
            let stream = agent.accept(timeout)?;
            let Peer::Incoming(peer) = stream.peer() else {
                return Err(Failure("UnexpectedPeer"));
            };
            if peer.principal() != allow_principal || stream.peer().protocol() != PROTOCOL {
                return Err(Failure("DiagnosticAdmissionDenied"));
            }
            if !stream.check_authority_supported() {
                return Err(Failure("AuthorityCheckUnsupported"));
            }
            output(&json!({"status":"Accepted", "connection":stream.id(), "peer":stream.peer()}))?;
            let mut frame = [0u8; 40];
            stream.recv_exact(&mut frame, timeout)?;
            if &frame[..8] != REQUEST || frame[8..].iter().all(|b| *b == 0) {
                return Err(Failure("InvalidProbeRequest"));
            }
            let mut hash = Sha256::new();
            hash.update(ACTION);
            hash.update(frame);
            let check = agent.check_authority(
                &stream,
                hash.finalize().into(),
                Duration::from_millis(connection.authority_timeout_ms),
            )?;
            if !check.permitted() {
                output(&json!({"status":"ProbeRefused", "check":check}))?;
                return Err(Failure("AuthorityNotPermitted"));
            }
            let mut response = frame;
            response[..8].copy_from_slice(RESPONSE);
            stream.send_observed(&check, &response)?;
            stream.shutdown_write()?;
            output(&json!({"status":"ProbeReplied", "connection":stream.id(),
                "peer":stream.peer(), "privacy":stream.privacy(), "check":check,
                "messageEncryption":"none", "chatCommitted":false}))
        }
    }
}

fn main() -> ExitCode {
    let result = match Cli::parse().command {
        Command::Gui(options) => gui::run(&options.profile, options.offline).map_err(Failure),
        Command::Tui(options) => tui::run(&options.profile, options.offline).map_err(Failure),
        Command::Bot(options) => bot(options),
        Command::Transport { command } => run(command),
        command => {
            let result = match command {
                Command::Service { command } => conversation::service(command),
                Command::Profile { command } => conversation::profile(command),
                Command::Room { command } => conversation::room(command),
                Command::Crypto { command } => conversation::encryption_cli::run(command),
                Command::Send(request) => conversation::send(request),
                Command::History(request) => conversation::history(request),
                Command::Search(request) => conversation::search(request),
                Command::Agent { command } => conversation::agent(command),
                Command::Api(request) => conversation::api(request),
                Command::Draft { command } => conversation::draft(command),
                Command::Outbox { profile } => conversation::outbox(&profile),
                Command::Submit { profile, candidate } => {
                    conversation::submit(&profile, &candidate)
                }
                Command::Resolve { profile } => conversation::resolve(&profile),
                Command::Abandon(request) => conversation::abandon(request),
                Command::Transport { .. } | Command::Gui(_) | Command::Tui(_) => unreachable!(),
                Command::Bot(_) => unreachable!(),
            };
            result.map_err(Failure).and_then(|v| output(&v))
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // No peer prose, paths, payload or operating-system diagnostics reach the terminal.
            let _ = writeln!(
                std::io::stderr().lock(),
                "{}",
                json!({"status":"Failed", "code":error.0})
            );
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
#[path = "../Tests/CommandLine.rs"]
mod tests;
