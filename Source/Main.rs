//! HyperNet Relay Chat command-line interface.
#[path = "Assistant/Mod.rs"]
mod assistant;
#[path = "Presentation/Commands.rs"]
mod commands;
#[path = "Cli.rs"]
mod conversation;
#[path = "Desktop/Mod.rs"]
mod desktop;
#[path = "Presentation/Display.rs"]
mod display;
#[path = "Gui/Mod.rs"]
mod gui;
#[path = "IntegrationCli.rs"]
mod integration_cli;
#[path = "Presentation/Interaction.rs"]
mod interaction;
#[path = "Onboarding/Mod.rs"]
mod onboarding;
#[path = "Operations/Mod.rs"]
mod operations;
#[path = "SelfService/Mod.rs"]
mod self_service;
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
    command: Option<Command>,
}

#[derive(Subcommand)]
enum Command {
    /// Connect external agents through the scoped local participant API.
    Integration {
        #[command(subcommand)]
        command: integration_cli::Command,
    },
    /// Explicitly enable and administer optional self-service invitations.
    Admission {
        #[command(subcommand)]
        command: self_service::commands::Command,
    },
    /// Desktop setup and operator actions with structured results.
    Manage {
        #[command(subcommand)]
        command: operations::Command,
    },
    /// Export optional skills and roles for an external LLM assistant.
    Assistant {
        #[command(subcommand)]
        command: assistant::Command,
    },
    /// Open the graphical conversation client.
    Gui(desktop::Options),
    /// Install the desktop launcher for the current user.
    Install,
    /// Assemble an operator invitation for the graphical setup wizard.
    SetupBundle(desktop::BundleOptions),
    /// Open the interactive terminal client.
    Tui(Interactive),
    /// Run a room bot with an agent profile and optional local model and memory.
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
    /// Configure explicit bilateral agreements and independently admitted gateways.
    Federation {
        #[command(subcommand)]
        command: conversation::federation_cli::Command,
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
    /// Local inference server address; only loopback IP addresses are accepted.
    #[arg(long, requires = "model")]
    model_endpoint: Option<std::net::SocketAddr>,
    /// Model name configured in the local server.
    #[arg(long, requires = "model_endpoint")]
    model: Option<String>,
    /// Absolute path of the locally installed curl executable.
    #[arg(long, default_value = "/usr/bin/curl")]
    model_curl: PathBuf,
    /// Prefix that addresses the local model; !help retains its fixed response.
    #[arg(long, default_value = "!qwen")]
    model_prefix: String,
    /// Respond to direct human messages and replies in exactly one selected room.
    #[arg(long, requires = "model_endpoint")]
    all_human_messages: bool,
    /// Local inference protocol.
    #[arg(long, value_enum, default_value = "llama-cpp")]
    model_adapter: ModelAdapter,
    /// Total model context, including its reply allowance.
    #[arg(long, default_value_t = 4096, value_parser=clap::value_parser!(u32).range(2048..=131072))]
    model_context_tokens: u32,
    #[arg(long, default_value_t = 512, value_parser=clap::value_parser!(u32).range(128..=8192))]
    model_output_tokens: u32,
    /// Complete reply deadline in seconds (10..240), including memory compaction; not a service lifetime.
    #[arg(long, default_value_t = 60, value_parser=model_request_seconds)]
    model_request_seconds: u32,
    /// Reply length in Unicode characters (128..2000), within the HRC message limit.
    #[arg(long, default_value_t = 1000, value_parser=clap::value_parser!(u32).range(128..=2000))]
    model_reply_characters: u32,
    /// Disable retained conversation context for model replies.
    #[arg(long)]
    no_memory: bool,
    /// Maximum source age; shorter room or encrypted archive limits still apply.
    #[arg(long, default_value_t = 30)]
    memory_days: u16,
    /// Bound for the encrypted derived memory record (16 KiB to 1 MiB).
    #[arg(long, default_value_t = 262144)]
    memory_bytes: usize,
}
#[derive(Clone, Copy, clap::ValueEnum)]
enum ModelAdapter {
    LlamaCpp,
    Ollama,
}
fn model_request_seconds(value: &str) -> Result<u32, String> {
    value.parse::<u32>().ok().filter(|v| (10..=240).contains(v)).ok_or_else(|| "Use 10 to 240 seconds so the complete reply fits within the 5-minute history certificate; this is not a service lifetime.".into())
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
    let output_failed = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let ready_failed = output_failed.clone();
    let status_failed = output_failed.clone();
    let ready_stop = stop.clone();
    let memory = (options.model_endpoint.is_some() && !options.no_memory).then_some(
        hrc::bot::MemoryPolicy {
            retention_days: options.memory_days,
            max_bytes: options.memory_bytes,
        },
    );
    let status_stop = stop.clone();
    let result = hrc::bot::run_reporting(
        hrc::bot::Config {
            profile: options.profile,
            rooms: options.room,
            help: options.help_text,
            poll_interval_ms: options.poll_interval_ms,
            grant: options.grant,
            resynchronise: options.resynchronise,
            model: options
                .model_endpoint
                .zip(options.model)
                .map(|(endpoint, model)| hrc::bot::LocalModel {
                    curl: options.model_curl,
                    endpoint,
                    model,
                    prefix: options.model_prefix,
                    all_human_messages: options.all_human_messages,
                    adapter: match options.model_adapter {
                        ModelAdapter::LlamaCpp => hrc::bot::Adapter::LlamaCpp,
                        ModelAdapter::Ollama => hrc::bot::Adapter::Ollama,
                    },
                    context_tokens: options.model_context_tokens,
                    output_tokens: options.model_output_tokens,
                    request_seconds: options.model_request_seconds,
                    reply_characters: options.model_reply_characters,
                }),
            memory,
        },
        stop,
        move || {
            if bot_output(
                &json!({"status":"BotReady","meaning":"InitialAuthorisedCatchUpComplete"}),
            )
            .is_err()
            {
                ready_failed.store(true, std::sync::atomic::Ordering::Release);
                ready_stop.store(true, std::sync::atomic::Ordering::Release);
            }
        },
        move |observation| {
            if bot_output(&json!({"status":"BotStatus","observation":observation})).is_err() {
                status_failed.store(true, std::sync::atomic::Ordering::Release);
                status_stop.store(true, std::sync::atomic::Ordering::Release);
            }
        },
    );
    signal_hook::low_level::unregister(interrupt);
    signal_hook::low_level::unregister(terminate);
    if output_failed.load(std::sync::atomic::Ordering::Acquire) {
        return Err(Failure("OutputFailed"));
    }
    result.map_err(|error| Failure(error.code()))?;
    bot_output(&json!({"status":"BotStopped"}))
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

// Bot observations must never hold the profile lock behind an unread diagnostic pipe.
fn bot_output(value: &Value) -> Result<(), Failure> {
    bot_output_to(libc::STDOUT_FILENO, value)
}
fn bot_output_to(fd: std::os::fd::RawFd, value: &Value) -> Result<(), Failure> {
    let mut bytes = serde_json::to_vec(value).map_err(|_| Failure("OutputFailed"))?;
    bytes.push(b'\n');
    if bytes.len() > 4096 {
        return Err(Failure("OutputFailed"));
    }
    let flags = unsafe { libc::fcntl(fd, libc::F_GETFL) };
    if flags < 0 || unsafe { libc::fcntl(fd, libc::F_SETFL, flags | libc::O_NONBLOCK) } < 0 {
        return Err(Failure("OutputFailed"));
    }
    let count = unsafe { libc::write(fd, bytes.as_ptr().cast(), bytes.len()) };
    let restored = unsafe { libc::fcntl(fd, libc::F_SETFL, flags) };
    if count != bytes.len() as isize || restored < 0 {
        return Err(Failure("OutputFailed"));
    }
    Ok(())
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
    let result = match Cli::parse()
        .command
        .unwrap_or_else(|| Command::Gui(desktop::Options::default()))
    {
        Command::Gui(options) => desktop::run(options).map_err(Failure),
        Command::Install => desktop::install().map_err(Failure).and_then(|v| output(&v)),
        Command::SetupBundle(options) => desktop::bundle(options)
            .map_err(Failure)
            .and_then(|v| output(&v)),
        Command::Tui(options) => tui::run(&options.profile, options.offline).map_err(Failure),
        Command::Bot(options) => bot(options),
        Command::Integration { command } => integration_cli::run(command).map_err(Failure),
        Command::Assistant { command } => assistant::run(command)
            .map_err(Failure)
            .and_then(|v| output(&v)),
        Command::Manage { command } => match operations::run(command) {
            Ok(value) => output(&value),
            Err(message) => {
                let _ = writeln!(
                    std::io::stderr().lock(),
                    "{}",
                    json!({"status":"Failed","code":"OperationRefused","message":message})
                );
                return ExitCode::FAILURE;
            }
        },
        Command::Admission { command } => match self_service::commands::run(command) {
            Ok(value) => output(&value),
            Err(message) => {
                let _ = writeln!(
                    std::io::stderr().lock(),
                    "{}",
                    json!({"status":"Failed","code":"AdmissionRefused","message":message.to_string()})
                );
                return ExitCode::FAILURE;
            }
        },
        Command::Transport { command } => run(command),
        command => {
            let result = match command {
                Command::Service { command } => conversation::service(command),
                Command::Profile { command } => conversation::profile(command),
                Command::Room { command } => conversation::room(command),
                Command::Crypto { command } => conversation::encryption_cli::run(command),
                Command::Federation { command } => conversation::federation_cli::run(command),
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
                Command::Bot(_) | Command::Install | Command::SetupBundle(_) => unreachable!(),
                Command::Manage { .. }
                | Command::Assistant { .. }
                | Command::Admission { .. }
                | Command::Integration { .. } => {
                    unreachable!()
                }
            };
            result.map_err(Failure).and_then(|v| output(&v))
        }
    };
    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            // stderr may share the same full pipe as stdout; do not block while reporting output failure.
            if error.0 == "OutputFailed" {
                return ExitCode::FAILURE;
            }
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
