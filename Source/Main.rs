//! HyperNet Relay Chat command-line interface.
#[path = "Cli.rs"]
mod conversation;
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
        Command::Transport { command } => run(command),
        command => {
            let result = match command {
                Command::Service { command } => conversation::service(command),
                Command::Profile { command } => conversation::profile(command),
                Command::Room { command } => conversation::room(command),
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
                Command::Transport { .. } => unreachable!(),
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
