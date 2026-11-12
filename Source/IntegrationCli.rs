// SPDX-License-Identifier: Apache-2.0
//! Installed participant commands use the same local API as external applications.
use hrc::integration::{self, Scope};
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    path::PathBuf,
    sync::{Arc, atomic::AtomicBool},
};
#[derive(clap::Subcommand)]
pub enum Command {
    /// Prepare API settings for an existing Agent profile; no model is required.
    Init {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        directory: PathBuf,
    },
    /// Export a private revocable integration credential scoped to selected rooms.
    Issue {
        #[arg(long)]
        config: PathBuf,
        #[arg(long, required = true)]
        room: Vec<hrc::protocol::RoomId>,
        #[arg(long)]
        allow_initiate: bool,
        #[arg(long)]
        allow_history: bool,
        #[arg(long)]
        allow_agent_replies: bool,
        #[arg(long)]
        output: PathBuf,
    },
    /// Disable a local integration credential without removing the Agent account.
    Revoke {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        id: hrc::protocol::Id,
    },
    /// Own the Agent profile and serve JSON-RPC through a private socket or stdio.
    Serve {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        stdio: bool,
    },
    /// Send one high-level request; parameters come from stdin, never shell evaluation.
    Request {
        #[arg(long)]
        socket: PathBuf,
        #[arg(long)]
        credential: PathBuf,
        #[arg(long)]
        method: String,
    },
    /// Follow a durable consumer; acknowledge each batch explicitly through the API.
    Events {
        #[arg(long)]
        socket: PathBuf,
        #[arg(long)]
        credential: PathBuf,
        #[arg(long)]
        consumer: String,
        #[arg(long)]
        follow: bool,
    },
}
fn output(v: &Value) -> Result<(), &'static str> {
    let mut out = std::io::stdout().lock();
    serde_json::to_writer(&mut out, v).map_err(|_| "OutputFailed")?;
    writeln!(out).map_err(|_| "OutputFailed")
}
pub fn run(command: Command) -> Result<(), &'static str> {
    let stop = Arc::new(AtomicBool::new(false));
    for signal in [signal_hook::consts::SIGINT, signal_hook::consts::SIGTERM] {
        signal_hook::flag::register(signal, stop.clone()).map_err(|_| "SignalUnavailable")?;
    }
    let result = match command {
        Command::Init { profile, directory } => {
            integration::initialise(&profile, &directory).map(|p| json!({"configuration":p}))
        }
        Command::Issue {
            config,
            room,
            allow_initiate,
            allow_history,
            allow_agent_replies,
            output,
        } => integration::issue(
            &config,
            Scope {
                rooms: room,
                initiate: allow_initiate,
                history: allow_history,
                agent_replies: allow_agent_replies,
            },
            &output,
        )
        .map(|id| json!({"credential":id,"file":output})),
        Command::Revoke { config, id } => {
            integration::revoke(&config, id).map(|()| json!({"revoked":id}))
        }
        Command::Serve { config, stdio } => {
            return integration::serve(&config, stdio, stop).map_err(|e| e.code());
        }
        Command::Request {
            socket,
            credential,
            method,
        } => {
            let mut bytes = Vec::new();
            std::io::stdin()
                .take(integration::REQUEST_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| "InputUnavailable")?;
            if bytes.len() > integration::REQUEST_BYTES {
                return Err("InvalidIntegrationRequest");
            }
            let params = if bytes.is_empty() {
                json!({})
            } else {
                serde_json::from_slice(&bytes).map_err(|_| "InvalidIntegrationRequest")?
            };
            integration::request(&socket, &credential, &method, params)
        }
        Command::Events {
            socket,
            credential,
            consumer,
            follow,
        } => {
            loop {
                let value = integration::request(
                    &socket,
                    &credential,
                    "events.next",
                    json!({"consumer":consumer}),
                )
                .map_err(|e| e.code())?;
                let failed = value.get("error").is_some();
                if follow && !failed {
                    output(
                        &json!({"jsonrpc":"2.0","method":"events.batch","params":value["result"]}),
                    )?;
                } else {
                    output(&value)?;
                }
                if !follow || failed || stop.load(std::sync::atomic::Ordering::Acquire) {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_secs(1));
            }
            return Ok(());
        }
    };
    output(&result.map_err(|e| e.code())?)
}
