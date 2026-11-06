// SPDX-License-Identifier: Apache-2.0
//! Structured operation entry points share the desktop's validation and effects.
use super::{Result, failure, home, network, read_json};
use serde_json::{Value, json};
use std::{
    path::PathBuf,
    sync::{Arc, atomic::AtomicBool},
};

#[derive(clap::Subcommand)]
pub enum Command {
    /// Create, preview and operate a finite-consent native HyperNet.
    Network {
        #[command(subcommand)]
        command: Network,
    },
    /// Control a local home service and its signed account invitations.
    Service {
        #[command(subcommand)]
        command: home::Command,
    },
    /// Save and run an independently authenticated bot.
    Bot {
        #[command(subcommand)]
        command: super::bots::Command,
    },
    /// Configure and control a local inference runtime.
    Model {
        #[command(subcommand)]
        command: super::models::Command,
    },
    /// Verify and import signed native release packages for this user.
    Package {
        #[command(subcommand)]
        command: super::packages::Command,
    },
    /// Return the supported operations and the explicit authority boundaries.
    Capabilities,
}
#[derive(clap::Subcommand)]
pub enum Network {
    /// Write an editable configuration without provisioning a network.
    Template {
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    Preview {
        #[arg(long)]
        config: PathBuf,
    },
    /// Apply exactly the reviewed configuration digest.
    Apply {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        digest: String,
    },
    Status {
        #[arg(long)]
        config: PathBuf,
    },
    Start {
        #[arg(long)]
        config: PathBuf,
    },
    Stop {
        #[arg(long)]
        config: PathBuf,
    },
    RenewalPreview {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        valid_until_ms: u64,
    },
    /// Load the exact review of an unfinished renewal without issuing new consent.
    RenewalResume {
        #[arg(long)]
        config: PathBuf,
    },
    Renew {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        valid_until_ms: u64,
        #[arg(long)]
        digest: String,
    },
    /// Admit a signed native desktop request and create its HRC setup bundle.
    Invite {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        operator: Option<String>,
    },
    /// Activate the separately signed HRC endpoint registration.
    Enrol {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        registration: PathBuf,
    },
}
pub fn network_run(command: Network, cancel: &AtomicBool) -> Result<Value> {
    match command {
        Network::Template { root, output } => {
            super::private_json(&output, &network::Configuration::at(root))?;
            Ok(json!({"status":"Saved","config":output}))
        }
        Network::Preview { config } => {
            serde_json::to_value(network::preview(&read_json(&config)?, cancel).map_err(failure)?)
                .map_err(failure)
        }
        Network::Apply { config, digest } => serde_json::to_value(
            network::apply(&read_json(&config)?, &digest, cancel).map_err(failure)?,
        )
        .map_err(failure),
        Network::Status { config } => {
            serde_json::to_value(network::status(&read_json(&config)?, cancel).map_err(failure)?)
                .map_err(failure)
        }
        Network::Start { config } => {
            serde_json::to_value(network::start(&read_json(&config)?, cancel).map_err(failure)?)
                .map_err(failure)
        }
        Network::Stop { config } => {
            serde_json::to_value(network::stop(&read_json(&config)?, cancel).map_err(failure)?)
                .map_err(failure)
        }
        Network::RenewalPreview {
            config,
            valid_until_ms,
        } => serde_json::to_value(
            network::renewal_preview(&read_json(&config)?, valid_until_ms, cancel)
                .map_err(failure)?,
        )
        .map_err(failure),
        Network::Renew {
            config,
            valid_until_ms,
            digest,
        } => serde_json::to_value(
            network::renew(&read_json(&config)?, valid_until_ms, &digest, cancel)
                .map_err(failure)?,
        )
        .map_err(failure),
        Network::RenewalResume { config } => serde_json::to_value(
            network::pending_renewal(&read_json(&config)?, cancel).map_err(failure)?,
        )
        .map_err(failure),
        Network::Invite {
            config,
            request,
            operator,
        } => serde_json::to_value(
            network::invite_client(&read_json(&config)?, &request, operator.as_deref(), cancel)
                .map_err(failure)?,
        )
        .map_err(failure),
        Network::Enrol {
            config,
            registration,
        } => serde_json::to_value(
            network::enrol_client(&read_json(&config)?, &registration, cancel).map_err(failure)?,
        )
        .map_err(failure),
    }
}
pub fn run(command: Command) -> Result<Value> {
    let cancel = Arc::new(AtomicBool::new(false));
    let interrupt = signal_hook::flag::register(signal_hook::consts::SIGINT, cancel.clone())
        .map_err(failure)?;
    let terminate = match signal_hook::flag::register(signal_hook::consts::SIGTERM, cancel.clone())
    {
        Ok(id) => id,
        Err(error) => {
            signal_hook::low_level::unregister(interrupt);
            return Err(failure(error));
        }
    };
    let result = match command {
        Command::Network { command } => network_run(command, &cancel),
        Command::Service { command } => home::run(command, &cancel),
        Command::Bot { command } => super::bots::run(command, &cancel),
        Command::Model { command } => super::models::run(command, &cancel),
        Command::Package { command } => super::packages::run(command, &cancel),
        Command::Capabilities => Ok(
            json!({"schema":1,"operations":["network","service","model","bot"],"transport":"HyperNetOnly","nativePackages":{"core":super::packages::Product::Core.version(),"suite":super::packages::Product::Suite.version()},"hostChanges":"NoAutomaticPackagesFirewallOrSudo","modelEndpoints":"LoopbackOnly","consentRenewal":"ExplicitPreviewRequired","assistantAuthority":"InheritedFromInvokingUser"}),
        ),
    };
    signal_hook::low_level::unregister(interrupt);
    signal_hook::low_level::unregister(terminate);
    result
}
