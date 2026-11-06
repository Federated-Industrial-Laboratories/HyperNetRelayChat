// SPDX-License-Identifier: Apache-2.0
//! Local home-service controls and explicit admission during a bounded maintenance stop.
use super::{Result, failure, native, private_json, read_json, units};
use hrc::{protocol::*, service};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Configuration {
    pub directory: PathBuf,
    pub limits: units::Limits,
}
impl Configuration {
    pub fn at(directory: PathBuf) -> Self {
        Self {
            directory,
            limits: units::Limits::default(),
        }
    }
    pub fn load(path: &Path) -> Result<Self> {
        let value: Self = read_json(path)?;
        value.validate()?;
        Ok(value)
    }
    fn validate(&self) -> Result<service::Config> {
        native::path(&self.directory).map_err(failure)?;
        if !self.directory.is_absolute() {
            return Err("Choose an absolute service folder.".into());
        }
        self.limits.validate()?;
        service::Config::load(&self.directory)
            .map_err(|_| "The folder does not contain a valid local HRC service.".into())
    }
    fn unit(&self) -> Result<String> {
        Ok(units::name(
            "home",
            self.validate()?.descriptor.home.service,
        ))
    }
    pub fn save(&self, path: &Path, cancel: &AtomicBool) -> Result<()> {
        if status(self, cancel)?.active {
            return Err("Stop the service before changing its limits.".into());
        }
        private_json(path, self)
    }
}
pub fn status(config: &Configuration, cancel: &AtomicBool) -> Result<units::Status> {
    units::status(&config.unit()?, cancel)
}
pub fn start(config: &Configuration, cancel: &AtomicBool) -> Result<units::Status> {
    let service = config.validate()?;
    service.clock.sample().map_err(|_| {
        "The service clock is unavailable or stale. Start its HyperNet runtime first.".to_owned()
    })?;
    units::start(
        &config.unit()?,
        &std::env::current_exe().map_err(failure)?,
        &native::strings(&[
            "service",
            "run",
            "--directory",
            &native::path(&config.directory).map_err(failure)?,
            "--diagnostics",
        ]),
        &[],
        &config.limits,
        cancel,
    )
}
pub fn stop(config: &Configuration, cancel: &AtomicBool) -> Result<units::Status> {
    units::stop(&config.unit()?, cancel)
}

/// The store remains exclusive. Only the service unit derived from its verified identity is stopped.
fn maintenance<T>(
    config: &Configuration,
    cancel: &AtomicBool,
    operation: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let running = status(config, cancel)?.active;
    if running {
        stop(config, cancel)?;
    }
    let result = operation();
    if running {
        // Cancellation must not strand a previously running home after an admission request.
        let recovery = AtomicBool::new(false);
        if start(config, &recovery).is_err() {
            return Err("Admission finished or was refused, but the service restart failed. Check the registration outcome and start the service again.".into());
        }
    }
    result
}
pub fn invite(
    config: &Configuration,
    principal: Id,
    operator: Option<AccountId>,
    output: &Path,
    cancel: &AtomicBool,
) -> Result<Value> {
    config.validate()?;
    let class = operator.map_or(AccountClass::Human, |operator| AccountClass::Agent {
        operator,
    });
    maintenance(config, cancel, || {
        service::setup::invite(&config.directory,principal,class,output)
        .map(|invitation|json!({"status":"InvitationCreated","file":output,"expiresMs":invitation.expires_ms}))
        .map_err(|_|"The invitation could not be created. Check the clock, output path and whether another service process owns this store.".into())
    })
}
pub fn enrol(config: &Configuration, registration: &Path, cancel: &AtomicBool) -> Result<Value> {
    config.validate()?;
    maintenance(config, cancel, || {
        service::setup::enrol(&config.directory,registration)
        .map(|actor|json!({"status":"EndpointEnrolled","actor":actor}))
        .map_err(|_|"Registration was refused. Check its invitation, principal and expiry; another service process must not own the store.".into())
    })
}

#[derive(clap::Subcommand)]
pub enum Command {
    /// Register an existing local HRC service for desktop control.
    Import {
        #[arg(long)]
        directory: PathBuf,
        #[arg(long)]
        output: PathBuf,
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
    /// Briefly stop this managed service, create an invitation, then restore it.
    Invite {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        principal: Id,
        #[arg(long)]
        operator: Option<AccountId>,
        #[arg(long)]
        output: PathBuf,
    },
    /// Briefly stop this managed service, verify a registration, then restore it.
    Enrol {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        registration: PathBuf,
    },
}
pub fn run(command: Command, cancel: &AtomicBool) -> Result<Value> {
    match command {
        Command::Import { directory, output } => {
            let config = Configuration::at(directory);
            config.save(&output, cancel)?;
            Ok(json!({"status":"Saved","config":output}))
        }
        Command::Status { config } => {
            serde_json::to_value(status(&Configuration::load(&config)?, cancel)?).map_err(failure)
        }
        Command::Start { config } => {
            serde_json::to_value(start(&Configuration::load(&config)?, cancel)?).map_err(failure)
        }
        Command::Stop { config } => {
            serde_json::to_value(stop(&Configuration::load(&config)?, cancel)?).map_err(failure)
        }
        Command::Invite {
            config,
            principal,
            operator,
            output,
        } => invite(
            &Configuration::load(&config)?,
            principal,
            operator,
            &output,
            cancel,
        ),
        Command::Enrol {
            config,
            registration,
        } => enrol(&Configuration::load(&config)?, &registration, cancel),
    }
}
