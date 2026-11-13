// SPDX-License-Identifier: Apache-2.0
//! Normal local Agent API setup and managed lifecycle; no model or endpoint-key export.
use super::{Result, failure, native, private_json, read_json, units};
use hrc::{client::Profile, integration, protocol::*};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Configuration {
    pub version: u8,
    pub operator: AccountId,
    pub profile: PathBuf,
    pub api: PathBuf,
    pub credential: PathBuf,
    pub credential_id: Id,
    pub limits: units::Limits,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Entry {
    pub definition: PathBuf,
    pub configuration: Configuration,
    pub account: AccountId,
    pub socket: PathBuf,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Status {
    pub active: bool,
    pub state: String,
    pub api_ready: bool,
    pub connected: bool,
    pub paused: bool,
    pub last_error: Option<String>,
    pub socket: PathBuf,
}
impl Configuration {
    pub fn load(path: &Path) -> Result<Self> {
        let c: Self = read_json(path)?;
        c.validate()?;
        Ok(c)
    }
    fn validate(&self) -> Result<Profile> {
        self.limits.validate()?;
        let profile = Profile::load(&self.profile).map_err(failure)?;
        if self.version != 1
            || profile.registration.classification
                != (AccountClass::Agent {
                    operator: self.operator,
                })
        {
            return Err("Select the separate Agent profile owned by this operator.".into());
        }
        let api = integration::Configuration::load(&self.api).map_err(failure)?;
        if api.profile != self.profile
            || api.account != profile.registration.account
            || api.endpoint != profile.registration.endpoint
        {
            return Err("The API settings belong to another Agent profile.".into());
        }
        Ok(profile)
    }
    pub fn scope(&self) -> Result<integration::Scope> {
        let profile = self.validate()?;
        let (id, scope) =
            integration::credential_scope(&self.api, &self.credential).map_err(failure)?;
        if id != self.credential_id || scope.rooms.iter().any(|r| r.home != profile.server.home) {
            return Err("The local API credential does not match these settings.".into());
        }
        Ok(scope)
    }
    fn unit(&self) -> Result<String> {
        Ok(units::name("api", self.validate()?.registration.endpoint))
    }
}
pub fn prepare(profile: &Path, operator: AccountId, scope: integration::Scope) -> Result<Entry> {
    let p = Profile::load(profile).map_err(failure)?;
    if p.registration.classification != (AccountClass::Agent { operator })
        || scope.rooms.iter().any(|r| r.home != p.server.home)
    {
        return Err("Select this operator's Agent and rooms from the same server.".into());
    }
    scope.validate().map_err(failure)?;
    let directory = profile.join("Integration");
    let api = integration::initialise(profile, &directory).map_err(failure)?;
    let credential = directory.join("Client.json");
    let credential_id = integration::issue(&api, scope, &credential).map_err(failure)?;
    let definition = super::root()
        .join("Participants")
        .join(format!("{}.json", p.registration.endpoint));
    let mut configuration = Configuration {
        version: 1,
        operator,
        profile: profile.to_owned(),
        api,
        credential,
        credential_id,
        limits: Default::default(),
    };
    if definition.exists() {
        let existing = Configuration::load(&definition)?;
        if existing.operator != operator
            || existing.profile != profile
            || existing.api != configuration.api
            || existing.credential != configuration.credential
            || existing.credential_id != credential_id
        {
            return Err("The saved API entry has a different binding.".into());
        }
        configuration.limits = existing.limits;
    } else {
        private_json(&definition, &configuration)?;
    }
    configuration.validate()?;
    Ok(Entry {
        definition,
        account: p.registration.account,
        socket: integration::socket_path(&configuration.api).map_err(failure)?,
        configuration,
    })
}
pub fn saved(operator: AccountId) -> Result<Vec<Entry>> {
    let mut result = vec![];
    for path in super::configurations("Participants")? {
        let configuration: Configuration = read_json(&path)?;
        if configuration.operator == operator {
            let profile = configuration.validate()?;
            result.push(Entry {
                definition: path,
                account: profile.registration.account,
                socket: integration::socket_path(&configuration.api).map_err(failure)?,
                configuration,
            });
        }
    }
    Ok(result)
}
pub fn status(c: &Configuration, cancel: &AtomicBool) -> Result<Status> {
    let profile = c.validate()?;
    let unit = units::status(&c.unit()?, cancel)?;
    let socket = integration::socket_path(&c.api).map_err(failure)?;
    let mut result = Status {
        active: unit.active,
        state: unit.state,
        api_ready: false,
        connected: false,
        paused: false,
        last_error: None,
        socket: socket.clone(),
    };
    if !result.active {
        return Ok(result);
    }
    if let Err(error) = c.scope() {
        result.last_error = Some(error);
        return Ok(result);
    }
    let executable = std::env::current_exe().map_err(failure)?;
    let response = native::json(
        &executable,
        &native::strings(&[
            "integration",
            "request",
            "--socket",
            &native::path(&socket).map_err(failure)?,
            "--credential",
            &native::path(&c.credential).map_err(failure)?,
            "--method",
            "status",
        ]),
        cancel,
        Instant::now() + Duration::from_secs(15),
    );
    match response {
        Ok(response) => {
            let value = &response["result"];
            if serde_json::from_value::<AccountId>(value["account"].clone()).ok()
                != Some(profile.registration.account)
                || serde_json::from_value::<Id>(value["endpoint"].clone()).ok()
                    != Some(profile.registration.endpoint)
                || serde_json::from_value::<AccountClass>(value["classification"].clone()).ok()
                    != Some(profile.registration.classification)
            {
                result.last_error =
                    Some("The local API did not confirm the expected Agent identity.".into());
            } else {
                result.api_ready = true;
                result.connected = value["connected"].as_bool() == Some(true);
                result.paused = value["paused"].as_bool() == Some(true);
                result.last_error = value["lastError"].as_str().map(str::to_owned);
            }
        }
        Err(error) => result.last_error = Some(error.to_string()),
    }
    Ok(result)
}
pub fn start(c: &Configuration, cancel: &AtomicBool) -> Result<Status> {
    c.scope()?;
    if crate::onboarding::simple::load(&c.profile)
        .map_err(failure)?
        .is_some()
    {
        crate::onboarding::prepare_existing(&c.profile, false, cancel).map_err(failure)?;
    }
    units::start(
        &c.unit()?,
        &std::env::current_exe().map_err(failure)?,
        &native::strings(&[
            "integration",
            "serve",
            "--config",
            &native::path(&c.api).map_err(failure)?,
        ]),
        &[],
        &c.limits,
        cancel,
    )?;
    status(c, cancel)
}
pub fn stop(c: &Configuration, cancel: &AtomicBool) -> Result<Status> {
    units::stop(&c.unit()?, cancel)?;
    status(c, cancel)
}
#[derive(clap::Subcommand)]
pub enum Command {
    /// Prepare or recover one private credential for an admitted external Agent.
    Prepare {
        #[arg(long)]
        profile: PathBuf,
        #[arg(long)]
        operator: AccountId,
        #[arg(long, required = true)]
        room: Vec<RoomId>,
        #[arg(long)]
        allow_initiate: bool,
        #[arg(long)]
        allow_history: bool,
        #[arg(long)]
        allow_agent_replies: bool,
    },
    Start {
        #[arg(long)]
        config: PathBuf,
    },
    Stop {
        #[arg(long)]
        config: PathBuf,
    },
    Status {
        #[arg(long)]
        config: PathBuf,
    },
    List {
        #[arg(long)]
        operator: AccountId,
    },
}
pub fn run(command: Command, cancel: &AtomicBool) -> Result<Value> {
    match command {
        Command::Prepare {
            profile,
            operator,
            room,
            allow_initiate,
            allow_history,
            allow_agent_replies,
        } => serde_json::to_value(prepare(
            &profile,
            operator,
            integration::Scope {
                rooms: room,
                initiate: allow_initiate,
                history: allow_history,
                agent_replies: allow_agent_replies,
            },
        )?)
        .map_err(failure),
        Command::Start { config } => {
            serde_json::to_value(start(&Configuration::load(&config)?, cancel)?).map_err(failure)
        }
        Command::Stop { config } => {
            serde_json::to_value(stop(&Configuration::load(&config)?, cancel)?).map_err(failure)
        }
        Command::Status { config } => {
            serde_json::to_value(status(&Configuration::load(&config)?, cancel)?).map_err(failure)
        }
        Command::List { operator } => Ok(json!({"agents":saved(operator)?})),
    }
}

#[cfg(test)]
#[path = "../../Tests/Unit/Operations/Participants.rs"]
mod tests;
