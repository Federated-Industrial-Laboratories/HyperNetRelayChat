// SPDX-License-Identifier: Apache-2.0
//! Desktop bot definitions use the same authenticated CLI and bot runtime as other clients.
use super::{Result, failure, models, native, private_json, read_json, units};
use hrc::{
    bot, client,
    protocol::{AccountClass, Id, Operation, Outcome, RoomId, Target},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::PathBuf,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Config {
    pub schema: u32,
    pub id: Id,
    pub name: String,
    pub profile: PathBuf,
    pub nickname: String,
    pub rooms: Vec<RoomId>,
    pub help_text: String,
    pub grant: Option<Id>,
    pub poll_interval_ms: u64,
    pub model_id: Option<Id>,
    pub prefix: String,
    pub all_human_messages: bool,
    pub memory_enabled: bool,
    pub memory_days: u16,
    pub memory_bytes: usize,
    pub limits: units::Limits,
}
impl Config {
    pub fn new() -> Result<Self> {
        Ok(Self {
            schema: 1,
            id: Id::random().map_err(failure)?,
            name: "Chat bot".into(),
            profile: PathBuf::new(),
            nickname: "Qwen".into(),
            rooms: Vec::new(),
            help_text: "Use !qwen followed by a message.".into(),
            grant: None,
            poll_interval_ms: 1000,
            model_id: None,
            prefix: "!qwen".into(),
            all_human_messages: false,
            memory_enabled: true,
            memory_days: 30,
            memory_bytes: 262144,
            limits: units::Limits::default(),
        })
    }
    fn runtime(&self) -> Result<bot::Config> {
        let model = self
            .model_id
            .map(models::load)
            .transpose()?
            .map(|m| m.local_model(&self.prefix, self.all_human_messages));
        Ok(bot::Config {
            profile: self.profile.clone(),
            rooms: self.rooms.clone(),
            help: self.help_text.clone(),
            poll_interval_ms: self.poll_interval_ms,
            grant: self.grant,
            resynchronise: false,
            model,
            memory: (self.memory_enabled && self.model_id.is_some()).then_some(bot::MemoryPolicy {
                retention_days: self.memory_days,
                max_bytes: self.memory_bytes,
            }),
        })
    }
    pub fn validate(&self) -> Result<()> {
        if self.schema != 1 {
            return Err("Unsupported bot definition version.".into());
        }
        models::name(&self.name)?;
        hrc::text::handle(&self.nickname).map_err(failure)?;
        models::canonical(&self.profile)?;
        self.limits.validate()?;
        let profile = client::Profile::load(&self.profile)
            .map_err(|_| "Select an existing private HRC agent profile.".to_owned())?;
        if !matches!(
            profile.registration.classification,
            AccountClass::Agent { .. }
        ) {
            return Err(
                "A bot needs its own enrolled agent profile; a human profile cannot be reused."
                    .into(),
            );
        }
        self.runtime()?.validate().map_err(failure)
    }
}
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Summary {
    pub id: Id,
    pub name: String,
}

pub fn load(id: Id) -> Result<Config> {
    let value: Config = read_json(&models::definition_path("Bots", id))?;
    if value.schema != 1 || value.id != id {
        return Err("The bot definition identity does not match its file.".into());
    }
    Ok(value)
}
pub fn list() -> Result<Vec<Summary>> {
    models::definition_paths("Bots")?
        .iter()
        .map(|path| {
            let config: Config = read_json(path)?;
            if path != &models::definition_path("Bots", config.id) || config.schema != 1 {
                return Err("Invalid bot definition identity.".into());
            }
            Ok(Summary {
                id: config.id,
                name: config.name,
            })
        })
        .collect()
}
pub fn status(id: Id, cancel: &AtomicBool) -> Result<units::Status> {
    load(id)?;
    units::status(&units::name("bot", id), cancel)
}
pub(crate) fn ensure_model_idle(id: Id, cancel: &AtomicBool) -> Result<()> {
    for item in list()? {
        let bot = load(item.id)?;
        if bot.model_id == Some(id) && models::running(&status(bot.id, cancel)?) {
            return Err(format!(
                "Stop the dependent bot '{}' before changing or stopping its model.",
                bot.name
            ));
        }
    }
    Ok(())
}
pub fn save(config: &Config, cancel: &AtomicBool) -> Result<Value> {
    config.validate()?;
    let _lock = models::mutation_lock()?;
    let path = models::definition_path("Bots", config.id);
    if path.try_exists().map_err(failure)? {
        load(config.id)?;
        if models::running(&status(config.id, cancel)?) {
            return Err("Stop this bot before editing its definition.".into());
        }
    } else if list()?.len() >= 32 {
        return Err("The bot-definition limit is 32.".into());
    }
    for item in list()? {
        if item.id != config.id && load(item.id)?.profile == config.profile {
            return Err("This endpoint already belongs to another saved bot definition.".into());
        }
    }
    private_json(&path, config)?;
    Ok(json!({"status":"Saved","id":config.id}))
}

fn arguments(
    config: &Config,
    model: Option<&bot::LocalModel>,
    resynchronise: bool,
) -> Result<Vec<String>> {
    let mut args = vec![
        "bot".into(),
        "--profile".into(),
        native::path(&config.profile).map_err(failure)?,
        "--help-text".into(),
        config.help_text.clone(),
        "--poll-interval-ms".into(),
        config.poll_interval_ms.to_string(),
    ];
    for room in &config.rooms {
        args.extend(["--room".into(), room.to_string()]);
    }
    if let Some(grant) = config.grant {
        args.extend(["--grant".into(), grant.as_hex()]);
    }
    if resynchronise {
        args.push("--resynchronise".into());
    }
    if let Some(model) = model {
        args.extend([
            "--model-adapter".into(),
            match model.adapter {
                bot::Adapter::LlamaCpp => "llama-cpp",
                bot::Adapter::Ollama => "ollama",
            }
            .into(),
            "--model-endpoint".into(),
            model.endpoint.to_string(),
            "--model".into(),
            model.model.clone(),
            "--model-curl".into(),
            native::path(&model.curl).map_err(failure)?,
            "--model-prefix".into(),
            config.prefix.clone(),
            "--model-context-tokens".into(),
            model.context_tokens.to_string(),
            "--model-output-tokens".into(),
            model.output_tokens.to_string(),
        ]);
        if config.all_human_messages {
            args.push("--all-human-messages".into());
        }
        if config.memory_enabled {
            args.extend([
                "--memory-days".into(),
                config.memory_days.to_string(),
                "--memory-bytes".into(),
                config.memory_bytes.to_string(),
            ]);
        } else {
            args.push("--no-memory".into());
        }
    }
    Ok(args)
}
fn committed(value: &Outcome) -> Result<()> {
    if matches!(value, Outcome::Committed { .. }) {
        Ok(())
    } else {
        Err("The service did not commit the bot's setup operation. Inspect current permissions and pending outcomes before retrying.".into())
    }
}
/// This one-connection operation also has a native CLI entry point for bounded cancellation.
pub fn connect(id: Id, cancel: &AtomicBool) -> Result<Value> {
    let config = load(id)?;
    config.validate()?;
    if models::running(&status(id, cancel)?) {
        return Err("Stop this bot before preparing its profile connection.".into());
    }
    let deadline = Instant::now() + Duration::from_secs(120);
    native::check(cancel, deadline).map_err(failure)?;
    let mut client = client::Client::open(&config.profile).map_err(failure)?;
    let result = (|| {
        if client
            .resolve_pending()
            .map_err(failure)?
            .iter()
            .any(|reply| matches!(reply.outcome, Outcome::Unknown | Outcome::Absent))
        {
            return Err(
                "The bot has an unresolved operation. Its original identity was preserved.".into(),
            );
        }
        native::check(cancel, deadline).map_err(failure)?;
        let account = client.profile.registration.account;
        let reply = client
            .call(
                Operation::AccountSetNickname,
                Target::Account(account),
                &hrc::identity::Nickname {
                    nickname: config.nickname.clone(),
                },
            )
            .map_err(failure)?;
        committed(&reply.outcome)?;
        // Delegated access follows the represented user's grant and membership.
        if config.grant.is_none() {
            for room in &config.rooms {
                native::check(cancel, deadline).map_err(failure)?;
                let inspected = client
                    .call(
                        Operation::RoomInspect,
                        Target::Room(*room),
                        &hrc::home::Empty {},
                    )
                    .map_err(failure)?;
                match inspected.outcome {
                    Outcome::Result{..}=>(),
                    Outcome::Refused{ref detail,..} | Outcome::Rejected{ref detail,..} if detail=="Membership"=>{
                        let joined=client.call(Operation::RoomJoin,Target::Room(*room),&hrc::home::Empty{}).map_err(failure)?;
                        committed(&joined.outcome)?;
                    }
                    _=>return Err("The service refused room inspection. Check the bot's invitation, membership and current permissions.".into()),
                }
            }
        }
        Ok(json!({"status":"ProfilePrepared","id":id,"account":account}))
    })();
    client.disconnect();
    result
}
pub fn start_with(id: Id, resynchronise: bool, cancel: &AtomicBool) -> Result<units::Status> {
    let _lock = models::mutation_lock()?;
    let config = load(id)?;
    config.validate()?;
    let previous = status(id, cancel)?;
    if models::running(&previous) {
        return Ok(previous);
    }
    let runtime = config.runtime()?;
    if let Some(model_id) = config.model_id {
        let definition = models::load(model_id)?;
        definition.validate()?;
        let status = models::status(model_id, cancel)?;
        if status.managed && status.runtime.as_ref().is_none_or(|s| !s.active) {
            return Err("Start the selected model runtime before starting this bot.".into());
        }
        if !definition
            .local_model(&config.prefix, config.all_human_messages)
            .probe(cancel)
            .map_err(failure)?
        {
            return Err("The local model probe was cancelled or returned no reply.".into());
        }
    }
    crate::onboarding::prepare_existing(&config.profile, false, cancel).map_err(failure)?;
    let program = std::env::current_exe().map_err(failure)?;
    let deadline = Instant::now() + Duration::from_secs(150);
    native::json(
        &program,
        &native::strings(&["manage", "bot", "connect", "--id", &id.as_hex()]),
        cancel,
        deadline,
    )
    .map_err(failure)?;
    units::start(
        &units::name("bot", id),
        &program,
        &arguments(&config, runtime.model.as_ref(), resynchronise)?,
        &[],
        &config.limits,
        cancel,
    )
}
pub fn stop(id: Id, cancel: &AtomicBool) -> Result<units::Status> {
    let _lock = models::mutation_lock()?;
    load(id)?;
    units::stop(&units::name("bot", id), cancel)
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Preparation {
    pub invitation: PathBuf,
    pub trusted_service_key: Id,
    pub profile: PathBuf,
    pub recovery_key: PathBuf,
    pub registration: PathBuf,
    pub companion: PathBuf,
    pub clock_observation: PathBuf,
    pub clock_key: Id,
}
pub fn prepare(config: &Preparation, cancel: &AtomicBool) -> Result<Value> {
    let _lock = models::mutation_lock()?;
    let invitation: hrc::home::Invitation = read_json(&config.invitation)?;
    if invitation.service_key != config.trusted_service_key
        || !matches!(invitation.classification, AccountClass::Agent { .. })
    {
        return Err(
            "The invitation must be for an agent and match the independently accepted service key."
                .into(),
        );
    }
    for path in [
        &config.profile,
        &config.recovery_key,
        &config.registration,
        &config.companion,
        &config.clock_observation,
    ] {
        native::path(path).map_err(failure)?;
        if !path.is_absolute()
            || path
                .components()
                .any(|p| matches!(p, std::path::Component::ParentDir))
        {
            return Err("Choose absolute private profile and runtime paths.".into());
        }
    }
    if config.recovery_key.starts_with(&config.profile) {
        return Err("Keep the recovery key outside the agent profile.".into());
    }
    for path in [&config.profile, &config.recovery_key, &config.registration] {
        if path.try_exists().map_err(failure)? {
            return Err(
                "Profile creation needs new destinations. Existing state was preserved.".into(),
            );
        }
        let parent = path
            .parent()
            .ok_or("Choose a private destination folder.")?;
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(parent)
            .map_err(failure)?;
        native::directory(parent).map_err(failure)?;
    }
    let args = vec![
        "profile".into(),
        "create".into(),
        "--directory".into(),
        native::path(&config.profile).map_err(failure)?,
        "--invitation".into(),
        native::path(&config.invitation).map_err(failure)?,
        "--recovery-key-file".into(),
        native::path(&config.recovery_key).map_err(failure)?,
        "--registration-output".into(),
        native::path(&config.registration).map_err(failure)?,
        "--companion".into(),
        native::path(&config.companion).map_err(failure)?,
        "--clock-observation".into(),
        native::path(&config.clock_observation).map_err(failure)?,
        "--clock-key".into(),
        config.clock_key.as_hex(),
    ];
    let result = native::json(
        &std::env::current_exe().map_err(failure)?,
        &args,
        cancel,
        Instant::now() + Duration::from_secs(30),
    )
    .map_err(failure)?;
    Ok(
        json!({"status":"RegistrationRequired","registrationPending":true,"file":config.registration,"profile":config.profile,"account":result["account"]}),
    )
}

#[derive(clap::Subcommand)]
pub(crate) enum Command {
    Template,
    List,
    Show {
        #[arg(long)]
        id: Id,
    },
    Validate {
        #[arg(long)]
        file: PathBuf,
    },
    Save {
        #[arg(long)]
        file: PathBuf,
    },
    /// Create fresh agent keys and a signed registration from a separately trusted invitation.
    Prepare {
        #[arg(long)]
        file: PathBuf,
    },
    /// Authenticate, resolve pending operations, set nickname and join missing rooms.
    Connect {
        #[arg(long)]
        id: Id,
    },
    Status {
        #[arg(long)]
        id: Id,
    },
    Start {
        #[arg(long)]
        id: Id,
        #[arg(long)]
        resynchronise: bool,
    },
    Stop {
        #[arg(long)]
        id: Id,
    },
}
pub(crate) fn run(command: Command, cancel: &AtomicBool) -> Result<Value> {
    match command {
        Command::Template => serde_json::to_value(Config::new()?).map_err(failure),
        Command::List => serde_json::to_value(list()?).map_err(failure),
        Command::Show { id } => serde_json::to_value(load(id)?).map_err(failure),
        Command::Validate { file } => {
            let config: Config = read_json(&file)?;
            config.validate()?;
            Ok(json!({"valid":true,"id":config.id}))
        }
        Command::Save { file } => save(&read_json(&file)?, cancel),
        Command::Prepare { file } => prepare(&read_json(&file)?, cancel),
        Command::Connect { id } => connect(id, cancel),
        Command::Status { id } => serde_json::to_value(status(id, cancel)?).map_err(failure),
        Command::Start { id, resynchronise } => {
            serde_json::to_value(start_with(id, resynchronise, cancel)?).map_err(failure)
        }
        Command::Stop { id } => serde_json::to_value(stop(id, cancel)?).map_err(failure),
    }
}

#[cfg(test)]
#[path = "../../Tests/Unit/Operations/Bots.rs"]
mod tests;
