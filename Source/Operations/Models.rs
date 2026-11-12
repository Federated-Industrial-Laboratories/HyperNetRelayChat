// SPDX-License-Identifier: Apache-2.0
//! Saved local inference definitions and explicitly owned runtime lifecycles.
#[path = "ModelReadiness.rs"]
mod readiness;
use super::{Result, bots, failure, native, private_json, read_json, root, units};
use hrc::{
    bot::{Adapter, LocalModel},
    protocol::Id,
};
pub(crate) use readiness::{Progress, progress};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    fs::{self, File, OpenOptions},
    io::Read,
    net::{SocketAddr, TcpStream},
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    time::Duration,
};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub(crate) enum Backend {
    #[default]
    External,
    LlamaCpp {
        executable: PathBuf,
        model_file: PathBuf,
        gpu_layers: u32,
        cuda_devices: String,
    },
    Ollama {
        executable: PathBuf,
        models_directory: PathBuf,
        cuda_devices: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Config {
    pub schema: u32,
    pub id: Id,
    pub name: String,
    pub adapter: Adapter,
    pub endpoint: SocketAddr,
    pub model: String,
    pub curl: PathBuf,
    pub context_tokens: u32,
    pub output_tokens: u32,
    #[serde(default = "hrc::bot::default_request_seconds")]
    pub request_seconds: u32,
    #[serde(default = "hrc::bot::default_reply_characters")]
    pub reply_characters: u32,
    #[serde(default = "default_startup_seconds")]
    pub startup_seconds: u32,
    pub backend: Backend,
    pub library_directory: Option<PathBuf>,
    pub limits: units::Limits,
}
fn default_startup_seconds() -> u32 {
    900
}
impl Config {
    pub fn new() -> Result<Self> {
        Ok(Self {
            schema: 1,
            id: Id::random().map_err(failure)?,
            name: "Local model".into(),
            adapter: Adapter::LlamaCpp,
            endpoint: SocketAddr::from(([127, 0, 0, 1], 8080)),
            model: "Qwen".into(),
            curl: native::discover("curl"),
            context_tokens: 4096,
            output_tokens: 512,
            request_seconds: 60,
            reply_characters: 1000,
            startup_seconds: 900,
            backend: Backend::External,
            library_directory: None,
            limits: units::Limits {
                memory_mib: 8192,
                cpu_percent: 400,
                ..Default::default()
            },
        })
    }
    pub fn local_model(&self, prefix: &str, all_human_messages: bool) -> LocalModel {
        LocalModel {
            curl: self.curl.clone(),
            endpoint: self.endpoint,
            model: self.model.clone(),
            prefix: prefix.into(),
            all_human_messages,
            adapter: self.adapter,
            context_tokens: self.context_tokens,
            output_tokens: self.output_tokens,
            request_seconds: self.request_seconds,
            reply_characters: self.reply_characters,
        }
    }
    pub fn validate(&self) -> Result<()> {
        if self.schema != 1 {
            return Err("Unsupported model definition version.".into());
        }
        name(&self.name)?;
        if !(10..=240).contains(&self.request_seconds) {
            return Err("Reply requests must be 10 to 240 seconds so the complete reply, including memory compaction, fits within the existing 5-minute history certificate. This does not limit the bot's lifetime.".into());
        }
        if !(30..=3600).contains(&self.startup_seconds) {
            return Err("Choose a startup readiness wait from 30 to 3600 seconds. This does not stop a running model when it expires.".into());
        }
        if !(128..=2000).contains(&self.reply_characters) {
            return Err("Choose 128 to 2000 reply characters within HRC's message limit.".into());
        }
        if self.output_tokens.saturating_add(1024) >= self.context_tokens {
            return Err(
                "Reply tokens must leave at least 1025 Context tokens for the prompt and template."
                    .into(),
            );
        }
        self.local_model("!model", false)
            .validate()
            .map_err(failure)?;
        native::executable(&self.curl).map_err(|_|"Choose an executable curl binary in an installation whose files and parent folders cannot be changed by other users.".to_owned())?;
        self.limits.validate()?;
        if let Some(path) = &self.library_directory {
            canonical(path)?;
            if !path.is_dir() {
                return Err("Choose an existing local library folder.".into());
            }
        }
        match &self.backend {
            Backend::External => (),
            Backend::LlamaCpp {
                executable,
                model_file,
                gpu_layers,
                cuda_devices,
            } => {
                if self.adapter != Adapter::LlamaCpp || *gpu_layers > 1024 {
                    return Err(
                        "Choose the llama.cpp adapter and a GPU layer count from 0 to 1024.".into(),
                    );
                }
                native::executable(executable).map_err(failure)?;
                canonical(model_file)?;
                let mut file = OpenOptions::new()
                    .read(true)
                    .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
                    .open(model_file)
                    .map_err(failure)?;
                if !file.metadata().map_err(failure)?.is_file() {
                    return Err("Choose a local GGUF model file.".into());
                }
                let mut magic = [0; 4];
                file.read_exact(&mut magic)
                    .map_err(|_| "The selected file is not a readable GGUF model.".to_owned())?;
                if magic != *b"GGUF" {
                    return Err("The selected file is not a GGUF model.".into());
                }
                devices(cuda_devices)?;
            }
            Backend::Ollama {
                executable,
                models_directory,
                cuda_devices,
            } => {
                if self.adapter != Adapter::Ollama {
                    return Err("Choose the Ollama adapter for this runtime.".into());
                }
                native::executable(executable).map_err(failure)?;
                canonical(models_directory)?;
                if !models_directory.is_dir() {
                    return Err("Choose Ollama's existing local model folder.".into());
                }
                devices(cuda_devices)?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct Summary {
    pub id: Id,
    pub name: String,
}
#[derive(Clone, Debug, Serialize)]
pub(crate) struct Status {
    pub managed: bool,
    pub runtime: Option<units::Status>,
    pub readiness: Option<Progress>,
}

pub(crate) fn name(value: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
        return Err("Use a name of 1 to 128 bytes without control characters.".into());
    }
    Ok(())
}
pub(crate) fn canonical(path: &Path) -> Result<()> {
    native::path(path).map_err(failure)?;
    if !path.is_absolute() || path.canonicalize().map_err(failure)? != path {
        return Err("Choose an absolute local path without symbolic links.".into());
    }
    Ok(())
}
fn devices(value: &str) -> Result<()> {
    if value.len() > 128
        || !value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b',' | b'-' | b'_' | b'/'))
    {
        return Err(
            "Use a GPU device list or leave it empty to inherit the runtime selection.".into(),
        );
    }
    Ok(())
}
pub(crate) fn running(status: &units::Status) -> bool {
    status.active
        || status.pid != 0
        || matches!(
            status.state.as_str(),
            "activating" | "reloading" | "deactivating"
        )
}
pub(crate) fn definition_path(kind: &str, id: Id) -> PathBuf {
    root().join(kind).join(format!("{}.json", id.as_hex()))
}
pub(crate) fn definition_paths(kind: &str) -> Result<Vec<PathBuf>> {
    let directory = root().join(kind);
    if !directory.try_exists().map_err(failure)? {
        return Ok(Vec::new());
    }
    native::directory(&directory).map_err(failure)?;
    let mut entries = Vec::new();
    for entry in fs::read_dir(directory).map_err(failure)? {
        let entry = entry.map_err(failure)?;
        if entry.path().extension().is_some_and(|s| s == "json") {
            if entries.len() == 32 {
                return Err("The saved-definition limit is 32 per type.".into());
            }
            entries.push(entry.path());
        }
    }
    entries.sort();
    Ok(entries)
}
pub(crate) fn mutation_lock() -> Result<File> {
    let directory = root();
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&directory)
        .map_err(failure)?;
    native::directory(&directory).map_err(failure)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(directory.join("Control.lock"))
        .map_err(failure)?;
    let metadata = file.metadata().map_err(failure)?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o777 != 0o600
    {
        return Err("The operations lock is not a private regular file.".into());
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("Another bot or model operation is running.".into());
    }
    Ok(file)
}
pub fn load(id: Id) -> Result<Config> {
    let config: Config = read_json(&definition_path("Models", id))?;
    if config.id != id || config.schema != 1 {
        return Err("The model definition identity does not match its file.".into());
    }
    Ok(config)
}
pub fn list() -> Result<Vec<Summary>> {
    definition_paths("Models")?
        .iter()
        .map(|path| {
            let config: Config = read_json(path)?;
            if path != &definition_path("Models", config.id) || config.schema != 1 {
                return Err("Invalid model definition identity.".into());
            }
            Ok(Summary {
                id: config.id,
                name: config.name,
            })
        })
        .collect()
}
pub fn save(config: &Config, cancel: &AtomicBool) -> Result<Value> {
    config.validate()?;
    let _lock = mutation_lock()?;
    let path = definition_path("Models", config.id);
    if path.try_exists().map_err(failure)? {
        let previous = load(config.id)?;
        if let Some(runtime) = status_config(&previous, cancel)?.runtime
            && running(&runtime)
        {
            return Err("Stop this model runtime before editing its definition.".into());
        }
    } else if list()?.len() >= 32 {
        return Err("The model-definition limit is 32.".into());
    }
    bots::ensure_model_idle(config.id, cancel)?;
    private_json(&path, config)?;
    Ok(json!({"status":"Saved","id":config.id}))
}
fn status_config(config: &Config, cancel: &AtomicBool) -> Result<Status> {
    match config.backend {
        Backend::External => Ok(Status {
            managed: false,
            runtime: None,
            readiness: readiness::for_config(config)?,
        }),
        _ => Ok(Status {
            managed: true,
            runtime: Some(units::status(&units::name("model", config.id), cancel)?),
            readiness: readiness::for_config(config)?,
        }),
    }
}
pub fn status(id: Id, cancel: &AtomicBool) -> Result<Status> {
    status_config(&load(id)?, cancel)
}
pub fn probe(id: Id, cancel: &AtomicBool) -> Result<Value> {
    let _lock = mutation_lock()?;
    let config = load(id)?;
    config.validate()?;
    readiness::wait(&config, cancel)?;
    Ok(
        json!({"id":id,"ready":true,"scope":"SyntheticLocalInference","conversationContent":false,"readiness":readiness::for_config(&config)?}),
    )
}

pub(crate) fn wait_ready(config: &Config, cancel: &AtomicBool) -> Result<()> {
    readiness::wait(config, cancel)
}
type Launch = (PathBuf, Vec<String>, Vec<(String, String)>);
fn launch(config: &Config) -> Result<Launch> {
    let mut env = Vec::new();
    if let Some(path) = &config.library_directory {
        env.push((
            "LD_LIBRARY_PATH".into(),
            native::path(path).map_err(failure)?,
        ));
    }
    let (program, args, selected) = match &config.backend {
        Backend::External => {
            return Err(
                "This endpoint is externally managed; use Probe instead of Start or Stop.".into(),
            );
        }
        Backend::LlamaCpp {
            executable,
            model_file,
            gpu_layers,
            cuda_devices,
        } => {
            let args = vec![
                "--model".into(),
                native::path(model_file).map_err(failure)?,
                "--alias".into(),
                config.model.clone(),
                "--host".into(),
                config.endpoint.ip().to_string(),
                "--port".into(),
                config.endpoint.port().to_string(),
                "--ctx-size".into(),
                config.context_tokens.to_string(),
                "--parallel".into(),
                "1".into(),
                "--n-gpu-layers".into(),
                gpu_layers.to_string(),
                "--jinja".into(),
                "--offline".into(),
                "--log-disable".into(),
            ];
            (executable.clone(), args, cuda_devices)
        }
        Backend::Ollama {
            executable,
            models_directory,
            cuda_devices,
        } => {
            env.extend([
                ("OLLAMA_NO_CLOUD".into(), "1".into()),
                ("OLLAMA_HOST".into(), config.endpoint.to_string()),
                (
                    "OLLAMA_MODELS".into(),
                    native::path(models_directory).map_err(failure)?,
                ),
                ("OLLAMA_NUM_PARALLEL".into(), "1".into()),
            ]);
            (executable.clone(), vec!["serve".into()], cuda_devices)
        }
    };
    if !selected.is_empty() {
        env.push(("CUDA_VISIBLE_DEVICES".into(), selected.clone()));
    }
    Ok((program, args, env))
}
pub fn start(id: Id, cancel: &AtomicBool) -> Result<Status> {
    let _lock = mutation_lock()?;
    let config = load(id)?;
    config.validate()?;
    let (program, args, environment) = launch(&config)?;
    let old = status_config(&config, cancel)?;
    if old.runtime.as_ref().is_some_and(running) {
        readiness::wait(&config, cancel)?;
        return status_config(&config, cancel);
    }
    if TcpStream::connect_timeout(&config.endpoint, Duration::from_millis(250)).is_ok() {
        return Err("The selected endpoint already has a listener. Keep it as an external endpoint or choose a free port.".into());
    }
    let started = units::start(
        &units::name("model", id),
        &program,
        &args,
        &environment,
        &config.limits,
        cancel,
    );
    let ready = started.and_then(|_| readiness::wait(&config, cancel));
    if cancel.load(std::sync::atomic::Ordering::Acquire) {
        // Cancel owns only the process this Start created, never an already-running/external model.
        units::stop(&units::name("model", id), &AtomicBool::new(false))?;
    }
    ready?;
    status_config(&config, cancel)
}
pub fn stop(id: Id, cancel: &AtomicBool) -> Result<Status> {
    let _lock = mutation_lock()?;
    let config = load(id)?;
    if matches!(config.backend, Backend::External) {
        return Err("This endpoint is externally managed; HRC cannot stop it.".into());
    }
    bots::ensure_model_idle(id, cancel)?;
    let runtime = units::stop(&units::name("model", id), cancel)?;
    readiness::stopped(&config)?;
    Ok(Status {
        managed: true,
        runtime: Some(runtime),
        readiness: readiness::for_config(&config)?,
    })
}

#[derive(clap::Subcommand)]
pub(crate) enum Command {
    /// Print a new editable model definition with its stable identity.
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
    Status {
        #[arg(long)]
        id: Id,
    },
    Start {
        #[arg(long)]
        id: Id,
    },
    Stop {
        #[arg(long)]
        id: Id,
    },
    /// Send a synthetic request to the selected local backend without chat content.
    Probe {
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
        Command::Status { id } => serde_json::to_value(status(id, cancel)?).map_err(failure),
        Command::Start { id } => serde_json::to_value(start(id, cancel)?).map_err(failure),
        Command::Stop { id } => serde_json::to_value(stop(id, cancel)?).map_err(failure),
        Command::Probe { id } => probe(id, cancel),
    }
}

#[cfg(test)]
#[path = "../../Tests/Unit/Operations/Models.rs"]
mod tests;
