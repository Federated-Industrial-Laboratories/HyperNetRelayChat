// SPDX-License-Identifier: Apache-2.0
//! Private HRC composition for Suite hosting; native governance remains Suite-owned.
#[path = "Finish.rs"]
mod finish;
#[path = "Setup.rs"]
mod setup;
use crate::{
    clock,
    protocol::*,
    service::{self, files},
};
use serde::{Deserialize, Serialize};
use std::{
    fs::{File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path, PathBuf},
};

pub const FORMAT: &str = "HyperNet.HrcHost/1";
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the retained host configuration or private artifacts differ")]
    Configuration,
    #[error("another host provisioning request is active")]
    Busy,
    #[error("the current pinned native clock is unavailable")]
    Clock,
    #[error("host provisioning remains incomplete; retain its files and retry")]
    Unconfirmed,
    #[error(transparent)]
    Client(#[from] crate::client::Error),
}
impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Configuration => "HostConfigurationMismatch",
            Self::Busy => "HostProvisioningBusy",
            Self::Clock => "ClockUnavailable",
            Self::Unconfirmed => "HostProvisioningUnconfirmed",
            Self::Client(error) => error.code(),
        }
    }
}
type Result<T> = std::result::Result<T, Error>;
impl From<files::Invalid> for Error {
    fn from(_: files::Invalid) -> Self {
        Self::Configuration
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Options {
    pub home: ServiceId,
    pub receiver_companion: PathBuf,
    pub clock: clock::Config,
    pub owner_principal: Id,
    pub owner_companion: PathBuf,
    pub nickname: String,
    pub motd: String,
    pub agents_enabled: bool,
    pub max_agents_per_operator: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission_bridge: Option<PathBuf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission_uid: Option<u32>,
}
impl Options {
    fn bridge(&self) -> Result<Option<service::live_admission::Bridge>> {
        match (&self.admission_bridge, self.admission_uid) {
            (None, None) => Ok(None),
            (Some(directory), Some(uid)) => {
                let bridge = service::live_admission::Bridge {
                    directory: directory.clone(),
                    uid,
                };
                bridge.validate()?;
                Ok(Some(bridge))
            }
            _ => Err(Error::Configuration),
        }
    }
    fn validate(&self) -> Result<()> {
        self.bridge()?;
        for path in [
            &self.receiver_companion,
            &self.owner_companion,
            &self.clock.observation,
        ] {
            if !path.is_absolute()
                || path.as_os_str().len() > 4096
                || path
                    .components()
                    .any(|c| !matches!(c, Component::RootDir | Component::Normal(_)))
            {
                return Err(Error::Configuration);
            }
        }
        if self.receiver_companion == self.owner_companion
            || !(1..=8).contains(&self.max_agents_per_operator)
        {
            return Err(Error::Configuration);
        }
        for id in [
            self.owner_principal,
            self.home.service,
            self.home.network.network,
            self.home.network.incarnation,
        ] {
            if id.as_bytes() == &[0; 32] {
                return Err(Error::Configuration);
            }
        }
        crate::text::handle(&self.nickname).map_err(|_| Error::Configuration)?;
        crate::home::ServiceInformation::new(self.motd.clone())
            .map_err(|_| Error::Configuration)?;
        Ok(())
    }
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub format: String,
    pub action: Action,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "camelCase", deny_unknown_fields)]
pub enum Action {
    Prepare(Box<Options>),
    Finish,
    Status,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentPolicy {
    pub agents_enabled: bool,
    pub max_agents_per_operator: u16,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Response {
    pub format: String,
    pub status: String,
    pub descriptor: service::Descriptor,
    pub service_directory: PathBuf,
    pub owner_profile: PathBuf,
    pub recovery_key_file: PathBuf,
    pub admission_binding: PathBuf,
    pub rooms: Vec<RoomId>,
    pub policy: AgentPolicy,
}
fn lock(directory: &Path, create: bool) -> Result<File> {
    files::directory(directory, create && !directory.exists())?;
    let path = directory.join("Host.lock");
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&path)
        .map_err(|_| Error::Configuration)?;
    let meta = file.metadata().map_err(|_| Error::Configuration)?;
    let named = std::fs::symlink_metadata(&path).map_err(|_| Error::Configuration)?;
    if !meta.is_file()
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.mode() & 0o7777 != 0o600
        || meta.nlink() != 1
        || (meta.dev(), meta.ino()) != (named.dev(), named.ino())
    {
        return Err(Error::Configuration);
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(Error::Busy);
    }
    Ok(file)
}
fn exact<T: Serialize>(path: &Path, value: &T) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|_| Error::Configuration)?;
    if path.exists() {
        if files::read(path, 16384)? != bytes {
            return Err(Error::Configuration);
        }
    } else {
        files::create(path, &bytes)?;
    }
    Ok(())
}
fn key(path: &Path) -> Result<SigningKey> {
    Ok(if path.exists() {
        files::key(path)?
    } else {
        files::create_key(path)?
    })
}
pub fn request(directory: &Path, request: Request) -> Result<Response> {
    if request.format != FORMAT {
        return Err(Error::Configuration);
    }
    if let Action::Prepare(options) = &request.action {
        options.validate()?;
        if options
            .admission_bridge
            .as_ref()
            .is_some_and(|bridge| bridge.starts_with(directory) || directory.starts_with(bridge))
        {
            return Err(Error::Configuration);
        }
    }
    let _lock = lock(directory, matches!(request.action, Action::Prepare(_)))?;
    if let Action::Prepare(options) = &request.action {
        exact(&directory.join("Intent.json"), options)?;
    }
    let options: Options = files::json(&directory.join("Intent.json"))?;
    options.validate()?;
    if matches!(request.action, Action::Prepare(_)) {
        setup::prepare(directory, &options)?;
    }
    if matches!(request.action, Action::Finish) {
        finish::finish(directory, &options)?;
    }
    response(directory, &options)
}
fn response(directory: &Path, options: &Options) -> Result<Response> {
    let descriptor = setup::verify(directory, options)?;
    let rooms: Vec<RoomId> = if directory.join("Ready.json").exists() {
        let rooms: Vec<RoomId> = files::json(&directory.join("Ready.json"))?;
        if rooms.len() != 1 || rooms[0].home != options.home {
            return Err(Error::Configuration);
        }
        rooms
    } else {
        vec![]
    };
    Ok(Response {
        format: FORMAT.into(),
        status: if rooms.is_empty() {
            "Prepared"
        } else {
            "Ready"
        }
        .into(),
        descriptor,
        service_directory: directory.join("Home"),
        owner_profile: directory.join("Owner/Profile"),
        recovery_key_file: directory.join("Owner/Recovery.key"),
        admission_binding: directory.join("Registrar.json"),
        rooms,
        policy: AgentPolicy {
            agents_enabled: options.agents_enabled,
            max_agents_per_operator: options.max_agents_per_operator,
        },
    })
}
