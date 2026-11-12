// SPDX-License-Identifier: Apache-2.0
//! Local credentials restrict API methods and rooms without exporting endpoint keys.
use super::{Error, Result};
use crate::{client::Profile, protocol::*, service::files};
use serde::{Deserialize, Serialize};
use std::{
    fs::{self, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::{ffi::OsStrExt, fs::OpenOptionsExt},
    },
    path::{Path, PathBuf},
};
use zeroize::Zeroize;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Scope {
    pub rooms: Vec<RoomId>,
    #[serde(default)]
    pub initiate: bool,
    #[serde(default)]
    pub history: bool,
    #[serde(default)]
    pub agent_replies: bool,
}
impl Scope {
    pub fn validate(&self) -> Result<()> {
        if self.rooms.is_empty()
            || self.rooms.len() > 8
            || self
                .rooms
                .iter()
                .collect::<std::collections::BTreeSet<_>>()
                .len()
                != self.rooms.len()
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Binding {
    pub id: Id,
    pub digest: Id,
    pub scope: Scope,
    pub enabled: bool,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Configuration {
    pub version: u8,
    pub profile: PathBuf,
    pub account: AccountId,
    pub endpoint: Id,
    pub credentials: Vec<Binding>,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Credential {
    pub version: u8,
    pub id: Id,
    pub secret: String,
}
impl Drop for Credential {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}
impl Credential {
    pub fn load(path: &Path) -> Result<Self> {
        let value: Self = files::json(path).map_err(|_| Error::Invalid)?;
        if value.version != 1 || Id::from_hex(&value.secret).is_err() {
            return Err(Error::Invalid);
        }
        Ok(value)
    }
}
impl Configuration {
    pub fn load(path: &Path) -> Result<Self> {
        files::directory(path.parent().ok_or(Error::Invalid)?, false).map_err(|_| Error::State)?;
        let bytes = files::read(path, 65536).map_err(|_| Error::State)?;
        let value: Self = serde_json::from_slice(&bytes).map_err(|_| Error::State)?;
        if value.version != 1 || !value.profile.is_absolute() || value.credentials.len() > 8 {
            return Err(Error::State);
        }
        let mut ids = std::collections::BTreeSet::new();
        for b in &value.credentials {
            b.scope.validate()?;
            if !ids.insert(b.id) {
                return Err(Error::State);
            }
        }
        Ok(value)
    }
    pub(super) fn authenticate(&self, credential: &Credential) -> Result<Binding> {
        if credential.version != 1 || Id::from_hex(&credential.secret).is_err() {
            return Err(Error::Denied);
        }
        let pin = digest(credential.secret.as_bytes());
        self.credentials
            .iter()
            .find(|b| b.enabled && b.id == credential.id && b.digest == pin)
            .cloned()
            .ok_or(Error::Denied)
    }
}
/// Long profile paths use a short private runtime directory without moving keys or history.
pub fn socket_path(config: &Path) -> Result<PathBuf> {
    let canonical = config.canonicalize().map_err(|_| Error::State)?;
    let ordinary = canonical.parent().ok_or(Error::Invalid)?.join("Api.sock");
    if ordinary.as_os_str().as_bytes().len() < 108 {
        return Ok(ordinary);
    }
    let uid = unsafe { libc::geteuid() };
    let runtime = std::env::var_os("XDG_RUNTIME_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(format!("/run/user/{uid}")));
    let suffix = format!(
        "hrc-api-{uid}-{}",
        &digest(canonical.as_os_str().as_bytes()).as_hex()[..24]
    );
    let base = if runtime
        .join(&suffix)
        .join("Api.sock")
        .as_os_str()
        .as_bytes()
        .len()
        < 108
        && files::directory(&runtime, false).is_ok()
    {
        runtime
    } else {
        PathBuf::from("/tmp")
    };
    let path = base.join(suffix).join("Api.sock");
    if path.as_os_str().as_bytes().len() >= 108 {
        return Err(Error::Invalid);
    }
    Ok(path)
}
fn lock(path: &Path) -> Result<fs::File> {
    let parent = path.parent().ok_or(Error::Invalid)?;
    files::directory(parent, false).map_err(|_| Error::State)?;
    let p = parent.join("Configuration.lock");
    let f = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(&p)
        .map_err(|_| Error::State)?;
    let _ = files::read(&p, 16).map_err(|_| Error::State)?;
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(Error::State);
    }
    Ok(f)
}
fn save(path: &Path, value: &Configuration) -> Result<()> {
    let bytes = serde_json::to_vec_pretty(value).map_err(|_| Error::State)?;
    if bytes.len() > 65536 {
        return Err(Error::Capacity);
    }
    let temporary = path.with_file_name(format!(
        ".configuration-{}",
        Id::random().map_err(|_| Error::State)?
    ));
    files::create(&temporary, &bytes).map_err(|_| Error::State)?;
    fs::rename(&temporary, path)
        .and_then(|()| fs::File::open(path.parent().expect("parent"))?.sync_all())
        .map_err(|_| Error::State)
}
pub fn initialise(profile: &Path, directory: &Path) -> Result<PathBuf> {
    let p = Profile::load(profile).map_err(|_| Error::State)?;
    if !matches!(p.registration.classification, AccountClass::Agent { .. }) {
        return Err(Error::AgentRequired);
    }
    files::directory(directory, true).map_err(|_| Error::State)?;
    let path = directory.join("Configuration.json");
    let config = Configuration {
        version: 1,
        profile: profile.to_owned(),
        account: p.registration.account,
        endpoint: p.registration.endpoint,
        credentials: Vec::new(),
    };
    files::create_json(&path, &config).map_err(|_| Error::State)?;
    Ok(path)
}
pub fn issue(path: &Path, scope: Scope, output: &Path) -> Result<Id> {
    scope.validate()?;
    let _lock = lock(path)?;
    let mut c = Configuration::load(path)?;
    c.credentials.retain(|binding| binding.enabled);
    if c.credentials.len() >= 8 || output.exists() {
        return Err(Error::Capacity);
    }
    let credential = Credential {
        version: 1,
        id: Id::random().map_err(|_| Error::State)?,
        secret: Id::random().map_err(|_| Error::State)?.as_hex(),
    };
    // A failed export never enables a credential whose secret was not delivered.
    files::create_json(output, &credential).map_err(|_| Error::State)?;
    c.credentials.push(Binding {
        id: credential.id,
        digest: digest(credential.secret.as_bytes()),
        scope,
        enabled: true,
    });
    save(path, &c)?;
    Ok(credential.id)
}
pub fn revoke(path: &Path, id: Id) -> Result<()> {
    let _lock = lock(path)?;
    let mut c = Configuration::load(path)?;
    c.credentials
        .iter_mut()
        .find(|b| b.id == id)
        .ok_or(Error::Invalid)?
        .enabled = false;
    save(path, &c)
}
