// SPDX-License-Identifier: Apache-2.0
//! Exact local intents and bounded operator serialization preserve uncertain native outcomes.
use super::*;
use hrc::service::files;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    fs::{File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
};

pub(super) fn read<T: DeserializeOwned>(path: &Path) -> Result<T> {
    serde_json::from_slice(&files::read(path, 20 * 1024 * 1024).map_err(|_| Error::State)?)
        .map_err(|_| Error::State)
}
pub(super) fn exact(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.exists() {
        if files::read(path, 20 * 1024 * 1024).map_err(|_| Error::State)? != bytes {
            return Err(Error::Bound);
        }
        return Ok(());
    }
    files::create(path, bytes).map_err(|_| Error::State)
}
pub(super) fn save(path: &Path, value: &impl Serialize) -> Result<()> {
    exact(path, &serde_json::to_vec(value).map_err(|_| Error::State)?)
}
pub(super) fn directory(path: &Path) -> Result<()> {
    files::directory(path, !path.exists())
        .map(|_| ())
        .map_err(|_| Error::State)
}
pub(super) fn artifact(path: &Path) -> Result<Artifact> {
    Artifact::from_bytes(&files::read(path, 8 * 1024 * 1024).map_err(|_| Error::State)?)
}
pub(super) struct Lock(File);
impl Lock {
    pub fn acquire(config: &Config) -> Result<Self> {
        config.validate()?;
        let path = &config.operator_lock;
        files::directory(path.parent().ok_or(Error::State)?, false).map_err(|_| Error::State)?;
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .map_err(|_| Error::State)?;
        let m = file.metadata().map_err(|_| Error::State)?;
        if !m.is_file()
            || m.uid() != unsafe { libc::geteuid() }
            || m.mode() & 0o7777 != 0o600
            || m.nlink() != 1
        {
            return Err(Error::State);
        }
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err(Error::Busy);
        }
        Ok(Self(file))
    }
}
impl Drop for Lock {
    fn drop(&mut self) {
        unsafe {
            libc::flock(self.0.as_raw_fd(), libc::LOCK_UN);
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Candidate {
    pub request_sha256: String,
    pub principal: String,
    pub relay: String,
    pub reader_grant: String,
    pub connect_grant: Option<String>,
    pub member: String,
    pub join: String,
    pub authority: String,
    pub destination: String,
}
impl Candidate {
    pub fn new(request: &[u8], inspected: &Value, reader: bool) -> Result<Self> {
        let principal = string(inspected, "devicePublicKey")?;
        let relay = string(inspected, "relayPublicKey")?;
        if !is_id(&principal) || !is_id(&relay) || principal == relay {
            return Err(Error::Invalid);
        }
        Ok(Self {
            request_sha256: digest(request),
            principal,
            relay,
            reader_grant: id()?,
            connect_grant: if reader { None } else { Some(id()?) },
            member: id()?,
            join: id()?,
            authority: id()?,
            destination: id()?,
        })
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Admission {
    pub config_digest: String,
    pub bootstrap_sha256: String,
    pub network: String,
    pub incarnation: String,
    pub access_expires_ms: u64,
    pub route_seconds: u64,
    pub not_before_ms: u64,
    pub initial_expires_ms: u64,
    pub join_expires_ms: u64,
    pub invitation_id: String,
    pub invitation_expires_ms: u64,
    pub chat: Candidate,
    pub reader: Option<Candidate>,
}
impl Admission {
    pub fn validate(&self, config: &Config) -> Result<()> {
        if self.config_digest != digest(&serde_json::to_vec(config).map_err(|_| Error::State)?) {
            return Err(Error::State);
        }
        if self.bootstrap_sha256
            != digest(
                &process::public_file(&config.bootstrap, 1_048_576).map_err(|_| Error::State)?,
            )
        {
            return Err(Error::State);
        }
        Ok(())
    }
}
pub(super) fn active(work: &Path) -> Result<()> {
    if work.join("Revocation.json").exists() {
        return Err(Error::Expired);
    }
    Ok(())
}
#[derive(Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Intent {
    arguments: Vec<String>,
    output: Option<PathBuf>,
}

pub(super) fn recover_recorded_effect(
    native: &native::Native<'_>,
    work: &Path,
    name: &str,
    output: &Path,
) -> Result<bool> {
    let path = work.join("Effects").join(name).join("Intent.json");
    if !path.exists() {
        return Ok(false);
    }
    let intent: Intent = read(&path)?;
    if intent.output.as_deref() != Some(output) {
        return Err(Error::Bound);
    }
    if !output.exists() && !native.recover_output(output)? {
        return Ok(false);
    }
    // The existing intent and recovered output guarantee effect cannot issue again.
    effect(native, work, name, intent.arguments, Some(output))?;
    Ok(true)
}

pub(super) fn effect(
    native: &native::Native<'_>,
    work: &Path,
    name: &str,
    arguments: Vec<String>,
    output: Option<&Path>,
) -> Result<Value> {
    if !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-') {
        return Err(Error::State);
    }
    let effects = work.join("Effects");
    directory(&effects)?;
    let folder = effects.join(name);
    directory(&folder)?;
    let intent_path = folder.join("Intent.json");
    let intent = Intent {
        arguments,
        output: output.map(Path::to_owned),
    };
    let existed = intent_path.exists();
    save(&intent_path, &intent)?;
    let result_path = folder.join("Result.json");
    if result_path.exists() {
        return read(&result_path);
    }
    if existed {
        if let Some(path) = output
            && (path.exists() || native.recover_output(path)?)
        {
            let recovered = json!({"status":"RecoveredNativeOutput"});
            save(&result_path, &recovered)?;
            return Ok(recovered);
        }
        // No second issuance is inferred from a missing response after a possibly completed effect.
        save(
            &folder.join("Blocked.json"),
            &json!({"reason":"NativeOutcomeUncertain"}),
        )?;
        return Err(Error::Native);
    }
    match native.operator(&intent.arguments, output) {
        Ok(result) => {
            save(&result_path, &result)?;
            Ok(result)
        }
        Err(error) => {
            save(
                &folder.join("Blocked.json"),
                &json!({"reason":"NativeOutcomeUncertain"}),
            )?;
            Err(error)
        }
    }
}

#[cfg(test)]
#[path = "Tests.rs"]
mod tests;
