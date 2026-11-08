// SPDX-License-Identifier: Apache-2.0
//! Durable one-recipient binding and local operator controls for optional admission.
use super::*;
use hrc::service::files;
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{
    fs::{self, File, OpenOptions},
    net::SocketAddrV4,
    os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    },
    path::{Path, PathBuf},
};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Configuration {
    pub format: String,
    pub name: String,
    pub directory: PathBuf,
    pub address: SocketAddrV4,
    pub certificate_authority: PathBuf,
    pub certificate: PathBuf,
    pub private_key: PathBuf,
    pub certificate_sha256: String,
    pub maximum_invitations: u16,
    pub route_seconds: u64,
    pub backend: backend::Config,
    pub metadata: NetworkMetadata,
}
impl Configuration {
    pub fn load(path: &Path) -> Result<Self> {
        let c: Self = read(path, 131072)?;
        files::directory(&c.directory, false).map_err(|_| Error::State)?;
        if c.format != "HrcAdmissionHost/1"
            || path != c.directory.join("Configuration.json")
            || c.maximum_invitations == 0
            || c.maximum_invitations > 64
            || !(120..=86390).contains(&c.route_seconds)
            || !is_id(&c.certificate_sha256)
            || c.name.is_empty()
            || c.name.len() > 96
            || c.name.chars().any(char::is_control)
            || c.address.port() <= 1024
            || c.address.ip().is_unspecified()
            || c.address.ip().is_multicast()
            || c.address.ip().is_broadcast()
            || c.metadata.access_expires_ms == 0
        {
            return Err(Error::Invalid);
        }
        Ok(c)
    }
    pub fn pin(&self) -> Result<String> {
        Ok(digest(&serde_json::to_vec(self).map_err(|_| Error::State)?))
    }
    pub fn record_directory(&self, id: &str) -> Result<PathBuf> {
        if !is_id(id) {
            return Err(Error::Invalid);
        }
        Ok(self.directory.join("Invitations").join(id))
    }
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Control {
    pub configuration_sha256: String,
    pub enabled: bool,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(super) enum Phase {
    Available,
    Admitting,
    Ready,
    Enrolling,
    Active,
    Renewing,
    Revoking,
    Revoked,
    Blocked,
}
impl Phase {
    pub fn pending(self) -> bool {
        matches!(
            self,
            Self::Admitting | Self::Enrolling | Self::Renewing | Self::Revoking
        )
    }
    pub fn label(self) -> &'static str {
        match self {
            Self::Available => "Invitation available",
            Self::Admitting => "Preparing access",
            Self::Ready => "Waiting for account registration",
            Self::Enrolling => "Activating account",
            Self::Active => "Active",
            Self::Renewing => "Renewing access",
            Self::Revoking => "Revoking access",
            Self::Revoked => "Revoked",
            Self::Blocked => "Operator inspection required",
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Record {
    pub id: String,
    pub label: String,
    pub secret_sha256: String,
    pub expires_ms: u64,
    pub access_expires_ms: u64,
    pub authentication_key: Option<String>,
    pub chat_request_sha256: Option<String>,
    pub reader_request_sha256: Option<String>,
    pub registration_sha256: Option<String>,
    pub enrolled: bool,
    pub phase: Phase,
    pub failed_phase: Option<Phase>,
    pub revoke_requested: bool,
}
pub(super) struct Locked {
    pub configuration: Configuration,
    _lock: File,
}
impl Locked {
    pub fn open(configuration: &Configuration) -> Result<Self> {
        files::directory(&configuration.directory, false).map_err(|_| Error::State)?;
        let path = configuration.directory.join("Store.lock");
        let file = lock(&path)?;
        let result = Self {
            configuration: configuration.clone(),
            _lock: file,
        };
        if result.control()?.configuration_sha256 != configuration.pin()? {
            return Err(Error::State);
        }
        Ok(result)
    }
    pub fn control(&self) -> Result<Control> {
        read(&self.configuration.directory.join("Control.json"), 16384)
    }
    pub fn enable(&self, enabled: bool) -> Result<()> {
        write(
            &self.configuration.directory.join("Control.json"),
            &Control {
                configuration_sha256: self.configuration.pin()?,
                enabled,
            },
        )
    }
    pub fn load(&self, id: &str) -> Result<Record> {
        let r: Record = read(
            &self.configuration.record_directory(id)?.join("Record.json"),
            16384,
        )?;
        if r.id != id
            || !is_id(&r.secret_sha256)
            || r.access_expires_ms > self.configuration.metadata.access_expires_ms
            || r.expires_ms > r.access_expires_ms
        {
            return Err(Error::State);
        }
        Ok(r)
    }
    pub fn save(&self, r: &Record) -> Result<()> {
        write(
            &self
                .configuration
                .record_directory(&r.id)?
                .join("Record.json"),
            r,
        )
    }
    pub fn records(&self) -> Result<Vec<Record>> {
        let mut result = Vec::new();
        for (index, entry) in fs::read_dir(self.configuration.directory.join("Invitations"))
            .map_err(|_| Error::State)?
            .enumerate()
        {
            // Never hide committed records behind interrupted staging directories.
            if index >= 128 {
                return Err(Error::State);
            }
            let entry = entry.map_err(|_| Error::State)?;
            let name = entry.file_name();
            let id = name.to_str().ok_or(Error::State)?;
            if id.strip_prefix(".issuing-").is_some_and(is_id) {
                continue;
            }
            if !is_id(id) || !entry.file_type().map_err(|_| Error::State)?.is_dir() {
                return Err(Error::State);
            }
            result.push(self.load(id)?);
        }
        if result.len() > 64 {
            return Err(Error::State);
        }
        result.sort_by(|a, b| a.id.cmp(&b.id));
        Ok(result)
    }
    pub fn issue(&self, label: &str, expires_ms: u64) -> Result<Invitation> {
        let now = now_ms()?;
        if !self.control()?.enabled
            || self.records()?.len() >= self.configuration.maximum_invitations as usize
        {
            return Err(Error::Busy);
        }
        if label.is_empty()
            || label.len() > 96
            || label.chars().any(char::is_control)
            || expires_ms <= now
            || expires_ms > self.configuration.metadata.access_expires_ms
        {
            return Err(Error::Invalid);
        }
        let id = random()?;
        let secret = random()?;
        let directory = self.configuration.record_directory(&id)?;
        let pending = directory.with_file_name(format!(".issuing-{id}"));
        let ca = String::from_utf8(
            files::read(&self.configuration.certificate_authority, 16384)
                .map_err(|_| Error::State)?,
        )
        .map_err(|_| Error::State)?;
        let invitation = Invitation {
            format: INVITATION_FORMAT.into(),
            name: self.configuration.name.clone(),
            address: self.configuration.address,
            certificate_authority_pem: ca,
            server_certificate_sha256: self.configuration.certificate_sha256.clone(),
            network: self.configuration.metadata.network.clone(),
            incarnation: self.configuration.metadata.incarnation.clone(),
            bootstrap_sha256: self.configuration.metadata.bootstrap.sha256.clone(),
            bootstrap_fingerprint: self.configuration.metadata.bootstrap_fingerprint.clone(),
            id: id.clone(),
            secret,
            expires_ms,
            access_expires_ms: self.configuration.metadata.access_expires_ms,
        };
        let r = Record {
            id,
            label: label.into(),
            secret_sha256: digest(invitation.secret.as_bytes()),
            expires_ms,
            access_expires_ms: invitation.access_expires_ms,
            authentication_key: None,
            chat_request_sha256: None,
            reader_request_sha256: None,
            registration_sha256: None,
            enrolled: false,
            phase: Phase::Available,
            failed_phase: None,
            revoke_requested: false,
        };
        files::directory(&pending, true).map_err(|_| Error::State)?;
        files::directory(&pending.join("Native"), true).map_err(|_| Error::State)?;
        write(&pending.join("Record.json"), &r)?;
        // This operator-only export is the credential being delivered, never an API response.
        files::create(
            &pending.join("Invitation.txt"),
            client::invitation_code(&invitation)?.as_bytes(),
        )
        .map_err(|_| Error::State)?;
        fs::rename(&pending, &directory)
            .and_then(|()| {
                File::open(directory.parent().ok_or(std::io::ErrorKind::InvalidInput)?)?.sync_all()
            })
            .map_err(|_| Error::State)?;
        Ok(invitation)
    }
    pub fn delivery(&self, r: &Record) -> Result<Delivery> {
        read(
            &self
                .configuration
                .record_directory(&r.id)?
                .join("Delivery.json"),
            MAX_RESPONSE,
        )
    }
    pub fn response(&self, r: &Record) -> Result<Response> {
        if r.revoke_requested || r.phase == Phase::Revoked || r.access_expires_ms <= now_ms()? {
            return Err(Error::Expired);
        }
        match r.phase {
            Phase::Ready|Phase::Active=>Ok(Response::Ready{delivery:self.delivery(r)?,enrolled:r.enrolled}),
            Phase::Blocked=>Ok(Response::Refused{reason:"The host must inspect an unfinished native operation. Your keys and pending outcome were retained.".into()}),
            _=>Ok(Response::Pending{phase:r.phase.label().into(),retry_after_ms:1000}),
        }
    }
    pub fn request(&self, data: RequestData) -> Result<Response> {
        if !self.control()?.enabled {
            return Err(Error::Busy);
        }
        let mut r = self.load(&data.invitation_id)?;
        if r.revoke_requested || r.phase == Phase::Revoked || r.access_expires_ms <= now_ms()? {
            return Err(Error::Expired);
        }
        if r.authentication_key
            .as_ref()
            .is_some_and(|k| k != &data.authentication_key)
        {
            return Err(Error::Bound);
        }
        let directory = self.configuration.record_directory(&r.id)?;
        match data.action {
            Action::Inspect { secret } => {
                self.check_secret(&r, &secret)?;
                Ok(Response::Network {
                    metadata: self.configuration.metadata.clone(),
                })
            }
            Action::Redeem {
                secret,
                chat_request,
                reader_request,
            } => {
                self.check_secret(&r, &secret)?;
                let chat = chat_request.bytes(4096)?;
                let reader = reader_request.as_ref().map(|v| v.bytes(4096)).transpose()?;
                if reader.is_some() != self.configuration.metadata.reader_available
                    || reader.as_ref().is_some_and(|v| v == &chat)
                {
                    return Err(Error::Invalid);
                }
                if r.authentication_key.is_some() {
                    if r.chat_request_sha256.as_ref() != Some(&chat_request.sha256)
                        || r.reader_request_sha256
                            != reader_request.as_ref().map(|v| v.sha256.clone())
                    {
                        return Err(Error::Bound);
                    }
                } else {
                    exact(&directory.join("ChatRequest.cbor"), &chat)?;
                    if let Some(bytes) = reader {
                        exact(&directory.join("ReaderRequest.cbor"), &bytes)?;
                    }
                    r.authentication_key = Some(data.authentication_key);
                    r.chat_request_sha256 = Some(chat_request.sha256);
                    r.reader_request_sha256 = reader_request.map(|v| v.sha256);
                    r.phase = Phase::Admitting;
                    self.save(&r)?;
                }
                self.response(&r)
            }
            Action::Status => {
                self.check_bound(&r, &data.authentication_key)?;
                self.response(&r)
            }
            Action::Enrol { registration } => {
                self.check_bound(&r, &data.authentication_key)?;
                let bytes = registration.bytes(262144)?;
                if let Some(expected) = &r.registration_sha256
                    && expected != &registration.sha256
                {
                    return Err(Error::Bound);
                }
                if r.phase == Phase::Ready {
                    exact(&directory.join("Registration.cbor"), &bytes)?;
                    r.registration_sha256 = Some(registration.sha256);
                    r.phase = Phase::Enrolling;
                    self.save(&r)?;
                } else if !matches!(r.phase, Phase::Enrolling | Phase::Active | Phase::Blocked) {
                    return Err(Error::Invalid);
                }
                self.response(&r)
            }
            Action::Renew => {
                self.check_bound(&r, &data.authentication_key)?;
                if matches!(r.phase, Phase::Ready | Phase::Active)
                    && now_ms()? >= self.delivery(&r)?.renewal_after_ms
                {
                    r.phase = Phase::Renewing;
                    self.save(&r)?;
                } else if !matches!(
                    r.phase,
                    Phase::Ready | Phase::Active | Phase::Renewing | Phase::Blocked
                ) {
                    return Err(Error::Invalid);
                }
                self.response(&r)
            }
        }
    }
    fn check_secret(&self, r: &Record, secret: &str) -> Result<()> {
        if !is_id(secret)
            || !constant_equal(
                digest(secret.as_bytes()).as_bytes(),
                r.secret_sha256.as_bytes(),
            )
        {
            return Err(Error::Invalid);
        }
        if r.authentication_key.is_none() && now_ms()? >= r.expires_ms {
            return Err(Error::Expired);
        }
        Ok(())
    }
    fn check_bound(&self, r: &Record, key: &str) -> Result<()> {
        if r.authentication_key.as_deref() != Some(key) {
            return Err(Error::Bound);
        }
        Ok(())
    }
    pub fn revoke(&self, id: &str) -> Result<()> {
        let mut r = self.load(id)?;
        r.revoke_requested = true;
        if r.phase != Phase::Revoked {
            r.phase = if r.authentication_key.is_none() {
                Phase::Revoked
            } else {
                Phase::Revoking
            };
        }
        self.save(&r)
    }
}
fn constant_equal(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |v, (a, b)| v | (a ^ b)) == 0
}
pub(super) fn random() -> Result<String> {
    let mut bytes = [0u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| Error::State)?;
    Ok(hex::encode(bytes))
}
pub(super) fn lock(path: &Path) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK)
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
    Ok(file)
}
pub(super) fn read<T: DeserializeOwned>(path: &Path, maximum: usize) -> Result<T> {
    serde_json::from_slice(&files::read(path, maximum).map_err(|_| Error::State)?)
        .map_err(|_| Error::State)
}
pub(super) fn write(path: &Path, value: &impl Serialize) -> Result<()> {
    let bytes = serde_json::to_vec(value).map_err(|_| Error::State)?;
    if bytes.len() > MAX_RESPONSE {
        return Err(Error::State);
    }
    let parent = path.parent().ok_or(Error::State)?;
    files::directory(parent, false).map_err(|_| Error::State)?;
    if path.exists() {
        files::read(path, MAX_RESPONSE).map_err(|_| Error::State)?;
    }
    let temporary = parent.join(format!(".pending-{}", random()?));
    files::create(&temporary, &bytes).map_err(|_| Error::State)?;
    fs::rename(&temporary, path)
        .and_then(|()| File::open(parent)?.sync_all())
        .map_err(|_| Error::State)
}
pub(super) fn exact(path: &Path, bytes: &[u8]) -> Result<()> {
    if path.exists() {
        if files::read(path, MAX_RESPONSE).map_err(|_| Error::State)? != bytes {
            return Err(Error::Bound);
        }
        Ok(())
    } else {
        files::create(path, bytes).map_err(|_| Error::State)
    }
}

#[cfg(test)]
#[path = "../../Tests/Unit/SelfService/Store.rs"]
mod tests;
