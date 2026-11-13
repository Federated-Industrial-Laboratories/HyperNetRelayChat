// SPDX-License-Identifier: Apache-2.0
//! HRC service setup and its HyperNet-only transport lifecycle.
#[path = "Admission.rs"]
mod admission;
#[path = "FederationSetup.rs"]
pub mod federation;
#[path = "Files.rs"]
pub mod files;
#[path = "Host/Mod.rs"]
pub mod host;
#[path = "Io.rs"]
pub mod io;
#[path = "LiveAdmission.rs"]
pub mod live_admission;
#[path = "Runtime.rs"]
pub mod runtime;
#[path = "Setup.rs"]
pub mod setup;
use crate::{
    clock,
    protocol::{Id, ServiceId},
    storage,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub(crate) fn storage_limits() -> storage::Limits {
    storage::Limits {
        max_database_bytes: 10 * 1024 * 1024 * 1024 - 64 * 1024 * 1024,
        max_wal_bytes: 64 * 1024 * 1024,
        ..storage::Limits::default()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Descriptor {
    pub version: u64,
    pub home: ServiceId,
    pub signing_key: Id,
    pub protocol: String,
    pub text_profile: String,
}
impl Descriptor {
    pub fn validate(&self) -> files::Result<()> {
        if self.version != 1
            || self.protocol != "hrc/1"
            || self.text_profile != crate::text::PROFILE
        {
            return Err(files::Invalid);
        }
        let key = ed25519_dalek::VerifyingKey::from_bytes(self.signing_key.as_bytes())
            .map_err(|_| files::Invalid)?;
        if key.is_weak() {
            return Err(files::Invalid);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Config {
    pub descriptor: Descriptor,
    pub companion: PathBuf,
    pub clock: clock::Config,
    #[serde(default)]
    pub motd: String,
    #[serde(default)]
    pub room_creation: crate::home::RoomCreationPolicy,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub admission_bridge: Option<live_admission::Bridge>,
}
impl Config {
    pub fn load(directory: &Path) -> files::Result<Self> {
        files::directory(directory, false)?;
        let value: Self = files::json(&directory.join("Service.json"))?;
        value.descriptor.validate()?;
        if let Some(bridge) = &value.admission_bridge {
            bridge.validate()?;
            if bridge.directory.starts_with(directory) || directory.starts_with(&bridge.directory) {
                return Err(files::Invalid);
            }
        }
        value
            .room_creation
            .validate(value.descriptor.home.network)
            .map_err(|_| files::Invalid)?;
        crate::home::ServiceInformation::new(value.motd.clone()).map_err(|_| files::Invalid)?;
        let key = files::key(&directory.join("Signing.key"))?;
        if key.verifying_key().to_bytes() != *value.descriptor.signing_key.as_bytes() {
            return Err(files::Invalid);
        }
        Ok(value)
    }
    pub fn store(&self, directory: &Path) -> storage::Result<storage::Store> {
        let key = storage::Key::load(directory.join("Database.key"))?;
        storage::Store::open(
            directory.join("Data"),
            directory.join("Guard"),
            &key,
            *self.descriptor.home.service.as_bytes(),
            storage_limits(),
        )
    }
}
