// SPDX-License-Identifier: Apache-2.0
//! Shared persistent client state for CLI, terminal, GUI and agents.
#[path = "Network.rs"]
pub mod network;
#[path = "Outbox.rs"]
pub mod outbox;
#[path = "Runtime.rs"]
mod runtime;
#[path = "Setup.rs"]
pub mod setup;
pub use runtime::{Client, Error, Result};
#[path = "Json.rs"]
pub mod json;
#[path = "Local.rs"]
pub mod local;
use crate::{
    clock,
    protocol::{AccountRegistration, Id},
    service::{Descriptor, files},
    storage,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub(crate) fn storage_limits() -> storage::Limits {
    storage::Limits {
        max_database_bytes: 504 * 1024 * 1024,
        max_wal_bytes: 8 * 1024 * 1024,
        ..storage::Limits::default()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Profile {
    pub server: Descriptor,
    pub registration: AccountRegistration,
    pub companion: PathBuf,
    pub clock: clock::Config,
}
impl Profile {
    pub fn load(directory: &Path) -> files::Result<Self> {
        files::directory(directory, false)?;
        let profile: Self = files::json(&directory.join("Profile.json"))?;
        profile.server.validate()?;
        let key = files::key(&directory.join("Endpoint.key"))?;
        if profile.registration.home != profile.server.home
            || profile.registration.endpoint_key != Id::from_bytes(key.verifying_key().to_bytes())
        {
            return Err(files::Invalid);
        }
        Ok(profile)
    }
    pub fn store(&self, directory: &Path) -> storage::Result<storage::Store> {
        let key = storage::Key::load(directory.join("Database.key"))?;
        storage::Store::open(
            directory.join("Data"),
            directory.join("Guard"),
            &key,
            *self.registration.endpoint.as_bytes(),
            storage_limits(),
        )
    }
}

#[cfg(test)]
#[path = "../../Tests/Client/Workflow.rs"]
mod tests;
