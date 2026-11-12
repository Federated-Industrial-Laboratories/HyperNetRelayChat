// SPDX-License-Identifier: Apache-2.0
//! Shared persistent client state for CLI, terminal, GUI and agents.
#[path = "Admission.rs"]
pub mod admission;
#[path = "ConversationRead.rs"]
mod conversation_read;
#[path = "HostSetup.rs"]
mod host_setup;
pub use conversation_read::ConversationPage;
#[path = "Approvals.rs"]
mod approvals;
pub use approvals::GrantPreview;
#[path = "Encrypted.rs"]
mod encrypted;
pub use encrypted::PreparedSend;
pub(crate) use encrypted::SendGuard;
#[path = "Archive.rs"]
mod archive;
#[path = "EncryptedHistory.rs"]
mod encrypted_history;
#[path = "Roster.rs"]
mod roster;
#[path = "TrustStore.rs"]
mod trust_store;
pub use archive::{CryptoView, MessageContent};
#[path = "Devices.rs"]
pub mod devices;
#[path = "Federation.rs"]
pub mod federation;
#[path = "Network.rs"]
pub mod network;
#[path = "Outbox.rs"]
pub mod outbox;
#[path = "Runtime.rs"]
mod runtime;
#[path = "Setup.rs"]
pub mod setup;
#[path = "Trust.rs"]
pub mod trust;
pub use runtime::{Client, Error, Result};
#[path = "Json.rs"]
pub mod json;
#[path = "Local.rs"]
pub mod local;
#[path = "View.rs"]
pub mod view;
use crate::{
    clock,
    protocol::{AccountRegistration, Id},
    service::{Descriptor, files},
    storage,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
pub use view::*;

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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub federation: Option<crate::protocol::AgreementRef>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub agreements: Vec<federation::Selection>,
}
pub(super) const PROFILE_BYTES: usize = 1024 * 1024;
impl Profile {
    pub fn load(directory: &Path) -> files::Result<Self> {
        files::directory(directory, false)?;
        let profile: Self = serde_json::from_slice(&files::read(
            &directory.join("Profile.json"),
            PROFILE_BYTES,
        )?)
        .map_err(|_| files::Invalid)?;
        profile.server.validate()?;
        let key = files::key(&directory.join("Endpoint.key"))?;
        if profile.registration.home != profile.server.home
            || profile.registration.endpoint_key != Id::from_bytes(key.verifying_key().to_bytes())
        {
            return Err(files::Invalid);
        }
        profile.validate_federation()?;
        Ok(profile)
    }
    pub fn active_server(&self) -> &Descriptor {
        self.selected_federation()
            .map_or(&self.server, |selection| &selection.home)
    }
    pub fn service_choices(&self) -> Vec<ServiceChoice> {
        let mut choices = vec![ServiceChoice {
            home: self.server.home,
            agreement: None,
            selected: self.federation.is_none(),
        }];
        choices.extend(
            self.agreements
                .iter()
                .filter(|a| a.origin.home == self.server.home)
                .map(|a| ServiceChoice {
                    home: a.home.home,
                    agreement: Some(a.agreement),
                    selected: self.federation == Some(a.agreement),
                }),
        );
        choices
    }
    pub fn selected_federation(&self) -> Option<&federation::Selection> {
        self.agreements
            .iter()
            .find(|selection| Some(selection.agreement) == self.federation)
    }
    fn validate_federation(&self) -> files::Result<()> {
        if self.agreements.len() > 2
            || self.federation.is_some() && self.selected_federation().is_none()
        {
            return Err(files::Invalid);
        }
        for (index, selection) in self.agreements.iter().enumerate() {
            selection.validate()?;
            if self.agreements[..index]
                .iter()
                .any(|other| other.agreement.id == selection.agreement.id)
                || ![&selection.home, &selection.origin].iter().any(|server| {
                    server.home == self.server.home && server.signing_key == self.server.signing_key
                })
                || Some(selection.agreement) == self.federation
                    && (selection.origin.home != self.server.home
                        || selection.origin.signing_key != self.server.signing_key)
            {
                return Err(files::Invalid);
            }
        }
        Ok(())
    }
    pub(super) fn identity_server(
        &self,
        origin: crate::protocol::NetworkId,
    ) -> files::Result<&Descriptor> {
        if self.server.home.network == origin {
            return Ok(&self.server);
        }
        let active = self.active_server().home;
        let mut matching = self
            .agreements
            .iter()
            .filter(|a| a.home.home == active && a.origin.home.network == origin)
            .map(|a| &a.origin);
        if active.network == origin {
            return Ok(self.active_server());
        }
        let first = matching.next().ok_or(files::Invalid)?;
        if matching.any(|other| other.home != first.home || other.signing_key != first.signing_key)
        {
            return Err(files::Invalid);
        }
        Ok(first)
    }
    pub fn store(&self, directory: &Path) -> storage::Result<storage::Store> {
        let key = storage::Key::load(directory.join("Database.key"))?;
        let mut store = storage::Store::open(
            directory.join("Data"),
            directory.join("Guard"),
            &key,
            *self.registration.endpoint.as_bytes(),
            storage_limits(),
        )?;
        outbox::migrate(&mut store)?;
        Ok(store)
    }
}

#[cfg(test)]
#[path = "../../Tests/Client/Workflow.rs"]
mod tests;

#[path = "Cache.rs"]
mod cache;

#[path = "Controller.rs"]
pub mod controller;
pub use controller::{Controller, DispatchError};
