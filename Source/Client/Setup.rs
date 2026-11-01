// SPDX-License-Identifier: Apache-2.0
//! Owner-controlled endpoint creation and separately held account recovery keys.
use super::{Profile, outbox};
use crate::{
    clock,
    home::Invitation,
    protocol::*,
    service::{Descriptor, files},
    storage,
};
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
#[error("endpoint creation failed; existing keys and state were preserved")]
pub struct Error;
pub type Result<T> = std::result::Result<T, Error>;
pub fn create(
    directory: &Path,
    invitation_path: &Path,
    companion: PathBuf,
    clock: clock::Config,
    recovery_path: &Path,
    registration_path: &Path,
) -> Result<Profile> {
    let invitation: Invitation = files::json(invitation_path).map_err(|_| Error)?;
    let now = clock.sample().map_err(|_| Error)?;
    if now.upper_ms >= invitation.expires_ms || recovery_path.starts_with(directory) {
        return Err(Error);
    }
    let server = Descriptor {
        version: 1,
        home: invitation.home,
        signing_key: invitation.service_key,
        protocol: PROTOCOL.into(),
        text_profile: crate::text::PROFILE.into(),
    };
    server.validate().map_err(|_| Error)?;
    files::directory(directory, true).map_err(|_| Error)?;
    files::directory(&directory.join("Data"), true).map_err(|_| Error)?;
    files::directory(&directory.join("Guard"), true).map_err(|_| Error)?;
    let endpoint = files::create_key(&directory.join("Endpoint.key")).map_err(|_| Error)?;
    let recovery = files::create_key(recovery_path).map_err(|_| Error)?;
    let registration = AccountRegistration {
        home: invitation.home,
        account: AccountId {
            origin: invitation.home.network,
            local: Id::random().map_err(|_| Error)?,
        },
        endpoint: Id::random().map_err(|_| Error)?,
        endpoint_key: Id::from_bytes(endpoint.verifying_key().to_bytes()),
        transport_principal: invitation.principal,
        recovery_key: Id::from_bytes(recovery.verifying_key().to_bytes()),
        classification: invitation.classification,
        invitation: invitation.id,
    };
    let key = storage::Key::create(directory.join("Database.key")).map_err(|_| Error)?;
    let mut store = storage::Store::create(
        directory.join("Data"),
        directory.join("Guard"),
        &key,
        *registration.endpoint.as_bytes(),
        super::storage_limits(),
    )
    .map_err(|_| Error)?;
    outbox::initialize(&mut store).map_err(|_| Error)?;
    let profile = Profile {
        federation: None,
        agreements: Vec::new(),
        server,
        registration,
        companion,
        clock,
    };
    files::create_json(&directory.join("Profile.json"), &profile).map_err(|_| Error)?;
    let signed = sign_registration(&profile.registration, &endpoint).map_err(|_| Error)?;
    files::create(registration_path, &signed).map_err(|_| Error)?;
    Ok(profile)
}
