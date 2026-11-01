// SPDX-License-Identifier: Apache-2.0
//! Explicit local administration before service startup.
use super::{Config, Descriptor, files};
use crate::{
    clock,
    home::{Home, Invitation},
    protocol::*,
    storage,
};
use std::path::{Path, PathBuf};

#[derive(Debug, thiserror::Error)]
#[error("service administration failed; existing state was preserved")]
pub struct Error;
pub type Result<T> = std::result::Result<T, Error>;
pub fn create(
    directory: &Path,
    home: ServiceId,
    companion: PathBuf,
    clock: clock::Config,
) -> Result<Descriptor> {
    clock.sample().map_err(|_| Error)?;
    files::directory(directory, true).map_err(|_| Error)?;
    files::directory(&directory.join("Data"), true).map_err(|_| Error)?;
    files::directory(&directory.join("Guard"), true).map_err(|_| Error)?;
    let signer = files::create_key(&directory.join("Signing.key")).map_err(|_| Error)?;
    let key = storage::Key::create(directory.join("Database.key")).map_err(|_| Error)?;
    let descriptor = Descriptor {
        version: 1,
        home,
        signing_key: Id::from_bytes(signer.verifying_key().to_bytes()),
        protocol: PROTOCOL.into(),
        text_profile: crate::text::PROFILE.into(),
    };
    let config = Config {
        descriptor: descriptor.clone(),
        companion,
        clock,
    };
    let store = storage::Store::create(
        directory.join("Data"),
        directory.join("Guard"),
        &key,
        *home.service.as_bytes(),
        super::storage_limits(),
    )
    .map_err(|_| Error)?;
    Home::create(store, home, signer).map_err(|_| Error)?;
    files::create_json(&directory.join("Service.json"), &config).map_err(|_| Error)?;
    Ok(descriptor)
}
fn open(directory: &Path) -> Result<(Config, Home)> {
    let config = Config::load(directory).map_err(|_| Error)?;
    let signer = files::key(&directory.join("Signing.key")).map_err(|_| Error)?;
    let home = Home::open(
        config.store(directory).map_err(|_| Error)?,
        config.descriptor.home,
        signer,
    )
    .map_err(|_| Error)?;
    Ok((config, home))
}
pub fn invite(
    directory: &Path,
    principal: Id,
    classification: AccountClass,
    output: &Path,
) -> Result<Invitation> {
    let (config, mut home) = open(directory)?;
    let invitation = home
        .issue_invitation(
            principal,
            classification,
            config.clock.sample().map_err(|_| Error)?,
        )
        .map_err(|_| Error)?;
    files::create_json(output, &invitation).map_err(|_| Error)?;
    Ok(invitation)
}
pub fn enrol(directory: &Path, registration: &Path) -> Result<EndpointActor> {
    let bytes = files::read(registration, ORDINARY_FRAME_BYTES).map_err(|_| Error)?;
    let registration = verify_registration_request(&bytes).map_err(|_| Error)?;
    let (config, mut home) = open(directory)?;
    let endpoint = home
        .accept_registration(&registration, config.clock.sample().map_err(|_| Error)?)
        .map_err(|_| Error)?;
    Ok(endpoint.acting)
}
