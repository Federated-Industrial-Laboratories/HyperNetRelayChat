// SPDX-License-Identifier: Apache-2.0
//! Explicit local administration before service startup.
use super::{Config, Descriptor, files};
use crate::{
    clock,
    home::{Home, Invitation, RoomCreationPolicy, types::decode},
    protocol::*,
    storage,
};
use std::{
    fs,
    path::{Path, PathBuf},
    time::Duration,
};

#[derive(Debug, thiserror::Error)]
#[error("service administration failed; inspect retained state before retrying")]
pub struct Error;
pub type Result<T> = std::result::Result<T, Error>;
pub fn create(
    directory: &Path,
    home: ServiceId,
    companion: PathBuf,
    clock: clock::Config,
    motd: String,
) -> Result<Descriptor> {
    crate::home::ServiceInformation::new(motd.clone()).map_err(|_| Error)?;
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
        motd,
        room_creation: RoomCreationPolicy::default(),
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
/// Update only while the encrypted service store is exclusively held.
pub fn room_creation(directory: &Path, policy: RoomCreationPolicy) -> Result<RoomCreationPolicy> {
    let initial = Config::load(directory).map_err(|_| Error)?;
    let mut store = initial.store(directory).map_err(|_| Error)?;
    // A startup or another updater can have read configuration before acquiring the store.
    let mut config = Config::load(directory).map_err(|_| Error)?;
    if config.descriptor.home != initial.descriptor.home {
        return Err(Error);
    }
    policy
        .validate(config.descriptor.home.network)
        .map_err(|_| Error)?;
    if let RoomCreationPolicy::AllowList { accounts } = &policy {
        let human_accounts = store
            .read(Duration::from_secs(2), |db| {
                use rusqlite::OptionalExtension;
                for account in accounts {
                    let class: Option<Vec<u8>> = db
                        .query_row(
                            "SELECT class FROM hrc_accounts WHERE id=?1",
                            [account.to_string()],
                            |row| row.get(0),
                        )
                        .optional()?;
                    if class
                        .as_ref()
                        .and_then(|bytes| decode::<AccountClass>(bytes).ok())
                        != Some(AccountClass::Human)
                    {
                        return Ok(false);
                    }
                }
                Ok(true)
            })
            .map_err(|_| Error)?;
        if !human_accounts {
            return Err(Error);
        }
    }
    config.room_creation = policy.clone();
    let temporary = directory.join(format!(
        "RoomCreation-{}.json",
        Id::random().map_err(|_| Error)?
    ));
    let result = (|| {
        files::create_json(&temporary, &config).map_err(|_| Error)?;
        fs::rename(&temporary, directory.join("Service.json")).map_err(|_| Error)?;
        fs::File::open(directory)
            .and_then(|file| file.sync_all())
            .map_err(|_| Error)?;
        Ok(policy)
    })();
    let _ = fs::remove_file(temporary);
    result
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

/// Recover an operator-retained invitation after an interrupted output write.
pub fn invite_exact(
    directory: &Path,
    principal: Id,
    id: Id,
    expires_ms: u64,
) -> Result<Invitation> {
    let (config, mut home) = open(directory)?;
    home.issue_invitation_exact(
        id,
        principal,
        AccountClass::Human,
        expires_ms,
        config.clock.sample().map_err(|_| Error)?,
    )
    .map_err(|_| Error)
}

/// Exact retry returns the historical enrolment result; it never restores revoked authority.
pub fn enrol_exact(directory: &Path, bytes: &[u8]) -> Result<EndpointActor> {
    let registration = verify_registration_request(bytes).map_err(|_| Error)?;
    let (config, mut home) = open(directory)?;
    if let Some(actor) = home
        .registration_outcome(&registration)
        .map_err(|_| Error)?
    {
        return Ok(actor);
    }
    home.accept_registration(&registration, config.clock.sample().map_err(|_| Error)?)
        .map(|endpoint| endpoint.acting)
        .map_err(|_| Error)
}
