// SPDX-License-Identifier: Apache-2.0
//! Retained bootstrap artifacts are private and never replace an existing identity.
use super::*;
use crate::{
    client,
    home::{Home, RoomCreationPolicy, admission::Classification},
    storage,
};
use std::time::Duration;

fn home(directory: &Path, options: &Options) -> Result<(service::Config, Home)> {
    files::directory(directory, !directory.exists())?;
    for name in ["Data", "Guard"] {
        let p = directory.join(name);
        files::directory(&p, !p.exists())?;
    }
    let signer = key(&directory.join("Signing.key"))?;
    let key_path = directory.join("Database.key");
    let database = if key_path.exists() {
        storage::Key::load(&key_path)
    } else {
        storage::Key::create(&key_path)
    }
    .map_err(|_| Error::Unconfirmed)?;
    let mut store = if directory.join("Data/History.db").exists() {
        storage::Store::open(
            directory.join("Data"),
            directory.join("Guard"),
            &database,
            *options.home.service.as_bytes(),
            service::storage_limits(),
        )
    } else {
        storage::Store::create(
            directory.join("Data"),
            directory.join("Guard"),
            &database,
            *options.home.service.as_bytes(),
            service::storage_limits(),
        )
    }
    .map_err(|_| Error::Unconfirmed)?;
    let initialized = store
        .read(Duration::from_secs(2), |db| {
            db.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='hrc_meta')",
                [],
                |r| r.get::<_, bool>(0),
            )
        })
        .map_err(|_| Error::Unconfirmed)?;
    let home = if initialized {
        Home::open(store, options.home, signer.clone())
    } else {
        Home::create(store, options.home, signer.clone())
    }
    .map_err(|_| Error::Unconfirmed)?;
    let config = service::Config {
        descriptor: service::Descriptor {
            version: 1,
            home: options.home,
            signing_key: Id::from_bytes(signer.verifying_key().to_bytes()),
            protocol: PROTOCOL.into(),
            text_profile: crate::text::PROFILE.into(),
        },
        companion: options.receiver_companion.clone(),
        clock: options.clock.clone(),
        motd: options.motd.clone(),
        room_creation: RoomCreationPolicy::AllowList { accounts: vec![] },
    };
    Ok((config, home))
}
pub(super) fn prepare(directory: &Path, options: &Options) -> Result<()> {
    if directory.join("Prepared.json").exists() {
        verify(directory, options)?;
        return Ok(());
    }
    let (mut config, mut home) = home(&directory.join("Home"), options)?;
    let invitation_path = directory.join("OwnerInvitationId.json");
    let id = if invitation_path.exists() {
        files::json(&invitation_path)?
    } else {
        let id = Id::random().map_err(|_| Error::Unconfirmed)?;
        exact(&invitation_path, &id)?;
        id
    };
    let pending = client::admission::prepare_owner(
        &directory.join("Owner"),
        client::admission::Options {
            server: config.descriptor.clone(),
            claim_id: id,
            native_principal: options.owner_principal,
            classification: Classification::Person,
            rooms: vec![],
            allow_initiate: true,
            allow_agent_replies: false,
            successor: false,
            companion: options.owner_companion.clone(),
            clock: options.clock.clone(),
        },
    )?;
    let registration_path = directory.join("Owner/Registration.cbor");
    let registered = if registration_path.exists() {
        let registration = verify_registration_request(&files::read(&registration_path, 16384)?)
            .map_err(|_| Error::Configuration)?;
        home.registration_outcome(&registration)
            .map_err(|_| Error::Unconfirmed)?
            .is_some()
    } else {
        false
    };
    if !registered {
        // This private bootstrap is only for an empty Home. An exact retry cannot
        // admit a second owner or restore a previously disabled endpoint.
        let now = options.clock.sample().map_err(|_| Error::Clock)?;
        let expires = now.lower_ms.saturating_add(86_400_000);
        let principal = options.owner_principal;
        home.store.write(|db| {
            let count: u64=db.query_row("SELECT count(*) FROM hrc_accounts", [], |r| r.get(0))?;
            if count != 0 { return Err(rusqlite::Error::InvalidQuery); }
            let class=crate::home::types::encode(&AccountClass::Human)?;
            // Only the retained unused owner invitation may be renewed locally.
            db.execute("UPDATE hrc_invitations SET expires=?1 WHERE id=?2 AND principal=?3 AND class=?4 AND used=0", rusqlite::params![expires,id.as_hex(),principal.as_hex(),class])?;
            Ok(storage::Commit::new((), b"HRC.Host.OwnerInvitation".to_vec()))
        }).map_err(|_| Error::Unconfirmed)?;
        let invitation = home
            .issue_invitation_exact(
                id,
                principal,
                AccountClass::Human,
                expires,
                options.clock.sample().map_err(|_| Error::Clock)?,
            )
            .map_err(|_| Error::Unconfirmed)?;
        let registration = client::admission::registration(&directory.join("Owner"), &invitation)?
            .bytes()
            .map_err(|_| Error::Configuration)?;
        let registration =
            verify_registration_request(&registration).map_err(|_| Error::Configuration)?;
        home.accept_registration(
            &registration,
            options.clock.sample().map_err(|_| Error::Clock)?,
        )
        .map_err(|_| Error::Unconfirmed)?;
    }
    drop(home);
    config.room_creation = RoomCreationPolicy::AllowList {
        accounts: vec![pending.request.identity.account],
    };
    exact(&directory.join("Home/Service.json"), &config)?;
    let registrar = key(&directory.join("Registrar.key"))?;
    if registrar.verifying_key().to_bytes() == *config.descriptor.signing_key.as_bytes() {
        return Err(Error::Configuration);
    }
    exact(
        &directory.join("Registrar.json"),
        &service::live_admission::Binding {
            directory: directory.join("Home"),
            home: options.home,
            service_key: config.descriptor.signing_key,
            registrar_key_file: directory.join("Registrar.key"),
        },
    )?;
    exact(&directory.join("Prepared.json"), &config.descriptor)?;
    verify(directory, options)?;
    Ok(())
}
pub(super) fn verify(directory: &Path, options: &Options) -> Result<service::Descriptor> {
    let config = service::Config::load(&directory.join("Home"))?;
    let descriptor: service::Descriptor = files::json(&directory.join("Prepared.json"))?;
    if serde_json::to_vec(&descriptor).map_err(|_| Error::Configuration)?
        != serde_json::to_vec(&config.descriptor).map_err(|_| Error::Configuration)?
        || config.descriptor.home != options.home
        || config.companion != options.receiver_companion
        || config.clock.observation != options.clock.observation
        || config.clock.monitor_key != options.clock.monitor_key
    {
        return Err(Error::Configuration);
    }
    let profile = client::Profile::load(&directory.join("Owner/Profile"))?;
    let recovery = files::key(&directory.join("Owner/Recovery.key"))?;
    if profile.server.home != options.home
        || profile.server.signing_key != descriptor.signing_key
        || profile.registration.classification != AccountClass::Human
        || profile.registration.transport_principal != options.owner_principal
        || profile.registration.recovery_key != Id::from_bytes(recovery.verifying_key().to_bytes())
        || profile.companion != options.owner_companion
        || profile.clock.observation != options.clock.observation
        || profile.clock.monitor_key != options.clock.monitor_key
        || config.room_creation
            != (RoomCreationPolicy::AllowList {
                accounts: vec![profile.registration.account],
            })
    {
        return Err(Error::Configuration);
    }
    let binding: service::live_admission::Binding = files::json(&directory.join("Registrar.json"))?;
    files::key(&binding.registrar_key_file)?;
    if binding.directory != directory.join("Home")
        || binding.home != options.home
        || binding.service_key != descriptor.signing_key
        || binding.registrar_key_file != directory.join("Registrar.key")
    {
        return Err(Error::Configuration);
    }
    Ok(descriptor)
}
