// SPDX-License-Identifier: Apache-2.0
//! Local participant keys and exact registration retries; the registrar receives public values only.
use super::{Client, Error, Profile, Result, outbox};
use crate::{
    clock,
    home::{
        Invitation,
        admission::{Artifact, Classification, Consent, ConsentReceipt, Identity, Prepare},
    },
    protocol::*,
    service::{Descriptor, files},
    storage,
};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
pub const FORMAT: &str = "HyperNet.HrcParticipant/1";
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Options {
    pub server: Descriptor,
    pub claim_id: Id,
    pub native_principal: Id,
    pub classification: Classification,
    pub rooms: Vec<RoomId>,
    pub allow_initiate: bool,
    #[serde(default)]
    pub successor: bool,
    pub companion: PathBuf,
    pub clock: clock::Config,
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Pending {
    pub options: Options,
    pub request: Prepare,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub format: String,
    pub action: Action,
}
#[derive(Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "camelCase", deny_unknown_fields)]
pub enum Action {
    Prepare(Options),
    Registration { invitation: Invitation },
    Status,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Response {
    pub format: String,
    pub request: Prepare,
    pub profile_directory: PathBuf,
    pub registration: Option<Artifact>,
}
fn saved(directory: &Path) -> files::Result<Pending> {
    files::directory(directory, false)?;
    let saved: Pending = files::json(&directory.join("Participant.json"))?;
    let endpoint = files::key(&directory.join("Profile/Endpoint.key"))?;
    let recovery = files::key(&directory.join("Recovery.key"))?;
    if saved.request.identity.endpoint_key != Id::from_bytes(endpoint.verifying_key().to_bytes())
        || saved.request.identity.recovery_key
            != Id::from_bytes(recovery.verifying_key().to_bytes())
    {
        return Err(files::Invalid);
    }
    Ok(saved)
}
pub fn prepare(directory: &Path, mut options: Options) -> files::Result<Pending> {
    options.server.validate()?;
    options.rooms.sort();
    options.rooms.dedup();
    if options.rooms.is_empty()
        || options.rooms.len() > 16
        || options.rooms.iter().any(|r| r.home != options.server.home)
        || !options.companion.is_absolute()
    {
        return Err(files::Invalid);
    }
    if directory.exists() {
        files::directory(directory, false)?;
        let intent: Options = files::json(&directory.join("Intent.json"))?;
        if serde_json::to_vec(&intent).map_err(|_| files::Invalid)?
            != serde_json::to_vec(&options).map_err(|_| files::Invalid)?
        {
            return Err(files::Invalid);
        }
    } else {
        files::directory(directory, true)?;
        files::create_json(&directory.join("Intent.json"), &options)?;
    }
    if directory.join("Participant.json").exists() {
        let old = saved(directory)?;
        if serde_json::to_vec(&old.options).map_err(|_| files::Invalid)?
            != serde_json::to_vec(&options).map_err(|_| files::Invalid)?
        {
            return Err(files::Invalid);
        }
        ready(directory, &old)?;
        return Ok(old);
    }
    let profile = directory.join("Profile");
    files::directory(&profile, !profile.exists())?;
    let endpoint_path = profile.join("Endpoint.key");
    let endpoint = if endpoint_path.exists() {
        files::key(&endpoint_path)?
    } else {
        files::create_key(&endpoint_path)?
    };
    let recovery_path = directory.join("Recovery.key");
    let recovery = if recovery_path.exists() {
        files::key(&recovery_path)?
    } else {
        files::create_key(&recovery_path)?
    };
    let request = Prepare {
        claim_id: options.claim_id,
        native_principal: options.native_principal,
        identity: Identity {
            account: AccountId {
                origin: options.server.home.network,
                local: Id::random().map_err(|_| files::Invalid)?,
            },
            endpoint: Id::random().map_err(|_| files::Invalid)?,
            endpoint_key: Id::from_bytes(endpoint.verifying_key().to_bytes()),
            recovery_key: Id::from_bytes(recovery.verifying_key().to_bytes()),
        },
        classification: options.classification.clone(),
        rooms: options.rooms.clone(),
        allow_initiate: options.allow_initiate,
        successor: options.successor,
        operator_consent: None,
    };
    let pending = Pending { options, request };
    // Persist the public identity before initializing storage; a retry never generates new keys.
    files::create_json(&directory.join("Participant.json"), &pending)?;
    ready(directory, &pending)?;
    Ok(pending)
}
fn ready(directory: &Path, pending: &Pending) -> files::Result<()> {
    let marker = directory.join("Participant.ready");
    if marker.exists() {
        if files::json::<bool>(&marker)? {
            return Ok(());
        }
        return Err(files::Invalid);
    }
    let profile = directory.join("Profile");
    for name in ["Data", "Guard"] {
        let path = profile.join(name);
        files::directory(&path, !path.exists())?;
    }
    let key_path = profile.join("Database.key");
    let key = if key_path.exists() {
        storage::Key::load(&key_path)
    } else {
        storage::Key::create(&key_path)
    }
    .map_err(|_| files::Invalid)?;
    let mut store = if profile.join("Data/History.db").exists() {
        storage::Store::open(
            profile.join("Data"),
            profile.join("Guard"),
            &key,
            *pending.request.identity.endpoint.as_bytes(),
            super::storage_limits(),
        )
    } else {
        storage::Store::create(
            profile.join("Data"),
            profile.join("Guard"),
            &key,
            *pending.request.identity.endpoint.as_bytes(),
            super::storage_limits(),
        )
    }
    .map_err(|_| files::Invalid)?;
    outbox::initialize(&mut store).map_err(|_| files::Invalid)?;
    files::create_json(&marker, &true)
}
pub fn registration(directory: &Path, invitation: &Invitation) -> files::Result<Artifact> {
    let pending = saved(directory)?;
    ready(directory, &pending)?;
    if invitation.home != pending.options.server.home
        || invitation.service_key != pending.options.server.signing_key
        || invitation.principal != pending.request.native_principal
        || invitation.classification != pending.request.classification.account_class()
    {
        return Err(files::Invalid);
    }
    let profile = Profile {
        server: pending.options.server.clone(),
        registration: pending.request.registration(invitation.home, invitation.id),
        companion: pending.options.companion,
        clock: pending.options.clock,
        federation: None,
        agreements: vec![],
    };
    let endpoint = files::key(&directory.join("Profile/Endpoint.key"))?;
    let bytes = sign_registration(&profile.registration, &endpoint).map_err(|_| files::Invalid)?;
    let retained = directory.join("Registration.cbor");
    if retained.exists() {
        if files::read(&retained, 16_384)? != bytes {
            return Err(files::Invalid);
        }
    } else {
        if profile.clock.sample().map_err(|_| files::Invalid)?.upper_ms >= invitation.expires_ms {
            return Err(files::Invalid);
        }
        files::create(&retained, &bytes)?;
    }
    let profile_path = directory.join("Profile/Profile.json");
    if profile_path.exists() {
        if files::read(&profile_path, 16_384)?
            != serde_json::to_vec_pretty(&profile).map_err(|_| files::Invalid)?
        {
            return Err(files::Invalid);
        }
    } else {
        files::create_json(&profile_path, &profile)?;
    }
    Ok(Artifact::new(&bytes))
}
pub fn request(directory: &Path, input: Request) -> files::Result<Response> {
    if input.format != FORMAT {
        return Err(files::Invalid);
    }
    match input.action {
        Action::Prepare(options) => {
            prepare(directory, options)?;
        }
        Action::Registration { invitation } => {
            registration(directory, &invitation)?;
        }
        Action::Status => {}
    }
    let pending = saved(directory)?;
    ready(directory, &pending)?;
    let registration = if directory.join("Registration.cbor").exists() {
        Some(Artifact::new(&files::read(
            &directory.join("Registration.cbor"),
            16_384,
        )?))
    } else {
        None
    };
    Ok(Response {
        format: FORMAT.into(),
        request: pending.request,
        profile_directory: directory.join("Profile"),
        registration,
    })
}
impl Client {
    /// The current admitted operator authorizes this exact independently keyed Agent.
    pub fn consent_agent(&mut self, request: Prepare) -> Result<ConsentReceipt> {
        if request.successor && !self.pending()?.is_empty() {
            return Err(Error::Input);
        }
        if request.classification
            != (Classification::Agent {
                operator: self.profile.registration.account,
            })
        {
            return Err(Error::Input);
        }
        let response = self.call(
            Operation::AgentConsent,
            Target::Account(self.profile.registration.account),
            &Consent { request },
        )?;
        match response.outcome {
            Outcome::Committed { body, .. } => body.deserialized().map_err(|_| Error::Input),
            _ => Err(Error::Input),
        }
    }
}
