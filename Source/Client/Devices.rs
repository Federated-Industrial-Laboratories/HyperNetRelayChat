// SPDX-License-Identifier: Apache-2.0
//! Persistent new-device intent and proof exchange without copying owner recovery secrets.
use super::{Profile, outbox};
use crate::{
    clock,
    hypernet::{Companion, Peer},
    protocol::*,
    service::{Descriptor, files, io},
    storage::{self, Commit},
};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("private device request configuration is unavailable")]
    Configuration,
    #[error("current device admission authority is unavailable")]
    Authority,
    #[error("device identity proof failed")]
    Binding,
    #[error("device transition outcome is unknown")]
    Unknown,
    #[error("device state could not be persisted")]
    Storage,
    #[error("device transition was refused: {0}")]
    Refused(String),
}
pub type Result<T> = std::result::Result<T, Error>;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PendingDevice {
    pub server: Descriptor,
    pub request: DeviceRequest,
    pub companion: PathBuf,
    pub clock: clock::Config,
}
pub struct Prepare<'a> {
    pub directory: &'a Path,
    pub server: &'a Path,
    pub account: AccountId,
    pub principal: Id,
    pub companion: PathBuf,
    pub clock: clock::Config,
    pub purpose: DevicePurpose,
    pub replacement: Option<&'a Path>,
    pub request_output: &'a Path,
}
pub fn prepare(options: Prepare<'_>) -> Result<PendingDevice> {
    let server: Descriptor = files::json(options.server).map_err(|_| Error::Configuration)?;
    server.validate().map_err(|_| Error::Configuration)?;
    if options.account.origin != server.home.network
        || options
            .replacement
            .is_some_and(|p| p.starts_with(options.directory))
    {
        return Err(Error::Configuration);
    }
    let now = options.clock.sample().map_err(|_| Error::Authority)?;
    let request_id = Id::random().map_err(|_| Error::Configuration)?;
    let replacement = if let Some(path) = options.replacement {
        let key = files::key(path).map_err(|_| Error::Configuration)?;
        Some(Blob(
            sign_replacement_key(
                &ReplacementKeyProof {
                    home: server.home,
                    account: options.account,
                    request: request_id,
                    key: Id::from_bytes(key.verifying_key().to_bytes()),
                },
                &key,
            )
            .map_err(|_| Error::Binding)?,
        ))
    } else {
        None
    };
    files::directory(options.directory, true).map_err(|_| Error::Configuration)?;
    files::directory(&options.directory.join("Data"), true).map_err(|_| Error::Configuration)?;
    files::directory(&options.directory.join("Guard"), true).map_err(|_| Error::Configuration)?;
    let key = files::create_key(&options.directory.join("Endpoint.key"))
        .map_err(|_| Error::Configuration)?;
    let request = DeviceRequest {
        home: server.home,
        account: options.account,
        request: request_id,
        endpoint: Id::random().map_err(|_| Error::Configuration)?,
        endpoint_key: Id::from_bytes(key.verifying_key().to_bytes()),
        principal: options.principal,
        purpose: options.purpose,
        created_ms: now.lower_ms,
        expires_ms: now.lower_ms + 86_400_000,
        replacement,
    };
    let bytes = sign_device_request(&request, &key).map_err(|_| Error::Configuration)?;
    let database =
        storage::Key::create(options.directory.join("Database.key")).map_err(|_| Error::Storage)?;
    let mut store = storage::Store::create(
        options.directory.join("Data"),
        options.directory.join("Guard"),
        &database,
        *request.endpoint.as_bytes(),
        super::storage_limits(),
    )
    .map_err(|_| Error::Storage)?;
    outbox::initialize(&mut store).map_err(|_| Error::Storage)?;
    store.write(|db|{db.execute_batch("CREATE TABLE client_device_receipt(singleton INTEGER PRIMARY KEY CHECK(singleton=1),receipt BLOB NOT NULL)")?;Ok(Commit::new((),b"HRC.Device.Profile.1".to_vec()))}).map_err(|_|Error::Storage)?;
    let pending = PendingDevice {
        server,
        request,
        companion: options.companion,
        clock: options.clock,
    };
    files::create_json(&options.directory.join("PendingDevice.json"), &pending)
        .map_err(|_| Error::Configuration)?;
    files::create(&options.directory.join("DeviceRequest.cbor"), &bytes)
        .map_err(|_| Error::Configuration)?;
    files::create(options.request_output, &bytes).map_err(|_| Error::Configuration)?;
    Ok(pending)
}
pub fn activate(directory: &Path, recovery: Option<&Path>) -> Result<DeviceReceipt> {
    files::directory(directory, false).map_err(|_| Error::Configuration)?;
    if recovery.is_some_and(|p| p.starts_with(directory)) {
        return Err(Error::Configuration);
    }
    let pending: PendingDevice =
        files::json(&directory.join("PendingDevice.json")).map_err(|_| Error::Configuration)?;
    pending
        .server
        .validate()
        .map_err(|_| Error::Configuration)?;
    let key = files::key(&directory.join("Endpoint.key")).map_err(|_| Error::Configuration)?;
    let bytes = files::read(&directory.join("DeviceRequest.cbor"), ORDINARY_FRAME_BYTES)
        .map_err(|_| Error::Configuration)?;
    let request =
        verify_device_request(&bytes, &key.verifying_key()).map_err(|_| Error::Binding)?;
    if request.value() != &pending.request || pending.server.home != pending.request.home {
        return Err(Error::Binding);
    }
    if request.value().endpoint_key.as_bytes() != key.verifying_key().as_bytes() {
        return Err(Error::Binding);
    }
    let recovery = recovery
        .map(files::key)
        .transpose()
        .map_err(|_| Error::Configuration)?;
    let database =
        storage::Key::load(directory.join("Database.key")).map_err(|_| Error::Storage)?;
    let mut store = storage::Store::open(
        directory.join("Data"),
        directory.join("Guard"),
        &database,
        *pending.request.endpoint.as_bytes(),
        super::storage_limits(),
    )
    .map_err(|_| Error::Storage)?;
    let saved: Option<Vec<u8>> = store
        .read(Duration::from_secs(1), |db| {
            use rusqlite::OptionalExtension;
            db.query_row(
                "SELECT receipt FROM client_device_receipt WHERE singleton=1",
                [],
                |r| r.get(0),
            )
            .optional()
        })
        .map_err(|_| Error::Storage)?;
    let server_key = VerifyingKey::from_bytes(pending.server.signing_key.as_bytes())
        .map_err(|_| Error::Binding)?;
    let receipt = if let Some(saved) = saved {
        verify_device_receipt(&saved, &server_key).map_err(|_| Error::Binding)?
    } else {
        let companion = Companion::new(&pending.companion).map_err(|_| Error::Authority)?;
        let stream = companion
            .connect(
                &pending.server.home.service.as_hex(),
                PROTOCOL,
                Duration::from_secs(10),
            )
            .map_err(|_| Error::Authority)?;
        if !matches!(stream.peer(), Peer::Outgoing(_))
            || stream.peer().network() != pending.server.home.network.network.as_hex()
            || stream.peer().incarnation() != pending.server.home.network.incarnation.as_hex()
            || stream.peer().service() != pending.server.home.service.as_hex()
            || stream.peer().protocol() != PROTOCOL
        {
            return Err(Error::Binding);
        }
        let end = clock::boot_ms().map_err(|_| Error::Authority)? + 5000;
        let remaining = || {
            let now = clock::boot_ms().map_err(|_| Error::Authority)?;
            if now >= end {
                Err(Error::Unknown)
            } else {
                Ok(Duration::from_millis(end - now))
            }
        };
        io::send(
            &stream,
            &Frame::new(FrameKind::DeviceHello, bytes).map_err(|_| Error::Binding)?,
            remaining()?,
        )
        .map_err(|_| Error::Unknown)?;
        let frame = io::receive(&stream, remaining()?).map_err(|_| Error::Unknown)?;
        if frame.kind != FrameKind::DeviceChallenge {
            return Err(Error::Binding);
        }
        let challenge =
            verify_device_challenge(&frame.payload, &server_key).map_err(|_| Error::Binding)?;
        let c = challenge.value();
        let now = pending.clock.sample().map_err(|_| Error::Authority)?;
        if c.home != pending.server.home
            || c.account != request.value().account
            || c.request != request.value().request
            || c.request_digest != request.digest()
            || c.principal != request.value().principal
            || c.session.as_hex() != stream.peer().session()
            || c.transport_generation != stream.peer().generation()
            || now.upper_ms >= c.expires_ms
            || c.expires_ms > now.upper_ms + 5000
        {
            return Err(Error::Binding);
        }
        let proof = DeviceProof {
            home: c.home,
            account: c.account,
            request: c.request,
            request_digest: c.request_digest,
            challenge_digest: challenge.digest(),
        };
        let owner = if c.recorded || request.value().purpose == DevicePurpose::Enrol {
            None
        } else {
            let key = recovery.as_ref().ok_or(Error::Configuration)?;
            if key.verifying_key().as_bytes() != c.recovery_key.as_bytes() {
                return Err(Error::Binding);
            }
            Some(Blob(
                sign_device_proof(&proof, key).map_err(|_| Error::Binding)?,
            ))
        };
        let proofs = DeviceProofs {
            endpoint: Blob(sign_device_proof(&proof, &key).map_err(|_| Error::Binding)?),
            recovery: owner,
        };
        let bytes = canonical_encode(
            &Value::serialized(&proofs).map_err(|_| Error::Binding)?,
            ORDINARY_FRAME_BYTES,
        )
        .map_err(|_| Error::Binding)?;
        io::send(
            &stream,
            &Frame::new(FrameKind::DeviceProof, bytes).map_err(|_| Error::Binding)?,
            remaining()?,
        )
        .map_err(|_| Error::Unknown)?;
        let frame = io::receive(&stream, remaining()?).map_err(|_| Error::Unknown)?;
        if frame.kind != FrameKind::DeviceReceipt {
            return Err(Error::Binding);
        }
        let receipt =
            verify_device_receipt(&frame.payload, &server_key).map_err(|_| Error::Binding)?;
        let r = receipt.value();
        if r.home != pending.server.home
            || r.account != request.value().account
            || r.request != request.value().request
            || r.request_digest != request.digest()
        {
            return Err(Error::Binding);
        }
        if matches!(r.outcome, Outcome::Committed { .. }) {
            store
                .write(|db| {
                    db.execute(
                        "INSERT INTO client_device_receipt VALUES(1,?1)",
                        [receipt.signed_bytes()],
                    )?;
                    Ok(Commit::new((), receipt.digest().as_bytes().to_vec()))
                })
                .map_err(|_| Error::Storage)?;
        }
        receipt
    };
    let response = receipt.value();
    if response.home != pending.server.home
        || response.account != request.value().account
        || response.request != request.value().request
        || response.request_digest != request.digest()
    {
        return Err(Error::Binding);
    }
    match &receipt.value().outcome {
        Outcome::Committed { body, .. } => {
            let result: DeviceActivated = body.deserialized().map_err(|_| Error::Binding)?;
            if result.identity.home != pending.server.home
                || result.identity.account != pending.request.account
            {
                return Err(Error::Binding);
            }
            if let Some(actor) = result.endpoint {
                if actor.account != pending.request.account
                    || actor.endpoint != pending.request.endpoint
                {
                    return Err(Error::Binding);
                }
                let profile = Profile {
                    federation: None,
                    agreements: Vec::new(),
                    server: pending.server.clone(),
                    registration: AccountRegistration {
                        home: pending.server.home,
                        account: actor.account,
                        endpoint: actor.endpoint,
                        endpoint_key: pending.request.endpoint_key,
                        transport_principal: pending.request.principal,
                        recovery_key: result.identity.recovery_key,
                        classification: result.identity.classification,
                        invitation: pending.request.request,
                    },
                    companion: pending.companion,
                    clock: pending.clock,
                };
                let path = directory.join("Profile.json");
                if path.exists() {
                    let old = Profile::load(directory).map_err(|_| Error::Configuration)?;
                    if old.registration != profile.registration {
                        return Err(Error::Binding);
                    }
                } else {
                    files::create_json(&path, &profile).map_err(|_| Error::Storage)?;
                }
            }
        }
        Outcome::Refused { detail, .. } | Outcome::Rejected { detail, .. } => {
            return Err(Error::Refused(detail.clone()));
        }
        _ => return Err(Error::Unknown),
    }
    Ok(receipt.value().clone())
}
