// SPDX-License-Identifier: Apache-2.0
//! Offline drafts and unresolved-operation inspection do not require transport authority.
use super::{Profile, outbox};
use crate::{protocol::*, service::files};
use serde::Serialize;
use std::path::Path;
#[derive(Debug, thiserror::Error)]
#[error("local endpoint state is unavailable")]
pub struct Error;
pub fn save_draft(directory: &Path, room: RoomId, text: &str) -> std::result::Result<(), Error> {
    let profile = Profile::load(directory).map_err(|_| Error)?;
    if room.home != profile.active_server().home {
        return Err(Error);
    }
    let mut store = profile.store(directory).map_err(|_| Error)?;
    outbox::save_draft(&mut store, room, text).map_err(|_| Error)
}
pub fn draft(directory: &Path, room: RoomId) -> std::result::Result<Option<String>, Error> {
    let profile = Profile::load(directory).map_err(|_| Error)?;
    let mut store = profile.store(directory).map_err(|_| Error)?;
    outbox::draft(&mut store, room).map_err(|_| Error)
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Pending {
    operation_id: OperationId,
    action_digest: Id,
    operation: Operation,
    target: Target,
    outcome_known: bool,
    abandoned: bool,
    held: bool,
}
pub fn pending(directory: &Path) -> std::result::Result<Vec<Pending>, Error> {
    let profile = Profile::load(directory).map_err(|_| Error)?;
    let key = files::key(&directory.join("Endpoint.key")).map_err(|_| Error)?;
    let mut store = profile.store(directory).map_err(|_| Error)?;
    Ok(outbox::pending(&mut store, &key.verifying_key())
        .map_err(|_| Error)?
        .iter()
        .map(|p| Pending {
            operation_id: p.action.action().operation_id,
            action_digest: p.action.digest(),
            operation: p.action.action().operation,
            target: p.action.action().target.clone(),
            outcome_known: false,
            abandoned: p.abandoned,
            held: p.held,
        })
        .collect())
}

pub fn abandon(directory: &Path, id: OperationId, digest: Id) -> std::result::Result<(), Error> {
    let profile = Profile::load(directory).map_err(|_| Error)?;
    let mut store = profile.store(directory).map_err(|_| Error)?;
    outbox::abandon(&mut store, id, digest).map_err(|_| Error)
}
