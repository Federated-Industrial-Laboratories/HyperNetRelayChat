// SPDX-License-Identifier: Apache-2.0
//! Fixed Suite handoff for locally prepared Agents and current-controller consent.
use super::{
    Error, Result, native,
    simple::{Binding, Joined},
};
use hrc::{
    home::admission::{Classification, ConsentReceipt, Prepare},
    protocol::*,
};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};
#[derive(Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Proposal {
    pub operator: AccountId,
    pub rooms: Vec<RoomId>,
    pub allow_initiate: bool,
    pub allow_agent_replies: bool,
    pub successor: bool,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Pending {
    pub agent_directory: PathBuf,
    pub runtime_configuration: PathBuf,
    pub request: Prepare,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Prepared {
    status: String,
    agent_directory: PathBuf,
    runtime_configuration: PathBuf,
    request: Prepare,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PendingList {
    status: String,
    agents: Vec<Pending>,
}
impl Pending {
    fn checked(self, operator: AccountId) -> Result<Self> {
        if self.request.classification != (Classification::Agent { operator })
            || self.request.operator_consent.is_some()
            || self.request.rooms.is_empty()
            || self.request.rooms.len() > 16
        {
            return Err(Error::CompanionBinding);
        }
        super::simple::absolute(&self.agent_directory)?;
        super::simple::absolute(&self.runtime_configuration)?;
        hrc::service::files::directory(&self.agent_directory, false)
            .map_err(|_| Error::LocalConfiguration)?;
        hrc::service::files::read(&self.runtime_configuration, 65536)
            .map_err(|_| Error::LocalConfiguration)?;
        Ok(self)
    }
    pub fn matches_consent(&self, receipt: &ConsentReceipt) -> bool {
        let Ok(value) = ciborium::Value::serialized(&self.request) else {
            return false;
        };
        canonical_encode(&value, CRYPTO_FRAME_BYTES).is_ok_and(|bytes| {
            receipt.claim_id == self.request.claim_id && receipt.request_digest == digest(&bytes)
        })
    }
}
pub fn prepare(binding: &Binding, proposal: &Proposal, cancel: &AtomicBool) -> Result<Pending> {
    let exe = std::env::current_exe().map_err(|_| Error::RuntimeMissing)?;
    native::executable(&exe)?;
    let response: Prepared = native::input_json(
        &binding.suite,
        &native::strings(&[
            "join",
            "agent",
            "prepare",
            "--directory",
            &native::path(&binding.directory)?,
            "--config",
            &native::path(&binding.runtime_configuration)?,
            "--hrc-executable",
            &native::path(&exe)?,
        ]),
        proposal,
        cancel,
        Some(Instant::now() + Duration::from_secs(120)),
    )?;
    if response.status != "ConsentRequired" {
        return Err(Error::Admission);
    }
    let request = &response.request;
    if request.rooms != proposal.rooms
        || request.allow_initiate != proposal.allow_initiate
        || request.allow_agent_replies != proposal.allow_agent_replies
        || request.successor != proposal.successor
    {
        return Err(Error::CompanionBinding);
    }
    Pending {
        agent_directory: response.agent_directory,
        runtime_configuration: response.runtime_configuration,
        request: response.request,
    }
    .checked(proposal.operator)
}
pub fn pending(
    binding: &Binding,
    operator: AccountId,
    cancel: &AtomicBool,
) -> Result<Vec<Pending>> {
    let response: PendingList = native::input_json(
        &binding.suite,
        &native::strings(&[
            "join",
            "agent",
            "pending",
            "--directory",
            &native::path(&binding.directory)?,
        ]),
        &serde_json::json!({}),
        cancel,
        Some(Instant::now() + Duration::from_secs(10)),
    )?;
    if response.status != "PendingAgents" || response.agents.len() > 8 {
        return Err(Error::Admission);
    }
    response
        .agents
        .into_iter()
        .map(|a| a.checked(operator))
        .collect()
}
pub fn complete(
    suite: &Path,
    pending: &Pending,
    receipt: &ConsentReceipt,
    cancel: &AtomicBool,
) -> Result<Joined> {
    if !pending.matches_consent(receipt) {
        return Err(Error::CompanionBinding);
    }
    let joined: Joined = native::input_json(
        suite,
        &native::strings(&[
            "join",
            "agent",
            "complete",
            "--directory",
            &native::path(&pending.agent_directory)?,
            "--config",
            &native::path(&pending.runtime_configuration)?,
        ]),
        receipt,
        cancel,
        Some(Instant::now() + Duration::from_secs(120)),
    )?;
    if joined.server_directory != pending.agent_directory
        || joined.runtime_configuration != pending.runtime_configuration
    {
        return Err(Error::CompanionBinding);
    }
    let joined = joined.checked(suite)?;
    let profile =
        hrc::client::Profile::load(&joined.hrc_profile).map_err(|_| Error::LocalConfiguration)?;
    if profile.registration
        != pending
            .request
            .registration(profile.server.home, profile.registration.invitation)
    {
        return Err(Error::CompanionBinding);
    }
    Ok(joined)
}
