// SPDX-License-Identifier: Apache-2.0
//! Explicit encrypted-room requests and public metadata; none establishes authority by construction.
use crate::{crypto::EndpointCredential, protocol::*};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Direct {
    pub recipient: AccountId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Invite {
    pub account: AccountId,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EnrolKey {
    pub mls_key: Id,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublishPackage {
    pub package: Blob,
    pub expires_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Initialise {
    pub group: Id,
    pub group_info: Blob,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommitEpoch {
    pub group: Id,
    pub epoch: u64,
    pub commit: Blob,
    pub additions: Vec<Id>,
    pub removals: Vec<Id>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Ready {
    pub group: Id,
    pub epoch: u64,
    pub commit_digest: Id,
    pub sequence: u64,
    pub welcome: Option<Blob>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransitionFailure {
    pub group: Id,
    pub epoch: u64,
    pub commit_digest: Id,
}

#[derive(Clone, Debug)]
pub struct Member {
    pub actor: Actor,
    pub credential: EndpointCredential,
    pub registration: Blob,
    pub delegation: Option<DelegationEvidence>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Package {
    pub digest: Id,
    pub member: Member,
    pub package: Blob,
    pub expires_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Inspection {
    pub room: RoomId,
    pub confidentiality: RoomConfidentiality,
    pub group: Option<Id>,
    pub epoch: u64,
    pub commit_digest: Option<Id>,
    pub sequence: u64,
    pub send_barrier: bool,
    pub frozen: bool,
    pub members: Vec<Member>,
    pub packages: Vec<Package>,
    pub required_removals: Vec<Id>,
    pub history_from_ms: u64,
    pub history_until_ms: u64,
    pub filter_revision: u64,
    pub ignored: Vec<AccountId>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Welcome {
    pub event: Id,
    pub group: Id,
    pub epoch: u64,
    pub commit_digest: Id,
    pub sequence: u64,
    pub package_digest: Id,
    pub welcome: Blob,
    pub members: Vec<Member>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TransitionEvent {
    pub group: Id,
    pub previous_epoch: Option<u64>,
    pub epoch: u64,
    pub commit: Blob,
    pub commit_digest: Id,
    pub members: Vec<Member>,
    pub additions: Vec<Id>,
    pub removals: Vec<Id>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DelegationEvidence {
    pub position: u64,
    pub grant: crate::delegation::Grant,
    pub authorization: Blob,
}
