// SPDX-License-Identifier: Apache-2.0
//! Closed endpoint lifecycle statements. Signatures prove possession, not current eligibility.
use super::*;
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DevicePurpose {
    Enrol,
    Recover,
    RotateRecovery,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ReplacementKeyProof {
    pub home: ServiceId,
    pub account: AccountId,
    pub request: Id,
    pub key: Id,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceRequest {
    pub home: ServiceId,
    pub account: AccountId,
    pub request: Id,
    pub endpoint: Id,
    pub endpoint_key: Id,
    pub principal: Id,
    pub purpose: DevicePurpose,
    pub created_ms: u64,
    pub expires_ms: u64,
    pub replacement: Option<Blob>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceChallenge {
    pub home: ServiceId,
    pub account: AccountId,
    pub request: Id,
    pub request_digest: Id,
    pub nonce: Id,
    pub service_boot: Id,
    pub principal: Id,
    pub session: Id,
    pub transport_generation: u64,
    pub security_generation: u64,
    pub account_revision: u64,
    pub recovery_generation: u64,
    pub recovery_key: Id,
    pub continuity_head: Id,
    pub recorded: bool,
    pub issued_ms: u64,
    pub expires_ms: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceProof {
    pub home: ServiceId,
    pub account: AccountId,
    pub request: Id,
    pub request_digest: Id,
    pub challenge_digest: Id,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceProofs {
    pub endpoint: Blob,
    pub recovery: Option<Blob>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceReceipt {
    pub home: ServiceId,
    pub account: AccountId,
    pub request: Id,
    pub request_digest: Id,
    pub outcome: Outcome,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointView {
    pub actor: EndpointActor,
    pub key: Id,
    pub principal: Id,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentitySnapshot {
    pub home: ServiceId,
    pub account: AccountId,
    pub classification: AccountClass,
    pub security_generation: u64,
    pub revision: u64,
    pub recovery_key: Id,
    pub recovery_generation: u64,
    pub head: Option<Id>,
    pub legacy_anchor: bool,
    pub endpoints: Vec<EndpointView>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum IdentityChange {
    Registered,
    LegacyServiceAnchor,
    EndpointEnrolled,
    EndpointDisabled,
    Recovered,
    RecoveryRotated,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContinuityRecord {
    pub index: u64,
    pub previous: Option<Id>,
    pub position: u64,
    pub change: IdentityChange,
    pub authorizations: Vec<Blob>,
    pub state: IdentitySnapshot,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DeviceActivated {
    pub identity: IdentitySnapshot,
    pub endpoint: Option<EndpointActor>,
}
