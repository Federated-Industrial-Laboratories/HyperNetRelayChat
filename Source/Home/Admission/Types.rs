// SPDX-License-Identifier: Apache-2.0
//! Public values for the private registrar and independently keyed participants.
use crate::{home::Invitation, protocol::*};
use serde::{Deserialize, Serialize};

pub const FORMAT: &str = "HyperNet.HrcAdmission/1";
pub const MAXIMUM: usize = 65_536;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Artifact {
    pub hex: String,
}
impl Artifact {
    pub fn new(bytes: &[u8]) -> Self {
        Self {
            hex: hex::encode(bytes),
        }
    }
    pub fn bytes(&self) -> Result<Vec<u8>> {
        if self.hex.is_empty()
            || self.hex.len() > 32_768
            || !self
                .hex
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::Invalid);
        }
        hex::decode(&self.hex).map_err(|_| Error::Invalid)
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Identity {
    pub account: AccountId,
    pub endpoint: Id,
    pub endpoint_key: Id,
    pub recovery_key: Id,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum Classification {
    Person,
    Agent { operator: AccountId },
}
impl Classification {
    pub fn account_class(&self) -> AccountClass {
        match self {
            Self::Person => AccountClass::Human,
            Self::Agent { operator } => AccountClass::Agent {
                operator: *operator,
            },
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Prepare {
    pub claim_id: Id,
    pub native_principal: Id,
    pub identity: Identity,
    pub classification: Classification,
    pub rooms: Vec<RoomId>,
    pub allow_initiate: bool,
    #[serde(default)]
    pub allow_agent_replies: bool,
    #[serde(default)]
    pub successor: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operator_consent: Option<Artifact>,
}
impl Prepare {
    pub fn registration(&self, home: ServiceId, invitation: Id) -> AccountRegistration {
        AccountRegistration {
            home,
            account: self.identity.account,
            endpoint: self.identity.endpoint,
            endpoint_key: self.identity.endpoint_key,
            transport_principal: self.native_principal,
            recovery_key: self.identity.recovery_key,
            classification: self.classification.account_class(),
            invitation,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Request {
    pub format: String,
    pub action: Action,
}
impl Request {
    pub fn new(action: Action) -> Self {
        Self {
            format: FORMAT.into(),
            action,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "camelCase", deny_unknown_fields)]
pub enum Action {
    Describe,
    Prepare(Box<Prepare>),
    Enrol {
        #[serde(rename = "claimId")]
        claim_id: Id,
        registration: Artifact,
    },
    RetiredClaims {
        #[serde(rename = "claimId")]
        claim_id: Id,
        after: Option<Id>,
    },
    Revoke {
        #[serde(rename = "claimId")]
        claim_id: Id,
    },
    Status {
        #[serde(rename = "claimId")]
        claim_id: Id,
    },
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Response {
    pub format: String,
    #[serde(flatten)]
    pub result: Status,
}
impl Response {
    pub fn new(result: Status) -> Self {
        Self {
            format: FORMAT.into(),
            result,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "camelCase", deny_unknown_fields)]
pub enum Status {
    Described {
        home: ServiceId,
        #[serde(rename = "serviceKey")]
        service_key: Id,
        policy: Policy,
    },
    Prepared {
        #[serde(rename = "claimId")]
        claim_id: Id,
        #[serde(rename = "requestDigest")]
        request_digest: Id,
        invitation: Invitation,
    },
    Complete {
        #[serde(rename = "claimId")]
        claim_id: Id,
        #[serde(rename = "registrationDigest")]
        registration_digest: Id,
        actor: EndpointActor,
    },
    Revoked {
        #[serde(rename = "claimId")]
        claim_id: Id,
        account: Option<AccountId>,
        #[serde(rename = "affectedClaimIds")]
        affected_claim_ids: Vec<Id>,
        #[serde(rename = "moreAffected")]
        more_affected: bool,
    },
    RetiredClaims {
        #[serde(rename = "claimId")]
        claim_id: Id,
        #[serde(rename = "affectedClaimIds")]
        affected_claim_ids: Vec<Id>,
        next: Option<Id>,
    },
    Refused {
        code: String,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Policy {
    pub enabled: bool,
    pub registrar_key: Id,
    pub rooms: Vec<RoomId>,
    pub agents_enabled: bool,
    pub max_agents_per_operator: u16,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Consent {
    pub request: Prepare,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ConsentReceipt {
    pub claim_id: Id,
    pub request_digest: Id,
    pub expires_ms: u64,
    pub operator_consent: Artifact,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgentAccess {
    pub account: AccountId,
    pub rooms: Vec<RoomId>,
    pub allow_initiate: bool,
    #[serde(default)]
    pub allow_agent_replies: bool,
    pub paused: bool,
    pub revoke: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Scope {
    pub rooms: Vec<RoomId>,
    pub allow_initiate: bool,
    #[serde(default)]
    pub allow_agent_replies: bool,
    pub paused: bool,
    pub revoked: bool,
    pub successor_of: Option<AccountId>,
}
