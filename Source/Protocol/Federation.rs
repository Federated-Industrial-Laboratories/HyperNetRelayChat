// SPDX-License-Identifier: Apache-2.0
//! Federation evidence is untrusted data until its signer and current scope are checked.
use super::*;
use serde::{Deserialize, Serialize};

pub const FEDERATION_PROFILE: u64 = 1;
pub const FEDERATION_CAPABILITY: &str = "federation-runtime-1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AdmissionRef {
    pub id: Id,
    pub revision: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum FederationSubject {
    Action {
        action_digest: Id,
        operation_id: OperationId,
    },
    Session {
        request_digest: Id,
        request: Id,
    },
}
impl FederationSubject {
    pub fn digest(&self) -> Id {
        match self {
            Self::Action { action_digest, .. } => *action_digest,
            Self::Session { request_digest, .. } => *request_digest,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GatewayBinding {
    pub network: NetworkId,
    pub destination: ServiceId,
    pub principal: Id,
    pub service_endpoint: Id,
    pub signing_key: Id,
    pub protocol: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum GatewayMessage {
    Hello {
        profile: u64,
        agreement: AgreementRef,
        gateway: Id,
        receiver: ServiceId,
        client_nonce: Id,
    },
    Challenge {
        profile: u64,
        agreement: AgreementRef,
        gateway: Id,
        receiver: ServiceId,
        client_nonce: Id,
        server_nonce: Id,
        service_boot: Id,
        principal: Id,
        session: Id,
        transport_generation: u64,
        issued_ms: u64,
        expires_ms: u64,
    },
    Proof {
        profile: u64,
        agreement: AgreementRef,
        challenge_digest: Id,
    },
    Ready {
        profile: u64,
        agreement: AgreementRef,
        challenge_digest: Id,
        service_boot: Id,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RemoteSessionRequest {
    pub profile: u64,
    pub home: ServiceId,
    pub origin: ServiceId,
    pub agreement: AgreementRef,
    pub request: Id,
    pub account: AccountId,
    pub endpoint: Id,
    pub endpoint_binding_digest: Id,
    pub client_nonce: Id,
    pub created_ms: u64,
    pub expires_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CheckpointRef {
    pub account: AccountId,
    pub checkpoint_digest: Id,
}

/// A short origin identity observation; it is not a HyperNet transport permit.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct IdentityFreshness {
    pub profile: u64,
    pub home: ServiceId,
    pub origin: ServiceId,
    pub agreement: AgreementRef,
    pub checkpoints: Vec<CheckpointRef>,
    pub issued_ms: u64,
    pub expires_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FederationRelay {
    Unknown,
    ApprovedAttachment,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum FederationProtection {
    Tls13FinalService,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederationPrivacy {
    pub endpoint_mode: Option<u8>,
    pub transport_protection: Option<FederationProtection>,
    pub relay_arrival: FederationRelay,
    pub relay_service: Option<Id>,
    pub attachment_profile_digest: Option<Id>,
    pub provenance: String,
    pub physical_independence_verified: bool,
    pub profile_currentness_asserted: bool,
}
impl FederationPrivacy {
    pub fn validate(&self) -> Result<()> {
        if self.provenance != "endpointAttestedArrival"
            || self.physical_independence_verified
            || self.profile_currentness_asserted
            || self.transport_protection != Some(FederationProtection::Tls13FinalService)
        {
            return Err(Error::Invalid);
        }
        match (
            &self.endpoint_mode,
            &self.relay_arrival,
            &self.relay_service,
            &self.attachment_profile_digest,
        ) {
            (Some(2), FederationRelay::Unknown, None, None)
            | (Some(3), FederationRelay::ApprovedAttachment, Some(_), Some(_)) => Ok(()),
            _ => Err(Error::Invalid),
        }
    }
    pub fn attested_relay(&self) -> bool {
        self.validate().is_ok() && self.endpoint_mode == Some(3)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RemoteSessionReady {
    pub profile: u64,
    pub home: ServiceId,
    pub origin: ServiceId,
    pub agreement: AgreementRef,
    pub admission: AdmissionRef,
    pub request: Id,
    pub request_digest: Id,
    pub acting: EndpointActor,
    pub classification: AccountClass,
    pub checkpoints: Vec<CheckpointRef>,
    pub window: RetryWindow,
    pub source_privacy: FederationPrivacy,
    pub destination_privacy: FederationPrivacy,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OriginIdentityCheckpoint {
    pub profile: u64,
    pub origin: ServiceId,
    pub account: AccountId,
    pub state: IdentitySnapshot,
    pub anchor_digest: Id,
    pub head: Id,
    pub records: u16,
    pub nickname: String,
    pub issued_ms: u64,
    pub expires_ms: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OriginIdentityPage {
    pub profile: u64,
    pub origin: ServiceId,
    pub agreement: AgreementRef,
    pub account: AccountId,
    pub checkpoint: Id,
    pub after: u64,
    pub records: Vec<Blob>,
    pub next: u64,
    pub complete: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum ProofPurpose {
    Admission { admission: Id, revision: u64 },
    Room(Box<RoomProofPurpose>),
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RoomProofPurpose {
    pub room: RoomId,
    pub requester: EndpointActor,
    pub represented: AccountId,
    pub grant: Option<GrantRef>,
    pub filter_revision: u64,
    pub evidence: Option<Id>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum FederationControl {
    Request {
        profile: u64,
        home: ServiceId,
        origin: ServiceId,
        agreement: AgreementRef,
        request: Id,
        operation: Operation,
        body: Value,
        created_ms: u64,
        expires_ms: u64,
    },
    Result {
        profile: u64,
        home: ServiceId,
        origin: ServiceId,
        agreement: AgreementRef,
        request: Id,
        operation: Operation,
        request_digest: Id,
        outcome: Outcome,
        created_ms: u64,
        expires_ms: u64,
    },
    ProofAuthorization {
        profile: u64,
        home: ServiceId,
        origin: ServiceId,
        agreement: AgreementRef,
        request: Id,
        account: AccountId,
        checkpoint: Id,
        purpose: Box<ProofPurpose>,
        expires_ms: u64,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RemoteSessionExchange {
    pub request: Blob,
    pub endpoint_binding: Blob,
    pub challenge: Blob,
    pub origin_assertion: Blob,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OwnerCheckpointEvidence {
    pub origin: ServiceId,
    pub checkpoint_digest: Id,
    pub head: Id,
    pub checkpoint: Blob,
    pub creation_assertion: Blob,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    rename_all = "camelCase",
    rename_all_fields = "camelCase",
    deny_unknown_fields
)]
pub enum IdentityTransfer {
    Read {
        account: AccountId,
        checkpoint: Id,
        after: u64,
        limit: u16,
        authorization: Blob,
    },
    Import {
        checkpoint: Blob,
        page: Blob,
    },
    Freshness {
        lease: Blob,
    },
}

pub(crate) fn check_freshness(v: &IdentityFreshness) -> Result<()> {
    profile(v.profile)?;
    interval(v.issued_ms, v.expires_ms, 5000)?;
    if v.home.network == v.origin.network
        || v.agreement.revision == 0
        || v.checkpoints.is_empty()
        || v.checkpoints.len() > 32
        || v.checkpoints
            .iter()
            .any(|c| c.account.origin != v.origin.network)
        || v.checkpoints
            .windows(2)
            .any(|w| w[0].account >= w[1].account)
    {
        return Err(Error::Invalid);
    }
    Ok(())
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum WithdrawalReason {
    Administrative,
    Expiry,
    IdentityChange,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederationWithdrawal {
    pub agreement: AgreementRef,
    pub request: Id,
    pub reason: WithdrawalReason,
}

fn profile(value: u64) -> Result<()> {
    if value == FEDERATION_PROFILE {
        Ok(())
    } else {
        Err(Error::Feature)
    }
}
fn interval(start: u64, end: u64, maximum: u64) -> Result<()> {
    if end > start && end - start <= maximum {
        Ok(())
    } else {
        Err(Error::Invalid)
    }
}
pub(crate) fn check_gateway(v: &GatewayMessage) -> Result<()> {
    match v {
        GatewayMessage::Hello {
            profile: p,
            agreement,
            ..
        }
        | GatewayMessage::Proof {
            profile: p,
            agreement,
            ..
        }
        | GatewayMessage::Ready {
            profile: p,
            agreement,
            ..
        } => {
            profile(*p)?;
            if agreement.revision == 0 {
                return Err(Error::Invalid);
            }
        }
        GatewayMessage::Challenge {
            profile: p,
            agreement,
            issued_ms,
            expires_ms,
            transport_generation,
            ..
        } => {
            profile(*p)?;
            interval(*issued_ms, *expires_ms, 5000)?;
            if agreement.revision == 0 || *transport_generation == 0 {
                return Err(Error::Invalid);
            }
        }
    }
    Ok(())
}
pub(crate) fn check_session_request(v: &RemoteSessionRequest) -> Result<()> {
    profile(v.profile)?;
    interval(v.created_ms, v.expires_ms, 60_000)?;
    if v.origin.network == v.home.network
        || v.account.origin != v.origin.network
        || v.agreement.revision == 0
    {
        return Err(Error::Binding);
    }
    Ok(())
}
pub(crate) fn check_session_ready(v: &RemoteSessionReady) -> Result<()> {
    profile(v.profile)?;
    v.source_privacy.validate()?;
    v.destination_privacy.validate()?;
    if v.origin.network == v.home.network
        || v.acting.account.origin != v.origin.network
        || v.agreement.revision == 0
        || v.admission.revision == 0
        || v.checkpoints.len() > 3
    {
        return Err(Error::Invalid);
    }
    Ok(())
}
pub(crate) fn check_checkpoint(v: &OriginIdentityCheckpoint) -> Result<()> {
    profile(v.profile)?;
    interval(v.issued_ms, v.expires_ms, 7 * 86_400_000)?;
    if v.account.origin != v.origin.network
        || v.state.home != v.origin
        || v.state.account != v.account
        || v.state.head != Some(v.head)
        || v.records == 0
        || v.records > 1024
        || v.state.endpoints.len() > 8
        || v.nickname.len() > 64
    {
        return Err(Error::Invalid);
    }
    Ok(())
}
pub(crate) fn check_page(v: &OriginIdentityPage) -> Result<()> {
    profile(v.profile)?;
    if v.account.origin != v.origin.network
        || v.agreement.revision == 0
        || v.records.len() > 4
        || v.records.iter().map(|b| b.0.len()).sum::<usize>() > 56 * 1024
        || v.next != v.after + v.records.len() as u64
        || v.next > 1024
        || v.records.is_empty() && !v.complete
    {
        return Err(Error::Invalid);
    }
    Ok(())
}
pub(crate) fn check_control(v: &FederationControl) -> Result<()> {
    let (p, home, origin, agreement) = match v {
        FederationControl::Request {
            profile,
            home,
            origin,
            agreement,
            operation,
            created_ms,
            expires_ms,
            ..
        }
        | FederationControl::Result {
            profile,
            home,
            origin,
            agreement,
            operation,
            created_ms,
            expires_ms,
            ..
        } => {
            interval(*created_ms, *expires_ms, 60_000)?;
            if !(80..=89).contains(&operation.code()) {
                return Err(Error::Feature);
            }
            (*profile, home, origin, agreement)
        }
        FederationControl::ProofAuthorization {
            profile,
            home,
            origin,
            agreement,
            ..
        } => (*profile, home, origin, agreement),
    };
    profile(p)?;
    if home.network == origin.network || agreement.revision == 0 {
        return Err(Error::Binding);
    }
    Ok(())
}
