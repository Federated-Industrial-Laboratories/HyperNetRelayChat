// SPDX-License-Identifier: Apache-2.0
//! Plain wire data. Construction or deserialization alone confers no authority.
use super::federation::*;
use super::{Error, Result};
use ciborium::Value;
use serde::{
    Deserialize, Deserializer, Serialize, Serializer,
    de::{self, Visitor},
};
use std::{collections::BTreeMap, fmt, str::FromStr};

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Id([u8; 32]);
impl Id {
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
    pub fn from_hex(text: &str) -> Result<Self> {
        if text.len() != 64
            || !text
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(Error::Invalid);
        }
        let mut bytes = [0; 32];
        hex::decode_to_slice(text, &mut bytes).map_err(|_| Error::Invalid)?;
        Ok(Self(bytes))
    }
    pub fn random() -> Result<Self> {
        let mut bytes = [0; 32];
        getrandom::fill(&mut bytes).map_err(|_| Error::Random)?;
        Ok(Self(bytes))
    }
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
    pub fn as_hex(&self) -> String {
        hex::encode(self.0)
    }
}
impl fmt::Display for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.as_hex())
    }
}
impl fmt::Debug for Id {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl FromStr for Id {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        Self::from_hex(s)
    }
}
impl Serialize for Id {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        if s.is_human_readable() {
            s.serialize_str(&self.as_hex())
        } else {
            s.serialize_bytes(&self.0)
        }
    }
}
impl<'de> Deserialize<'de> for Id {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct IdVisitor;
        impl Visitor<'_> for IdVisitor {
            type Value = Id;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("a32-byte identifier")
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Id, E> {
                Id::from_hex(v).map_err(E::custom)
            }
            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> std::result::Result<Id, E> {
                v.try_into()
                    .map(Id)
                    .map_err(|_| E::custom("identifier length"))
            }
            fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> std::result::Result<Id, E> {
                self.visit_bytes(&v)
            }
        }
        if d.is_human_readable() {
            d.deserialize_str(IdVisitor)
        } else {
            d.deserialize_bytes(IdVisitor)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct NetworkId {
    pub network: Id,
    pub incarnation: Id,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServiceId {
    pub network: NetworkId,
    pub service: Id,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountId {
    pub origin: NetworkId,
    pub local: Id,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RoomId {
    pub home: ServiceId,
    pub local: Id,
}
impl fmt::Display for NetworkId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.network, self.incarnation)
    }
}
impl fmt::Display for ServiceId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.network, self.service)
    }
}
impl fmt::Display for AccountId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.origin, self.local)
    }
}
impl fmt::Display for RoomId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.home, self.local)
    }
}
impl FromStr for NetworkId {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let (network, incarnation) = s.split_once(':').ok_or(Error::Invalid)?;
        Ok(Self {
            network: network.parse()?,
            incarnation: incarnation.parse()?,
        })
    }
}
impl FromStr for ServiceId {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let (network, service) = s.rsplit_once(':').ok_or(Error::Invalid)?;
        Ok(Self {
            network: network.parse()?,
            service: service.parse()?,
        })
    }
}
impl FromStr for AccountId {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let (origin, local) = s.rsplit_once(':').ok_or(Error::Invalid)?;
        Ok(Self {
            origin: origin.parse()?,
            local: local.parse()?,
        })
    }
}
impl FromStr for RoomId {
    type Err = Error;
    fn from_str(s: &str) -> Result<Self> {
        let (home, local) = s.rsplit_once(':').ok_or(Error::Invalid)?;
        Ok(Self {
            home: home.parse()?,
            local: local.parse()?,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointActor {
    pub account: AccountId,
    pub endpoint: Id,
    pub security_generation: u64,
    pub enrolment_generation: u64,
    pub binding_digest: Id,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct GrantRef {
    pub id: Id,
    pub generation: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AgreementRef {
    pub id: Id,
    pub revision: u64,
    pub digest: Id,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "camelCase", deny_unknown_fields)]
pub enum Actor {
    Direct {
        acting: EndpointActor,
    },
    IndependentAgent {
        acting: EndpointActor,
        operator: AccountId,
    },
    Delegated {
        acting: EndpointActor,
        operator: AccountId,
        represented: AccountId,
        represented_security_generation: u64,
        grant: GrantRef,
    },
}
impl Actor {
    pub fn acting(&self) -> &EndpointActor {
        match self {
            Self::Direct { acting }
            | Self::IndependentAgent { acting, .. }
            | Self::Delegated { acting, .. } => acting,
        }
    }
    pub fn represented(&self) -> AccountId {
        match self {
            Self::Delegated { represented, .. } => *represented,
            _ => self.acting().account,
        }
    }
    pub(super) fn validate(&self) -> Result<()> {
        let a = self.acting();
        if a.security_generation == 0 || a.enrolment_generation == 0 {
            return Err(Error::Invalid);
        }
        if let Self::Delegated {
            grant,
            represented_security_generation,
            ..
        } = self
            && (grant.generation == 0 || *represented_security_generation == 0)
        {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OperationId {
    pub window: Id,
    pub operation: Id,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(
    tag = "kind",
    content = "id",
    rename_all = "camelCase",
    deny_unknown_fields
)]
pub enum Target {
    Service,
    Account(AccountId),
    Room(RoomId),
    Delegation(GrantRef),
    Endpoint(Id),
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Revision {
    Account,
    Room,
    Grant,
    Agreement,
    Epoch,
    Filter,
}

macro_rules! operations {
    ($($variant:ident=$number:literal),+ $(,)?)=>{
        #[derive(Clone,Copy,Debug,PartialEq,Eq)]
        #[repr(u16)]
        pub enum Operation{$($variant=$number),+}
        impl Operation {pub fn code(self)->u16{self as u16} pub fn name(self)->&'static str {match self{$(Self::$variant=>stringify!($variant)),+}}}
        impl TryFrom<u16> for Operation{type Error=Error;fn try_from(n:u16)->Result<Self>{match n{$($number=>Ok(Self::$variant)),+,_=>Err(Error::Feature)}}}
        impl Serialize for Operation {fn serialize<S:Serializer>(&self,s:S)->std::result::Result<S::Ok,S::Error>{s.serialize_u16(self.code())}}
        impl<'de> Deserialize<'de> for Operation {fn deserialize<D:Deserializer<'de>>(d:D)->std::result::Result<Self,D::Error>{Self::try_from(u16::deserialize(d)?).map_err(de::Error::custom)}}
    }
}
operations! {
    AccountSetNickname=1,PresenceSet=2,AccountInspect=3,AgentList=4,ServiceInspect=5,
    RoomCreate=10,RoomJoin=11,RoomLeave=12,RoomSetTopic=13,RoomList=14,RoomInspect=15,RoomInvite=16,
    MessageSend=20,MessageReply=21,MessageAction=22,
    HistoryPage=30,SearchQuery=31,SearchCancel=32,EventsSubscribe=33,EventsResume=34,UnreadSet=35,OperationResolve=36,HistoryContext=37,HistoryTail=38,CryptoTail=39,
    DelegationCreate=40,DelegationInspect=41,DelegationPause=42,DelegationResume=43,DelegationRevoke=44,DelegationList=45,
    ApprovalPrepare=50,ApprovalApprove=51,ApprovalReject=52,
    ModerationIgnore=60,ModerationMute=61,ModerationSilence=62,ModerationKick=63,ModerationBan=64,ModerationFilters=65,ModerationRestrictions=66,
    CryptoEnrolEndpoint=70,CryptoPublishKeyPackage=71,CryptoPropose=72,CryptoCommit=73,CryptoEpochReady=74,
    CryptoInspect=75,CryptoWelcome=76,CryptoRecover=77,CryptoReport=78,CryptoHistory=79,
    FederationPropose=80,FederationAccept=81,FederationWithdraw=82,FederationExchange=83,FederationChallenge=84,
    FederationAdmitEndpoint=85,FederationWithdrawEndpoint=86,FederationIdentityPage=87,FederationInspect=88,FederationSession=89,
    AccountRecover=90,AccountRotateRecovery=91,AccountEnrolEndpoint=92,AccountDisableEndpoint=93,
    AccountDevices=94,AccountContinuity=95,AccountLifecycleOutcome=96,AccountPublicIdentity=97,
    DirectCreate=100,
    ClientMetadata=110,CommunitySync=111,
}
impl Operation {
    pub fn is_crypto_transition(self) -> bool {
        matches!(
            self,
            Self::CryptoPublishKeyPackage
                | Self::CryptoPropose
                | Self::CryptoCommit
                | Self::CryptoEpochReady
                | Self::CryptoInspect
                | Self::CryptoWelcome
                | Self::CryptoRecover
                | Self::CryptoHistory
                | Self::CryptoTail
        )
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Action {
    pub home: ServiceId,
    pub operation_id: OperationId,
    pub actor: Actor,
    pub target: Target,
    pub operation: Operation,
    pub body: Value,
    pub expected: BTreeMap<Revision, u64>,
    pub approval: Option<Id>,
    pub agreement: Option<AgreementRef>,
}
impl Action {
    pub fn validate(&self) -> Result<()> {
        self.actor.validate()?;
        if let Target::Room(room) = self.target
            && room.home != self.home
        {
            return Err(Error::Binding);
        }
        if let Target::Delegation(grant) = self.target
            && grant.generation == 0
        {
            return Err(Error::Invalid);
        }
        if self.agreement.is_some_and(|a| a.revision == 0) {
            return Err(Error::Invalid);
        }
        if self.actor.acting().account.origin != self.home.network && self.agreement.is_none() {
            return Err(Error::Binding);
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase", deny_unknown_fields)]
pub enum AccountClass {
    Human,
    Agent { operator: AccountId },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AccountRegistration {
    pub home: ServiceId,
    pub account: AccountId,
    pub endpoint: Id,
    pub endpoint_key: Id,
    pub transport_principal: Id,
    pub recovery_key: Id,
    pub classification: AccountClass,
    pub invitation: Id,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointBinding {
    pub origin: ServiceId,
    pub account: AccountId,
    pub endpoint: Id,
    pub endpoint_key: Id,
    pub transport_principal: Id,
    pub security_generation: u64,
    pub enrolment_generation: u64,
    pub not_before_ms: u64,
    pub expires_ms: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionHello {
    pub home: ServiceId,
    pub account: AccountId,
    pub endpoint: Id,
    pub client_nonce: Id,
    pub versions: Vec<u64>,
    pub required_capabilities: Vec<String>,
    pub optional_capabilities: Vec<String>,
}
impl SessionHello {
    pub fn validate(&self) -> Result<()> {
        if self.versions != [super::VERSION] {
            return Err(Error::Version);
        }
        let all = self
            .required_capabilities
            .iter()
            .chain(&self.optional_capabilities)
            .collect::<Vec<_>>();
        if all.len() > 16
            || all
                .iter()
                .any(|s| s.is_empty() || s.len() > 64 || !s.bytes().all(|c| c.is_ascii_graphic()))
        {
            return Err(Error::Limit);
        }
        if all.iter().enumerate().any(|(i, v)| all[..i].contains(v)) {
            return Err(Error::Invalid);
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionChallenge {
    pub home: ServiceId,
    pub account: AccountId,
    pub endpoint: Id,
    pub client_nonce: Id,
    pub nonce: Id,
    pub session: Id,
    pub service_boot: Id,
    pub transport_principal: Id,
    pub transport_session: Id,
    pub transport_generation: u64,
    pub expires_ms: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionProof {
    pub home: ServiceId,
    pub account: AccountId,
    pub endpoint: Id,
    pub client_nonce: Id,
    pub challenge_digest: Id,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RetryWindow {
    pub id: Id,
    pub expires_ms: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionReady {
    pub home: ServiceId,
    pub session: Id,
    pub challenge_digest: Id,
    pub window: RetryWindow,
    pub maximum_frame_bytes: u64,
    pub maximum_crypto_frame_bytes: u64,
    pub capabilities: Vec<String>,
    pub account_revision: u64,
    pub binding_digest: Id,
    pub acting: EndpointActor,
    pub classification: AccountClass,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ErrorCode {
    InvalidInput,
    Denied,
    Expired,
    Conflict,
    Unavailable,
    UnsupportedVersion,
    UnsupportedFeature,
    RateLimited,
    Overloaded,
    ResynchronisationRequired,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "camelCase", deny_unknown_fields)]
pub enum Outcome {
    Committed {
        event: Option<Id>,
        position: u64,
        body: Value,
    },
    Rejected {
        code: ErrorCode,
        detail: String,
    },
    Refused {
        code: ErrorCode,
        detail: String,
        retry_after_ms: Option<u64>,
    },
    Result {
        body: Value,
    },
    Absent,
    Unknown,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Response {
    pub home: ServiceId,
    pub operation_id: OperationId,
    pub action_digest: Id,
    pub outcome: Outcome,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Event {
    pub home: ServiceId,
    pub room: RoomId,
    pub event: Id,
    pub sequence: u64,
    pub timestamp_ms: u64,
    pub actor: Actor,
    pub operation_id: OperationId,
    pub action_digest: Id,
    pub kind: Operation,
    pub body: Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct HistoryCursor {
    pub home: ServiceId,
    pub room: RoomId,
    pub account: AccountId,
    pub sequence: u64,
    pub membership_revision: u64,
    pub filter_revision: u64,
    pub access_digest: Id,
    pub expires_ms: u64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ApprovalDecision {
    Approve,
    Reject,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Approval {
    pub id: Id,
    pub home: ServiceId,
    pub owner: EndpointActor,
    pub grant: GrantRef,
    pub action_digest: Id,
    pub decision: ApprovalDecision,
    pub expires_ms: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederationChallenge {
    pub profile: u64,
    pub admission: AdmissionRef,
    pub subject: FederationSubject,
    pub home: ServiceId,
    pub origin: ServiceId,
    pub agreement: AgreementRef,
    pub gateway: Id,
    pub nonce: Id,
    pub service_boot: Id,
    pub issued_ms: u64,
    pub expires_ms: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AuthorityEvidence {
    pub configuration: Id,
    pub epoch: u64,
    pub height: u64,
    pub state: Id,
    pub statement_digest: Id,
    pub evaluated_at_ms: u64,
    pub expires_at_ms: u64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OriginAssertion {
    pub profile: u64,
    pub admission: AdmissionRef,
    pub subject: FederationSubject,
    pub checkpoints: Vec<CheckpointRef>,
    pub source_privacy: FederationPrivacy,
    pub origin: ServiceId,
    pub home: ServiceId,
    pub agreement: AgreementRef,
    pub challenge_digest: Id,
    pub endpoint_binding_digest: Id,
    pub endpoint: Id,
    pub security_generation: u64,
    pub enrolment_generation: u64,
    pub transport_network: NetworkId,
    pub transport_principal: Id,
    pub transport_session: Id,
    pub transport_generation: u64,
    pub transport_grant: Id,
    pub transport_grant_generation: u64,
    pub source_service_boot: Id,
    pub control_generation: u64,
    pub companion_instance: Id,
    pub endpoint_instance: Id,
    pub permit_nonce: Id,
    pub authority: AuthorityEvidence,
    pub source_evaluated_ms: u64,
    pub source_not_after_ms: u64,
    pub source_uncertainty_ms: u64,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RoomConfidentiality {
    #[default]
    Community,
    ConfidentialDirect,
    PrivateGroup,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum StorageLocations {
    HomeOnly,
    BothNetworks,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PrivacyRequirement {
    SupportedHyperNetRoute,
    AttestedRelayArrival,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SharedRoom {
    pub room: RoomId,
    pub history_from_ms: u64,
    pub retention_ms: u64,
    pub storage: StorageLocations,
    pub confidentiality: RoomConfidentiality,
    pub privacy: PrivacyRequirement,
    pub moderator_accounts: Vec<AccountId>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederationAgreement {
    pub profile: u64,
    pub id: Id,
    pub revision: u64,
    pub home: ServiceId,
    pub origin: ServiceId,
    pub home_gateway: GatewayBinding,
    pub origin_gateway: GatewayBinding,
    pub home_service_key: Id,
    pub origin_service_key: Id,
    pub origin_attestor_key: Id,
    pub rooms: Vec<SharedRoom>,
    pub not_before_ms: u64,
    pub expires_ms: u64,
}
/// A binary field remains a CBOR byte string, rather than an array of byte values.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Blob(pub Vec<u8>);
impl Serialize for Blob {
    fn serialize<S: Serializer>(&self, s: S) -> std::result::Result<S::Ok, S::Error> {
        if self.0.len() >= super::CRYPTO_FRAME_BYTES {
            return Err(serde::ser::Error::custom("byte limit"));
        }
        if s.is_human_readable() {
            s.serialize_str(&hex::encode(&self.0))
        } else {
            s.serialize_bytes(&self.0)
        }
    }
}
impl<'de> Deserialize<'de> for Blob {
    fn deserialize<D: Deserializer<'de>>(d: D) -> std::result::Result<Self, D::Error> {
        struct Bytes;
        impl Visitor<'_> for Bytes {
            type Value = Blob;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("bounded bytes")
            }
            fn visit_bytes<E: de::Error>(self, v: &[u8]) -> std::result::Result<Blob, E> {
                if v.len() >= super::CRYPTO_FRAME_BYTES {
                    Err(E::custom("byte limit"))
                } else {
                    Ok(Blob(v.to_vec()))
                }
            }
            fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> std::result::Result<Blob, E> {
                if v.len() >= super::CRYPTO_FRAME_BYTES {
                    Err(E::custom("byte limit"))
                } else {
                    Ok(Blob(v))
                }
            }
            fn visit_str<E: de::Error>(self, v: &str) -> std::result::Result<Blob, E> {
                if v.len() >= 2 * super::CRYPTO_FRAME_BYTES
                    || !v.len().is_multiple_of(2)
                    || !v
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                {
                    return Err(E::custom("bounded lowercase hexadecimal bytes"));
                }
                hex::decode(v).map(Blob).map_err(E::custom)
            }
        }
        if d.is_human_readable() {
            d.deserialize_str(Bytes)
        } else {
            d.deserialize_bytes(Bytes)
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FederationEnvelope {
    pub profile: u64,
    pub admission: AdmissionRef,
    pub agreement: AgreementRef,
    pub action: Blob,
    pub endpoint_binding: Blob,
    pub challenge: Blob,
    pub origin_assertion: Blob,
}
