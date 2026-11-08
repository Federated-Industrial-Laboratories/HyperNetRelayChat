// SPDX-License-Identifier: Apache-2.0
//! Bounded public admission artifacts and explicit invitation protocol messages.
use super::{Error, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    net::SocketAddrV4,
    time::{SystemTime, UNIX_EPOCH},
};

pub(crate) const INVITATION_FORMAT: &str = "HrcSelfServiceInvitation/1";
pub(crate) const PROTOCOL: &str = "HrcAdmission/1";
pub(crate) const MAX_ARTIFACT: usize = 8 * 1024 * 1024;
pub(crate) const MAX_REQUEST: usize = 1024 * 1024;
pub(crate) const MAX_RESPONSE: usize = 20 * 1024 * 1024;

pub(crate) fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
pub(crate) fn is_id(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}
pub(crate) fn now_ms() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|v| v.as_millis() as u64)
        .map_err(|_| Error::State)
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Artifact {
    pub sha256: String,
    pub hex: String,
}
impl Artifact {
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > MAX_ARTIFACT {
            return Err(Error::Invalid);
        }
        Ok(Self {
            sha256: digest(bytes),
            hex: hex::encode(bytes),
        })
    }
    pub fn bytes(&self, maximum: usize) -> Result<Vec<u8>> {
        if !is_id(&self.sha256) || self.hex.len() > maximum.saturating_mul(2) {
            return Err(Error::Invalid);
        }
        let bytes = hex::decode(&self.hex).map_err(|_| Error::Invalid)?;
        if bytes.is_empty() || hex::encode(&bytes) != self.hex || digest(&bytes) != self.sha256 {
            return Err(Error::Invalid);
        }
        Ok(bytes)
    }
}

/// Contains a bearer secret before redemption. Never include it in diagnostics.
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Invitation {
    pub format: String,
    pub name: String,
    pub address: SocketAddrV4,
    pub certificate_authority_pem: String,
    pub server_certificate_sha256: String,
    pub network: String,
    pub incarnation: String,
    pub bootstrap_sha256: String,
    pub bootstrap_fingerprint: String,
    pub id: String,
    pub secret: String,
    pub expires_ms: u64,
    pub access_expires_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct NetworkMetadata {
    pub bootstrap: Artifact,
    pub bootstrap_fingerprint: String,
    pub network: String,
    pub incarnation: String,
    pub application_service: String,
    pub reader_available: bool,
    pub access_expires_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RouteDelivery {
    pub role: String,
    pub subject: String,
    pub artifact: Artifact,
    pub voucher_id: String,
    pub generation: u64,
    pub expires_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct ReaderDelivery {
    pub network_invitation: Artifact,
    pub request_sha256: String,
    pub routes: Vec<RouteDelivery>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Delivery {
    /// The original candidate-bound setup bundle; renewal never replaces its identity.
    pub setup_bundle: Artifact,
    pub chat_request_sha256: String,
    pub chat_routes: Vec<RouteDelivery>,
    pub reader: Option<ReaderDelivery>,
    pub access_expires_ms: u64,
    pub join_expires_ms: u64,
    pub route_expires_ms: u64,
    pub renewal_after_ms: u64,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "operation", rename_all = "camelCase", deny_unknown_fields)]
pub(crate) enum Action {
    Inspect {
        secret: String,
    },
    Redeem {
        secret: String,
        chat_request: Artifact,
        reader_request: Option<Artifact>,
    },
    Status,
    Enrol {
        registration: Artifact,
    },
    Renew,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct RequestData {
    pub invitation_id: String,
    pub authentication_key: String,
    pub action: Action,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct SignedRequest {
    pub data: RequestData,
    pub signature: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "camelCase", deny_unknown_fields)]
pub(crate) enum Response {
    Network { metadata: NetworkMetadata },
    Pending { phase: String, retry_after_ms: u64 },
    Ready { delivery: Delivery, enrolled: bool },
    Refused { reason: String },
}
