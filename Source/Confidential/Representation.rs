// SPDX-License-Identifier: Apache-2.0
//! Bounded proof records keep large rosters within the ordinary decoder's structural limits.
use super::{DelegationEvidence, Member};
use crate::{crypto::EndpointCredential, home::types::*, protocol::*};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

pub(super) const ROSTER_BYTES: usize = 96 * 1024;
pub(super) const PACKAGE_BYTES: usize = 48 * 1024;
pub(super) const TRANSITION_BYTES: usize = 192 * 1024;
const MEMBER_BYTES: usize = 32 * 1024;

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct MemberFields<'a> {
    actor: &'a Actor,
    credential: &'a EndpointCredential,
    registration: &'a Blob,
    delegation: &'a Option<DelegationEvidence>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct OwnedMemberFields {
    actor: Actor,
    credential: EndpointCredential,
    registration: Blob,
    delegation: Option<DelegationEvidence>,
}
impl Serialize for Member {
    fn serialize<S: Serializer>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error> {
        let fields = MemberFields {
            actor: &self.actor,
            credential: &self.credential,
            registration: &self.registration,
            delegation: &self.delegation,
        };
        if serializer.is_human_readable() {
            return fields.serialize(serializer);
        }
        let value = Value::serialized(&fields).map_err(serde::ser::Error::custom)?;
        let bytes = canonical_encode(&value, MEMBER_BYTES).map_err(serde::ser::Error::custom)?;
        Blob(bytes).serialize(serializer)
    }
}
impl<'de> Deserialize<'de> for Member {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> std::result::Result<Self, D::Error> {
        let fields: OwnedMemberFields = if deserializer.is_human_readable() {
            OwnedMemberFields::deserialize(deserializer)?
        } else {
            let bytes = Blob::deserialize(deserializer)?;
            canonical_decode(&bytes.0, MEMBER_BYTES)
                .map_err(serde::de::Error::custom)?
                .deserialized()
                .map_err(serde::de::Error::custom)?
        };
        Ok(Self {
            actor: fields.actor,
            credential: fields.credential,
            registration: fields.registration,
            delegation: fields.delegation,
        })
    }
}
pub(super) fn bounded<T: Serialize>(value: &T, maximum: usize) -> Domain<()> {
    let value = Value::serialized(value)
        .map_err(|_| Fault::Reject(ErrorCode::Overloaded, "EncryptedMetadataCapacity"))?;
    canonical_encode(&value, maximum)
        .map(|_| ())
        .map_err(|_| Fault::Reject(ErrorCode::Overloaded, "EncryptedMetadataCapacity"))
}
pub(super) fn roster(members: &[Member]) -> Domain<()> {
    if members.len() > crate::crypto::MAX_ENDPOINTS {
        return Err(Fault::Reject(
            ErrorCode::Overloaded,
            "EncryptedEndpointLimit",
        ));
    }
    bounded(&members, ROSTER_BYTES)
}

#[cfg(test)]
#[path = "../../Tests/Confidential/Representation.rs"]
mod tests;
