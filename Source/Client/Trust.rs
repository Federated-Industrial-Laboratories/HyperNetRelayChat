// SPDX-License-Identifier: Apache-2.0
//! Replay owner-authorized account changes before a contact key can enter an MLS roster.
use crate::{identity, protocol::*};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, thiserror::Error)]
#[error("contact continuity is invalid or does not extend its trusted anchor")]
pub struct Invalid;
type Result<T> = std::result::Result<T, Invalid>;
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum TrustState {
    UntrustedRegistration,
    LegacyAnchor,
    Trusted,
    Changed,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ContactTrust {
    pub account: AccountId,
    pub anchor: Id,
    pub head: Id,
    pub recovery_key: Id,
    pub state: TrustState,
}
#[derive(Clone)]
pub(super) struct CheckedChain {
    pub records: Vec<ContinuityRecord>,
    pub hashes: Vec<Id>,
}
impl CheckedChain {
    pub fn latest(&self) -> &IdentitySnapshot {
        &self.records.last().expect("checked nonempty chain").state
    }
    pub fn at(&self, position: u64) -> Option<IdentitySnapshot> {
        self.records
            .iter()
            .rev()
            .find(|r| r.position < position)
            .map(|r| r.state.clone())
    }
    pub fn view(&self, state: TrustState) -> ContactTrust {
        ContactTrust {
            account: self.latest().account,
            anchor: self.hashes[0],
            head: *self.hashes.last().expect("checked nonempty chain"),
            recovery_key: self.latest().recovery_key,
            state,
        }
    }
}
fn bytes<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    canonical_encode(
        &Value::serialized(v).map_err(|_| Invalid)?,
        CRYPTO_FRAME_BYTES,
    )
    .map_err(|_| Invalid)
}
fn value<T: serde::de::DeserializeOwned>(blob: &Blob) -> Result<T> {
    canonical_decode(&blob.0, ORDINARY_FRAME_BYTES)
        .map_err(|_| Invalid)?
        .deserialized()
        .map_err(|_| Invalid)
}
fn key(id: Id) -> Result<VerifyingKey> {
    let key = VerifyingKey::from_bytes(id.as_bytes()).map_err(|_| Invalid)?;
    if key.is_weak() {
        return Err(Invalid);
    }
    Ok(key)
}
fn endpoints(state: &IdentitySnapshot) -> Result<BTreeMap<Id, Vec<u8>>> {
    if state.endpoints.len() > 8 || state.security_generation == 0 || state.recovery_generation == 0
    {
        return Err(Invalid);
    }
    key(state.recovery_key)?;
    let mut result = BTreeMap::new();
    for endpoint in &state.endpoints {
        if endpoint.actor.account != state.account
            || endpoint.actor.security_generation != state.security_generation
            || endpoint.actor.enrolment_generation != 1
            || endpoint.key == state.recovery_key
            || result
                .insert(endpoint.actor.endpoint, bytes(endpoint)?)
                .is_some()
        {
            return Err(Invalid);
        }
        key(endpoint.key)?;
    }
    Ok(result)
}
fn unsigned_action(blob: &Blob) -> Result<Action> {
    let Value::Array(outer) =
        canonical_decode(&blob.0, ORDINARY_FRAME_BYTES).map_err(|_| Invalid)?
    else {
        return Err(Invalid);
    };
    let Some(Value::Bytes(payload)) = outer.get(2) else {
        return Err(Invalid);
    };
    let Value::Array(parts) =
        canonical_decode(payload, ORDINARY_FRAME_BYTES).map_err(|_| Invalid)?
    else {
        return Err(Invalid);
    };
    parts
        .get(2)
        .ok_or(Invalid)?
        .deserialized()
        .map_err(|_| Invalid)
}
fn controller(
    blob: &Blob,
    prior: &IdentitySnapshot,
    position: u64,
    operator: &impl Fn(AccountId, u64) -> Option<IdentitySnapshot>,
) -> Result<VerifiedAction> {
    let action = unsigned_action(blob)?;
    let Actor::Direct { acting } = &action.actor else {
        return Err(Invalid);
    };
    let authority = if acting.account == prior.account {
        prior.clone()
    } else {
        if prior.classification
            != (AccountClass::Agent {
                operator: acting.account,
            })
        {
            return Err(Invalid);
        }
        operator(acting.account, position).ok_or(Invalid)?
    };
    if authority.classification != AccountClass::Human
        || action.home != prior.home
        || action.target != Target::Account(prior.account)
    {
        return Err(Invalid);
    }
    let endpoint = authority
        .endpoints
        .iter()
        .find(|e| e.actor == *acting)
        .ok_or(Invalid)?;
    verify_action(&blob.0, &key(endpoint.key)?).map_err(|_| Invalid)
}
fn replacement(blob: &Blob, home: ServiceId, account: AccountId) -> Result<Id> {
    let signed = verify_new_recovery_key(&blob.0).map_err(|_| Invalid)?;
    if signed.value().home != home || signed.value().account != account {
        return Err(Invalid);
    }
    Ok(signed.value().key)
}
/// `operator` returns already checked, trusted operator state preceding this home position.
pub(super) fn check_chain(
    home_key: &VerifyingKey,
    records: Vec<ContinuityRecord>,
    operator: impl Fn(AccountId, u64) -> Option<IdentitySnapshot>,
) -> Result<CheckedChain> {
    if records.is_empty() || records.len() > 1024 {
        return Err(Invalid);
    }
    let first = &records[0];
    let home = first.state.home;
    let account = first.state.account;
    if home.network != account.origin
        || first.index != 1
        || first.previous.is_some()
        || first.state.head.is_some()
    {
        return Err(Invalid);
    }
    let mut hashes = Vec::new();
    let mut total = 0;
    for (index, record) in records.iter().enumerate() {
        let encoded = bytes(record)?;
        total += encoded.len();
        if total > 16 * 1024 * 1024
            || record.index != index as u64 + 1
            || record.state.home != home
            || record.state.account != account
            || record.previous != hashes.last().copied()
            || record.state.head != record.previous
            || record.position == 0
        {
            return Err(Invalid);
        }
        endpoints(&record.state)?;
        if index == 0 {
            match record.change {
                IdentityChange::Registered => {
                    if record.state.legacy_anchor
                        || record.authorizations.len() != 1
                        || record.state.security_generation != 1
                        || record.state.revision != 1
                        || record.state.recovery_generation != 1
                        || record.state.endpoints.len() != 1
                    {
                        return Err(Invalid);
                    }
                    let signed = verify_registration_request(&record.authorizations[0].0)
                        .map_err(|_| Invalid)?;
                    let registration = signed.value();
                    let endpoint = &record.state.endpoints[0];
                    if registration.home != home
                        || registration.account != account
                        || registration.recovery_key != record.state.recovery_key
                        || registration.classification != record.state.classification
                        || registration.endpoint != endpoint.actor.endpoint
                        || registration.endpoint_key != endpoint.key
                        || registration.transport_principal != endpoint.principal
                    {
                        return Err(Invalid);
                    }
                }
                IdentityChange::LegacyServiceAnchor => {
                    if !record.state.legacy_anchor || !record.authorizations.is_empty() {
                        return Err(Invalid);
                    }
                }
                _ => return Err(Invalid),
            }
        } else {
            let prior = &records[index - 1].state;
            if record.position <= records[index - 1].position
                || record.state.legacy_anchor != prior.legacy_anchor
                || record.state.classification != prior.classification
                || record.state.revision <= prior.revision
            {
                return Err(Invalid);
            }
            verify_change(home_key, record, prior, &hashes, &operator)?;
        }
        hashes.push(digest(&encoded));
    }
    Ok(CheckedChain { records, hashes })
}
fn verify_change(
    home_key: &VerifyingKey,
    record: &ContinuityRecord,
    prior: &IdentitySnapshot,
    ancestors: &[Id],
    operator: &impl Fn(AccountId, u64) -> Option<IdentitySnapshot>,
) -> Result<()> {
    let next = &record.state;
    let mut expected = endpoints(prior)?;
    let mut security = prior.security_generation;
    let mut recovery = prior.recovery_key;
    let mut recovery_generation = prior.recovery_generation;
    if record.authorizations.len() == 1 {
        let signed = controller(&record.authorizations[0], prior, record.position, operator)?;
        let action = signed.action();
        match record.change {
            IdentityChange::EndpointDisabled => {
                if action.operation != Operation::AccountDisableEndpoint {
                    return Err(Invalid);
                }
                let body: identity::DisableEndpoint =
                    action.body.deserialized().map_err(|_| Invalid)?;
                if Some(body.head) != record.previous
                    || body.revision < prior.revision
                    || next.revision != body.revision + 1
                    || expected.remove(&body.endpoint).is_none()
                {
                    return Err(Invalid);
                }
            }
            IdentityChange::RecoveryRotated => {
                if action.operation != Operation::AccountRotateRecovery {
                    return Err(Invalid);
                }
                let body: identity::RotateRecovery =
                    action.body.deserialized().map_err(|_| Invalid)?;
                if Some(body.head) != record.previous
                    || body.revision < prior.revision
                    || next.revision != body.revision + 1
                {
                    return Err(Invalid);
                }
                recovery = replacement(&body.replacement, prior.home, prior.account)?;
                recovery_generation += 1;
            }
            _ => return Err(Invalid),
        }
    } else {
        if !(3..=4).contains(&record.authorizations.len()) {
            return Err(Invalid);
        }
        let request = verify_new_device(&record.authorizations[0].0).map_err(|_| Invalid)?;
        let r = request.value();
        let challenge =
            verify_device_challenge(&record.authorizations[1].0, home_key).map_err(|_| Invalid)?;
        let c = challenge.value();
        let proofs: DeviceProofs = value(&record.authorizations[2])?;
        let expected_proof = DeviceProof {
            home: r.home,
            account: r.account,
            request: r.request,
            request_digest: request.digest(),
            challenge_digest: challenge.digest(),
        };
        let proof =
            verify_device_proof(&proofs.endpoint.0, &key(r.endpoint_key)?).map_err(|_| Invalid)?;
        if proof.value() != &expected_proof
            || r.home != prior.home
            || r.account != prior.account
            || c.home != r.home
            || c.account != r.account
            || c.request != r.request
            || c.request_digest != request.digest()
            || c.principal != r.principal
            || c.security_generation != prior.security_generation
            || c.recovery_generation != prior.recovery_generation
            || c.recovery_key != prior.recovery_key
            || Some(c.continuity_head) != record.previous
            || c.account_revision < prior.revision
            || c.recorded
            || c.issued_ms < r.created_ms
            || c.expires_ms > r.expires_ms
            || next.revision != c.account_revision + 1
        {
            return Err(Invalid);
        }
        if r.purpose == DevicePurpose::Enrol {
            if record.change != IdentityChange::EndpointEnrolled
                || record.authorizations.len() != 4
                || proofs.recovery.is_some()
            {
                return Err(Invalid);
            }
            let approval = controller(&record.authorizations[3], prior, record.position, operator)?;
            if approval.action().operation != Operation::AccountEnrolEndpoint {
                return Err(Invalid);
            }
            let body: identity::ApproveEndpoint =
                approval.action().body.deserialized().map_err(|_| Invalid)?;
            if body.request.0 != request.signed_bytes()
                || !ancestors.contains(&body.head)
                || body.revision > c.account_revision
            {
                return Err(Invalid);
            }
        } else {
            if record.authorizations.len() != 3 {
                return Err(Invalid);
            }
            let recovery_proof = verify_device_proof(
                &proofs.recovery.as_ref().ok_or(Invalid)?.0,
                &key(prior.recovery_key)?,
            )
            .map_err(|_| Invalid)?;
            if recovery_proof.value() != &expected_proof {
                return Err(Invalid);
            }
            match r.purpose {
                DevicePurpose::Recover => {
                    if record.change != IdentityChange::Recovered {
                        return Err(Invalid);
                    }
                    security += 1;
                    expected.clear();
                }
                DevicePurpose::RotateRecovery => {
                    if record.change != IdentityChange::RecoveryRotated {
                        return Err(Invalid);
                    }
                    recovery =
                        replacement(r.replacement.as_ref().ok_or(Invalid)?, r.home, r.account)?;
                    recovery_generation += 1;
                }
                DevicePurpose::Enrol => return Err(Invalid),
            }
        }
        if r.purpose != DevicePurpose::RotateRecovery {
            let endpoint = next
                .endpoints
                .iter()
                .find(|e| e.actor.endpoint == r.endpoint)
                .ok_or(Invalid)?;
            if endpoint.key != r.endpoint_key
                || endpoint.principal != r.principal
                || expected.insert(r.endpoint, bytes(endpoint)?).is_some()
            {
                return Err(Invalid);
            }
        }
    }
    if next.security_generation != security
        || next.recovery_key != recovery
        || next.recovery_generation != recovery_generation
        || expected != endpoints(next)?
    {
        return Err(Invalid);
    }
    Ok(())
}
