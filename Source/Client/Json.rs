// SPDX-License-Identifier: Apache-2.0
//! Human-readable JSON uses typed operation bodies and hexadecimal opaque bytes.
use crate::{
    confidential, conversations, crypto, delegation, home, identity, messaging, moderation,
    protocol::*,
};
use serde::de::DeserializeOwned;
use serde_json::Value as Json;
#[derive(Debug, thiserror::Error)]
#[error("invalid structured operation representation")]
pub struct Invalid;
type Result<T> = std::result::Result<T, Invalid>;
/// JSON hex and syntax have a separate ingress bound from decoded crypto frames.
pub const MAX_ACTION_BYTES: usize = 4 * CRYPTO_FRAME_BYTES;

fn body<T: DeserializeOwned + serde::Serialize>(json: Json) -> Result<Value> {
    let typed: T = serde_json::from_value(json).map_err(|_| Invalid)?;
    Value::serialized(&typed).map_err(|_| Invalid)
}
/// Convert JSON at the boundary, then use the same closed DTOs as native requests.
pub fn action(bytes: &[u8]) -> Result<Action> {
    if bytes.len() > MAX_ACTION_BYTES {
        return Err(Invalid);
    }
    // Preserve map entries until duplicate keys and the shared structural bounds are checked.
    let raw: Value = serde_json::from_slice(bytes).map_err(|_| Invalid)?;
    canonical_encode(&raw, MAX_ACTION_BYTES).map_err(|_| Invalid)?;
    let mut json = convert(raw)?;
    let body_json = json.get_mut("body").ok_or(Invalid)?.take();
    let mut action: Action = serde_json::from_value(json).map_err(|_| Invalid)?;
    if !action.operation.is_crypto_transition() && bytes.len() > ORDINARY_FRAME_BYTES {
        return Err(Invalid);
    }
    use Operation::*;
    action.body = match action.operation {
        AccountSetNickname => body::<identity::Nickname>(body_json)?,
        AccountEnrolEndpoint => body::<identity::ApproveEndpoint>(body_json)?,
        AccountDisableEndpoint => body::<identity::DisableEndpoint>(body_json)?,
        AccountRotateRecovery => body::<identity::RotateRecovery>(body_json)?,
        AccountContinuity => body::<identity::ContinuityPage>(body_json)?,
        PresenceSet => body::<identity::Presence>(body_json)?,
        RoomInvite => body::<confidential::Invite>(body_json)?,
        DirectCreate => body::<confidential::Direct>(body_json)?,
        CryptoEnrolEndpoint => body::<confidential::EnrolKey>(body_json)?,
        CryptoPublishKeyPackage => body::<confidential::PublishPackage>(body_json)?,
        CryptoPropose | CryptoRecover => body::<confidential::Initialise>(body_json)?,
        CryptoCommit => body::<confidential::CommitEpoch>(body_json)?,
        CryptoEpochReady => body::<confidential::Ready>(body_json)?,
        CryptoReport => body::<confidential::TransitionFailure>(body_json)?,
        CryptoInspect | CryptoWelcome => body::<home::Empty>(body_json)?,
        CryptoHistory => body::<messaging::Page>(body_json)?,
        AccountPublicIdentity => body::<identity::PublicIdentityRequest>(body_json)?,
        RoomCreate => body::<conversations::Create>(body_json)?,
        RoomList => body::<conversations::List>(body_json)?,
        AgentList | DelegationList | ModerationFilters | ModerationRestrictions => {
            body::<home::InspectPage>(body_json)?
        }
        ServiceInspect | RoomInspect | AccountInspect | AccountDevices | RoomJoin | RoomLeave
        | DelegationInspect | DelegationPause | DelegationResume | DelegationRevoke => {
            body::<home::Empty>(body_json)?
        }
        RoomSetTopic => body::<conversations::Topic>(body_json)?,
        MessageSend | MessageReply | MessageAction => {
            if body_json.get("ciphertext").is_some() {
                body::<crypto::EncryptedBody>(body_json)?
            } else {
                body::<messaging::Send>(body_json)?
            }
        }
        HistoryPage | EventsSubscribe | EventsResume => body::<messaging::Page>(body_json)?,
        HistoryTail | CryptoTail => body::<messaging::Tail>(body_json)?,
        SearchQuery => body::<messaging::Search>(body_json)?,
        HistoryContext => body::<messaging::Context>(body_json)?,
        UnreadSet => body::<messaging::Unread>(body_json)?,
        OperationResolve | SearchCancel | AccountLifecycleOutcome => {
            body::<home::Resolve>(body_json)?
        }
        DelegationCreate => body::<delegation::Create>(body_json)?,
        ApprovalPrepare => body::<delegation::Prepare>(body_json)?,
        ApprovalApprove | ApprovalReject => body::<delegation::Decision>(body_json)?,
        ModerationIgnore | ModerationMute => body::<moderation::Filter>(body_json)?,
        ModerationSilence | ModerationKick | ModerationBan => {
            body::<moderation::Restriction>(body_json)?
        }
        _ => return Err(Invalid),
    };
    action.validate().map_err(|_| Invalid)?;
    action_bytes(&action).map_err(|_| Invalid)?;
    Ok(action)
}
pub fn value<T: serde::Serialize>(value: &T) -> Result<Json> {
    convert(Value::serialized(value).map_err(|_| Invalid)?)
}
/// Display a candidate from an authenticated home inspection response.
/// This does not verify its endpoint signature or construct operation authority.
pub fn pending_action(pending: &delegation::Pending) -> Result<Action> {
    let Value::Array(outer) =
        canonical_decode(&pending.candidate.0, ORDINARY_FRAME_BYTES).map_err(|_| Invalid)?
    else {
        return Err(Invalid);
    };
    let [
        Value::Bytes(_),
        Value::Map(_),
        Value::Bytes(payload),
        Value::Bytes(_),
    ] = outer.as_slice()
    else {
        return Err(Invalid);
    };
    if digest(payload) != pending.action_digest {
        return Err(Invalid);
    }
    let Value::Array(fields) =
        canonical_decode(payload, ORDINARY_FRAME_BYTES).map_err(|_| Invalid)?
    else {
        return Err(Invalid);
    };
    let [Value::Integer(version), Value::Integer(role), body] = fields.as_slice() else {
        return Err(Invalid);
    };
    if i128::from(*version) != 1 || i128::from(*role) != 1 {
        return Err(Invalid);
    }
    let action: Action = body.deserialized().map_err(|_| Invalid)?;
    if action.approval != Some(pending.approval)
        || action_bytes(&action).map_err(|_| Invalid)? != *payload
    {
        return Err(Invalid);
    }
    Ok(action)
}
fn convert(value: Value) -> Result<Json> {
    Ok(match value {
        Value::Integer(n) => {
            let n: i128 = n.into();
            if n >= 0 {
                Json::from(u64::try_from(n).map_err(|_| Invalid)?)
            } else {
                Json::from(i64::try_from(n).map_err(|_| Invalid)?)
            }
        }
        Value::Bytes(bytes) => Json::String(hex::encode(bytes)),
        Value::Text(text) => Json::String(text),
        Value::Bool(b) => Json::Bool(b),
        Value::Null => Json::Null,
        Value::Array(items) => Json::Array(items.into_iter().map(convert).collect::<Result<_>>()?),
        Value::Map(entries) => {
            let mut map = serde_json::Map::new();
            for (key, value) in entries {
                let key = match key {
                    Value::Text(s) => s,
                    Value::Integer(i) => i128::from(i).to_string(),
                    _ => return Err(Invalid),
                };
                if map.insert(key, convert(value)?).is_some() {
                    return Err(Invalid);
                }
            }
            Json::Object(map)
        }
        _ => return Err(Invalid),
    })
}
