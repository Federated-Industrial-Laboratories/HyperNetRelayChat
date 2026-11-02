// SPDX-License-Identifier: Apache-2.0
//! Exact credential, approved roster, and application authenticated-data encodings.
use super::*;
use crate::protocol::{
    Action, Actor, AgreementRef, EndpointActor, Operation, OperationId, Revision, ServiceId, Target,
};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EndpointCredential {
    pub room: RoomId,
    pub actor: EndpointActor,
    pub mls_key: Id,
}
impl EndpointCredential {
    pub fn bytes(&self) -> Result<Vec<u8>> {
        if self.actor.security_generation == 0 || self.actor.enrolment_generation == 0 {
            return Err(Error::Binding);
        }
        encode(&("HRC MLS BasicCredential", 1u8, self))
    }
    pub fn digest(&self) -> Result<Id> {
        Ok(digest(&self.bytes()?))
    }
    fn with_key(&self) -> Result<CredentialWithKey> {
        Ok(CredentialWithKey {
            credential: BasicCredential::new(self.bytes()?).into(),
            signature_key: self.mls_key.as_bytes().to_vec().into(),
        })
    }
}
/// Construct only from current HRC-authorised endpoint registrations. Constructing
/// this value performs structural checks; it does not create room permission.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ApprovedRoster {
    room: RoomId,
    members: Vec<EndpointCredential>,
}
impl ApprovedRoster {
    pub fn new(room: RoomId, members: Vec<EndpointCredential>) -> Result<Self> {
        if members.is_empty() || members.len() > MAX_ENDPOINTS {
            return Err(Error::Limit);
        }
        let mut endpoints = BTreeSet::new();
        let mut keys = BTreeSet::new();
        for member in &members {
            if member.room != room
                || !endpoints.insert(member.actor.endpoint)
                || !keys.insert(member.mls_key)
            {
                return Err(Error::Binding);
            }
            member.bytes()?;
        }
        Ok(Self { room, members })
    }
    pub fn room(&self) -> RoomId {
        self.room
    }
    pub fn members(&self) -> &[EndpointCredential] {
        &self.members
    }
    pub fn endpoint(&self, id: Id) -> Result<&EndpointCredential> {
        self.members
            .iter()
            .find(|m| m.actor.endpoint == id)
            .ok_or(Error::Binding)
    }
    pub(super) fn check(&self, members: impl Iterator<Item = Member>) -> Result<()> {
        Self::new(self.room, self.members.clone())?;
        let actual: Vec<_> = members.collect();
        if actual.len() != self.members.len() {
            return Err(Error::Binding);
        }
        let mut matched = BTreeSet::new();
        for member in actual {
            let expected = self
                .members
                .iter()
                .find(|m| m.mls_key.as_bytes().as_slice() == member.signature_key)
                .ok_or(Error::Binding)?;
            if member.credential != expected.with_key()?.credential
                || !matched.insert(expected.actor.endpoint)
            {
                return Err(Error::Binding);
            }
        }
        Ok(())
    }
    pub(super) fn credential(&self, credential: &Credential, actor: &EndpointActor) -> Result<()> {
        let member = self.endpoint(actor.endpoint)?;
        if &member.actor != actor || credential != &member.with_key()?.credential {
            return Err(Error::Binding);
        }
        Ok(())
    }
}

/// Public endpoint descriptor; its signing secret is loaded only inside a transaction.
#[derive(Clone, Debug)]
pub struct Device {
    pub actor: EndpointActor,
    pub mls_key: Id,
}
impl Device {
    pub fn provision(store: &mut Store, actor: EndpointActor) -> Result<Self> {
        if actor.enrolment_generation == 0 || actor.security_generation == 0 {
            return Err(Error::Binding);
        }
        let input = encode(&actor)?;
        atomic(store, "endpoint", &input, |tx| {
            let provider = Provider::new(tx);
            let keys = SignatureKeyPair::new(SUITE.signature_algorithm())
                .map_err(|_| Error::Verification)?;
            let mls_key =
                Id::from_bytes(keys.public().try_into().map_err(|_| Error::Verification)?);
            keys.store(provider.storage())?;
            tx.execute(
                "INSERT INTO crypto_devices(endpoint,actor,key) VALUES(?1,?2,?3)",
                rusqlite::params![
                    actor.endpoint.as_bytes().as_slice(),
                    input,
                    mls_key.as_bytes().as_slice()
                ],
            )?;
            Ok((Self { actor, mls_key }, mls_key.as_bytes().to_vec()))
        })
    }
    pub fn open(store: &mut Store, actor: &EndpointActor) -> Result<Self> {
        let (saved, key): (Vec<u8>, Vec<u8>) =
            store.read(std::time::Duration::from_secs(1), |conn| {
                conn.query_row(
                    "SELECT actor,key FROM crypto_devices WHERE endpoint=?1",
                    [actor.endpoint.as_bytes().as_slice()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
            })?;
        if encode(actor)? != saved {
            return Err(Error::Binding);
        }
        Ok(Self {
            actor: actor.clone(),
            mls_key: Id::from_bytes(key.try_into().map_err(|_| Error::Database)?),
        })
    }
    pub fn credential(&self, room: RoomId) -> EndpointCredential {
        EndpointCredential {
            room,
            actor: self.actor.clone(),
            mls_key: self.mls_key,
        }
    }
    pub(super) fn credential_with_key(&self, room: RoomId) -> Result<CredentialWithKey> {
        self.credential(room).with_key()
    }
    pub(super) fn check(&self, roster: &ApprovedRoster) -> Result<()> {
        if roster.endpoint(self.actor.endpoint)? != &self.credential(roster.room) {
            return Err(Error::Binding);
        }
        Ok(())
    }
    pub(super) fn group(&self, provider: &Provider<'_>, group: Id) -> Result<MlsGroup> {
        let mls = load(provider, group)?;
        let own = mls
            .members()
            .find(|member| member.index == mls.own_leaf_index())
            .ok_or(Error::Binding)?;
        if own.signature_key != self.mls_key.as_bytes().as_slice() {
            return Err(Error::Binding);
        }
        Ok(mls)
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EncryptedBody {
    pub group: Id,
    pub epoch: u64,
    #[serde(with = "bytes")]
    pub ciphertext: Vec<u8>,
    pub parent: Option<Id>,
    pub causation: Option<Id>,
}
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EncryptionContext {
    pub home: ServiceId,
    pub room: RoomId,
    pub operation_id: OperationId,
    pub actor: Actor,
    pub operation: Operation,
    pub expected: BTreeMap<Revision, u64>,
    pub approval: Option<Id>,
    pub agreement: Option<AgreementRef>,
    pub group: Id,
    pub epoch: u64,
    pub parent: Option<Id>,
    pub causation: Option<Id>,
}
impl EncryptionContext {
    pub fn from_action(action: &Action) -> Result<(Self, EncryptedBody)> {
        action.validate()?;
        let Target::Room(room) = action.target else {
            return Err(Error::Binding);
        };
        let body: EncryptedBody = action.body.deserialized().map_err(|_| Error::Invalid)?;
        let value = Self {
            home: action.home,
            room,
            operation_id: action.operation_id,
            actor: action.actor.clone(),
            operation: action.operation,
            expected: action.expected.clone(),
            approval: action.approval,
            agreement: action.agreement,
            group: body.group,
            epoch: body.epoch,
            parent: body.parent,
            causation: body.causation,
        };
        value.aad()?;
        if body.ciphertext.is_empty()
            || body.ciphertext.len() > crate::protocol::ORDINARY_FRAME_BYTES
        {
            return Err(Error::Limit);
        }
        Ok((value, body))
    }
    pub fn aad(&self) -> Result<Vec<u8>> {
        Action {
            home: self.home,
            operation_id: self.operation_id,
            actor: self.actor.clone(),
            target: Target::Room(self.room),
            operation: self.operation,
            body: crate::protocol::Value::Null,
            expected: self.expected.clone(),
            approval: self.approval,
            agreement: self.agreement,
        }
        .validate()?;
        if self.home != self.room.home
            || !matches!(
                self.operation,
                Operation::MessageSend | Operation::MessageReply | Operation::MessageAction
            )
            || self.epoch > i64::MAX as u64
        {
            return Err(Error::Binding);
        }
        let bytes = encode(&("HRC MLS application", 1u8, self))?;
        if bytes.len() > 8192 {
            return Err(Error::Limit);
        }
        Ok(bytes)
    }
    pub fn action(&self, ciphertext: Vec<u8>) -> Result<Action> {
        self.aad()?;
        Ok(Action {
            home: self.home,
            operation_id: self.operation_id,
            actor: self.actor.clone(),
            target: Target::Room(self.room),
            operation: self.operation,
            body: crate::protocol::Value::serialized(&EncryptedBody {
                group: self.group,
                epoch: self.epoch,
                ciphertext,
                parent: self.parent,
                causation: self.causation,
            })
            .map_err(|_| Error::Invalid)?,
            expected: self.expected.clone(),
            approval: self.approval,
            agreement: self.agreement,
        })
    }
}

/// The authenticated home event retains all original AAD fields and exact ciphertext.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct EncryptedEvent {
    pub context: EncryptionContext,
    pub ciphertext: crate::protocol::Blob,
}
impl EncryptedEvent {
    pub fn validate_event(&self, event: &crate::protocol::Event) -> Result<()> {
        let context = &self.context;
        if context.home != event.home
            || context.room != event.room
            || context.operation_id != event.operation_id
            || context.actor != event.actor
            || context.operation != event.kind
            || crate::protocol::action_digest(&context.action(self.ciphertext.0.clone())?)?
                != event.action_digest
        {
            return Err(Error::Binding);
        }
        Ok(())
    }
}
/// Versioned MLS plaintext. Limits apply to original text and grapheme-aligned mention spans.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApplicationMessage {
    pub text: String,
    pub mentions: Vec<crate::messaging::Mention>,
}
impl ApplicationMessage {
    pub fn validate(&self) -> Result<()> {
        crate::text::message(&self.text).map_err(|_| Error::Invalid)?;
        crate::messaging::mention_spans(&self.text, &self.mentions).map_err(|_| Error::Invalid)
    }
    pub fn bytes(&self) -> Result<Vec<u8>> {
        self.validate()?;
        encode(&("HRC MLS plaintext", 1u8, self))
    }
    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        let (domain, version, value): (String, u8, Self) = decode(bytes)?;
        if domain != "HRC MLS plaintext" || version != 1 {
            return Err(Error::Invalid);
        }
        value.validate()?;
        Ok(value)
    }
}
impl From<&str> for ApplicationMessage {
    fn from(text: &str) -> Self {
        Self {
            text: text.to_owned(),
            mentions: Vec::new(),
        }
    }
}
impl From<String> for ApplicationMessage {
    fn from(text: String) -> Self {
        Self {
            text,
            mentions: Vec::new(),
        }
    }
}
