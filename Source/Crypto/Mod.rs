// SPDX-License-Identifier: Apache-2.0
//! Persistent MLS endpoints. Room authority is supplied by the authenticated domain boundary.
#[path = "Binding.rs"]
mod binding;
#[path = "Groups.rs"]
mod groups;
#[path = "Messages.rs"]
mod messages;
#[path = "Provider.rs"]
mod provider;
#[path = "Public.rs"]
mod public;
#[path = "Retention.rs"]
mod retention;

use crate::{
    protocol::{Id, RoomId},
    storage::{Commit, Store},
};
pub use binding::*;
pub use groups::*;
pub use messages::*;
use openmls::prelude::*;
use openmls_basic_credential::SignatureKeyPair;
use openmls_traits::OpenMlsProvider;
use provider::Provider;
pub use provider::initialize;
pub use public::*;
pub use retention::*;
use rusqlite::{Connection, OptionalExtension, Transaction};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use tls_codec::{Deserialize as TlsDeserializeTrait, Serialize as TlsSerializeTrait};

mod bytes {
    use serde::{
        Deserializer, Serializer,
        de::{self, Visitor},
    };
    pub fn serialize<S: Serializer>(
        bytes: &[u8],
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_bytes(bytes)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Vec<u8>, D::Error> {
        struct Bytes;
        impl Visitor<'_> for Bytes {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a byte string")
            }
            fn visit_bytes<E: de::Error>(
                self,
                value: &[u8],
            ) -> std::result::Result<Self::Value, E> {
                Ok(value.to_vec())
            }
            fn visit_byte_buf<E: de::Error>(
                self,
                value: Vec<u8>,
            ) -> std::result::Result<Self::Value, E> {
                Ok(value)
            }
        }
        deserializer.deserialize_byte_buf(Bytes)
    }
}
mod optional_bytes {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    #[derive(Serialize, Deserialize)]
    struct Bytes(#[serde(with = "super::bytes")] Vec<u8>);
    pub fn serialize<S: Serializer>(
        bytes: &Option<Vec<u8>>,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        match bytes {
            Some(bytes) => serializer.serialize_some(&Bytes(bytes.clone())),
            None => serializer.serialize_none(),
        }
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(
        deserializer: D,
    ) -> std::result::Result<Option<Vec<u8>>, D::Error> {
        Ok(Option::<Bytes>::deserialize(deserializer)?.map(|b| b.0))
    }
}

pub const SUITE: Ciphersuite = Ciphersuite::MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519;
pub const MAX_ENDPOINTS: usize = 64;
pub const MAX_FORWARD_DISTANCE: u32 = 8;
pub const MAX_MESSAGES_PER_EPOCH: u64 = 4096;
const RECORD_LIMIT: i64 = 10_000;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("cryptographic input is invalid")]
    Invalid,
    #[error("MLS identity or approved membership differs")]
    Binding,
    #[error("cryptographic operation conflicts with durable state")]
    Conflict,
    #[error("encrypted conversation requires resynchronisation")]
    Resynchronise,
    #[error("encrypted conversation is suspended")]
    Suspended,
    #[error("encrypted state or message exceeds its budget")]
    Limit,
    #[error("cryptographic verification failed")]
    Verification,
    #[error("encrypted persistence failed")]
    Database,
    #[error(transparent)]
    Storage(#[from] crate::storage::Error),
}
pub type Result<T> = std::result::Result<T, Error>;
impl From<rusqlite::Error> for Error {
    fn from(_: rusqlite::Error) -> Self {
        Self::Database
    }
}
impl From<crate::protocol::Error> for Error {
    fn from(_: crate::protocol::Error) -> Self {
        Self::Invalid
    }
}
fn encode<T: Serialize>(v: &T) -> Result<Vec<u8>> {
    crate::protocol::canonical_encode(
        &crate::protocol::Value::serialized(v).map_err(|_| Error::Invalid)?,
        crate::protocol::CRYPTO_FRAME_BYTES,
    )
    .map_err(Into::into)
}
fn decode<T: DeserializeOwned>(b: &[u8]) -> Result<T> {
    crate::protocol::canonical_decode(b, crate::protocol::CRYPTO_FRAME_BYTES)?
        .deserialized()
        .map_err(|_| Error::Invalid)
}
fn digest(b: &[u8]) -> Id {
    Id::from_bytes(Sha256::digest(b).into())
}
fn tls<T: TlsSerializeTrait>(value: &T) -> Result<Vec<u8>> {
    let bytes = value.tls_serialize_detached().map_err(|_| Error::Invalid)?;
    if bytes.len() > crate::protocol::CRYPTO_FRAME_BYTES {
        return Err(Error::Limit);
    }
    Ok(bytes)
}
fn message(bytes: &[u8]) -> Result<MlsMessageIn> {
    if bytes.is_empty() || bytes.len() > crate::protocol::CRYPTO_FRAME_BYTES {
        return Err(Error::Limit);
    }
    MlsMessageIn::tls_deserialize_exact(bytes).map_err(|_| Error::Invalid)
}
fn atomic<T>(
    store: &mut Store,
    label: &str,
    input: &[u8],
    f: impl FnOnce(&Transaction<'_>) -> Result<(T, Vec<u8>)>,
) -> Result<T> {
    let mut failure = None;
    let result = store.write(|tx| match f(tx) {
        Ok((value, outcome)) => {
            let change = encode(&(
                "HRC crypto transaction",
                1u8,
                label,
                digest(input),
                digest(&outcome),
            ))
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
            Ok(Commit::new(value, change))
        }
        Err(error) => {
            failure = Some(error);
            Err(rusqlite::Error::InvalidQuery)
        }
    });
    match result {
        Ok(value) => Ok(value),
        Err(error) => Err(failure.unwrap_or(Error::Storage(error))),
    }
}
fn group_id(group: Id) -> GroupId {
    GroupId::from_slice(group.as_bytes())
}
fn signer(provider: &Provider<'_>, key: Id) -> Result<SignatureKeyPair> {
    SignatureKeyPair::read(
        provider.storage(),
        key.as_bytes(),
        SUITE.signature_algorithm(),
    )
    .ok_or(Error::Database)
}
fn load(provider: &Provider<'_>, group: Id) -> Result<MlsGroup> {
    MlsGroup::load(provider.storage(), &group_id(group))?.ok_or(Error::Resynchronise)
}
fn metadata(conn: &Connection, group: Id) -> Result<(RoomId, u64, bool)> {
    let (room, cursor, frozen): (Vec<u8>, u64, bool) = conn.query_row(
        "SELECT room,cursor,frozen FROM crypto_groups WHERE id=?1 AND mode='member'",
        [group.as_bytes().as_slice()],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    )?;
    Ok((decode(&room)?, cursor, frozen))
}
fn check_cursor(conn: &Connection, group: Id, prior: u64, next: u64) -> Result<()> {
    let (_, cursor, frozen) = metadata(conn, group)?;
    if frozen {
        return Err(Error::Suspended);
    }
    if prior != cursor || next <= prior || next > i64::MAX as u64 {
        return Err(Error::Resynchronise);
    }
    Ok(())
}
fn join_config() -> MlsGroupJoinConfig {
    MlsGroupJoinConfig::builder()
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(0)
        .number_of_resumption_psks(0)
        .use_ratchet_tree_extension(true)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(0, MAX_FORWARD_DISTANCE))
        .build()
}
fn create_config() -> MlsGroupCreateConfig {
    MlsGroupCreateConfig::builder()
        .ciphersuite(SUITE)
        .wire_format_policy(PURE_PLAINTEXT_WIRE_FORMAT_POLICY)
        .max_past_epochs(0)
        .number_of_resumption_psks(0)
        .use_ratchet_tree_extension(true)
        .sender_ratchet_configuration(SenderRatchetConfiguration::new(0, MAX_FORWARD_DISTANCE))
        .build()
}

#[cfg(test)]
#[path = "../../Tests/Crypto/Conversations.rs"]
mod tests;
