// SPDX-License-Identifier: Apache-2.0
//! Shared operation boundary values; verified transport is supplied by the service.
use crate::{protocol::*, storage};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};

pub type Result<T> = std::result::Result<T, Error>;
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("{0}")]
    Storage(#[from] storage::Error),
    #[error("invalid or unavailable conversation state")]
    Invalid,
    #[error("operation refused: {0}")]
    Refused(&'static str),
}
#[derive(Clone, Debug)]
pub struct EndpointRecord {
    pub acting: EndpointActor,
    pub classification: AccountClass,
    pub key: VerifyingKey,
    pub principal: Id,
    pub revision: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Invitation {
    pub home: ServiceId,
    pub service_key: Id,
    pub id: Id,
    pub principal: Id,
    pub classification: AccountClass,
    pub expires_ms: u64,
}
/// Construct only after the service has verified challenge possession and HyperNet context.
#[derive(Clone, Debug)]
pub struct AuthenticatedSession {
    pub(crate) acting: EndpointActor,
    pub(crate) principal: Id,
    pub(crate) signer: Id,
    pub session: Id,
    pub transport_generation: u64,
}
impl AuthenticatedSession {
    pub fn new(
        record: &EndpointRecord,
        principal: Id,
        session: Id,
        transport_generation: u64,
    ) -> Result<Self> {
        if record.principal != principal || transport_generation == 0 {
            return Err(Error::Invalid);
        }
        Ok(Self {
            acting: record.acting.clone(),
            principal,
            signer: Id::from_bytes(record.key.to_bytes()),
            session,
            transport_generation,
        })
    }
}
#[derive(Clone, Default)]
pub struct Cancellation(Arc<AtomicBool>);
impl Cancellation {
    pub fn cancel(&self) {
        self.0.store(true, Ordering::Release);
    }
    pub fn is_cancelled(&self) -> bool {
        self.0.load(Ordering::Acquire)
    }
}

#[derive(Debug)]
pub(crate) enum Fault {
    Sql(rusqlite::Error),
    Reject(ErrorCode, &'static str),
}
impl From<rusqlite::Error> for Fault {
    fn from(e: rusqlite::Error) -> Self {
        Self::Sql(e)
    }
}
pub(crate) type Domain<T> = std::result::Result<T, Fault>;
pub(crate) fn deny<T>(detail: &'static str) -> Domain<T> {
    Err(Fault::Reject(ErrorCode::Denied, detail))
}
pub(crate) fn invalid<T>(detail: &'static str) -> Domain<T> {
    Err(Fault::Reject(ErrorCode::InvalidInput, detail))
}
pub(crate) fn conflict<T>(detail: &'static str) -> Domain<T> {
    Err(Fault::Reject(ErrorCode::Conflict, detail))
}
pub(crate) fn unpack<T: DeserializeOwned>(v: &Value) -> Domain<T> {
    v.deserialized()
        .map_err(|_| Fault::Reject(ErrorCode::InvalidInput, "Body"))
}
pub(crate) fn value<T: Serialize>(v: &T) -> Domain<Value> {
    Value::serialized(v).map_err(|_| Fault::Reject(ErrorCode::InvalidInput, "Representation"))
}
pub(crate) fn encode<T: Serialize>(v: &T) -> rusqlite::Result<Vec<u8>> {
    let value = Value::serialized(v).map_err(|_| rusqlite::Error::InvalidQuery)?;
    canonical_encode(&value, CRYPTO_FRAME_BYTES).map_err(|_| rusqlite::Error::InvalidQuery)
}
pub(crate) fn decode<T: DeserializeOwned>(v: &[u8]) -> rusqlite::Result<T> {
    canonical_decode(v, CRYPTO_FRAME_BYTES)
        .and_then(|v| {
            v.deserialized()
                .map_err(|_| crate::protocol::Error::Invalid)
        })
        .map_err(|_| rusqlite::Error::InvalidQuery)
}
pub(crate) fn sql_fault(e: Fault) -> rusqlite::Error {
    match e {
        Fault::Sql(e) => e,
        _ => rusqlite::Error::InvalidQuery,
    }
}
pub(crate) fn random() -> Domain<Id> {
    Id::random().map_err(|_| Fault::Reject(ErrorCode::Unavailable, "Random"))
}
pub(crate) fn id_column(row: &rusqlite::Row<'_>, i: usize) -> rusqlite::Result<Id> {
    let s: String = row.get(i)?;
    Id::from_hex(&s).map_err(|_| rusqlite::Error::InvalidQuery)
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Empty {}
pub(crate) fn empty(v: &Value) -> Domain<()> {
    unpack::<Empty>(v).map(|_| ())
}

pub(crate) const DAY: u64 = 86_400_000;
pub(crate) const RETENTION: u64 = 30 * DAY;
pub(crate) const HISTORY_QUOTA: u64 = 10 * 1024 * 1024 * 1024;
