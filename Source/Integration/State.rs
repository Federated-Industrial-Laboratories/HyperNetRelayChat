// SPDX-License-Identifier: Apache-2.0
//! Event acknowledgement and stable send identifiers share the encrypted writer.
use super::{Error, RESPONSE_BYTES, Result};
use crate::{
    client,
    protocol::*,
    storage::{Commit, Store},
};
use rusqlite::{OptionalExtension, params};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::time::Duration;
const READ: Duration = Duration::from_secs(1);
pub(super) fn encode<T: Serialize>(v: &T) -> rusqlite::Result<Vec<u8>> {
    let value = Value::serialized(v).map_err(|_| rusqlite::Error::InvalidQuery)?;
    canonical_encode(&value, RESPONSE_BYTES).map_err(|_| rusqlite::Error::InvalidQuery)
}
fn decode<T: DeserializeOwned>(b: &[u8]) -> rusqlite::Result<T> {
    if b.len() > RESPONSE_BYTES {
        return Err(rusqlite::Error::InvalidQuery);
    }
    canonical_decode(b, RESPONSE_BYTES)
        .and_then(|v| {
            v.deserialized()
                .map_err(|_| crate::protocol::Error::Encoding)
        })
        .map_err(|_| rusqlite::Error::InvalidQuery)
}
pub(super) fn initialise(store: &mut Store) -> Result<()> {
    store.write(|db| {
        db.execute_batch("CREATE TABLE IF NOT EXISTS integration_keys(id TEXT PRIMARY KEY,watermark INTEGER NOT NULL DEFAULT 0,paused INTEGER NOT NULL DEFAULT 0);
          CREATE TABLE IF NOT EXISTS integration_consumers(credential TEXT NOT NULL,name TEXT NOT NULL,room TEXT NOT NULL,cursor BLOB,live INTEGER NOT NULL DEFAULT 0,batch BLOB,ack TEXT,PRIMARY KEY(credential,name));
          CREATE TABLE IF NOT EXISTS integration_requests(credential TEXT NOT NULL,request INTEGER NOT NULL,payload BLOB NOT NULL,operation BLOB NOT NULL,digest BLOB NOT NULL,expires INTEGER NOT NULL,consumer TEXT,trigger TEXT,outcome BLOB,PRIMARY KEY(credential,request),UNIQUE(credential,consumer,trigger));")?;
        Ok(Commit::new((),b"HRC.Integration.Schema.1".to_vec()))
    }).map_err(|_|Error::State)
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(super) struct Batch {
    pub id: Id,
    pub room: RoomId,
    pub events: Vec<Event>,
    pub content: Vec<(Id, client::MessageContent)>,
    pub cursor: Blob,
    pub historical: bool,
    pub has_more: bool,
    pub room_revision: u64,
    pub filter_revision: u64,
    pub expires_ms: u64,
}
pub(super) struct Consumer {
    pub room: RoomId,
    pub cursor: Option<Blob>,
    pub live: bool,
    pub batch: Option<Batch>,
    pub ack: Option<String>,
}
fn name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_-".contains(&b))
}
pub(super) fn open(store: &mut Store, key: Id, n: &str, room: RoomId) -> Result<()> {
    if !name(n) {
        return Err(Error::Invalid);
    }
    if let Some(c) = consumer(store, key, n)? {
        return if c.room == room {
            Ok(())
        } else {
            Err(Error::Conflict)
        };
    }
    store
        .write(|db| {
            let count: u64 =
                db.query_row("SELECT count(*) FROM integration_consumers", [], |r| {
                    r.get(0)
                })?;
            if count >= 32 {
                return Err(rusqlite::Error::InvalidQuery);
            }
            db.execute(
                "INSERT INTO integration_consumers(credential,name,room) VALUES(?1,?2,?3)",
                params![key.as_hex(), n, room.to_string()],
            )?;
            Ok(Commit::new(
                (),
                encode(&("HRC.Integration.Consumer", key, n, room))?,
            ))
        })
        .map_err(|_| Error::Capacity)
}
pub(super) fn consumer(store: &mut Store, key: Id, n: &str) -> Result<Option<Consumer>> {
    if !name(n) {
        return Err(Error::Invalid);
    }
    store.read(READ,|db|db.query_row("SELECT room,cursor,live,batch,ack FROM integration_consumers WHERE credential=?1 AND name=?2",params![key.as_hex(),n],|r| {
        Ok(Consumer{room:r.get::<_,String>(0)?.parse().map_err(|_|rusqlite::Error::InvalidQuery)?,
            cursor:r.get::<_,Option<Vec<u8>>>(1)?.map(Blob),live:r.get(2)?,
            batch:r.get::<_,Option<Vec<u8>>>(3)?.map(|b|decode(&b)).transpose()?,ack:r.get(4)?})
    }).optional()).map_err(|_|Error::State)
}
pub(super) fn batch(store: &mut Store, key: Id, n: &str, b: &Batch) -> Result<()> {
    store.write(|db| {
        if db.execute("UPDATE integration_consumers SET batch=?1 WHERE credential=?2 AND name=?3 AND batch IS NULL AND room=?4",params![encode(b)?,key.as_hex(),n,b.room.to_string()])?!=1 {return Err(rusqlite::Error::InvalidQuery);}
        Ok(Commit::new((),encode(&("HRC.Integration.Batch",key,n,b.id))?))
    }).map_err(|_|Error::State)
}
pub(super) fn start(store: &mut Store, key: Id, n: &str, cursor: &Blob) -> Result<()> {
    store.write(|db| {
        if db.execute("UPDATE integration_consumers SET cursor=?1,live=1 WHERE credential=?2 AND name=?3 AND cursor IS NULL AND batch IS NULL",params![cursor.0,key.as_hex(),n])?!=1 {return Err(rusqlite::Error::InvalidQuery);}
        Ok(Commit::new((),encode(&("HRC.Integration.Start",key,n))?))
    }).map_err(|_|Error::State)
}
pub(super) fn acknowledge(store: &mut Store, key: Id, n: &str, id: Id) -> Result<()> {
    let c = consumer(store, key, n)?.ok_or(Error::Invalid)?;
    let Some(b) = c.batch else {
        return if c.ack == Some(id.as_hex()) {
            Ok(())
        } else {
            Err(Error::Conflict)
        };
    };
    if b.id != id {
        return Err(Error::Conflict);
    }
    store.write(|db| {
        db.execute("UPDATE integration_consumers SET cursor=?1,live=?2,batch=NULL,ack=?5 WHERE credential=?3 AND name=?4",params![b.cursor.0,c.live||!b.has_more,key.as_hex(),n,id.as_hex()])?;
        Ok(Commit::new((),encode(&("HRC.Integration.Acknowledge",key,n,id))?))
    }).map_err(|_|Error::State)
}
pub(super) fn resynchronise(store: &mut Store, key: Id, n: &str) -> Result<()> {
    store.write(|db| {
        if db.execute("UPDATE integration_consumers SET cursor=NULL,live=0,batch=NULL WHERE credential=?1 AND name=?2",params![key.as_hex(),n])?!=1 {return Err(rusqlite::Error::InvalidQuery);}
        Ok(Commit::new((),encode(&("HRC.Integration.Resynchronise",key,n))?))
    }).map_err(|_|Error::State)
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Request {
    pub payload: Id,
    pub operation: OperationId,
    pub digest: Id,
    pub outcome: Option<Outcome>,
}
pub(super) fn lookup(store: &mut Store, key: Id, id: u64) -> Result<Option<Request>> {
    store.read(READ,|db|db.query_row("SELECT payload,operation,digest,outcome FROM integration_requests WHERE credential=?1 AND request=?2",params![key.as_hex(),id],|r| {
        let parse=|b:Vec<u8>|b.try_into().map(Id::from_bytes).map_err(|_|rusqlite::Error::InvalidQuery);
        Ok(Request{payload:parse(r.get(0)?)?,operation:decode(&r.get::<_,Vec<u8>>(1)?)?,digest:parse(r.get(2)?)?,outcome:r.get::<_,Option<Vec<u8>>>(3)?.map(|b|decode(&b)).transpose()?})
    }).optional()).map_err(|_|Error::State)
}
pub(super) fn watermark(store: &mut Store, key: Id) -> Result<u64> {
    store
        .read(READ, |db| {
            db.query_row(
                "SELECT watermark FROM integration_keys WHERE id=?1",
                [key.as_hex()],
                |r| r.get(0),
            )
            .optional()
            .map(|v| v.unwrap_or(0))
        })
        .map_err(|_| Error::State)
}
pub(super) fn prepare(
    db: &rusqlite::Transaction<'_>,
    key: Id,
    id: u64,
    payload: Id,
    action: &VerifiedAction,
    expires: u64,
    trigger: Option<(&str, Id)>,
) -> rusqlite::Result<()> {
    if id == 0 || id > 9_007_199_254_740_991 {
        return Err(rusqlite::Error::InvalidQuery);
    }
    db.execute(
        "INSERT OR IGNORE INTO integration_keys(id) VALUES(?1)",
        [key.as_hex()],
    )?;
    let watermark: u64 = db.query_row(
        "SELECT watermark FROM integration_keys WHERE id=?1",
        [key.as_hex()],
        |r| r.get(0),
    )?;
    let count: u64 = db.query_row("SELECT count(*) FROM integration_requests", [], |r| {
        r.get(0)
    })?;
    if id != watermark + 1 || count >= 4096 {
        return Err(rusqlite::Error::InvalidQuery);
    }
    db.execute("INSERT INTO integration_requests(credential,request,payload,operation,digest,expires,consumer,trigger) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",params![key.as_hex(),id,payload.as_bytes(),encode(&action.action().operation_id)?,action.digest().as_bytes(),expires,trigger.map(|t|t.0),trigger.map(|t|t.1.as_hex())])?;
    db.execute(
        "UPDATE integration_keys SET watermark=?1 WHERE id=?2",
        params![id, key.as_hex()],
    )?;
    Ok(())
}
pub(super) fn complete(store: &mut Store, key: Id, id: u64, outcome: &Outcome) -> Result<()> {
    if !matches!(
        outcome,
        Outcome::Committed { .. } | Outcome::Rejected { .. }
    ) {
        return Ok(());
    }
    store
        .write(|db| {
            if db.execute(
                "UPDATE integration_requests SET outcome=?1 WHERE credential=?2 AND request=?3",
                params![encode(outcome)?, key.as_hex(), id],
            )? != 1
            {
                return Err(rusqlite::Error::InvalidQuery);
            }
            Ok(Commit::new(
                (),
                encode(&("HRC.Integration.Complete", key, id))?,
            ))
        })
        .map_err(|_| Error::State)
}
pub(super) fn maintain(store: &mut Store, now: u64) -> Result<()> {
    store
        .write(|db| {
            // Unknown outcomes remain retained; the watermark forbids reuse after retirement.
            db.execute(
                "DELETE FROM integration_requests WHERE outcome IS NOT NULL AND expires<?1",
                [now.saturating_sub(7 * 86400000)],
            )?;
            Ok(Commit::new((), b"HRC.Integration.Retain".to_vec()))
        })
        .map_err(|_| Error::State)
}

pub(super) fn paused(store: &mut Store, key: Id) -> Result<bool> {
    store
        .read(READ, |db| {
            db.query_row(
                "SELECT paused FROM integration_keys WHERE id=?1",
                [key.as_hex()],
                |r| r.get(0),
            )
            .optional()
            .map(|v| v.unwrap_or(false))
        })
        .map_err(|_| Error::State)
}
pub(super) fn pause(store: &mut Store, key: Id, value: bool) -> Result<()> {
    store.write(|db| {
        db.execute("INSERT INTO integration_keys(id,paused) VALUES(?1,?2) ON CONFLICT(id) DO UPDATE SET paused=excluded.paused",params![key.as_hex(),value])?;
        Ok(Commit::new((),encode(&("HRC.Integration.Pause",key,value))?))
    }).map_err(|_|Error::State)
}
