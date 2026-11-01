// SPDX-License-Identifier: Apache-2.0
//! Durable exact-byte retries and private drafts in the endpoint SQLCipher store.
use crate::{
    clock::TimeBounds,
    protocol::*,
    storage::{self, Commit, Store},
};
use rusqlite::{OptionalExtension, params};
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("client storage is unavailable")]
    Storage(#[from] storage::Error),
    #[error("outbox identity or current clock does not match")]
    Invalid,
}
pub type Result<T> = std::result::Result<T, Error>;
#[derive(Clone, Debug)]
pub struct Pending {
    pub action: VerifiedAction,
    pub last_response: Option<Response>,
}

pub fn initialize(store: &mut Store) -> Result<()> {
    store.write(|tx|{
        tx.execute_batch("CREATE TABLE IF NOT EXISTS client_outbox(window TEXT NOT NULL,operation TEXT NOT NULL,digest BLOB NOT NULL,action BLOB NOT NULL,response BLOB,terminal INTEGER NOT NULL DEFAULT 0,created INTEGER NOT NULL,expires INTEGER NOT NULL,PRIMARY KEY(window,operation));
            CREATE TABLE IF NOT EXISTS client_clock(singleton INTEGER PRIMARY KEY CHECK(singleton=1),floor INTEGER NOT NULL);
            INSERT OR IGNORE INTO client_clock VALUES(1,0);
            CREATE TABLE IF NOT EXISTS client_drafts(room TEXT PRIMARY KEY,text TEXT NOT NULL,updated INTEGER NOT NULL);")?;
        Ok(Commit::new((),b"client outbox schema 1".to_vec()))
    })?;
    Ok(())
}
fn clock(tx: &rusqlite::Transaction<'_>, now: TimeBounds) -> rusqlite::Result<TimeBounds> {
    let floor = tx.query_row(
        "SELECT floor FROM client_clock WHERE singleton=1",
        [],
        |r| r.get(0),
    )?;
    let now = now.refresh().map_err(|_| rusqlite::Error::InvalidQuery)?;
    now.after_floor(floor)
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    tx.execute(
        "UPDATE client_clock SET floor=?1 WHERE singleton=1",
        [now.lower_ms],
    )?;
    Ok(now)
}
/// Must finish before a transport send. Existing operation IDs cannot change bytes.
pub fn prepare(
    store: &mut Store,
    action: &VerifiedAction,
    window: &RetryWindow,
    now: TimeBounds,
) -> Result<()> {
    if action.action().operation_id.window != window.id || now.upper_ms >= window.expires_ms {
        return Err(Error::Invalid);
    }
    store.write(|tx|{
        let now=clock(tx,now)?;
        if now.upper_ms>=window.expires_ms{return Err(rusqlite::Error::InvalidQuery);}
        let id=action.action().operation_id;
        let previous:Option<Vec<u8>>=tx.query_row("SELECT action FROM client_outbox WHERE window=?1 AND operation=?2",params![id.window.as_hex(),id.operation.as_hex()],|r|r.get(0)).optional()?;
        if let Some(previous)=previous {
            if previous!=action.signed_bytes(){return Err(rusqlite::Error::InvalidQuery);}
        }else{
            let (count,bytes):(u64,u64)=tx.query_row("SELECT count(*),coalesce(sum(length(action)),0) FROM client_outbox WHERE terminal=0",[],|r|Ok((r.get(0)?,r.get(1)?)))?;
            if count>=32||bytes+action.signed_bytes().len() as u64>8*1024*1024{return Err(rusqlite::Error::InvalidQuery);}
            tx.execute("INSERT INTO client_outbox(window,operation,digest,action,created,expires) VALUES(?1,?2,?3,?4,?5,?6)",params![id.window.as_hex(),id.operation.as_hex(),action.digest().as_bytes(),action.signed_bytes(),now.lower_ms,window.expires_ms])?;
        }
        Ok(Commit::new((),action.digest().as_bytes().to_vec()))
    })?;
    Ok(())
}
pub fn record(
    store: &mut Store,
    action: &VerifiedAction,
    response: &Verified<Response>,
    now: TimeBounds,
) -> Result<()> {
    let r = response.value();
    if r.home != action.action().home
        || r.operation_id != action.action().operation_id
        || r.action_digest != action.digest()
    {
        return Err(Error::Invalid);
    }
    let encoded = canonical_encode(
        &Value::serialized(r).map_err(|_| Error::Invalid)?,
        CRYPTO_FRAME_BYTES,
    )
    .map_err(|_| Error::Invalid)?;
    let terminal = matches!(
        r.outcome,
        Outcome::Committed { .. } | Outcome::Rejected { .. } | Outcome::Result { .. }
    );
    store.write(|tx|{
        clock(tx,now)?;
        let n=tx.execute("UPDATE client_outbox SET response=?1,terminal=?2 WHERE window=?3 AND operation=?4 AND digest=?5 AND action=?6",params![encoded,terminal,r.operation_id.window.as_hex(),r.operation_id.operation.as_hex(),action.digest().as_bytes(),action.signed_bytes()])?;
        if n!=1{return Err(rusqlite::Error::InvalidQuery);}
        Ok(Commit::new((),response.digest().as_bytes().to_vec()))
    })?;
    Ok(())
}
pub fn pending(store: &mut Store, key: &VerifyingKey) -> Result<Vec<Pending>> {
    Ok(store.read(Duration::from_secs(2),|db|{
        let mut q=db.prepare("SELECT action,response FROM client_outbox WHERE terminal=0 ORDER BY created,operation LIMIT 32")?;
        q.query_map([],|r|{
            let bytes:Vec<u8>=r.get(0)?;
            let action=verify_action(&bytes,key).map_err(|_|rusqlite::Error::InvalidQuery)?;
            let encoded:Option<Vec<u8>>=r.get(1)?;
            let last_response=encoded.map(|v|canonical_decode(&v,CRYPTO_FRAME_BYTES).and_then(|v|v.deserialized().map_err(|_|crate::protocol::Error::Encoding))).transpose().map_err(|_|rusqlite::Error::InvalidQuery)?;
            Ok(Pending{action,last_response})
        })?.collect()
    })?)
}
pub fn save_draft(store: &mut Store, room: RoomId, text: &str) -> Result<()> {
    if !text.is_empty() {
        crate::text::message(text).map_err(|_| Error::Invalid)?;
    }
    // Draft editing is local and grants no effect authority. An unavailable monitor
    // must not prevent preservation of text during a transport outage.
    let updated = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| Error::Invalid)?
        .as_millis()
        .min(i64::MAX as u128) as u64;
    store.write(|tx|{
        if text.is_empty(){tx.execute("DELETE FROM client_drafts WHERE room=?1",[room.to_string()])?;}else{
            let exists:bool=tx.query_row("SELECT EXISTS(SELECT 1 FROM client_drafts WHERE room=?1)",[room.to_string()],|r|r.get(0))?;
            let count:u64=tx.query_row("SELECT count(*) FROM client_drafts",[],|r|r.get(0))?;
            if !exists&&count>=64{return Err(rusqlite::Error::InvalidQuery);}
            tx.execute("INSERT INTO client_drafts VALUES(?1,?2,?3) ON CONFLICT(room) DO UPDATE SET text=excluded.text,updated=excluded.updated",params![room.to_string(),text,updated])?;
        }
        Ok(Commit::new((),digest(text.as_bytes()).as_bytes().to_vec()))
    })?;
    Ok(())
}
pub fn draft(store: &mut Store, room: RoomId) -> Result<Option<String>> {
    Ok(store.read(Duration::from_secs(1), |db| {
        db.query_row(
            "SELECT text FROM client_drafts WHERE room=?1",
            [room.to_string()],
            |r| r.get(0),
        )
        .optional()
    })?)
}
/// Resolution carries its own signed request identity and the original minimal outcome.
pub fn record_resolution(
    store: &mut Store,
    original: &VerifiedAction,
    query: &VerifiedAction,
    response: &Verified<Response>,
    now: TimeBounds,
) -> Result<()> {
    let body: crate::home::Resolve = query
        .action()
        .body
        .deserialized()
        .map_err(|_| Error::Invalid)?;
    let r = response.value();
    if query.action().operation != Operation::OperationResolve
        || query.action().target != Target::Service
        || query.action().home != original.action().home
        || query.action().actor.acting() != original.action().actor.acting()
        || body.operation_id != original.action().operation_id
        || body.action_digest != original.digest()
        || r.operation_id != query.action().operation_id
        || r.action_digest != query.digest()
        || r.home != query.action().home
    {
        return Err(Error::Invalid);
    }
    let encoded = canonical_encode(
        &Value::serialized(r).map_err(|_| Error::Invalid)?,
        CRYPTO_FRAME_BYTES,
    )
    .map_err(|_| Error::Invalid)?;
    let Outcome::Result { body } = &r.outcome else {
        return Ok(());
    };
    let resolved: crate::home::ResolveResult = body.deserialized().map_err(|_| Error::Invalid)?;
    if resolved.operation_id != original.action().operation_id
        || resolved.action_digest != original.digest()
    {
        return Err(Error::Invalid);
    }
    let terminal = matches!(
        resolved.outcome,
        Outcome::Committed { .. } | Outcome::Rejected { .. }
    );
    store.write(|tx|{
        clock(tx,now)?;
        let id=original.action().operation_id;
        let changed=tx.execute("UPDATE client_outbox SET response=?1,terminal=?2 WHERE window=?3 AND operation=?4 AND digest=?5 AND action=?6",params![encoded,terminal,id.window.as_hex(),id.operation.as_hex(),original.digest().as_bytes(),original.signed_bytes()])?;
        if changed!=1{return Err(rusqlite::Error::InvalidQuery);}
        Ok(Commit::new((),response.digest().as_bytes().to_vec()))
    })?;
    Ok(())
}
pub fn retain(store: &mut Store, now: TimeBounds) -> Result<()> {
    store.write(|tx| {
        let now = clock(tx, now)?;
        let before = now.lower_ms.saturating_sub(7 * 86_400_000);
        // Unresolved records remain explicit until resolved or deliberately discarded.
        tx.execute(
            "DELETE FROM client_outbox WHERE terminal=1 AND created<?1 AND expires<?1",
            [before],
        )?;
        tx.execute("DELETE FROM client_drafts WHERE updated<?1", [before])?;
        Ok(Commit::new((), b"client retention".to_vec()))
    })?;
    Ok(())
}
