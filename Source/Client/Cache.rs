// SPDX-License-Identifier: Apache-2.0
//! Atomic filtered event/cursor cache and local preferences under the existing encrypted writer.
use super::{Preferences, RoomPreferences};
use crate::{
    conversations, messaging,
    protocol::*,
    storage::{self, Commit, Store},
};
use rusqlite::{OptionalExtension, params};
use serde::{Serialize, de::DeserializeOwned};
use std::time::Duration;
type RoomMetadata = (Option<Vec<u8>>, Option<Vec<u8>>, Option<String>);
const TIMEOUT: Duration = Duration::from_secs(2);
pub(super) fn encode<T: Serialize>(v: &T) -> rusqlite::Result<Vec<u8>> {
    canonical_encode(
        &Value::serialized(v).map_err(|_| rusqlite::Error::InvalidQuery)?,
        CRYPTO_FRAME_BYTES,
    )
    .map_err(|_| rusqlite::Error::InvalidQuery)
}
pub(super) fn decode<T: DeserializeOwned>(v: &[u8]) -> rusqlite::Result<T> {
    canonical_decode(v, CRYPTO_FRAME_BYTES)
        .map_err(|_| rusqlite::Error::InvalidQuery)?
        .deserialized()
        .map_err(|_| rusqlite::Error::InvalidQuery)
}
pub(super) fn initialize(store: &mut Store, origin: ServiceId) -> storage::Result<()> {
    let version=store.read(TIMEOUT,|db| {let exists:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='client_cache_meta' AND type='table')",[],|r|r.get(0))?;if exists {db.query_row("SELECT version FROM client_cache_meta WHERE singleton=1",[],|r|r.get::<_,u64>(0)).map(Some)}else{Ok(None)}})?;
    if version == Some(2) {
        return Ok(());
    }
    if version == Some(1) {
        return store.write(|db| {
            db.execute_batch("ALTER TABLE client_filters RENAME TO client_filters_v1; CREATE TABLE client_filters(home TEXT NOT NULL,subject TEXT NOT NULL,ignored INTEGER NOT NULL,muted INTEGER NOT NULL,PRIMARY KEY(home,subject));")?;
            db.execute("INSERT INTO client_filters SELECT ?1,subject,ignored,muted FROM client_filters_v1", [origin.to_string()])?;
            db.execute_batch("DROP TABLE client_filters_v1; UPDATE client_cache_meta SET version=2 WHERE singleton=1;")?;
            Ok(Commit::new((), b"HRC.ClientCache.Schema.2".to_vec()))
        });
    }
    if version.is_some() {
        return Err(storage::Error::InvalidInput);
    }
    store.write(|db|{db.execute_batch("CREATE TABLE client_cache_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1),version INTEGER NOT NULL);INSERT INTO client_cache_meta VALUES(1,2);CREATE TABLE client_rooms(id TEXT PRIMARY KEY,summary BLOB NOT NULL,cursor BLOB,members BLOB,updated INTEGER NOT NULL DEFAULT 0,gap TEXT);CREATE TABLE client_events(id TEXT PRIMARY KEY,room TEXT NOT NULL,sequence INTEGER NOT NULL,created INTEGER NOT NULL,event BLOB NOT NULL,bytes INTEGER NOT NULL,UNIQUE(room,sequence));CREATE INDEX client_events_room ON client_events(room,sequence);CREATE TABLE client_preferences(id TEXT PRIMARY KEY,value BLOB NOT NULL);CREATE TABLE client_candidates(id TEXT PRIMARY KEY,action BLOB NOT NULL,expires INTEGER NOT NULL);CREATE TABLE client_filters(home TEXT NOT NULL,subject TEXT NOT NULL,ignored INTEGER NOT NULL,muted INTEGER NOT NULL,PRIMARY KEY(home,subject));")?;Ok(Commit::new((),b"HRC.ClientCache.Schema.2".to_vec()))})
}
pub(super) fn preferences<T: DeserializeOwned + Default>(
    store: &mut Store,
    id: &str,
) -> storage::Result<T> {
    store.read(TIMEOUT, |db| {
        let bytes: Option<Vec<u8>> = db
            .query_row(
                "SELECT value FROM client_preferences WHERE id=?1",
                [id],
                |r| r.get(0),
            )
            .optional()?;
        bytes
            .map(|v| serde_json::from_slice(&v).map_err(|_| rusqlite::Error::InvalidQuery))
            .transpose()
            .map(|v| v.unwrap_or_default())
    })
}
pub(super) fn save_preferences<T: Serialize>(
    store: &mut Store,
    id: &str,
    prefs: &T,
) -> storage::Result<()> {
    let bytes = serde_json::to_vec(prefs).map_err(|_| storage::Error::InvalidInput)?;
    if bytes.len() > 4096 {
        return Err(storage::Error::InvalidInput);
    }
    store.write(|db|{db.execute("INSERT INTO client_preferences VALUES(?1,?2) ON CONFLICT(id) DO UPDATE SET value=excluded.value",params![id,bytes])?;Ok(Commit::new((),encode(&("HRC.ClientPreferences",id,digest(&bytes)))?))})
}
pub(super) fn validate_preferences(p: &Preferences) -> bool {
    p.text_scale.is_finite() && (0.75..=2.0).contains(&p.text_scale)
}
pub(super) fn room_preferences(
    store: &mut Store,
    room: RoomId,
) -> storage::Result<RoomPreferences> {
    preferences(store, &room.to_string())
}
pub(super) fn rooms(store: &mut Store) -> storage::Result<Vec<conversations::Summary>> {
    store.read(TIMEOUT, |db| {
        let mut stmt = db.prepare("SELECT summary FROM client_rooms ORDER BY id LIMIT 256")?;
        stmt.query_map([], |r| decode(&r.get::<_, Vec<u8>>(0)?))?
            .collect()
    })
}
pub(super) fn save_rooms(
    store: &mut Store,
    home: ServiceId,
    rooms: &[conversations::Summary],
) -> storage::Result<()> {
    if rooms.len() > 256 || rooms.iter().any(|room| room.room.home != home) {
        return Err(storage::Error::InvalidInput);
    }
    store.write(|db|{
  // Disappeared or inaccessible rooms cannot retain an apparently current view.
  let ids:std::collections::BTreeSet<_>=rooms.iter().map(|r|r.room.to_string()).collect();
  let mut stmt=db.prepare("SELECT id FROM client_rooms")?;let old=stmt.query_map([],|r|r.get::<_,String>(0))?.collect::<rusqlite::Result<Vec<_>>>()?;drop(stmt);
  for id in old {let room:RoomId=id.parse().map_err(|_|rusqlite::Error::InvalidQuery)?;if room.home==home&&!ids.contains(&id){db.execute("DELETE FROM client_events WHERE room=?1",[&id])?;db.execute("DELETE FROM client_rooms WHERE id=?1",[&id])?;}}
  for room in rooms {db.execute("INSERT INTO client_rooms(id,summary) VALUES(?1,?2) ON CONFLICT(id) DO UPDATE SET summary=excluded.summary",params![room.room.to_string(),encode(room)?])?;if !room.joined {db.execute("DELETE FROM client_events WHERE room=?1",[room.room.to_string()])?;db.execute("UPDATE client_rooms SET cursor=NULL,members=NULL WHERE id=?1",[room.room.to_string()])?;}}
  let count:u64=db.query_row("SELECT count(*) FROM client_rooms",[],|r|r.get(0))?;if count>256{return Err(rusqlite::Error::InvalidQuery);}
  Ok(Commit::new((),encode(&("HRC.ClientRooms",digest(&rooms.iter().map(encode).collect::<rusqlite::Result<Vec<_>>>()?.concat())))?))
 })
}
pub(super) struct Cached {
    pub events: Vec<Event>,
    pub cursor: Option<Blob>,
    pub members: Vec<conversations::Member>,
    pub gap: Option<String>,
}
pub(super) fn room(store: &mut Store, room: RoomId) -> storage::Result<Cached> {
    store.read(TIMEOUT,|db|{
 let meta:Option<RoomMetadata>=db.query_row("SELECT cursor,members,gap FROM client_rooms WHERE id=?1",[room.to_string()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
 let mut stmt=db.prepare("SELECT event FROM (SELECT event,sequence FROM client_events WHERE room=?1 ORDER BY sequence DESC LIMIT 256) ORDER BY sequence")?;
 let events=stmt.query_map([room.to_string()],|r|decode(&r.get::<_,Vec<u8>>(0)?))?.collect::<rusqlite::Result<Vec<_>>>()?;
 let (cursor,members,gap)=meta.unwrap_or_default();Ok(Cached{events,cursor:cursor.map(Blob),members:members.map(|v|decode(&v)).transpose()?.unwrap_or_default(),gap})
})
}
pub(super) fn inspection_failed(
    store: &mut Store,
    operation: Operation,
    room: RoomId,
    error: &super::Error,
) -> storage::Result<bool> {
    // A history cursor can expire or lose its room revision while access remains
    // valid. Deleting encrypted events would also erase unrecoverable plaintext.
    if operation == Operation::CryptoHistory {
        if cursor_context_changed(error) {
            return Ok(false);
        }
        if let Some(detail) = cursor_gap(error) {
            // Keep MLS and decrypted archive associations; the missing interval
            // remains explicit and cannot be replaced by a cursorless retry.
            store.write(|db| {
                db.execute(
                    "UPDATE client_rooms SET gap=?2 WHERE id=?1",
                    params![room.to_string(), detail],
                )?;
                Ok(Commit::new(
                    (),
                    encode(&("HRC.ClientHistoryGap", room, detail))?,
                ))
            })?;
            return Ok(true);
        }
    }
    if !access_unavailable(error) {
        return Ok(false);
    }
    invalidate(store, room)?;
    Ok(true)
}
pub(super) fn cursor_context_changed(error: &super::Error) -> bool {
    matches!(error,
        super::Error::Rejected { code: ErrorCode::ResynchronisationRequired, detail }
        | super::Error::Refused { code: ErrorCode::ResynchronisationRequired, detail, .. }
        if detail == "CursorContext")
}
pub(super) fn cursor_gap(error: &super::Error) -> Option<&str> {
    match error {
        super::Error::Rejected {
            code: ErrorCode::ResynchronisationRequired,
            detail,
        }
        | super::Error::Refused {
            code: ErrorCode::ResynchronisationRequired,
            detail,
            ..
        } if matches!(detail.as_str(), "CursorHistoryGap" | "CursorPosition") => Some(detail),
        _ => None,
    }
}
/// Replace community presentation under a fresh access context, never MLS history.
pub(super) fn restart_community(
    store: &mut Store,
    room: RoomId,
    gap: Option<&str>,
) -> storage::Result<()> {
    store.write(|db| {
        let summary: Vec<u8> = db.query_row(
            "SELECT summary FROM client_rooms WHERE id=?1",
            [room.to_string()],
            |r| r.get(0),
        )?;
        if decode::<conversations::Summary>(&summary)?.confidentiality
            != RoomConfidentiality::Community
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        db.execute(
            "DELETE FROM client_events WHERE room=?1",
            [room.to_string()],
        )?;
        db.execute(
            "UPDATE client_rooms SET cursor=NULL,members=NULL,gap=?2 WHERE id=?1",
            params![room.to_string(), gap],
        )?;
        Ok(Commit::new(
            (),
            encode(&("HRC.ClientCommunityRestart", room, gap))?,
        ))
    })
}
pub(super) fn restart_cursor(store: &mut Store, room: RoomId) -> storage::Result<()> {
    store.write(|db| {
        db.execute(
            "UPDATE client_rooms SET cursor=NULL WHERE id=?1",
            [room.to_string()],
        )?;
        Ok(Commit::new(
            (),
            encode(&("HRC.ClientHistoryRestart", room))?,
        ))
    })
}
pub(super) fn access_unavailable(error: &super::Error) -> bool {
    matches!(
        error,
        super::Error::Rejected {
            code: ErrorCode::Denied | ErrorCode::Expired | ErrorCode::ResynchronisationRequired,
            ..
        } | super::Error::Refused {
            code: ErrorCode::Denied | ErrorCode::Expired | ErrorCode::ResynchronisationRequired,
            ..
        }
    )
}
pub(super) fn invalidate(store: &mut Store, room: RoomId) -> storage::Result<()> {
    store.write(|db|{db.execute("DELETE FROM client_events WHERE room=?1",[room.to_string()])?;db.execute("UPDATE client_rooms SET cursor=NULL,members=NULL,gap='ResynchronisationRequired' WHERE id=?1",[room.to_string()])?;Ok(Commit::new((),encode(&("HRC.ClientInvalidate",room))?))})
}
pub(super) fn receive(
    store: &mut Store,
    room: RoomId,
    account: AccountId,
    page: &messaging::PageResult,
    key: &VerifyingKey,
    now: u64,
) -> storage::Result<()> {
    let c = verify_cursor(&page.cursor.0, key).map_err(|_| storage::Error::InvalidInput)?;
    let c = c.value();
    if c.room != room
        || c.home != room.home
        || c.account != account
        || c.expires_ms <= now
        || page.events.len() > 32
        || page.members.len() > 32
    {
        return Err(storage::Error::InvalidInput);
    }
    let mut previous = 0;
    for e in &page.events {
        if e.room != room
            || e.home != room.home
            || e.sequence <= previous
            || e.sequence > c.sequence
        {
            return Err(storage::Error::InvalidInput);
        }
        previous = e.sequence;
    }
    store.write(|db|{
  let old:Option<Vec<u8>>=db.query_row("SELECT cursor FROM client_rooms WHERE id=?1",[room.to_string()],|r|r.get(0))?;
  if let Some(old)=old {let old=verify_cursor(&old,key).map_err(|_|rusqlite::Error::InvalidQuery)?;if old.value().sequence>c.sequence||old.value().access_digest!=c.access_digest {return Err(rusqlite::Error::InvalidQuery);}}
  for e in &page.events {let bytes=encode(e)?;let existing:Option<Vec<u8>>=db.query_row("SELECT event FROM client_events WHERE id=?1 OR (room=?2 AND sequence=?3)",params![e.event.as_hex(),room.to_string(),e.sequence],|r|r.get(0)).optional()?;if existing.as_ref().is_some_and(|old|old!=&bytes){return Err(rusqlite::Error::InvalidQuery);}db.execute("INSERT OR IGNORE INTO client_events VALUES(?1,?2,?3,?4,?5,?6)",params![e.event.as_hex(),room.to_string(),e.sequence,e.timestamp_ms,bytes,bytes.len()])?;}
  db.execute("UPDATE client_rooms SET cursor=?1,members=?2,updated=?3 WHERE id=?4",params![page.cursor.0,encode(&page.members)?,now,room.to_string()])?;
  db.execute("DELETE FROM client_events WHERE created<?1",[now.saturating_sub(7*86400000)])?;
  db.execute("DELETE FROM client_events WHERE id IN (SELECT id FROM client_events ORDER BY created DESC,id DESC LIMIT -1 OFFSET 4096)",[])?;
  // A bounded local archive is not a claim that all retained server history is cached.
  db.execute("DELETE FROM client_events WHERE id IN (SELECT id FROM (SELECT id,SUM(bytes) OVER(ORDER BY created DESC,id DESC) AS used FROM client_events) WHERE used>16777216)",[])?;
  Ok(Commit::new((),encode(&("HRC.ClientReceive",room,digest(&page.cursor.0),digest(&encode(&page.events)?)))?))
 })
}
pub(super) fn candidate(
    store: &mut Store,
    id: Id,
    bytes: &[u8],
    expires: u64,
) -> storage::Result<()> {
    store.write(|db| {
        let count: u64 =
            db.query_row("SELECT count(*) FROM client_candidates", [], |r| r.get(0))?;
        if count >= 32 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        db.execute(
            "INSERT INTO client_candidates VALUES(?1,?2,?3)",
            params![id.as_hex(), bytes, expires],
        )?;
        Ok(Commit::new(
            (),
            encode(&("HRC.ClientCandidate", id, digest(bytes), expires))?,
        ))
    })
}
pub(super) fn candidate_bytes(store: &mut Store, id: Id, now: u64) -> storage::Result<Vec<u8>> {
    store.read(TIMEOUT, |db| {
        db.query_row(
            "SELECT action FROM client_candidates WHERE id=?1 AND expires>?2",
            params![id.as_hex(), now],
            |r| r.get(0),
        )
    })
}

/// Explicit local recovery has one meaning for interactive and headless clients.
pub(super) fn resynchronise_history(store: &mut Store, room: RoomId) -> storage::Result<()> {
    store.write(|db| {
        let summary: Option<Vec<u8>> = db
            .query_row(
                "SELECT summary FROM client_rooms WHERE id=?1",
                [room.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        if let Some(summary) = summary
            && decode::<conversations::Summary>(&summary)?.confidentiality
                == RoomConfidentiality::Community
        {
            db.execute(
                "DELETE FROM client_events WHERE room=?1",
                [room.to_string()],
            )?;
        }
        db.execute(
            "UPDATE client_rooms SET gap=NULL,cursor=NULL,members=NULL WHERE id=?1",
            [room.to_string()],
        )?;
        Ok(Commit::new(
            (),
            encode(&("HRC.ClientHistoryResynchronise", room))?,
        ))
    })
}
/// Retention of disclosed local copies needs no authority and runs while offline.
pub(super) fn maintain(store: &mut Store) -> storage::Result<()> {
    let wall = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_err(|_| storage::Error::Unavailable)?
        .as_millis()
        .min(i64::MAX as u128) as u64;
    let (now,needed)=store.read(TIMEOUT,|db|{
  let floor:u64=db.query_row("SELECT floor FROM client_clock WHERE singleton=1",[],|r|r.get(0))?;let now=wall.max(floor);let before=now.saturating_sub(7*86400000);
  let needed=db.query_row("SELECT EXISTS(SELECT 1 FROM client_events WHERE created<?1) OR EXISTS(SELECT 1 FROM client_drafts WHERE updated<?1) OR EXISTS(SELECT 1 FROM client_candidates WHERE expires<=?2)",params![before,now],|r|r.get::<_,bool>(0))?;Ok((now,needed))
 })?;
    if !needed {
        return Ok(());
    }
    store.write(|db| {
        let before = now.saturating_sub(7 * 86400000);
        db.execute("DELETE FROM client_events WHERE created<?1", [before])?;
        db.execute("DELETE FROM client_drafts WHERE updated<?1", [before])?;
        db.execute("DELETE FROM client_candidates WHERE expires<=?1", [now])?;
        Ok(Commit::new((), encode(&("HRC.ClientRetention", now))?))
    })
}
pub(super) fn complete_candidate(store: &mut Store, id: Id) -> storage::Result<()> {
    store.write(|db| {
        db.execute("DELETE FROM client_candidates WHERE id=?1", [id.as_hex()])?;
        Ok(Commit::new(
            (),
            encode(&("HRC.ClientCandidateComplete", id))?,
        ))
    })
}

pub(super) fn filters(
    store: &mut Store,
    home: ServiceId,
) -> storage::Result<Vec<crate::moderation::FilterState>> {
    store.read(TIMEOUT, |db| {
        let mut stmt = db.prepare(
            "SELECT subject,ignored,muted FROM client_filters WHERE home=?1 ORDER BY subject LIMIT 256",
        )?;
        stmt.query_map([home.to_string()], |r| {
            Ok(crate::moderation::FilterState {
                subject: r
                    .get::<_, String>(0)?
                    .parse()
                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
                ignored: r.get(1)?,
                muted: r.get(2)?,
            })
        })?
        .collect()
    })
}
pub(super) fn save_filters(
    store: &mut Store,
    home: ServiceId,
    filters: &[crate::moderation::FilterState],
) -> storage::Result<()> {
    if filters.len() > 256 {
        return Err(storage::Error::InvalidInput);
    }
    let old = self::filters(store, home)?;
    if encode(&old)? == encode(&filters)? {
        return Ok(());
    }
    store.write(|db| {
        db.execute(
            "DELETE FROM client_filters WHERE home=?1",
            [home.to_string()],
        )?;
        for f in filters {
            db.execute(
                "INSERT INTO client_filters VALUES(?1,?2,?3,?4)",
                params![home.to_string(), f.subject.to_string(), f.ignored, f.muted],
            )?;
        }
        let mut stmt = db.prepare("SELECT event FROM client_events LIMIT 4096")?;
        let events = stmt
            .query_map([], |r| decode::<Event>(&r.get::<_, Vec<u8>>(0)?))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(stmt);
        for event in events {
            if event.room.home == home
                && matches!(
                    event.kind,
                    Operation::MessageSend | Operation::MessageReply | Operation::MessageAction
                )
                && filtered(filters, &event.actor, false)
            {
                db.execute(
                    "DELETE FROM client_events WHERE id=?1",
                    [event.event.as_hex()],
                )?;
            }
        }
        Ok(Commit::new(
            (),
            encode(&("HRC.ClientFilters", digest(&encode(&filters)?)))?,
        ))
    })
}
/// Presentation of retained copies follows the service's actor/represented/operator
/// matching rule. This does not grant access or replace fresh service authorization.
pub(super) fn filtered(
    filters: &[crate::moderation::FilterState],
    actor: &Actor,
    notification: bool,
) -> bool {
    let subjects = crate::conversations::subjects(actor);
    filters.iter().any(|filter| {
        (filter.ignored || notification && filter.muted) && subjects.contains(&filter.subject)
    })
}
