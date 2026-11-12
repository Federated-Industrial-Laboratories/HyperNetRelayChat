// SPDX-License-Identifier: Apache-2.0
//! A trigger cursor, reply plan, retry identity and local rate reservation commit together.
use super::{Config, Error, Result};
use crate::{
    client::outbox,
    clock::TimeBounds,
    protocol::*,
    storage::{Commit, Store},
};
use rusqlite::{OptionalExtension, params};
use serde::{Serialize, de::DeserializeOwned};
use std::time::Duration;
const READ: Duration = Duration::from_secs(1);
fn encode<T: Serialize>(value: &T) -> rusqlite::Result<Vec<u8>> {
    canonical_encode(
        &Value::serialized(value).map_err(|_| rusqlite::Error::InvalidQuery)?,
        ORDINARY_FRAME_BYTES,
    )
    .map_err(|_| rusqlite::Error::InvalidQuery)
}
fn decode<T: DeserializeOwned>(bytes: &[u8]) -> rusqlite::Result<T> {
    canonical_decode(bytes, ORDINARY_FRAME_BYTES)
        .map_err(|_| rusqlite::Error::InvalidQuery)?
        .deserialized()
        .map_err(|_| rusqlite::Error::InvalidQuery)
}
pub(super) struct Room {
    pub cursor: Option<Blob>,
    pub live: bool,
}
#[derive(Clone, Debug)]
pub(super) struct Plan {
    pub room: Option<RoomId>,
    pub operation: OperationId,
    pub digest: Id,
}
pub(super) fn exists(store: &mut Store) -> Result<bool> {
    store
        .read(READ, |db| {
            db.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='bot_meta')",
                [],
                |row| row.get(0),
            )
        })
        .map_err(|source| Error::Storage {
            operation: "State.exists",
            source,
        })
}
pub(super) fn initialise(store: &mut Store, config: &Config) -> Result<()> {
    let identity = if let Some(model) = &config.model {
        encode(&(
            "HRC.LocalModelBot.1",
            &config.rooms,
            &config.help,
            config.grant,
            model,
        ))
    } else {
        // Preserve existing deterministic bots' cursor and exact-outbox identity.
        encode(&("HRC.HelpBot.1", &config.rooms, &config.help, config.grant))
    }
    .map_err(|_| Error::InvalidState("BotConfigurationEncoding"))?;
    let identity = digest(&identity);
    let existing = store
        .read(READ, |db| {
            let exists: bool = db.query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE type='table' AND name='bot_meta')",
                [],
                |r| r.get(0),
            )?;
            if exists {
                db.query_row(
                    "SELECT version,configuration FROM bot_meta WHERE singleton=1",
                    [],
                    |r| Ok(Some((r.get::<_, u64>(0)?, r.get::<_, Vec<u8>>(1)?))),
                )
            } else {
                Ok(None)
            }
        })
        .map_err(|source| Error::Storage {
            operation: "State.initialise",
            source,
        })?;
    if existing.as_ref().is_some_and(|(version, _)| *version != 1) {
        return Err(Error::InvalidState("BotStateSchema"));
    }
    let changed = existing
        .as_ref()
        .is_some_and(|(_, saved)| saved != identity.as_bytes());
    if existing.is_some() && !changed && !config.resynchronise {
        return Ok(());
    }
    if changed {
        let pending: u64 = store
            .read(READ, |db| {
                db.query_row("SELECT count(*) FROM bot_plans", [], |r| r.get(0))
            })
            .map_err(|source| Error::Storage {
                operation: "State.configuration_pending",
                source,
            })?;
        if pending != 0 {
            return Err(Error::PendingOutcome);
        }
    }
    store
        .write(|db| {
            if existing.is_none() {
                db.execute_batch(
                    "CREATE TABLE bot_meta(singleton INTEGER PRIMARY KEY CHECK(singleton=1),
                     version INTEGER NOT NULL,configuration BLOB NOT NULL,
                     next_reply INTEGER NOT NULL,next_presence INTEGER NOT NULL);
                     CREATE TABLE bot_rooms(room TEXT PRIMARY KEY,cursor BLOB,
                     live INTEGER NOT NULL DEFAULT 0);
                     CREATE TABLE bot_plans(room BLOB NOT NULL,window TEXT NOT NULL,
                     operation TEXT NOT NULL,digest BLOB NOT NULL,trigger TEXT NOT NULL UNIQUE,
                     PRIMARY KEY(window,operation));",
                )?;
                db.execute(
                    "INSERT INTO bot_meta VALUES(1,1,?1,0,0)",
                    [identity.as_bytes().as_slice()],
                )?;
            }
            if changed {
                let pending: u64 =
                    db.query_row("SELECT count(*) FROM bot_plans", [], |r| r.get(0))?;
                if pending != 0 {
                    return Err(rusqlite::Error::InvalidQuery);
                }
                db.execute(
                    "UPDATE bot_meta SET configuration=?1 WHERE singleton=1",
                    [identity.as_bytes().as_slice()],
                )?;
                db.execute("DELETE FROM bot_rooms", [])?;
            }
            for room in &config.rooms {
                db.execute(
                    "INSERT OR IGNORE INTO bot_rooms(room) VALUES(?1)",
                    [room.to_string()],
                )?;
            }
            if config.resynchronise {
                db.execute("UPDATE bot_rooms SET cursor=NULL,live=0", [])?;
            }
            Ok(Commit::new(
                (),
                encode(&("HRC.HelpBot.Configure", identity, config.resynchronise))?,
            ))
        })
        .map_err(|source| Error::Storage {
            operation: "State.initialise",
            source,
        })
}
pub(super) fn room(store: &mut Store, room: RoomId) -> Result<Room> {
    store
        .read(READ, |db| {
            db.query_row(
                "SELECT cursor,live FROM bot_rooms WHERE room=?1",
                [room.to_string()],
                |r| {
                    Ok(Room {
                        cursor: r.get::<_, Option<Vec<u8>>>(0)?.map(Blob),
                        live: r.get(1)?,
                    })
                },
            )
        })
        .map_err(|source| Error::Storage {
            operation: "State.room",
            source,
        })
}
pub(super) fn next_reply(store: &mut Store) -> Result<u64> {
    store
        .read(READ, |db| {
            db.query_row(
                "SELECT next_reply FROM bot_meta WHERE singleton=1",
                [],
                |r| r.get(0),
            )
        })
        .map_err(|source| Error::Storage {
            operation: "State.next_reply",
            source,
        })
}
pub(super) fn restart_room(store: &mut Store, room: RoomId) -> Result<()> {
    store
        .write(|db| {
            if db.execute(
                "UPDATE bot_rooms SET cursor=NULL,live=0 WHERE room=?1",
                [room.to_string()],
            )? != 1
            {
                return Err(rusqlite::Error::InvalidQuery);
            }
            Ok(Commit::new((), encode(&("HRC.BotRestartContext", room))?))
        })
        .map_err(|source| Error::Storage {
            operation: "State.restart_room",
            source,
        })
}
pub(super) fn plans(store: &mut Store) -> Result<Vec<Plan>> {
    store
        .read(READ, |db| {
            let mut stmt = db.prepare(
                "SELECT room,window,operation,digest FROM bot_plans ORDER BY window,operation LIMIT 2",
            )?;
            stmt.query_map([], |r| {
                Ok(Plan {
                    room: decode(&r.get::<_, Vec<u8>>(0)?)?,
                    operation: OperationId {
                        window: r.get::<_, String>(1)?.parse().map_err(|_| rusqlite::Error::InvalidQuery)?,
                        operation: r.get::<_, String>(2)?.parse().map_err(|_| rusqlite::Error::InvalidQuery)?,
                    },
                    digest: Id::from_bytes(
                        r.get::<_, Vec<u8>>(3)?.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?,
                    ),
                })
            })?
            .collect()
        })
        .map_err(|source| Error::Storage { operation: "State.plans", source })
}
pub(super) struct Advance<'a> {
    pub room: RoomId,
    pub prior: Option<&'a Blob>,
    pub cursor: &'a Blob,
    pub live: bool,
    pub reply: Option<(&'a VerifiedAction, Id)>,
    pub window: &'a RetryWindow,
    pub now: TimeBounds,
}
#[cfg(test)]
pub(super) fn advance(store: &mut Store, a: Advance<'_>) -> Result<()> {
    store
        .write(|db| {
            advance_in(db, &a)?;
            Ok(Commit::new(
                (),
                encode(&(
                    "HRC.HelpBot.Advance",
                    a.room,
                    digest(&a.cursor.0),
                    a.live,
                    a.reply.map(|(r, event)| (r.digest(), event)),
                ))?,
            ))
        })
        .map_err(|source| Error::Storage {
            operation: "State.advance",
            source,
        })
}
pub(super) fn advance_in(db: &rusqlite::Transaction<'_>, a: &Advance<'_>) -> rusqlite::Result<()> {
    let now = a.now.refresh().map_err(|_| rusqlite::Error::InvalidQuery)?;
    let (prior, live): (Option<Vec<u8>>, bool) = db.query_row(
        "SELECT cursor,live FROM bot_rooms WHERE room=?1",
        [a.room.to_string()],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if prior.as_deref() != a.prior.map(|b| b.0.as_slice()) {
        return Err(rusqlite::Error::InvalidQuery);
    }
    if let Some((reply, trigger)) = a.reply {
        let (parent, causation) =
            if let Ok(body) = reply.action().body.deserialized::<crate::messaging::Send>() {
                (body.parent, body.causation)
            } else {
                let (_, body) = crate::crypto::EncryptionContext::from_action(reply.action())
                    .map_err(|_| rusqlite::Error::InvalidQuery)?;
                (body.parent, body.causation)
            };
        if !live
            || reply.action().operation != Operation::MessageReply
            || reply.action().target != Target::Room(a.room)
            || matches!(reply.action().actor, Actor::Direct { .. })
            || parent != Some(trigger)
            || causation != Some(trigger)
        {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let pending: u64 = db.query_row("SELECT count(*) FROM bot_plans", [], |r| r.get(0))?;
        if pending != 0 {
            return Err(rusqlite::Error::InvalidQuery);
        }
        let next: u64 = db.query_row(
            "SELECT next_reply FROM bot_meta WHERE singleton=1",
            [],
            |r| r.get(0),
        )?;
        if now.lower_ms < next {
            return Err(rusqlite::Error::InvalidQuery);
        }
        outbox::prepare_transaction(db, reply, a.window, now)?;
        let id = reply.action().operation_id;
        db.execute(
            "INSERT INTO bot_plans VALUES(?1,?2,?3,?4,?5)",
            params![
                encode(&Some(a.room))?,
                id.window.as_hex(),
                id.operation.as_hex(),
                reply.digest().as_bytes(),
                trigger.as_hex()
            ],
        )?;
        db.execute(
            "UPDATE bot_meta SET next_reply=?1 WHERE singleton=1",
            [now.upper_ms.saturating_add(5000)],
        )?;
    }
    db.execute(
        "UPDATE bot_rooms SET cursor=?1,live=?2 WHERE room=?3",
        params![a.cursor.0, a.live, a.room.to_string()],
    )?;
    Ok(())
}
pub(super) fn complete(store: &mut Store, plan: &Plan, outcome: &Outcome) -> Result<()> {
    if !matches!(
        outcome,
        Outcome::Committed { .. } | Outcome::Rejected { .. }
    ) {
        return Err(Error::PendingOutcome);
    }
    store
        .write(|db| {
            let saved: Option<Vec<u8>> = db
                .query_row(
                    "SELECT digest FROM bot_plans WHERE window=?1 AND operation=?2",
                    params![
                        plan.operation.window.as_hex(),
                        plan.operation.operation.as_hex()
                    ],
                    |r| r.get(0),
                )
                .optional()?;
            if saved.as_deref() != Some(plan.digest.as_bytes().as_slice()) {
                return Err(rusqlite::Error::InvalidQuery);
            }
            db.execute(
                "DELETE FROM bot_plans WHERE window=?1 AND operation=?2",
                params![
                    plan.operation.window.as_hex(),
                    plan.operation.operation.as_hex()
                ],
            )?;
            Ok(Commit::new(
                (),
                encode(&(
                    "HRC.HelpBot.Complete",
                    plan.operation,
                    plan.digest,
                    digest(&encode(outcome)?),
                ))?,
            ))
        })
        .map_err(|source| Error::Storage {
            operation: "State.complete",
            source,
        })
}
pub(super) fn abandoned(store: &mut Store, plan: &Plan) -> Result<()> {
    store
        .write(|db| {
            db.execute(
                "DELETE FROM bot_plans WHERE window=?1 AND operation=?2 AND digest=?3",
                params![
                    plan.operation.window.as_hex(),
                    plan.operation.operation.as_hex(),
                    plan.digest.as_bytes()
                ],
            )?;
            Ok(Commit::new(
                (),
                encode(&("HRC.HelpBot.RetryAbandoned", plan.operation, plan.digest))?,
            ))
        })
        .map_err(|source| Error::Storage {
            operation: "State.abandoned",
            source,
        })
}

pub(super) fn presence_due(store: &mut Store, now: u64) -> Result<bool> {
    store
        .read(READ, |db| {
            db.query_row(
                "SELECT next_presence<=?1 FROM bot_meta WHERE singleton=1",
                [now],
                |r| r.get(0),
            )
        })
        .map_err(|source| Error::Storage {
            operation: "State.presence_due",
            source,
        })
}
pub(super) fn presence(
    store: &mut Store,
    action: &VerifiedAction,
    window: &RetryWindow,
    now: TimeBounds,
) -> Result<()> {
    store
        .write(|db| {
            if action.action().operation != Operation::PresenceSet
                || !matches!(action.action().actor, Actor::IndependentAgent { .. })
                || action.action().target != Target::Account(action.action().actor.acting().account)
            {
                return Err(rusqlite::Error::InvalidQuery);
            }
            let pending: u64 = db.query_row("SELECT count(*) FROM bot_plans", [], |r| r.get(0))?;
            if pending != 0 {
                return Err(rusqlite::Error::InvalidQuery);
            }
            outbox::prepare_transaction(db, action, window, now)?;
            let id = action.action().operation_id;
            db.execute(
                "INSERT INTO bot_plans VALUES(?1,?2,?3,?4,?5)",
                params![
                    encode(&None::<RoomId>)?,
                    id.window.as_hex(),
                    id.operation.as_hex(),
                    action.digest().as_bytes(),
                    format!("presence:{}", id.operation)
                ],
            )?;
            db.execute(
                "UPDATE bot_meta SET next_presence=?1 WHERE singleton=1",
                [now.upper_ms.saturating_add(30000)],
            )?;
            Ok(Commit::new(
                (),
                encode(&("HRC.HelpBot.Presence", action.digest()))?,
            ))
        })
        .map_err(|source| Error::Storage {
            operation: "State.presence",
            source,
        })
}
