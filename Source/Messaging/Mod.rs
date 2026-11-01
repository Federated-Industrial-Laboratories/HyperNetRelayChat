// SPDX-License-Identifier: Apache-2.0
//! One ordered event stream, attributed sends and access-filtered history.
#[path = "History.rs"]
mod history;
use crate::{
    clock::TimeBounds,
    conversations,
    delegation::Permit,
    home::{self, types::*},
    protocol::*,
};
pub use history::{Page, PageResult, Search, Unread};
use rusqlite::{OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Send {
    pub text: String,
    pub parent: Option<Id>,
    pub causation: Option<Id>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Committed {
    pub room: Option<RoomId>,
}

pub(crate) fn record(
    db: &Transaction<'_>,
    action: &Action,
    room: RoomId,
    body: Value,
    text: &str,
    now: TimeBounds,
) -> Domain<Outcome> {
    let sequence: u64 = db.query_row(
        "SELECT sequence+1 FROM hrc_rooms WHERE id=?1",
        [room.to_string()],
        |r| r.get(0),
    )?;
    // A failed representation or random source is a transaction failure, never a partial domain success.
    let event_id = Id::random().map_err(|_| Fault::Sql(rusqlite::Error::InvalidQuery))?;
    let event = Event {
        home: action.home,
        room,
        event: event_id,
        sequence,
        timestamp_ms: now.lower_ms,
        actor: action.actor.clone(),
        operation_id: action.operation_id,
        action_digest: action_digest(action)
            .map_err(|_| Fault::Sql(rusqlite::Error::InvalidQuery))?,
        kind: action.operation,
        body,
    };
    let bytes = encode(&event)?;
    let normal = if text.is_empty() {
        String::new()
    } else {
        crate::text::lookup(text, 32768).map_err(|_| Fault::Sql(rusqlite::Error::InvalidQuery))?
    };
    let position = home::next_position(db)?;
    let operator = match action.actor {
        Actor::IndependentAgent { operator, .. } | Actor::Delegated { operator, .. } => {
            Some(operator.to_string())
        }
        _ => None,
    };
    db.execute("INSERT INTO hrc_events(position,id,room,sequence,created,actor,represented,operator,kind,event,text,normal,bytes) VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13)",params![position,event_id.as_hex(),room.to_string(),sequence,now.lower_ms,action.actor.acting().account.to_string(),action.actor.represented().to_string(),operator,action.operation.code(),bytes,text,normal,bytes.len()+text.len()+normal.len()])?;
    db.execute(
        "UPDATE hrc_rooms SET sequence=?1 WHERE id=?2",
        params![sequence, room.to_string()],
    )?;
    db.execute(
        "UPDATE hrc_meta SET history_bytes=history_bytes+?1 WHERE singleton=1",
        [(bytes.len() + text.len() + normal.len()) as u64],
    )?;
    Ok(Outcome::Committed {
        event: Some(event_id),
        position,
        body: value(&Committed { room: Some(room) })
            .map_err(|_| Fault::Sql(rusqlite::Error::InvalidQuery))?,
    })
}
pub(crate) fn operate(
    db: &Transaction<'_>,
    action: &Action,
    now: TimeBounds,
    permit: Permit,
    signer: &SigningKey,
    cancel: &Cancellation,
) -> Domain<Outcome> {
    match action.operation {
        Operation::MessageSend | Operation::MessageReply | Operation::MessageAction => {
            send(db, action, now, permit)
        }
        Operation::HistoryPage | Operation::EventsSubscribe | Operation::EventsResume => {
            history::page(db, action, now, permit, signer, cancel)
        }
        Operation::SearchQuery => history::search(db, action, now, permit, signer, cancel),
        Operation::UnreadSet => history::unread(db, action, now),
        _ => invalid("MessageOperation"),
    }
}
fn send(db: &Transaction<'_>, action: &Action, now: TimeBounds, permit: Permit) -> Domain<Outcome> {
    let body: Send = unpack(&action.body)?;
    crate::text::message(&body.text)
        .map_err(|_| Fault::Reject(ErrorCode::InvalidInput, "MessageText"))?;
    if (action.operation == Operation::MessageReply) != body.parent.is_some() {
        return invalid("ReplyParent");
    }
    let access = conversations::access(db, action, now)?;
    if conversations::restriction(db, access.room, &action.actor, 1, now)? {
        return deny("RoomSilenced");
    }
    let accessible = |id: Id| -> Domain<(Option<String>, u8)> {
        let row:Option<(Vec<u8>,Option<String>,u8)>=db.query_row("SELECT event,causal_root,causal_depth FROM hrc_events WHERE id=?1 AND room=?2 AND created>=?3 AND created<=?4",params![id.as_hex(),access.room.to_string(),access.history_from.max(permit.history_from).max(now.upper_ms.saturating_sub(RETENTION)),permit.history_until.min(i64::MAX as u64)],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
        let Some((bytes, root, depth)) = row else {
            return deny("ReferencedEvent");
        };
        let event: Event = decode(&bytes)?;
        if crate::moderation::ignored(db, action.actor.represented(), &event.actor)? {
            return deny("ReferencedEvent");
        }
        Ok((root, depth))
    };
    if let Some(parent) = body.parent {
        accessible(parent)?;
    }
    let mut causality = None;
    if let Some(cause) = body.causation {
        if matches!(action.actor, Actor::Direct { .. }) {
            return invalid("HumanCausation");
        }
        let (root, depth) = accessible(cause)?;
        let root = root.unwrap_or_else(|| cause.as_hex());
        if depth >= 4 {
            return deny("AgentDepth");
        }
        let grant = match action.actor {
            Actor::Delegated { grant, .. } => grant.id.as_hex(),
            _ => String::new(),
        };
        if db.query_row("SELECT EXISTS(SELECT 1 FROM hrc_agent_effects WHERE cause=?1 AND agent=?2 AND grant_id=?3)",params![cause.as_hex(),action.actor.acting().account.to_string(),grant],|r|r.get::<_,bool>(0))?{return deny("AgentTriggerRepeated");}
        let count: u64 = db.query_row(
            "SELECT count(*) FROM hrc_agent_effects WHERE root=?1",
            [&root],
            |r| r.get(0),
        )?;
        if count >= 8 {
            return deny("AgentChainLimit");
        }
        causality = Some((cause, root, depth + 1, grant));
    }
    let event_body = value(&body)?;
    let outcome = record(db, action, access.room, event_body, &body.text, now)?;
    if let (
        Some((cause, root, depth, grant)),
        Outcome::Committed {
            event: Some(event), ..
        },
    ) = (causality, &outcome)
    {
        db.execute(
            "INSERT INTO hrc_agent_effects VALUES(?1,?2,?3,?4)",
            params![
                cause.as_hex(),
                action.actor.acting().account.to_string(),
                grant,
                root
            ],
        )?;
        db.execute(
            "UPDATE hrc_events SET causal_root=?1,causal_depth=?2 WHERE id=?3",
            params![root, depth, event.as_hex()],
        )?;
    }
    Ok(outcome)
}
