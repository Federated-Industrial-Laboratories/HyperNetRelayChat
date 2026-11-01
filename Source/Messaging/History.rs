// SPDX-License-Identifier: Apache-2.0
//! Bounded history and indexed search share current membership and recipient filtering.
use crate::{
    clock::TimeBounds,
    conversations::{self, Access},
    delegation::Permit,
    home::{self, types::*},
    protocol::*,
};
use rusqlite::{Connection, Transaction, params};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Page {
    pub cursor: Option<Blob>,
    pub limit: u16,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Search {
    pub terms: Vec<String>,
    pub sender: Option<AccountId>,
    pub represented: Option<AccountId>,
    pub from_ms: Option<u64>,
    pub until_ms: Option<u64>,
    pub cursor: Option<Blob>,
    pub limit: u16,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Unread {
    pub sequence: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PageResult {
    pub events: Vec<Event>,
    pub cursor: Blob,
    pub has_more: bool,
    pub room_revision: u64,
    pub members: Vec<conversations::Member>,
}
const FILTER: &str = " AND NOT EXISTS(SELECT 1 FROM hrc_filters f WHERE f.owner=?5 AND f.ignored=1 AND f.subject IN(e.actor,e.represented,e.operator))";
fn after(
    cursor: &Option<Blob>,
    access: &Access,
    action: &Action,
    now: TimeBounds,
    signer: &SigningKey,
    digest: Id,
) -> Domain<u64> {
    let Some(cursor) = cursor else {
        return Ok(0);
    };
    let verified = verify_cursor(&cursor.0, &signer.verifying_key())
        .map_err(|_| Fault::Reject(ErrorCode::InvalidInput, "CursorSignature"))?;
    let c = verified.value();
    if c.home != action.home
        || c.room != access.room
        || c.account != action.actor.represented()
        || c.membership_revision != access.membership_revision
        || c.filter_revision != access.filter_revision
        || c.access_digest != digest
        || now.upper_ms >= c.expires_ms
        || c.sequence > access.sequence
        || c.sequence.saturating_add(1) < access.earliest
    {
        return Err(Fault::Reject(
            ErrorCode::ResynchronisationRequired,
            "CursorContext",
        ));
    }
    Ok(c.sequence)
}
struct PageContext<'a> {
    db: &'a Connection,
    action: &'a Action,
    now: TimeBounds,
    signer: &'a SigningKey,
    access: &'a Access,
    digest: Id,
    start: u64,
}
impl PageContext<'_> {
    fn finish(self, mut events: Vec<Event>, mut last: u64, mut more: bool) -> Domain<Outcome> {
        let members = conversations::members(self.db, self.access.room, self.now)?;
        loop {
            let cursor = HistoryCursor {
                home: self.action.home,
                room: self.access.room,
                account: self.action.actor.represented(),
                sequence: last,
                membership_revision: self.access.membership_revision,
                filter_revision: self.access.filter_revision,
                access_digest: self.digest,
                expires_ms: self.now.lower_ms + 300_000,
            };
            let signed = sign_cursor(&cursor, self.signer)
                .map_err(|_| Fault::Sql(rusqlite::Error::InvalidQuery))?;
            let outcome = Outcome::Result {
                body: value(&PageResult {
                    events: events.clone(),
                    cursor: Blob(signed),
                    has_more: more,
                    room_revision: self.access.revision,
                    members: members.clone(),
                })?,
            };
            let response = Response {
                home: self.action.home,
                operation_id: self.action.operation_id,
                action_digest: action_digest(self.action)
                    .map_err(|_| Fault::Sql(rusqlite::Error::InvalidQuery))?,
                outcome: outcome.clone(),
            };
            // Enforce the actual role, frame, logical depth and node limits together.
            if sign_response(&response, self.signer).is_ok() {
                return Ok(outcome);
            }
            if events.pop().is_none() {
                return Err(Fault::Reject(ErrorCode::Overloaded, "PageRepresentation"));
            }
            last = events.last().map(|e| e.sequence).unwrap_or(self.start);
            more = true;
        }
    }
}
fn page_limit(limit: u16) -> Domain<usize> {
    if !(1..=50).contains(&limit) {
        return invalid("PageLimit");
    }
    Ok(usize::from(limit).min(32))
}
pub(super) fn page(
    db: &Transaction<'_>,
    action: &Action,
    now: TimeBounds,
    permit: Permit,
    signer: &SigningKey,
    cancel: &Cancellation,
) -> Domain<Outcome> {
    let body: Page = unpack(&action.body)?;
    let limit = page_limit(body.limit)?;
    let access = conversations::access(db, action, now)?;
    let context = digest(&encode(&(
        "history",
        access.access_digest,
        permit.history_from,
        permit.history_until,
    ))?);
    let start = after(&body.cursor, &access, action, now, signer, context)?;
    let sql = format!(
        "SELECT e.sequence,e.event FROM hrc_events e WHERE e.room=?1 AND e.sequence>?2 AND e.created>=?3 AND e.created<=?4{FILTER} ORDER BY e.sequence LIMIT 257"
    );
    let mut stmt = db.prepare(&sql)?;
    let mut rows = stmt.query(params![
        access.room.to_string(),
        start,
        access
            .history_from
            .max(permit.history_from)
            .max(now.upper_ms.saturating_sub(RETENTION)),
        permit.history_until.min(i64::MAX as u64),
        action.actor.represented().to_string()
    ])?;
    let mut result = Vec::new();
    let mut last = start;
    let mut bytes = 0;
    let mut more = false;
    while let Some(row) = rows.next()? {
        if cancel.is_cancelled() {
            return Err(Fault::Reject(ErrorCode::Unavailable, "Cancelled"));
        }
        let data: Vec<u8> = row.get(1)?;
        if result.len() >= limit || bytes + data.len() > 48 * 1024 {
            more = true;
            break;
        }
        last = row.get(0)?;
        bytes += data.len();
        result.push(decode(&data)?);
    }
    if !more {
        last = access.sequence;
    }
    PageContext {
        db,
        action,
        now,
        signer,
        access: &access,
        digest: context,
        start,
    }
    .finish(result, last, more)
}
pub(super) fn search(
    db: &Transaction<'_>,
    action: &Action,
    now: TimeBounds,
    permit: Permit,
    signer: &SigningKey,
    cancel: &Cancellation,
) -> Domain<Outcome> {
    let body: Search = unpack(&action.body)?;
    let limit = page_limit(body.limit)?;
    let access = conversations::access(db, action, now)?;
    let terms = crate::text::query(&body.terms)
        .map_err(|_| Fault::Reject(ErrorCode::InvalidInput, "SearchTerms"))?;
    let start_ms = body
        .from_ms
        .unwrap_or(0)
        .max(access.history_from)
        .max(permit.history_from)
        .max(now.upper_ms.saturating_sub(RETENTION));
    let end_ms = body
        .until_ms
        .unwrap_or(i64::MAX as u64)
        .min(permit.history_until)
        .min(i64::MAX as u64);
    if start_ms > end_ms {
        return invalid("SearchInterval");
    }
    let context = digest(&encode(&(
        "search",
        access.access_digest,
        &terms,
        body.sender,
        body.represented,
        body.from_ms,
        body.until_ms,
        permit.history_from,
        permit.history_until,
    ))?);
    let start = after(&body.cursor, &access, action, now, signer, context)?;
    let expression = crate::text::match_expression(&terms);
    let from = if expression.is_some() {
        "hrc_search s JOIN hrc_events e ON e.position=s.rowid"
    } else {
        "hrc_events e"
    };
    let indexed = if expression.is_some() {
        " AND hrc_search MATCH ?8"
    } else {
        " AND ?8 IS NULL"
    };
    let sql = format!(
        "SELECT e.sequence,e.event,e.normal FROM {from} WHERE e.kind IN(20,21,22) AND e.room=?1 AND e.sequence>?2 AND e.created>=?3 AND e.created<=?4{FILTER} AND (?6 IS NULL OR e.actor=?6) AND (?7 IS NULL OR e.represented=?7){indexed} ORDER BY e.sequence LIMIT 257"
    );
    let mut stmt = db.prepare(&sql)?;
    let mut rows = stmt.query(params![
        access.room.to_string(),
        start,
        start_ms,
        end_ms,
        action.actor.represented().to_string(),
        body.sender.map(|v| v.to_string()),
        body.represented.map(|v| v.to_string()),
        expression
    ])?;
    let mut candidates = Vec::new();
    let mut scanned = 0;
    let mut limited = false;
    while let Some(row) = rows.next()? {
        if cancel.is_cancelled() {
            return Err(Fault::Reject(ErrorCode::Unavailable, "Cancelled"));
        }
        let data: Vec<u8> = row.get(1)?;
        scanned += data.len();
        if candidates.len() >= 256 || scanned > 1024 * 1024 {
            if expression.is_none() {
                return Err(Fault::Reject(ErrorCode::Overloaded, "QueryTooBroad"));
            }
            limited = true;
            break;
        }
        candidates.push((row.get::<_, u64>(0)?, data, row.get::<_, String>(2)?));
    }
    let mut result = Vec::new();
    let mut bytes = 0;
    let mut last = start;
    let mut more = limited;
    for (sequence, data, normal) in candidates {
        if !terms.iter().all(|term| normal.contains(term)) {
            last = sequence;
            continue;
        }
        if result.len() >= limit || bytes + data.len() > 48 * 1024 {
            more = true;
            break;
        }
        last = sequence;
        bytes += data.len();
        result.push(decode(&data)?);
    }
    if !more {
        last = access.sequence;
    }
    PageContext {
        db,
        action,
        now,
        signer,
        access: &access,
        digest: context,
        start,
    }
    .finish(result, last, more)
}
pub(super) fn unread(db: &Transaction<'_>, action: &Action, now: TimeBounds) -> Domain<Outcome> {
    let body: Unread = unpack(&action.body)?;
    let access = conversations::access(db, action, now)?;
    if body.sequence > access.sequence {
        return invalid("UnreadSequence");
    }
    db.execute("INSERT INTO hrc_unread VALUES(?1,?2,?3) ON CONFLICT(room,account) DO UPDATE SET sequence=MAX(sequence,excluded.sequence)",params![access.room.to_string(),action.actor.represented().to_string(),body.sequence])?;
    home::committed(db, None, Value::Null)
}
