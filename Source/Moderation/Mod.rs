// SPDX-License-Identifier: Apache-2.0
//! Recipient filters and attributable room restrictions remain distinct.
#[path = "Inspection.rs"]
pub(crate) mod inspection;
use crate::{
    clock::TimeBounds,
    conversations,
    home::{self, types::*},
    protocol::*,
};
pub use inspection::{FilterState, RestrictionState};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Filter {
    pub subject: AccountId,
    pub enabled: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Restriction {
    pub subject: AccountId,
    pub enabled: bool,
    pub duration_ms: u64,
    pub reason: String,
}
pub(crate) fn ignored(db: &Connection, owner: AccountId, actor: &Actor) -> Domain<bool> {
    for subject in conversations::subjects(actor) {
        if db.query_row(
            "SELECT EXISTS(SELECT 1 FROM hrc_filters WHERE owner=?1 AND subject=?2 AND ignored=1)",
            params![owner.to_string(), subject.to_string()],
            |r| r.get::<_, bool>(0),
        )? {
            return Ok(true);
        }
    }
    Ok(false)
}
pub(crate) fn operate(db: &Transaction<'_>, action: &Action, now: TimeBounds) -> Domain<Outcome> {
    match action.operation {
        Operation::ModerationFilters | Operation::ModerationRestrictions => {
            inspection::read(db, action, now)
        }
        Operation::ModerationIgnore | Operation::ModerationMute => {
            if action.target != Target::Account(action.actor.represented()) {
                return invalid("FilterOwner");
            }
            let body: Filter = unpack(&action.body)?;
            if body.subject == action.actor.represented() {
                return invalid("SelfFilter");
            }
            let count: u64 = db.query_row(
                "SELECT count(*) FROM hrc_filters WHERE owner=?1",
                [action.actor.represented().to_string()],
                |r| r.get(0),
            )?;
            let exists: bool = db.query_row(
                "SELECT EXISTS(SELECT 1 FROM hrc_filters WHERE owner=?1 AND subject=?2)",
                params![
                    action.actor.represented().to_string(),
                    body.subject.to_string()
                ],
                |r| r.get(0),
            )?;
            if count >= 256 && !exists {
                return Err(Fault::Reject(ErrorCode::Overloaded, "FilterLimit"));
            }
            let column = if action.operation == Operation::ModerationIgnore {
                "ignored"
            } else {
                "muted"
            };
            db.execute("INSERT INTO hrc_filters(owner,subject,ignored,muted) VALUES(?1,?2,0,0) ON CONFLICT(owner,subject) DO NOTHING",params![action.actor.represented().to_string(),body.subject.to_string()])?;
            db.execute(
                &format!("UPDATE hrc_filters SET {column}=?1 WHERE owner=?2 AND subject=?3"),
                params![
                    body.enabled,
                    action.actor.represented().to_string(),
                    body.subject.to_string()
                ],
            )?;
            if action.operation == Operation::ModerationIgnore {
                db.execute(
                    "UPDATE hrc_accounts SET filter_revision=filter_revision+1 WHERE id=?1",
                    [action.actor.represented().to_string()],
                )?;
            }
            home::committed(db, None, Value::Null)
        }
        Operation::ModerationSilence | Operation::ModerationKick | Operation::ModerationBan => {
            let body: Restriction = unpack(&action.body)?;
            let access = conversations::access(db, action, now)?;
            if !access.moderator {
                return deny("Moderator");
            }
            if body.reason.len() > 256 || body.reason.chars().any(char::is_control) {
                return invalid("ModerationReason");
            }
            if body.duration_ms > 30 * DAY || body.enabled && body.duration_ms < 1000 {
                return invalid("RestrictionDuration");
            }
            let owner: String = db.query_row(
                "SELECT owner FROM hrc_rooms WHERE id=?1",
                [access.room.to_string()],
                |r| r.get(0),
            )?;
            if body.subject.to_string() == owner {
                return deny("RoomOwner");
            }
            let member: Option<bool> = db
                .query_row(
                    "SELECT moderator FROM hrc_members WHERE room=?1 AND account=?2",
                    params![access.room.to_string(), body.subject.to_string()],
                    |r| r.get(0),
                )
                .optional()?;
            if member == Some(true) && owner != action.actor.represented().to_string() {
                return deny("ModeratorPeer");
            }
            let count: u64 = db.query_row(
                "SELECT count(*) FROM hrc_restrictions WHERE room=?1 AND expires>?2",
                params![access.room.to_string(), now.lower_ms],
                |r| r.get(0),
            )?;
            if count >= 256 && body.enabled {
                return Err(Fault::Reject(ErrorCode::Overloaded, "RestrictionLimit"));
            }
            let event_body = value(&body)?;
            if action.operation != Operation::ModerationKick {
                let kind = if action.operation == Operation::ModerationSilence {
                    1
                } else {
                    2
                };
                if body.enabled {
                    db.execute("INSERT INTO hrc_restrictions VALUES(?1,?2,?3,?4,?5) ON CONFLICT(room,subject,kind) DO UPDATE SET expires=excluded.expires,moderator=excluded.moderator",params![access.room.to_string(),body.subject.to_string(),kind,now.upper_ms+body.duration_ms,action.actor.represented().to_string()])?;
                } else {
                    db.execute(
                        "DELETE FROM hrc_restrictions WHERE room=?1 AND subject=?2 AND kind=?3",
                        params![access.room.to_string(), body.subject.to_string(), kind],
                    )?;
                }
            }
            if body.enabled
                && matches!(
                    action.operation,
                    Operation::ModerationKick | Operation::ModerationBan
                )
            {
                db.execute("UPDATE hrc_members SET active=0,revision=revision+1 WHERE room=?1 AND account=?2",params![access.room.to_string(),body.subject.to_string()])?;
            }
            if body.enabled
                && matches!(
                    action.operation,
                    Operation::ModerationKick | Operation::ModerationBan
                )
            {
                crate::confidential::invalidate_accounts(db, &[body.subject])?;
            }
            db.execute(
                "UPDATE hrc_rooms SET revision=revision+1 WHERE id=?1",
                [access.room.to_string()],
            )?;
            crate::messaging::record(db, action, access.room, event_body, "", now)
        }
        _ => invalid("ModerationOperation"),
    }
}
