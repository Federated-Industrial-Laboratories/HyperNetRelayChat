// SPDX-License-Identifier: Apache-2.0
//! Room inspection rechecks current membership and exposes the current unread position.
use super::*;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Inspection {
    pub members: Vec<Member>,
    pub read_sequence: u64,
    pub room_revision: u64,
    pub filter_revision: u64,
    pub moderator: bool,
    #[serde(default)]
    pub confidentiality: RoomConfidentiality,
}
pub(crate) fn read(db: &Connection, action: &Action, now: TimeBounds) -> Domain<Outcome> {
    empty(&action.body)?;
    let a = access(db, action, now)?;
    let read_sequence = db
        .query_row(
            "SELECT sequence FROM hrc_unread WHERE room=?1 AND account=?2",
            params![a.room.to_string(), action.actor.represented().to_string()],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or(0);
    Ok(Outcome::Result {
        body: value(&Inspection {
            members: members(db, a.room, now)?,
            read_sequence,
            room_revision: a.revision,
            filter_revision: a.filter_revision,
            moderator: a.moderator,
            confidentiality: a.confidentiality,
        })?,
    })
}
