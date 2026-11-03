// SPDX-License-Identifier: Apache-2.0
//! Recipient-owned filters and attributable active room restrictions.
use super::*;
use crate::home::inspection;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct FilterState {
    pub subject: AccountId,
    pub ignored: bool,
    pub muted: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RestrictionState {
    pub subject: AccountId,
    pub kind: u8,
    pub expires_ms: u64,
    pub moderator: AccountId,
}
pub(super) fn read(db: &Connection, action: &Action, now: TimeBounds) -> Domain<Outcome> {
    read_bounded(db, action, now, ORDINARY_FRAME_BYTES - 8192)
}
pub(crate) fn read_bounded(
    db: &Connection,
    action: &Action,
    now: TimeBounds,
    bytes: usize,
) -> Domain<Outcome> {
    let p = inspection::request(action)?;
    if action.operation == Operation::ModerationFilters {
        inspection::own(action)?;
        let mut stmt=db.prepare("SELECT subject,ignored,muted FROM hrc_filters WHERE owner=?1 AND subject>?2 ORDER BY subject LIMIT ?3")?;
        let rows = stmt
            .query_map(
                params![
                    action.actor.acting().account.to_string(),
                    p.after.unwrap_or_default(),
                    u32::from(p.limit) + 1
                ],
                |r| {
                    let subject: String = r.get(0)?;
                    Ok((
                        subject.clone(),
                        FilterState {
                            subject: subject.parse().map_err(|_| rusqlite::Error::InvalidQuery)?,
                            ignored: r.get(1)?,
                            muted: r.get(2)?,
                        },
                    ))
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        inspection::page_bounded(rows, p.limit, bytes)
    } else {
        let a = conversations::access(db, action, now)?;
        let mut stmt=db.prepare("SELECT subject,kind,expires,moderator,subject||':'||kind FROM hrc_restrictions WHERE room=?1 AND expires>?2 AND subject||':'||kind>?3 ORDER BY subject,kind LIMIT ?4")?;
        let rows = stmt
            .query_map(
                params![
                    a.room.to_string(),
                    now.lower_ms,
                    p.after.unwrap_or_default(),
                    u32::from(p.limit) + 1
                ],
                |r| {
                    Ok((
                        r.get(4)?,
                        RestrictionState {
                            subject: r
                                .get::<_, String>(0)?
                                .parse()
                                .map_err(|_| rusqlite::Error::InvalidQuery)?,
                            kind: r.get(1)?,
                            expires_ms: r.get(2)?,
                            moderator: r
                                .get::<_, String>(3)?
                                .parse()
                                .map_err(|_| rusqlite::Error::InvalidQuery)?,
                        },
                    ))
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        inspection::page_bounded(rows, p.limit, bytes)
    }
}
