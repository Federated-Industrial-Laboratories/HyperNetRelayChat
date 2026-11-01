// SPDX-License-Identifier: Apache-2.0
//! Membership, room metadata and the current history-access boundary.
#[path = "Inspection.rs"]
mod inspection;
use crate::{
    clock::TimeBounds,
    home::{self, types::*},
    protocol::*,
};
pub use inspection::Inspection;
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Create {
    pub name: String,
    pub confidentiality: RoomConfidentiality,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Topic {
    pub topic: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct List {
    pub after: Option<RoomId>,
    pub limit: u16,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Summary {
    pub room: RoomId,
    pub name: String,
    pub topic: String,
    pub revision: u64,
    pub sequence: u64,
    pub joined: bool,
    pub unread: u64,
    #[serde(default)]
    pub confidentiality: RoomConfidentiality,
    #[serde(default)]
    pub invited: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Member {
    pub account: AccountId,
    pub nickname: String,
    pub classification: AccountClass,
    pub present: bool,
    pub moderator: bool,
}
pub(crate) fn members(db: &Connection, room: RoomId, now: TimeBounds) -> Domain<Vec<Member>> {
    let mut stmt=db.prepare("SELECT a.account,a.nickname,a.class,m.moderator,EXISTS(SELECT 1 FROM hrc_presence p WHERE p.account=a.id AND p.expires>?2) FROM hrc_members m JOIN hrc_accounts a ON a.id=m.account WHERE m.room=?1 AND m.active=1 ORDER BY a.id LIMIT 32")?;
    let result = stmt
        .query_map(params![room.to_string(), now.upper_ms], |r| {
            Ok(Member {
                account: decode(&r.get::<_, Vec<u8>>(0)?)?,
                nickname: r.get(1)?,
                classification: decode(&r.get::<_, Vec<u8>>(2)?)?,
                moderator: r.get(3)?,
                present: r.get(4)?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    Ok(result)
}
#[derive(Clone, Debug)]
pub(crate) struct Access {
    pub room: RoomId,
    pub sequence: u64,
    pub revision: u64,
    pub membership_revision: u64,
    pub history_from: u64,
    pub filter_revision: u64,
    pub access_digest: Id,
    pub moderator: bool,
    pub earliest: u64,
    pub confidentiality: RoomConfidentiality,
}
pub(crate) fn target(action: &Action) -> Domain<RoomId> {
    match action.target {
        Target::Room(room) => Ok(room),
        _ => invalid("RoomTarget"),
    }
}
pub(crate) fn subjects(actor: &Actor) -> Vec<AccountId> {
    let mut result = vec![actor.acting().account, actor.represented()];
    if let Actor::IndependentAgent { operator, .. } | Actor::Delegated { operator, .. } = actor {
        result.push(*operator);
    }
    result.sort();
    result.dedup();
    result
}
pub(crate) fn restriction(
    db: &Connection,
    room: RoomId,
    actor: &Actor,
    kind: u8,
    now: TimeBounds,
) -> Domain<bool> {
    for subject in subjects(actor) {
        if db.query_row("SELECT EXISTS(SELECT 1 FROM hrc_restrictions WHERE room=?1 AND subject=?2 AND kind=?3 AND expires>?4)",params![room.to_string(),subject.to_string(),kind,now.lower_ms],|r|r.get::<_,bool>(0))? {return Ok(true);}
    }
    Ok(false)
}
pub(crate) fn access(db: &Connection, action: &Action, now: TimeBounds) -> Domain<Access> {
    let room = target(action)?;
    crate::federation::actor_admitted(db, action.actor.acting(), room, now)?;
    let data: Option<(u64, u64, u64, u8)> = db
        .query_row(
            "SELECT sequence,revision,earliest,mode FROM hrc_rooms WHERE id=?1",
            [room.to_string()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let Some((sequence, revision, earliest, mode)) = data else {
        return deny("RoomUnavailable");
    };
    let confidentiality = mode_value(mode)?;
    if restriction(db, room, &action.actor, 2, now)? {
        return deny("RoomBan");
    }
    let membership:Option<(bool,u64,u64,bool)>=db.query_row("SELECT active,revision,history_from,moderator FROM hrc_members WHERE room=?1 AND account=?2",params![room.to_string(),action.actor.represented().to_string()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
    let Some((true, membership_revision, history_from, moderator)) = membership else {
        return deny("Membership");
    };
    home::check_revision(action, Revision::Room, revision)?;
    let filter_revision: u64 = db.query_row(
        "SELECT filter_revision FROM hrc_accounts WHERE id=?1",
        [action.actor.represented().to_string()],
        |r| r.get(0),
    )?;
    home::check_revision(action, Revision::Filter, filter_revision)?;
    let access_digest = digest(&encode(&(
        action.home,
        &action.actor,
        room,
        membership_revision,
        revision,
        filter_revision,
        history_from,
        &action.agreement,
    ))?);
    Ok(Access {
        room,
        sequence,
        revision,
        membership_revision,
        history_from,
        filter_revision,
        access_digest,
        moderator,
        earliest,
        confidentiality,
    })
}
pub(crate) fn operate(db: &Transaction<'_>, action: &Action, now: TimeBounds) -> Domain<Outcome> {
    match action.operation {
        Operation::RoomCreate => create(db, action, now),
        Operation::DirectCreate => direct(db, action, now),
        Operation::RoomInvite => invite(db, action, now),
        Operation::RoomList => list(db, action, now),
        Operation::RoomInspect => inspection::read(db, action, now),
        Operation::RoomJoin => join(db, action, now),
        Operation::RoomLeave => {
            empty(&action.body)?;
            let access = access(db, action, now)?;
            let owner: String = db.query_row(
                "SELECT owner FROM hrc_rooms WHERE id=?1",
                [access.room.to_string()],
                |r| r.get(0),
            )?;
            if owner == action.actor.represented().to_string() {
                return deny("OwnerMustRemain");
            }
            db.execute(
                "UPDATE hrc_members SET active=0,revision=revision+1 WHERE room=?1 AND account=?2",
                params![
                    access.room.to_string(),
                    action.actor.represented().to_string()
                ],
            )?;
            db.execute(
                "UPDATE hrc_rooms SET revision=revision+1 WHERE id=?1",
                [access.room.to_string()],
            )?;
            crate::confidential::invalidate_accounts(db, &[action.actor.represented()])?;
            crate::messaging::record(db, action, access.room, Value::Null, "", now)
        }
        Operation::RoomSetTopic => {
            let body: Topic = unpack(&action.body)?;
            if body.topic.len() > 1024 {
                return invalid("Topic");
            }
            if !body.topic.is_empty() {
                crate::text::message(&body.topic)
                    .map_err(|_| Fault::Reject(ErrorCode::InvalidInput, "Topic"))?;
            }
            let access = access(db, action, now)?;
            if !access.moderator {
                return deny("Moderator");
            }
            let event_body = value(&body)?;
            db.execute(
                "UPDATE hrc_rooms SET topic=?1,revision=revision+1 WHERE id=?2",
                params![body.topic, access.room.to_string()],
            )?;
            crate::messaging::record(db, action, access.room, event_body, "", now)
        }
        _ => invalid("RoomOperation"),
    }
}
pub(crate) fn mode_value(mode: u8) -> Domain<RoomConfidentiality> {
    match mode {
        0 => Ok(RoomConfidentiality::Community),
        1 => Ok(RoomConfidentiality::ConfidentialDirect),
        2 => Ok(RoomConfidentiality::PrivateGroup),
        _ => Err(Fault::Sql(rusqlite::Error::InvalidQuery)),
    }
}
fn create(db: &Transaction<'_>, action: &Action, now: TimeBounds) -> Domain<Outcome> {
    let body: Create = unpack(&action.body)?;
    if body.confidentiality == RoomConfidentiality::ConfidentialDirect {
        return invalid("UseDirectCreate");
    }
    create_room(db, action, now, &body, None)
}
fn direct(db: &Transaction<'_>, action: &Action, now: TimeBounds) -> Domain<Outcome> {
    let body: crate::confidential::Direct = unpack(&action.body)?;
    if body.recipient == action.actor.represented() {
        return invalid("DirectRecipient");
    }
    let exists: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM hrc_accounts WHERE id=?1)",
        [body.recipient.to_string()],
        |r| r.get(0),
    )?;
    if !exists || crate::moderation::ignored(db, body.recipient, &action.actor)? {
        return deny("RecipientUnavailable");
    }
    create_room(
        db,
        action,
        now,
        &Create {
            name: "Direct".into(),
            confidentiality: RoomConfidentiality::ConfidentialDirect,
        },
        Some(body.recipient),
    )
}
fn create_room(
    db: &Transaction<'_>,
    action: &Action,
    now: TimeBounds,
    body: &Create,
    recipient: Option<AccountId>,
) -> Domain<Outcome> {
    if action.target != Target::Service || matches!(action.actor, Actor::Delegated { .. }) {
        return deny("RoomCreation");
    }
    crate::text::handle(&body.name)
        .map_err(|_| Fault::Reject(ErrorCode::InvalidInput, "RoomName"))?;
    let count: u64 = db.query_row("SELECT count(*) FROM hrc_rooms", [], |r| r.get(0))?;
    if count >= 256 {
        return Err(Fault::Reject(ErrorCode::Overloaded, "RoomLimit"));
    }
    let room = RoomId {
        home: action.home,
        local: random()?,
    };
    let mode = match body.confidentiality {
        RoomConfidentiality::Community => 0,
        RoomConfidentiality::ConfidentialDirect => 1,
        RoomConfidentiality::PrivateGroup => 2,
    };
    db.execute("INSERT INTO hrc_rooms(id,room,name,topic,owner,revision,sequence,created,mode) VALUES(?1,?2,?3,'',?4,1,0,?5,?6)",params![room.to_string(),encode(&room)?,body.name,action.actor.represented().to_string(),now.lower_ms,mode])?;
    db.execute(
        "INSERT INTO hrc_members VALUES(?1,?2,1,1,?3,1)",
        params![
            room.to_string(),
            action.actor.represented().to_string(),
            now.lower_ms
        ],
    )?;
    if mode != 0 {
        db.execute(
            "INSERT INTO hrc_encrypted_rooms(room) VALUES(?1)",
            [room.to_string()],
        )?;
    }
    if let Some(recipient) = recipient {
        db.execute(
            "INSERT INTO hrc_room_invitations VALUES(?1,?2,?3,?4)",
            params![
                room.to_string(),
                recipient.to_string(),
                action.actor.represented().to_string(),
                now.lower_ms + DAY
            ],
        )?;
    }
    crate::messaging::record(db, action, room, value(&(room, &body.name))?, "", now)
}
fn invite(db: &Transaction<'_>, action: &Action, now: TimeBounds) -> Domain<Outcome> {
    let body: crate::confidential::Invite = unpack(&action.body)?;
    let a = access(db, action, now)?;
    if !a.moderator
        || matches!(action.actor, Actor::Delegated { .. })
        || a.confidentiality != RoomConfidentiality::PrivateGroup
    {
        return deny("PrivateGroupModerator");
    }
    let exists: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM hrc_accounts WHERE id=?1)",
        [body.account.to_string()],
        |r| r.get(0),
    )?;
    if !exists || crate::moderation::ignored(db, body.account, &action.actor)? {
        return deny("RecipientUnavailable");
    }
    let joined: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM hrc_members WHERE room=?1 AND account=?2 AND active=1)",
        params![a.room.to_string(), body.account.to_string()],
        |r| r.get(0),
    )?;
    if joined {
        return conflict("AlreadyJoined");
    }
    db.execute(
        "DELETE FROM hrc_room_invitations WHERE room=?1 AND expires<=?2",
        params![a.room.to_string(), now.lower_ms],
    )?;
    let count: u64 = db.query_row(
        "SELECT count(*) FROM hrc_room_invitations WHERE room=?1",
        [a.room.to_string()],
        |r| r.get(0),
    )?;
    if count >= 32 {
        return Err(Fault::Reject(ErrorCode::Overloaded, "InvitationLimit"));
    }
    db.execute("INSERT INTO hrc_room_invitations VALUES(?1,?2,?3,?4) ON CONFLICT(room,account) DO UPDATE SET inviter=excluded.inviter,expires=excluded.expires",params![a.room.to_string(),body.account.to_string(),action.actor.represented().to_string(),now.lower_ms+DAY])?;
    crate::messaging::record(db, action, a.room, value(&body)?, "", now)
}
fn join(db: &Transaction<'_>, action: &Action, now: TimeBounds) -> Domain<Outcome> {
    empty(&action.body)?;
    let room = target(action)?;
    let existing: Option<(u64, u8)> = db
        .query_row(
            "SELECT revision,mode FROM hrc_rooms WHERE id=?1",
            [room.to_string()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((revision, mode)) = existing else {
        return deny("RoomUnavailable");
    };
    mode_value(mode)?;
    if mode != 0 {
        if matches!(action.actor, Actor::Delegated { .. }) {
            return deny("InvitationRecipient");
        }
        let invited:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM hrc_room_invitations WHERE room=?1 AND account=?2 AND expires>?3)",params![room.to_string(),action.actor.represented().to_string(),now.upper_ms],|r|r.get(0))?;
        if !invited {
            return deny("InvitationRequired");
        }
    }
    home::check_revision(action, Revision::Room, revision)?;
    if restriction(db, room, &action.actor, 2, now)? {
        return deny("RoomBan");
    }
    let existing: Option<bool> = db
        .query_row(
            "SELECT active FROM hrc_members WHERE room=?1 AND account=?2",
            params![room.to_string(), action.actor.represented().to_string()],
            |r| r.get(0),
        )
        .optional()?;
    if existing == Some(true) {
        return conflict("AlreadyJoined");
    }
    let count: u64 = db.query_row(
        "SELECT count(*) FROM hrc_members WHERE room=?1 AND active=1",
        [room.to_string()],
        |r| r.get(0),
    )?;
    if count >= if mode == 1 { 2 } else { 32 } {
        return Err(Fault::Reject(ErrorCode::Overloaded, "MemberLimit"));
    }
    db.execute("INSERT INTO hrc_members VALUES(?1,?2,1,1,?3,0) ON CONFLICT(room,account) DO UPDATE SET active=1,revision=revision+1,history_from=excluded.history_from",params![room.to_string(),action.actor.represented().to_string(),now.lower_ms])?;
    db.execute(
        "UPDATE hrc_rooms SET revision=revision+1 WHERE id=?1",
        [room.to_string()],
    )?;
    db.execute(
        "DELETE FROM hrc_room_invitations WHERE room=?1 AND account=?2",
        params![room.to_string(), action.actor.represented().to_string()],
    )?;
    crate::messaging::record(db, action, room, Value::Null, "", now)
}
fn list(db: &Transaction<'_>, action: &Action, now: TimeBounds) -> Domain<Outcome> {
    if action.target != Target::Service {
        return invalid("ServiceTarget");
    }
    let body: List = unpack(&action.body)?;
    if !(1..=50).contains(&body.limit) {
        return invalid("PageLimit");
    }
    if body.after.is_some_and(|r| r.home != action.home) {
        return invalid("RoomCursorHome");
    }
    if matches!(action.actor, Actor::Delegated { .. }) {
        return deny("ExplicitRoomScope");
    }
    let mut stmt=db.prepare("SELECT r.room,r.name,r.topic,r.revision,r.sequence,COALESCE(m.active,0),COALESCE(u.sequence,0),COALESCE(m.history_from,0),r.mode,EXISTS(SELECT 1 FROM hrc_room_invitations i WHERE i.room=r.id AND i.account=?1 AND i.expires>?3) FROM hrc_rooms r LEFT JOIN hrc_members m ON m.room=r.id AND m.account=?1 LEFT JOIN hrc_unread u ON u.room=r.id AND u.account=?1 WHERE r.id>?2 AND (r.mode=0 OR m.active=1 OR EXISTS(SELECT 1 FROM hrc_room_invitations i WHERE i.room=r.id AND i.account=?1 AND i.expires>?3)) ORDER BY r.id LIMIT 256")?;
    let rows = stmt.query_map(
        params![
            action.actor.represented().to_string(),
            body.after.map(|v| v.to_string()).unwrap_or_default(),
            now.upper_ms
        ],
        |r| {
            Ok((
                decode::<RoomId>(&r.get::<_, Vec<u8>>(0)?)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, u64>(3)?,
                r.get::<_, u64>(4)?,
                r.get::<_, bool>(5)?,
                r.get::<_, u64>(6)?,
                r.get::<_, u64>(7)?,
                r.get::<_, u8>(8)?,
                r.get::<_, bool>(9)?,
            ))
        },
    )?;
    let mut result = Vec::new();
    for row in rows {
        let (room, name, topic, revision, sequence, joined, read, history_from, mode, invited) =
            row?;
        match crate::federation::actor_admitted(db, action.actor.acting(), room, now) {
            Ok(()) => {}
            Err(Fault::Reject(..)) => continue,
            Err(e) => return Err(e),
        }
        if restriction(db, room, &action.actor, 2, now)? {
            continue;
        }
        let unread = if joined {
            db.query_row("SELECT count(*) FROM hrc_events e WHERE e.room=?1 AND e.sequence>?2 AND e.created>=?3 AND e.kind IN(20,21,22) AND NOT EXISTS(SELECT 1 FROM hrc_filters f WHERE f.owner=?4 AND f.ignored=1 AND f.subject IN(e.actor,e.represented,e.operator))",params![room.to_string(),read,history_from.max(now.upper_ms.saturating_sub(RETENTION)),action.actor.represented().to_string()],|r|r.get(0))?
        } else {
            0
        };
        result.push(Summary {
            room,
            name,
            topic,
            revision,
            sequence,
            joined,
            unread,
            confidentiality: mode_value(mode)?,
            invited,
        });
        if canonical_encode(&value(&result)?, ORDINARY_FRAME_BYTES - 4096).is_err() {
            result.pop();
            break;
        }
        if result.len() >= body.limit as usize {
            break;
        }
    }
    Ok(Outcome::Result {
        body: value(&result)?,
    })
}
