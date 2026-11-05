// SPDX-License-Identifier: Apache-2.0
//! The home serialises public MLS transitions; endpoint receipts release the exact epoch barrier.
use super::{authority, *};
use crate::{
    clock::TimeBounds,
    conversations, crypto,
    delegation::Permit,
    home::{self, types::*},
    protocol::*,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};

pub(super) struct State {
    pub group: Option<Id>,
    pub epoch: u64,
    pub digest: Option<Id>,
    pub sequence: u64,
    pub barrier: bool,
    pub frozen: bool,
}
fn id(bytes: Option<Vec<u8>>) -> rusqlite::Result<Option<Id>> {
    bytes
        .map(|b| {
            b.try_into()
                .map(Id::from_bytes)
                .map_err(|_| rusqlite::Error::InvalidQuery)
        })
        .transpose()
}
pub(super) fn state(db: &Connection, room: RoomId) -> Domain<State> {
    db.query_row("SELECT group_id,epoch,commit_digest,sequence,barrier,frozen FROM hrc_encrypted_rooms WHERE room=?1",[room.to_string()],|r|Ok(State{group:id(r.get(0)?)?,epoch:r.get(1)?,digest:id(r.get(2)?)?,sequence:r.get(3)?,barrier:r.get(4)?,frozen:r.get(5)?})).optional()?.ok_or(Fault::Reject(ErrorCode::InvalidInput,"EncryptedRoomRequired"))
}
fn roster(room: RoomId, members: &[Member]) -> Domain<crypto::ApprovedRoster> {
    crypto::ApprovedRoster::new(room, members.iter().map(|m| m.credential.clone()).collect())
        .map_err(|_| Fault::Reject(ErrorCode::InvalidInput, "EncryptedRoster"))
}
fn public_error(_: crypto::Error) -> Fault {
    Fault::Reject(ErrorCode::InvalidInput, "MlsTransitionBinding")
}
fn controller(db: &Connection, action: &Action, now: TimeBounds) -> Domain<conversations::Access> {
    let a = conversations::access(db, action, now)?;
    if a.confidentiality == RoomConfidentiality::Community
        || matches!(action.actor, Actor::Delegated { .. })
        || !a.moderator
    {
        return deny("EncryptedRoomModerator");
    }
    if !authority::eligible(db, a.room, &action.actor, now)? {
        return deny("EncryptedEndpointAuthority");
    }
    Ok(a)
}
fn save_members(db: &Transaction<'_>, room: RoomId, members: &[Member]) -> Domain<()> {
    representation::roster(members)?;
    db.execute(
        "DELETE FROM hrc_encrypted_roster WHERE room=?1",
        [room.to_string()],
    )?;
    for member in members {
        let (operator, grant) = match member.actor {
            Actor::Direct { .. } => (None, None),
            Actor::IndependentAgent { operator, .. } => (Some(operator.to_string()), None),
            Actor::Delegated {
                operator, grant, ..
            } => (Some(operator.to_string()), Some(grant.id.as_hex())),
        };
        db.execute(
            "INSERT INTO hrc_encrypted_roster VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
            params![
                room.to_string(),
                member.actor.acting().endpoint.as_hex(),
                member.actor.acting().account.to_string(),
                member.actor.represented().to_string(),
                operator,
                grant,
                encode(&member.actor)?,
                encode(&member.credential)?,
                member.registration.0,
                member.delegation.as_ref().map(encode).transpose()?
            ],
        )?;
    }
    Ok(())
}
fn record(
    db: &Transaction<'_>,
    action: &Action,
    room: RoomId,
    event: &TransitionEvent,
    now: TimeBounds,
) -> Domain<Outcome> {
    // This leaves room for the signed event, history cursor and bounded room members.
    representation::bounded(event, representation::TRANSITION_BYTES)?;
    let result = crate::messaging::record(db, action, room, value(event)?, "", now)?;
    let sequence: u64 = db.query_row(
        "SELECT sequence FROM hrc_rooms WHERE id=?1",
        [room.to_string()],
        |r| r.get(0),
    )?;
    db.execute("UPDATE hrc_encrypted_rooms SET group_id=?1,epoch=?2,commit_digest=?3,sequence=?4,barrier=1,frozen=0 WHERE room=?5",params![event.group.as_bytes().as_slice(),event.epoch,event.commit_digest.as_bytes().as_slice(),sequence,room.to_string()])?;
    db.execute(
        "UPDATE hrc_rooms SET revision=revision+1 WHERE id=?1",
        [room.to_string()],
    )?;
    Ok(result)
}
pub(super) fn initialise(
    db: &Transaction<'_>,
    action: &Action,
    now: TimeBounds,
) -> Domain<Outcome> {
    let a = controller(db, action, now)?;
    let body: Initialise = unpack(&action.body)?;
    let current = state(db, a.room)?;
    if (action.operation == Operation::CryptoPropose) != current.group.is_none() {
        return conflict("EncryptedGroupState");
    }
    if current.group.is_some() && !current.frozen && !current.barrier {
        return deny("RecoveryRequiresBarrier");
    }
    if db.query_row(
        "SELECT EXISTS(SELECT 1 FROM crypto_groups WHERE id=?1)",
        [body.group.as_bytes().as_slice()],
        |r| r.get::<_, bool>(0),
    )? {
        return conflict("GroupIdentityReuse");
    }
    let count: u64 = db.query_row("SELECT count(*) FROM crypto_groups", [], |r| r.get(0))?;
    if count >= 4096 {
        return Err(Fault::Reject(ErrorCode::Overloaded, "GroupRecoveryLimit"));
    }
    let member = authority::member(db, a.room, &action.actor)?;
    let members = vec![member];
    crypto::create_public_in(
        db,
        body.group,
        &body.group_info.0,
        &roster(a.room, &members)?,
    )
    .map_err(public_error)?;
    // A fresh group is a visible future-only reset. Old ciphertext is never relabelled.
    save_members(db, a.room, &members)?;
    db.execute(
        "DELETE FROM hrc_mls_ready WHERE room=?1",
        [a.room.to_string()],
    )?;
    db.execute(
        "DELETE FROM hrc_mls_welcomes WHERE room=?1",
        [a.room.to_string()],
    )?;
    let event = TransitionEvent {
        group: body.group,
        previous_epoch: None,
        epoch: 0,
        commit_digest: digest(&body.group_info.0),
        commit: body.group_info,
        members,
        additions: vec![],
        removals: vec![],
    };
    record(db, action, a.room, &event, now)
}
fn package(db: &Connection, room: RoomId, key: Id) -> Domain<Package> {
    db.query_row("SELECT actor,credential,registration,delegation,package,expires FROM hrc_mls_packages WHERE digest=?1 AND room=?2 AND used=0",params![key.as_hex(),room.to_string()],|r|Ok(Package{digest:key,member:Member{actor:decode(&r.get::<_,Vec<u8>>(0)?)?,credential:decode(&r.get::<_,Vec<u8>>(1)?)?,registration:Blob(r.get(2)?),delegation:r.get::<_,Option<Vec<u8>>>(3)?.map(|b|decode(&b)).transpose()?},package:Blob(r.get(4)?),expires_ms:r.get(5)?})).optional()?.ok_or(Fault::Reject(ErrorCode::Denied,"KeyPackageUnavailable"))
}
pub(super) fn commit(db: &Transaction<'_>, action: &Action, now: TimeBounds) -> Domain<Outcome> {
    let a = controller(db, action, now)?;
    let request: CommitEpoch = unpack(&action.body)?;
    let state = state(db, a.room)?;
    if state.group != Some(request.group) || state.epoch != request.epoch || state.frozen {
        return conflict("EncryptedEpoch");
    }
    if request.additions.len() > 64 || request.removals.len() > 64 {
        return invalid("TransitionLimit");
    }
    let old = authority::members(db, a.room)?;
    if !old.iter().any(|m| m.actor == action.actor) {
        return deny("CommitterNotInEpoch");
    }
    let mut next = old.clone();
    let mut unique = std::collections::BTreeSet::new();
    for endpoint in &request.removals {
        if !unique.insert(*endpoint)
            || *endpoint == action.actor.acting().endpoint
            || !next.iter().any(|m| m.actor.acting().endpoint == *endpoint)
        {
            return invalid("RemovedEndpoint");
        }
        next.retain(|m| m.actor.acting().endpoint != *endpoint);
    }
    unique.clear();
    for key in &request.additions {
        if !unique.insert(*key) {
            return invalid("DuplicatePackage");
        }
        let package = package(db, a.room, *key)?;
        if package.expires_ms <= now.upper_ms
            || !authority::eligible(db, a.room, &package.member.actor, now)?
        {
            return deny("PackageAuthority");
        }
        if authority::member(db, a.room, &package.member.actor)?.credential
            != package.member.credential
        {
            return deny("PackageEndpointChanged");
        }
        next.push(package.member);
    }
    if !authority::required_removals(db, a.room, &next, now)?.is_empty() {
        return deny("RequiredEndpointRemoval");
    }
    let accepted = crypto::accept_public_in(
        db,
        request.group,
        request.epoch,
        &request.commit.0,
        action.actor.acting(),
        &roster(a.room, &old)?,
        &roster(a.room, &next)?,
    )
    .map_err(public_error)?;
    for key in &request.additions {
        db.execute(
            "UPDATE hrc_mls_packages SET used=1 WHERE digest=?1",
            [key.as_hex()],
        )?;
    }
    save_members(db, a.room, &next)?;
    let event = TransitionEvent {
        group: request.group,
        previous_epoch: Some(request.epoch),
        epoch: accepted.epoch,
        commit: request.commit,
        commit_digest: accepted.commit_digest,
        members: next,
        additions: request.additions,
        removals: request.removals,
    };
    record(db, action, a.room, &event, now)
}
fn transition(db: &Connection, room: RoomId, sequence: u64) -> Domain<(Event, TransitionEvent)> {
    let bytes: Vec<u8> = db.query_row(
        "SELECT event FROM hrc_events WHERE room=?1 AND sequence=?2",
        params![room.to_string(), sequence],
        |r| r.get(0),
    )?;
    let event: Event = decode(&bytes)?;
    let transition = unpack(&event.body)?;
    Ok((event, transition))
}
pub(super) fn ready(db: &Transaction<'_>, action: &Action, now: TimeBounds) -> Domain<Outcome> {
    let a = conversations::access(db, action, now)?;
    let body: Ready = unpack(&action.body)?;
    let state = state(db, a.room)?;
    if state.frozen
        || state.group != Some(body.group)
        || state.epoch != body.epoch
        || state.digest != Some(body.commit_digest)
        || state.sequence != body.sequence
    {
        return conflict("EpochReceipt");
    }
    let members = authority::members(db, a.room)?;
    if !members.iter().any(|m| m.actor == action.actor)
        || !authority::eligible(db, a.room, &action.actor, now)?
    {
        return deny("EpochEndpoint");
    }
    if !authority::required_removals(db, a.room, &members, now)?.is_empty() {
        return deny("RequiredEndpointRemoval");
    }
    let (event, transition) = transition(db, a.room, state.sequence)?;
    let author = event.actor == action.actor;
    if body.welcome.is_some() && (!author || transition.additions.is_empty()) {
        return deny("WelcomeAuthor");
    }
    if author && !transition.additions.is_empty() && body.welcome.is_none() {
        return invalid("WelcomeRequired");
    }
    if let Some(welcome) = body.welcome {
        if welcome.0.is_empty() || welcome.0.len() > 192 * 1024 {
            return invalid("WelcomeSize");
        }
        representation::bounded(
            &Welcome {
                event: event.event,
                group: body.group,
                epoch: body.epoch,
                commit_digest: body.commit_digest,
                sequence: body.sequence,
                package_digest: Id::from_bytes([0; 32]),
                welcome: welcome.clone(),
                members: transition.members.clone(),
            },
            representation::TRANSITION_BYTES,
        )?;
        for package in &transition.additions {
            let endpoint: String = db.query_row(
                "SELECT endpoint FROM hrc_mls_packages WHERE digest=?1 AND room=?2 AND used=1",
                params![package.as_hex(), a.room.to_string()],
                |r| r.get(0),
            )?;
            db.execute("INSERT INTO hrc_mls_welcomes VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9) ON CONFLICT(group_id,epoch,endpoint) DO NOTHING",params![a.room.to_string(),body.group.as_bytes().as_slice(),body.epoch,endpoint,package.as_hex(),body.commit_digest.as_bytes().as_slice(),body.sequence,welcome.0,now.lower_ms+DAY])?;
        }
    }
    db.execute("INSERT INTO hrc_mls_ready VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(group_id,epoch,endpoint) DO NOTHING",params![a.room.to_string(),body.group.as_bytes().as_slice(),body.epoch,action.actor.acting().endpoint.as_hex(),body.commit_digest.as_bytes().as_slice(),body.sequence])?;
    // The selected author must first verify its own winning commit and release its Welcomes.
    let author_ready: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM hrc_mls_ready WHERE group_id=?1 AND epoch=?2 AND endpoint=?3)",
        params![
            body.group.as_bytes().as_slice(),
            body.epoch,
            event.actor.acting().endpoint.as_hex()
        ],
        |r| r.get(0),
    )?;
    if author_ready {
        db.execute(
            "UPDATE hrc_encrypted_rooms SET barrier=0 WHERE room=?1",
            [a.room.to_string()],
        )?;
    }
    home::committed(db, None, Value::Null)
}
pub(super) fn inspect(
    db: &Transaction<'_>,
    action: &Action,
    now: TimeBounds,
    permit: Permit,
) -> Domain<Outcome> {
    empty(&action.body)?;
    let a = conversations::access(db, action, now)?;
    if !authority::reader(db, a.room, &action.actor, now)? {
        return deny("EncryptedReadPermission");
    }
    let state = state(db, a.room)?;
    let members = authority::members(db, a.room)?;
    let required_removals = authority::required_removals(db, a.room, &members, now)?;
    let keys=db.prepare("SELECT digest FROM hrc_mls_packages WHERE room=?1 AND used=0 AND expires>?2 ORDER BY digest LIMIT 64")?.query_map(params![a.room.to_string(),now.upper_ms],|r|home::types::id_column(r,0))?.collect::<rusqlite::Result<Vec<_>>>()?;
    let mut packages = Vec::new();
    for key in keys {
        let p = package(db, a.room, key)?;
        if authority::reader(db, a.room, &p.member.actor, now)? {
            packages.push(p);
        }
    }
    let ignored=db.prepare("SELECT subject FROM hrc_filters WHERE owner=?1 AND ignored=1 ORDER BY subject LIMIT 257")?.query_map([action.actor.represented().to_string()],|r|r.get::<_,String>(0)?.parse::<AccountId>().map_err(|_|rusqlite::Error::InvalidQuery))?.collect::<rusqlite::Result<Vec<_>>>()?;
    if ignored.len() > 256 {
        return Err(Fault::Sql(rusqlite::Error::InvalidQuery));
    }
    Ok(Outcome::Result {
        body: value(&Inspection {
            room: a.room,
            confidentiality: a.confidentiality,
            group: state.group,
            epoch: state.epoch,
            commit_digest: state.digest,
            sequence: state.sequence,
            send_barrier: state.barrier
                || !required_removals.is_empty()
                || !authority::fresh(db, a.room, &members, now)?,
            frozen: state.frozen,
            members,
            packages,
            required_removals,
            history_from_ms: a
                .history_from
                .max(permit.history_from)
                .max(now.upper_ms.saturating_sub(RETENTION)),
            history_until_ms: permit.history_until,
            filter_revision: a.filter_revision,
            ignored,
        })?,
    })
}
pub(super) fn welcome(db: &Transaction<'_>, action: &Action, now: TimeBounds) -> Domain<Outcome> {
    type WelcomeRow = (Vec<u8>, u64, Vec<u8>, u64, String, Vec<u8>);
    empty(&action.body)?;
    let a = conversations::access(db, action, now)?;
    if !authority::eligible(db, a.room, &action.actor, now)? {
        return deny("EncryptedReadPermission");
    }
    let members = authority::members(db, a.room)?;
    if !members.iter().any(|m| m.actor == action.actor) {
        return deny("WelcomeEndpoint");
    }
    let row:Option<WelcomeRow>=db.query_row("SELECT group_id,epoch,commit_digest,sequence,package_digest,welcome FROM hrc_mls_welcomes WHERE room=?1 AND endpoint=?2 AND expires>?3 ORDER BY sequence DESC LIMIT 1",params![a.room.to_string(),action.actor.acting().endpoint.as_hex(),now.upper_ms],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?))).optional()?;
    let Some((group, epoch, hash, sequence, package, welcome)) = row else {
        return conflict("WelcomeUnavailable");
    };
    let (event, transition) = transition(db, a.room, sequence)?;
    Ok(Outcome::Result {
        body: value(&Welcome {
            event: event.event,
            group: id(Some(group))?.ok_or(rusqlite::Error::InvalidQuery)?,
            epoch,
            commit_digest: id(Some(hash))?.ok_or(rusqlite::Error::InvalidQuery)?,
            sequence,
            package_digest: package.parse().map_err(|_| rusqlite::Error::InvalidQuery)?,
            welcome: Blob(welcome),
            members: transition.members,
        })?,
    })
}
pub(super) fn report(db: &Transaction<'_>, action: &Action, now: TimeBounds) -> Domain<Outcome> {
    let a = conversations::access(db, action, now)?;
    let body: TransitionFailure = unpack(&action.body)?;
    let state = state(db, a.room)?;
    if state.group != Some(body.group)
        || state.epoch != body.epoch
        || state.digest != Some(body.commit_digest)
    {
        return conflict("EpochReport");
    }
    if !authority::eligible(db, a.room, &action.actor, now)?
        || !authority::members(db, a.room)?
            .iter()
            .any(|m| m.actor == action.actor)
    {
        return deny("EpochEndpoint");
    }
    db.execute(
        "UPDATE hrc_encrypted_rooms SET barrier=1,frozen=1 WHERE room=?1",
        [a.room.to_string()],
    )?;
    db.execute(
        "UPDATE hrc_rooms SET revision=revision+1 WHERE id=?1",
        [a.room.to_string()],
    )?;
    crate::messaging::record(db, action, a.room, value(&body)?, "", now)
}
