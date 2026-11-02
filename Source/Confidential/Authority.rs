// SPDX-License-Identifier: Apache-2.0
//! Current authority for every leaf, including finite delegated reading and room restrictions.
use super::Member;
use crate::{clock::TimeBounds, conversations, delegation, home::types::*, identity, protocol::*};
use rusqlite::{Connection, OptionalExtension, params};

pub(super) fn member(db: &Connection, room: RoomId, actor: &Actor) -> Domain<Member> {
    let row: Option<(Vec<u8>, Vec<u8>, Vec<u8>)> = db
        .query_row(
            "SELECT actor,key,registration FROM hrc_mls_keys WHERE account=?1 AND endpoint=?2",
            params![
                actor.acting().account.to_string(),
                actor.acting().endpoint.as_hex()
            ],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let Some((saved, key, registration)) = row else {
        return deny("MlsEndpointNotEnrolled");
    };
    if decode::<EndpointActor>(&saved)? != *actor.acting() {
        return deny("MlsEndpointGeneration");
    }
    let delegation = if let Actor::Delegated { grant, .. } = actor {
        let authorization: Option<(Vec<u8>, u64)> = db
            .query_row(
                "SELECT authorization,position FROM hrc_mls_grants WHERE grant_id=?1",
                [grant.id.as_hex()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let Some((authorization, position)) = authorization else {
            return deny("EncryptedGrantProofRequired");
        };
        Some(super::DelegationEvidence {
            position,
            grant: delegation::load(db, grant.id)?,
            authorization: Blob(authorization),
        })
    } else {
        None
    };
    Ok(Member {
        delegation,
        actor: actor.clone(),
        registration: Blob(registration),
        credential: crate::crypto::EndpointCredential {
            room,
            actor: actor.acting().clone(),
            mls_key: Id::from_bytes(key.try_into().map_err(|_| rusqlite::Error::InvalidQuery)?),
        },
    })
}

pub(super) fn reader(
    db: &Connection,
    room: RoomId,
    actor: &Actor,
    now: TimeBounds,
) -> Domain<bool> {
    let Some(endpoint) = identity::endpoint(db, actor.acting().account, actor.acting().endpoint)?
    else {
        return Ok(false);
    };
    if endpoint.acting != *actor.acting() {
        return Ok(false);
    }
    match (&endpoint.classification, actor) {
        (AccountClass::Human, Actor::Direct { .. }) => {}
        (
            AccountClass::Agent { operator: expected },
            Actor::IndependentAgent { operator, .. } | Actor::Delegated { operator, .. },
        ) if expected == operator => {}
        _ => return Ok(false),
    }
    if conversations::restriction(db, room, actor, 2, now)? {
        return Ok(false);
    }
    let member: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM hrc_members WHERE room=?1 AND account=?2 AND active=1)",
        params![room.to_string(), actor.represented().to_string()],
        |r| r.get(0),
    )?;
    if !member {
        return Ok(false);
    }
    match delegation::read_authority(db, actor, room, now) {
        Ok(_) => {}
        Err(Fault::Reject(_, _)) => return Ok(false),
        Err(error) => return Err(error),
    }
    Ok(true)
}

pub(super) fn eligible(
    db: &Connection,
    room: RoomId,
    actor: &Actor,
    now: TimeBounds,
) -> Domain<bool> {
    if !reader(db, room, actor, now)? {
        return Ok(false);
    }
    let permit = delegation::read_authority(db, actor, room, now)?;
    Ok(now.lower_ms >= permit.history_from && now.upper_ms < permit.history_until)
}

pub(super) fn members(db: &Connection, room: RoomId) -> Domain<Vec<Member>> {
    let mut statement = db.prepare(
        "SELECT actor,credential,registration,delegation FROM hrc_encrypted_roster WHERE room=?1 ORDER BY endpoint LIMIT 65",
    )?;
    let result = statement
        .query_map([room.to_string()], |r| {
            Ok(Member {
                actor: decode(&r.get::<_, Vec<u8>>(0)?)?,
                credential: decode(&r.get::<_, Vec<u8>>(1)?)?,
                registration: Blob(r.get(2)?),
                delegation: r
                    .get::<_, Option<Vec<u8>>>(3)?
                    .map(|bytes| decode(&bytes))
                    .transpose()?,
            })
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if result.len() > crate::crypto::MAX_ENDPOINTS {
        return Err(Fault::Sql(rusqlite::Error::InvalidQuery));
    }
    for member in &result {
        if member.credential.room != room || member.credential.actor != *member.actor.acting() {
            return Err(Fault::Sql(rusqlite::Error::InvalidQuery));
        }
    }
    Ok(result)
}

pub(super) fn required_removals(
    db: &Connection,
    room: RoomId,
    members: &[Member],
    now: TimeBounds,
) -> Domain<Vec<Id>> {
    let mut result = Vec::new();
    for member in members {
        if !eligible(db, room, &member.actor, now)? {
            result.push(member.actor.acting().endpoint);
        }
    }
    Ok(result)
}
