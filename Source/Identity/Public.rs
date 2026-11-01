// SPDX-License-Identifier: Apache-2.0
//! Shared-room participants can verify public endpoint continuity without gaining controller rights.
use super::*;
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicIdentityRequest {
    pub room: RoomId,
    pub after: u64,
    pub limit: u16,
    #[serde(default)]
    pub evidence: Option<Id>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PublicIdentity {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub origin_checkpoint: Option<Blob>,
    pub identity: IdentitySnapshot,
    pub continuity: crate::home::InspectionPage<ContinuityRecord>,
}
pub(crate) fn read(db: &Connection, action: &Action, now: TimeBounds) -> Domain<Outcome> {
    let Target::Account(account) = action.target else {
        return invalid("AccountTarget");
    };
    let request: PublicIdentityRequest = unpack(&action.body)?;
    if request.room.home != action.home {
        return deny("IdentityOrigin");
    }
    let mut room_action = action.clone();
    room_action.target = Target::Room(request.room);
    let access = crate::conversations::access(db, &room_action, now)?;
    let mut shares: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM hrc_members WHERE room=?1 AND account=?2 AND active=1)",
        params![request.room.to_string(), account.to_string()],
        |r| r.get(0),
    )?;
    if !shares {
        let mut stmt=db.prepare("SELECT actor FROM hrc_encrypted_roster WHERE room=?1 UNION ALL SELECT actor FROM hrc_mls_packages WHERE room=?1 AND used=0 AND expires>?2 LIMIT 129")?;
        let actors = stmt
            .query_map(params![request.room.to_string(), now.upper_ms], |r| {
                decode::<Actor>(&r.get::<_, Vec<u8>>(0)?)
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        if actors.len() > 128 {
            return Err(Fault::Sql(rusqlite::Error::InvalidQuery));
        }
        shares = actors
            .iter()
            .any(|actor| crate::conversations::subjects(actor).contains(&account));
    }
    if !shares && let Some(evidence) = request.evidence {
        let permit = crate::delegation::read_authority(db, &action.actor, request.room, now)?;
        let bytes:Option<Vec<u8>>=db.query_row("SELECT e.event FROM hrc_events e WHERE e.id=?1 AND e.room=?2 AND e.kind IN(72,73,77) AND ((e.created>=?3 AND e.created<=?4) OR EXISTS(SELECT 1 FROM hrc_mls_welcomes w JOIN hrc_encrypted_rooms c ON c.room=w.room AND c.group_id=w.group_id WHERE w.room=e.room AND w.sequence=e.sequence AND w.endpoint=?5 AND w.expires>?6))",params![evidence.as_hex(),request.room.to_string(),access.history_from.max(permit.history_from).max(now.upper_ms.saturating_sub(RETENTION)),permit.history_until.min(i64::MAX as u64),action.actor.acting().endpoint.as_hex(),now.upper_ms],|r|r.get(0)).optional()?;
        if let Some(bytes) = bytes {
            let event: Event = decode(&bytes)?;
            let transition: crate::confidential::TransitionEvent = unpack(&event.body)?;
            shares = transition
                .members
                .iter()
                .any(|m| crate::conversations::subjects(&m.actor).contains(&account));
        }
    }
    if !shares {
        return deny("SharedRoomIdentity");
    }
    if account.origin != action.home.network {
        let (identity, checkpoint) = crate::federation::foreign_identity(db, account)?;
        let continuity =
            crate::federation::foreign_page(db, account, request.after, request.limit)?;
        return Ok(Outcome::Result {
            body: value(&PublicIdentity {
                identity,
                continuity,
                origin_checkpoint: Some(checkpoint),
            })?,
        });
    }
    let identity = continuity::snapshot(db, action.home, account)?;
    let continuity = lifecycle::continuity_page(
        db,
        account,
        &ContinuityPage {
            after: request.after,
            limit: request.limit,
        },
    )?;
    Ok(Outcome::Result {
        body: value(&PublicIdentity {
            origin_checkpoint: None,
            identity,
            continuity,
        })?,
    })
}
