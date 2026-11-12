// SPDX-License-Identifier: Apache-2.0
//! Consent is issued only inside an authenticated operator operation and consumed once.
use super::*;
type StoredConsent = (Vec<u8>, Vec<u8>, Vec<u8>, u64, bool);

fn unsigned(request: &Prepare) -> Prepare {
    let mut r = request.clone();
    r.operator_consent = None;
    r
}
fn operator(request: &Prepare) -> Domain<AccountId> {
    match request.classification {
        Classification::Agent { operator } => Ok(operator),
        _ => invalid("AgentClassification"),
    }
}
fn current_operator(
    db: &Connection,
    actor: &EndpointActor,
    request: &Prepare,
    time: TimeBounds,
) -> Domain<()> {
    if actor.account != operator(request)? {
        return deny("AgentOperatorBinding");
    }
    let current = crate::identity::endpoint(db, actor.account, actor.endpoint)?
        .ok_or(Fault::Reject(ErrorCode::Denied, "OperatorEndpoint"))?;
    if current.acting != *actor || current.classification != AccountClass::Human {
        return deny("OperatorEndpoint");
    }
    for room in &request.rooms {
        scopes::room(db, actor.account, *room)?;
        let joined: bool = db.query_row(
            "SELECT EXISTS(SELECT 1 FROM hrc_members WHERE room=?1 AND account=?2 AND active=1)",
            params![room.to_string(), actor.account.to_string()],
            |r| r.get(0),
        )?;
        if !joined
            || crate::conversations::restriction(
                db,
                *room,
                &Actor::Direct {
                    acting: actor.clone(),
                },
                2,
                time,
            )?
        {
            return deny("OperatorRoomAccess");
        }
    }
    Ok(())
}
fn quota(db: &Connection, p: &Policy, operator: AccountId) -> Domain<()> {
    let mut count = 0;
    let mut stmt = db.prepare("SELECT scope FROM hrc_account_scopes WHERE operator=?1")?;
    for row in stmt.query_map([operator.to_string()], |r| r.get::<_, Vec<u8>>(0))? {
        if !domain::decode::<Scope>(&row?)?.revoked {
            count += 1;
        }
    }
    if count >= p.max_agents_per_operator {
        return deny("OperatorAgentQuota");
    }
    Ok(())
}
pub(super) fn check(
    db: &Connection,
    p: &Policy,
    request: &Prepare,
    time: TimeBounds,
    consume: bool,
) -> Domain<()> {
    let operator = operator(request)?;
    let consent = request
        .operator_consent
        .as_ref()
        .ok_or(Fault::Reject(ErrorCode::Denied, "OperatorConsentRequired"))?
        .bytes()
        .map_err(|_| Fault::Reject(ErrorCode::InvalidInput, "OperatorConsentEncoding"))?;
    let saved: Option<StoredConsent> = db
        .query_row(
            "SELECT request,actor,receipt,expires,used FROM hrc_agent_consents WHERE id=?1",
            [request.claim_id.as_hex()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
        )
        .optional()?;
    let Some((bytes, actor, receipt, expires, used)) = saved else {
        return deny("OperatorConsentMissing");
    };
    if used
        || expires <= time.upper_ms
        || bytes != domain::encode(&unsigned(request))?
        || receipt != consent
    {
        return deny("OperatorConsentBinding");
    }
    current_operator(db, &domain::decode(&actor)?, request, time)?;
    quota(db, p, operator)?;
    if consume {
        db.execute(
            "UPDATE hrc_agent_consents SET used=1 WHERE id=?1",
            [request.claim_id.as_hex()],
        )?;
    }
    Ok(())
}
pub(crate) fn operate(
    db: &Transaction<'_>,
    action: &protocol::Action,
    time: TimeBounds,
) -> Domain<Outcome> {
    if !matches!(action.actor, Actor::Direct { .. })
        || action.agreement.is_some()
        || action.target != Target::Account(action.actor.acting().account)
    {
        return deny("LocalOperatorRequired");
    }
    match action.operation {
        Operation::AgentConsent => {
            let body: Consent = unpack(&action.body)?;
            let request = body.request;
            if request.operator_consent.is_some() {
                return invalid("UnexpectedConsent");
            }
            let p = policy(db)?;
            validate_prepare(db, action.home, &p, &request)?;
            let operator = operator(&request)?;
            current_operator(db, action.actor.acting(), &request, time)?;
            quota(db, &p, operator)?;
            let bytes = domain::encode(&request)?;
            let old: Option<(Vec<u8>, Vec<u8>, u64, bool)> = db
                .query_row(
                    "SELECT request,receipt,expires,used FROM hrc_agent_consents WHERE id=?1",
                    [request.claim_id.as_hex()],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .optional()?;
            let (receipt, expires) = if let Some((old, receipt, expires, used)) = old {
                if old != bytes || used || expires <= time.upper_ms {
                    return conflict("ConsentClaimContent");
                }
                (receipt, expires)
            } else {
                db.execute(
                    "DELETE FROM hrc_agent_consents WHERE expires<=?1",
                    [time.lower_ms],
                )?;
                let count: u64 =
                    db.query_row("SELECT count(*) FROM hrc_agent_consents", [], |r| r.get(0))?;
                if count >= 128 {
                    return Err(Fault::Reject(ErrorCode::Overloaded, "ConsentCapacity"));
                }
                let mut pending =
                    db.prepare("SELECT actor FROM hrc_agent_consents WHERE used=0 AND expires>?1")?;
                let mut operator_pending = 0u16;
                for actor in pending.query_map([time.upper_ms], |r| r.get::<_, Vec<u8>>(0))? {
                    if domain::decode::<EndpointActor>(&actor?)?.account == operator {
                        operator_pending += 1;
                    }
                }
                if operator_pending > p.max_agents_per_operator {
                    return deny("OperatorConsentQuota");
                }
                let receipt = domain::encode(&(
                    "HRC.AgentConsent.1",
                    request.claim_id,
                    protocol::digest(&bytes),
                    random()?,
                ))?;
                let expires = time.lower_ms + 15 * 60 * 1000;
                db.execute(
                    "INSERT INTO hrc_agent_consents VALUES(?1,?2,?3,?4,?5,0)",
                    params![
                        request.claim_id.as_hex(),
                        bytes,
                        domain::encode(action.actor.acting())?,
                        receipt,
                        expires
                    ],
                )?;
                (receipt, expires)
            };
            super::super::committed(
                db,
                None,
                value(&ConsentReceipt {
                    claim_id: request.claim_id,
                    request_digest: protocol::digest(&bytes),
                    expires_ms: expires,
                    operator_consent: Artifact::new(&receipt),
                })?,
            )
        }
        Operation::AgentSetAccess => {
            let update: AgentAccess = unpack(&action.body)?;
            let saved: Option<(String, Vec<u8>, Vec<u8>)> = db
                .query_row(
                    "SELECT operator,original,scope FROM hrc_account_scopes WHERE account=?1",
                    [update.account.to_string()],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            let Some((operator, original, scope)) = saved else {
                return deny("AgentUnavailable");
            };
            let original: Scope = domain::decode(&original)?;
            let mut scope: Scope = domain::decode(&scope)?;
            if operator != action.actor.acting().account.to_string() || scope.revoked {
                return deny("AgentOperatorBinding");
            }
            if update.rooms.len() > 16
                || update.rooms.windows(2).any(|v| v[0] >= v[1])
                || update.rooms.iter().any(|r| !original.rooms.contains(r))
                || update.allow_initiate && !original.allow_initiate
                || update.allow_agent_replies && !original.allow_agent_replies
            {
                return deny("AgentOriginalScope");
            }
            scope.rooms = update.rooms;
            scope.allow_initiate = update.allow_initiate;
            scope.allow_agent_replies = update.allow_agent_replies;
            scope.paused = update.paused;
            scope.revoked = update.revoke;
            db.execute(
                "UPDATE hrc_account_scopes SET scope=?1 WHERE account=?2",
                params![domain::encode(&scope)?, update.account.to_string()],
            )?;
            super::super::committed(db, None, value(&scope)?)
        }
        _ => invalid("AgentOperation"),
    }
}
