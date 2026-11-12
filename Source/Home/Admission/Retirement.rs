// SPDX-License-Identifier: Apache-2.0
//! Terminal claim tombstones retain original receipts and release only active participation.
use super::*;
pub(super) fn outcome(db: &Connection, claim: Id) -> Domain<Option<Response>> {
    let bytes: Option<Vec<u8>> = db
        .query_row(
            "SELECT result FROM hrc_admission_retired WHERE claim=?1",
            [claim.as_hex()],
            |r| r.get(0),
        )
        .optional()?;
    Ok(bytes.map(|bytes| domain::decode(&bytes)).transpose()?)
}
fn retire_account(db: &Transaction<'_>, account: AccountId) -> Domain<()> {
    let Some(mut scope) = scopes::load(db, account)? else {
        return deny("ScopedParticipantMissing");
    };
    scope.revoked = true;
    scope.paused = true;
    db.execute(
        "UPDATE hrc_account_scopes SET scope=?1 WHERE account=?2",
        params![domain::encode(&scope)?, account.to_string()],
    )?;
    db.execute(
        "UPDATE hrc_endpoints SET disabled=1 WHERE account=?1",
        [account.to_string()],
    )?;
    db.execute("UPDATE hrc_rooms SET revision=revision+1 WHERE id IN (SELECT room FROM hrc_members WHERE account=?1 AND active=1)",[account.to_string()])?;
    db.execute(
        "UPDATE hrc_members SET active=0 WHERE account=?1",
        [account.to_string()],
    )?;
    db.execute(
        "DELETE FROM hrc_presence WHERE account=?1",
        [account.to_string()],
    )?;
    Ok(())
}
pub(super) fn revoke(db: &Transaction<'_>, claim: Id) -> Domain<Response> {
    let bytes: Option<Vec<u8>> = db
        .query_row(
            "SELECT request FROM hrc_admission_claims WHERE id=?1",
            [claim.as_hex()],
            |r| r.get(0),
        )
        .optional()?;
    let Some(bytes) = bytes else {
        return deny("AdmissionClaimAbsent");
    };
    let target: Prepare = domain::decode(&bytes)?;
    if target.claim_id != claim {
        return invalid("AdmissionRetirementBinding");
    }
    let mut affected = Vec::new();
    // The claim table has a persistent 1024-entry bound. Retired accounts/history keep
    // counting towards the separate 256-account storage bound; this is not deletion.
    let mut statement = db.prepare(
        "SELECT request,invitation,result FROM hrc_admission_claims ORDER BY id LIMIT 1025",
    )?;
    let rows = statement.query_map([], |r| {
        Ok((
            r.get::<_, Vec<u8>>(0)?,
            r.get::<_, Vec<u8>>(1)?,
            r.get::<_, Option<Vec<u8>>>(2)?,
        ))
    })?;
    for row in rows {
        let (request, invitation, result) = row?;
        let request: Prepare = domain::decode(&request)?;
        let cascade = matches!(target.classification, Classification::Person)
            && matches!(request.classification,Classification::Agent{operator}if operator==target.identity.account);
        if request.claim_id == claim || cascade {
            affected.push((request, domain::decode::<Invitation>(&invitation)?, result));
        }
    }
    if affected.len() > 1024 {
        return invalid("AdmissionRetirementCapacity");
    }
    let affected_claim_ids = affected
        .iter()
        .map(|(r, _, _)| r.claim_id)
        .collect::<Vec<_>>();
    let mut target_account = None;
    for (request, invitation, result) in &affected {
        let account = if let Some(result) = result {
            let original: Response = domain::decode(result)?;
            if !matches!(original.result,Status::Complete{actor,..}if actor.account==request.identity.account)
            {
                return invalid("AdmissionRetirementBinding");
            }
            retire_account(db, request.identity.account)?;
            Some(request.identity.account)
        } else {
            None
        };
        if request.claim_id == claim {
            target_account = account;
        }
        db.execute(
            "UPDATE hrc_invitations SET used=1 WHERE id=?1",
            [invitation.id.as_hex()],
        )?;
        db.execute(
            "UPDATE hrc_agent_consents SET used=1 WHERE id=?1",
            [request.claim_id.as_hex()],
        )?;
        // A child may have been revoked independently. Its prior tombstone stays exact.
        if request.claim_id != claim && outcome(db, request.claim_id)?.is_none() {
            let response = Response::new(Status::Revoked {
                claim_id: request.claim_id,
                account,
                affected_claim_ids: vec![request.claim_id],
                more_affected: false,
            });
            db.execute(
                "INSERT INTO hrc_admission_retired VALUES(?1,?2,?3)",
                params![
                    request.claim_id.as_hex(),
                    domain::encode(&response)?,
                    request.claim_id.as_bytes().as_slice()
                ],
            )?;
        }
    }
    let response = Response::new(Status::Revoked {
        claim_id: claim,
        account: target_account,
        affected_claim_ids: affected_claim_ids.iter().take(256).copied().collect(),
        more_affected: affected_claim_ids.len() > 256,
    });
    db.execute(
        "INSERT INTO hrc_admission_retired VALUES(?1,?2,?3)",
        params![
            claim.as_hex(),
            domain::encode(&response)?,
            affected_claim_ids
                .iter()
                .flat_map(|id| id.as_bytes().iter().copied())
                .collect::<Vec<_>>()
        ],
    )?;
    Ok(response)
}

pub(super) fn page(db: &Connection, claim: Id, after: Option<Id>) -> Domain<Response> {
    let bytes: Option<Vec<u8>> = db
        .query_row(
            "SELECT affected FROM hrc_admission_retired WHERE claim=?1",
            [claim.as_hex()],
            |r| r.get(0),
        )
        .optional()?;
    let Some(bytes) = bytes else {
        return deny("AdmissionRetirementMissing");
    };
    // Private fixed-width snapshot: shared untrusted CBOR arrays remain limited to256.
    if bytes.is_empty() || bytes.len() > 1024 * 32 || bytes.len() % 32 != 0 {
        return invalid("AdmissionRetirementSnapshot");
    }
    let affected = bytes
        .chunks_exact(32)
        .map(|chunk| {
            let mut id = [0; 32];
            id.copy_from_slice(chunk);
            Id::from_bytes(id)
        })
        .collect::<Vec<_>>();
    if affected.windows(2).any(|p| p[0] >= p[1]) {
        return invalid("AdmissionRetirementSnapshot");
    }
    let start = match after {
        None => 0,
        Some(after) => match affected.binary_search(&after) {
            Ok(i) => i + 1,
            Err(_) => return invalid("AdmissionRetirementCursor"),
        },
    };
    let ids = affected
        .iter()
        .skip(start)
        .take(256)
        .copied()
        .collect::<Vec<_>>();
    let next = if start + ids.len() < affected.len() {
        ids.last().copied()
    } else {
        None
    };
    Ok(Response::new(Status::RetiredClaims {
        claim_id: claim,
        affected_claim_ids: ids,
        next,
    }))
}
