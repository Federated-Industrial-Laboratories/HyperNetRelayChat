// SPDX-License-Identifier: Apache-2.0
//! One retained claim binds the invitation, signed registration and initial membership.
use super::*;
type PendingClaim = (Vec<u8>, Vec<u8>, Option<Vec<u8>>);
type StoredClaim = (Vec<u8>, Vec<u8>, Option<Vec<u8>>, Option<Vec<u8>>);

fn prepared(claim: Id, request: &[u8], invitation: Invitation) -> Response {
    Response::new(Status::Prepared {
        claim_id: claim,
        request_digest: protocol::digest(request),
        invitation,
    })
}
pub(super) fn handle(
    db: &Transaction<'_>,
    home: ServiceId,
    signer: &SigningKey,
    p: &Policy,
    request: &Request,
    time: TimeBounds,
) -> Domain<Response> {
    match &request.action {
        Action::Describe => Ok(Response::new(Status::Described {
            home,
            service_key: Id::from_bytes(signer.verifying_key().to_bytes()),
            policy: p.clone(),
        })),
        Action::Prepare(candidate) => prepare(db, home, signer, p, candidate, time),
        Action::Enrol {
            claim_id,
            registration,
        } => enrol(db, home, signer, p, *claim_id, registration, time),
        Action::Status { claim_id } => {
            let saved: Option<PendingClaim> = db
                .query_row(
                    "SELECT request,invitation,result FROM hrc_admission_claims WHERE id=?1",
                    [claim_id.as_hex()],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
                )
                .optional()?;
            match saved {
                Some((_, _, Some(result))) => Ok(domain::decode(&result)?),
                Some((request, invitation, None)) => {
                    Ok(prepared(*claim_id, &request, domain::decode(&invitation)?))
                }
                None => deny("AdmissionClaimMissing"),
            }
        }
    }
}
fn prepare(
    db: &Transaction<'_>,
    home: ServiceId,
    signer: &SigningKey,
    p: &Policy,
    candidate: &Prepare,
    time: TimeBounds,
) -> Domain<Response> {
    let bytes = domain::encode(candidate)?;
    let old: Option<(Vec<u8>, Vec<u8>)> = db
        .query_row(
            "SELECT request,invitation FROM hrc_admission_claims WHERE id=?1",
            [candidate.claim_id.as_hex()],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    if let Some((request, invitation)) = old {
        if request != bytes {
            return conflict("AdmissionClaimContent");
        }
        return Ok(prepared(
            candidate.claim_id,
            &bytes,
            domain::decode(&invitation)?,
        ));
    }
    validate_prepare(db, home, p, candidate)?;
    if let Classification::Agent { .. } = candidate.classification {
        consent::check(db, p, candidate, time, false)?;
    }
    let claims: u64 = db.query_row("SELECT count(*) FROM hrc_admission_claims", [], |r| {
        r.get(0)
    })?;
    let invitations: u64 = db.query_row(
        "SELECT count(*) FROM hrc_invitations WHERE expires>?1",
        [time.lower_ms],
        |r| r.get(0),
    )?;
    if claims >= 1024 || invitations >= 128 {
        return Err(Fault::Reject(ErrorCode::Overloaded, "AdmissionCapacity"));
    }
    let invitation = Invitation {
        home,
        service_key: Id::from_bytes(signer.verifying_key().to_bytes()),
        id: random()?,
        principal: candidate.native_principal,
        classification: candidate.classification.account_class(),
        expires_ms: time.lower_ms + 15 * 60 * 1000,
    };
    db.execute(
        "INSERT INTO hrc_invitations(id,principal,class,expires) VALUES(?1,?2,?3,?4)",
        params![
            invitation.id.as_hex(),
            invitation.principal.as_hex(),
            domain::encode(&invitation.classification)?,
            invitation.expires_ms
        ],
    )?;
    db.execute(
        "INSERT INTO hrc_admission_claims VALUES(?1,?2,?3,NULL,NULL,?4)",
        params![
            candidate.claim_id.as_hex(),
            bytes,
            domain::encode(&invitation)?,
            invitation.expires_ms
        ],
    )?;
    Ok(prepared(candidate.claim_id, &bytes, invitation))
}
fn enrol(
    db: &Transaction<'_>,
    home: ServiceId,
    signer: &SigningKey,
    p: &Policy,
    claim: Id,
    artifact: &Artifact,
    time: TimeBounds,
) -> Domain<Response> {
    let bytes = artifact
        .bytes()
        .map_err(|_| Fault::Reject(ErrorCode::InvalidInput, "RegistrationEncoding"))?;
    let registration = verify_registration_request(&bytes)
        .map_err(|_| Fault::Reject(ErrorCode::Denied, "RegistrationSignature"))?;
    let saved: Option<StoredClaim> = db
        .query_row(
            "SELECT request,invitation,registration,result FROM hrc_admission_claims WHERE id=?1",
            [claim.as_hex()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
        )
        .optional()?;
    let Some((request, invitation, old, result)) = saved else {
        return deny("AdmissionClaimMissing");
    };
    if let Some(old) = old {
        if old != bytes {
            return conflict("RegistrationRetryBinding");
        }
        return Ok(domain::decode(
            &result.ok_or(rusqlite::Error::InvalidQuery)?,
        )?);
    }
    let candidate: Prepare = domain::decode(&request)?;
    let invitation: Invitation = domain::decode(&invitation)?;
    if candidate.registration(home, invitation.id) != *registration.value() {
        return deny("RegistrationBinding");
    }
    validate_prepare(db, home, p, &candidate)?;
    if let Classification::Agent { .. } = candidate.classification {
        consent::check(db, p, &candidate, time, true)?;
    }
    for room in &candidate.rooms {
        let count: u64 = db.query_row(
            "SELECT count(*) FROM hrc_members WHERE room=?1 AND active=1",
            [room.to_string()],
            |r| r.get(0),
        )?;
        if count >= 32 {
            return Err(Fault::Reject(ErrorCode::Overloaded, "MemberLimit"));
        }
    }
    let endpoint = crate::identity::register_in(db, home, signer, &registration, time)?
        .map_err(|reason| Fault::Reject(ErrorCode::Denied, reason))?;
    let operator = match candidate.classification {
        Classification::Agent { operator } => Some(operator),
        _ => None,
    };
    let scope = Scope {
        rooms: candidate.rooms.clone(),
        allow_initiate: candidate.allow_initiate,
        paused: false,
        revoked: false,
        successor_of: operator.filter(|_| candidate.successor),
    };
    db.execute(
        "INSERT INTO hrc_account_scopes VALUES(?1,?2,?3,?4)",
        params![
            candidate.identity.account.to_string(),
            operator.map(|a| a.to_string()),
            domain::encode(&scope)?,
            domain::encode(&scope)?
        ],
    )?;
    for room in &candidate.rooms {
        db.execute(
            "INSERT INTO hrc_members VALUES(?1,?2,1,1,?3,0)",
            params![
                room.to_string(),
                candidate.identity.account.to_string(),
                time.lower_ms
            ],
        )?;
        db.execute(
            "UPDATE hrc_rooms SET revision=revision+1 WHERE id=?1",
            [room.to_string()],
        )?;
    }
    let final_time = time
        .refresh()
        .map_err(|_| Fault::Reject(ErrorCode::Unavailable, "AdmissionClock"))?;
    if final_time.upper_ms >= invitation.expires_ms {
        return deny("AdmissionExpiredAtCommit");
    }
    if operator.is_some() {
        let expires: u64 = db.query_row(
            "SELECT expires FROM hrc_agent_consents WHERE id=?1",
            [claim.as_hex()],
            |r| r.get(0),
        )?;
        if final_time.upper_ms >= expires {
            return deny("ConsentExpiredAtCommit");
        }
    }
    let response = Response::new(Status::Complete {
        claim_id: claim,
        registration_digest: registration.digest(),
        actor: endpoint.acting,
    });
    db.execute(
        "UPDATE hrc_admission_claims SET registration=?1,result=?2 WHERE id=?3",
        params![bytes, domain::encode(&response)?, claim.as_hex()],
    )?;
    Ok(response)
}
