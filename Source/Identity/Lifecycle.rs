// SPDX-License-Identifier: Apache-2.0
//! Controller authorization and fresh device proof converge at one durable identity boundary.
use super::continuity;
use crate::{
    clock::TimeBounds,
    home::{self, types::*},
    protocol::*,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ApproveEndpoint {
    pub request: Blob,
    pub revision: u64,
    pub head: Id,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DisableEndpoint {
    pub endpoint: Id,
    pub revision: u64,
    pub head: Id,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RotateRecovery {
    pub replacement: Blob,
    pub revision: u64,
    pub head: Id,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ContinuityPage {
    pub after: u64,
    pub limit: u16,
}
fn account(action: &Action) -> Domain<AccountId> {
    if let Target::Account(account) = action.target {
        Ok(account)
    } else {
        invalid("AccountTarget")
    }
}
fn current(state: &IdentitySnapshot, revision: u64, head: Id) -> Domain<()> {
    if state.revision != revision || state.head != Some(head) {
        return conflict("AccountChanged");
    }
    Ok(())
}
pub(crate) fn continuity_page(
    db: &Connection,
    account: AccountId,
    page: &ContinuityPage,
) -> Domain<home::InspectionPage<ContinuityRecord>> {
    if page.limit == 0 || page.limit > 16 || page.after > i64::MAX as u64 {
        return invalid("ContinuityPage");
    }
    let mut items = Vec::new();
    let mut last = None;
    let mut more = false;
    let mut stmt=db.prepare("SELECT number,record FROM identity_records WHERE account=?1 AND number>?2 ORDER BY number LIMIT ?3")?;
    let mut rows = stmt.query(params![
        account.to_string(),
        page.after,
        u32::from(page.limit) + 1
    ])?;
    while let Some(row) = rows.next()? {
        if items.len() >= page.limit as usize {
            more = true;
            break;
        }
        let record: ContinuityRecord = decode(&row.get::<_, Vec<u8>>(1)?)?;
        items.push(record);
        if encode(&items)?.len() > ORDINARY_FRAME_BYTES - 8192 {
            items.pop();
            more = true;
            break;
        }
        last = Some(row.get::<_, u64>(0)?);
    }
    if more && items.is_empty() {
        return Err(Fault::Reject(ErrorCode::Overloaded, "ContinuityRecordSize"));
    }
    Ok(home::InspectionPage {
        items,
        next: if more {
            last.map(|n| n.to_string())
        } else {
            None
        },
    })
}
pub(crate) fn operate(
    db: &Transaction<'_>,
    verified: &VerifiedAction,
    now: TimeBounds,
) -> Domain<Outcome> {
    let action = verified.action();
    let account = account(action)?;
    if account.origin != action.home.network {
        return deny("AccountOrigin");
    }
    continuity::controller(db, &action.actor, account)?;
    if action.operation == Operation::AccountContinuity {
        let page: ContinuityPage = unpack(&action.body)?;
        return Ok(Outcome::Result {
            body: value(&continuity_page(db, account, &page)?)?,
        });
    }
    let state = continuity::snapshot(db, action.home, account)?;
    match action.operation {
        Operation::AccountDevices => {
            empty(&action.body)?;
            Ok(Outcome::Result {
                body: value(&state)?,
            })
        }
        Operation::AccountLifecycleOutcome => {
            let body: home::Resolve = unpack(&action.body)?;
            let saved:Option<(Vec<u8>,Vec<u8>,Vec<u8>)>=db.query_row("SELECT digest,action,outcome FROM hrc_operations WHERE window=?1 AND operation=?2",params![body.operation_id.window.as_hex(),body.operation_id.operation.as_hex()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
            let outcome = if let Some((hash, action_bytes, result)) = saved {
                if hash != body.action_digest.as_bytes() {
                    return conflict("OperationContent");
                }
                let raw = canonical_decode(&action_bytes, ORDINARY_FRAME_BYTES)
                    .map_err(|_| Fault::Sql(rusqlite::Error::InvalidQuery))?;
                let Value::Array(fields) = raw else {
                    return Err(Fault::Sql(rusqlite::Error::InvalidQuery));
                };
                let original: Action = fields
                    .get(2)
                    .ok_or(Fault::Sql(rusqlite::Error::InvalidQuery))?
                    .deserialized()
                    .map_err(|_| Fault::Sql(rusqlite::Error::InvalidQuery))?;
                if original.target != Target::Account(account)
                    || !matches!(
                        original.operation,
                        Operation::AccountEnrolEndpoint
                            | Operation::AccountDisableEndpoint
                            | Operation::AccountRotateRecovery
                    )
                {
                    return deny("LifecycleOutcome");
                }
                decode(&result)?
            } else {
                Outcome::Unknown
            };
            Ok(Outcome::Result {
                body: value(&home::ResolveResult {
                    operation_id: body.operation_id,
                    action_digest: body.action_digest,
                    outcome,
                })?,
            })
        }
        Operation::AccountEnrolEndpoint => {
            let body: ApproveEndpoint = unpack(&action.body)?;
            current(&state, body.revision, body.head)?;
            let request = verify_new_device(&body.request.0)
                .map_err(|_| Fault::Reject(ErrorCode::InvalidInput, "DeviceRequest"))?;
            let r = request.value();
            if r.home != action.home
                || r.account != account
                || r.purpose != DevicePurpose::Enrol
                || !now.permits(r.created_ms, r.expires_ms)
            {
                return deny("DeviceRequest");
            }
            let count: u64 = db.query_row(
                "SELECT count(*) FROM identity_tickets WHERE used=0 AND expires>?1",
                [now.lower_ms],
                |r| r.get(0),
            )?;
            if count >= 128 {
                return Err(Fault::Reject(ErrorCode::Overloaded, "DeviceTickets"));
            }
            if db.query_row(
                "SELECT EXISTS(SELECT 1 FROM identity_tickets WHERE request=?1)",
                [r.request.as_hex()],
                |r| r.get::<_, bool>(0),
            )? {
                return conflict("DeviceRequest");
            }
            let total: u64 =
                db.query_row("SELECT count(*) FROM identity_tickets", [], |r| r.get(0))?;
            if total >= 10000 {
                return Err(Fault::Reject(ErrorCode::Overloaded, "DeviceTicketQuota"));
            }
            db.execute(
                "INSERT INTO identity_tickets VALUES(?1,?2,?3,?4,?5,?6,0,?7,?8,?9,?10,?11)",
                params![
                    r.request.as_hex(),
                    request.digest().as_bytes(),
                    request.signed_bytes(),
                    encode(action.actor.acting())?,
                    verified.signed_bytes(),
                    r.expires_ms.min(now.lower_ms + 600000),
                    account.to_string(),
                    r.endpoint.as_hex(),
                    action.actor.acting().account.to_string(),
                    action.actor.acting().endpoint.as_hex(),
                    state.security_generation
                ],
            )?;
            home::committed(db, None, value(&r.request)?)
        }
        Operation::AccountDisableEndpoint => {
            let body: DisableEndpoint = unpack(&action.body)?;
            current(&state, body.revision, body.head)?;
            let changed=db.execute("UPDATE hrc_endpoints SET disabled=1 WHERE account=?1 AND endpoint=?2 AND disabled=0",params![account.to_string(),body.endpoint.as_hex()])?;
            if changed != 1 {
                return conflict("EndpointUnavailable");
            }
            db.execute(
                "DELETE FROM hrc_presence WHERE account=?1 AND endpoint=?2",
                params![account.to_string(), body.endpoint.as_hex()],
            )?;
            db.execute(
                "UPDATE hrc_accounts SET revision=revision+1 WHERE id=?1",
                [account.to_string()],
            )?;
            cancel_tickets(db, account, Some(body.endpoint))?;
            continuity::invalidate(db, account)?;
            let position = continuity::append(
                db,
                action.home,
                account,
                IdentityChange::EndpointDisabled,
                vec![Blob(verified.signed_bytes().to_vec())],
            )?;
            Ok(Outcome::Committed {
                event: None,
                position,
                body: value(&continuity::snapshot(db, action.home, account)?)?,
            })
        }
        Operation::AccountRotateRecovery => {
            let body: RotateRecovery = unpack(&action.body)?;
            current(&state, body.revision, body.head)?;
            rotate(db, action.home, account, &body.replacement)?;
            let position = continuity::append(
                db,
                action.home,
                account,
                IdentityChange::RecoveryRotated,
                vec![Blob(verified.signed_bytes().to_vec())],
            )?;
            Ok(Outcome::Committed {
                event: None,
                position,
                body: value(&continuity::snapshot(db, action.home, account)?)?,
            })
        }
        _ => invalid("IdentityOperation"),
    }
}
fn rotate(db: &Transaction<'_>, home: ServiceId, account: AccountId, proof: &Blob) -> Domain<()> {
    let replacement = verify_new_recovery_key(&proof.0)
        .map_err(|_| Fault::Reject(ErrorCode::InvalidInput, "RecoveryKeyProof"))?;
    let p = replacement.value();
    if p.home != home || p.account != account {
        return deny("RecoveryKeyBinding");
    }
    if db.query_row(
        "SELECT recovery=?1 FROM hrc_accounts WHERE id=?2",
        params![p.key.as_bytes(), account.to_string()],
        |r| r.get::<_, bool>(0),
    )? {
        return conflict("RecoveryKeyUnchanged");
    }
    if db.query_row(
        "SELECT EXISTS(SELECT 1 FROM hrc_endpoints WHERE account=?1 AND key=?2)",
        params![account.to_string(), p.key.as_bytes()],
        |r| r.get::<_, bool>(0),
    )? {
        return deny("RecoveryKeySeparation");
    }
    db.execute(
        "UPDATE hrc_accounts SET recovery=?1,revision=revision+1 WHERE id=?2",
        params![p.key.as_bytes(), account.to_string()],
    )?;
    db.execute(
        "UPDATE identity_accounts SET recovery_generation=recovery_generation+1 WHERE account=?1",
        [account.to_string()],
    )?;
    Ok(())
}
fn cancel_tickets(
    db: &Transaction<'_>,
    account: AccountId,
    endpoint: Option<Id>,
) -> rusqlite::Result<()> {
    db.execute("UPDATE identity_tickets SET used=1 WHERE (account=?1 AND (?2 IS NULL OR endpoint=?2)) OR (controller_account=?1 AND (?2 IS NULL OR controller_endpoint=?2))",params![account.to_string(),endpoint.map(|e|e.as_hex())])?;
    Ok(())
}
fn ticket(db: &Connection, request: &Verified<DeviceRequest>, now: TimeBounds) -> Domain<Vec<u8>> {
    struct Ticket {
        hash: Vec<u8>,
        actor: Vec<u8>,
        authorization: Vec<u8>,
        expires: u64,
        used: bool,
    }
    let row = db.query_row(
        "SELECT digest,controller,authorization,expires,used FROM identity_tickets WHERE request=?1",
        [request.value().request.as_hex()],
        |r| Ok(Ticket { hash: r.get(0)?, actor: r.get(1)?, authorization: r.get(2)?, expires: r.get(3)?, used: r.get(4)? }),
    ).optional()?;
    let Some(Ticket {
        hash,
        actor,
        authorization,
        expires,
        used,
    }) = row
    else {
        return deny("DeviceTicket");
    };
    if used || hash != request.digest().as_bytes() || now.upper_ms >= expires {
        return deny("DeviceTicket");
    }
    if !db.query_row("SELECT t.target_generation=a.security FROM identity_tickets t JOIN hrc_accounts a ON a.id=t.account WHERE t.request=?1",[request.value().request.as_hex()],|r|r.get::<_,bool>(0))?{return deny("DeviceTicketGeneration")}
    let actor: EndpointActor = decode(&actor)?;
    let Some(current) = super::endpoint(db, actor.account, actor.endpoint)? else {
        return deny("DeviceController");
    };
    if current.acting != actor {
        return deny("DeviceController");
    }
    continuity::controller(
        db,
        &Actor::Direct { acting: actor },
        request.value().account,
    )?;
    if current.classification != AccountClass::Human {
        return deny("DeviceController");
    }
    Ok(authorization)
}
pub(crate) fn eligibility(
    db: &Connection,
    request: &Verified<DeviceRequest>,
    now: TimeBounds,
) -> Domain<(IdentitySnapshot, Option<DeviceReceipt>)> {
    let r = request.value();
    if request.signer_key() != r.endpoint_key {
        return deny("DeviceKeyBinding");
    }
    if !now.permits(r.created_ms, r.expires_ms) {
        return Err(Fault::Reject(ErrorCode::Expired, "DeviceRequestExpired"));
    }
    let state = continuity::snapshot(db, r.home, r.account)?;
    let saved: Option<(Vec<u8>, Vec<u8>)> = db
        .query_row(
            "SELECT digest,receipt FROM identity_receipts WHERE request=?1",
            [r.request.as_hex()],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()?;
    if let Some((hash, receipt)) = saved {
        if hash != request.digest().as_bytes() {
            return conflict("DeviceRequest");
        }
        let receipt: DeviceReceipt = decode(&receipt)?;
        if matches!(receipt.outcome, Outcome::Committed { .. })
            && r.purpose != DevicePurpose::RotateRecovery
            && !state.endpoints.iter().any(|e| {
                e.actor.endpoint == r.endpoint
                    && e.key == r.endpoint_key
                    && e.principal == r.principal
            })
        {
            return deny("EndpointDisabled");
        }
        return Ok((state, Some(receipt)));
    }
    if r.purpose == DevicePurpose::Enrol {
        ticket(db, request, now)?;
    }
    if db.query_row(
        "SELECT EXISTS(SELECT 1 FROM hrc_endpoints WHERE account=?1 AND endpoint=?2)",
        params![r.account.to_string(), r.endpoint.as_hex()],
        |r| r.get::<_, bool>(0),
    )? {
        return conflict("EndpointIdentity");
    }
    Ok((state, None))
}
pub(crate) fn activate(
    db: &Transaction<'_>,
    request: &Verified<DeviceRequest>,
    challenge: &Verified<DeviceChallenge>,
    proofs: &DeviceProofs,
    now: TimeBounds,
) -> Domain<DeviceReceipt> {
    let r = request.value();
    let c = challenge.value();
    let (state, saved) = eligibility(db, request, now)?;
    let key = VerifyingKey::from_bytes(r.endpoint_key.as_bytes())
        .map_err(|_| Fault::Reject(ErrorCode::InvalidInput, "DeviceKey"))?;
    let endpoint = verify_device_proof(&proofs.endpoint.0, &key)
        .map_err(|_| Fault::Reject(ErrorCode::Denied, "DeviceProof"))?;
    let expected = DeviceProof {
        home: r.home,
        account: r.account,
        request: r.request,
        request_digest: request.digest(),
        challenge_digest: challenge.digest(),
    };
    if endpoint.value() != &expected
        || c.home != r.home
        || c.account != r.account
        || c.request_digest != request.digest()
        || c.request != r.request
        || c.principal != r.principal
        || now.upper_ms >= c.expires_ms
        || state.security_generation != c.security_generation
        || state.revision != c.account_revision
        || state.head != Some(c.continuity_head)
        || state.recovery_generation != c.recovery_generation
        || state.recovery_key != c.recovery_key
    {
        return deny("DeviceChallenge");
    }
    if let Some(receipt) = saved {
        if !c.recorded {
            return conflict("DeviceOutcomeChanged");
        }
        return Ok(receipt);
    }
    if c.recorded {
        return conflict("DeviceOutcomeChanged");
    }
    let mut authorization = vec![
        Blob(request.signed_bytes().to_vec()),
        Blob(challenge.signed_bytes().to_vec()),
        Blob(encode(proofs)?),
    ];
    if r.purpose == DevicePurpose::Enrol {
        if proofs.recovery.is_some() {
            return invalid("UnexpectedRecoveryProof");
        }
        authorization.push(Blob(ticket(db, request, now)?));
    } else {
        let recovery = proofs
            .recovery
            .as_ref()
            .ok_or(Fault::Reject(ErrorCode::Denied, "RecoveryProof"))?;
        let key = VerifyingKey::from_bytes(state.recovery_key.as_bytes())
            .map_err(|_| Fault::Sql(rusqlite::Error::InvalidQuery))?;
        let proof = verify_device_proof(&recovery.0, &key)
            .map_err(|_| Fault::Reject(ErrorCode::Denied, "RecoveryProof"))?;
        if proof.value() != &expected {
            return deny("RecoveryProof");
        }
    }
    let receipts: u64 = db.query_row("SELECT count(*) FROM identity_receipts", [], |r| r.get(0))?;
    if receipts >= 10000 {
        return Err(Fault::Reject(ErrorCode::Overloaded, "DeviceReceiptQuota"));
    }
    let endpoint = if r.purpose == DevicePurpose::RotateRecovery {
        rotate(
            db,
            r.home,
            r.account,
            r.replacement
                .as_ref()
                .ok_or(Fault::Reject(ErrorCode::InvalidInput, "RecoveryKeyProof"))?,
        )?;
        None
    } else {
        if r.endpoint_key == state.recovery_key {
            return deny("RecoveryKeySeparation");
        }
        if r.purpose == DevicePurpose::Recover {
            db.execute(
                "UPDATE hrc_accounts SET security=security+1 WHERE id=?1",
                [r.account.to_string()],
            )?;
            db.execute(
                "UPDATE hrc_endpoints SET disabled=1 WHERE account=?1",
                [r.account.to_string()],
            )?;
            db.execute(
                "DELETE FROM hrc_presence WHERE account=?1",
                [r.account.to_string()],
            )?;
            cancel_tickets(db, r.account, None)?;
            continuity::invalidate(db, r.account)?;
        } else if state.endpoints.len() >= 8 {
            return Err(Fault::Reject(ErrorCode::Overloaded, "EndpointQuota"));
        }
        let security = state.security_generation + u64::from(r.purpose == DevicePurpose::Recover);
        let binding = EndpointBinding {
            origin: r.home,
            account: r.account,
            endpoint: r.endpoint,
            endpoint_key: r.endpoint_key,
            transport_principal: r.principal,
            security_generation: security,
            enrolment_generation: 1,
            not_before_ms: now.lower_ms,
            expires_ms: u64::MAX,
        };
        db.execute(
            "INSERT INTO federation_bindings VALUES(?1,?2,?3)",
            params![
                r.account.to_string(),
                r.endpoint.as_hex(),
                encode(&binding)?
            ],
        )?;
        // Binding digest is the canonical role payload, independent of the service signature bytes.
        let digest =
            binding_digest(&binding).map_err(|_| Fault::Sql(rusqlite::Error::InvalidQuery))?;
        let actor = EndpointActor {
            account: r.account,
            endpoint: r.endpoint,
            security_generation: security,
            enrolment_generation: 1,
            binding_digest: digest,
        };
        db.execute(
            "INSERT INTO hrc_endpoints VALUES(?1,?2,?3,?4,?5,0)",
            params![
                r.account.to_string(),
                r.endpoint.as_hex(),
                encode(&actor)?,
                r.endpoint_key.as_bytes(),
                r.principal.as_hex()
            ],
        )?;
        db.execute(
            "UPDATE hrc_accounts SET revision=revision+1 WHERE id=?1",
            [r.account.to_string()],
        )?;
        db.execute(
            "UPDATE identity_tickets SET used=1 WHERE request=?1",
            [r.request.as_hex()],
        )?;
        Some(actor)
    };
    let change = match r.purpose {
        DevicePurpose::Enrol => IdentityChange::EndpointEnrolled,
        DevicePurpose::Recover => IdentityChange::Recovered,
        DevicePurpose::RotateRecovery => IdentityChange::RecoveryRotated,
    };
    let position = continuity::append(db, r.home, r.account, change, authorization)?;
    let receipt = DeviceReceipt {
        home: r.home,
        account: r.account,
        request: r.request,
        request_digest: request.digest(),
        outcome: Outcome::Committed {
            event: None,
            position,
            body: value(&DeviceActivated {
                identity: continuity::snapshot(db, r.home, r.account)?,
                endpoint,
            })?,
        },
    };
    db.execute(
        "INSERT INTO identity_receipts VALUES(?1,?2,?3,?4,?5,?6)",
        params![
            r.request.as_hex(),
            request.digest().as_bytes(),
            r.account.to_string(),
            r.endpoint.as_hex(),
            encode(&receipt)?,
            r.expires_ms
        ],
    )?;
    Ok(receipt)
}
