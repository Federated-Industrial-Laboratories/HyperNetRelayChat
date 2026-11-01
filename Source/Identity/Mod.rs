// SPDX-License-Identifier: Apache-2.0
//! Current account, endpoint and authenticated actor bindings.
use crate::{
    clock::TimeBounds,
    home::{self, types::*},
    protocol::*,
    storage::Commit,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Nickname {
    pub nickname: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Presence {
    pub status: String,
    pub duration_ms: u64,
}

pub(crate) fn endpoint(
    db: &Connection,
    account: AccountId,
    endpoint: Id,
) -> rusqlite::Result<Option<EndpointRecord>> {
    db.query_row("SELECT e.actor,e.key,e.principal,a.class,a.security,a.revision FROM hrc_endpoints e JOIN hrc_accounts a ON a.id=e.account WHERE e.account=?1 AND e.endpoint=?2 AND e.disabled=0",
        params![account.to_string(),endpoint.as_hex()],|r| {
            let acting:EndpointActor=decode(&r.get::<_,Vec<u8>>(0)?)?;
            let key:Vec<u8>=r.get(1)?;
            let key=VerifyingKey::from_bytes(&key.try_into().map_err(|_|rusqlite::Error::InvalidQuery)?).map_err(|_|rusqlite::Error::InvalidQuery)?;
            let security:u64=r.get(4)?;
            if acting.account!=account||acting.endpoint!=endpoint||acting.security_generation!=security||key.is_weak() {return Err(rusqlite::Error::InvalidQuery);}
            Ok(EndpointRecord{acting,key,principal:id_column(r,2)?,classification:decode(&r.get::<_,Vec<u8>>(3)?)?,revision:r.get(5)?})
        }).optional()
}
pub(crate) fn authenticate(
    db: &Connection,
    verified: &VerifiedAction,
    session: &AuthenticatedSession,
) -> Domain<EndpointRecord> {
    let actor = &verified.action().actor;
    let Some(current) = endpoint(db, session.acting.account, session.acting.endpoint)? else {
        return deny("EndpointDisabled");
    };
    if current.acting != session.acting
        || actor.acting() != &current.acting
        || verified.signer_key() != Id::from_bytes(current.key.to_bytes())
        || session.signer != verified.signer_key()
        || session.principal != current.principal
    {
        return deny("EndpointBinding");
    }
    match (&current.classification, actor) {
        (AccountClass::Human, Actor::Direct { .. }) => {}
        (
            AccountClass::Agent { operator: a },
            Actor::IndependentAgent { operator: b, .. } | Actor::Delegated { operator: b, .. },
        ) if a == b => {}
        _ => return deny("ActorClassification"),
    }
    if let Actor::Delegated {
        represented,
        represented_security_generation,
        ..
    } = actor
    {
        let generation: Option<u64> = db
            .query_row(
                "SELECT security FROM hrc_accounts WHERE id=?1",
                [represented.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        if generation != Some(*represented_security_generation) {
            return deny("RepresentedBinding");
        }
    }
    Ok(current)
}
pub(crate) fn register(
    db: &Transaction<'_>,
    home: ServiceId,
    signer: &SigningKey,
    verified: &Verified<AccountRegistration>,
    now: TimeBounds,
) -> rusqlite::Result<Commit<std::result::Result<EndpointRecord, &'static str>>> {
    let r = verified.value();
    let refusal = |reason| {
        Ok(Commit::new(
            Err(reason),
            verified.digest().as_bytes().to_vec(),
        ))
    };
    if r.home != home
        || r.account.origin != home.network
        || verified.signer_key() != r.endpoint_key
        || r.endpoint_key == r.recovery_key
    {
        return refusal("RegistrationBinding");
    }
    let invitation: Option<(String, Vec<u8>, u64, bool)> = db
        .query_row(
            "SELECT principal,class,expires,used FROM hrc_invitations WHERE id=?1",
            [r.invitation.as_hex()],
            |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?)),
        )
        .optional()?;
    let Some((principal, class, expires, used)) = invitation else {
        return refusal("InvitationMissing");
    };
    if used
        || now.upper_ms >= expires
        || principal != r.transport_principal.as_hex()
        || decode::<AccountClass>(&class)? != r.classification
    {
        return refusal("InvitationBinding");
    }
    if db.query_row(
        "SELECT EXISTS(SELECT 1 FROM hrc_accounts WHERE id=?1)",
        [r.account.to_string()],
        |row| row.get::<_, bool>(0),
    )? {
        return refusal("AccountExists");
    }
    if db.query_row("SELECT count(*) FROM hrc_accounts", [], |row| {
        row.get::<_, u64>(0)
    })? >= 256
    {
        return refusal("AccountLimit");
    }
    if let AccountClass::Agent { operator } = r.classification {
        let class: Option<Vec<u8>> = db
            .query_row(
                "SELECT class FROM hrc_accounts WHERE id=?1",
                [operator.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        if class.map(|v| decode::<AccountClass>(&v)).transpose()? != Some(AccountClass::Human) {
            return refusal("OperatorBinding");
        }
    }
    let binding = EndpointBinding {
        origin: home,
        account: r.account,
        endpoint: r.endpoint,
        endpoint_key: r.endpoint_key,
        transport_principal: r.transport_principal,
        security_generation: 1,
        enrolment_generation: 1,
        not_before_ms: now.lower_ms,
        expires_ms: u64::MAX,
    };
    let signed =
        sign_endpoint_binding(&binding, signer).map_err(|_| rusqlite::Error::InvalidQuery)?;
    let verified_binding = verify_endpoint_binding(&signed, &signer.verifying_key())
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let acting = EndpointActor {
        account: r.account,
        endpoint: r.endpoint,
        security_generation: 1,
        enrolment_generation: 1,
        binding_digest: verified_binding.digest(),
    };
    let key = VerifyingKey::from_bytes(r.endpoint_key.as_bytes())
        .map_err(|_| rusqlite::Error::InvalidQuery)?;
    let nickname = format!("account-{}", &r.account.local.as_hex()[..12]);
    db.execute("INSERT INTO hrc_accounts(id,account,class,recovery,security,revision,nickname,lookup) VALUES(?1,?2,?3,?4,1,1,?5,?5)",params![r.account.to_string(),encode(&r.account)?,class,r.recovery_key.as_bytes(),nickname])?;
    db.execute(
        "INSERT INTO hrc_endpoints(account,endpoint,actor,key,principal) VALUES(?1,?2,?3,?4,?5)",
        params![
            r.account.to_string(),
            r.endpoint.as_hex(),
            encode(&acting)?,
            r.endpoint_key.as_bytes(),
            principal
        ],
    )?;
    db.execute(
        "UPDATE hrc_invitations SET used=1 WHERE id=?1",
        [r.invitation.as_hex()],
    )?;
    db.execute(
        "UPDATE hrc_meta SET clock_floor=?1 WHERE singleton=1",
        [now.lower_ms],
    )?;
    Ok(Commit::new(
        Ok(EndpointRecord {
            acting,
            key,
            principal: r.transport_principal,
            classification: r.classification.clone(),
            revision: 1,
        }),
        verified.digest().as_bytes().to_vec(),
    ))
}
pub(crate) fn operate(db: &Transaction<'_>, action: &Action, now: TimeBounds) -> Domain<Outcome> {
    if !matches!(
        action.actor,
        Actor::Direct { .. } | Actor::IndependentAgent { .. }
    ) {
        return deny("AccountController");
    }
    if action.target != Target::Account(action.actor.acting().account) {
        return invalid("AccountTarget");
    }
    match action.operation {
        Operation::AccountSetNickname => {
            let body: Nickname = unpack(&action.body)?;
            crate::text::handle(&body.nickname)
                .map_err(|_| Fault::Reject(ErrorCode::InvalidInput, "Nickname"))?;
            let lookup = crate::text::lookup(&body.nickname, 256)
                .map_err(|_| Fault::Reject(ErrorCode::InvalidInput, "Nickname"))?;
            let revision: u64 = db.query_row(
                "SELECT revision FROM hrc_accounts WHERE id=?1",
                [action.actor.acting().account.to_string()],
                |r| r.get(0),
            )?;
            home::check_revision(action, Revision::Account, revision)?;
            db.execute(
                "UPDATE hrc_accounts SET nickname=?1,lookup=?2,revision=revision+1 WHERE id=?3",
                params![
                    body.nickname,
                    lookup,
                    action.actor.acting().account.to_string()
                ],
            )?;
        }
        Operation::PresenceSet => {
            let body: Presence = unpack(&action.body)?;
            if body.status.len() > 128 || !(1000..=300_000).contains(&body.duration_ms) {
                return invalid("Presence");
            }
            crate::text::message(&body.status)
                .map_err(|_| Fault::Reject(ErrorCode::InvalidInput, "Presence"))?;
            db.execute("INSERT INTO hrc_presence VALUES(?1,?2,?3,?4) ON CONFLICT(account,endpoint) DO UPDATE SET status=excluded.status,expires=excluded.expires",params![action.actor.acting().account.to_string(),action.actor.acting().endpoint.as_hex(),body.status,now.upper_ms+body.duration_ms])?;
        }
        _ => return invalid("IdentityOperation"),
    }
    home::committed(db, None, Value::Null)
}
