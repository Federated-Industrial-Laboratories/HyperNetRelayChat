// SPDX-License-Identifier: Apache-2.0
//! Explicit scope, lifecycle and one-use exact-action approvals.
use crate::{
    clock::TimeBounds,
    home::{self, types::*},
    protocol::*,
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Mode {
    Draft,
    Approve,
    Autonomous,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum State {
    Active,
    Paused,
    Revoked,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Create {
    pub agent: EndpointActor,
    pub rooms: Vec<RoomId>,
    pub recipients: Vec<AccountId>,
    pub operations: Vec<Operation>,
    pub mode: Mode,
    pub not_before_ms: u64,
    pub expires_ms: u64,
    pub history_from_ms: u64,
    pub history_until_ms: u64,
    pub max_operations_per_minute: u16,
    pub purpose: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Grant {
    pub reference: GrantRef,
    pub home: ServiceId,
    pub owner: AccountId,
    pub owner_security_generation: u64,
    pub operator: AccountId,
    pub scope: Create,
    pub state: State,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Prepare {
    pub candidate: Blob,
    pub expires_ms: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Decision {
    pub approval: Id,
    pub action_digest: Id,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Pending {
    pub approval: Id,
    pub action_digest: Id,
    pub candidate: Blob,
    pub expires_ms: u64,
    pub state: u8,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Inspection {
    pub grant: Grant,
    pub pending: Vec<Pending>,
}
#[derive(Clone, Copy, Debug)]
pub(crate) struct Permit {
    pub history_from: u64,
    pub history_until: u64,
    pub consume: Option<Id>,
}
impl Default for Permit {
    fn default() -> Self {
        Self {
            history_from: 0,
            history_until: u64::MAX,
            consume: None,
        }
    }
}
pub(crate) fn load(db: &Connection, id: Id) -> Domain<Grant> {
    let row: Option<(u64, u8, Vec<u8>)> = db
        .query_row(
            "SELECT generation,state,grant_data FROM hrc_grants WHERE id=?1",
            [id.as_hex()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    let Some((generation, state, bytes)) = row else {
        return deny("GrantUnavailable");
    };
    let grant: Grant = decode(&bytes)?;
    if grant.reference.id != id
        || grant.reference.generation != generation
        || state != state_number(grant.state)
    {
        return Err(Fault::Sql(rusqlite::Error::InvalidQuery));
    }
    Ok(grant)
}
fn state_number(state: State) -> u8 {
    match state {
        State::Active => 0,
        State::Paused => 1,
        State::Revoked => 2,
    }
}
pub(crate) fn authorize(
    db: &Transaction<'_>,
    action: &Action,
    now: TimeBounds,
    digest: Id,
) -> Domain<Permit> {
    let Actor::Delegated {
        acting,
        represented,
        represented_security_generation,
        operator,
        grant: reference,
    } = &action.actor
    else {
        return Ok(Permit::default());
    };
    let grant = load(db, reference.id)?;
    if grant.reference.id != reference.id
        || grant.home != action.home
        || grant.owner != *represented
        || grant.owner_security_generation != *represented_security_generation
        || grant.scope.agent != *acting
        || grant.operator != *operator
    {
        return deny("GrantBinding");
    }
    if grant.state != State::Active {
        return deny(if grant.state == State::Paused {
            "GrantPaused"
        } else {
            "GrantRevoked"
        });
    }
    if grant.reference != *reference {
        return conflict("GrantRevision");
    }
    if !now.permits(grant.scope.not_before_ms, grant.scope.expires_ms) {
        return Err(Fault::Reject(ErrorCode::Expired, "GrantValidity"));
    }
    home::check_revision(action, Revision::Grant, grant.reference.generation)?;
    if action.operation == Operation::ApprovalPrepare {
        return Ok(Permit {
            history_from: grant.scope.history_from_ms,
            history_until: grant.scope.history_until_ms,
            consume: None,
        });
    }
    if !grant.scope.operations.contains(&action.operation) {
        return deny("GrantOperation");
    }
    match action.target {
        Target::Room(room) if grant.scope.rooms.contains(&room) => {}
        Target::Account(account) if grant.scope.recipients.contains(&account) => {}
        _ => return deny("GrantTarget"),
    }
    let is_read = home::read_operation(action.operation);
    if grant.scope.mode == Mode::Draft && !is_read {
        return deny("DraftOnly");
    }
    let consume = if grant.scope.mode == Mode::Approve && !is_read {
        let Some(approval) = action.approval else {
            return deny("ApprovalRequired");
        };
        let existing: Option<(String, u64, Vec<u8>, u64, u8)> = db
            .query_row(
                "SELECT grant_id,generation,digest,expires,state FROM hrc_approvals WHERE id=?1",
                [approval.as_hex()],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?)),
            )
            .optional()?;
        let Some((id, generation, expected, expires, 1)) = existing else {
            return deny("ApprovalUnavailable");
        };
        if id != reference.id.as_hex()
            || generation != reference.generation
            || expected != digest.as_bytes()
            || now.upper_ms >= expires
        {
            return deny("ApprovalBinding");
        }
        Some(approval)
    } else {
        if action.approval.is_some() {
            return invalid("UnexpectedApproval");
        }
        None
    };
    Ok(Permit {
        history_from: grant.scope.history_from_ms,
        history_until: grant.scope.history_until_ms,
        consume,
    })
}
pub(crate) fn consume(db: &Transaction<'_>, permit: Permit) -> rusqlite::Result<()> {
    if let Some(id) = permit.consume
        && db.execute(
            "UPDATE hrc_approvals SET state=3 WHERE id=?1 AND state=1",
            [id.as_hex()],
        )? != 1
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(())
}
fn allowed(operation: Operation) -> bool {
    matches!(
        operation,
        Operation::MessageSend
            | Operation::MessageReply
            | Operation::MessageAction
            | Operation::HistoryPage
            | Operation::SearchQuery
            | Operation::EventsSubscribe
            | Operation::EventsResume
            | Operation::UnreadSet
            | Operation::RoomSetTopic
            | Operation::ModerationSilence
            | Operation::ModerationKick
            | Operation::ModerationBan
    )
}
fn owner(action: &Action, grant: &Grant) -> Domain<()> {
    if !matches!(action.actor, Actor::Direct { .. }) || action.actor.acting().account != grant.owner
    {
        return deny("GrantOwner");
    }
    Ok(())
}
fn reference(action: &Action) -> Domain<GrantRef> {
    match action.target {
        Target::Delegation(r) => Ok(r),
        _ => invalid("GrantTarget"),
    }
}
pub(crate) fn operate(db: &Transaction<'_>, action: &Action, now: TimeBounds) -> Domain<Outcome> {
    match action.operation {
        Operation::DelegationCreate => create(db, action, now),
        Operation::ApprovalPrepare => prepare(db, action, now),
        Operation::ApprovalApprove | Operation::ApprovalReject => decide(db, action, now),
        _ => {
            empty(&action.body)?;
            let reference = reference(action)?;
            let mut grant = load(db, reference.id)?;
            if grant.reference != reference {
                return conflict("GrantRevision");
            }
            if action.operation == Operation::DelegationInspect {
                if action.actor.acting().account != grant.owner
                    && action.actor.acting() != &grant.scope.agent
                {
                    return deny("GrantInspection");
                }
                let mut stmt=db.prepare("SELECT id,digest,action,expires,state FROM hrc_approvals WHERE grant_id=?1 AND expires>?2 AND state<2 ORDER BY id LIMIT 2")?;
                let pending = stmt
                    .query_map(params![reference.id.as_hex(), now.lower_ms], |r| {
                        Ok(Pending {
                            approval: id_column(r, 0)?,
                            action_digest: Id::from_bytes(
                                r.get::<_, Vec<u8>>(1)?
                                    .try_into()
                                    .map_err(|_| rusqlite::Error::InvalidQuery)?,
                            ),
                            candidate: Blob(r.get(2)?),
                            expires_ms: r.get(3)?,
                            state: r.get(4)?,
                        })
                    })?
                    .collect::<rusqlite::Result<Vec<_>>>()?;
                return Ok(Outcome::Result {
                    body: value(&Inspection { grant, pending })?,
                });
            }
            owner(action, &grant)?;
            grant.state = match (action.operation, grant.state) {
                (Operation::DelegationPause, State::Active) => State::Paused,
                (Operation::DelegationResume, State::Paused)
                    if now.permits(grant.scope.not_before_ms, grant.scope.expires_ms) =>
                {
                    State::Active
                }
                (Operation::DelegationRevoke, State::Active | State::Paused) => State::Revoked,
                _ => return conflict("GrantTransition"),
            };
            grant.reference.generation = grant
                .reference
                .generation
                .checked_add(1)
                .ok_or(Fault::Reject(ErrorCode::Conflict, "GenerationLimit"))?;
            let encoded = encode(&grant)?;
            let result = value(&grant.reference)?;
            db.execute(
                "UPDATE hrc_grants SET generation=?1,state=?2,grant_data=?3 WHERE id=?4",
                params![
                    grant.reference.generation,
                    state_number(grant.state),
                    encoded,
                    reference.id.as_hex()
                ],
            )?;
            db.execute(
                "UPDATE hrc_approvals SET state=2 WHERE grant_id=?1 AND state<2",
                [reference.id.as_hex()],
            )?;
            home::committed(db, None, result)
        }
    }
}
fn create(db: &Transaction<'_>, action: &Action, now: TimeBounds) -> Domain<Outcome> {
    if !matches!(action.actor, Actor::Direct { .. })
        || action.target != Target::Account(action.actor.acting().account)
    {
        return deny("GrantOwner");
    }
    let scope: Create = unpack(&action.body)?;
    if scope.rooms.len() > 32
        || scope.recipients.len() > 32
        || scope.operations.is_empty()
        || scope.operations.len() > 16
        || scope.purpose.len() > 512
        || scope.purpose.chars().any(char::is_control)
        || scope.max_operations_per_minute == 0
        || scope.max_operations_per_minute > 120
        || scope.not_before_ms > scope.expires_ms
        || scope.expires_ms <= now.upper_ms
        || scope.expires_ms - now.lower_ms > 7 * DAY
        || scope.history_from_ms > scope.history_until_ms
        || scope.operations.iter().any(|o| !allowed(*o))
    {
        return invalid("GrantScope");
    }
    if scope.rooms.iter().any(|r| r.home != action.home)
        || scope
            .recipients
            .iter()
            .any(|a| a.origin != action.home.network)
    {
        return invalid("GrantHome");
    }
    if scope
        .rooms
        .iter()
        .collect::<std::collections::BTreeSet<_>>()
        .len()
        != scope.rooms.len()
        || scope
            .operations
            .iter()
            .map(|o| o.code())
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != scope.operations.len()
    {
        return invalid("GrantDuplicates");
    }
    let Some(agent) = crate::identity::endpoint(db, scope.agent.account, scope.agent.endpoint)?
    else {
        return deny("AgentEndpoint");
    };
    let AccountClass::Agent { operator } = agent.classification else {
        return deny("AgentClassification");
    };
    if agent.acting != scope.agent || operator != action.actor.acting().account {
        return deny("AgentOwner");
    }
    for room in &scope.rooms {
        let mut scoped = action.clone();
        scoped.target = Target::Room(*room);
        crate::conversations::access(db, &scoped, now)?;
    }
    let count: u64 = db.query_row(
        "SELECT count(*) FROM hrc_grants WHERE owner=?1 AND state<2",
        [operator.to_string()],
        |r| r.get(0),
    )?;
    if count >= 64 {
        return Err(Fault::Reject(ErrorCode::Overloaded, "GrantLimit"));
    }
    let grant = Grant {
        reference: GrantRef {
            id: random()?,
            generation: 1,
        },
        home: action.home,
        owner: operator,
        owner_security_generation: action.actor.acting().security_generation,
        operator,
        scope,
        state: State::Active,
    };
    let encoded = encode(&grant)?;
    let result = value(&grant.reference)?;
    db.execute(
        "INSERT INTO hrc_grants VALUES(?1,?2,?3,?4,1,0,?5)",
        params![
            grant.reference.id.as_hex(),
            operator.to_string(),
            grant.scope.agent.account.to_string(),
            grant.scope.agent.endpoint.as_hex(),
            encoded
        ],
    )?;
    home::committed(db, None, result)
}
fn prepare(db: &Transaction<'_>, action: &Action, now: TimeBounds) -> Domain<Outcome> {
    let reference = reference(action)?;
    let grant = load(db, reference.id)?;
    if grant.scope.mode == Mode::Autonomous {
        return deny("GrantApprovalMode");
    }
    let body: Prepare = unpack(&action.body)?;
    if body.candidate.0.len() > 16 * 1024 {
        return invalid("CandidateSize");
    }
    if grant.reference != reference
        || grant.state != State::Active
        || !now.permits(grant.scope.not_before_ms, grant.scope.expires_ms)
    {
        return deny("GrantUnavailable");
    }
    if action.actor.acting() != &grant.scope.agent && action.actor.acting().account != grant.owner {
        return deny("ApprovalPreparer");
    }
    if body.expires_ms <= now.upper_ms
        || body.expires_ms > now.lower_ms + 300_000
        || body.expires_ms > grant.scope.expires_ms
    {
        return invalid("ApprovalValidity");
    }
    let endpoint =
        crate::identity::endpoint(db, grant.scope.agent.account, grant.scope.agent.endpoint)?
            .ok_or(Fault::Reject(ErrorCode::Denied, "AgentEndpoint"))?;
    let verified = verify_action(&body.candidate.0, &endpoint.key)
        .map_err(|_| Fault::Reject(ErrorCode::InvalidInput, "CandidateSignature"))?;
    let candidate = verified.action();
    let Some(approval) = candidate.approval else {
        return invalid("CandidateApproval");
    };
    if candidate.home != action.home
        || candidate.actor.acting() != &grant.scope.agent
        || !matches!(&candidate.actor,Actor::Delegated{grant:r,represented,..} if *r==reference&&*represented==grant.owner)
        || !grant.scope.operations.contains(&candidate.operation)
        || !matches!(candidate.target,Target::Room(r) if grant.scope.rooms.contains(&r))
        || home::read_operation(candidate.operation)
    {
        return deny("CandidateScope");
    }
    crate::conversations::access(db, candidate, now)?;
    let count: u64 = db.query_row(
        "SELECT count(*) FROM hrc_approvals WHERE grant_id=?1 AND state<2 AND expires>?2",
        params![reference.id.as_hex(), now.lower_ms],
        |r| r.get(0),
    )?;
    if count >= 2 {
        return Err(Fault::Reject(ErrorCode::Overloaded, "ApprovalLimit"));
    }
    if db.query_row(
        "SELECT EXISTS(SELECT 1 FROM hrc_approvals WHERE id=?1)",
        [approval.as_hex()],
        |r| r.get::<_, bool>(0),
    )? {
        return conflict("ApprovalExists");
    }
    let result = value(&(approval, verified.digest()))?;
    db.execute(
        "INSERT INTO hrc_approvals VALUES(?1,?2,?3,?4,?5,?6,?7,0)",
        params![
            approval.as_hex(),
            grant.owner.to_string(),
            reference.id.as_hex(),
            reference.generation,
            verified.digest().as_bytes(),
            body.candidate.0,
            body.expires_ms
        ],
    )?;
    home::committed(db, None, result)
}
fn decide(db: &Transaction<'_>, action: &Action, now: TimeBounds) -> Domain<Outcome> {
    let reference = reference(action)?;
    let grant = load(db, reference.id)?;
    owner(action, &grant)?;
    let body: Decision = unpack(&action.body)?;
    if grant.reference != reference
        || grant.state != State::Active
        || !now.permits(grant.scope.not_before_ms, grant.scope.expires_ms)
    {
        return deny("GrantUnavailable");
    }
    if action.operation == Operation::ApprovalApprove && grant.scope.mode != Mode::Approve {
        return deny("GrantApprovalMode");
    }
    let data:Option<(Vec<u8>,u64,u8)>=db.query_row("SELECT digest,expires,state FROM hrc_approvals WHERE id=?1 AND grant_id=?2 AND generation=?3",params![body.approval.as_hex(),reference.id.as_hex(),reference.generation],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
    let Some((digest, expires, 0)) = data else {
        return deny("ApprovalUnavailable");
    };
    if digest != body.action_digest.as_bytes() || now.upper_ms >= expires {
        return deny("ApprovalBinding");
    }
    db.execute(
        "UPDATE hrc_approvals SET state=?1 WHERE id=?2",
        params![
            if action.operation == Operation::ApprovalApprove {
                1
            } else {
                2
            },
            body.approval.as_hex()
        ],
    )?;
    home::committed(db, None, Value::Null)
}
