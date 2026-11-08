// SPDX-License-Identifier: Apache-2.0
//! An operation receives one immutable durable outcome or an explicit pre-admission refusal.
use super::types::{Error, Result};
use super::{Home, budgets, retention, types::*};
use crate::{
    clock::TimeBounds,
    protocol::*,
    storage::{self, Commit},
};
use rusqlite::{Connection, OptionalExtension, Transaction, params};
use serde::{Deserialize, Serialize};
use std::cell::Cell;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Resolve {
    pub operation_id: OperationId,
    pub action_digest: Id,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ResolveResult {
    pub operation_id: OperationId,
    pub action_digest: Id,
    pub outcome: Outcome,
}
struct RetainedOperation {
    digest: Vec<u8>,
    action: Vec<u8>,
    outcome: Vec<u8>,
    read_only: bool,
}

pub fn read_operation(op: Operation) -> bool {
    matches!(
        op,
        Operation::ClientMetadata
            | Operation::CommunitySync
            | Operation::RoomList
            | Operation::ServiceInspect
            | Operation::RoomInspect
            | Operation::AccountInspect
            | Operation::AgentList
            | Operation::AccountDevices
            | Operation::AccountContinuity
            | Operation::AccountLifecycleOutcome
            | Operation::AccountPublicIdentity
            | Operation::CryptoInspect
            | Operation::CryptoWelcome
            | Operation::CryptoHistory
            | Operation::CryptoTail
            | Operation::DelegationList
            | Operation::ModerationFilters
            | Operation::ModerationRestrictions
            | Operation::HistoryPage
            | Operation::HistoryTail
            | Operation::HistoryContext
            | Operation::SearchQuery
            | Operation::SearchCancel
            | Operation::EventsSubscribe
            | Operation::EventsResume
            | Operation::OperationResolve
            | Operation::DelegationInspect
    )
}
pub(crate) fn check_revision(action: &Action, kind: Revision, current: u64) -> Domain<()> {
    if action
        .expected
        .get(&kind)
        .is_some_and(|expected| *expected != current)
    {
        return conflict("ExpectedRevision");
    }
    Ok(())
}
pub(crate) fn next_position(db: &Connection) -> rusqlite::Result<u64> {
    if db.execute("UPDATE hrc_meta SET position=position+1 WHERE singleton=1 AND position<9223372036854775807",[])?!=1{return Err(rusqlite::Error::InvalidQuery);}
    db.query_row("SELECT position FROM hrc_meta WHERE singleton=1", [], |r| {
        r.get(0)
    })
}
pub(crate) fn committed(db: &Transaction<'_>, event: Option<Id>, body: Value) -> Domain<Outcome> {
    Ok(Outcome::Committed {
        event,
        position: next_position(db)?,
        body,
    })
}
fn refusal(code: ErrorCode, detail: &str) -> Outcome {
    Outcome::Refused {
        code,
        detail: detail.into(),
        retry_after_ms: matches!(code, ErrorCode::RateLimited | ErrorCode::Overloaded)
            .then_some(1000),
    }
}
fn checked_clock(
    db: &Connection,
    clock: TimeBounds,
) -> std::result::Result<TimeBounds, &'static str> {
    let now = clock.refresh().map_err(|_| "ClockUnavailable")?;
    let floor: u64 = db
        .query_row(
            "SELECT clock_floor FROM hrc_meta WHERE singleton=1",
            [],
            |r| r.get(0),
        )
        .map_err(|_| "ClockState")?;
    now.after_floor(floor).map_err(|_| "ClockRollback")?;
    Ok(now)
}
fn window(db: &Connection, id: Id, actor: &EndpointActor) -> rusqlite::Result<Option<u64>> {
    db.query_row(
        "SELECT expires FROM hrc_windows WHERE id=?1 AND account=?2 AND endpoint=?3",
        params![
            id.as_hex(),
            actor.account.to_string(),
            actor.endpoint.as_hex()
        ],
        |r| r.get(0),
    )
    .optional()
}
fn expected(db: &Connection, action: &Action) -> Domain<()> {
    for (kind, wanted) in &action.expected {
        let current = match kind {
            Revision::Account => db.query_row(
                "SELECT revision FROM hrc_accounts WHERE id=?1",
                [action.actor.acting().account.to_string()],
                |r| r.get::<_, u64>(0),
            )?,
            Revision::Filter => db.query_row(
                "SELECT filter_revision FROM hrc_accounts WHERE id=?1",
                [action.actor.represented().to_string()],
                |r| r.get(0),
            )?,
            Revision::Room => {
                let room = crate::conversations::target(action)?;
                db.query_row(
                    "SELECT revision FROM hrc_rooms WHERE id=?1",
                    [room.to_string()],
                    |r| r.get(0),
                )
                .optional()?
                .ok_or(Fault::Reject(ErrorCode::Denied, "RoomUnavailable"))?
            }
            Revision::Grant => {
                let reference = match action.target {
                    Target::Delegation(r) => r,
                    _ => match action.actor {
                        Actor::Delegated { grant, .. } => grant,
                        _ => return invalid("GrantRevisionTarget"),
                    },
                };
                crate::delegation::load(db, reference.id)?
                    .reference
                    .generation
            }
            Revision::Agreement => {
                let reference = action
                    .agreement
                    .ok_or(Fault::Reject(ErrorCode::InvalidInput, "AgreementRevision"))?;
                if *wanted != reference.revision {
                    return conflict("AgreementRevision");
                }
                reference.revision
            }
            Revision::Epoch => {
                return Err(Fault::Reject(
                    ErrorCode::UnsupportedFeature,
                    "RevisionFeature",
                ));
            }
        };
        if current != *wanted {
            return conflict("ExpectedRevision");
        }
    }
    Ok(())
}
fn resolve(db: &Connection, action: &Action, now: TimeBounds) -> Domain<Outcome> {
    if action.target != Target::Service {
        return invalid("ServiceTarget");
    }
    let body: Resolve = unpack(&action.body)?;
    let Some(expires) = window(db, body.operation_id.window, action.actor.acting())? else {
        return deny("RetryWindow");
    };
    let saved: Option<(Vec<u8>, Vec<u8>)> = db
        .query_row(
            "SELECT digest,outcome FROM hrc_operations WHERE window=?1 AND operation=?2",
            params![
                body.operation_id.window.as_hex(),
                body.operation_id.operation.as_hex()
            ],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let outcome = match saved {
        Some((digest, bytes)) if digest == body.action_digest.as_bytes() => decode(&bytes)?,
        Some(_) => return conflict("OperationContent"),
        None if now.upper_ms < expires => Outcome::Absent,
        None => Outcome::Unknown,
    };
    if matches!(outcome, Outcome::Result { .. }) {
        return invalid("ResolveReadOperation");
    }
    Ok(Outcome::Result {
        body: value(&ResolveResult {
            operation_id: body.operation_id,
            action_digest: body.action_digest,
            outcome,
        })?,
    })
}
#[allow(clippy::too_many_arguments)]
fn dispatch(
    db: &Transaction<'_>,
    verified: &VerifiedAction,
    now: TimeBounds,
    permit: crate::delegation::Permit,
    signer: &SigningKey,
    cancel: &Cancellation,
    information: &super::ServiceInformation,
    room_creation: &super::RoomCreationPolicy,
    context: ExecutionContext<'_>,
) -> Domain<Outcome> {
    let action = verified.action();
    use Operation::*;
    match action.operation {
        ClientMetadata | CommunitySync => {
            if !matches!(context, ExecutionContext::Local(_)) {
                return deny("LocalViewOnly");
            }
            if action.operation == ClientMetadata {
                super::views::metadata(db, action, now, information, signer)
            } else {
                super::views::community(db, action, now, permit, signer, cancel)
            }
        }
        AccountEnrolEndpoint
        | AccountDisableEndpoint
        | AccountRotateRecovery
        | AccountDevices
        | AccountContinuity
        | AccountLifecycleOutcome => crate::identity::lifecycle::operate(db, verified, now),
        AccountPublicIdentity => crate::identity::public::read(db, action, now),
        CryptoEnrolEndpoint
        | CryptoPublishKeyPackage
        | CryptoPropose
        | CryptoCommit
        | CryptoEpochReady
        | CryptoInspect
        | CryptoWelcome
        | CryptoRecover
        | CryptoReport => crate::confidential::operate(db, verified, now, permit),
        ServiceInspect => {
            if action.target != Target::Service {
                return invalid("ServiceTarget");
            }
            empty(&action.body)?;
            Ok(Outcome::Result {
                body: value(information)?,
            })
        }
        AccountSetNickname | PresenceSet | AccountInspect | AgentList => {
            crate::identity::operate(db, action, now)
        }
        RoomList => match context {
            ExecutionContext::Local(_) => crate::conversations::operate(db, action, now),
            ExecutionContext::Remote(remote) => crate::federation::list_rooms(db, remote, now),
        },
        RoomCreate | DirectCreate if !room_creation.permits(&action.actor) => {
            deny("RoomCreationPolicy")
        }
        RoomCreate | DirectCreate | RoomInvite | RoomJoin | RoomLeave | RoomSetTopic
        | RoomInspect => crate::conversations::operate(db, action, now),
        MessageSend | MessageReply | MessageAction | HistoryPage | HistoryContext | SearchQuery
        | EventsSubscribe | EventsResume | CryptoHistory | HistoryTail | CryptoTail | UnreadSet => {
            crate::messaging::operate(db, action, now, permit, signer, cancel)
        }
        DelegationCreate | DelegationInspect | DelegationList | DelegationPause
        | DelegationResume | DelegationRevoke | ApprovalPrepare | ApprovalApprove
        | ApprovalReject => crate::delegation::operate(db, verified, now),
        ModerationIgnore
        | ModerationMute
        | ModerationSilence
        | ModerationKick
        | ModerationBan
        | ModerationFilters
        | ModerationRestrictions => crate::moderation::operate(db, action, now),
        OperationResolve => resolve(db, action, now),
        SearchCancel => {
            if action.target != Target::Service {
                return invalid("ServiceTarget");
            }
            let _: Resolve = unpack(&action.body)?;
            if !cancel.control_registered() {
                return conflict("NoActiveSearch");
            }
            Ok(Outcome::Result {
                body: value(&true)?,
            })
        }
        _ => Err(Fault::Reject(
            ErrorCode::UnsupportedFeature,
            "OperationFeature",
        )),
    }
}
impl Home {
    pub(crate) fn budget_screen_candidate(action: &Action) -> bool {
        action.agreement.is_none()
            && !matches!(action.actor, Actor::Delegated { .. })
            && action.approval.is_none()
            && matches!(
                action.operation,
                Operation::MessageSend
                    | Operation::MessageReply
                    | Operation::MessageAction
                    | Operation::SearchQuery
            )
    }
    /// A queue owner is a verified binding, never an operation permission or reservation.
    pub(crate) fn admission_owner(
        &mut self,
        verified: &VerifiedAction,
        session: &AuthenticatedSession,
        clock: TimeBounds,
        timeout: std::time::Duration,
    ) -> Option<AccountId> {
        if verified.action().home != self.home
            || !matches!(verified.action().actor, Actor::Delegated { .. })
        {
            return None;
        }
        self.store
            .read(timeout, |db| {
                let Some(now) = checked_clock(db, clock).ok() else {
                    return Ok(None);
                };
                if crate::identity::authenticate_source(db, verified, session).is_err() {
                    return Ok(None);
                }
                Ok(
                    crate::delegation::current_grant(db, &verified.action().actor, self.home, now)
                        .ok()
                        .flatten()
                        .map(|grant| grant.owner),
                )
            })
            .ok()
            .flatten()
    }
    /// Reject demonstrably exhausted local work without granting permission or charging it.
    pub(crate) fn budget_exhausted(
        &mut self,
        verified: &VerifiedAction,
        session: &AuthenticatedSession,
        clock: TimeBounds,
        timeout: std::time::Duration,
    ) -> bool {
        let action = verified.action();
        if action.home != self.home
            || action.actor.acting().account.origin != self.home.network
            || !Self::budget_screen_candidate(action)
        {
            return false;
        }
        self.store
            .read(timeout, |db| {
                let Some(now) = checked_clock(db, clock).ok() else {
                    return Ok(false);
                };
                if crate::identity::authenticate(db, verified, session).is_err() {
                    return Ok(false);
                }
                let Some(expires) = window(db, action.operation_id.window, action.actor.acting())?
                else {
                    return Ok(false);
                };
                // Even a conflicting or retained read must take the ordinary fresh-check path.
                let retained: bool = db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM hrc_operations WHERE window=?1 AND operation=?2)",
                    params![
                        action.operation_id.window.as_hex(),
                        action.operation_id.operation.as_hex()
                    ],
                    |row| row.get(0),
                )?;
                if retained || now.upper_ms >= expires || expected(db, action).is_err() {
                    return Ok(false);
                }
                let Ok(access) = crate::conversations::access(db, action, now) else {
                    return Ok(false);
                };
                if access.confidentiality != RoomConfidentiality::Community
                    || action.operation != Operation::SearchQuery
                        && !matches!(
                            crate::conversations::restriction(
                                db,
                                access.room,
                                &action.actor,
                                1,
                                now
                            ),
                            Ok(false)
                        )
                {
                    return Ok(false);
                }
                let exhausted = matches!(budgets::exhausted(db, action, now.lower_ms), Ok(true));
                Ok(exhausted && checked_clock(db, clock).is_ok_and(|now| now.upper_ms < expires))
            })
            .unwrap_or(false)
    }
    pub fn execute(
        &mut self,
        verified: &VerifiedAction,
        session: &AuthenticatedSession,
        clock: TimeBounds,
        permit: &dyn Fn() -> bool,
    ) -> Result<Response> {
        self.execute_cancellable(verified, session, clock, permit, &Cancellation::default())
    }
    pub fn execute_cancellable(
        &mut self,
        verified: &VerifiedAction,
        session: &AuthenticatedSession,
        clock: TimeBounds,
        permit: &dyn Fn() -> bool,
        cancel: &Cancellation,
    ) -> Result<Response> {
        self.execute_context(
            verified,
            ExecutionContext::Local(session),
            clock,
            permit,
            cancel,
        )
    }
    pub fn execute_remote(
        &mut self,
        remote: &crate::federation::VerifiedRemoteSubmission,
        clock: TimeBounds,
        permit: &dyn Fn() -> bool,
    ) -> Result<Response> {
        self.execute_remote_cancellable(remote, clock, permit, &Cancellation::default())
    }
    pub fn execute_remote_cancellable(
        &mut self,
        remote: &crate::federation::VerifiedRemoteSubmission,
        clock: TimeBounds,
        permit: &dyn Fn() -> bool,
        cancel: &Cancellation,
    ) -> Result<Response> {
        self.execute_context(
            remote.action(),
            ExecutionContext::Remote(remote),
            clock,
            permit,
            cancel,
        )
    }
    fn execute_context(
        &mut self,
        verified: &VerifiedAction,
        context: ExecutionContext<'_>,
        clock: TimeBounds,
        permit: &dyn Fn() -> bool,
        cancel: &Cancellation,
    ) -> Result<Response> {
        let action = verified.action();
        let home = self.home;
        let signer = &self.signer;
        let information = &self.information;
        let room_creation = &self.room_creation;
        let response = |outcome| Response {
            home,
            operation_id: action.operation_id,
            action_digest: verified.digest(),
            outcome,
        };
        if action.home != home
            || matches!(context, ExecutionContext::Local(_))
                && (action.agreement.is_some()
                    || action.actor.acting().account.origin != home.network)
        {
            return Ok(response(refusal(ErrorCode::Denied, "HomeBinding")));
        }
        if !permit() || clock.refresh().is_err() {
            return Ok(response(refusal(
                ErrorCode::Unavailable,
                "AuthorityUnavailable",
            )));
        }
        let rollback_reason = Cell::new(None);
        let federation_boot = self.federation_boot;
        let result=self.store.write(|db|{
            let commit=|outcome:Outcome|->rusqlite::Result<Commit<Outcome>>{
                if let ExecutionContext::Remote(remote)=context && !matches!(outcome,Outcome::Refused{..}) {
                    let final_time=clock.refresh().map_err(|_|rusqlite::Error::InvalidQuery)?;
                    if !permit()||cancel.is_cancelled()||crate::federation::final_check(db,remote,federation_boot,final_time).is_err(){rollback_reason.set(Some("FederationAuthorityUnavailable"));return Err(rusqlite::Error::InvalidQuery)}
                    crate::federation::consume_in(db,remote)?;
                }
                let change=encode(&("HRC.Operation",verified.digest(),digest(&encode(&outcome)?)))?;Ok(Commit::new(outcome,change))};
            let now=match checked_clock(db,clock){Ok(now)=>now,Err(reason)=>return commit(refusal(ErrorCode::Unavailable,reason))};
            if !permit()||cancel.is_cancelled(){return commit(refusal(ErrorCode::Unavailable,"AuthorityUnavailable"));}
            crate::federation::expire_in(db,now)?;
            if let Err(error)=context.authenticate(db,verified,federation_boot,now){return match error{Fault::Sql(e)=>Err(e),Fault::Reject(code,detail)=>commit(refusal(code,detail))};}
            let Some(expires)=window(db,action.operation_id.window,action.actor.acting())? else{return commit(refusal(ErrorCode::Denied,"RetryWindow"));};
            let existing:Option<RetainedOperation>=db.query_row("SELECT digest,action,outcome,read_only FROM hrc_operations WHERE window=?1 AND operation=?2",params![action.operation_id.window.as_hex(),action.operation_id.operation.as_hex()],|r|Ok(RetainedOperation{digest:r.get(0)?,action:r.get(1)?,outcome:r.get(2)?,read_only:r.get(3)?})).optional()?;
            let mut repeated_read=false;
            if let Some(RetainedOperation{digest:old_digest,action:old_action,outcome:saved,read_only:read})=existing {
                if old_digest!=verified.digest().as_bytes()||old_action!=verified.bytes(){return commit(Outcome::Rejected{code:ErrorCode::Conflict,detail:"OperationContent".into()});}
                let outcome:Outcome=decode(&saved)?;
                if !read||!matches!(outcome,Outcome::Result{..}){return commit(outcome);}
                repeated_read=true;
            }
            if now.upper_ms>=expires{return commit(Outcome::Unknown);}
            let used:u64=db.query_row("SELECT history_bytes FROM hrc_meta WHERE singleton=1",[],|r|r.get(0))?;
            if used>HISTORY_QUOTA-CRYPTO_FRAME_BYTES as u64&&!read_operation(action.operation){return commit(refusal(ErrorCode::Overloaded,"HistoryQuota"));}
            let admitted=(||->Domain<crate::delegation::Permit>{
                expected(db,action)?;
                if !matches!(action.actor,Actor::Delegated{..})&&action.approval.is_some(){return invalid("UnexpectedApproval");}
                let p=crate::delegation::authorize(db,action,now,verified.digest())?;
                match context { ExecutionContext::Local(_)=>Ok(p), ExecutionContext::Remote(remote)=>crate::federation::constrain(db,remote,p,now) }
            })();
            let mut admitted_permit=None;
            let outcome=match admitted {
                Err(Fault::Sql(e))=>return Err(e),
                Err(Fault::Reject(code,detail))=>Outcome::Rejected{code,detail:detail.into()},
                Ok(grant_permit)=>{
                    admitted_permit=Some(grant_permit);
                    match budgets::admit(db,action,now.lower_ms){Ok(true)=>{},Ok(false)=>return commit(refusal(ErrorCode::RateLimited,"OperationBudget")),Err(e)=>return Err(sql_fault(e))}
                    db.execute_batch("SAVEPOINT hrc_domain_effects")?;
                    match dispatch(db,verified,now,grant_permit,signer,cancel,information,room_creation,context) {
                        Ok(outcome)=>{if let ExecutionContext::Remote(remote)=context {crate::federation::record_creation(db,remote,&outcome).map_err(sql_fault)?;}crate::delegation::consume(db,grant_permit)?;db.execute_batch("RELEASE hrc_domain_effects")?;outcome},
                        Err(Fault::Sql(e))=>return Err(e),
                        Err(Fault::Reject(ErrorCode::Unavailable,"OriginIdentityFreshnessUnavailable"))=>{rollback_reason.set(Some("OriginIdentityFreshnessUnavailable"));return Err(rusqlite::Error::InvalidQuery)},
                        Err(Fault::Reject(code,detail))=>{db.execute_batch("ROLLBACK TO hrc_domain_effects; RELEASE hrc_domain_effects")?;Outcome::Rejected{code,detail:detail.into()}},
                    }
                },
            };
            // Tentative SQL changes stay invisible. The final permit check is the serial authorization point.
            let final_time=match checked_clock(db,clock){Ok(now)=>now,Err(reason)=>{rollback_reason.set(Some(reason));return Err(rusqlite::Error::InvalidQuery);}};
            if !permit()||cancel.is_cancelled()||final_time.upper_ms>=expires {
                rollback_reason.set(Some("AuthorityUnavailable"));return Err(rusqlite::Error::InvalidQuery);
            }
            if admitted_permit.is_some_and(|p|!p.approval_current(final_time)) && !matches!(outcome,Outcome::Rejected{..}) {
                rollback_reason.set(Some("ApprovalExpiredAtCommit"));return Err(rusqlite::Error::InvalidQuery);
            }
            if let Actor::Delegated{grant,..}=action.actor
                && !matches!(outcome,Outcome::Rejected{..}) {
                let current=crate::delegation::load(db,grant.id).map_err(sql_fault)?;
                if !final_time.permits(current.scope.not_before_ms,current.scope.expires_ms){rollback_reason.set(Some("GrantExpiredAtCommit"));return Err(rusqlite::Error::InvalidQuery);}
            }
            if !matches!(outcome,Outcome::Rejected{..}) && !crate::confidential::final_authority(db,action,final_time).map_err(sql_fault)? {
                rollback_reason.set(Some("EncryptedAuthorityChangedAtCommit"));return Err(rusqlite::Error::InvalidQuery);
            }
            let retained=if matches!(outcome,Outcome::Result{..}){Outcome::Result{body:Value::Null}}else{outcome.clone()};
            if !repeated_read {db.execute("INSERT INTO hrc_operations VALUES(?1,?2,?3,?4,?5,?6,?7)",params![action.operation_id.window.as_hex(),action.operation_id.operation.as_hex(),verified.digest().as_bytes(),verified.bytes(),encode(&retained)?,final_time.lower_ms,read_operation(action.operation)])?;}
            db.execute("UPDATE hrc_meta SET clock_floor=?1 WHERE singleton=1",[final_time.lower_ms])?;
            retention::clean(db,final_time.upper_ms)?;
            commit(outcome)
        });
        match result {
            Ok(outcome) => Ok(response(outcome)),
            Err(_) if rollback_reason.get().is_some() => Ok(response(refusal(
                ErrorCode::Unavailable,
                rollback_reason.get().unwrap_or("AuthorityUnavailable"),
            ))),
            Err(storage::Error::Fenced) => Ok(response(Outcome::Unknown)),
            Err(storage::Error::Busy | storage::Error::Quota | storage::Error::Deadline) => {
                Ok(response(refusal(ErrorCode::Overloaded, "StorageCapacity")))
            }
            Err(error) => Err(Error::Storage(error)),
        }
    }
}

#[derive(Clone, Copy)]
enum ExecutionContext<'a> {
    Local(&'a AuthenticatedSession),
    Remote(&'a crate::federation::VerifiedRemoteSubmission),
}
impl ExecutionContext<'_> {
    fn authenticate(
        &self,
        db: &Connection,
        verified: &VerifiedAction,
        boot: Id,
        now: TimeBounds,
    ) -> Domain<()> {
        match self {
            Self::Local(session) => {
                crate::identity::authenticate(db, verified, session).map(|_| ())
            }
            Self::Remote(remote) => crate::federation::authenticate_in(db, remote, boot, now),
        }
    }
}
