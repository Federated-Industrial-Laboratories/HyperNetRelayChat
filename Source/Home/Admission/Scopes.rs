// SPDX-License-Identifier: Apache-2.0
//! Server-side scope checks cover raw clients, delegated actors and metadata reads.
use super::*;
pub(crate) fn load(db: &Connection, account: AccountId) -> rusqlite::Result<Option<Scope>> {
    let bytes: Option<Vec<u8>> = db
        .query_row(
            "SELECT scope FROM hrc_account_scopes WHERE account=?1",
            [account.to_string()],
            |r| r.get(0),
        )
        .optional()?;
    bytes.map(|b| domain::decode(&b)).transpose()
}
pub(crate) fn room(db: &Connection, account: AccountId, room: RoomId) -> Domain<()> {
    if let Some(scope) = load(db, account)? {
        let p = policy(db)?;
        if scope.paused || scope.revoked || !scope.rooms.contains(&room) || !p.rooms.contains(&room)
        {
            return deny("AdmissionRoomScope");
        }
    }
    Ok(())
}
pub(crate) fn authorize(db: &Connection, action: &protocol::Action) -> Domain<()> {
    let Some(scope) = load(db, action.actor.acting().account)? else {
        return Ok(());
    };
    if scope.paused || scope.revoked {
        return deny("ParticipantPaused");
    }
    if !matches!(
        action.actor,
        Actor::Direct { .. } | Actor::IndependentAgent { .. }
    ) || action.agreement.is_some()
    {
        return deny("BasicParticipantScope");
    }
    let p = policy(db)?;
    if matches!(action.actor, Actor::IndependentAgent { .. }) {
        if !p.agents_enabled {
            return deny("AgentParticipationDisabled");
        }
        if matches!(
            action.operation,
            Operation::MessageSend | Operation::MessageAction
        ) && !scope.allow_initiate
        {
            return deny("AgentInitiationDisabled");
        }
    }
    if let Target::Room(room_id) = action.target {
        room(db, action.actor.acting().account, room_id)?;
    }
    use Operation::*;
    if !matches!(
        action.operation,
        AccountSetNickname
            | PresenceSet
            | AccountInspect
            | AgentList
            | ServiceInspect
            | AgentConsent
            | AgentSetAccess
            | RoomJoin
            | RoomLeave
            | RoomList
            | RoomInspect
            | MessageSend
            | MessageReply
            | MessageAction
            | HistoryPage
            | HistoryContext
            | HistoryTail
            | SearchQuery
            | SearchCancel
            | EventsSubscribe
            | EventsResume
            | UnreadSet
            | OperationResolve
            | ModerationIgnore
            | ModerationMute
            | ModerationFilters
            | ModerationRestrictions
            | AccountRotateRecovery
            | AccountEnrolEndpoint
            | AccountDisableEndpoint
            | AccountDevices
            | AccountContinuity
            | AccountLifecycleOutcome
            | AccountPublicIdentity
            | ClientMetadata
            | CommunitySync
    ) {
        return deny("BasicParticipantScope");
    }
    Ok(())
}
