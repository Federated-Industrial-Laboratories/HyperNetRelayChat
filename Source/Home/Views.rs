// SPDX-License-Identifier: Apache-2.0
//! Fixed local view reads share one authority observation and guarded transaction.
use super::{InspectPage, InspectionPage, ServiceInformation, types::*};
use crate::{
    clock::TimeBounds, conversations, delegation, identity, messaging, moderation, protocol::*,
};
use rusqlite::Transaction;
use serde::{Deserialize, Serialize, de::DeserializeOwned};

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetadataRequest {
    pub rooms: Option<conversations::List>,
    pub filters: Option<InspectPage>,
    pub grants: Option<InspectPage>,
    pub agents: Option<InspectPage>,
    pub filter_revision: Option<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RoomListPage {
    pub items: Vec<conversations::Summary>,
    pub next: Option<RoomId>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MetadataPage {
    pub account: identity::AccountView,
    pub service: ServiceInformation,
    pub rooms: Option<RoomListPage>,
    pub filters: Option<InspectionPage<moderation::FilterState>>,
    pub grants: Option<InspectionPage<delegation::Grant>>,
    pub agents: Option<InspectionPage<identity::AgentEndpoint>>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommunityRequest {
    pub filters: Option<InspectPage>,
    pub history: Option<messaging::Page>,
    pub restrictions: Option<InspectPage>,
    pub context: Option<Id>,
}
/// Unlike the legacy inspection, this wire type requires an explicit mode.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RoomInspection {
    pub members: Vec<conversations::Member>,
    pub read_sequence: u64,
    pub room_revision: u64,
    pub filter_revision: u64,
    pub moderator: bool,
    pub confidentiality: RoomConfidentiality,
}
impl From<conversations::Inspection> for RoomInspection {
    fn from(v: conversations::Inspection) -> Self {
        Self {
            members: v.members,
            read_sequence: v.read_sequence,
            room_revision: v.room_revision,
            filter_revision: v.filter_revision,
            moderator: v.moderator,
            confidentiality: v.confidentiality,
        }
    }
}
impl From<RoomInspection> for conversations::Inspection {
    fn from(v: RoomInspection) -> Self {
        Self {
            members: v.members,
            read_sequence: v.read_sequence,
            room_revision: v.room_revision,
            filter_revision: v.filter_revision,
            moderator: v.moderator,
            confidentiality: v.confidentiality,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CommunityPage {
    pub inspection: RoomInspection,
    pub context: Id,
    pub filters: Option<InspectionPage<moderation::FilterState>>,
    /// Members occur once, in inspection; this page's members must be empty.
    pub history: Option<messaging::PageResult>,
    pub restrictions: Option<InspectionPage<moderation::RestrictionState>>,
}

/// New view schemas require their complete typed shape, including explicit nulls.
pub(crate) fn decode<T: DeserializeOwned + Serialize>(body: &Value) -> Option<T> {
    let parsed: T = body.deserialized().ok()?;
    let typed = Value::serialized(&parsed).ok()?;
    if canonical_encode(body, ORDINARY_FRAME_BYTES).ok()?
        != canonical_encode(&typed, ORDINARY_FRAME_BYTES).ok()?
    {
        return None;
    }
    Some(parsed)
}

pub(super) fn cost(action: &Action) -> u64 {
    match action.operation {
        Operation::ClientMetadata => unpack::<MetadataRequest>(&action.body).map_or(6, |p| {
            2 + u64::from(p.rooms.is_some())
                + u64::from(p.filters.is_some())
                + u64::from(p.grants.is_some())
                + u64::from(p.agents.is_some())
        }),
        Operation::CommunitySync => unpack::<CommunityRequest>(&action.body).map_or(4, |p| {
            1 + u64::from(p.filters.is_some())
                + u64::from(p.history.is_some())
                + u64::from(p.restrictions.is_some())
        }),
        _ => 1,
    }
}
fn part<T: Serialize>(
    outer: &Action,
    operation: Operation,
    target: Target,
    body: &T,
) -> Domain<Action> {
    let mut action = outer.clone();
    action.operation = operation;
    action.target = target;
    action.body = value(body)?;
    Ok(action)
}
fn result<T: DeserializeOwned>(outcome: Outcome) -> Domain<T> {
    match outcome {
        Outcome::Result { body } => unpack(&body),
        _ => invalid("ViewResult"),
    }
}
fn bounded<T: Serialize>(item: &T, action: &Action, signer: &SigningKey) -> Domain<Outcome> {
    let outcome = Outcome::Result { body: value(item)? };
    let response = Response {
        home: action.home,
        operation_id: action.operation_id,
        action_digest: action_digest(action)
            .map_err(|_| Fault::Reject(ErrorCode::InvalidInput, "ViewAction"))?,
        outcome: outcome.clone(),
    };
    sign_response(&response, signer)
        .map_err(|_| Fault::Reject(ErrorCode::Overloaded, "ViewRepresentation"))?;
    Ok(outcome)
}
pub(super) fn metadata(
    db: &Transaction<'_>,
    action: &Action,
    now: TimeBounds,
    information: &ServiceInformation,
    signer: &SigningKey,
) -> Domain<Outcome> {
    super::inspection::own(action)?;
    let request: MetadataRequest =
        decode(&action.body).ok_or(Fault::Reject(ErrorCode::InvalidInput, "ViewBody"))?;
    let account = Target::Account(action.actor.acting().account);
    let account_view: identity::AccountView = result(identity::inspection::read_bounded(
        db,
        &part(
            action,
            Operation::AccountInspect,
            account.clone(),
            &Empty {},
        )?,
        1024,
    )?)?;
    if request
        .filter_revision
        .is_some_and(|r| r != account_view.filter_revision)
    {
        return conflict("ViewContextChanged");
    }
    let single = usize::from(request.rooms.is_some())
        + usize::from(request.filters.is_some())
        + usize::from(request.grants.is_some())
        + usize::from(request.agents.is_some())
        == 1;
    let allowance = |shared| {
        if single {
            ORDINARY_FRAME_BYTES - 8192
        } else {
            shared
        }
    };
    let mut page = MetadataPage {
        account: account_view,
        service: information.clone(),
        rooms: None,
        filters: None,
        grants: None,
        agents: None,
    };
    if let Some(p) = request.rooms {
        let (items, next) = conversations::list_bounded(
            db,
            &part(action, Operation::RoomList, Target::Service, &p)?,
            now,
            |_| Ok(()),
            allowance(8192),
        )?;
        page.rooms = Some(RoomListPage { items, next });
    }
    if let Some(p) = request.filters {
        page.filters = Some(result(moderation::inspection::read_bounded(
            db,
            &part(action, Operation::ModerationFilters, account.clone(), &p)?,
            now,
            allowance(4096),
        )?)?);
    }
    if let Some(p) = request.grants {
        page.grants = Some(result(delegation::list_bounded(
            db,
            &part(action, Operation::DelegationList, account.clone(), &p)?,
            allowance(32768),
        )?)?);
    }
    if let Some(p) = request.agents {
        page.agents = Some(result(identity::inspection::read_bounded(
            db,
            &part(action, Operation::AgentList, account, &p)?,
            allowance(4096),
        )?)?);
    }
    bounded(&page, action, signer)
}
pub(super) fn community(
    db: &Transaction<'_>,
    action: &Action,
    now: TimeBounds,
    permit: delegation::Permit,
    signer: &SigningKey,
    cancel: &Cancellation,
) -> Domain<Outcome> {
    if matches!(action.actor, Actor::Delegated { .. }) {
        return deny("PrivateInspection");
    }
    let request: CommunityRequest =
        decode(&action.body).ok_or(Fault::Reject(ErrorCode::InvalidInput, "ViewBody"))?;
    let access = conversations::access(db, action, now)?;
    if access.confidentiality != RoomConfidentiality::Community {
        return invalid("HistoryPrivacyMode");
    }
    if request.context.is_some_and(|c| c != access.access_digest) {
        return conflict("ViewContextChanged");
    }
    let inspection: conversations::Inspection = result(conversations::inspection::read(
        db,
        &part(
            action,
            Operation::RoomInspect,
            action.target.clone(),
            &Empty {},
        )?,
        now,
    )?)?;
    let mut page = CommunityPage {
        inspection: inspection.into(),
        context: access.access_digest,
        filters: None,
        history: None,
        restrictions: None,
    };
    let single_policy = request.history.is_none()
        && usize::from(request.filters.is_some()) + usize::from(request.restrictions.is_some())
            == 1;
    let policy_bytes = if single_policy {
        let used = canonical_encode(&value(&page)?, ORDINARY_FRAME_BYTES - 4096)
            .map_err(|_| Fault::Reject(ErrorCode::Overloaded, "ViewRepresentation"))?
            .len();
        (ORDINARY_FRAME_BYTES - 4096).saturating_sub(used)
    } else {
        4096
    };
    if let Some(p) = request.filters {
        page.filters = Some(result(moderation::inspection::read_bounded(
            db,
            &part(
                action,
                Operation::ModerationFilters,
                Target::Account(action.actor.acting().account),
                &p,
            )?,
            now,
            policy_bytes,
        )?)?);
    }
    if let Some(p) = request.restrictions {
        page.restrictions = Some(result(moderation::inspection::read_bounded(
            db,
            &part(
                action,
                Operation::ModerationRestrictions,
                action.target.clone(),
                &p,
            )?,
            now,
            policy_bytes,
        )?)?);
    }
    if let Some(p) = request.history {
        let used = canonical_encode(&value(&page)?, ORDINARY_FRAME_BYTES - 4096)
            .map_err(|_| Fault::Reject(ErrorCode::Overloaded, "ViewRepresentation"))?
            .len();
        let bytes = (ORDINARY_FRAME_BYTES - 4096).saturating_sub(used);
        page.history = Some(result(messaging::history::page_bounded(
            db,
            &part(action, Operation::EventsResume, action.target.clone(), &p)?,
            now,
            permit,
            signer,
            cancel,
            bytes,
            false,
        )?)?);
    }
    bounded(&page, action, signer)
}
