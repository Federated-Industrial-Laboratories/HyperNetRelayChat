// SPDX-License-Identifier: Apache-2.0
//! Bounded frontend commands and immutable views, without presentation dependencies.
use crate::{conversations, delegation, identity, messaging, moderation, protocol::*};
use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Theme {
    #[default]
    Dark,
    Light,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum Density {
    Compact,
    #[default]
    Comfortable,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChatLayout {
    #[default]
    Classic,
    Bubbles,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub enum NotificationMode {
    #[default]
    All,
    Mentions,
    Off,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Preferences {
    pub theme: Theme,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub palette: Option<String>,
    pub density: Density,
    #[serde(default)]
    pub chat_layout: ChatLayout,
    pub text_scale: f32,
    pub quiet: bool,
    pub sound: bool,
    pub ambiguous_wide: bool,
}
impl Default for Preferences {
    fn default() -> Self {
        Self {
            theme: Theme::Dark,
            palette: None,
            density: Density::Comfortable,
            chat_layout: ChatLayout::Classic,
            text_scale: 1.0,
            quiet: false,
            sound: false,
            ambiguous_wide: false,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RoomPreferences {
    pub notifications: NotificationMode,
    pub sound: bool,
}
impl Default for RoomPreferences {
    fn default() -> Self {
        Self {
            notifications: NotificationMode::All,
            sound: false,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ConnectionState {
    Offline,
    Connecting,
    Resolving,
    Online,
    Backoff {
        attempt: u8,
        retry_in_ms: u64,
        reason: String,
    },
}
#[derive(Clone, Debug)]
pub struct Status {
    pub request_id: Option<u64>,
    pub code: String,
    pub detail: String,
}
#[derive(Clone, Debug)]
pub struct Delivery {
    /// Prepared frame write to complete direct committed acknowledgement; never recovered.
    pub exchange_ns: Option<u64>,
    pub abandoned: bool,
    pub held: bool,
    pub request_id: Option<u64>,
    pub operation: Operation,
    pub operation_id: OperationId,
    pub action_digest: Id,
    pub room: Option<RoomId>,
    pub outcome: Option<Outcome>,
}
#[derive(Clone, Debug)]
pub struct Notification {
    pub id: u64,
    pub room: RoomId,
    pub event: Id,
    pub sound: bool,
    pub mention: bool,
    // Retain attribution while queued so newly current recipient filters also
    // suppress notifications whose events have left the visible history page.
    pub(crate) actor: Actor,
}
#[derive(Clone, Debug)]
pub struct RoomView {
    pub crypto: Option<super::CryptoView>,
    pub focus: Option<Id>,
    pub summary: conversations::Summary,
    pub members: Vec<conversations::Member>,
    pub events: Vec<Event>,
    pub content: std::collections::BTreeMap<Id, super::MessageContent>,
    pub draft: String,
    pub draft_mentions: Vec<messaging::Mention>,
    pub stale: bool,
    pub gap: Option<String>,
    pub has_more: bool,
    pub read_sequence: u64,
    pub preferences: RoomPreferences,
}
#[derive(Clone, Debug, Default)]
pub struct Inspection {
    pub admission_consent: Option<crate::home::admission::ConsentReceipt>,
    pub filters_stale: bool,
    pub filters: Vec<moderation::FilterState>,
    /// Belongs to the selected room and follows that RoomView's freshness.
    pub restrictions: Vec<moderation::RestrictionState>,
    pub grants: Vec<delegation::Grant>,
    pub agents: Vec<identity::AgentEndpoint>,
    pub grant: Option<delegation::Inspection>,
    pub proposed: Vec<Action>,
    pub proposed_content: std::collections::BTreeMap<Id, super::MessageContent>,
    pub stale: bool,
}
#[derive(Clone, Debug)]
pub struct SearchView {
    pub room: RoomId,
    pub query: messaging::Search,
    pub events: Vec<Event>,
    pub content: std::collections::BTreeMap<Id, super::MessageContent>,
    pub has_more: bool,
    pub running: bool,
    pub cancelled: bool,
}
#[derive(Clone, Debug)]
pub struct ServiceChoice {
    pub home: ServiceId,
    pub agreement: Option<AgreementRef>,
    pub selected: bool,
}
#[derive(Clone, Debug)]
pub struct Snapshot {
    pub revision: u64,
    /// View reads are in progress. This is not an authority or delivery guarantee.
    pub updating: bool,
    pub account: AccountId,
    pub home: ServiceId,
    pub services: Vec<ServiceChoice>,
    pub classification: AccountClass,
    pub nickname: String,
    pub motd: String,
    pub connection: ConnectionState,
    pub privacy: Option<crate::hypernet::Privacy>,
    pub federation_privacy: Option<crate::protocol::RemoteSessionReady>,
    pub rooms: Vec<conversations::Summary>,
    pub selected: Option<RoomView>,
    pub search: Option<SearchView>,
    pub deliveries: Vec<Delivery>,
    pub inspection: Inspection,
    pub preferences: Preferences,
    pub notifications: Vec<Notification>,
    pub completions: Vec<Completion>,
    pub status: Option<Status>,
}
#[derive(Clone, Copy, Debug)]
pub enum GrantChange {
    Pause,
    Resume,
    Revoke,
}
#[derive(Clone, Copy, Debug)]
pub enum RestrictionKind {
    Silence,
    Kick,
    Ban,
}
#[derive(Clone, Debug)]
pub enum Command {
    Connect,
    Disconnect,
    SelectService(Option<AgreementRef>),
    Refresh,
    SelectRoom(RoomId),
    OpenEvent {
        room: RoomId,
        event: Id,
    },
    LoadMore,
    Resynchronise,
    Search(messaging::Search),
    NextSearchPage,
    CancelSearch,
    CloseSearch,
    SaveDraft {
        room: RoomId,
        text: String,
        mentions: Vec<messaging::Mention>,
    },
    Send {
        room: RoomId,
        text: String,
        mentions: Vec<messaging::Mention>,
        parent: Option<Id>,
        causation: Option<Id>,
        action: bool,
        grant: Option<Box<delegation::Grant>>,
    },
    MarkRead {
        room: RoomId,
        sequence: u64,
    },
    CreateRoom {
        name: String,
    },
    CreatePrivateGroup {
        name: String,
    },
    CreateDirect {
        recipient: AccountId,
    },
    Invite {
        room: RoomId,
        account: AccountId,
    },
    CryptoEnrol,
    CryptoInspect {
        room: RoomId,
        grant: Option<Box<delegation::Grant>>,
    },
    CryptoPublish {
        room: RoomId,
        grant: Option<Box<delegation::Grant>>,
    },
    CryptoInitialise {
        room: RoomId,
        recover: bool,
    },
    CryptoCommit {
        room: RoomId,
        additions: Vec<Id>,
        removals: Vec<Id>,
    },
    CryptoSync {
        room: RoomId,
        grant: Option<Box<delegation::Grant>>,
    },
    TrustContact {
        account: AccountId,
        anchor_digest: Id,
        legacy: bool,
    },
    Join(RoomId),
    Leave(RoomId),
    SetTopic {
        room: RoomId,
        topic: String,
    },
    SetNickname(String),
    SetPresence(identity::Presence),
    SetFilter {
        subject: AccountId,
        ignored: Option<bool>,
        muted: Option<bool>,
    },
    SetRestriction {
        room: RoomId,
        kind: RestrictionKind,
        restriction: moderation::Restriction,
    },
    Inspect,
    CreateGrant(delegation::Create),
    ConsentAgent(crate::home::admission::Prepare),
    AgentAccess(crate::home::admission::AgentAccess),
    InspectGrant(GrantRef),
    ChangeGrant {
        grant: GrantRef,
        change: GrantChange,
    },
    DecideApproval {
        grant: GrantRef,
        decision: delegation::Decision,
        approve: bool,
    },
    SubmitCandidate(Id),
    AbandonPending {
        operation_id: OperationId,
        action_digest: Id,
    },
    ResolvePending {
        operation_id: OperationId,
        action_digest: Id,
    },
    SetPreferences(Preferences),
    SetRoomPreferences {
        room: RoomId,
        preferences: RoomPreferences,
    },
}

#[derive(Clone, Debug)]
pub struct Completion {
    pub request_id: u64,
    pub error: Option<Status>,
}
