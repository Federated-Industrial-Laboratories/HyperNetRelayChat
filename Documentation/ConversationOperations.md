# Local conversation operations

The local service uses the [native wire profile](WireProtocol.md) and one SQLCipher
writer. Identity, delegation, conversations, messaging and moderation own their
respective rules. The Home boundary coordinates current admission, ordering,
retry outcomes and durable commit. Frontends call these operations; they cannot
replace service authorization with a display check.

This profile provides service-readable community rooms. Confidential direct
conversations, private groups and federation require their respective feature
contracts. Until a feature is connected, its operations return
`UnsupportedFeature`. In particular, `DirectCreate` and an encrypted room request
cannot produce a plaintext conversation.

## Enrolment and sessions

A service administrator creates a one-use invitation with the exact HyperNet
principal, human or agent classification, operator binding, home identity, service
public key and 24-hour expiry. The owner checks the service public key through the
explicit local descriptor exchange. The account registration proves possession of
the proposed endpoint key and includes a distinct owner-held recovery public key.
The administrator accepts that exact signed registration. A wrong principal,
classification, operator or invitation does not consume the invitation. An existing
account cannot be overwritten by another registration.

Subsequent devices use the [endpoint lifecycle](EndpointLifecycle.md): exact
controller admission followed by new-key/HyperNet proof, or the separately held
owner recovery key. Recovery uses the finite device exchange rather than an
ordinary authenticated `AccountRecover` Action. Registration never acts as an
administrative recovery override.

Agent accounts require an already enrolled human operator. A human classification
does not prove that a person typed an event. Each accepted endpoint has an exact
HyperNet principal, account security generation, endpoint enrolment generation and
canonical endpoint-binding digest. A session is constructed only after verified
HyperNet context and the signed challenge proof agree. An action is checked against
both this session and the current endpoint record. The caller's account label,
signature key identifier or delegation label cannot establish that binding.

There are at most 256 accounts in this pilot profile, 128 outstanding invitations
and four unexpired retry windows per endpoint. Reconnect normally reuses the
endpoint's current window after fresh authorization. A window with less than five
minutes remaining is replaced. Reuse does not renew its original expiry. Closed
window identities remain tombstones and are never recreated from client input.

## Operation bodies

All bodies are closed canonical CBOR maps. Field names use the camel-case form of
the public Rust DTOs; optional fields are present with `null` when unset. Unknown
fields fail. Stable IDs, not names, select accounts and rooms.

| Operation | Target and body | Result |
| --- | --- | --- |
| `AccountSetNickname` | Own `Account`; `identity::Nickname { nickname }` | Account revision and home position advance; attribution retains the account ID |
| `PresenceSet` | Own `Account`; `identity::Presence { status, duration_ms }` | Endpoint presence expires after 1–300 seconds; human and agent accounts remain separate |
| `AccountInspect` (3) | Own `Account`; `{}` | `identity::AccountView { nickname, revision, filter_revision }` |
| `AgentList` (4) | Own `Account`; `home::InspectPage { after, limit }` | Current eligible owned `identity::AgentEndpoint { actor, nickname }` entries |
| `ServiceInspect` (5) | `Service`; `{}` | `home::ServiceInformation { motd }`; plain text, at most 1,024 bytes, empty by default |
| `RoomCreate` | `Service`; `conversations::Create { name, confidentiality }` | A new room, owner membership and ordered creation event |
| `RoomList` | `Service`; `conversations::List { after, limit }` | At most 50 eligible room summaries in stable ID order |
| `RoomJoin`, `RoomLeave` | `Room`; `{}` | Membership and room revisions advance with an ordered event |
| `RoomSetTopic` | `Room`; `conversations::Topic { topic }` | Current moderator changes the topic with an ordered event |
| `RoomInspect` (15) | `Room`; `{}` | `conversations::Inspection { members, read_sequence, room_revision, filter_revision, moderator }` under current membership |
| `MessageSend`, `MessageReply`, `MessageAction` | `Room`; `messaging::Send { text, mentions, parent, causation }` | One attributed event, or a durable rejection |
| `HistoryPage`, `EventsSubscribe`, `EventsResume` | `Room`; `messaging::Page { cursor, limit }` | Current-authorized bounded page and signed continuation cursor |
| `HistoryContext` (37) | `Room`; `messaging::Context { event }` | `messaging::ContextResult { events, members, room_revision }`; accessible original event and bounded surrounding context |
| `SearchQuery` | `Room`; `messaging::Search { terms, sender, represented, from_ms, until_ms, cursor, limit }` | Indexed or bounded short-query results with original event identities |
| `SearchCancel` (32) | `Service`; `home::Resolve { operation_id, action_digest }` | Exact current-session query cancellation, with the ordinary signed control response |
| `UnreadSet` | `Room`; `messaging::Unread { sequence }` | Account-owned monotonic read position; cannot advance past the room sequence |
| `OperationResolve` | `Service`; `home::Resolve { operation_id, action_digest }` | A correlated `ResolveResult`, described below |
| `ModerationIgnore`, `ModerationMute` | Own represented `Account`; `moderation::Filter { subject, enabled }` | Recipient filter changes; ignore advances the filter revision |
| `ModerationSilence`, `ModerationKick`, `ModerationBan` | `Room`; `moderation::Restriction { subject, enabled, duration_ms, reason }` | Attributable moderator decision and room revision |
| `ModerationFilters` (65) | Own `Account`; `home::InspectPage` | `moderation::FilterState { subject, ignored, muted }` entries |
| `ModerationRestrictions` (66) | `Room`; `home::InspectPage` | Active `moderation::RestrictionState { subject, kind, expires_ms, moderator }` entries; silence kind 1, ban kind 2 |
| `DelegationList` (45) | Own `Account`; `home::InspectPage` | Current grants owned by the account or assigned to its exact current agent endpoint |
| `AccountEnrolEndpoint` (92) | Controlled `Account`; `identity::ApproveEndpoint { request, revision, head }` | An exact, finite admission ticket; new-key activation is still required |
| `AccountDisableEndpoint` (93) | Controlled `Account`; `identity::DisableEndpoint { endpoint, revision, head }` | Endpoint withdrawal, affected permission invalidation and continuity record |
| `AccountRotateRecovery` (91) | Controlled `Account`; `identity::RotateRecovery { replacement, revision, head }` | Replacement-key possession and current-controller-authorized rotation |
| `AccountDevices` (94) | Controlled `Account`; `{}` | Current `IdentitySnapshot`, including active endpoints, public keys, revisions, head and explicit `legacyAnchor` flag |
| `AccountContinuity` (95) | Known local `Account`; `identity::ContinuityPage { after, limit }` | Bounded public `ContinuityRecord` entries and optional next record number |
| `AccountLifecycleOutcome` (96) | Controlled `Account`; `home::Resolve` | Original account-control outcome without re-authorizing or resubmitting it |

Inspection lists return `home::InspectionPage { items, next }`. A request limit is
1-16; `after` and `next` are optional ASCII positions of at most 512 bytes. Encoding
bounds can shorten a page. These positions do not grant access. Private account,
agent and recipient-filter inspection requires the acting account, with no
delegated impersonation. Room inspections require current room access. Member
lists contain at most 32 entries. Service information discloses no client version,
local address or device clock.

Rooms have at most 32 active accounts. A community join starts a new history interval
at admission; rejoining does not restore a previous interval. The owner remains a
member. Topic and moderation require current moderator rights. The initial room
owner is its moderator; this profile does not implicitly make a network
administrator a room moderator. A room can have at most 256 active restrictions.

`MessageReply` requires an accessible parent in the same room. Other message kinds
require a null parent. Text uses the shared [Unicode profile](TextAndSearch.md),
with an 8 KiB and 2,000-grapheme maximum. Original content is retained; normalized
lookup text is separate. Text never contains executable terminal control sequences.

`mentions` contains at most 16 `messaging::Mention { account, start, end }` values.
Start and end are UTF-8 byte offsets on whole grapheme boundaries, with ordered,
non-overlapping spans. Each span must equal `@` followed by that stable account's
current nickname, and the account must be a current room member. A rename can
reject a stale mention; it cannot retarget it to another account. Unselected
`@text` remains ordinary text. Omitting `mentions` in an older text-only body
means an empty list. Client drafts retain these bindings with the text, and
mention-only notifications use account IDs rather than substring matching.

Home positions order all committed effects. Room sequences order that room's
events, including membership and moderation. A server event timestamp is the
conservative lower UTC bound at evaluation; timestamps do not resolve conflicting
operations. A room-effect `Committed` body contains only `messaging::Committed {
room }`, alongside the top-level event ID and home position. It contains no message
text. Grant creation/control returns its new `GrantRef`. Other committed results
contain no private content.

## Retry and admission

The client persists exact signed effect bytes before submission. The service stores
the canonical action bytes, their digest and minimal outcome under the endpoint's
service-issued window and operation ID. Identical retries return that outcome;
different bytes under the same ID return `Conflict`. Terminal rejections are also
retained. A restart cannot discard protection while an operation remains retryable.

An authenticated resolution request uses its own current window and signs the
original window, operation ID and action digest. A successful lookup returns:

```text
Outcome::Result {
  body: ResolveResult {
    operation_id: original operation,
    action_digest: original action digest,
    outcome: Committed | Rejected | Absent | Unknown
  }
}
```

The response envelope binds the resolution request. The inner object separately
binds the original action. A rejection of the resolver is an outer rejection and
is never interpreted as the original send's outcome. The original window must
belong to the current endpoint. A digest mismatch is a conflict. `Absent` means
the original action has no outcome **and its window remains open**; only this state
permits resubmission of the exact original bytes. Missing history after expiry is
`Unknown`, not permission to create another send. A repeated resolution request
performs a fresh lookup, including after an earlier `Absent`.

Read operations apply current access each time and do not have an immutable result
transcript. Their retained marker contains no page text. The authoritative
`home::is_read_operation` classifier identifies them for clients. Reissue reads
under current access; attempting to resolve a previously successful read returns
`ResolveReadOperation` rather than a stale page.

`Refused` means an action did not enter durable operation admission, for example
when capacity, current clock evidence or fresh transport authority is unavailable.
Its retry hint is bounded. It is distinct from a retained `Rejected` outcome.
Tentative SQL effects remain invisible until the final authorization boundary.
The original clock witness is refreshed there, the retained UTC floor is checked,
the current transport permit is checked again, and window/grant expiry is checked.
Failure rolls back all tentative state, including approval consumption and rate
charges. No later action can interleave with this boundary. Physical durable
completion can follow the authorization point; a continuity-fenced commit returns
`Unknown` and must be recovered before new writes.

Deduplication records remain for at least seven days and past the window expiry.
All retries still require a current authenticated endpoint. Minimal retained
outcomes can be resolved after room access is lost without exposing message text.
Nickname changes do not change endpoint identity or an old event's attribution.

## Delegation and approval

`delegation::Create` binds an exact current agent endpoint and its operator to an
owner, home service, up to 32 rooms and 32 recipients, allowed operations, history
interval, validity, mode, operation-rate limit and explanatory purpose. The owner
must be that agent's enrolled operator and currently have each requested room's
rights. A grant lasts at most seven days. It cannot authorize further delegation,
account administration or automatic endpoint enrolment. Unsupported conversation
modes remain unsupported even if a grant names their recipient.

Current endpoint, represented-account security generation, operator, grant
generation, room rights and applicable bans all participate in every operation.
The grant cannot bypass the represented account's or operator's ban. Read history
is the intersection of the grant interval, current membership interval, retention
and current recipient filter. A supplied expected revision is always checked;
unsupported revision families fail explicitly.

`Draft` permits scoped reads and owner-visible preparation, with no conversation
send. The owner can reject a draft; approving it remains forbidden. `Approve`
requires the exact one-use approval for every effect. `Autonomous`
permits effects inside the current scope without repeated approval. Unneeded
approval references are rejected. Each owner has at most 64 non-revoked grants.

Grant lifecycle operations target the exact `GrantRef` with an empty body.
Pause, resume and revoke each advance its generation and invalidate pending
approvals. Revocation is terminal. A fresh action using a paused or revoked grant
receives a distinct grant-state denial; queued work cannot continue using the old
generation. `DelegationInspect` is available to the owner or exact enrolled agent
and returns the current grant and pending exact candidates.
`DelegationList` returns only grants owned by the acting account or bound to its
exact current agent endpoint; listing does not enable a paused or revoked grant.

An agent or owner prepares `delegation::Prepare { candidate, expires_ms }`. The
candidate is the complete signed agent action, including its preallocated approval
ID and original operation ID. Its signature, current grant and room scope are
checked. Candidates are limited to 16 KiB and five minutes, within grant expiry;
there are at most two pending candidates per grant. The owner inspects these exact
bytes before submitting `delegation::Decision { approval, action_digest }` through
`ApprovalApprove` or `ApprovalReject`. Changing content, target, operation ID or any
other signed field changes the digest and invalidates approval. Execution consumes
the approved record atomically with the send outcome. Retry returns that outcome
without consuming another approval or creating another event.

For a declared automated causation, the service verifies an accessible cause,
deduplicates the event/agent/grant trigger, permits depth at most four, and permits
at most eight automated effects per root event. Clients must identify automatic
replies with `causation`; ordinary unsolicited agent posts remain subject to the
same actor, represented-account and room rate limits. No service action
automatically triggers a language model or replies to an error.

## History, search and moderation

History and event subscriptions return bounded pull pages. A page contains at most
32 events, no more than 48 KiB of encoded event content, a signed continuation
cursor, the room revision and at most 32 current member summaries. The request's
maximum is 50; a byte or node bound can shorten a page. Consumers use `has_more`
and the cursor and must not infer delivery or read receipts from page completion.
Member summaries retain human/agent classification, stable origin, nickname,
current finite presence and moderator status.

The cursor binds home, room, account, sequence, membership revision, filter
revision, current actor/grant/agreement context and five-minute expiry. Search
cursors additionally bind all normalized terms and query filters. A changed access
context or a gap before retained history returns `ResynchronisationRequired`.
Neither a cursor nor previously returned search data grants future access.

`HistoryContext` opens the original event from a search result under these same
current rules. It returns at most two sequence positions before and after the
target, at most five events total. Filtering, retention or frame size can remove
neighbors; the target must remain accessible and present. An inaccessible target
returns `EventUnavailable`, rather than a substitute cached tail. Context does not
advance or rewind the live conversation cursor.

Search uses a SQLCipher FTS5 trigram index over the shared Unicode-normalized text.
The service constructs literal quoted phrases; callers cannot submit FTS syntax.
At most 16 terms and 1 KiB of input enter a query. Queries without a trigram term
scan at most 256 candidates and 1 MiB before returning `QueryTooBroad`. Indexed
queries can continue through bounded candidate batches. Each operation has a
two-second storage deadline. A session runs at most one query at a time and
registers its operation ID, action digest and actor before execution. The service
can read one correctly correlated, signed `SearchCancel` concurrently on that
same stream; it verifies current transport and endpoint authority before signalling
the query token. Query iteration checks the token, and there remains one response
writer and one client reader. Wrong identifiers or actors cannot cancel another
operation. A late cancellation can report the query already ended; it does not
rewrite a completed result. The query and control response keep distinct operation
identities. Cancellation does not renew query deadlines or permit stale result
disclosure.

Recipient ignore matches the acting account, represented account or operator and
removes matching live pull delivery, history and search before presentation.
Notification, preview and agent-trigger consumers must use these filtered results.
Mute changes notification/presentation preferences and does not erase or hide
history. Neither operation changes shared room history. Silence denies publication;
kick removes membership; ban also denies readmission and applies to dependent agent
identities. Restrictions expire conservatively and cannot remove the room owner.
Moderation reasons are at most 256 bytes; notices are ordinary bounded events.

Conversation retention is 30 days with a 10 GiB content quota. Quota exhaustion
refuses new content rather than shortening the promised interval. Expired content
is excluded immediately from every query. `Home::maintain` and ordinary operations
remove up to 128 expired events and their index entries per transaction. A running
service schedules one background maintenance task every 30 seconds; it remains subject to
the same current clock and storage health checks. No transcript is written to
diagnostic output. Database, WAL and derived indexes have the same encrypted
storage boundary.

Persisted token budgets cover actor and represented-account sends at two per
second with burst eight, 32 KiB/s per account, ten room sends/s and twenty service
sends/s. Service ingress bytes are limited to 256 KiB/s. Membership changes allow
ten per minute; nickname/presence changes allow six per minute. Search allows one
per second with burst two. Grant-specific rates further restrict these budgets.
These are pilot admission limits; supported latency and memory claims still require
the release load evidence. Stream queues, fan-out, presentation work and fresh
HyperNet authority are separately bounded by their owning integration layers.

The maintained SQLCipher workflow tests cover exact invitation binding, durable
retry and resolution after restart, Unicode search, grant scope and lifecycle,
one-use exact approval, a permit lost after tentative effects, recipient ignore,
silence, cursor invalidation, closed windows and explicit confidentiality refusal.
They also cover a full member list with delegated event attribution, page shortening
without missing or duplicate events, filtered unread counts, and removal of expired
search entries and retry-action bytes.
Unknown and expired grants retain their explicit rejection, and rejected draft
candidates no longer occupy the pending-inspection list.
