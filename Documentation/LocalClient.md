# Shared local client

The graphical and terminal interfaces use `client::Controller`. One background
worker owns the endpoint's existing SQLCipher store. Opening the controller does
not open HyperNet, sample the authority clock, or create a second store owner.
The account configuration, database key, continuity guard and private paths still
receive their normal validation. Explicit connection obtains a new verified
session and resolves persisted operation identities before preparing new effects.
There is no direct Internet fallback.

Online status follows successful initial refresh as well as session setup.
Temporary pre-admission authority, rate or capacity refusals preserve their retry
guidance and enter bounded reconnect backoff. Reconnect obtains fresh authority
and resolves exact retained operations before retrying an absent effect. A durable
rejection, invalid identity or malformed frame does not become an automatic retry.
Readiness failure remains visible on the original command; later recovery does
not rewrite that completion as success. Current-query errors remain explicit.
The five-second metadata refresh interval starts after a successful full refresh
finishes, including initial connection and commands that change membership or
policy. Due metadata work runs between command turns, even with a busy queue.
With the negotiated bounded-view capability, each periodic turn performs one
finite group or continuation page before yielding to queued command work. A full
metadata refresh cannot occupy every intervening command turn. Initial connection
and membership or policy changes still complete their required refresh before
reporting readiness.
Room selection and targeted post-send reads do not postpone that deadline.
A selected community page with authenticated `has_more` schedules a finite
catch-up burst without waiting for the next metadata interval. Each turn reads
one bounded grouped component, then yields to queued commands; due metadata has
priority. Up to eight additional history pages share the first page's original
ten-second admission and currentness end, including time spent on intervening work.
Each newly dispatched read separately owns the existing ten-second exchange bound,
captured before signing. Its exact retries cannot restart that bound. A read already
in flight may finish after the view end, within its own original exchange bound;
total completion can extend the logical view end only by that bounded in-flight
read. Such a late reply is consumed and authenticated without publishing its content,
advancing a cursor, installing filters or scheduling another continuation. No new
request starts after the view end. Incomplete recipient
policy cannot publish history. Each completed page advances the authenticated
cursor; an unchanged position with `has_more` is rejected. Initial catch-up does
not emit live notifications. A completed command pull supersedes matching partial
work without extending its end or page allowance. Cancellation, disconnection,
room or focused-context changes, gaps and failures stop continuation. A finite
burst that exhausts its time or page allowance leaves `has_more` visible; the next
ordinary refresh can resume it. No read grants authority to a subsequent read.
A slow full refresh does not schedule an immediate second full refresh.
A failed full attempt also waits that interval before another metadata attempt;
connection backoff can require a longer wait. Failure never makes a view current.

Snapshots distinguish `updating` from stale room or inspection state. The GUI and
TUI show "refreshing views" while reads run or a committed community send has a
bounded room update or selected-room catch-up pending. Pending work does not make retained policy current
and does not extend the lifetime of any authority observation. Starting an ordinary refresh retains
the last successfully synchronized view; it does not itself signal lost access.
Cached or already-stale views remain stale until their required current reads
succeed. A failed view scope marks its retained views stale, including local
storage and invalid-response failures. An authenticated read refusal is published
as stale before any bounded same-action retry wait. Temporary refusals of
RoomInspect, EventsResume and ModerationRestrictions with a room target mark only
that matching room view stale. They preserve unrelated inspection and transport
privacy observations: a synchronized application refusal is not evidence of
changed TLS or route properties. The completed room pull revalidates its room,
history and restrictions before making that view current. It cannot clear
already-stale account inspection. Restriction lists follow selected-room
freshness and are cleared when selection changes. Other read kinds, including
recipient filters, search and focused context, retain global failure handling;
no room-only recovery is inferred for them. Exhausted retries and final view
failures still invalidate the full view and privacy observation. Existing denial, expiry,
history-gap and encrypted-history protections still apply. Neither a synchronized
view nor a retained privacy observation grants authority: the service checks
current authority on every read and effect.

For local nondelegated community views, `bounded-client-views-v1` groups related
reads through the same server policy owners. Account metadata and community-room
synchronization have separate fixed contracts. Each group receives a fresh
authority check and retains the summed operation costs and ordinary frame limit.
Incomplete filter or restriction pages cannot admit history or notifications;
changed context discards the partial assembly. Failures invalidate the requested
view scopes. Remote, encrypted and delegated paths retain their existing reads.
See [bounded client views](WireProtocol.md#bounded-client-views).

Recipient-filter freshness is separate from grant and agent metadata freshness.
`inspection.filters_stale` remains true until complete current filter assembly;
`inspection.stale` covers the metadata refresh. A grouped community-read failure
invalidates filter-dependent room, search and notification state without making
unrelated grant or agent metadata stale. Global terminal and transport failures
invalidate both scopes. Current presentation and pilot readiness require both
flags to be clear; completing filters alone cannot refresh metadata.

An explicitly authenticated community classification can supply private,
in-memory room-mode evidence for an exact prepared message. It binds the room,
home and pinned service key, and requires the negotiated immutable-mode contract.
It is not an access grant. Current service authority and room or delegation
checks remain mandatory on submission. A caller-supplied room summary, missing
mode field or mutable prepared object cannot provide that evidence. Raw API
submissions, unknown-room preparation, encrypted messages and persisted retries
retain their validation paths.

Session setup allows at most three attempts within one original 30-second
deadline. Each HyperNet preparation wait is at most 10 seconds; each HRC
handshake is at most five seconds within that same deadline. Incomplete HRC
handshakes and typed HyperNet Timeout, Unavailable, Closed, Capacity, Busy or
NotActive preparation failures can obtain a fresh stream. An authenticated
federation Unavailable, RateLimited or Overloaded response can also retry setup.
Its retry guidance is a minimum wait; guidance outside the remaining original
deadline returns the refusal without another attempt. These attempts share the
same three-attempt ceiling. Explicit HyperNet Refused, federation denial or
expiry, invalid protocol/frame/version, private-path or ownership failures are terminal;
Controller and bot reconnect classification preserves that distinction.
An authenticated Unavailable, RateLimited or Overloaded refusal from the service
or origin forwarder leaves its current session synchronized. After a bounded
read retry is exhausted, the Controller also retains that session, marks the view
stale and honors its existing backoff. It resolves exact pending operations and
refreshes through that session before reporting Online. Retaining the connection
does not treat a refused operation as successful or preserve expired authority.
Genuine transport failures still require reconnection; invalid frames and
identities remain terminal. Disconnect stays available during the wait. Session reuse supplies no
new authority, extends no operation window and cannot replace uncertain effects.
No conversation operation is prepared or replayed by session setup. Preparation
failure diagnostics contain only the static adapter category and boot-time
start, finish and original deadline, without identities or credential data.
They stop after 128 attempts per process. One process-lifetime writer receives
at most 32 queued records, each at most 1,024 bytes including its newline.
Saturated, closed or oversized output is discarded. Connection workers never
wait for the output sink, and shutdown does not join the diagnostic writer.
Unavailable diagnostic output does not change the connection outcome.

Controller and direct CLI/API reads share the same temporary-refusal recovery.
An authenticated temporary read refusal retries the same signed bytes on the
same session, at most five attempts within one original ten-second budget.
This also covers room inspection before direct message preparation. Retry
guidance must fit that budget. Each attempt requires a new service authority
check; earlier successful refresh reads are not restarted. Permanent refusals,
invalid responses and transport loss end the attempt. Controller disconnect and
shutdown interrupt retry waiting; synchronous direct reads retain the same fixed
budget. This read path cannot submit mutations or recreate a
pending message. Room lists stop when the final partial page is received.

A read or logical view budget that ends before dispatch or after a complete verified response
reports `ReadDeadlineExpired`. Late content cannot make a view current. The
Controller retains the synchronized session, marks affected views stale and uses
its existing bounded backoff. Terminal refusals retain their authority meaning;
an incomplete exchange at its own read deadline or actual socket failure still
requires reconnection. A logical view deadline never shortens an already dispatched
frame exchange. Neither deadline grants authority or permits mutation retries.

The command queue contains at most 32 bounded commands. Dispatch returns a local
request number. Immutable snapshots carry that number on command status and
operation delivery records. A frontend can distinguish the exact submitted text
from later typing. Historical recovered operations have no local request number.
When connection is still desired, the worker can retain one unstarted
state-changing command ahead of that queue while the connection recovers. Its
30-second admission deadline starts at dispatch, including queue time. The worker
honours existing reconnect backoff and checks the original deadline again before
starting any effect, even when synchronous reconnection finishes late. The same
request and command are consumed once; this mechanism never reruns a started
command or prepares a replacement effect identity. `CommandWaitingForConnection`
shows the pending request; `CommandAdmissionExpired` reports expiry without a
delivery identity or a changed connection retry schedule. Deliberate offline
mode retains normal refusal and local-draft behaviour. Reserved disconnect and
shutdown controls remain available while a command is held. Read-only commands
retain their existing explicit current-read failures and offline cache behaviour.
Local draft/preference writes, retry abandonment and search close use a local
lane sharing that same 32-item queued budget. At most four local commands run
per worker turn, so they remain responsive during reconnect backoff without
starving an eligible effect. Shutdown atomically closes queue admission, then
drains accepted local work only; it does not execute queued network effects.
Local persistence errors remain visible on their original completions.
Effect completion succeeds only after every requested effect and its required
local persistence succeeds. A later room, grant or inspection refresh can fail
without changing that confirmed outcome or replaying the effect. The original
durable delivery is published before follow-up view reads start. A normal send
refreshes recipient filters, the affected room and the companion privacy
observation. Direct committed sends to the selected, unfocused local community
room may share this work when bounded views are negotiated and no history gap is
present. At most two committed sends share one pull. The first pending update's
one-second age is never reset by newer sends; the next worker turn flushes at
that age or after the second commit. An in-flight operation keeps its existing
deadline and cancellation checks. Idle time and an incompatible room or context
command flush sooner. Reserved disconnect and shutdown can discard pending view
work and leave the room stale; they never replay a committed effect.
Delegated and approval sends, confidential conversations, focused history,
background-room sends and unsupported view paths retain their immediate refresh.
The existing finite metadata turns and five-second cadence continue between
commands, and a targeted pull supersedes its matching partial room assembly.
Unrelated room-list, account, service, grant and agent metadata wait
until the existing full-refresh deadline. The affected-room pull retains current
room authorization, filtered history and restriction inspection; focused history
also receives its current context check. Membership and policy mutations still
invalidate their retained views and perform a full refresh. The command
completion and exact committed delivery remain successful; the affected views,
inspection and privacy become stale. `ViewRefreshFailed` reports the separate
view failure without attributing it to the effect request, and normal connection
failure and reconnect rules still apply. The warning clears when a current
online view is restored. Partial failure of a compound command remains an error,
with each earlier confirmed delivery retained independently.
Network and database work never run in a widget or terminal input callback.
Disconnect closes the active stream and publishes Offline with stale room and
inspection state and no active privacy badge, even when the worker is idle.
Shutdown joins the bounded worker.

## Local state and reconnect

Drafts preserve text and up to 16 stable mention spans in one guarded transaction.
Saving a draft does not require current authority. A mention contains an account
identity and UTF-8 byte range, aligned to complete Unicode graphemes. Sending
checks the current room membership and exact nickname represented by that span.
A renamed account causes an explicit conflict; text does not retarget another
account with the old nickname. Plain unselected `@text` has no notification power.

Received events and their verified room/access cursor commit atomically. The
local archive holds at most 4,096 events and 16 MiB of encoded event data, with a
seven-day content retention window. A selected snapshot contains at most 256
events. The archive is a bounded local copy, not a complete service backup.
Conflicting event identities or ordering positions fail without advancing the
cursor. Preferences and candidate approvals share the encrypted store. Community search results are bounded transient views. Encrypted conversations
use a local index inside the endpoint SQLCipher store; the service receives no
plaintext index.

Cached views explicitly show stale status until current filtered history is read.
Resume uses the service's current membership, grant, retention and recipient
filter checks. An expired or changed community cursor can reacquire one current
cursorless page within the original ten-second read deadline. The old community
cache, focused view, search and queued room notifications are cleared before that
read; catch-up does not emit live notifications. Every attempt checks current
authority. A second context change, missing retained history, an impossible
position, or an unclassified persisted gap remains explicit and needs recovery.
Disappeared or unjoined rooms lose cached events. A transport failure
keeps drafts, retained history, its signed cursor and exact uncertain outbox bytes.
A transient authority/availability refusal cannot fabricate an access-withdrawal
gap; only explicit denied, expired or resynchronisation outcomes invalidate the
current cached presentation. Reconnect uses capped exponential
backoff with jitter, fresh permission, and original operation resolution.

A committed effect clears a draft only when the stored draft still belongs to
that exact operation ID and action digest. Every later draft save removes that
binding, including a save with identical text or an empty draft. A held send cannot
overwrite a newer acknowledged draft. Rejected and unknown effects retain the
draft. An approval candidate persists its exact signed bytes before exposure. The owner's
inspection exposes its action digest, content, scope and validity. Submission
uses those same bytes; changing content or scope requires another approval.

## Inspection and notification

Account inspection, room inspection, owned filters, active room restrictions,
owned or assigned grants, and owned eligible agent endpoints have typed operations.
Private inspection requires the authenticated account's own target. Delegated
actors cannot use private account inspection to expand their grant. Room details
require current membership and show moderator attribution and expiry. Lists use
bounded pages and explicit continuation positions; these positions confer no
permission.

Preferences include dark/light theme, compact/comfortable density, text scale from
0.75 to 2, quiet mode, sound, terminal ambiguous character width, and per-room
all/mentions/off notifications. Mentions use stable account bindings. Ignored or
muted actors produce no local notification. Catch-up after connection does not
emit notification bursts. Sounds are emitted only when both global and room
preferences permit them. A current filter update immediately refilters live and
focused history, search results and queued notifications, even if a later view
read fails. Muting suppresses notifications without hiding retained history.
Explicit denial of a focused context removes that context; a temporary failure
retains it with stale status.

Search cancellation uses the existing authenticated stream. One query can be in
flight, with at most one exact correlated cancel request. The service registers
that query before execution, verifies the control's signature and transport
permission, and checks current account authority before returning its result.
The query worker observes a cancellation token. A request without a matching
active query does not report success. The single client reader consumes both
signed responses under the original bounded query deadline, and ignores a result
that the user cancelled. No extra persistent companion connection is required.
Cancellation shares the service's bounded FIFO authority admission with ordinary
actions. Later requests cannot overtake it; it receives no permission bypass.
Both its initial transport check and its subsequent Home admission retain the
original query deadline, and no authority slot is held while Home work executes.

The cache schema uses version 2, migrating version-1 filters into the original
local service. Draft migrations preserve text and add
an empty mention list to the known earlier three-column table. The independent
`HRC.ClientDraftBinding.Schema.1` migration adds a nullable exact-send binding.
Older drafts remain unbound; resolving an old outbox action cannot claim ownership
of them. Unknown schema or corrupt encrypted state is refused; opening never
resets a database or guard.

`hrc service init --motd 'Welcome to this service.'` stores an optional message of
the day in the private service configuration. The default is empty; the maximum
is 1,024 bytes of validated protocol text. Authenticated `ServiceInspect` returns
this text only, without automatic platform, version, clock or address disclosure.
The controller exposes the authenticated value as `Snapshot.motd`.

`Snapshot.completions` retains the last 64 queued command completions. Each entry
binds the local request number to success or its stable error. A draft save can
therefore be acknowledged before switching rooms or closing an interface without
confusing it with message delivery. Shared presentation tracks each edit revision
and retires completed save requests. A delayed save or send acknowledgement cannot
claim a later revision, even when text or selected mention spelling is identical.
Room and event-context navigation waits for the latest old-room draft to be saved.
The composer visibly pauses only while the dispatched navigation is pending,
then resumes on success or failure. Disconnect and search cancellation use their
reserved control flags rather than waiting behind the normal command queue.

`OpenEvent` requests `HistoryContext` from the service under current room,
delegation, retention and recipient-filter rules. The response contains the
requested event and up to two neighbouring ordering positions on either side;
representation bounds may omit neighbours but never the requested event. The
selected view exposes `focus` and shows this authenticated context. Selecting the
room again returns to its live/resume view. Context reads do not rewind the
persisted resume cursor or fabricate surrounding messages from the cached tail.

An unresolved effect can be explicitly abandoned with its exact operation ID
and action digest. This stops automatic resubmission; it does not retract a
message, erase its immutable request, or assert rejection. The outbox exposes
`abandoned: true` and retains the unknown outcome. `ResolvePending` can still
query that identity and record a later authoritative result without resubmitting
it. Reconnect automatically resolves active retries only. Active retries remain
limited to 32, abandoned unresolved records to 256, and their combined exact-byte
storage to 8 MiB. Exhaustion is explicit. CLI `abandon --profile ... --window ...
--operation ... --action-digest ...` performs the same local transition.

The [deterministic service bot](ServiceBots.md) uses the same current session,
signed operations and exact outbox. Its separate durable trigger cursor and
planned reply commit atomically, so transient interface notifications are never
used as persistent automation progress.


## Confidential conversations

`prepare_send` first reads current room metadata. Community text and encrypted
messages take distinct typed paths before any content is transmitted. Encrypted
sends verify pinned contacts and the current endpoint roster, then atomically
persist the MLS sender state, exact ciphertext Action and ordinary outbox. The
internal `prepare_send_with` also accepts a transaction-local finalizer for the
bot's cursor/plan. It cannot perform network I/O. Preparing a candidate with an
approval ID marks its outbox record held: reconnect never submits it automatically.
`submit_candidate` requires the exact currently approved digest and grant before
releasing that held record. Explicit abandonment retains an honest unknown outcome.

`CryptoEnrol`, `CryptoPublish`, `CryptoInitialise`, `CryptoCommit`, `CryptoSync`
and `CryptoInspect` operate through the same current session and guarded store.
Private groups and confidential direct rooms have explicit invitations; membership
alone does not import prior keys. Each explicit package publication creates a fresh
one-use package, bounded to 64 unused local packages. Exact uncertain publications
are resolved before another is prepared. Successful MLS transitions and their
verified rosters share one commit; a missing future epoch produces an explicit
gap. Epoch-ready acknowledgement is sent only for the selected latest epoch and
an endpoint currently eligible for live content.

Encrypted history can restart one stale access cursor within its existing
eight-request catch-up bound. A missing-history or impossible-position gap stays
explicit and does not trigger that restart. Cursor gaps and explicit
resynchronisation retain MLS state, pending transitions and already decrypted
local content under the local retention policy. Current history windows and
filters still govern presentation; acknowledging a gap cannot recover missing
keys or confer access.

The shared `Client::resynchronise_history(room)` operation explicitly clears a
local history gap and continuation. It preserves encrypted archives, MLS state,
drafts and exact pending effects; it does not fetch content or authorize access.
Controller Resynchronise, `/resync` and bot `--resynchronise` use that operation.
For CLI encrypted history, use `hrc crypto sync --profile PATH --room ROOM
--resynchronise`. Omit the flag for ordinary synchronization. Resumed reads still
check current room, grant, device and transport authority. A failed explicit
CryptoSync exposes any persisted gap in the selected view and its recovery control.

The selected room exposes an encryption view, exact roster, pending packages,
barrier and contact trust status. `TrustContact` accepts an exact displayed anchor
and its legacy/nonlegacy classification. New registration anchors require explicit
acceptance too. Public continuity records are replayed cryptographically; a pinned
anchor and prior head cannot be replaced by a home-only assertion. Historical
transition evidence permits verification of former participants within current
history rights. Separate MLS keys are generated for each enrolled endpoint.

`RoomView.content`, `SearchView.content` and `ConversationPage.content` hold local
plaintext or a precise rejection separately from the unchanged authenticated
Event. Serialized content maps use the original message ID as a hex text key.
Encrypted approvals use the same principle, keyed by exact candidate action digest.
Inspection decrypts a candidate once; approval requires inspectable valid content.
Matching delivery consumes the saved preview rather than advancing the receive
ratchet a second time.

Online `history_messages`, `search_messages` and `message_context` apply current
room/grant/filter rules. Search and context use only already decrypted local copies,
including permitted past-only grants, without requiring current live admission or
new history keys. `search_retained` is an explicit offline operation with stale
status. Results retain the original authenticated event and message identity.
The local FTS index, plaintext and consumed delivery copy expire with the event.
Unresolved outbox/approval records have bounded explicit retention until resolution;
no expiry is reported as successful delivery or authoritative rejection.


The private encryption-view cache stores the remote snapshot and each contact as
separately bounded canonical objects. A full 256-entry filter list can coexist
with 256 contact views without exceeding the protocol parser's recursive-node
budget. The aggregate cache record remains bounded to 256 KiB; each contact is
bounded to 2 KiB. Capacity is checked before dependent contact or crypto effects.
The public view remains structured data for the interfaces.

CLI history and search return `ConversationPage` with original `events`, separate
local `content`, cursor and access state. Agent inspection returns `GrantPreview`
with its grant inspection, exact candidates and decrypted proposal content.
Preflight permission failures report `OperationDenied` or `OperationExpired`;
temporary non-admission reports `OperationTemporarilyUnavailable`. These failures
do not claim that a message was committed or delivered.

## Federation service selection

An endpoint keeps its original account, signing key, recovery model and HyperNet
companion. Selecting a foreign room home first authenticates the endpoint to its
origin service. The origin then forwards a separate signed bootstrap through an
independently admitted destination companion. The client verifies the remote
home signature, exact request digest, endpoint binding and home retry window.
A foreign home cannot replace the endpoint's origin account or key.

Import the two service descriptors through a deliberate trusted exchange. The
agreement's embedded keys do not establish those trust pins. Both administrations
must sign the same agreement. The following command stores those signatures and
selects the foreign home for subsequent CLI, GUI, TUI and bot sessions:

```sh
hrc federation client-select --directory PROFILE \
  --home-descriptor HOME_DESCRIPTOR --origin-descriptor ORIGIN_DESCRIPTOR \
  --home-signature HOME_SIGNATURE --origin-signature ORIGIN_SIGNATURE
```

Use `--trust-only` on a home-side client to verify the remote participants'
origin continuity without selecting a foreign home. At most two bilateral
agreements are retained in one profile. Profile input is bounded to 1 MiB,
including encoded signatures; each agreement retains the ordinary wire bounds.
Registration profiles without federation fields remain compatible.

The GUI connection details list the configured conversation services. The TUI
and GUI accept `/network local` and `/network AGREEMENT_ID`; `/who` lists the
choices. Switching services closes the current stream, preserves drafts and
uncertain operations under their original home, and authenticates a fresh
session for the selected service. CLI clients can select their origin again with
`hrc federation client-local --directory PROFILE`. Origin-owned account and
endpoint administration use the local selection. No network route is inferred
from an account identifier or silently replaced by a direct connection.

Room caches, active ignore/mute lists and retry selection are scoped to the home
service. Switching does not erase another home's retained rooms or drafts. The
aggregate cache and outbox limits still apply. The filter-schema migration moves
existing filters into the original local service exactly once.

Privacy details distinguish the endpoint's transport observation from the source
and destination leg observations verified at remote admission. Admission is a
historical observation; both current permissions are checked again for every
forwarded action. Disconnect clears the displayed admission observations. The
client does not assert physical relay-operator independence from these receipts.
`hrc profile session` includes the signed remote-admission fields as structured
output alongside the ordinary endpoint transport properties.

A remote query owns one serial gateway stream. Cancelling it closes that stream
and propagates bounded cancellation to the home query. The client discards that
query result and reconnects with current permission; it does not report a
home-signed cancellation outcome or replay the query as a mutation. Other clients
retain their own streams. Pending sends keep their exact durable identities and
are resolved separately after reconnect.

Encrypted remote contacts require independently pinned origin service evidence
and the same explicit contact-anchor acceptance as local contacts. A foreign
owner's grant proof selects its signed origin continuity head. The home grant
position is never compared with an unrelated origin history position. Origin
assertions and exact owner-signed grant bytes remain bound to that checkpoint.
