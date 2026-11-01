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
The five-second background refresh interval starts after a successful refresh
finishes, including initial connection and explicit commands. A slow refresh does
not schedule an immediate second full refresh.

The command queue contains at most 32 bounded commands. Dispatch returns a local
request number. Immutable snapshots carry that number on command status and
operation delivery records. A frontend can distinguish the exact submitted text
from later typing. Historical recovered operations have no local request number.
Network and database work never run in a widget or terminal input callback.
Disconnect closes the active stream; shutdown joins the bounded worker.

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
filter checks. An expired or changed access cursor produces an explicit gap;
resynchronisation discards the invalid cached presentation and starts a current
history pull. Disappeared or unjoined rooms lose cached events. A transport failure
keeps drafts, retained history, its signed cursor and exact uncertain outbox bytes.
A transient authority/availability refusal cannot fabricate an access-withdrawal
gap; only explicit denied, expired or resynchronisation outcomes invalidate the
current cached presentation. Reconnect uses capped exponential
backoff with jitter, fresh permission, and original operation resolution.

A committed effect clears its submitted draft only after the service's durable
response has been recorded. Rejected and unknown effects retain the draft. An
approval candidate persists its exact signed bytes before exposure. The owner's
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
preferences permit them.

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

The cache schema accepts version 1 only. The draft migration adds an empty mention
list to the known earlier three-column table, preserving text. Unknown schema or
corrupt encrypted state is refused; opening never resets a database or guard.

`hrc service init --motd 'Welcome to this service.'` stores an optional message of
the day in the private service configuration. The default is empty; the maximum
is 1,024 bytes of validated protocol text. Authenticated `ServiceInspect` returns
this text only, without automatic platform, version, clock or address disclosure.
The controller exposes the authenticated value as `Snapshot.motd`.

`Snapshot.completions` retains the last 64 queued command completions. Each entry
binds the local request number to success or its stable error. A draft save can
therefore be acknowledged before switching rooms or closing an interface without
confusing it with message delivery. Disconnect and search cancellation use their
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
