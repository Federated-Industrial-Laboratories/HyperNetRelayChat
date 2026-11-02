# Native conversation qualification

`NativeLoad.py` and the `native-load-client` example provide the separate bounded
pilot/load workflow. Select `configuration.loadOnly=true` or
`HRC_NATIVE_LOAD_ONLY=1`, and supply `configuration.loadClientBinary` or
`HRC_NATIVE_LOAD_CLIENT`. It uses the existing real Alice/Bob/Agent companion
prerequisites. This selection is exclusive with the local/confidential-only
workflows and does not rerun or claim their functional evidence.

The shipped CLI creates twelve distinct HRC accounts, endpoint keys and profiles:
eight interactive users, two independently identified agents, and two operator
users. The agents have explicit operator bindings. Ten human profiles share the
Bob outgoing HyperNet application; two agents share the Agent application. Alice's
application receives the twelve service streams. These are two distinct client
HyperNet principals, not twelve independently administered devices. One operator
owns and moderates the test room; the second holds a separate authenticated
stream. The two transition slots and two federation slots remain unoccupied.
Simultaneous federation capacity requires separate evidence.

The isolated HyperNet fixture selects sixteen concurrent connections in both its
relay and application route profiles, with matching signed admission and memory
consent. This accommodates the twelve HRC streams and retained fixture transport.
The generic eight-connection route defaults cannot run this topology. Finite
voucher connection allowance and the companion's sixteen-stream ceiling are
separate limits; neither overrides a lower route profile. These are explicit
fixture policy settings, not changes to HyperNet's capacity implementation or
HRC's performance thresholds.

After room setup, all eight interactive Client instances release their streams
and SQLCipher Store ownership. The production Controller then opens each of those
same profiles, connects and selects the room. The helper waits for all eight
current room views, inspection state and privacy observations. Their ordinary
background refresh remains enabled throughout both measurements. The remaining
four profiles retain one Client owner each; no profile is opened twice and the
transition adds no companion slots.

The Rust helper has an original 360-second deadline inside the unchanged
900-second outer fixture, with time retained for process cleanup. It measures a
30-second baseline and a 45-second overload period. Five Controllers receive
one send command each second, staggered by 200 milliseconds. The schedule keeps
offering commands while earlier work is queued. Queue refusals and missed
scheduled offers are counted instead of slowing the offered schedule. Every
normal offered message must commit within the measurement window; missed,
refused, unknown or late outcomes fail the throughput gate. The reported p95
includes scheduled waiting and all Controller work before the committed delivery
becomes visible, including preflight, durable outbox and earlier queued work.
Confirmed durable deliveries are published before trailing view reads finish;
current room views remain a separate requirement for every Controller. The p95
must remain below 500 milliseconds. Each request ID is bound to its observed operation
ID and digest; an unrelated completion cannot count as its commit. All eight
Controllers must also receive fresh messages from another account and finish
with current selected-room state. State durations and snapshot revision counts
are reported; revision counts are not presented as transport request counts.
The helper cannot pass by reducing offered load or ignoring rejections.

During overload, one agent offers up to ten signed protocol sends per
second and the other agent offers two bounded sixteen-term searches per
second. Each hostile stream has at most one operation in flight; offers missed
because of its response time are counted. The eight Controllers remain active.
The spare operator sends sixteen authenticated history requests, withholds reads for
twelve seconds and then drains only bounded, request-bound signed responses.
HRC uses authenticated pull delivery; this measures an unread response stream,
not an unimplemented push fan-out queue. The moderator silences and unsilences
the flood actor during the phase; both commits must take less than one second.
A pass requires the flood to exercise actual rate/overload refusal and the
active silence restriction, as well as the unaffected-client targets. A transport
or local failure that stops either hostile schedule invalidates that overload
measurement, even if earlier offers received the required refusals. Disconnecting
an abusive stream may be a legitimate service response; the helper cannot use the
remaining interval without that pressure to claim sustained-load qualification.

Recipient ignore is enabled before the flood and rechecked through history and
indexed search, with an unfiltered search proving the retained marker exists.
The eighth Controller must never display an event from that ignored flood actor.
Four subsequent connection openings and closures test bounded churn while an
unaffected endpoint commits messages. Typed temporary admission refusals are
recorded; the helper does not infer a particular connection rate policy from them.
Additional authenticated streams receive a malformed CBOR frame
and an oversized length header; observed closure must be distinguishable from a
local timeout or authority failure. Two real agent identities exercise repeated
causal-trigger rejection and the maximum four-effect depth. Default bot
response suppression, notifications, Unicode editing, confidential conversation
and federation behavior retain their separately identified functional evidence;
the load helper does not claim to repeat them.

Normal sends use the actual Controller command and durable Client path. Staging may retry
only the exact saved operation identifier and digest, through product resolution
and matching certified absence. The helper never redispatches an offered send;
the production Controller retains and resolves its original uncertain effects.
During setup, a temporary refusal of an outcome-resolution query keeps the
original effect pending and uses the original setup deadline. A resolver rejection
or unknown result fails setup with a separate bounded diagnostic; it cannot be
reported as the original effect's completion. Only the production client can
resubmit the original bytes after a verified absence result.

Startup emits connection-dispatch times and at most eight observed state changes
per Controller, using host boot milliseconds for correlation with transport
logs. These are published snapshot observations, not internal request timings.
They include connection state, inspection staleness, privacy presence and whether
the selected room is current. They contain no account IDs, room IDs, message
content or keys. Startup logging does not change admission, polling cadence,
retries or measurement bounds.

Deliberately hostile protocol offers
use the authenticated Session submission API without a durable retry loop.
Recovery waits for the original offered effects to resolve, then submits one new
marker through each sending Controller. All eight Controllers must become current
and receive a remote recovery marker. Its thirty-second measurement starts at attack stop,
including any wait for authority/transport health; a slow prerequisite does not
silently move that clock.

The parent samples only the HRC service's `/proc` RSS and thread count every
200 milliseconds. Peak RSS must remain at or below 512 MiB; HyperNet and helper
processes are excluded and thread count is reported without an invented limit.
Each phase emits bounded JSON metrics before evaluating its result. Failures,
partial output, output caps and the final service shutdown remain inspectable.
Controller wire bytes are not observed. Supporting-session signed request sizes
and decoded response sizes exclude hidden preflight traffic,
response COSE overhead and HyperNet transport overhead. The slow-reader and
invalid-frame cases separately report directly observed frame or byte counts.
Internal queue occupancy, link saturation and total network amplification are
not observable here and are explicitly unqualified. No product limits change
when a measured threshold fails.

`NativeConversation.py` drives the shipped HRC CLI against three independently
admitted HyperNet principals: two humans and an agent. The fixture provisions
real Core/Suite application service consent, service-scoped grants, retained
routes and running companions. It does not replace HRC operations with SDK calls.

The driver creates a home service, invitations and endpoint profiles through the
CLI. Recovery keys are generated by HRC and stored separately from profiles.
It exercises room membership, Unicode text, persistent indexed history,
independent and delegated agent attribution, scope denial, pause/resume/revoke,
expiry, recipient ignore and room silencing. It restarts the service and checks
that history and message identifiers remain stable.

One isolated acknowledgement-loss case uses `CompanionFault.py`. The fixture
temporarily moves one outgoing companion to a sibling private directory and
places the proxy at its original local socket path. The proxy forwards exact
control requests and responses, real verified peer context, and HRC payloads.
After explicit arming it discards one complete HRC Response frame and closes the
connection. It never creates identities, authority evidence or service results.
The driver verifies the actual committed event, the client's durable unresolved
outbox, service restart, exact resolution and absence of duplicate publication.
The ordinary companion is restored afterwards. Baseline conversation uses no
proxy.

`NativeLocalClient.rs`, built as the `native-local-client` example, optionally
extends this same fixture with the production Controller used by the local
interfaces. Set `configuration.localClientBinary` or
`HYPERNET_HRC_LOCAL_CLIENT` to its exact executable path. The hook runs after
acknowledgement-loss recovery and before final HyperNet grant revocation, using
the existing Alice, Bob and Agent profiles and live service. It opens one Store
owner per profile; no CLI process accesses those profiles concurrently.

For independent local-client qualification, set `configuration.localClientOnly`
to true or `HYPERNET_HRC_LOCAL_CLIENT_ONLY=1`. This mode creates the real service,
three profiles and one room through shipped commands, joins Bob and Agent, then
runs the Controller immediately. After all Controller profiles close, it creates
and revokes an exact fixture grant, runs the same bot cases and final HyperNet
authority refusal. Its result is `NativeLocalClientWorkflow`, with
`conversationBaselineIncluded=false`; it does not claim to rerun the separate
conversation baseline, acknowledgement-loss or service-restart cases. Reuse their
identified existing evidence only when that source and behaviour remain applicable.

The example checks persistent Controller send/receive, three distinct identities,
request/completion and delivery/event correlation, Unicode typed mentions,
unread state and mention notifications, current ignore filtering, indexed search
and current-authorised event context. It saves a draft while disconnected,
releases and reopens Bob's profile, verifies cached state is marked stale, then
resumes current history without duplicate event IDs and sends the retained draft.
Commands are submitted once and results are asserted through actual immutable
snapshots. The helper does not resubmit uncertain effects.

Initial connection may complete with `OperationTemporarilyUnavailable` while the
Controller reconnects automatically. The helper waits for `Online` with current
inspection and privacy state within the original 40-second command budget; it
does not dispatch another Connect. The same transient status from SelectRoom
must recover the original selection to a current room view without a gap, Online
connection, current inspection and privacy within that command's original bound.
The helper does not dispatch another selection. Successful offline selection
still exposes stale cached state. Other command errors fail the check. A send
with a visibly pending delivery may recover only if the same request, operation
ID and Action digest become committed through the Controller's own resolution.
Permanent refusals, abandonment and replacement identities fail. Evidence counts
observed backoff entries, recovered selections and resolved original deliveries, and claims zero
helper resubmissions, not zero internal retries. Failure diagnostics name the
principal, command and last visible status, with bounded native service logs
providing the individual read-operation category when available.
The helper retains at most sixteen observed connection/status transitions per
principal, with boot time, command stage and request number. A failure therefore
distinguishes waiting before dispatch from waiting for a specific completion.
The trace contains no message content, keys or permission evidence and does not
change deadlines, retries or effects.

Cancellation is attempted while a real query is visibly running. Evidence says
whether cancellation was observed or completion won the race; it does not claim
that a small native query was interrupted inside SQL. A subsequent search checks
that request/response correlation remains usable. This verifies the shared client
workflow, not GUI rendering, terminal interaction or desktop notification delivery.

The example accepts `--request FILE --maximum-seconds 240`. The private JSON file
contains `alice`, `bob`, `agent` profile paths and the typed `room` ID. Input is
limited to 16 KiB, one command queue is used per Controller, and observed snapshots
are checked against their bounds. Command/result waits are at most 40 seconds;
a process watchdog and the parent subprocess timeout enforce the total limit.
The optional run consumes the existing 900-second conversation budget. Build it
from the same frozen candidate as HRC with `cargo build --example native-local-client`.

The optional extension then releases all Controllers and starts the shipped
`hrc bot` on the Agent profile, with a one-second poll interval and a unique fixed
help response. It waits for the exact `BotReady` result whose meaning is
`InitialAuthorisedCatchUpComplete`. A historical human `!help` must produce no
reply; one new Alice `!help` must produce exactly one independently attributed
agent `MessageReply`, with parent and causation both naming that exact event.

After a bounded clean stop, the ordinary CLI publishes an agent `!help` and a
human reply containing `!help`. No process shares the Agent profile while the bot
runs. The check crosses the documented five-second reply-rate window before
restarting, so throttling cannot mask a trigger-rule failure. Restart readiness
proves a current authorised catch-up; unchanged reply IDs then establish agent
and reply suppression without replay. A final bot invocation with the existing
revoked fixture grant must explicitly refuse before readiness and publication.
This extension has a 180-second budget within the same conversation deadline,
and cleanup terminates only its own child process, escalating to a bounded kill
if needed. Readiness and history assertions establish progress; timed waits are
used only for polling and the documented reply-rate boundary.

The final refusal case revokes the agent principal's actual HyperNet stream
grant. The shipped send command must refuse connection, preserve its local draft
and leave no corresponding conversation event. No direct connection is provided.

The external fixture calls `NativeConversation.run(configuration, controls,
record)`. Configuration supplies an exact executable path, a fresh private work
directory, the real home network/incarnation/service, a current signed HyperNet
clock-export path and pinned monitor key, and each companion's private path and
authenticated principal. Controls provide only `begin_ack_loss`, `end_ack_loss`
and `revoke_principal`. Record accepts bounded result dictionaries for the
qualification report. Every subprocess has a deadline; service and proxy cleanup
runs even after a failed assertion. Never point this destructive finite fixture
at ordinary user profiles, installed services or production grants.

Set `configuration.suiteBinary` or `HYPERNET_HRC_SUITE_BINARY` to the exact installed
Suite executable for failure diagnostics. Before teardown, the driver uses the
supported `streams status` command to retain each companion's at most eight recent
errors and connection count. Collection is limited to six seconds in total and
the remaining conversation deadline, with at most two seconds per companion.
Diagnostic failure does not replace the original workflow failure. CLI result
records include boot-time start and finish; connection-preparation stderr retains
the static adapter failure category. No diagnostic triggers another effect or retry.

The baseline qualifies community conversations. The optional confidential helper
below adds native encrypted client scenarios. Independently administered
federation requires its own real integration scenario before release. A helper's
presence or successful compilation is not a passing qualification result.


## Confidential conversation extension

Build `cargo build --example native-confidential-client` from the same candidate
as the service and CLI. Select its exact executable with
`configuration.confidentialClientBinary` or `HRC_NATIVE_CONFIDENTIAL_CLIENT`.
This selector is independent of the Controller extension. The helper runs after
the baseline and optional Controller/bot scenarios, before final HyperNet grant
withdrawal. No process shares its Alice, Bob or Agent profile while it runs.
The private request contains `alice`, `bob`, `agent`, the typed existing community
`room` identity, and `bobRecovery`, the separately held fixture owner-key path.
The key is used only by the production device-proof API and never enters output.

For independent confidential qualification, select `configuration.confidentialClientOnly`
or `HRC_NATIVE_CONFIDENTIAL_ONLY=1`. This mode uses the same shipped CLI setup,
three profiles and room joins, then runs the confidential helper and final actual
HyperNet authority refusal. It reports `conversationBaselineIncluded=false` and
does not rerun unrelated baseline or Controller scenarios. It cannot be combined
with local-client-only mode. Its original overall and per-step deadlines remain.

The helper uses public production Client APIs and the profiles' real admitted
HyperNet sessions and signed clock. It creates and joins an explicitly invited
private group; each endpoint generates its own MLS key. It explicitly accepts
inspected nonlegacy account anchors, publishes one-use packages, commits the
membership transition, processes Welcome and verifies the selected epoch.
A multilingual message with a stable account mention must decrypt without
rewriting the authenticated Event body. Replaying the exact retained ciphertext
Action must resolve to the original event. Closing and reopening Bob's store must
preserve locally indexed content; offline search is stale, and online search
rechecks current authority. Active recipient ignore must remove that content
from current search presentation.

A fresh scoped autonomous grant adds the agent as a delegated MLS leaf. Earlier
plaintext must remain unavailable to that new endpoint. A new delegated encrypted
message must preserve its represented account and exact grant attribution.
Revocation must establish a send barrier and required removal; an already prepared
old-epoch send must be durably rejected without publication. Only the verified
removal transition restores sending. A separate invited confidential direct room
then completes the same actual encrypted send/decrypt path.

The device scenario authorizes and activates an exact new endpoint, verifies its
independent encrypted state, then disables it. Owner-key recovery replaces Bob's
old endpoint generation and must establish the encrypted-room removal barrier.
After the old leaf is removed, the recovered endpoint explicitly requests and
receives future-message admission. Earlier ciphertext remains available under
room policy, but its plaintext is unavailable; a new message must decrypt.
Device retries retain the same signed request and original step deadline.
Participants that return after another participant's workflow open a fresh session
before their next read or effect preparation. These connections require current
HyperNet permission within the original step deadline. A revoked delegated read
is checked on the independent endpoint's fresh session so a closed idle stream
cannot stand in for the required permission refusal.
Current inspection, history, online search and encrypted synchronisation share
bounded recovery for typed transient failures within the original step deadline.
Session recovery uses the production client; synchronisation retains the client's
exact readiness outbox operation. Contact trust is written once after a successful
current inspection. Retained search remains offline.

Each scenario operation has a 45-second watchdog. The total defaults to 600
seconds, bounded by the driver's remaining conversation budget; the parent adds
a subprocess deadline. Two-second pacing precedes operations to respect the
crypto-account burst/refill budget. Explicitly prepared operations can recover
only their original Action ID, digest and signed bytes through the production
resolver. The helper never recreates an uncertain effect with a new ID. A
high-level crypto method that cannot expose its original operation after failure
causes the scenario to fail rather than be blindly redispatched. Diagnostics name
only principal, operation and bounded status; they contain no keys or chat text.
The helper does not read private SQL state or manufacture protocol authority.

The current CLI returns `ConversationPage` directly for `history` and `search`,
and `GrantPreview` directly for `agent inspect`. The driver checks these exact
shapes. Delegated send preflight rejects denied/expired access with the exact
`OperationDenied` or `OperationExpired` failure code and separately verifies no
matching event was published. Availability, malformed input and unrelated failures
cannot satisfy those refusal cases. The prior M4 qualification tree and its
recorded results remain separate from this updated candidate.

## Two-network federation extension

`NativeFederation.py` receives two independently administered installed HyperNet
contexts. The maintained installed fixture creates separate bootstrap identities,
administrators, voter sets, authority endpoints and native Suite companions. It
uses eight authority containers and the existing bounded route and application
services. Both networks can run on the same qualification host; this does not
establish independent host failure domains. Durable authority and HRC stores stay
on disk. Only signed, boot-bound clock observations may use the qualified ephemeral
clock directory.

Build `cargo build --example native-federation-client` from the same candidate as
the normal binary and set `HRC_NATIVE_FEDERATION_CLIENT` to its exact executable.
The installed runner selects this workflow with `--hrc-federation`. It does not
run the single-network conversation or Page federation workflow first. The helper
uses the shipped CLI to create both HRC services, independently enroll Alice,
Bob and Bob's agent, create separate gateway/attestor keys, exchange descriptors,
sign matching agreements against explicit pins, import bounded owner-continuity
pages, approve exact endpoints and install the destination companion route.
A setup-only agreement has no rooms; its next revision explicitly shares the
community room, private group and direct conversation. Client selection retains
the origin account, endpoint keys and origin HyperNet companion.

The Rust helper uses real Client APIs and sessions for remote human and
independent-agent messages, foreign delegated scope, encrypted private-group and
direct conversation membership, explicit contact pinning, Unicode mentions,
restart of the local encrypted index and current recipient-ignore filtering.
It verifies exact ciphertext replay and original event identity. A signed action
with a substituted origin is sent over the actual endpoint stream; its refusal
must be signed and correlated by the origin, and history must show no effect.
A short-lived delegation must expire without publishing its prepared operation.

Two private control markers request stopping and restarting the origin service.
After its original five-second identity lease expires, a local sender must receive
a non-consuming availability refusal for an already prepared ciphertext. The
room retains its MLS roster. Restarting the origin must renew the lease through
the real gateway; retrying the exact ciphertext must yield one event. The helper
then performs owner-key recovery at the origin and waits for the running service
to publish the changed checkpoint automatically. No manual proof import occurs
in this scenario. The home must establish the old endpoint's removal barrier and
refuse its queued old-generation operation. Bounded private controls then stop
the services for explicit operator admission of the new endpoint. The CLI exports
the origin's exact current checkpoint identifier and admits it at the home; this
must fail if the running origin had not already imported that checkpoint. There
is no manual identity-import fallback. The new profile selects the same bilateral
agreement, authenticates with its new endpoint key and retains the same account.
Both encrypted rooms remove the old MLS leaf and explicitly admit a separately
generated replacement key through package, commit, Welcome and Ready. The home
participant retains the original contact anchor. Earlier ciphertext remains in
permitted history without becoming decryptable by the recovered endpoint, while
new messages must decrypt in both the private group and direct conversation.
The separately held recovery key is loaded only through the production device
API and never printed. Control requests carry the original step's boot deadline;
CLI admission shares that deadline, and no restart extends the overall budget.

After clients release their stores, the shipped withdrawal command durably stops
the origin and requests the home's signed acknowledgement. The driver checks the
actual home barrier through stopped-service inspection. After the origin restarts,
the previously eligible independent agent must receive the signed, correlated
`AgreementWithdrawn` refusal; its retained draft survives and home history contains
no corresponding event. Gateway status samples
record observed connection identities and reuse; these samples are explicitly
not a complete connection census. Existing 16-concurrent and 128-total fixture
connection limits remain unchanged.

The Rust helper has a 45-second per-step watchdog and a bounded overall budget,
with two-second operation pacing. Exact retries retain the original ID, digest,
signed bytes and deadline and respect supplied retry guidance. High-level crypto
failures are not blindly repeated. Current inspection, history, online search and
encrypted synchronisation recover typed transient failures within the original
step deadline, using the production client for session and exact readiness outbox
recovery. Contact trust writes follow a successful inspection once; retained
search remains offline. Recipient readiness polling shares that same deadline.
The Python owner has its own fixture deadline and exact process cleanup.
Successful compilation is not a native qualification result; the first two-network
run remains required before release.
