# Federation runtime contract

This is the implementation contract for the first bilateral HRC federation
profile. It extends the [integration profile](IntegrationProfile.md),
[wire protocol](WireProtocol.md) and [permission model](ProtocolPermissions.md).
It covers remote human, independent-agent and delegated-agent participation in
community rooms, encrypted direct conversations and encrypted private groups.
Each shared room has one authoritative home service. There is no onward
forwarding, third-network origin, replicated writer or direct Internet fallback.

The home/domain implementation includes the signed objects, dual-signature
agreement acceptance, explicit remote admissions, verified origin continuity,
purpose-bound bootstrap and shared local/remote execution. Tests use two guarded
home stores and actual signatures, delegation and MLS operations. Transport
evidence in those domain tests is synthetic: it does not establish that both
HyperNet legs work. The gateway and client paths are implemented. Real two-network
qualification must complete before this document can describe a shipped or
qualified federation runtime. The ordinary local handshake still authenticates
locally enrolled endpoints only; remote execution has its own verified context.

## 1. Roles and the two transport legs

An origin endpoint reaches its origin HRC service through HyperNet A. The origin
service uses a separate application principal and companion, independently
admitted in HyperNet B, to reach the room's home HRC service. Both legs carry
actual HyperNet application streams. The second companion belongs to B; passing
a foreign service ID to A's companion does not create a cross-network route.
The gateway process may hold both local companion handles, but neither network
membership nor application consent is inherited from the other handle.

The home-to-origin response travels over the established duplex stream. Rooms
whose home is on the other side require the separately configured reverse
direction. A return response is not a new room event or a second send effect.

| Role | Authority and authentication |
| --- | --- |
| Endpoint | Signs its immutable home-targeted Action with its enrolled HRC endpoint key; its source transport principal must match its origin binding. |
| Origin service | Owns the origin account's endpoint lifecycle, classification, operator binding and continuity records. Its pinned service key authenticates those records and checkpoints. |
| Origin attestor | Explicitly trusted to report a fresh source-side HyperNet check and the current origin identity checkpoint for the exact request. It does not issue home room rights or home grants. |
| Gateway | Proves its independently admitted receiving-network principal and its pinned gateway key. It can carry only the agreed federation exchange, not impersonate a normal HRC endpoint. |
| Home service | Orders room events, remote admissions, retry windows, grants, approvals, restrictions and agreement barriers; signs outcomes and history. |
| Each administration | Independently pins its counterpart and accepts identical agreement bytes. A key supplied inside an agreement cannot establish its own trust. |

Gateway keys, origin service keys, origin-attestor keys and endpoint keys have
separate accepted roles. No signature from one role substitutes for another.
Gateway private keys are not endpoint or account-recovery keys. Normal service
configuration contains an explicit companion path and target service for each
direction; private paths and secrets never become wire fields.

Each receiving gateway handshake verifies the actual incoming network,
incarnation, service, protocol, principal, session and transport generation.
Only an incoming stream can obtain the fresh `checkAuthority` observation.
Configured identities are compared with verified context, never used to replace
it. Missing destination admission refuses the route.

## 2. Encoding and compatibility

All objects use the existing canonical CBOR, SHA-256 and role-separated
COSE_Sign1/Ed25519 rules. IDs, account IDs, service IDs, endpoint actors,
agreement references and operation IDs retain their existing encodings.
`Blob` means a bounded CBOR byte string containing complete canonical signed
bytes. Maps reject missing, unknown and duplicate fields. No compression,
caller-selected public address or embedded executable content is supported.

The required capability is `federation-runtime-1`. The following schemas
complete the previously unused federation primitives; they are not a compatible
reinterpretation of the earlier incomplete federation schema. Implementation
must update the federation wire tables and vectors together. Existing local
Action, endpoint-binding and endpoint-lifecycle objects keep their encodings.
Old or unknown federation profiles fail explicitly; there is no permissive
fallback to ordinary actor authentication.

Runtime federation objects include `profile: 1`. Existing federation COSE roles
10, 11 and 12 remain respectively home challenge, origin assertion and agreement,
with the completed schemas below. New roles are reserved as follows. Their
protected content types are `application/hrc-<name>+cbor;v=1`; signed payloads
retain `[1, role, object]` and the existing `HRC/1` external AAD.

| Role | Name | Permitted signer |
| --- | --- | --- |
| 19 | `gateway-message` | The named gateway for hello/proof; receiving service for challenge/ready |
| 20 | `remote-session-request` | The exact origin endpoint |
| 21 | `remote-session-ready` | The receiving home service |
| 22 | `origin-identity-checkpoint` | The pinned origin service |
| 23 | `federation-control` | Gateway for requests; receiving service for results/proof authorizations; agreement administration for administrative requests |
| 24 | `origin-identity-page` | The pinned origin service |
| 25 | `identity-freshness` | The pinned origin service; bounded identity observation, not endpoint transport authority |

Role-specific tagged variants are closed enums. Verification selects the
expected variant and signer role from the current exchange before interpreting
its payload. A service-signed gateway challenge is not a gateway proof.

Reserve frame 18, `FederationControl`, with the ordinary frame bound. Its payload
is one complete signed role-19 through role-24 object. Frames 9 and 12 retain
ordinary/crypto federation exchange, with runtime payload `[1, envelope]` and
the mandatory profile field. Responses to forwarded Actions remain unchanged
home-signed Response/CryptoResponse frames. The client selects the accepted
home key, not the forwarding origin's key, to verify them.

## 3. Agreement and administration

`FederationAgreement` has these exact fields:

```
profile, id, revision, home, origin,
homeGateway, originGateway,
homeServiceKey, originServiceKey, originAttestorKey,
rooms, notBeforeMs, expiresMs
```

Each gateway field is a `GatewayBinding`:

```
{network, destination, principal, serviceEndpoint, signingKey, protocol}
```

`network` includes incarnation; `destination` is the receiving HRC ServiceId.
`principal` is the gateway's receiving-network application identity.
`serviceEndpoint` is the destination service endpoint from verified peer context,
not an invented caller endpoint. `protocol` is `hrc/1`.
`homeGateway` names origin-to-home admission;
`originGateway` names home-to-origin admission. A runtime implementation must
retain the verified peer endpoint needed for this comparison in its typed
HyperNet context. Gateway identity rotation requires a newly accepted agreement
revision, not a changed local lookup under an old digest.

There are zero to 32 unique home rooms. An empty agreement permits only
administrative setup, identity proof and endpoint bootstrap, never conversation
access. This deliberately completes the earlier draft's nonempty-room check:
it permits identity admission before a new cross-network direct room exists,
without inventing room access. Each room entry retains
`{room, historyFromMs, retentionMs, storage, confidentiality, privacy,
moderatorAccounts}` from the wire contract, with at most 32 moderators. Both
administrations sign the same payload. Room consent is also explicit at the
home. The first profile fixes remote admission as per-endpoint approval and
forbids onward sharing; an agreement cannot weaken either rule.

Remote room discovery uses the current request's exact agreement and endpoint
admission. Each room must also satisfy that agreement's room mode and the privacy
requirements on both transport legs before unread counts, metadata or pagination
include it. An admission under another agreement cannot contribute rooms, even
for the same endpoint and home. A setup-only agreement therefore returns an
empty room list. Local discovery keeps its existing membership, invitation, ban
and recipient-filter rules.

A room identity is bound to one foreign origin service when it is first shared.
That binding survives agreement revision, expiry and withdrawal. An agreement
with a different foreign origin must use a separate room identity, so retained
history cannot become a bridge to a third network. Each service retains at most
1,024 such bindings; exceeding that bound refuses the new agreement without
changing existing authority. Different rooms may use different bilateral peers.

For a first direct room, both administrations can accept that empty agreement,
approve the foreign endpoint with an empty room scope and verify its identity.
A home user then creates the direct room/invitation through the ordinary home
operation. Both administrations accept the next agreement revision naming the
room, and the home explicitly expands the endpoint admission before remote
join or delivery. A private group follows the same create-then-share sequence.
Remote room creation cannot bypass the signed room list. No room invitation,
content, package or Welcome is delivered during the setup-only phase.

`storage: homeOnly` forbids a durable gateway/service transcript at the origin.
It permits bounded forwarding buffers and the endpoint's separately configured
archive policy. `bothNetworks` permits a bounded origin copy under the signed
retention policy, subject to the same current delivery/filter checks. Neither
setting grants plaintext keys for encrypted rooms or overrides endpoint archive
retention. Agreement expiry must not exceed either administration's accepted
consent expiry; HyperNet renewal remains an independent explicit operation.

Codes 80-84 retain their names. Codes 85-89 complete the profile below. Administration
requires a locally authenticated service-administration capability, not an
ordinary room moderator or a gateway acting as an account.

| Code | Operation | Body and result |
| --- | --- | --- |
| 80 | FederationPropose | Reserved transport operation. Current local administration validates and signs an agreement proposal file while the service is stopped; no network proposal handler is enabled. |
| 81 | FederationAccept | Reserved transport operation. Current local administration supplies both signed agreement files and independent pins to guarded acceptance; both signatures must cover identical payload bytes. |
| 82 | FederationWithdraw | `{agreement, request, reason}`; `reason` is a closed enum `administrative`, `expiry` or `identityChange`; returns the signed local stop/home barrier state. |
| 83 | FederationExchange | The exact envelope in section 7; produces the original Action's home-signed response. |
| 84 | FederationChallenge | `{agreement, subject, admission}`; authenticated gateway asks for a purpose-bound home challenge. |
| 85 | FederationAdmitEndpoint | `{agreement, account, endpoint, bindingDigest, checkpoint, rooms, expiresMs, expectedRevision}`; home administration creates or replaces an explicit remote admission. |
| 86 | FederationWithdrawEndpoint | Local administration supplies exact `{id, revision}` admission reference; withdraws that admission and applies dependent barriers. No general gateway mutation is enabled. |
| 87 | FederationIdentityPage | Closed `IdentityTransfer`: `read {account, checkpoint, after, limit, authorization}` returns an origin-signed page; `import {checkpoint: Blob, page: Blob}` updates only already-pinned identities referenced by this gateway's current admissions; `freshness {lease: Blob}` supplies a role-25 observation for exact imported heads. |
| 88 | FederationInspect | Gateway request `{account, endpoint, bindingDigest}` finds one exact current admission under the outer agreement. Local administrative inspection separately reads an exact agreement reference, including expiry/withdrawal. Neither is a public account directory. |
| 89 | FederationSession | `{request: Blob, endpointBinding: Blob, challenge: Blob, originAssertion: Blob}`; completes endpoint bootstrap and returns the home-signed RemoteSessionReady. |

Enabled gateway operations use a `FederationControl` object without inventing
an account actor. Reserved administrative transport codes are explicitly
unsupported; the local stopped-service workflow is authoritative. Its
closed variants are:

```
Request {profile, home, origin, agreement, request, operation, body,
         createdMs, expiresMs}
Result {profile, home, origin, agreement, request, operation, requestDigest,
        outcome, createdMs, expiresMs}
ProofAuthorization {profile, home, origin, agreement, request, account,
                    checkpoint, purpose, expiresMs}
```

`ProofAuthorization` is signed only by the room home; its closed purpose is
defined in section 5. `outcome` is the operation's typed result or a stable error.
Requests expire
within 60 seconds; results bind the original request expiry rather than grant a
new execution lifetime. Authenticated control mutations retain request ID,
digest and
outcome for at least seven days. Changing bytes under an ID conflicts. A
retryable pre-admission failure does not consume the mutation identity.
Code 83 is the transport envelope, not a second Action around the original
Action. Code 84 has a five-second challenge result, not a durable chat effect.

Each forwarded query uses one serial gateway stream. Cancelling it closes that
query's gateway stream and propagates the receiving home's cancellation token;
the existing authenticated source control remains correlated with the original
query. This does not manufacture a home-signed SearchCancel Action outcome.
Cancellation or disconnection cannot change a previously committed effect.

An admission result is
`{reference: {id, revision}, home, origin, agreement, acting: EndpointActor,
checkpoint, rooms, notBeforeMs, expiresMs, withdrawn}`. `withdrawn` is boolean;
rooms are unique, at most 32, and a subset of the accepted agreement. Expiry is
at most seven days and no later than the agreement expiry. Revision changes are
monotonic; changing an endpoint generation requires fresh explicit approval.
The zero `expectedRevision` means create; otherwise it must match current state.
An identical retry of the latest admission request returns the original
admission and revision while it remains current. Changed scope under the old
revision conflicts. Withdrawal cannot be undone by replaying an earlier request.
An admission names only the acting endpoint. It does not grant represented-user
rights or permit every agent associated with that account.

## 4. Gateway and endpoint bootstrap

The gateway handshake is a signed `GatewayMessage` closed variant:

```
Hello {profile, agreement, gateway, receiver, clientNonce}
Challenge {profile, agreement, gateway, receiver, clientNonce, serverNonce,
           serviceBoot, principal, session, transportGeneration,
           issuedMs, expiresMs}
Proof {profile, agreement, challengeDigest}
Ready {profile, agreement, challengeDigest, serviceBoot}
```

In these variants, `gateway` is the receiving-network principal and `receiver`
is its configured destination ServiceId. Hello and Proof use the accepted
gateway key. Challenge and Ready use the
receiving service key. The receiver preserves one original five-second boot
deadline, verifies proof and a fresh destination check, then constructs a
gateway-only context. Reopening a transport stream is not renewed agreement or
endpoint authority. All subsequent controls and exchanges still require their
own applicable fresh check.

A remote endpoint first authenticates normally to its origin service. It then
signs a `RemoteSessionRequest`:

```
{profile, home, origin, agreement, request, account, endpoint,
 endpointBindingDigest, clientNonce, createdMs, expiresMs}
```

The request lifetime is at most 60 seconds and cannot extend on retry. The
origin verifies the signature against the current local endpoint and requires
the live incoming source principal to match. The destination must already have
an explicit admission for that exact endpoint/binding and agreement. Importing
identity evidence alone does not create an admission or room membership.

Define the challenge's `subject` as exactly one of:

```
Action {actionDigest, operationId}
Session {requestDigest, request}
```

The completed `FederationChallenge` is
`{profile, home, origin, agreement, gateway, admission, subject, nonce,
serviceBoot, issuedMs, expiresMs}`. `admission` is `{id, revision}`.
The gateway field identifies the bound authenticated destination principal.
This replaces the Action-only challenge's separate digest/operation fields;
a Session challenge cannot authorize an Action.

After receiving this challenge, the origin obtains a fresh check for the exact
subject digest on the endpoint's still-current incoming stream. It emits the
assertion in section 6. It submits code 89 on the authenticated gateway stream
with the exact signed endpoint request and evidence. The home verifies the
request, evidence, current
admission and destination authority, then atomically creates/reuses a window
and records a bootstrap receipt. `RemoteSessionReady` is
`{profile, home, origin, agreement, admission, request, requestDigest, acting,
classification, checkpoints, window, sourcePrivacy, destinationPrivacy}`.
It is signed by the home and returned unchanged to the endpoint.

On the source leg, an already authenticated ordinary endpoint stream carries
the role-20 request and receives the role-21 result in frame 18. Subsequent
foreign-targeted Actions use the existing Action/CryptoAction frames on that
stream. The origin validates its local endpoint session and selects the exact
accepted foreign route; it does not execute the foreign Action in its local
home database. The gateway then sends the completed frame-9/12 envelope to the
destination. Client routing keeps the source transport session separate from
the destination's signed ready/window/key. It forwards no rewritten Action or
Response and cannot mistake the source's local retry window for the home window.

Windows are home-issued, at most 24 hours, with at most four live windows per
endpoint. They bind agreement/admission revisions and the complete endpoint
generation as well as account/endpoint identity. Returning a prior receipt
requires current eligibility and the original request's unexpired lifetime.
After its expiry, a new bootstrap request may obtain current session state but
cannot reopen an old window. Window expiry does not erase retained outcomes.

## 5. Origin identity checkpoint and paging

The existing EndpointBinding remains an origin-service signature over the
endpoint key/principal/generations. It is accompanied by an
`OriginIdentityCheckpoint`:

```
{profile, origin, account, state: IdentitySnapshot, anchorDigest,
 head, records, nickname, issuedMs, expiresMs}
```

The account and snapshot home must match `origin`. `head` equals the snapshot's
current continuity head; `records` is 1-1024. The anchor digest, every chain link,
record digest, endpoint authorization and recovery proof are checked using the
existing [endpoint lifecycle](EndpointLifecycle.md). Security-sensitive fields
in the snapshot must match the verified final chain state; a later display or
account revision cannot change classification, keys or generations without its
required continuity authorization. Nicknames obey the current text profile.
The checkpoint is an identity statement, never a reusable transport permit.
Its expiry is at most seven days and cannot outlive the agreement.

The signed checkpoint carries classification/operator and recovery continuity
that EndpointBinding alone lacks. Agent classification must match origin
enrolment and its verified human operator. Include the origin checkpoints for
the acting account, its operator, and the represented account when that account
belongs to the origin. Deduplicate these: at most three checkpoint references
per assertion. Accounts on the home side use current home authority. A third
origin is refused.

`FederationIdentityPage` selects one immutable checkpoint head. `after` is the
last verified record index, initially zero; `limit` is 1-4. Its signed result is
`{profile, origin, agreement, account, checkpoint, after, records, next,
complete}`, where each record is a canonical CBOR blob. A page includes at
most four whole records and at most 56 KiB of record bytes, and its final signed
encoding must fit the ordinary frame. A single record retains the existing
56-KiB ceiling. `next` is the final returned index; `complete` is true only at
the checkpoint's record count. Empty incomplete pages, gaps, substitutions and
changing heads are invalid. Both indices are bounded to 0-1,024 before checked
addition of the record count; a valid signature cannot bypass these bounds.
Retain the existing per-account 16-MiB chain bound.

The request's `authorization` is a Blob containing a home-signed
`ProofAuthorization` with exact account and checkpoint. Its purpose is either
`Admission {admission, revision}` or
`Room {room, requester: EndpointActor, represented: AccountId,
grant: Option<GrantRef>, filterRevision, evidence: Option<Id>}`. It expires
within 60 seconds and is usable only with the matching page request ID and
agreement. An admission purpose requires an explicit pending/current admission;
a room purpose requires current access and any named retained transition or
selected Welcome evidence.
Both ends restrict it to accounts actually referenced by that admission or the
authorized room evidence. It cannot enumerate arbitrary foreign accounts.

Fetch and verify pages before requesting a five-second operation challenge.
Fresh assertions name those exact checkpoints; a changed head requires bounded
proof refresh and a new challenge for the unchanged Action. Pin existing
anchors and refuse rollback/fork/key substitution. New contacts require visible
explicit trust; legacy service-only anchors require separate deliberate
acceptance. A home signature over an origin's public key is not owner continuity.

At the home, verified foreign identity is a provenance-marked projection. Origin
identity and endpoint lifecycle remain origin-owned. Home membership, filters,
unread positions, grants and operation outcomes remain home-owned. Local
registration/recovery handlers cannot modify a foreign identity projection.
New verified generations invalidate dependent approvals, pause affected grants
and establish encrypted removal barriers in the same transaction.

## 6. Fresh source evidence and privacy

The completed `OriginAssertion` has these fields:

```
profile, origin, home, agreement, admission, challengeDigest, subject,
endpointBindingDigest, endpoint, securityGeneration, enrolmentGeneration,
transportNetwork, transportPrincipal, transportSession, transportGeneration,
transportGrant, transportGrantGeneration, sourceServiceBoot, controlGeneration,
companionInstance, endpointInstance, permitNonce, authority, checkpoints,
sourcePrivacy, sourceEvaluatedMs, sourceNotAfterMs, sourceUncertaintyMs
```

`authority` retains the existing `{configuration, epoch, height, state,
statementDigest, evaluatedAtMs, expiresAtMs}` observation. `subject` replaces
the earlier Action-only digest without omitting its exact Action correlation.
`checkpoints` is a sorted unique list of `{account, checkpointDigest}`.

The source check must begin after receipt of the matching home challenge.
The adapter must retain its already validated receipt identities and original
boot-clock deadlines through a typed accessor. It must not reconstruct them
from status JSON or caller input. Only a currently permitted check can produce
an assertion. Immediately before signing, recheck the source stream, checkpoint
heads, account generations and original check deadline.

For conservative time conversion, sample the healthy clock with bounds
`[L,U]` at source boot time `b`, bracketed so elapsed sampling time is included.
Let `d` be the earliest original local call/companion/receipt boot deadline.
Set `sourceEvaluatedMs = L` and
`sourceNotAfterMs <= L + max(0,d-b)`, also no later than the conservative
authority/credential expiry. Record the bounded clock uncertainty; reject if
it exceeds 250 ms or no positive safe interval remains. Do not use `U` to add
permission lifetime. The represented positive interval is at most 5,000 ms.
The home requires its current upper time bound to precede
this expiry and all applicable credential/agreement/admission expiries.

Independently, the home retains a boot deadline of at most five seconds from
challenge issuance. Source checking, forwarding, destination checking and queue
wait all consume that same interval. A fresh destination check or a new foreign
wall-clock timestamp cannot restart it. An identical retry can obtain a new
challenge only within its still-valid home window; this never renews the old
source check. The final home authorization is before the earliest bound.
Durable completion may follow authorization; a late response does not imply
that an effect was rejected.

`sourcePrivacy` is a closed normalized record from the verified fresh incoming
observation: `{endpointMode, transportProtection, relayArrival, provenance,
relayService, attachmentProfileDigest, physicalIndependenceVerified,
profileCurrentnessAsserted}`. The two final assertions are false under the
current HyperNet contract; relay service/profile fields are present only for
the supported attested attachment mode.
Its enum values retain the typed HyperNet meanings. Unknown evidence stays
unknown; source configuration or an outgoing description cannot become an
incoming relay-attestation claim. Destination privacy is independently derived
from the fresh destination check and included in the home-authenticated result
or current route inspection.

`attestedRelayArrival` requires the supported attested relay-arrival evidence
on both legs. `supportedHyperNetRoute` still preserves each endpoint's selected
HyperNet policy and mandatory HyperNet transport; it does not force optional
obfuscation. Transport protection, address properties and message encryption
are separate displayed facts. No gateway claims end-to-end obfuscation from one
leg or possesses MLS content keys merely because it forwards ciphertext.

## 7. Shared home execution and exact retry

`FederationEnvelope` is
`{profile, agreement, admission, action, endpointBinding, challenge,
originAssertion}`. The last four fields contain exact signed blobs. Checkpoints
are referenced by digest after bounded import, not embedded as whole chains.
All object home/origin/subject/actor/binding/generation/agreement/admission
values must agree exactly. The original Action signs its agreement reference;
neither gateway nor attestor may change actor, target, expected revisions,
approval, ciphertext or causation.

Use an explicit execution context at the home boundary:

```
Local {authenticatedSession, destinationCheck}
Remote {verifiedRemoteSubmission, destinationCheck}
```

Only the federation verifier can construct `verifiedRemoteSubmission`. It
contains the verified original Action and immutable references to the accepted
gateway, challenge, identity checkpoints and their deadlines. It is not a local
Session, a gateway account or a mutable ambient actor. The existing feature
handlers receive the same original `VerifiedAction` after this boundary.

Obtain fresh checks and proof pages outside the writer lock. Under the same
guarded SQLCipher transaction used by local execution:

1. Check current agreement/admission and the challenge's gateway, subject,
   boot identity, original deadline and unconsumed state. Apply eligible verified
   origin continuity updates and their dependent invalidations.
2. Authenticate the original actor against current provenance-aware identity.
   Check the home window and exact retained operation bytes/digest. An existing
   committed result creates no new effect. An identical successful read is
   re-evaluated against current access before content is returned.
3. Apply the same expected revisions, represented-account rights, home grant,
   exact approval, room/recipient restrictions and cost budgets as a local
   operation. Agreement revision is now a supported expected revision.
4. Run domain effects inside `hrc_domain_effects`. A domain rejection rolls back
   those tentative effects, not the legitimate terminal rejection/outcome.
5. At the existing final authorization point, recheck current policy and all
   original authority/challenge deadlines. Commit the event, outcome, approval
   consumption, challenge consumption and authoritative state change together.
   Publish only after the database and external continuity guard are durable.

No network call occurs in this transaction. A failed final authorization rolls
back tentative effects and challenge consumption. A successful retained outcome
and its challenge consumption are atomic too. A pre-admission transient refusal
may consume that particular challenge with a bounded refusal receipt but must
not become a terminal `hrc_operations` result. Retrying needs a new challenge,
the same immutable Action and current authority.

Pending challenges are boot-bound and unusable after restart. Keep at most one
pending challenge for a gateway/subject/admission tuple; replacement invalidates
the earlier nonce. Outcomes and committed challenge receipts survive restart
under the normal deduplication policy. A response lost after commit resolves to
the original outcome. Reusing an operation ID for changed bytes conflicts.

A changed agreement, endpoint binding or admission revision cannot retrofit
authority onto an old Action. A new currently authorized Resolve Action may
inspect the retained outcome under the existing disclosure rules; it does not
resubmit the old effect. No gateway creates fresh operation IDs for uncertain
endpoint work. The endpoint keeps exact ciphertext/outbox state before exposure.

## 8. Delegation and confidential conversations

Grants are created, paused, revoked, approved and consumed at the room's home.
The owner signs the exact home-targeted creation scope through its own current
local or remote context. Remote agent identity comes from its verified origin
classification and operator, not from the grant payload. Grant ownership is the
signing represented human; the agent's operator remains a separate verified
binding and need not be that human. Both origins must belong to the bilateral
profile. The owner's room rights, agent's explicit scope, origin admission and
destination policy must all permit the operation.

The existing local-only recipient restriction is replaced by exact admission
under the agreement. Independent participation still requires its own room
rights and cannot bypass a ban through relabeling. Pausing/revoking a grant is
home-ordered, invalidates queued effects and applies the existing encrypted
read-removal barrier. It does not retract previously disclosed content.

Extend encrypted `DelegationEvidence` with
`ownerCheckpoint: {origin, checkpointDigest, head}` and
`creationEvidence: Blob`, the accepted creation-time origin assertion for a
remote owner; local owners use an explicit local evidence variant. Retain the
exact owner-signed creation Action and home creation position. A client verifies
the owner endpoint in the named origin chain state, the assertion's exact Action
digest, and the home-recorded creation outcome. It never compares an origin
continuity position with a destination grant/event position. Historical proof
validates creation; current home grant state and current identity still govern
new access.

Foreign endpoints enrol their independent MLS key with the existing
home-targeted `CryptoEnrolEndpoint` Action through federation. Thus the current
endpoint-signed registration proof still names the room home. Packages,
credentials, actor mode, represented generation and exact grant are verified
through the same home confidential handlers. No recovery key or message secret
is shared with gateways. New or recovered endpoints receive future keys only.

`AccountPublicIdentity` retains current room/history/Welcome authorization and
can return unchanged origin-signed checkpoint/page evidence inside its
home-authenticated response. Select the pinned origin service key from the
accepted agreement; retain the account's accepted anchor independently. The
same historical transition authorization permits proof retrieval for removed
members needed to verify retained ciphertext. Missing proof or a chain fork
suspends dependent verification; it never authorizes a home-only replacement key.

CryptoHistory, Welcome and membership transitions remain home-ordered. Verify
home signatures, then origin continuity and the MLS roster before advancing
endpoint state. Current ignore filters suppress application deliveries and
agent triggers, while required public transition metadata remains available.
Locally decrypted FTS and archives keep the existing current-access checks and
explicit offline-stale status. Gateways cannot offer plaintext service search
for encrypted content. Exact-approval inspection and the coupled MLS/outbox
transaction are unchanged by forwarding.

## 9. Withdrawal, expiry and recovery

An identity checkpoint can remain valid for seven days as a cached proof. It
does not establish that its endpoint list is still current for new encrypted
publication. `IdentityFreshness` is a separate role-25 signed object:
`{profile, home, origin, agreement, checkpoints, issuedMs, expiresMs}`. Its sorted
unique checkpoint references name at most 32 origin accounts. Its lifetime is
positive and at most five seconds, bounded further by the agreement and proof
expiry. It conveys identity currentness only; it cannot authorize a sender or
replace either HyperNet transport check.

Explicit origin checkpoint export records a persistent watch for that account
and agreement, with at most 256 watches per agreement. Continuity changes and
nickname changes mark watched identities dirty in the same transaction as the
local change. The origin service propagates changed signed checkpoints and
bounded pages over its admitted gateway, acknowledges the watch only after the
home confirms complete import, then signs short observations of the exact heads
still current at the origin. Dirty-first work and account-ordered round-robin
renewal are separate bounded queries; a busy account cannot hide untouched
recipients from renewal. No network operation holds the home writer.

The receiving home accepts observations only for independently pinned,
completely imported identities in that gateway's admission scope. It checks
the original signed expiry and records a conservative receiving boot deadline.
Replaying the same observation cannot extend that deadline; restarting the home
invalidates received observations. Agreement revision changes also invalidate
them. The encrypted send and final commit boundary check all foreign acting,
represented and operator identities. Missing or expired freshness creates an
availability barrier, visible through `sendBarrier`, without adding a required
MLS removal. Restoring freshness of unchanged heads releases that temporary
barrier. An exact pending ciphertext may then be retried without advancing its
sender ratchet again.

This bounds an undisclosed origin identity change to the remaining original
five-second observation lifetime. Receipt of the actual changed continuity
proof immediately applies the stronger grant, approval and MLS removal barriers
below. A disconnected origin cannot keep renewing observations, and a large or
slow watch workload fails closed when renewal misses its deadline.

Either administration records a durable local stop before sending a withdrawal
request. The home commits the stop at a home position and returns an
`AgreementState` with `withdrawn: true` and `barrierPosition` inside the correlated
home-signed `FederationControl::Result`. The origin verifies the exact request,
signer, accepted agreement and original validity interval before retaining that
home barrier and the signed acknowledgement. Its own local stop has no home
position. The CLI reports `StoppedLocally` until it can report
`HomeWithdrawalAcknowledged`; `--local-only` explicitly omits notification.
Failure to notify leaves the durable local stop in place.

Withdrawal, expired agreement/admission and verified endpoint/account recovery
block affected new exchange and queued effects. In the same home transaction,
invalidate affected approvals, pause dependent grants and mark encrypted rooms
for removal. Even a local sender cannot publish new ciphertext while an expired
or withdrawn remote leaf requires removal. Community-room local conversation
may continue under its ordinary rules. Encrypted publication resumes only after
the existing verified removal/Ready barrier, or explicit fresh-group recovery
with a visible discontinuity. A missing eligible rekey endpoint leaves sends
unavailable.

Admission checks enforce expiry even before periodic cleanup runs. Known local
withdrawal stops immediately; an unknown source change remains subject to the
declared finite freshness race until the home learns it. The origin forwards
monotonic lifecycle checkpoints promptly using authenticated control exchange;
loss of that route cannot be reported as a confirmed home barrier. No claim of
instantaneous global revocation is made.

Withdrawal controls remain inspectable and may complete their signed barrier
exchange after ordinary agreement expiry, but only through fresh valid gateway
transport and the already pinned administrative identity. They cannot reopen
ordinary exchange. Reconnection obtains fresh transport/admission and resolves
uncertain outcomes before effects. An older service snapshot must pass the
existing continuity guard; it cannot revive agreements or windows. A changed
network incarnation or service identity requires explicit new agreement/trust.

## 10. Bounds and qualification

All limits below are ceilings, not preallocations or measured capacity claims.
The pilot allocation remains 16 streams per companion: eight interactive, two
agent, two federation-direction, two operator and two transition slots. Both
companions in a gateway retain their own limits. Multiplexing does not collapse
actor/represented-account budgets into a single gateway identity.

| Boundary | Runtime ceiling |
| --- | --- |
| Parsing | Existing 64-KiB ordinary/256-KiB crypto frames, depth 16, 256 collection entries and 4,096 nodes; embedded signed objects retain their tighter depth limits. |
| Forwarded Action | At most 48 KiB signed ordinary bytes or 224 KiB signed crypto bytes, plus a final exact envelope-size check before exposure. Other fixed evidence consumes at most 16 KiB; crypto keeps additional headroom. Oversize refuses before ratchet/outbox commit. |
| Evidence | Checkpoint at most 8 KiB; assertion at most 8 KiB including at most three references; challenge/binding at most 2 KiB each; full chain limits from section 5. |
| Proof cache | At most 256 imported accounts, eight active endpoints per account and 64 MiB aggregate verified proof storage. Do not evict evidence referenced by live admissions/rosters to make room; refuse capacity explicitly. |
| Identity propagation | At most 256 persistent watched accounts per agreement; pages and freshness batches at most 32 accounts. Freshness lasts at most five seconds and cannot survive a home restart without new authenticated observation. Missed renewal is an availability barrier, not permission to retain stale recipients. |
| Pending proof work | One page fetch per peer, two service-wide; at most 256 KiB unverified staging. No proof fetch holds a home transaction or extends a challenge. |
| Checks and handshakes | At most four fresh checks per companion, one per incoming stream, including ordinary clients; respect the upstream serialized endpoint read. At most four HRC handshakes service-wide. |
| Exchange | One active forwarded operation per gateway stream; queue before challenge issuance. At most four pending home challenges service-wide, two per gateway and one per exact subject. |
| Challenge admission | Gateway sustained two requests/s, burst four, plus actor/represented-account and service budgets. Invalid/expired attempts still consume bounded admission work. |
| Controls | Existing four costly workers with one reserved for authenticated controls; 64 KiB reserved within the global queue budget, four control operations/s and 8-KiB maximum reserved-control frames. Proof pages use ordinary metadata budgets, not this reserve. |
| Queues and output | Existing 32 pending operations/actor, 64/room, 512 KiB outbound/stream and 16-MiB aggregate queue cap; 256 KiB/s output/peer and 1 MiB/s service. All lower applicable bounds win. |
| Catch-up | Existing 1 MiB/peer/minute; history pages and local processing remain bounded and cancellable. No individual notifications for resumed backlog. |

Charge original actor, represented account, room and peer before expensive
decoding/verification where their authenticated identities are available; use
separate cheap pre-authentication budgets before that point. Shared relay
addresses are not actor identities. Diagnostic output contains fixed categories
and bounded references, never message plaintext, keys or admission secrets.
No response automatically generates another response or onward federation event.

Implementation qualification must demonstrate two independently administered
networks and distinct actual gateway admissions, including refusal on either
leg. Representative scenarios cover foreign direct and delegated sends; exact
approval; source/gateway/key/continuity substitution; original deadline expiry;
lost acknowledgement and restart deduplication; admission withdrawal and
partitioned barrier reporting; ignore and bounded history; encrypted direct and
private-group add/remove/Ready; origin recovery and contact pinning; foreign
owner grant proof without cross-service position comparisons; and expired
remote-leaf barriers on local ciphertext sends. Resource measurements must
include proof paging, slow gateways, replay and control responsiveness.

The dependency order is agreement/gateway/bootstrap, common foreign execution
and delegation, then encrypted proof/history/barrier integration. Federation is
complete only when the combined native workflow passes; a signed envelope test
or a local mock route is not the release acceptance evidence.
