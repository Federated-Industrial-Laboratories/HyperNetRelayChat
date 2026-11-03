# HRC native wire profile 1

This specification fixes the version-1 representation used by the Rust protocol
boundary. It complements [operation permissions](ProtocolPermissions.md), the
[transport profile](IntegrationProfile.md), and [state recovery](StateAndRecovery.md).
It defines signed data and framing; a valid signature does not establish room
membership, a current delegation or a federation agreement. Those checks belong
to the receiving service's operation boundary.

## Framing and deterministic CBOR

The HyperNet application protocol label is `hrc/1`. Each frame begins with a
four-byte unsigned big-endian length followed by a one-byte kind. The length
includes the kind and excludes the four length bytes. The remaining bytes are
one canonical CBOR value. Read and validate these first five bytes before
allocating the payload. No compression, padding or trailing CBOR data is allowed.

| Kind | Number | Maximum length including kind |
| --- | --- | --- |
| Hello | 1 | 65,536 bytes; the Hello decoder further limits its payload to 4,096 bytes |
| Challenge | 2 | 65,536 bytes |
| Proof | 3 | 65,536 bytes |
| Ready | 4 | 65,536 bytes |
| Action | 5 | 65,536 bytes |
| Response | 6 | 65,536 bytes |
| Event | 7 | 65,536 bytes |
| Close | 8 | 65,536 bytes |
| Federation | 9 | 65,536 bytes |
| CryptoAction | 10 | 262,144 bytes |
| CryptoEvent | 11 | 262,144 bytes |
| CryptoFederation | 12 | 262,144 bytes |
| DeviceHello | 13 | 65,536 bytes |
| DeviceChallenge | 14 | 65,536 bytes |
| DeviceProof | 15 | 65,536 bytes |
| DeviceReceipt | 16 | 65,536 bytes |
| CryptoResponse | 17 | 262,144 bytes |
| FederationControl | 18 | 65,536 bytes |

A crypto class is valid only for KeyPackage publication, proposal, commit, epoch
readiness, crypto inspection, Welcome or crypto recovery operations, or an envelope
carrying such an operation. Receiving services enforce
that semantic relationship after signature verification. Declaring a larger
class never grants additional authority. Unsupported kinds are refused before
payload allocation. The transport maintains one original finite deadline across
partial reads and writes of a frame; receiving another fragment cannot renew it.

Use the core deterministic encoding requirements of RFC 8949: definite lengths,
shortest integer and length forms, and map keys ordered by bytewise lexicographic
comparison of their encoded bytes. This is not the alternative length-first
ordering. Duplicate keys are rejected. This profile permits integers, byte and
UTF-8 text strings, arrays, maps, booleans and null. Map keys are unsigned integers
or text. Floats, other simple values, tags and indefinite forms are unsupported.
[CBOR deterministic encoding](https://www.rfc-editor.org/rfc/rfc8949.html#section-4.2.1)

The decoder scans lengths, UTF-8, types and structure before allocating decoded
objects. Each collection has at most 256 entries; nesting is at most 16 levels
and a decoded object has at most 4,096 nodes. Embedded COSE payloads allow 14
levels, leaving two for their containing signed object. Protected headers have a
512-byte and two-level bound. Embedded objects and their enclosing frame must
both fit their bounds. Original text and signed bytes are preserved. Normalising
Unicode is a separate lookup/index operation and never changes signature input.

Version-1 typed objects are closed maps: every listed field is required, including
explicit null for absent options, and unknown fields fail. Enum variants are
closed. Operation bodies are canonical CBOR values; each owning feature must
validate its exact body schema before effects. Unknown critical capabilities or
operations cannot be treated as an optional no-op. Optional capabilities are
negotiated explicitly. This version defines no ignorable typed-object fields.

## Identifiers and common values

`Id` is a 32-byte CBOR byte string. It represents an opaque identifier, a public
Ed25519 key, or a SHA-256 digest according to the containing field. Random IDs
and nonces are generated with the operating system random source. JSON diagnostic
and configuration representations use exactly 64 lowercase hexadecimal characters.
Variable-length `Blob` fields use even-length lowercase hexadecimal JSON strings,
bounded to less than 256 KiB of decoded bytes. CBOR continues to encode these
fields as byte strings; JSON conversion does not change signed bytes. Compound
identifier parsing accepts only the exact colon-separated lowercase display form.
The wire never substitutes that textual representation for the byte string.

All field names below are case-sensitive. Unsigned fields use `u64` unless stated
otherwise. HRC security, enrolment, grant and agreement generations start at one;
HyperNet generation fields retain HyperNet's own numbering. Times ending in `Ms`
are UTC milliseconds under the service's validated clock policy. A timestamp by
itself is not evidence that time is healthy or an authority assertion remains
current. Event order is its home-assigned sequence, not its timestamp.

| Type | Exact map fields |
| --- | --- |
| NetworkId | `network: Id`, `incarnation: Id` |
| ServiceId | `network: NetworkId`, `service: Id` |
| AccountId | `origin: NetworkId`, `local: Id` |
| RoomId | `home: ServiceId`, `local: Id` |
| EndpointActor | `account: AccountId`, `endpoint: Id`, `securityGeneration`, `enrolmentGeneration`, `bindingDigest: Id` |
| OperationId | `window: Id`, `operation: Id`; the enclosing Action binds the home |
| GrantRef | `id: Id`, `generation` |
| AgreementRef | `id: Id`, `revision`, `digest: Id` |
| RetryWindow | `id: Id`, `expiresMs` |

An account's origin includes its network incarnation. A room's identity includes
its home service. A different network incarnation or home service cannot inherit
an older identifier merely by reusing its local bytes. Colon-separated lowercase
hex displays are storage/display keys, not alternative signed encodings.

## COSE and key roles

Signed payloads are the CBOR array `[1, role, object]`. COSE_Sign1 is untagged and
contains exactly `[protectedBytes, {}, payloadBytes, signatureBytes]`. The attached
payload and 64-byte Ed25519 signature are mandatory. The protected header is
exactly `{1: -19, 3: mediaType, 4: SHA256(publicKeyBytes)}`. No unprotected fields,
extra protected fields or detached payloads are accepted. External AAD is the five
ASCII bytes `HRC/1`.

COSE constructs the standard `Signature1` signature input. The implementation uses
coset 0.4.2 and ed25519-dalek 2.2.0 with strict verification. The fully specified
Ed25519 algorithm is `-19`; the polymorphic `EdDSA` value `-8` is refused.
The key ID is a lookup hint. Verification takes a separately selected key with
an accepted role; a key found in a payload cannot establish that trust.
[COSE_Sign1](https://www.rfc-editor.org/rfc/rfc9052.html#section-4.2) ·
[Ed25519 algorithm assignment](https://www.rfc-editor.org/rfc/rfc9864.html#section-2.2) ·
[coset API](https://docs.rs/coset/0.4.2/coset/)

Each media type below has prefix `application/hrc-` and suffix `+cbor;v=1`.
The role is bound in both the protected media type and signed payload.

| Role | Number | Media-type middle | Accepted signing role |
| --- | --- | --- | --- |
| Action | 1 | `action` | Enrolled acting endpoint |
| AccountRegistration | 2 | `registration` | Proposed initial endpoint; possession only |
| EndpointBinding | 3 | `endpoint-binding` | Accepted origin service/attestor |
| SessionChallenge | 4 | `session-challenge` | Pinned receiving service |
| SessionProof | 5 | `session-proof` | Enrolled endpoint |
| SessionReady | 6 | `session-ready` | Pinned receiving service |
| Response | 7 | `response` | Exact receiving home service |
| Event | 8 | `event` | Exact room home service |
| Approval | 9 | `approval` | Currently authorised owner endpoint |
| FederationChallenge | 10 | `federation-challenge` | Receiving home service |
| OriginAssertion | 11 | `origin-assertion` | Agreement's pinned origin attestor |
| FederationAgreement | 12 | `agreement` | Each independently accepted service administration |
| HistoryCursor | 13 | `history-cursor` | Exact receiving home service |
| DeviceRequest | 14 | `device-request` | Proposed endpoint key; possession alone grants no admission |
| DeviceChallenge | 15 | `device-challenge` | Exact receiving home service |
| DeviceProof | 16 | `device-proof` | Proposed endpoint key and, when required, current owner recovery key |
| DeviceReceipt | 17 | `device-receipt` | Exact receiving home service |
| ReplacementKey | 18 | `replacement-key` | Proposed replacement recovery key |
| GatewayMessage | 19 | `gateway-message` | Accepted gateway for hello/proof; receiving service for challenge/ready |
| RemoteSessionRequest | 20 | `remote-session-request` | Exact origin endpoint |
| RemoteSessionReady | 21 | `remote-session-ready` | Receiving home service |
| OriginIdentityCheckpoint | 22 | `origin-identity-checkpoint` | Pinned origin service |
| FederationControl | 23 | `federation-control` | Accepted gateway/admin for requests; receiving service for results and proof authorization |
| OriginIdentityPage | 24 | `origin-identity-page` | Pinned origin service |
| IdentityFreshness | 25 | `identity-freshness` | Pinned origin service; short observation of exact identity heads, never a HyperNet permit |

The object's digest is SHA-256 of its exact canonical payload array, excluding
the COSE wrapper. This lets both administrations sign identical agreement bytes.
A verified object's `bytes()` retains that payload; `signed_bytes()` retains its
original COSE encoding. Re-encoding during verification checks closed typed shape;
the signature is always checked against the received bytes. Verified wrappers
have private construction and cannot be deserialised into existence. Their
`signer_key()` records the key actually verified, so the operation owner can
compare it with current enrolment rather than trusting a payload key label.

## Registration and session establishment

`AccountRegistration` contains `home`, `account`, `endpoint`, `endpointKey`,
`transportPrincipal`, `recoveryKey`, `classification`, and `invitation`.
`classification` is `{"kind":"human"}` or
`{"kind":"agent","operator":AccountId}`. All identifiers/keys are `Id` except
the typed home and account. The registration is signed by `endpointKey`; its
account origin must equal the home network. Recovery and endpoint keys are
validated Ed25519 public keys.

`verify_registration_request` checks possession of the proposed key. It does not
authorise enrolment. Initial admission requires a stored invitation, exact allowed
transport principal and account classification/operator, and explicit acceptance
of the signed descriptor. The invitation is consumed by the authoritative owner.
Additional endpoints require the current controller or recovery operation. A
nickname, a self-signed descriptor or an arbitrary transport connection cannot
substitute for this admission.

`EndpointBinding` contains `origin: ServiceId`, `account`, `endpoint`,
`endpointKey`, `transportPrincipal`, `securityGeneration`, `enrolmentGeneration`,
`notBeforeMs` and `expiresMs`. Its account origin equals the attesting service's
network. The binding's digest includes all these fields and its role/version.
Validity and current enrolment must be checked again at use.

Hello is unsigned CBOR `[1, object]`, with fields `home`, `account`, `endpoint`,
`clientNonce`, `versions`, `requiredCapabilities` and `optionalCapabilities`.
Version 1 offers exactly `[1]`. There are at most 16 combined capability names,
no duplicates, and each name is 1-64 visible ASCII bytes. The home resolves the
claimed endpoint through its current enrolment and the verified incoming HyperNet
principal. Hello is an untrusted selection request.

| Object | Exact fields |
| --- | --- |
| SessionChallenge | `home`, `account`, `endpoint`, `clientNonce`, `nonce`, `session`, `serviceBoot`, `transportPrincipal`, `transportSession`, `transportGeneration`, `expiresMs` |
| SessionProof | `home`, `account`, `endpoint`, `clientNonce`, `challengeDigest` |
| SessionReady | `home`, `session`, `challengeDigest`, `window: RetryWindow`, `maximumFrameBytes`, `maximumCryptoFrameBytes`, `capabilities`, `accountRevision`, `bindingDigest`, `acting: EndpointActor`, `classification` |

The client verifies the pinned service signature and exact Hello correlation
before signing the challenge digest. The home verifies the endpoint proof, the
stored challenge, its current transport binding and its original five-second
boot-time deadline. `serviceBoot` is a random service-incarnation nonce; challenges
are one-use and never survive process restart. The service uses its own stored
deadline, not a caller's interpretation of `expiresMs`.

Ready binds the exact accepted challenge, current endpoint state and service-issued
retry window. The client checks those correlations before constructing Actions.
A reconnect starts a new handshake and fresh current authority checks. It may
resolve old operation IDs, but does not renew old windows or authority.

## Actions and operations

An Action has exactly `home`, `operationId`, `actor`, `target`, `operation`, `body`,
`expected`, `approval` and `agreement`. `approval` is null or an `Id` allocated
before the immutable action is constructed. The separate Approval signs this
Action's digest; there is no circular approval-signature digest in the Action.
`agreement` is null or the exact `AgreementRef`. `expected` is a map from the
revision names `account`, `room`, `grant`, `agreement`, `epoch` and `filter` to
unsigned revisions; unused revisions are omitted from that map.

Actor forms are closed maps:

- Direct: `mode:"direct"`, `acting: EndpointActor`.
- Independent agent: `mode:"independentAgent"`, `acting`, `operator: AccountId`.
- Delegated: `mode:"delegated"`, `acting`, `operator`, `represented: AccountId`,
  `representedSecurityGeneration`, `grant: GrantRef`.

Direct actions cannot contain delegated fields. Acting identity always remains
separate from the represented account. The service compares the entire actor
binding with current enrolment and delegation; a correctly signed claim alone
cannot select a represented account.

Targets are `{"kind":"service"}`, or a map with `kind` and `id`. The other kinds
are `account` with AccountId, `room` with RoomId, `delegation` with GrantRef and
`endpoint` with Id. A room target's home must match the Action home. A foreign
acting account requires an agreement reference. Destination admission and
operation-specific target compatibility remain feature-owner checks.

| Operation codes | Meaning in code order |
| --- | --- |
| 1-5 | Account.SetNickname, Presence.Set, Account.Inspect, Agent.List, Service.Inspect |
| 10-16 | Room.Create, Join, Leave, SetTopic, List, Inspect, Invite |
| 20-22 | Message.Send, Reply, Action |
| 30-37 | History.Page, Search.Query, Search.Cancel, Events.Subscribe, Events.Resume, Unread.Set, Operation.Resolve, History.Context |
| 40-45 | Delegation.Create, Inspect, Pause, Resume, Revoke, List |
| 50-52 | Approval.Prepare, Approve, Reject |
| 60-66 | Moderation.Ignore, Mute, Silence, Kick, Ban, Filters, Restrictions |
| 70-79 | Crypto.EnrolEndpoint, PublishKeyPackage, Propose, Commit, EpochReady, Inspect, Welcome, Recover, Report, History |
| 80-89 | Federation.Propose, Accept, Withdraw, Exchange, Challenge, AdmitEndpoint, WithdrawEndpoint, IdentityPage, Inspect, Session |
| 90-96 | Account.Recover, RotateRecovery, EnrolEndpoint, DisableEndpoint, Devices, Continuity, LifecycleOutcome |
| 97 | Account.PublicIdentity |
| 100 | Direct.Create |
| 110-111 | Client.Metadata, Community.Sync |

Operation names describe contracts from the permission specification. Defining a
code does not enable its handler. Services refuse known but unavailable operations
with `UnsupportedFeature`. Codes 71-77 use crypto framing; all other Actions fit
ordinary framing. Message bodies still obey their separate text and grapheme
limits. HRC's current operation authorization point checks the Action digest,
fresh transport observation and current home state before effects.

The following inspection bodies are closed maps. `InspectionPage<T>` is
`{items: [T], next: text or null}`; an input page is `{after: text or null,
limit: unsigned}`. The limit is 1-16, the continuation text is at most 512 ASCII
bytes, and encoding limits can shorten a page. Continuations are positions, not
authorization. Each request checks current endpoint, account and room rights.

| Code | Target and request body | Successful result body |
| --- | --- | --- |
| 3 | Own account, `{}` | `{nickname, revision, filterRevision}` |
| 4 | Own account, input page | `InspectionPage<{actor: EndpointActor, nickname}>`; current eligible endpoints of agents operated by that account |
| 5 | Service, `{}` | `{motd: text}`; at most 1,024 bytes, empty by default |
| 15 | Room, `{}` | `{members, readSequence, roomRevision, filterRevision, moderator, confidentiality}`; at most 32 members |
| 37 | Room, `{event: Id}` | `{events, members, roomRevision}`; the accessible original event and up to two sequence positions on each side, at most five events |
| 45 | Own account, input page | `InspectionPage<Grant>`; grants owned by the caller or assigned to its exact current agent endpoint |
| 65 | Own account, input page | `InspectionPage<{subject: AccountId, ignored: bool, muted: bool}>` |
| 66 | Room, input page | `InspectionPage<{subject: AccountId, kind: unsigned, expiresMs, moderator: AccountId}>`; active silence (`kind=1`) and ban (`kind=2`) restrictions |

Account and filter inspections cannot impersonate a represented account through a
delegated actor. History context uses the same current membership, retention,
delegation and recipient-filter rules as ordinary history. Context does not issue
or rewind a resume cursor. See [conversation operations](ConversationOperations.md)
for operation-specific access and the correlated Search.Cancel contract.

### Bounded client views

The optional `bounded-client-views-v1` capability selects two fixed read contracts.
Client.Metadata targets the acting account and always returns its account view
and service information. Its optional pages contain rooms, recipient filters,
delegations and eligible agent endpoints. Community.Sync targets one local
community room and always returns its current inspection and access-context
digest. Its optional pages contain recipient filters, history and restrictions.
These operations reject delegated and remote actors; Community.Sync also rejects
encrypted rooms. Other clients and room types retain their existing operations.
There is no caller-selected batch of arbitrary Actions.

| Object | Fields |
| --- | --- |
| MetadataRequest | `rooms: RoomListRequest or null`, `filters: InspectPage or null`, `grants: InspectPage or null`, `agents: InspectPage or null`, `filterRevision: unsigned or null` |
| RoomListRequest | `after: RoomId or null`, `limit: unsigned`; the existing room-list bounds apply |
| MetadataPage | `account: AccountView`, `service: ServiceInformation`, `rooms: RoomListPage or null`, `filters: InspectionPage<FilterState> or null`, `grants: InspectionPage<Grant> or null`, `agents: InspectionPage<AgentEndpoint> or null` |
| RoomListPage | `items: [RoomSummary]`, `next: RoomId or null` |
| HistoryPageRequest | `cursor: Blob or null`, `limit: unsigned`; the existing history-page bounds apply |
| PageResult | `events: [Event]`, `cursor: Blob`, `hasMore: bool`, `roomRevision: unsigned`, `members: [Member]` |
| CommunityRequest | `filters: InspectPage or null`, `history: HistoryPageRequest or null`, `restrictions: InspectPage or null`, `context: Id or null` |
| CommunityPage | `inspection: RoomInspection`, `context: Id`, `filters: InspectionPage<FilterState> or null`, `history: PageResult or null`, `restrictions: InspectionPage<RestrictionState> or null` |
| RoomInspection | `members`, `readSequence`, `roomRevision`, `filterRevision`, `moderator`, `confidentiality`; the confidentiality field is mandatory |

`InspectPage` is the inspection-page input defined above. History uses its
existing request and signed-cursor schema. CommunityPage carries members once,
in its strict inspection; `history.members` must be empty. The client restores
that member list into its internal history-page representation after validation.
Null page selectors request no work for those components, and their results are
null. `filterRevision` and `context` compare current state on continuations.

The home runs the requested components through their existing policy owners in
one guarded transaction under one fresh, action-bound authority observation.
Final cancellation, clock and permit checks still precede result publication.
Budget admission atomically charges the sum of all included operation costs,
including the mandatory account/service or room inspection on each continuation.
Grouping does not reduce those charges or grant broader access.

Each combined response must fit the ordinary 65,536-byte frame and the aggregate
decoder depth, collection and node limits. Component allowances can shorten
pages, which return explicit continuations. A required nonpaged item that cannot
fit produces a bounded refusal; identity and policy data are never truncated.
An initial shared metadata page limits room data to 8 KiB, filters to 4 KiB,
grants to 32 KiB and agents to 4 KiB. A request for one component can use up to
57,344 bytes for that component; the complete signed response must still fit.
Single-component continuation turns preserve the existing collection capacities
without requiring every maximum-sized record to fit the smaller shared slice.
Each continuation obtains fresh authority. Recipient-filter pages bind the
current account filter revision; room continuations also compare the supplied
access-context digest. Neither a continuation nor that digest grants authority.
The existing signed history cursor and genuine history-gap semantics remain.

Clients finish filter and restriction assembly before presenting the associated
history or admitting notifications. A changed context discards the incomplete
assembly. Bounded page rounds and original read deadlines still apply.

This capability also promises that a fixed room identity has immutable
confidentiality. A client may retain an explicitly authenticated community
classification as private in-memory evidence bound to the exact home, room and
pinned service key while the capability remains negotiated. Missing mode data
cannot establish that evidence. It can remove repeated classification reads
while preparing an exact community message; it cannot establish membership,
delegation, transport authority or permission to send. The service checks those
conditions freshly for the submitted effect. Raw submissions, unknown rooms,
encrypted messages and persisted retries retain their validation paths.

The [endpoint lifecycle](EndpointLifecycle.md) defines device frames and recovery
authorization. `DeviceHello` carries the exact signed `DeviceRequest`.
`DeviceProof` carries `{endpoint: Blob, recovery: Blob or null}`, containing
separately signed statements of the same challenge digest. Challenge and receipt
frames carry their exact signed objects. All times use the existing bounded clock
contract; reconnect never refreshes the original request expiry.

| Object | Exact fields |
| --- | --- |
| DeviceRequest | `home`, `account`, `request`, `endpoint`, `endpointKey`, `principal`, `purpose`, `createdMs`, `expiresMs`, `replacement: Blob or null` |
| DeviceChallenge | `home`, `account`, `request`, `requestDigest`, `nonce`, `serviceBoot`, `principal`, `session`, `transportGeneration`, `securityGeneration`, `accountRevision`, `recoveryGeneration`, `recoveryKey`, `continuityHead`, `recorded: bool`, `issuedMs`, `expiresMs` |
| DeviceProof | `home`, `account`, `request`, `requestDigest`, `challengeDigest` |
| DeviceReceipt | `home`, `account`, `request`, `requestDigest`, `outcome` |
| ReplacementKeyProof | `home`, `account`, `request`, `key` |

Device purposes are `enrol`, `recover` and `rotateRecovery`. Only the last carries
replacement-key proof bytes. A request lasts at most 24 hours; a challenge lasts
at most five seconds and is further clipped by the request and admission ticket.
Account.Recover uses this proof exchange rather than an ordinary authenticated
Action: a lost endpoint cannot authenticate itself back into authority.

## Responses, events and cursors

`Response` contains `home`, `operationId`, `actionDigest` and `outcome`.
Outcome is a closed map with `status` plus the fields below:

| Status | Fields and meaning |
| --- | --- |
| `committed` | `event: Id or null`, `position`, `body`; the nonzero position and associated state are durable |
| `rejected` | `code`, `detail`; terminal admitted rejection retained for the operation's deduplication period |
| `refused` | `code`, `detail`, `retryAfterMs: u64 or null`; no admitted durable outcome, hint at most 60,000 ms |
| `result` | `body`; authenticated read/control result according to its operation |
| `absent` | No other fields; absent in a still-open, current-authorised retry window |
| `unknown` | No other fields; no definitive outcome can currently be established |

Error codes are `invalidInput`, `denied`, `expired`, `conflict`, `unavailable`,
`unsupportedVersion`, `unsupportedFeature`, `rateLimited`, `overloaded` and
`resynchronisationRequired`. `detail` is 1-64 ASCII alphanumeric, underscore,
hyphen or dot characters. Arbitrary peer prose, paths, keys or transcripts are
not error detail. Refusal permits only a semantics-safe identical retry; it does
not override backoff, current permissions or the original window. An expired
window without a retained outcome must not be represented as `absent`.

`Event` contains `home`, `room`, `event: Id`, `sequence`, `timestampMs`, `actor`,
`operationId`, `actionDigest`, `kind: Operation` and `body`. The sequence is nonzero
and the room home matches the signer role. The home signature attests committed
attribution; original endpoint/agent attribution is retained in `actor`.

`HistoryCursor` contains `home`, `room`, `account`, `sequence`,
`membershipRevision`, `filterRevision`, `accessDigest` and `expiresMs`.
The service computes `accessDigest` from its exact endpoint, represented-account,
delegation, agreement and history-access context. Each use checks current access,
expiry and those exact bindings. A cursor positions a bounded query; it never
grants membership or suppresses an explicit retained-history gap.

## Approval and federation objects

`Approval` contains `id`, `home`, `owner: EndpointActor`, `grant`, `actionDigest`,
`decision` (`approve` or `reject`) and `expiresMs`. The owner endpoint signature
binds exact immutable Action bytes. The service independently checks current
controller authority, grant mode, scope, expiry and one-use approval consumption.
An encrypted approval additionally requires the owner endpoint's verified
plaintext/ciphertext handling specified by the state contract.

Federation runtime objects require `profile: 1` and capability
`federation-runtime-1`. They complete the previously unused federation schemas;
local Action and endpoint-binding bytes retain their existing encodings.

`FederationAgreement` contains `profile`, `id`, `revision`, `home`, `origin`, `homeGateway`,
`originGateway`, `homeServiceKey`, `originServiceKey`, `originAttestorKey`, `rooms`,
`notBeforeMs` and `expiresMs`. Each gateway is a closed object containing
`network`, `destination`, `principal`, `serviceEndpoint`, `signingKey` and
`protocol`. These are exact HyperNet application bindings
admitted on the named receiving side: homeGateway receives origin-to-home
exchange; originGateway receives home-to-origin exchange. Both services sign
identical canonical agreement payload bytes after explicit local administration
acceptance. All signing keys must be independently pinned; self-listing a key in
an agreement cannot establish trust. The two network identities differ.

Each of at most 32 `rooms` entries contains `room`, `historyFromMs`, `retentionMs`,
`storage` (`homeOnly` or `bothNetworks`), `confidentiality` (`community`,
`confidentialDirect` or `privateGroup`), `privacy` (`supportedHyperNetRoute` or
`attestedRelayArrival`) and at most 32 `moderatorAccounts`. Rooms are unique and
belong to this home. Remote admission is explicit and per enrolled endpoint.
Onward sharing and transitive third-network origin assertions are unsupported.
Those fixed rules are not optional fields that an agreement can weaken.

`FederationChallenge` contains `profile`, `home`, `origin`, `agreement`, `gateway`,
`admission`, `subject`, `nonce`, `serviceBoot`, `issuedMs` and `expiresMs`.
`admission` contains `id` and `revision`. The closed subject is either
`{kind: action, actionDigest, operationId}` or
`{kind: session, requestDigest, request}`. Bootstrap evidence cannot authorize
an Action, and an Action challenge cannot open a retry window.
The represented interval is positive and at most five seconds. The home also
retains the original boot-time deadline and gateway binding in its bounded,
one-use challenge table. Restart discards pending challenges. No remote clock
can extend that original home bound.

`OriginAssertion` contains `profile`, `origin`, `home`, `agreement`, `admission`,
`subject`, `checkpoints`, `sourcePrivacy`, `challengeDigest`,
`endpointBindingDigest`, `endpoint`, `securityGeneration`,
`enrolmentGeneration`, `transportNetwork`, `transportPrincipal`,
`transportSession`, `transportGeneration`, `transportGrant`,
`transportGrantGeneration`, `sourceServiceBoot`, `controlGeneration`,
`companionInstance`, `endpointInstance`, `permitNonce`, `authority`,
`sourceEvaluatedMs`, `sourceNotAfterMs` and `sourceUncertaintyMs`.
Its authority map contains `configuration`, `epoch`, `height`, `state`,
`statementDigest`, `evaluatedAtMs` and `expiresAtMs`.
`checkpoints` is a sorted unique list of at most three
`{account, checkpointDigest}` references for the acting, operator and represented
accounts belonging to the origin. Their independently verified continuity
records establish classification and endpoint authority; the transport receipt
alone does not establish them. `sourcePrivacy` uses the closed effective-privacy
schema in [the federation runtime contract](FederationRuntime.md#6-fresh-source-evidence-and-privacy).

Only a permitted, currently usable source check can produce this assertion.
Source lifetime is positive, at most five seconds, and conservatively translated
from the original observation; source uncertainty is at most 250 ms. The transport
network matches the origin. These are signed attestor assertions, not portable
HyperNet quorum certificates. The home applies its clock policy and the earliest
source, challenge, credential and agreement expiry. Copying or forwarding never
starts a new source lifetime.

A Federation frame is unsigned canonical `[1, envelope]`; the envelope has
`profile`, `agreement`, `admission`, `action`, `endpointBinding`, `challenge` and `originAssertion`.
The last four fields are byte strings containing their complete signed objects.
The entire envelope, including all evidence, must fit its selected frame class.
CryptoFederation permits a larger original crypto Action but does not enlarge
individual binding/challenge/assertion limits. Forwarded signed payloads have an
11-level bound so the enclosing envelope and COSE object still fit the combined
16-level limit.

The home verifies all signatures under separately accepted roles, then compares
home/origin, agreement ID/revision/digest, Action digest, operation ID, challenge,
gateway, endpoint, generations, binding digest and represented/grant identities
across these objects. Its current room and delegation policies can further refuse
an otherwise valid remote operation. Challenge consumption and a new outcome are
atomic. An existing identical outcome does not create a second effect. Withdrawal
uses the acknowledged home barrier described in the transport profile.

Gateway handshake, bootstrap, signed identity checkpoints/pages and closed
control schemas are specified in [FederationRuntime.md](FederationRuntime.md).
They retain the ordinary canonical decoding bounds. An authenticated foreign
execution uses an explicit verified remote context, never a fabricated local
session. Its exact operation outcome and original home challenge consumption
share the same guarded transaction as domain effects.

## Boundary evidence

Maintained tests live under `Tests/Protocol/`. They reject malformed/duplicate and
noncanonical CBOR, excessive lengths/depth, wrong signing keys and roles, altered
headers, validly signed unknown or omitted fields, cross-home targets and oversized
ordinary actions. Tests preserve exact multilingual text and distinguish
pre-admission refusal from a retained terminal rejection.

`Tests/Protocol/Vector.json` is a fixed SessionProof vector. Its regeneration
script uses the public RFC 8032 test seed, an independent small RFC 8949 encoder
and Python cryptography Ed25519. Rust matches its complete COSE bytes, digest,
signature structure and signature. These are public test keys, never deployment
credentials. Passing wire tests does not establish complete service admission,
federation, encryption lifecycle or load qualification.

Encrypted-room operations, shared-room public identity97 and DirectCreate100 use
[ConfidentialConversations](ConfidentialConversations.md). CryptoResponse17 uses
the existing Response signature role; it does not create another signing role.
The receiver must bind its larger allowance to the exact outstanding crypto
operation. Ordinary responses and application-message actions retain64KiB bounds.
