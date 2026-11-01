# Confidential conversation operations

This document fixes the service and client integration contract for the existing
[persistent MLS boundary](CryptoRuntime.md). Implementation and native qualification
are in progress. Direct conversations and private groups use the same ordered
encrypted-room lifecycle. Community rooms remain service-readable.

## Admission and identity

An encrypted room has explicit account invitations. Creating a direct conversation
invites one other account; creating a private group starts with its creator. A
moderator can invite accounts to a private group. An invitation exposes the room's
name and inviter to its recipient but grants no history, message or MLS authority.
The recipient accepts through `RoomJoin`. Recipient ignore, current room bans
and rate limits apply before invitation delivery. An unaccepted invitation expires after one day. Leaving ends
membership; it does not erase previous recipients' archives.

Room names and topics are service-visible metadata. The interface states this
alongside message encryption. An uninvited account cannot discover a private room
through room lists, search or inspection. Direct rooms contain exactly their two
human or independent-agent account identities; additional devices use those
accounts. A delegated agent joins as an explicitly authorised endpoint of its
represented member, not as an extra account or an invisible shared device.

Each enrolled endpoint registers one independent MLS public key with a signed
HRC action. The registration is immutable for that endpoint generation; replacing
the key requires endpoint replacement. A room-bound KeyPackage proves the exact
MLS credential and key and represents that endpoint's explicit request to join
future encrypted traffic. Packages are one-use and are checked again when selected
by a membership transition. At most 64 endpoint leaves and 32 represented account
members exist in a room. Inactive invitations and packages have bounded counts
and expiry; they cannot accumulate indefinitely.

An authorised roster entry binds the complete endpoint actor and its participation
mode. A delegated entry also binds its exact grant and represented account security
generation. The service derives these from current authenticated operations. It
never accepts a caller-supplied roster as authority. An agent requires current
read permission, room access for its represented account, and the destination's
room policy. Pause, revocation, expiry, recovery, a ban or lost membership can
withdraw that access. Re-granting access does not restore old leaf authority.

## Wire operations

These bodies use the existing signed Action, exact operation identity and durable
outcome rules. Crypto bodies use the bounded crypto frame size where required.

| Code | Operation and target | Body |
| --- | --- | --- |
| 16 | RoomInvite, room | `{account}`; current moderator invites one account |
| 70 | CryptoEnrolEndpoint, own account | `{mlsKey}`; immutable for the current endpoint generation |
| 71 | CryptoPublishKeyPackage, room | `{package, expiresMs}`; at most one day of home admission validity |
| 72 | CryptoPropose, room | `{group, groupInfo}`; initial one-member group only |
| 73 | CryptoCommit, room | `{group, epoch, commit, additions, removals}`; addition entries are exact package digests, removal entries are endpoint IDs |
| 74 | CryptoEpochReady, room | `{group, epoch, commitDigest, sequence, welcome}`; optional Welcome bytes accompany the selected author's durable receipt |
| 75 | CryptoInspect, room | Empty body; bounded current public state, eligible packages and required removals |
| 76 | CryptoWelcome, room | Empty body; only the requesting admitted endpoint's selected Welcome |
| 77 | CryptoRecover, room | `{group, groupInfo}`; explicit fresh group and visible discontinuity |
| 78 | CryptoReport, room | `{group, epoch, commitDigest}`; current endpoint reports an unverified transition and freezes dependent sends |
| 79 | CryptoHistory, room | `{cursor, limit}`; current-authorised ciphertext and necessary ordered membership metadata |
| 97 | AccountPublicIdentity, account | `{room, after, limit, evidence}`; optional retained transition event permits verification of its historical participants within current history or selected-Welcome access |
| 100 | DirectCreate, service | `{recipient}`; new direct room and explicit recipient invitation |

Membership commits bind the exact current group and epoch. Current room policy and
any supplied room revision are checked before effects. They cannot select an earlier roster after a policy change. A readiness
receipt names the exact currently selected transition; it cannot clear a barrier
that requires another removal. A transition report contains no plaintext or
caller-defined diagnostic text. Only a currently eligible endpoint can report it.
Such a report can deny availability, as can other malicious member behaviour; it
does not authorise a new group, new members or access to old content.

Crypto operations use frame17, `CryptoResponse`, with the existing role-separated
Response signature and the 256KiB bound. Ordinary responses retain their 64KiB
limit. The client accepts the larger frame only for its correlated crypto request.
CryptoHistory suppresses ignored application events while preserving ordered
membership controls needed to verify subsequent epochs. It never labels those
controls as delivered user messages.

Each roster entry retains the exact endpoint-signed MLS key registration.
Delegated entries also retain the owner's signed grant-creation action and its
home position. Clients replay signed account continuity from an explicitly
accepted first-contact fingerprint before admitting a key. A legacy anchor
requires separate visible acceptance; an existing pin is never silently reset.
Owner-signed scope constrains encrypted agent admission even if a home supplies
misleading roster metadata. Current grant state and ordering remain the home's
policy responsibility.

The CBOR representation of each roster member is one byte string containing a
canonical `{actor, credential, registration, delegation}` record. Its decoded
record is limited to 32KiB and the existing depth, collection and node bounds.
JSON inspection keeps these fields structured. Aggregate rosters are limited to
96KiB and 64 leaves; pending packages consume at most 48KiB including their
proofs and encoding allowance. Both count and byte limits apply. Large grants
can therefore reduce the number of concurrently admitted leaves or packages.
An excess request fails before durable state changes; it cannot make the current
room uninspectable. Expired packages stop occupying the pending allowance while
their one-use tombstones remain retained.

A transition body and a selected Welcome with its full roster each have a
192KiB bound. This leaves space for signed response/event metadata, a history
cursor and the room member list inside the 256KiB frame. Recipient inspection
supports all 256 active ignore entries independently of those roster limits.
No oversized membership object raises the ordinary frame or parser limits.

## Ordered group state

The home stores public group state, the committed roster, pending admission
packages, a group identity and epoch, and an explicit send barrier. It stores no
MLS private keys. Encrypted message bodies, public commits and bounded rejection
records occupy the same authoritative room order as membership controls.

| Operation | Required result |
| --- | --- |
| Initialise | An eligible moderator creates a fresh one-member group and submits its exact GroupInfo. The home checks its current credential and public signature. |
| Add | An eligible current moderator proposes an exact next roster using current, consenting endpoint packages. The home checks every identity, grant and package before accepting one public commit from the expected epoch. |
| Remove | The required roster excludes every endpoint whose access ended. A remaining eligible moderator submits the exact removal commit. |
| Update | A current eligible moderator advances an otherwise unchanged roster to clear bounded ratchet maintenance requirements. |
| Ready | An eligible endpoint confirms that it durably verified the exact group, epoch, commit digest and ordered position. This can clear the corresponding home barrier; it does not attest for other devices. |
| Recover group | An eligible moderator explicitly starts a new group identity after an unavailable or inconsistent predecessor. The discontinuity is visible and admission is future-only. |

Only the selected author's verified readiness receipt releases the send barrier
and its Welcomes. Other endpoints acknowledge their own verified epoch before
sending. The home accepts at most one transition from an expected group and epoch. The
candidate's signed operation identity and bytes remain durable through uncertain
outcomes. A rejected candidate never rewinds exposed sender state. Welcome bytes
are released only for the selected transition, to the exact admitted endpoints.
An endpoint cannot fetch another endpoint's Welcome or package secret.

Membership removal, device disable, account recovery and agent read withdrawal
establish the home send barrier in the same transaction as the policy change.
The send boundary also evaluates finite grants and memberships against current
time; missing a background timer cannot permit a send to an expired leaf. The
required removal must be committed and an eligible endpoint must acknowledge its
exact epoch before new application sends succeed. Other endpoints independently
verify the same transition before accepting or sending application messages.

If all old endpoints are unavailable, the room remains unable to send until an
eligible moderator explicitly starts fresh group recovery. Old keys, restored
ratchet snapshots and administrative identity replacement are never recovery
shortcuts. A new or recovered device receives future traffic only. Retained
plaintext archives remain governed by their separate local retention policy.

## Application and local state

An encrypted application plaintext is a versioned canonical HRC value containing
the original UTF-8 message and stable mention spans. The outer signed Action and
MLS authenticated data bind the room, group, epoch, actor, represented identity,
grant, approval, operation identity, reply parent and agent causation. The home
can enforce bounded reply chains without inspecting message plaintext. Recipients
validate plaintext text and mention structure after authenticated decryption.

The endpoint persists sender-state advancement, exact signed ciphertext Action
and its ordinary HRC outbox entry in one transaction before transmission. Resolve
uses the same operation identifier and digest as community messages. It never
encrypts a transport retry again. An unknown outcome keeps the exact candidate
pending; abandonment is explicit and does not restore a sender generation.

Received ciphertext remains bound to its authenticated home Event. A separate
local presentation record contains the decrypted message; rewriting the signed
event body to pretend it contained plaintext is forbidden. MLS state, decrypted
archive/index updates, rejected-delivery records and cursor advancement are atomic.
Invalid cryptography follows the rollback and bounded rejection rules in
CryptoRuntime. Invalid membership freezes the dependent chain instead of skipping
to a later epoch.

Confidential search uses only the authorised, locally decrypted archive. Before
an online query or context lookup, the client checks current room and delegation
access and applies current recipient filters. Offline archive inspection is
labelled as retained local content with current access unconfirmed. The service
refuses plaintext search for encrypted rooms. No plaintext is written to service
indexes, events, diagnostic logs or federation envelopes.

Exact approval requires an already authorised owner endpoint to decrypt and save
the proposed ciphertext once. The approval binds the unchanged Action and content.
Changing epoch, content, grant or target requires a new candidate. Approved
delivery consumes the saved preview rather than decrypting its generation twice.
Independent agents and bounded autonomous grants retain their existing current
authority checks; encryption grants no broader operation permission.

## Interfaces

Create a private group with `hrc room create --private`; create a confidential
conversation with `hrc room direct --recipient`. Invite a group account with
`hrc room invite`, then accept using `hrc room join`. The GUI exposes the same
controls in the conversation switcher and encryption panel. The TUI provides
`/private`, `/msg`, `/whisper` and `/invite` with explicit account IDs.

`hrc crypto enrol`, `inspect`, `contact`, `trust`, `publish`, `initialise`, `commit`
and `sync` expose endpoint lifecycle and exact fingerprints. Each command's help
lists its required profile and room arguments. The GUI shows pending endpoint
packages and required removals. TUI `/crypto` and `/trust` commands use the same
client operations. Recovering a group is explicit and shows that other endpoints
must be readmitted for future traffic.

The send, history and search commands inspect the room mode first. Encrypted
plaintext is never submitted to the home as a discovery probe. Search and history
output keep original authenticated events separate from decrypted local content.
An exact encrypted approval candidate is held in the durable outbox until its
explicit approved submission; reconnect cannot release it automatically.

## Verification boundaries

Qualification must include two-device direct conversation and a three-member
private group over real HyperNet, including restart and uncertain-send resolution,
indexed local search, outsider refusal, removal barriers, future-only admission,
owner-key recovery, current delegated reading/sending and exact approval. Inspect
service database/index and diagnostic output for planted plaintext markers.
Federated encrypted membership uses the same contracts with independently verified
remote admission; local crypto checks alone do not qualify federation.
