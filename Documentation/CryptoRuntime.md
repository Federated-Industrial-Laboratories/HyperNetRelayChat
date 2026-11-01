# Persistent encrypted conversations

HRC uses OpenMLS 0.9.1, RustCrypto 0.6.0 and the OpenMLS SQLite provider 0.3.0
for confidential direct conversations and private groups. The ciphersuite is
`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`. Each enrolled endpoint has an
independent Ed25519 MLS key. MLS secrets and application records reside in the
same guarded [SQLCipher store](StorageRuntime.md). The account recovery key and
the HRC endpoint signing key are separate credentials.

## Credential and application bytes

The BasicCredential identity is deterministic HRC CBOR encoding of
`["HRC MLS BasicCredential", 1, {room, actor, mlsKey}]`. `room` includes the home
network, incarnation, service and room identifiers. `actor` is the complete HRC
EndpointActor: origin/account, endpoint, security and enrolment generations, and
endpoint-binding digest. `mlsKey` is the exact 32-byte MLS signature public key.
All names and binary encodings follow the protocol's camelCase structs. Nicknames
never enter credential verification. The credential digest is SHA-256 of these
exact bytes.

An `ApprovedRoster` comes from current authenticated HRC endpoint registrations
and room rules. It is not a new trust source: constructing or deserialising one
does not authorise a member. Enrolling an MLS public key requires an HRC action
signed by the current enrolled endpoint, with its account/generation binding.
The crypto boundary requires unique endpoints and keys, at most 64 leaves, and
an exact match between every approved credential/key and the actual MLS leaves.
An account operator and represented identity remain in the signed Action rather
than becoming transferable device keys.

An encrypted Action body is `{group, epoch, ciphertext, parent}`. Ciphertext is
a CBOR byte string. `EncryptionContext::from_action` and `action` provide the
shared conversion. MLS authenticated data is the canonical encoding of
`["HRC MLS application", 1, EncryptionContext]`. The context includes home,
room, operation ID, complete actor, operation, expected revisions, approval ID,
agreement, group, epoch and parent. It excludes ciphertext to avoid a circular
hash. The complete signed Action subsequently binds that exact ciphertext.
The context is bounded to 8 KiB, application frames to 64 KiB, and membership
objects to 256 KiB. There is no alternate UI encoding.

## Durable endpoint lifecycle

`initialize` runs before admission, under the store's exclusive ownership. The
pinned upstream provider runs its migrations on an empty in-memory connection;
the resulting schema is then created in one guarded HRC transaction. This
temporary connection contains no endpoint keys, messages or live MLS state.
HRC crypto schema version 1 is accepted; unknown versions refuse startup. This
is new-profile schema installation, not a general provider upgrade facility.
An upgrade must supply and qualify an explicit guarded migration before changing
these pins. All live provider calls borrow the HRC transaction's connection.

`Device::provision` generates and persists an independent MLS signing key.
`open` checks the persisted actor binding. `publish_key_package` creates one-use
packages, with at most 64 unpublished/unused records per profile. New group
creation persists the exact initial GroupInfo for retries. Joining through a
Welcome atomically consumes its package, checks the complete approved roster,
and records group identity, epoch and initial home cursor. Any failed check rolls
back package consumption. Repeating an exact successful join returns its durable
receipt. New endpoints receive future messages only; no history keys are imported.

Each operation constructs its provider and loads the group inside the database
transaction. No mutable group survives the transaction. A cryptographic failure
therefore rolls back all tentative writes and discards the in-memory state.

`prepare_message` validates text and current roster, advances sender secrets,
constructs ciphertext, and invokes a local finalizer to sign the exact Action.
The finalizer must perform no network I/O or external effects. State, plaintext
local copy, ciphertext, Action and operation identity commit before the method
returns. A retry returns those exact bytes. A changed input under the same
operation conflicts. `resolve_outbox` requires an authenticated durable home
outcome; a timeout is not rejection. Only one unresolved send per group is
allowed, including approval candidates.

`receive_with` couples MLS receive state, a valid local message or bounded
rejection, cursor movement, and the caller's archive/index updates. The caller
first verifies the home event, action, ordering, membership and history access.
It supplies the last consumed sequence and the next relevant ordered sequence;
unrelated intervening events must already have been accounted for. Duplicate
events return the saved outcome. An archive callback failure rolls everything
back. Invalid authenticated UTF-8 or text consumes the generation and records
`InvalidContent` without retaining the invalid plaintext. Invalid cryptography
first rolls back MLS changes, then separately records the authenticated home
position and rejection. Diagnostics contain no message transcript.

An owner's `preview` decrypts an exact approval candidate once and saves its
verified result privately. `decide_preview` changes only that immutable record;
the domain must check current owner authority and expiry. Matching committed
delivery uses the saved result without decrypting again. A rejected candidate
does not rewind a ratchet. At most one unresolved preview per sender/group is
stored. Approval IDs and all delegated metadata are already bound by the Action.

## Membership, ordering and recovery

`prepare_transition` creates an add, remove or self-update commit and keeps it
pending. Public handshakes are required; external joins, external senders, PSKs
and unsupported proposal families are rejected. The home uses
`create_public_in` and `accept_public_in` inside its authoritative room transaction
to verify public GroupInfo, signatures, expected epoch and the exact next roster.
`accept_public_in` also binds the actual MLS commit signer to the authenticated
HRC Action's endpoint actor; forwarding someone else's commit cannot relabel it.
The author merges only the home-selected winner; a competing local candidate is
discarded before processing that winner. Welcome bytes become available only
after the exact winning transition is durable. Durable transition receipts make
an interrupted acceptance retryable. `reject_transition` clears only a candidate
that the home has durably rejected.

Public-group validation cannot verify the private confirmation value. The home
must keep its removal/read-withdrawal send barrier until an eligible endpoint
durably verifies the exact epoch/commit and supplies its authenticated receipt.
Every other endpoint independently verifies before using the epoch. An invalid
membership transition freezes the endpoint at its existing cursor and epoch;
it is never skipped into a successor epoch. Recovery creates a new group identity
and current authorised roster. It never restores an old sender snapshot or keys
held by a removed endpoint.

The ordered profile retains **zero old epochs**, **zero out-of-order generation
keys**, and permits a **maximum forward distance of eight generations**. OpenMLS
compares the incoming generation with the next ratchet generation: generation 8
from a fresh head 0 succeeds, while generation 9 requires resynchronisation.
Eight abandoned local sends also stop further sends until an authorised epoch
update. A profile freezes after eight invalid-cryptography gaps, or immediately
when a forward-distance failure requires resynchronisation. Senders require an
epoch update after 4,096 local application sends. The UI must expose this as
maintenance requiring current home permission; an old grant is not renewed by
the crypto layer. Membership changes already produce updates.

The provider settings and failure behaviour follow the pinned upstream
[ratchet implementation](https://github.com/openmls/openmls/blob/1762090a4523cdd241f454b4058e91b64bbdc6de/openmls/src/tree/sender_ratchet.rs),
[group configuration](https://github.com/openmls/openmls/blob/1762090a4523cdd241f454b4058e91b64bbdc6de/openmls/src/group/mls_group/config.rs),
[message processing](https://github.com/openmls/openmls/blob/1762090a4523cdd241f454b4058e91b64bbdc6de/openmls/src/group/mls_group/processing.rs),
and [SQLite provider](https://github.com/openmls/openmls/blob/1762090a4523cdd241f454b4058e91b64bbdc6de/sqlite_storage/src/storage_provider.rs).
The numerical budgets are HRC policy, not claimed MLS defaults.

## Retention and integration checks

Outbox, delivery and approval tables each admit at most 10,000 records; physical
storage remains subject to the SQLCipher quota. `prune_in` shares the caller's
archive/index expiry transaction. It deletes consumed delivery/transition
records and resolved outbox/approval records for authenticated closed operation
windows. Unknown outcomes and unresolved previews remain available for explicit
resolution. Permanent closed-window tombstones prevent re-encryption after an
outbox record is removed. An old cursor beyond retained records requires explicit
resynchronisation. Retention permission and expiry dates belong to HRC policy.

The dedicated Crypto tests use actual SQLCipher and real two/three-member MLS
groups. They cover persistence/restart, exact ciphertext retry, transaction
rollback, invalid text/cryptography, one-pass approvals, bounded abandonment,
forward-distance 8/9, competing commits, Welcome failure and one-use consumption,
credential substitution, new-member history exclusion, removal, public-home
validation without member secrets, frozen transitions and retention. Real
HyperNet admission, endpoint registration, home removal barriers and interface
flows are separate integration gates; these crypto tests do not replace them.
