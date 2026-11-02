# Endpoint lifecycle and account continuity

This profile implements endpoint admission, removal and owner-key recovery. It
does not restore message keys or old encrypted history. Confidential-room removal
barriers share the identity transaction through the confidential feature boundary;
encrypted recovery is complete only when that feature's epoch workflow succeeds.

## Controllers and ordinary operations

A current direct human endpoint controls its own account and agent accounts whose
operator is that human. Independent and delegated agents cannot enrol endpoints,
disable endpoints or rotate recovery authority. A disabled endpoint cannot resume
its old session. Account recovery advances the account security generation and
invalidates all previous endpoint generations.

`AccountEnrolEndpoint` (92) approves an exact new-key-signed `DeviceRequest` for a
finite admission ticket. It does not activate the endpoint. The newly admitted
HyperNet principal must finish the separate device challenge before ordinary HRC
authentication is possible. `AccountDisableEndpoint` (93) removes an exact
endpoint and cancels its pending admission. `AccountRotateRecovery` (91) binds a
proof signed by the replacement recovery key, the current account revision and
the current continuity head. The existing Action/outbox retry rules apply.

`AccountDevices` (94) returns a bounded current account/endpoint snapshot.
`AccountContinuity` (95) pages the public continuity records.
`AccountLifecycleOutcome` (96) lets a current controller inspect the exact retained
outcome of an earlier account-control Action, including after its original endpoint
was disabled. It does not resubmit that Action or grant an old endpoint authority.

## Fresh device exchange

The new endpoint creates private signing and SQLCipher keys locally. Its immutable
`DeviceRequest` binds home, account, request ID, new endpoint/key, exact destination
HyperNet principal, purpose and original expiry. Purpose is controller-approved
enrolment, owner-key recovery, or owner-key recovery-key rotation. Rotation also
binds a replacement-key possession proof. The request is signed by the new endpoint
key before it leaves the device. No endpoint or recovery secret enters a payload.

Ordinary-size frames 13-16 are `DeviceHello`, `DeviceChallenge`, `DeviceProof` and
`DeviceReceipt`. They use distinct signed object roles. The service accepts this
exchange only on an actual admitted HyperNet stream. It binds the challenge to the
incoming principal, stream session/generation, service boot, immutable request
digest, current account/security/recovery generations, current continuity head,
fresh random nonce and expiry. The complete exchange has the same original
five-second handshake ceiling as ordinary authentication.

The new endpoint signs the exact home challenge. Recovery or owner-key rotation
also requires that challenge to be signed by the currently enrolled recovery key.
An administrator or ordinary service signature cannot substitute for it. Enrolment
instead requires a current, unexpired controller ticket for this exact request.
The approving controller must remain eligible. The service obtains a fresh
action-bound HyperNet authority check and rechecks its original lifetime, account
state, ticket/key authority and request expiry at the serial mutation boundary.
There are no network calls inside that transaction.

Only one challenge exists on an active device exchange. Disconnect or restart
discards it. A consumed challenge cannot perform another transition. Fresh
challenges can resolve the same immutable request ID and digest after a lost
receipt; they do not recreate an endpoint or alter the original outcome. Original
request expiry and current eligibility remain required. Reusing the request ID
with different bytes fails. Failed key possession never consumes a valid ticket.

## Atomic effects and continuity

Activation records the new endpoint binding, consumes its admission ticket,
appends a continuity record and stores the exact outcome in one guarded home
transaction. Recovery additionally advances the account security generation,
disables old endpoints, clears presence and pending admissions, invalidates pending
approvals and pauses affected owner, acting-agent and operator grants. Queued
old-generation work is rejected. Confidential invalidation runs in that same
transaction before acknowledgement; its failure rolls back the identity change.

Recovery-key rotation proves possession of the new key, changes its generation,
and records the authorizing current controller or old recovery-key signature.
It does not itself restore archives or authorize ordinary messages. Losing all
controllers and the recovery secret requires a new account.

Continuity records retain the authorization bytes, previous record digest,
resulting public account state and home position. New accounts start with their
original signed registration. Existing stores that did not retain this signature
receive an explicitly labelled service-only legacy anchor. That anchor is not
owner-signed and cannot silently replace a contact's trusted anchor. Contacts must
deliberately accept a legacy trust starting point. Later endpoint and recovery
transitions retain their actual controller/new-key/recovery-key signatures.

The client replays the signed transition chain from an explicitly accepted
first-contact fingerprint and persists that anchor in its encrypted local store.
Encrypted admission verifies registration, endpoint possession and controller or
recovery authorization before accepting roster key changes. An agent's operator
binding is verified separately from its represented account and exact grant.
Changed or incomplete continuity blocks admission; a service response cannot
silently reset a pin. Service history alone is not proof of contact continuity.

`AccountPublicIdentity` (97) supplies bounded identity evidence only within a
currently authorized room, roster or admission context. A retained transition
reference can authorize verification of a historical participant needed for
current permitted encrypted history or a selected Welcome. It does not expose
a general account directory or restore a former participant's room access.

Public inspection exposes keys and opaque principal identifiers, never secrets,
transport addresses, private paths or message content. Chain pagination and account
endpoint counts are bounded. A full chain or quota refuses further changes rather
than deleting the continuity evidence needed to verify earlier transitions.

Each account has at most eight active endpoints and 1,024 continuity records,
with a 16 MiB continuity budget. A page contains 1-16 records and is shortened to
the ordinary response bound. At most 128 admission tickets are simultaneously
active; a ticket lasts at most ten minutes within the original request expiry.
There are at most 10,000 retained ticket identities and 10,000 device receipts per
service. Device requests expire within 24 hours. Exhaustion refuses new work;
these initial pilot limits do not permit silent deletion of retry identities.

## CLI workflow

Each path below must be absolute and owner-private. Keep recovery keys outside
ordinary device and bot directories. The service descriptor contains public
information; exchange and pin it deliberately.

```sh
hrc profile identity descriptor --profile /private/controller --output /private/exchange/Service.json
hrc profile identity prepare --directory /private/new-device \
  --server /private/exchange/Service.json --account ACCOUNT --principal PRINCIPAL \
  --purpose enrol --request-output /private/exchange/Device.cbor \
  --companion /private/companion --clock-observation /private/Clock.json --clock-key CLOCK_KEY
hrc profile identity authorize --profile /private/controller --request /private/exchange/Device.cbor
hrc profile identity activate --directory /private/new-device
hrc profile session --profile /private/new-device
```

HyperNet admission for `PRINCIPAL` is a prerequisite, independent of controller
approval. For recovery, prepare a fresh directory with `--purpose recover`, omit
controller authorization, then activate with `--recovery-key-file` naming the
separately retained existing owner key. Failed or uncertain activation keeps the
same signed request; repeat `activate` to resolve it. It never generates another
endpoint or request automatically. A locally persisted committed receipt can
finish interrupted profile-file creation; ordinary login still checks current
authority. The profile's legacy `registration.invitation` metadata field records
the device request ID for these subsequent admissions, not an unused invitation.

```sh
hrc profile identity devices --profile /private/controller
hrc profile identity disable --profile /private/controller --endpoint ENDPOINT
hrc profile identity key-create --output /private/owner/NewRecovery.key
hrc profile identity rotate --profile /private/controller --replacement-key-file /private/owner/NewRecovery.key
hrc profile identity continuity --profile /private/controller --after 0 --limit 4
```

An owner without a surviving controller can rotate through a temporary prepared
request with `--purpose rotate-recovery --replacement-key-file NEW_KEY`, then
activate with the existing owner recovery key. This does not enrol the temporary
endpoint or disable surviving devices. Ordinary controller operations keep their
exact Action/outbox outcomes. A surviving controller can inspect a disabled
endpoint's earlier control outcome with `profile identity outcome`, supplying the
original window, operation and action digest. `--account` selects an owned agent
account where applicable. No command prints or exports a recovery secret.
