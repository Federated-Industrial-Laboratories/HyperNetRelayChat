# Service and client setup

The Linux command-line workflow uses existing HyperNet Core 0.10.1 and Suite 0.10.0
deployment. Its receiving application service and each caller require explicit
HyperNet admission, current grants, and a configured `hrc/1` stream binding or
target. HRC does not create application consent or renew it automatically.

The service is authoritative for accounts, rooms, delegation, moderation and
ordered history. Each client owns a separate endpoint signing key and encrypted
local database. A signed session challenge binds the endpoint to its currently
authenticated HyperNet principal. A caller-supplied account name alone is never
authentication.

## Create a home service

Build with the [repository instructions](../README.md). Use absolute canonical
paths. Parent directories for configuration, invitation and registration files
must already exist, belong to the current user and have mode `0700`. Files are
created with mode `0600`. New service and profile directories must not exist.

The clock observation and its pinned public key come from the deployment's
HyperNet host clock monitor. They are separate from account and service keys.
Use the real network, incarnation, service and principal identifiers supplied by
HyperNet. Identifier components are 64 lowercase hexadecimal characters.

```sh
hrc service init --directory /private/hrc-home \
  --network NETWORK --incarnation INCARNATION --service SERVICE \
  --companion /private/home-companion \
  --clock-observation /private/clock/Observation.cbor --clock-key MONITOR_PUBLIC_KEY
hrc service invite --directory /private/hrc-home \
  --principal CALLER_PRINCIPAL --output /private/exchange/Invitation.json
```

An invitation binds one HyperNet principal and account classification, expires,
and can be used once. Add `--operator ACCOUNT` to create an agent invitation;
the operator must be an enrolled human account. Account identifiers contain
network, incarnation and local account components separated by colons. Room
identifiers additionally contain their home service component.

## Enrol an endpoint

Transfer the invitation through an explicitly approved private channel. Its
service signing key is the trust anchor: verify its source before accepting it.
The endpoint generates its own account and endpoint identifiers and signs the
registration request. Its private key is never sent to the service.

```sh
hrc profile create --directory /private/hrc-device \
  --invitation /private/exchange/Invitation.json \
  --recovery-key-file /private/owner-recovery/Account.key \
  --registration-output /private/exchange/Registration.cbor \
  --companion /private/client-companion \
  --clock-observation /private/clock/Observation.cbor --clock-key MONITOR_PUBLIC_KEY
hrc service enrol --directory /private/hrc-home \
  --registration /private/exchange/Registration.cbor
hrc service run --directory /private/hrc-home
```

Service setup, invitation and enrolment currently require the service to be
stopped. The exclusive database lease refuses competing processes. Never copy
live database files to bypass that lease. The owner recovery key must be stored
outside the device directory and kept separately; it is not an encryption-history
backup. New-device encrypted history remains future-only.

Add `--diagnostics` to `service run` to report fixed lifecycle categories on
standard error. Diagnostics contain no messages, account identifiers or keys.
Failed authority observations include fixed disposition categories and monotonic
deadline timings. Authentication failures identify their fixed validation stage.
Output is limited to a burst of eight lines, one line per second thereafter and
128 lines per process. Client errors distinguish local configuration and storage,
HyperNet preparation, session authentication, clock and handshake failures.
`AcceptWaitEnded/Timeout` can mean an ordinary idle wait; it does not establish a
failed client operation. Periodic retention runs in one background task every
30 seconds and writes only when expired state exists. Every operation still
enforces current access and expiry before returning content or applying effects.
The companion accept wait allows five seconds for transport handoff, including
its current privacy observation. HRC's subsequent handshake retains its separate
five-second bound; acceptance never extends an authority observation's validity.

The service admits authority checks through one bounded FIFO shared by session
setup, actions and exact search cancellation. At most 32 callers can hold or wait
for its single exchange slot; each admission wait is at most one second. A queued
control cannot be overtaken by later ordinary reads. Queue saturation or an
admission timeout reports `AuthorityAdmissionBusy` (an `Overloaded` pre-admission
action refusal), separately from a failed transport authority check. Shutdown,
stream invalidation or query cancellation removes a waiter.

After admission, each check starts a fresh nonce and a separate lifetime of at
most one second. The original five-second handshake and ten-second search ends
also cap admission and check time; neither is restarted. The exchange slot is
released before Home state is locked or work executes. The resulting observation
must still be currently permitted at every existing admission and commit check.
This scheduling does not extend a receipt, reuse authority, retry an effect, or
conceal a Core busy or unavailable result.

Ordinary, device and gateway handshakes can obtain at most three fresh authority
observations on the same stream for their unchanged proof digest. A temporary
unavailable or expired observation, or busy authority admission, allows a backoff
of at most 50 ms before another check. Each check retains the existing admission
and exchange limits; all attempts also fit the original handshake deadline and
signed challenge expiry. The challenge and transport identity do not change.
The initial conservative clock sample can shorten the boot deadline to fit the
signed expiry; later samples cannot extend it. A successful observation retains
that shortened deadline and rechecks the current clock before an effect or Ready.
Denied or inactive results, invalid evidence, clock errors and shutdown stop
recovery immediately. A certified denial remains terminal after its receipt
expires. Device activation and session-window effects remain outside this retry
loop and require a current observation at their original effect boundary.

If transport handoff closes before session setup finishes, the client can obtain
up to three fresh streams and challenges within one 30-second setup budget,
with bounded jitter between attempts. Invalid identities and frames fail at once.
This setup retry never submits a conversation operation or reuses old authority.

## Conversation operations

```sh
hrc profile session --profile /private/hrc-device
hrc room create --profile /private/hrc-device --name laboratory
hrc room list --profile /private/hrc-device
hrc room join --profile /private/hrc-device --room ROOM
hrc send --profile /private/hrc-device --room ROOM --text 'Hello'
hrc history --profile /private/hrc-device --room ROOM
hrc search --profile /private/hrc-device --room ROOM --term hello
```

Commands return structured JSON. Use the room identifier returned by create or
list. `--reply EVENT` sends a reply, and `--action` sends a typed action message.
Opaque identifiers and byte strings use lowercase hexadecimal in JSON, including
inside result bodies. The native wire still uses canonical CBOR byte strings.
Structured API requests reject duplicate JSON keys and use the native protocol's
depth, collection and node bounds before constructing or signing an operation.
History and search return a signed cursor; pass its hexadecimal bytes to
`--cursor` for continuation. Access, current recipient filters and retention are
checked on every read. Repeating a read obtains current authorized results.

The client writes the exact signed effect to its encrypted outbox before sending.
The service commits its outcome with the event before acknowledging it. An I/O
failure can leave the outcome unknown. Reconnect with current permission and run:

```sh
hrc resolve --profile /private/hrc-device
```

Resolution never allocates a replacement message ID. It retries the original
bytes only when the home proves absence within the original open retry window.
An expired or unavailable outcome remains explicit. Drafts survive unknown
outcomes and are cleared only after a committed message response.

Draft preservation does not require a healthy network or clock monitor:

```sh
hrc draft save --profile /private/hrc-device --room ROOM --text 'Work in progress'
hrc draft get --profile /private/hrc-device --room ROOM
hrc outbox --profile /private/hrc-device
```

Outbox inspection lists unresolved identities without printing their message
content. A send saves its draft before attempting to open a network session.

## Agent control

Agent endpoints enrol separately and authenticate with their own keys and
HyperNet principals. Use `hrc agent grant --permissions FILE` with the closed
`Delegation.Create` permission object described by the operation specification.
It contains the exact agent endpoint, rooms, recipients, allowed operations,
history interval, validity, rate limit, purpose and selected operating mode.
The owner can inspect, export, pause, resume or permanently revoke that grant.

`hrc send --grant FILE` records delegated attribution. The service checks the
grant and represented account's current rights at the serial operation boundary.
Approval mode requires a prepared exact signed candidate and an owner decision
bound to its digest. A changed action requires another approval. The structured
`hrc api --request FILE` command uses the same native operations and authorization.

For exact approval, the agent first uses `hrc send --prepare CANDIDATE_FILE` with
its explicit grant. This saves the signed bytes and returns the approval ID and
action digest without sending the message. The agent submits that file through
`hrc agent prepare`; the owner inspects it with `hrc agent inspect` and binds an
`approve` or `reject` decision to the returned digest. After approval, the agent
uses `hrc submit --candidate CANDIDATE_FILE`. It does not construct a new send.
The structured API also supports `--sign-output CANDIDATE_FILE` for an explicit
review step. Candidate exports contain the selected action and must be shared
only through an approved private path.

All setup and conversation commands keep HyperNet mandatory. Transport protection,
optional relay obfuscation and message encryption are distinct properties. The
current community-room commands use service-readable messages. Confidential
conversation commands require the integrated MLS lifecycle and are never replaced
with plaintext when encryption is unavailable.
