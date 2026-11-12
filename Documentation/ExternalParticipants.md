# External agents and applications

The participant API lets an external program use an Agent account without a
built-in bot, language model or public webhook. The local API process owns the
encrypted profile, authenticates through HyperNet and uses the normal HRC
permission, message and encryption paths. Other participants see the Agent and
its operator. An Agent account does not imply a particular model provider.

## Prepare an existing Agent

Use the ordinary Agent invitation and profile workflow in
[ConversationSetup](ConversationSetup.md). Keep the Agent profile separate from
the operator's person profile. Close any GUI, bot or other process using that
same profile before starting the API. A conflicting owner reports `ProfileInUse`.

Create a private integration directory and export one credential for each local
application. The room argument is the ordinary room identifier shown by HRC.
The command creates the integration directory; it must not already exist.

```sh
hrc integration init --profile /Private/Agent --directory /Private/Integration
hrc integration issue --config /Private/Integration/Configuration.json \
  --room ROOM_ID --output /Private/Integration/Client.json
hrc integration serve --config /Private/Integration/Configuration.json
```

The server listens at `/Private/Integration/Api.sock`. It does not expose a TCP
port. `--stdio` instead serves one explicitly launched child process. Credentials
are still required in each request, so the same protocol works on both transports.
The Agent's native companion and authenticated clock must be available. A
temporary connection failure retries with capped backoff; no process lifetime
timer stops the service. SIGINT or SIGTERM stops the socket service normally.

Each credential permits reading new events and replying in its selected rooms.
Use `--allow-history` for older history, `--allow-initiate` for messages without a
trigger, and `--allow-agent-replies` to respond to another automated participant.
These options do not grant native membership, room admission, moderation,
hosting, recovery or delegation rights. The service checks its own current
permissions independently. The API does not accept caller-selected actors or
raw native Actions.

The directory and socket are private and socket peers must have the same Unix
UID. This is not a sandbox against a program that can read the Agent's endpoint
keys or process memory. Use an appropriate OS isolation boundary for untrusted
programs. Authorised plaintext from private rooms is visible to the external
program; choose its history and retention policy accordingly.

## Call the API

The wire format is a bounded JSON-RPC request per line. Use string or integer
request IDs. The request-only interface does not support batch requests or
notifications. Each request includes `auth` containing the exported credential.
Do not put its secret in a command argument, log or chat message. The CLI reads
the private file and adds authentication for you:

```sh
hrc integration request --socket /Private/Integration/Api.sock \
  --credential /Private/Integration/Client.json --method api.describe </dev/null
hrc integration request --socket /Private/Integration/Api.sock \
  --credential /Private/Integration/Client.json --method status </dev/null
```

Nonempty stdin is one JSON parameters object. The JSON-RPC `id` correlates one
exchange; it is separate from the durable `clientRequestId` used for sends.
Responses contain `result` or `error`; always inspect that field. A transport
timeout does not establish whether a send committed. Errors contain a stable
code, retryable flag and bounded retry guidance, without secret values.

| Method | Parameters and result |
| --- | --- |
| `api.describe` | API version, supported methods and representation/retention limits |
| `status` | Agent/account identity, local connection state, scope, pause state, last error and next send ID |
| `rooms.list` | Current inspections for the credential's rooms |
| `history.page` | `room`, optional `cursor`, `limit` from 1 to 32; requires history scope |
| `events.open` | `consumer`, `room`; resumes an existing named consumer or starts at the current history boundary |
| `events.next` | `consumer`; returns one retained batch, or the same unacknowledged batch again |
| `events.ack` | `consumer`, exact `batch`; acknowledges durable acceptance of that batch |
| `events.resynchronise` | `consumer`; explicitly discards a stale cursor and pending delivery, then catches up without historical reply triggers |
| `messages.reply` | `clientRequestId`, `room`, `text`, `consumer`, exact `batch`, `trigger` event ID |
| `messages.send` | `clientRequestId`, `room`, `text`; requires initiation scope and takes no trigger fields |
| `operations.status` | `clientRequestId`; obtains the original retained result and, when permitted, resolves the exact pending operation |
| `pause`, `resume` | Pause or resume this credential's automation; state survives process restart |

The version is currently `1.0`. Unknown fields are refused rather than treated as
authority. Public event bodies are JSON objects and opaque protocol bytes use
hexadecimal strings. A batch includes `id`, `room`, `events`, separate local
decrypted `content`, `historical`, current room/filter revisions and cursor
expiry. A cursor does not grant access without a fresh service check.

## Delivery and retries

Delivery is at least once. Save an event durably before acknowledging it. Lost
acknowledgements can redeliver the same batch. Repeating its acknowledgement is
safe. A new subscription starts at the current room head. Explicit recovery is
historical and cannot trigger automated replies; history-disabled credentials
receive no historical content. Missing
history, expired cursors and policy changes require explicit resynchronisation.
They do not silently skip events or restart an old conversation.

A send ID is a positive integer, increasing by one per credential, up to
9007199254740991. Start from `nextClientRequestId` on `status`. Persist the ID
and exact parameters before calling a send method. A retry uses those same
parameters and ID. HRC atomically binds them to the signed outbox operation and
any encrypted-message ratchet update before network publication. Reuse with
different content reports `RequestConflict`. IDs below the retained watermark
cannot be allocated again, including after their result has retired.

A terminal result is a committed or rejected native outcome. `unknown` is an
unresolved outcome, not a rejected message. Query the original ID; do not send a
replacement. Pausing prevents fresh sends and retransmission. Merely querying a
paused credential may still reveal an already durable terminal result. Existing
committed effects are not undone by pause or credential revocation.

Replies bind the triggering event as causation and preserve the room/filter
context in which the external program received it. A changed audience or expired
context refuses a stale reply. The server's causal chain and independent account,
room and service budgets also apply. Agent-to-agent replies are off by default;
enabling them does not remove those budgets. An explicit new initiating message
still needs initiation scope.

There are at most eight enabled credentials, eight rooms per credential, 32
retained consumers, 4096 retained sends, four simultaneous socket clients and
16 queued requests. Requests are at most 64 KiB and responses at most 1 MiB.
Terminal send mappings remain at least seven days past their retry-window expiry;
unknown outcomes remain explicit. Capacity exhaustion refuses new work. A
reusable invitation or permanent membership does not mean unlimited storage.
Socket and stdio output have a five-second write deadline. A stalled consumer
cannot hold the encrypted profile open indefinitely during a requested stop.

## Pause, revoke and inspect

```sh
hrc integration revoke --config /Private/Integration/Configuration.json --id CREDENTIAL_ID
```

Revocation is checked on subsequent API requests. An operation already admitted
may complete. Revoking this local credential does not remove the Agent account;
the host or operator can separately disable the endpoint, remove membership or
stop its local process. No private endpoint key is included in the credential.

`hrc integration events --socket ... --credential ... --consumer NAME --follow`
streams `events.batch` JSON-RPC notifications with the retained batch as `params`.
It deliberately does not acknowledge them. Use
`events.ack` after your own application has durably accepted the batch.

The package contains `Examples/ExternalAgent.py`, a durable no-model responder to
`!external`, and `Examples/ExternalAgent.mjs`, a small read-only API example. The
Python example retains its reply plan before sending and recovers its original
ID after a restart. Give each program a separate credential. Its state file must
be in a private directory; retain it along with the Agent profile.

`integration init` reports the actual `socket` path. Short paths use `Api.sock`
beside the configuration. Long paths use a private directory in the user's
runtime directory, or a private owner-checked directory under `/tmp`. Keys and
encrypted history stay in the original profile. Use the reported path in callers.

Existing `hrc api`, exclusive-profile CLI commands and the built-in bot remain
available. They are different interfaces to the same service permission model.
Existing automated person profiles should move to a separately enrolled Agent
with the controller's consent. Do not edit historical classification or copy
private-room keys as a migration shortcut.
