# Service bots

`hrc bot` runs a persistent, headless help bot through the shared authenticated
client and encrypted outbox, with optional local-model replies. It requires a
separately enrolled agent endpoint
with an explicit human operator. It does not use an operator's endpoint keys,
execute tools, or load scripts. Model inference requires explicit configuration
below. Human classification
describes an account; it does not prove that a person typed a message.

Create and enrol the agent profile using [conversation setup](ConversationSetup.md).
For independent participation, join each room using that profile before starting
the bot. Run one process per profile; the encrypted store permits one owner.

```sh
hrc bot --profile /absolute/private/agent \
  --room ROOM \
  --help-text 'Room help: ask a moderator if you need assistance.'
```

Use the exact room identity returned by the service. Repeat `--room` for up to
eight rooms. `--poll-interval-ms` accepts 1,000-60,000 and defaults to 5,000.
The interval multiplied by the room count must not exceed 120,000 milliseconds,
leaving time for bounded calls before the five-minute history cursor expires.
`--help-text` is validated protocol text of at most 1,024 bytes. SIGINT or SIGTERM
requests shutdown; an active transport operation retains its existing bounded
deadline. No direct network fallback is available.

`BotReady` with meaning `InitialAuthorisedCatchUpComplete` is a single startup
event. Every configured room must have reached an authenticated history head on
the current connection, and no bot plan may remain unresolved. A reconnect before
this event requires fresh observations for every room; a shutdown request prevents
the event. It records completion at that instant, not a promise of continuing
connectivity. The library's `run_observed` callback has these same once-only
semantics; `run` provides the ordinary silent library entry point.

## Local model chat

Use llama.cpp or Ollama on the bot's host. Install the backend and a local model
first; HRC does not download models or start the backend. Enrol a separate agent
profile and set its nickname to the name participants should see, such as `Qwen`.
Join the selected room with that profile before running the bot.

### llama.cpp

Start an installed `llama-server` with a local GGUF file and a chat template
appropriate for the model. For example:

```sh
llama-server --model /absolute/models/qwen.gguf --alias Qwen \
  --host 127.0.0.1 --port 8080 --ctx-size 4096 --parallel 1 \
  --jinja --offline --log-disable
```

The backend must provide `/props`, `/apply-template`, `/tokenize` and
`/v1/chat/completions`. HRC checks the active server context and tokenizes the
rendered chat template before generation. The smaller of the server context and
`--model-context-tokens` applies. Keep prompt logging disabled. Backend options
are described in the [llama.cpp server guide](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md).

In another terminal, start the bot:

```sh
hrc bot --profile /absolute/private/qwen \
  --room ROOM --help-text 'Qwen: type !qwen followed by a message.' \
  --model-adapter llama-cpp --model-endpoint 127.0.0.1:8080 --model Qwen \
  --poll-interval-ms 1000
```

### Ollama

Run Ollama with cloud features disabled and a loopback listener:

```sh
OLLAMA_NO_CLOUD=1 OLLAMA_HOST=127.0.0.1:11434 ollama serve
```

If an Ollama service is already running, configure these variables on that
service and restart it instead of starting a second server. Check its startup
log for `Ollama cloud disabled: true`. See
[Ollama server configuration](https://docs.ollama.com/faq#how-do-i-configure-ollama-server)
and [cloud controls](https://docs.ollama.com/faq#how-do-i-disable-ollamas-cloud-features).
Do not enable prompt debug logging.

Use `ollama list` to find an installed local model. Replace `LOCAL_MODEL_NAME`
below with its exact name:

```sh
hrc bot --profile /absolute/private/qwen \
  --room ROOM --help-text 'Qwen: type !qwen followed by a message.' \
  --model-adapter ollama --model-endpoint 127.0.0.1:11434 \
  --model LOCAL_MODEL_NAME --poll-interval-ms 1000
```

HRC checks `/api/show` before sending conversation text, rejects cloud-model
names and remote-model metadata, and uses Ollama's native `/api/chat` interface.
Cloud disabling must be applied to the daemon; setting the variable only on the
`hrc bot` command does not configure Ollama.

### Options and interaction

`--model-endpoint` and `--model` explicitly enable inference for exactly one
selected room. `--model-adapter` defaults to `llama-cpp`. The endpoint must be a
numeric loopback socket address, not a URL or hostname. HRC uses `/usr/bin/curl`;
`--model-curl` selects another absolute regular-file path. Curl configuration
files, proxies and redirects are disabled. These adapters have no external
provider mode. Chat transport continues to use HyperNet.

`--model-prefix` defaults to `!qwen`. Send `!qwen Explain the topic` to ask a
question; the prefix is removed from the current question. Add
`--all-human-messages` for a dedicated bot room where direct human messages and
threaded replies should trigger answers without a prefix. Agent messages,
delegated messages, automated causation and unrelated `!` commands do not trigger
inference. `!help` returns the configured help and available memory commands.
One answer is generated at a time. Rate and catch-up rules still apply, so
additional questions in the same history page or rate interval can be skipped.

| Option | Default | Accepted range |
| --- | --- | --- |
| `--model-context-tokens` | 4,096 | 2,048-32,768, including the reply allowance |
| `--model-output-tokens` | 512 | 128-2,048; context must exceed output plus 1,024 |
| `--memory-days` | 30 | 1-30; encrypted rooms have a seven-day ceiling |
| `--memory-bytes` | 262,144 (256 KiB) | 16,384-1,048,576 bytes |

Llama.cpp verifies prompt size with its tokenizer. Ollama uses a conservative
UTF-8 byte budget with room for the template and reply; this is not an exact token
count. Older context is removed as necessary. The current question is never
silently shortened; a question that cannot fit receives a fixed failure notice.
Increasing the context requires enough memory in the model backend.

## Conversation memory

Model bots retain room context by default in the agent profile's encrypted
store. Memory starts when enabled; it does not import earlier room history.
It survives bot restarts, with a default maximum age of 30 days and a 256 KiB
storage cap. Encrypted-room sources expire within seven days, matching the
existing decrypted archive limit. These are upper bounds, not guaranteed recall.

The bot retains at most 64 recent messages. Each answer can use up to 12 recent
messages plus a rolling summary of older context, within the model's input
budget. Summaries are limited to 1,024 bytes and can omit details or contain model
errors. Older messages are compressed in bounded groups; storage pressure can
discard them, and expiry of a summary's oldest source removes that summary.
No full archive, embedding database or unlimited conversation is sent to the
model. Long-running rooms therefore use bounded storage and bounded prompts.

| Room command | Effect | Who can use it |
| --- | --- | --- |
| `!memory` | Show counts, byte usage, retention and whether a summary exists | Direct human participants |
| `!memory show` | Show the same metadata and current lossy summary | Bot operator or room moderator |
| `!forget` | Clear retained context and start again from the current room position | Bot operator or room moderator |

These commands produce replies in the room. In particular, `!memory show` shares
the summary with current room participants. Clearing memory does not erase chat
history or replies already sent. Memory commands do not invoke the model.

Changes to the room audience, the bot's membership, recipient filters,
delegation or encrypted-room membership clear prior context before reuse. The
bot does not carry an old audience's conversation into a newly joined audience.
Current read authority is checked before generation, and current send permission
and room/filter revisions are checked when the answer is submitted. A change
during generation prevents that answer from being published.

Use `--no-memory` for replies based only on the current question. This also clears
the stored derived memory and supports older or remote HRC services without the
new bounded-history operation. Conversation history and encrypted archives are
unchanged. Memory-enabled bots currently require an updated service that hosts
the selected room; access through another service's federation route is not yet
supported. There is no silent fallback that changes the selected memory policy.

Enabling a model permits that host's model process to read the selected room's
authorised context, including decrypted confidential messages when the agent is
an admitted participant. History and summaries are supplied as untrusted data;
they cannot grant tools, credentials or broader HRC permissions.

## Model limits and recovery

Both adapters use nonstreaming text generation with thinking disabled where the
model template supports it. Requests are bounded to 128 KiB, responses to 256 KiB,
and each call to 66 chat messages. Output must be one complete assistant text
reply, at most 4,096 bytes and within normal protocol text limits. Tool calls,
truncated generation, invalid text and excessive output are rejected.

Each generation has a 60-second deadline covering its backend checks and HTTP
requests, with a two-second connection limit. A reply that first compacts older
memory can require a separate bounded summary generation. If summarisation
fails, the bot continues with the context that still fits. Stop requests cancel
and reap curl without creating a reply plan.

A model connection failure, timeout or invalid response produces a short fixed
failure notice. That notice uses the same attributed reply, permission checks,
rate limit and durable outbox as a successful answer. Reconnect resolves a stored
reply without rerunning inference. Configuration, authority and storage failures
remain terminal. HRC does not write prompt or response bodies to diagnostics.

Changing model settings requires no pending plan and resets catch-up, like other
bot configuration changes. Presence identifies a local model bot independently
of its operator. Long inference can allow its short-lived presence to expire;
presence refresh resumes with the next bot cycle.

## Rules and current authority

The deterministic rule replies only to a new original `MessageSend` containing `!help` after
whitespace trimming, from a direct account actor. Agent actors, delegated actors,
replies and events already carrying automated causation do not trigger it. The
reply names the original event as both parent and causation. The service's normal
causal deduplication, loop budgets, membership and rate checks remain authoritative.
The bot reserves at most one reply per five seconds across all configured rooms;
additional triggers in that interval are skipped, not queued into a later burst.

History is pulled through the service's current recipient filters before rule
evaluation. Ignored messages cannot trigger the bot. Its own independent agent
presence is refreshed at most every 30 seconds and expires after 60 seconds. It
never sets the represented human's presence.

`--grant GRANT_ID` explicitly selects delegated participation. The current grant
must name this exact agent endpoint and permit autonomous actions. Its room and
history scope must permit `HistoryPage` and `MessageReply` in each selected room.
The bot fetches the current grant generation; the service rechecks all effective
authority for reads and effects. A paused, revoked, expired, out-of-scope or
approval-required grant cannot produce an autonomous reply. The bot does not
create grants or approve its own actions.

## Encrypted rooms

Confidential rooms use the same bot rules after authenticated local decryption.
Before starting the process, enrol its independent MLS key, inspect and explicitly
trust the required account fingerprints, publish its room-bound package, and have
an authorised room moderator admit that package. Follow the same operations in
[confidential conversations](ConfidentialConversations.md) for each room. A
delegated bot publishes and reads using its exact selected grant. The operator
does not give the bot their private endpoint or recovery keys.

The runtime never accepts an unknown contact fingerprint automatically. A missing
key, untrusted roster, unavailable Welcome or required membership change prevents
encrypted participation until the operator completes that step. Current recipient
filters and history scope apply before rule evaluation. Rejected or unavailable
ciphertext cannot trigger a reply. After decryption, deterministic and model
triggers follow their respective rules above.

Encrypted reply preparation commits the MLS sender state, ordinary exact-byte
outbox, trigger cursor and bot plan in one transaction. Reconnect submits those
original bytes rather than encrypting again. Grant withdrawal establishes the
room's removal barrier through the ordinary service policy, and cannot be bypassed
by a queued bot plan. Decrypted local archives remain under the profile's encrypted
storage and retention rules.

## Durable progress and recovery

The bot maintains its own bounded room cursor in the existing SQLCipher store.
It does not consume transient GUI notifications. Initial startup catches up to
the current history head without responding to earlier messages. Thereafter,
the verified cursor, exact signed reply bytes, operation identity, trigger identity
and rate reservation commit together before submission. A failed transaction
advances neither the cursor nor the planned effect.

Only one bot effect can be outstanding. Reconnect resolves that exact original
identity first and resubmits its original bytes only after the service confirms
absence inside the original valid retry window. It does not retry unrelated
profile outbox entries or create a replacement message after an unknown result.
The bot obtains a fresh authorized session before its current window has fewer
than five minutes remaining. This does not change an already planned action's
window or renew HyperNet application consent.
Presence updates use the same durable plan. A crash after the client records a
terminal result but before the bot clears its plan is recovered from that retained
result, without another effect.

Transport and current-clock unavailability use capped backoff with jitter. Service
overload, rate limiting and temporary refusal retain the plan and respect retry
guidance up to 60 seconds. Identity mismatches, malformed authenticated frames,
invalid storage and permanent permission errors stop with an explicit error.
Unknown original outcomes require operator attention. Stop the bot before using
`hrc outbox`, `hrc resolve` or an exact `hrc abandon` operation on its profile.
Abandonment stops resubmission while preserving the immutable unknown record; it
does not assert rejection or retract an already committed reply.

An authenticated `CursorContext` refusal, including an ordinary room membership
change, resets that room's bot cursor and catches up without triggering old
messages. The next normal polling cycle rechecks current authority; no immediate
retry loop is used. Exact pending plans, decrypted archives and MLS state survive.
Permission refusal, expired authority and actual history gaps are not treated as
context changes.

History gaps, invalid history positions or other unrecoverable continuation states
require an explicit restart with `--resynchronise`. This replaces the stale cursor and catches up without old
triggers. It also resets the shared encrypted-history continuation and gap while
preserving decrypted archives and MLS state. Current authority is checked again
on resumed reads; no pending exact effect is discarded. Changing the configured
rooms, help text, model settings or selected grant requires no outstanding bot plan and starts
the same no-trigger catch-up. Both transitions preserve existing outbox outcomes.

The bot schema accepts version 1 only. Unknown schemas and corrupt encrypted
state fail closed. Cursors, one plan, rate metadata and optional bounded model
memory are stored in the encrypted profile. Conversation history and outbox
retention remain governed by their existing service and client policies.
