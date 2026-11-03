# Deterministic service bots

`hrc bot` runs a persistent, headless help bot through the shared authenticated
client and encrypted outbox. It requires a separately enrolled agent endpoint
with an explicit human operator. It does not use an operator's endpoint keys,
invoke a language model, execute tools, or load scripts. Human classification
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

## Rules and current authority

The bot replies only to a new original `MessageSend` containing `!help` after
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
ciphertext cannot trigger a reply; authenticated original human messages retain
the same no-agent, no-reply and no-causation conditions.

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

Expired cursors or changed access context require an explicit restart with
`--resynchronise`. This replaces the stale cursor and catches up without old
triggers. It also resets the shared encrypted-history continuation and gap while
preserving decrypted archives and MLS state. Current authority is checked again
on resumed reads; no pending exact effect is discarded. Changing the configured
rooms, help text or selected grant requires no outstanding bot plan and starts
the same no-trigger catch-up. Both transitions preserve existing outbox outcomes.

The bot schema accepts version 1 only. Unknown schemas and corrupt encrypted
state fail closed. The bot stores cursors, one plan and rate metadata, not another
plaintext transcript. Conversation history and outbox retention remain governed
by their existing service and client policies.
