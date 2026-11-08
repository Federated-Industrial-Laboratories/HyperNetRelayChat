# Operating an HRC service

An HRC home owns one ordered event history and one guarded encrypted database.
It is not a replicated cluster. HyperNet provides transport and current application
authority; HRC enforces account, room, delegation and federation policies.

## Start and stop

Complete [service setup](ConversationSetup.md) while the service is stopped, then
run `hrc service run --directory SERVICE`. SIGINT and SIGTERM request orderly
shutdown. Clients retain drafts and exact uncertain operations during outages.
After a restart, require current HyperNet permission and a healthy pinned clock
observation. A running process alone does not establish readiness.

Use `hrc transport status --companion COMPANION` to inspect the actual companion
capabilities and directional privacy facts. Use a separately enrolled operator
profile for authenticated room and grant inspection. Current service-readable
room access does not grant access to confidential content keys.

HyperNet application consent and route lifetimes remain finite. An expired route
can require a fresh authorized stream; expired consent requires the HyperNet
renewal procedure. HRC cannot extend either by retrying or changing its clock.
Preserve the chosen relay policy when restoring service.

## Restrict conversation creation

The local service operator can restrict new rooms and direct conversations to
an explicit list of enrolled human accounts. This policy is enforced by the
service, including requests from older or modified clients. It grants no other
account or room permissions. An agent cannot use its operator's listed account;
delegated creation remains refused. Existing rooms, memberships, messages and
moderator rights remain unchanged.

In **Operations > HRC service > Room creation**, load the current policy, select
**Only selected human accounts may create conversations**, and enter complete
account identifiers, one per line. Apply the policy. An empty list disables all
new conversation creation. At most 32 distinct local human accounts are accepted.
The managed service briefly stops, updates its private configuration atomically
and restarts if it was running. A service started outside these managed controls
must be stopped separately; the exclusive store lease prevents a live update.

The equivalent managed commands are:

```sh
hrc manage service room-creation --config /private/Home.json
hrc manage service room-creation --config /private/Home.json --account OWNER_ACCOUNT
hrc manage service room-creation --config /private/Home.json --deny-all
```

Repeat `--account` to replace the list with several permitted accounts. With no
selection flag the command inspects the current policy. `--allow-all` explicitly
restores the original creation rules. A stopped, directly operated service uses
the same selections with `hrc service room-creation --directory /private/hrc-home`.
Use `hrc profile session --profile PROFILE` to obtain an authenticated account ID.
An account must already be enrolled before it can be listed.
If an update reports an unconfirmed result, inspect the retained policy before
retrying. A completed replacement can remain in place after a later I/O error.

Existing configurations default to `all` for compatibility. Configure the policy
before admitting untrusted participants. Restricting creation also blocks new
confidential direct conversations and private groups for excluded users. Existing
conversations remain available under their normal access rules. HRC services
older than this setting cannot load the updated configuration; do not downgrade
to bypass the restriction. Core, Suite and the HRC wire format are unchanged.

## Persistent state and backups

Keep service and client directories on private local storage with the required
owner and file modes. Store their continuity guards independently. Retain the
database, WAL and shared-memory files together while a store is active. Do not
copy live database files as a backup, edit SQL rows or discard an unfamiliar file
to make startup succeed.

There is no automatic backup scheduler. Stop the owning process before making an
encrypted backup of its state and configuration through an approved private path.
Protect database keys, endpoint keys and local indexes consistently with their
content. Keep the current continuity guard outside a backup's rollback authority.
Account recovery keys belong to their owners and remain separate from devices.

A backup is not permission to roll identity or operation history backward. The
store refuses a database behind its retained guard. An interrupted commit exactly
one verified transaction ahead can repair its guard on open; other discrepancies
require investigation. HRC has no administrative bypass or automatic restoration
of an old snapshot under the same identity. Loss of the current authoritative
store without valid continuity requires a new explicit service identity and new
agreements. Preserve the old encrypted files for investigation; do not pretend an
empty replacement contains the old history.

Owner-key account recovery is a separate [endpoint lifecycle](EndpointLifecycle.md).
It fences old devices and delegated authority without recovering prior message
keys. New and recovered devices receive future encrypted content only. Losing all
authorized devices and the pre-enrolled recovery key requires a new account.

## Retention and disclosure

The initial service policy retains conversation events for 30 days within a 10 GiB
logical history quota. Accepted operation outcomes remain for at least seven days
and beyond their original retry window; a client retry window lasts at most 24
hours. Removing conversation content does not reopen a used operation identifier.
Physical storage limits and continuity checks also apply.

Expiry is checked when reading and applying effects. Background maintenance removes
expired rows in bounded batches, with their derived indexes; it does not make
already expired content temporarily readable. A history gap returns an explicit
resynchronization result. Clients maintain their own bounded encrypted caches and
archives. Previously authorized recipients may already hold copies that HRC cannot
retract.

History and search commands deliberately return selected authorized content on
standard output. Treat redirecting that output to a file or another process as a
disclosure. Grant and exact-action exports likewise contain selected private state.
HRC does not automatically export a whole transcript, fetch external links or send
content to a model. Confidential plaintext search runs on authorized endpoints;
the home service stores and searches no plaintext confidential transcript.

## Diagnostics and recovery

`service run --diagnostics` emits fixed categories and bounded authority timing,
without message bodies, account identifiers or keys. Its burst is eight lines,
then at most one per second, with 128 lines per process. It is diagnostic output,
not an audit transcript or a substitute for attributable moderation history.
The flag also permits a separate best-effort sample of verified local message
sends: two per second, burst four, at most 512 records per process. Fixed
`MessageTiming` spans distinguish authority admission and checking from remaining
execution, signing/encoding and response write. `authorityAdmissionNs` and
`authorityCheckNs` partition the combined `authorityNs` span. Admission includes
the bounded HRC queue; checking includes companion IPC and its fresh authority
exchange. Refused admission has no check span. The subsequent bounded FIFO wait
for serialized Home access belongs to `executeNs`, not `authorityAdmissionNs`.
Current authority and the clock are checked again after that wait, before effects.
Outcome labels contain no details. These service spans are not client exchange
latency or delivery receipts; missing records do not imply success. See
[conversation setup](ConversationSetup.md) for the precise boundaries and bounds.

Distinguish permanent denial, HRC pause/revocation, unavailable transport, overload
and an uncertain durable outcome. Do not send a replacement message merely because
the first response was lost. `hrc outbox --profile PROFILE` lists pending identities;
`hrc resolve --profile PROFILE` resolves or retries the original immutable bytes
under their supported window and current authority. A committed event remains
committed even if the subsequent interface refresh fails.

Local community sends and searches from direct users or independently acting
agents receive a bounded, read-only budget screen before the fresh HyperNet
check. It can only reject demonstrated exhaustion; it grants no permission and
does not reserve or charge credit. It verifies current endpoint and room bindings
and leaves retained outcomes, conflicts and uncertain state on the existing
fresh-authority path. Delegated, remote, confidential and other operations retain
that path as well. Work that passes the screen still receives current authority,
all guarded Home policy checks and one atomic budget charge. Concurrent screens
can pass together and subsequently be refused by final admission.

Investigate a storage or continuity failure before restarting repeatedly. Preserve
the exact files and keys, stop writers and check disk health and free space. Do not
enable plaintext SQLite, reset state, change the system clock or disable HyperNet
to suppress an error.

For a shared room, inspect both agreement validity and the designated home.
Withdrawal stops local exchange first; only a verified home acknowledgement proves
the receiving barrier. During a partition, show remote stop as unconfirmed and
retain permitted drafts. Follow [federation operations](FederationRuntime.md) for
independent gateway admission, identity continuity and encrypted membership changes.
