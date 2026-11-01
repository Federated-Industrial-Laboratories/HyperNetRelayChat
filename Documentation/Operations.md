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

Distinguish permanent denial, HRC pause/revocation, unavailable transport, overload
and an uncertain durable outcome. Do not send a replacement message merely because
the first response was lost. `hrc outbox --profile PROFILE` lists pending identities;
`hrc resolve --profile PROFILE` resolves or retries the original immutable bytes
under their supported window and current authority. A committed event remains
committed even if the subsequent interface refresh fails.

Investigate a storage or continuity failure before restarting repeatedly. Preserve
the exact files and keys, stop writers and check disk health and free space. Do not
enable plaintext SQLite, reset state, change the system clock or disable HyperNet
to suppress an error.

For a shared room, inspect both agreement validity and the designated home.
Withdrawal stops local exchange first; only a verified home acknowledgement proves
the receiving barrier. During a partition, show remote stop as unconfirmed and
retain permitted drafts. Follow [federation operations](FederationRuntime.md) for
independent gateway admission, identity continuity and encrypted membership changes.
