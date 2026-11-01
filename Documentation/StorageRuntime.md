# Encrypted storage runtime

HRC uses the selected SQLCipher Community 4.20.0 engine, based on SQLite 3.54.1.
The Rust binding links the controlled native library with `rusqlite 0.37`'s
`sqlcipher` feature. Plain SQLite and a different bundled engine are refused.
The connection verifies `cipher_version`, the exact SQLite source identifier,
FTS5, memory-only temporary storage and the required durability settings.

The approved SQLCipher source is commit
`355d4db92d3404e71faa8088d071a71d767807f4`. Its generated SQLite source identifier
is `2026-10-16 14:45:20 555e07ef33f69a0957d24d8e555b702464a131d6f1607f4c3c1e4551e8e6alt1`.
Build with `SQLITE_HAS_CODEC`, `SQLITE_EXTRA_INIT=sqlcipher_extra_init`,
`SQLITE_EXTRA_SHUTDOWN=sqlcipher_extra_shutdown`, `SQLITE_TEMP_STORE=3`, FTS5,
thread safety and the OpenSSL provider. Runtime checks supplement the pinned
source/build provenance; version strings alone are not a software signature.

## Files and unlocking

The data directory and independent guard directory are distinct, canonical,
owner-private directories with mode `0700`. Neither may contain the other.
Database, WAL, shared-memory, lock, guard and key files require mode `0600`.
Symlinks and substituted or multiply linked files are refused. Keep both
locations on local storage; WAL is not supported on network filesystems.

`Key::create` creates a fresh random 32-byte private file without replacing an
existing key. `Key::load` opens an existing private file. The key reaches
SQLCipher through `sqlite3_key`, never through command arguments, environment
variables, a SQL statement or diagnostics. The memory holding the Rust key is
zeroized on drop. SQLCipher memory security is enabled. This database key is
independent of account-recovery and MLS keys.

`Store::create` is explicit and refuses existing state. `Store::open` requires
existing encrypted data, the expected service/device identity and its guard.
Wrong keys, corruption and missing guards do not trigger reinitialization.
An exclusive nonblocking writer lease prevents a second HRC process from using
the same store. Directory ownership defines the local trust boundary; this does
not defend against an administrator able to rewrite every trusted local file.

## Transactions and continuity

Feature code owns tables, policy and the exact authoritative change record. A
`Store::write` closure receives a transaction and returns `Commit::new(value,
change_bytes)`. The change record includes the canonical action/outcome digests
and relevant authoritative state changes. Its size is checked before commit.
Feature code cannot attach another database, change boundary pragmas, end the
transaction itself or modify the reserved `_hrc_` continuity table.

The boundary atomically commits feature rows and the next global counter/hash
link using WAL and `synchronous=FULL`. It then atomically replaces and synchronizes
the independent continuity guard before returning the value. The caller may
publish or acknowledge only after that return. The hash link binds the previous
digest, identity, storage recovery generation, counter and bounded change digest.
Each storage incarnation begins at recovery generation 1. Loss of continuity
requires a new explicit service/device identity; it does not increment a local
counter to bypass a missing guard.

A commit or guard failure with an uncertain durable outcome fences that store.
Subsequent reads and writes fail until reopening establishes the result. On open,
matching database and guard state is accepted. A database exactly one transaction
ahead is accepted only when its verified next link names the retained guard's
counter and digest; the guard is repaired before service resumes. A database
behind, farther ahead or otherwise inconsistent is refused. Guard publication
finishes before another mutation can begin, including feature migrations and
maintenance.

A closure error or invalid change record rolls back before acknowledgement. A
normal SQL rejection does not create a durable operation result automatically;
the feature owner must store the appropriate accepted terminal outcome in its
own transaction. Errors expose stable categories without SQL text, keys or
message content. `OutcomeUnknown` is not a claim that the effect did not occur.

## Reads, quotas and migration

Reads use bounded read-only snapshot transactions. A progress handler enforces a
boot-time deadline of at most two seconds; the boundary also checks that deadline
when the closure returns. Attached databases and writes are refused during reads.
Feature code remains responsible for bounded result counts and allocations.

Limits distinguish physical database pages, retained WAL bytes and change-record
bytes from the product's logical history quotas. Defaults are 16 GiB of database
pages, 64 MiB of retained WAL and 64 KiB per authoritative change record. Feature
history, deduplication and cryptographic-state budgets are enforced by their
owners; this disk ceiling does not silently shorten their accepted retention.
SQLite's page-count limit refuses growth past the physical database ceiling.
Storage checks WAL admission bounds and checkpoints after each committed write;
a busy checkpoint or uncertain I/O result stops further effects. A feature's
transaction must also bound its payload and work: the change-record digest is
not a substitute for charging the rows it modifies.

The storage schema is versioned independently from feature schemas. Features
create or migrate their own versioned tables through the same guarded transaction
API before accepting live operations. Unknown storage schemas and corrupt
continuity rows refuse startup. An existing database is never silently reset.
Automatic backups are not enabled by this module. A consistent snapshot must
exclude the independently retained guard from rollback and obey the configured
backup destination, retention and disclosure policy.

The database contains service-readable room content only where policy permits.
Confidential room content remains ciphertext at the service. Device MLS state,
outbox and decrypted local archives can share one transaction with their feature
records through the upstream SQL storage provider. This boundary does not itself
implement the MLS lifecycle or grant access to conversation history.

Sources: [SQLCipher release source](https://github.com/sqlcipher/sqlcipher/tree/355d4db92d3404e71faa8088d071a71d767807f4),
[SQLCipher API](https://www.zetetic.net/sqlcipher/sqlcipher-api/),
[SQLite WAL](https://sqlite.org/wal.html), and
[rusqlite linkage selection](https://github.com/rusqlite/rusqlite/blob/v0.37.0/libsqlite3-sys/build.rs).
