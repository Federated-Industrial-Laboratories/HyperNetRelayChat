# HyperNet transport tools

The first HRC implementation provides a Linux Rust adapter and command-line
transport diagnostics. It connects only to an existing, explicitly configured
HyperNet Suite companion through its private Unix socket. It does not open an
Internet listener, create a direct route or renew application consent.

These commands qualify the transport dependency. They do not provide rooms,
messages, persistence, delegation, federation or encrypted conversations. The
complete chat protocol remains under design. There is no installable HRC release.

## Build and check

Use Rust 1.96 or later on Linux. From the repository root:

```sh
cargo build --locked
bash Tools/Check.sh
cargo install --locked --path .
hrc --help
```

`cargo install` installs the diagnostic executable into the selected Cargo binary
directory. It does not install or configure a system service. The crate is marked
`publish = false`; no software licence has been selected. Generated binaries and
Cargo's build cache are excluded from the repository. All maintained test bodies
are under `Tests/`; production source is under `Source/`. Pull requests run the
same format, Clippy and test checks on Ubuntu 24.04 with Rust 1.96.0. Hosted CI
does not create a HyperNet network; native qualification is a separate check.

## Companion prerequisites

Use matching HyperNet Core and Suite 0.10.0 with an admitted application and the
version-2 `checkAuthority-v2` capability. Configure the receiving service and the
caller's named target with the diagnostic protocol `hrc-probe/1`. The accepted
binding, target service, route policy and current application permissions must
already be valid. Follow the released Suite application-stream setup procedures;
HRC does not broaden those permissions.

The companion directory must be an absolute, canonical directory owned by the
current user with mode `0700`. Its `Control.sock` must be an owned Unix socket
with mode `0600`. The adapter checks the connected peer UID and rechecks path
identity. Symlink substitution and unexpected permissions are refused. It uses
Linux `CLOCK_BOOTTIME` and requires zero time-namespace offsets for checks.

```sh
hrc transport status --companion /absolute/private/companion
```

Status reports capability support, endpoint readiness, active connection context
and directional privacy. A status observation is not fresh permission. The
adapter requires version 2 and never falls back to version 1 or a public address.
Error output uses stable categories; remote error prose is not printed.

## One diagnostic exchange

Start the receiver with the exact admitted caller principal:

```sh
hrc transport probe-serve \
  --companion /absolute/private/receiver \
  --allow-principal CALLER_PRINCIPAL_HEX
```

Then start the caller with the configured service identifier:

```sh
hrc transport probe \
  --companion /absolute/private/caller \
  --service SERVICE_ID_HEX
```

Replace the two identifier placeholders with 64 lowercase hexadecimal characters.
Each receiver accepts one stream and exits. Both commands use a 10-second
preparation and payload wait by default; `--timeout-ms` accepts 100 through 60,000.
The receiver's separate fresh-authority wait defaults to 1,000 ms;
`--authority-timeout-ms` accepts 100 through 5,000. These are finite waits for
individual operations, not a promise that the entire command finishes in one wait.

The request is exactly 40 bytes: ASCII `HRCreq01` followed by a random 32-byte
nonce. The reply is ASCII `HRCack01` followed by that nonce. The receiver checks
its authenticated incoming principal and protocol, then asks the companion to
check current authority for SHA-256 of the bytes
`HRC transport diagnostic reply v1\0` followed by the complete request.
The `\0` denotes one zero byte. The nonce is diagnostic correlation, not an
application identity or a grant. Invalid requests receive no automatic response.

The reply is eligible only while the fresh observation remains permitted and
locally usable. The write is bounded by its remaining lifetime. No arbitrary
message text, file, command, model call or durable effect is part of this protocol.
The diagnostic protocol is distinct from the future HRC conversation wire format.

Output is JSON Lines. The receiver emits `Waiting`, `Accepted`, and then
`ProbeReplied` or a refusal. A successful caller emits `ProbeAcknowledged`.
Failures produce a bounded JSON error on standard error and a nonzero exit status.
These are diagnostic states: `chatCommitted` is always false. If a stream closes
or a wait expires, the command does not infer revocation or a committed outcome.
A failed diagnostic may be run again because it creates no durable chat effect.

## Authority and privacy contract

The adapter uses distinct incoming and outgoing peer types. Incoming context binds
the authenticated application principal and its HyperNet grant; outgoing context
identifies the destination. Neither establishes an HRC account or delegated user.
Only a companion-created incoming stream can obtain a fresh authority check.

Each check uses a fresh random nonce, an immutable action digest and its original
boot-time deadline, including IPC wait time. A result must match the connection,
session, network, incarnation, control identity and kernel boot. Copying a result
cannot extend its lifetime. A new check, known closure, cancellation, missing
status connection or observed control replacement invalidates earlier results.
A caller must check `permitted()` immediately before the effect; a serialized
receipt is diagnostic data and cannot be deserialized into permission.

The companion verifies endpoint signatures and certified authority observations.
HRC does not implement a second HyperNet authority evaluator. A permitted result
is a bounded current observation, not an atomic transaction with HRC storage or
proof that an unobserved remote revocation cannot occur. HRC room, delegation and
federation policy checks will remain separate at their authoritative boundaries.

Outgoing privacy can attest authenticated nested TLS through the configured
relay. Incoming privacy describes the exact arrival evidence: public mode does
not prove upstream relay transit, while an approved attachment has its narrower
endpoint attestation. Missing evidence remains unknown. The latest stream privacy snapshot follows
validated status changes. Known closure, lost connection context or control
replacement marks retained facts as `historical`; historical facts do not
establish an active privacy property. Previously returned snapshots remain
snapshots, so clients obtain the stream state again before presenting it as live.
Physical operator
independence and current profile validity are not asserted. HyperNet transport
protection is separate from message encryption; these probes have no application
end-to-end encryption.

## Bounded implementation

Control requests and responses use four-byte big-endian lengths and at most
16,384 JSON bytes. Decoding rejects duplicate keys, malformed UTF-8, invalid
shapes and unsupported versions. Payload methods also have finite deadlines;
partial reads do not restart the wait. The diagnostic payload is fixed at 40
bytes in each direction. Slow or malformed peers cannot request an unbounded
allocation or an automatic reply chain through these commands.

The library owns the stream lifecycle and validates external context at the
boundary. Presentation uses its typed context and stable errors. Application
business policy, storage formats and GUI dependencies do not belong in the
transport module. This boundary directly addresses implicit identity coupling,
duplicated validation, illegal states, excessive central responsibilities,
scattered policy changes, dependency violations and forwarding-only wrappers.
Future feature code remains grouped by its own capability.

Tests cover malformed IPC and important lifecycle failures. Native qualification
uses actual released Core/Suite admission, a relay and an attached endpoint,
including Rust-to-Rust and Python SDK interoperability and refusal after a grant
change. This does not qualify the pilot load, the complete chat acceptance suite,
other operating systems or federation.
