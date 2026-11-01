# HyperNet Relay Chat

HyperNet Relay Chat (HRC) is a Rust chat application in development for HyperNet.
It provides a GUI, interactive TUI, CLI and agent API for the implemented community-room workflow.

The development implementation includes a Linux Rust HyperNet adapter,
[transport diagnostic commands](Documentation/Transport.md), signed native
operations, encrypted persistence, and a shared local conversation client.
See [service and client setup](Documentation/ConversationSetup.md) and
[using the interfaces](Documentation/Interfaces.md). Release
qualification is still in progress; there is no supported chat release. HyperNet transport,
explicit agent delegation and two-network federation are required capabilities.

The [product plan](Documentation/ProductPlan.md) preserves the full proposal and
the first-release scope amendment, including encrypted private groups. The
[HyperNet contract map](Documentation/HyperNetContract.md) records inspected
interfaces and integration gaps. The
[protocol and permission proposal](Documentation/ProtocolPermissions.md) defines
operation contracts, state transitions, worked traces and decisions still open.
The [integration profile](Documentation/IntegrationProfile.md) specifies the
released 0.10.0 companion boundary, directional privacy evidence and bounded
federation authority model. The Rust adapter uses that version-2 interface. The
[state and recovery specification](Documentation/StateAndRecovery.md) selects
transactional storage, persistent MLS conversations, exact-content approval and
owner-key account recovery. The
[text and search profile](Documentation/TextAndSearch.md) fixes Unicode semantics,
identity lookup and bounded multilingual search. These designs still require
implementation evidence. The [wire specification](Documentation/WireProtocol.md),
[storage runtime](Documentation/StorageRuntime.md),
[clock boundary](Documentation/ClockAndOrdering.md), and
[MLS runtime](Documentation/CryptoRuntime.md) document the implemented boundaries.

Build on Linux with Rust 1.96, a C compiler, Make, Tcl, Git and OpenSSL development
headers, pkg-config, Fontconfig, XKB, Wayland and EGL development packages.
Install fonts that cover the languages used; the GUI loads system fallback fonts,
including colour emoji. Noto core, CJK and colour emoji fonts cover the supplied
presentation checks. The native bootstrap builds the pinned SQLCipher engine locally:

```sh
bash Tools/Native.sh
source Tools/Environment.sh
cargo build --locked
bash Tools/Check.sh
```

There is no plaintext SQLite fallback. Test bodies and conformance vectors live
under `Tests/`; product code lives under `Source/` in cohesive feature modules.

Product documentation is maintained with the source. Design changes use branches
and pull requests. Release support and security properties will be stated only
after the corresponding integration and qualification work passes.

Licensed under the [Apache License, Version 2.0](LICENSE).
The repository remains private during development.
