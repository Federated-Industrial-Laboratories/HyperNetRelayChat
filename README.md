# HyperNet Relay Chat

HyperNet Relay Chat (HRC) is a Rust chat application for HyperNet.
It provides a GUI, interactive TUI, CLI and agent API with shared conversation
and permission rules.

HRC 0.1.0 is qualified for the bounded native Linux pilot described in the
[integration profile](Documentation/IntegrationProfile.md#8-linux-pilot-qualification).

HRC includes a Linux Rust HyperNet adapter,
[transport diagnostic commands](Documentation/Transport.md), signed native
operations, encrypted persistence, community rooms, encrypted direct conversations
and private groups, and explicit bilateral federation.
See [service and client setup](Documentation/ConversationSetup.md) and
[using the interfaces](Documentation/Interfaces.md). The
[confidential conversation guide](Documentation/ConfidentialConversations.md),
[endpoint lifecycle](Documentation/EndpointLifecycle.md) and
[federation runtime](Documentation/FederationRuntime.md) describe their respective
trust, setup and recovery boundaries. HyperNet transport,
explicit agent delegation and two-network federation are required capabilities.

The [local client guide](Documentation/LocalClient.md) covers drafts, connection
states, contact trust and home-service selection. [Service bots](Documentation/ServiceBots.md)
use the same scoped API and do not require a language model.
The [installation guide](Documentation/Installation.md) covers packages and upgrades;
the [operations guide](Documentation/Operations.md) describes stopped backups,
continuity, retention and outage recovery.

The [product plan](Documentation/ProductPlan.md) preserves the full proposal and
the first-release scope amendment, including encrypted private groups. The
[HyperNet contract map](Documentation/HyperNetContract.md) records inspected
interfaces and declared limits. The
[protocol and permission model](Documentation/ProtocolPermissions.md) defines
operation contracts, state transitions, worked traces and qualification targets.
The [integration profile](Documentation/IntegrationProfile.md) specifies the
required Core 0.10.2 and Suite 0.10.1 pair, directional privacy evidence and bounded
federation authority model. The Rust adapter uses their version-2 companion
interface. The
[state and recovery specification](Documentation/StateAndRecovery.md) selects
transactional storage, persistent MLS conversations, exact-content approval and
owner-key account recovery. The
[text and search profile](Documentation/TextAndSearch.md) fixes Unicode semantics,
identity lookup and bounded multilingual search. The
[wire specification](Documentation/WireProtocol.md),
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
and pull requests. Deployment scope and security properties are recorded with
their qualification evidence in the integration profile.

Licensed under the [Apache License, Version 2.0](LICENSE).
The repository and release distribution remain private. Publishing selected
manuals does not make the source repository or package assets public.
