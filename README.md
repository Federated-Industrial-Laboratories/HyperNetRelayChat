# HyperNet Relay Chat

HyperNet Relay Chat (HRC) is a Rust chat application in development for HyperNet.
Its planned interfaces include a GUI, TUI, CLI and agent API.

The first implementation provides a Linux Rust HyperNet adapter and bounded
[transport diagnostic commands](Documentation/Transport.md). Conversation features
remain in design; there is no installable chat release. HyperNet transport,
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
implementation evidence.

Product documentation is maintained with the source. Design changes use branches
and pull requests. Release support and security properties will be stated only
after the corresponding integration and qualification work passes.

Licensed under the [Apache License, Version 2.0](LICENSE).
The repository remains private during development.
