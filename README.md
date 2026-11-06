<p align="center">
  <img src=".github/assets/header.svg" width="720" alt="HyperNet Relay Chat. Native conversation over HyperNet.">
</p>

<p align="center">Rooms, private conversations and scoped agents across independently administered HyperNets.</p>

<p align="center">
  <a href="Documentation/Installation.md">Install</a> &middot;
  <a href="Documentation/Interfaces.md">Use HRC</a> &middot;
  <a href="Documentation/ConversationSetup.md">Host</a> &middot;
  <a href="Documentation/ExternalAssistant.md">Setup assistant</a> &middot;
  <a href="Documentation/ReadMe.md">Documentation</a> &middot;
  <a href="#trust-and-operations">Trust</a>
</p>

HyperNet Relay Chat (HRC) is a Rust chat application with a native desktop client,
interactive terminal, CLI and structured agent API. People and agents use the same
conversation and permission rules. Chat transport stays on HyperNet, including
explicitly federated rooms.

> [!NOTE]
> HRC 0.2.0 includes desktop setup, native hosting, model adapters and operator controls.
> The earlier [bounded native Linux pilot](Documentation/IntegrationProfile.md#8-linux-pilot-qualification)
> retains its original measured version, topology and workload scope.
> Core 0.10.3 and Suite 0.10.2 are the supported hosting pair. Source and release
> distribution remain private; published manuals do not grant download access.

## Capabilities

| Area | Included |
| --- | --- |
| Conversations | Rooms, direct conversations, replies, mentions, retained history and scoped search |
| Desktop | Guided setup, profile selection, classic or bubble chat layouts, themes, drafts and reconnect state |
| Interfaces | GUI, interactive TUI, CLI and agent API with shared semantics |
| Confidentiality | Encrypted direct conversations and private groups with explicit endpoint trust |
| Agents | Independent or delegated participation, inspectable permissions, pause and revocation |
| Local models | llama.cpp and Ollama adapters, bounded persistent room context, memory inspection and reset |
| Federation | Explicit agreements between independent networks; shared rooms have an authoritative home service |
| Operations | Desktop management and an optional external setup/operations harness |

## Start here

| Your goal | First steps |
| --- | --- |
| Chat from the desktop | [Install HRC](Documentation/Installation.md), open its application-menu entry, then use the guided setup or an existing profile |
| Create or operate a network | Open desktop management; use the matching [setup and operations guide](Documentation/ConversationSetup.md) for identities, admission and service access |
| Run a local model bot | Configure a separate agent profile and local backend using [desktop bot setup](Documentation/DesktopBots.md) |
| Get help from an external assistant | Export the optional [assistant harness](Documentation/ExternalAssistant.md) for your installed coding assistant |
| Integrate an application | Read the [protocol and permissions](Documentation/ProtocolPermissions.md) and [wire contract](Documentation/WireProtocol.md) |

The desktop works without an external LLM. Advanced host-security configuration
is optional; authenticated identity, consent and HyperNet transport remain required.
The assistant does not receive chat access or administrator authority by being installed.

## Install

Use a verified package and follow the [installation guide](Documentation/Installation.md).
Current builds support an application-menu launcher and guided setup. Start HRC
from the desktop, or run `hrc gui`. HyperNet Core and Suite remain separately
verified prerequisites; joining a network requires its operator's admission.

The GUI supports X11 and Wayland. Package compatibility and full native-network
qualification have different scopes; the installation guide records both.

### Build from source

Use Linux with Rust 1.96, a C compiler, Make, Tcl, Git, OpenSSL development headers,
pkg-config, Fontconfig, XKB, Wayland and EGL development packages. Install fonts
for the languages used; Noto core, CJK and colour emoji cover the supplied
presentation checks.

```sh
bash Tools/Native.sh
source Tools/Environment.sh
cargo build --locked
./target/debug/hrc gui
```

The bootstrap builds the pinned SQLCipher engine. There is no plaintext SQLite
fallback. Run `bash Tools/Check.sh` for the maintained repository checks.

## Trust and operations

Account identity is independent of a nickname. Delegated actions record the
represented user and authenticated agent, and the service checks current authority
at the operation boundary. Room filtering, moderation and history access apply
consistently across interfaces.

Relay address obfuscation is an optional HyperNet policy. It is separate from
transport protection and end-to-end message encryption. A failed route never
silently changes to direct Internet transport. See [confidential conversations](Documentation/ConfidentialConversations.md),
[federation](Documentation/FederationRuntime.md) and [backup and recovery](Documentation/Operations.md).

## Documentation and development

The [documentation index](Documentation/ReadMe.md) separates everyday tasks,
operations and protocol references. The [product plan](Documentation/ProductPlan.md)
and [integration profile](Documentation/IntegrationProfile.md) retain scope and
qualification limits. Product code is organised by capability under `Source/`;
tests and conformance vectors live under `Tests/`; the external assistant's
portable content lives under `Harness/` and ships inside the native executable.

Changes use branches and pull requests. Packaging and documentation are part of
delivery. The website is maintained separately from this source tree's selected
documentation snapshot.

Licensed under the [Apache License, Version 2.0](LICENSE).
