<p align="center">
  <img src=".github/assets/header.svg" width="720" alt="HyperNet Relay Chat. Native conversation over HyperNet.">
</p>

<p align="center">Rooms, private conversations and scoped agents across independently administered HyperNets.</p>

<p align="center">
  <img src=".github/assets/badges.svg" width="720" alt="Apache 2.0 | Version 0.3.0 | Rust 1.96 | HyperNet transport">
</p>

<p align="center">
  <a href="https://github.com/Federated-Industrial-Laboratories/HyperNetRelayChat/releases/tag/v0.3.0">Linux 0.3.0</a> &middot;
  <a href="Documentation/Installation.md">Install</a> &middot;
  <a href="Documentation/Interfaces.md">Use HRC</a> &middot;
  <a href="Documentation/DesktopHosting.md">Host</a> &middot;
  <a href="Documentation/ExternalAssistant.md">Setup assistant</a> &middot;
  <a href="Documentation/ReadMe.md">Documentation</a> &middot;
  <a href="#trust-and-operations">Trust</a>
</p>

<p align="center"><img src=".github/assets/divider.svg" width="720" alt=""></p>

HyperNet Relay Chat (HRC) is a Rust chat application with a native desktop client,
interactive terminal, CLI and structured agent API. People and agents use the same
conversation and permission rules. Chat transport stays on HyperNet, including
explicitly federated rooms.

> [!NOTE]
> HRC 0.3.0 adds shared link, QR and password joining, saved servers, and separately keyed external Agent applications.
> The earlier [bounded native Linux pilot](Documentation/IntegrationProfile.md#8-linux-pilot-qualification)
> retains its original measured version, topology and workload scope.
> Core 0.11.0 and Suite 0.11.0 are the supported hosting pair. Source and signed
> release packages are public under Apache-2.0.

## Capabilities

| Area | Included |
| --- | --- |
| Conversations | Rooms, direct conversations, replies, mentions, retained history and scoped search |
| Desktop | Guided setup, profile selection, classic or bubble chat layouts, themes, drafts and reconnect state |
| Interfaces | GUI, interactive TUI, CLI and agent API with shared semantics |
| Confidentiality | Encrypted direct conversations and private groups with explicit endpoint trust |
| Agents | Independent or delegated participation, inspectable permissions, pause and revocation |
| Local models | llama.cpp and Ollama adapters, bounded persistent room context, memory inspection and reset |
| HyperNet Pages | Compact clickable addresses, complete hover/copy destinations and the configured Suite browser with shared colours |
| Federation | Explicit agreements between independent networks; shared rooms have an authoritative home service |
| Operations | Desktop management and an optional external setup/operations harness |

## Start here

| Your goal | First steps |
| --- | --- |
| Chat from the desktop | [Install HRC](Documentation/Installation.md), open its application-menu entry, then use the guided setup or an existing profile |
| Change the desktop appearance | Choose one of 14 light/dark palettes or import a validated JSON [theme](Documentation/Themes.md) from Settings |
| Join or return to a server | Use **Join a server** and [saved-server controls](Documentation/SimpleJoining.md) for link, QR or password access |
| Create or operate a network | Choose **Create or manage a server** and follow [desktop hosting](Documentation/DesktopHosting.md); finite/manual hosting remains available |
| Run a local model bot | Configure a separate agent profile and local backend using [desktop bot setup](Documentation/DesktopBots.md) |
| Connect an external Agent | Choose **Agents > Add an external Agent**, then prepare its [private application API](Documentation/ExternalParticipants.md) |
| Get help from an external assistant | Export the optional [assistant harness](Documentation/ExternalAssistant.md) for your installed coding assistant |
| Integrate an application | Read the [protocol and permissions](Documentation/ProtocolPermissions.md) and [wire contract](Documentation/WireProtocol.md) |

The desktop works without an external LLM. Advanced host-security configuration
is optional; authenticated identity, consent and HyperNet transport remain required.
The assistant does not receive chat access or administrator authority by being installed.

<p align="center"><img src=".github/assets/divider.svg" width="720" alt=""></p>

## Install

Download the [Linux 0.3.0 release](https://github.com/Federated-Industrial-Laboratories/HyperNetRelayChat/releases/tag/v0.3.0)
and follow the [signed-package installation guide](Documentation/Installation.md).
Run the coordinated package's `Tools/Install.sh`, or use **Install native tools**
in the first setup window. Open **HyperNet Relay Chat**, then select
an existing profile or choose **Join a server**. **Operations** remains available
before connecting and while chatting.

Native hosting uses separately verified Core 0.11.0 and Suite 0.11.0 packages.
The shared hosting window installs the coordinated signed package set;
**Operations > Native packages** retains individual package import. A host can
allow public, password or invitation joining with restricted default permissions.
Manual operator approval remains available. The optional assistant harness is installed
through **Operations > External assistant** and is separate from chat bots.

The GUI supports X11 and Wayland. Package compatibility and full native-network
qualification have different scopes; the installation guide records both.

### Build from source

<details>
<summary>Source requirements and build commands</summary>

Use Linux with Rust 1.96, a C compiler, Make, Tcl, Git, OpenSSL 3 development headers
and its static `libcrypto.a` archive,
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

</details>

<p align="center"><img src=".github/assets/divider.svg" width="720" alt=""></p>

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

The [release notes](Documentation/ReleaseNotes.md) describe 0.3.0 and its support
limits. The [documentation index](Documentation/ReadMe.md) separates everyday tasks,
operations and protocol references. The [product plan](Documentation/ProductPlan.md)
and [integration profile](Documentation/IntegrationProfile.md) retain scope and
qualification limits. Product code is organised by capability under `Source/`;
tests and conformance vectors live under `Tests/`; the external assistant's
portable content lives under `Harness/` and ships inside the native executable.

Licensed under the [Apache License, Version 2.0](LICENSE).

See [Live admission and external Agents](Documentation/LiveAdmission.md) for self-service
registration, restricted participant profiles and operator-approved Agent onboarding.
