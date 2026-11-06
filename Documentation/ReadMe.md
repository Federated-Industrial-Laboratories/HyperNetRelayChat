# Documentation

[Project](../README.md) &middot; [Install](Installation.md) &middot;
[Trust](../README.md#trust-and-operations) &middot; [HyperNet](https://github.com/Federated-Industrial-Laboratories/HyperNet)

These manuals describe HRC 0.2.0. Start with the task you want to complete;
the release notes distinguish current features from earlier qualification evidence.

## Choose a starting point

| Goal | Guide |
| --- | --- |
| Install and open the desktop application | [Installation and upgrades](Installation.md) |
| Join a conversation and use the interfaces | [GUI, TUI and CLI](Interfaces.md) |
| Choose or import desktop colours | [Themes](Themes.md) |
| Create a network or host an HRC service | [Desktop hosting](DesktopHosting.md) and [service setup](ConversationSetup.md) |
| Set up a bot from the desktop | [Desktop bots and local models](DesktopBots.md) |
| Configure bot behaviour and model memory | [Service bot reference](ServiceBots.md) |
| Use a separate assistant for setup and operations | [External assistant](ExternalAssistant.md) |
| Start a confidential conversation | [Direct conversations and private groups](ConfidentialConversations.md) |

## Operate and recover

| Topic | Guide |
| --- | --- |
| Backups, retention, shutdown and outages | [Operations](Operations.md) |
| Devices, account recovery and endpoint trust | [Endpoint lifecycle](EndpointLifecycle.md) |
| Shared rooms between independently administered networks | [Federation runtime](FederationRuntime.md) |
| HyperNet stream checks and failure diagnosis | [Transport diagnostics](Transport.md) |
| Clock evidence and ordering | [Clock and ordering](ClockAndOrdering.md) |
| Release origin and verification | [Publisher key](PublisherKey.txt) and [installation](Installation.md) |
| Features and support by version | [Release notes](ReleaseNotes.md) |

Advanced host hardening is an optional, separately selected operations task.
Product identity, permission and transport checks remain enabled in every setup.
The external assistant does not replace a network operator or provide permission
to administer a host.

## Protocol and implementation reference

| Boundary | Reference |
| --- | --- |
| Product scope and milestones | [Product plan](ProductPlan.md) |
| Qualified platforms, topology and limits | [Integration profile](IntegrationProfile.md) |
| Inspected Core and Suite interfaces | [HyperNet contract map](HyperNetContract.md) |
| Identity, delegation and operation rules | [Protocol and permissions](ProtocolPermissions.md) |
| Framing and compatibility | [Wire protocol](WireProtocol.md) |
| State transitions and recovery decisions | [State and recovery](StateAndRecovery.md) |
| Text, identifiers and indexed search | [Text and search](TextAndSearch.md) |
| Transactional persistence | [Storage runtime](StorageRuntime.md) |
| MLS encryption lifecycle | [Cryptographic runtime](CryptoRuntime.md) |
| Local drafts, connection state and controller lifecycle | [Local client](LocalClient.md) |

## Terms and command conventions

A **network** supplies HyperNet identity and admission. A **home service** owns an
HRC room's ordered history. A **profile** is an endpoint's private local state; it
must have one active owner. A **bot** participates in chat through an agent
endpoint. The **external assistant** helps an authorised operator manage the
software and receives no chat identity merely by installing its harness.

Command examples use `hrc` for the installed executable. Substitute absolute
private paths and identifiers from the selected deployment. Uppercase placeholders
are not literal identifiers. Use the installed command's `--help` and supported
template and validation commands when preparing management input. Never place passwords or private keys in
commands, exported diagnostics or assistant prompts.
