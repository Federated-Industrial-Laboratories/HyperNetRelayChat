# HyperNet Relay Chat product plan

## Scope amendment, 31 October 2026

The first-release scope is Linux first, service-readable community rooms, end-to-end encrypted confidential direct conversations, and end-to-end encrypted private groups. Private-group encryption is included in the first release. This decision supersedes any proposal below to defer private-group encryption or assess its inclusion separately. Encryption construction, device admission, recovery, membership changes and history policy still require the protocol design decisions below.

The complete source draft follows. Confirmed requirements and proposed defaults retain their original distinction. Its HyperNet integration references describe the inspected 0.9.0 baseline; a versioned integration contract must account for subsequent permission changes before implementation. No application implementation or release qualification is claimed by this plan.

## Accepted pilot and history decisions, 31 October 2026

The initial pilot target per home service is eight interactive endpoint streams, two agent streams and two federation-direction streams, with two operator slots and two transition slots reserved. This is the accepted qualification target, not a measured capacity claim.

Default service history is 30 days with a 10 GiB quota; default local history is seven days with a 512 MiB quota. Deduplication records last at least seven days and beyond the associated retry-window expiry; retry windows last at most 24 hours. Quota exhaustion rejects new work before silently shortening agreed retention. These defaults do not grant access beyond current membership or delegation.

New or recovered devices receive future encrypted messages only by default, for confidential direct conversations and private groups. Existing authorised devices may retain their local archives. Access to earlier encrypted history is strictly optional, disabled by default, and requires deliberate, separately authorised disclosure. This decision does not select or enable an archive-transfer, backup or key-recovery mechanism.

These decisions supersede the corresponding open choices in the preserved draft. Other technical defaults, resource budgets and integration contracts remain subject to design and qualification.

## Preserved source draft

**Draft updated 31 October 2026.** HyperNet Relay Chat (HRC) is a Rust-based chat application using a native protocol over HyperNet, with an interactive GUI, a terminal interface, and an API for people and their authorised agents. It preserves IRC’s immediacy while adopting HyperNet’s identity, consent, and federation model.

Repositories and GitHub procedures from the start, documentation included, in a private repository. (camelcase, HyperNetRelayChat)

The first release should provide dependable conversation, explicit agent delegation, and a bounded federation profile. This plan defines the product, architecture, delivery sequence, and evidence required before implementation choices become commitments. It contains no application implementation.

# Confirmed requirements

- The product is named HyperNet Relay Chat, abbreviated HRC.

- HyperNet is mandatory for chat transport and service integration. A failed route must not silently fall back to a direct Internet connection.

- Address obfuscation is an optional HyperNet relay capability, selected through supported HyperNet policy. HRC reports the active privacy properties without making obfuscation a separate mandatory HRC feature or silently weakening a selected policy.

- HRC uses a native protocol. Existing IRC clients do not need to connect.

- Rust is the implementation target, with compatibility assessed against actual HyperNet and platform constraints.

- The product has a CLI, an interactive TUI, and an intuitive GUI drawing on HyperNetSuite’s existing presentation work.

- Agents can participate independently or act on a user’s behalf through explicit API permissions.

- Federation between independently administered HyperNets is part of the design. Replicated chat clusters, leader elections, and automatic failover are not required scope.

- Code quality is assessed against all nine warning signs supplied for this project.

The following sections propose a first-release scope and technical defaults. Encryption policy, supported platforms, scale, retention, and the exact federation contract remain explicit decisions.

# Proposed first release

| Area | Initial capability |
| - | - |
| Conversations | Local and explicitly federated rooms; direct conversations; replies; persistent history across reconnects and restarts; unread markers; scoped, indexed search. |
| Text | UTF-8 protocol text, Unicode-aware editing and display, and explicit identifier and search rules. |
| Identity | Stable account and room identifiers, changeable nicknames, visible network origin, and separate human and agent presence. |
| Familiar interaction | Join and leave rooms, direct messages through /msg and /whisper, /me, /nick, /motd, topics, mentions, and completion. |
| Everyday usability | Draft preservation, reconnect and resume, clear delivery states, themes, per-room notifications, optional sounds, and quiet mode. |
| Moderation | Blocking, server-side ignore, room silencing, muting, kicking, banning, bounded rate limits, and attributable moderation records. |
| Agents | Independent and delegated participation, persistent service bots, scoped context access, structured events, inspectable grants, pause, and revocation. Bots may be deterministic and need no language model. |
| Federation | A first profile for explicitly shared rooms between two independently administered HyperNets, including remote delegated participation. |
| Privacy | Accurate indicators for optional HyperNet relay obfuscation, transport protection, and message encryption; an agreed encryption design before confidential direct conversations ship. |

The first useful internal prototype may be local to one HyperNet. The first release must pass the federation scenarios; federation is not satisfied by a placeholder interface.

Image previews, approved file exchange, terminal image rendering, and model-assisted moderation follow the dependable text path. Start moderation with deterministic controls. A small model can later flag messages, with punitive authority granted separately.

Defer voice and video, a plugin marketplace, arbitrary agent tool execution, IRC compatibility bridges, and active-active chat replication. These are not prerequisites for the stated product.

# HyperNet integration considerations

HyperNet application streams provide opaque duplex payload transport and verified application context. HRC remains responsible for conversation semantics, room permissions, message storage, and federation behaviour. Payloads do not become entries in HyperNet’s authority history. [Core streams](https://github.com/Federated-Industrial-Laboratories/HyperNet/blob/master/Documentation/ApplicationStreams.md) · [Suite streams](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/blob/master/Documentation/ApplicationStreams.md)

| Existing documented constraint | HRC design consequence |
| - | - |
| At most 16 active connections per companion | Measure the intended receiving and sending topology before committing to a concurrent-user target. This is a companion limit, not a universal network user count. |
| A route ceiling of one hour and 1 GiB per connection, with lower configured limits possible | Resume conversations over fresh authorised streams. Leave allowance for framing and transport overhead. |
| Application admission and same-rights renewal intervals of at most seven days | Show expiry and support explicit renewal. Do not assume prior consent permits unattended renewal. |
| A packaged Python SDK for the companion interface | Establish a supported Rust binding or reuse a suitable existing Rust interface after inspection. Keep that integration behind a narrow boundary. |
| Suite uses eframe/egui and Crossterm | Reuse appropriate appearance and interaction conventions without importing the entire Suite application structure. |
| Linux 0.9.0 is qualified on native Ubuntu x86_64; other listed platforms remain unqualified | Use Linux as the proposed initial validation target. Windows and macOS require a separate compatibility decision and evidence. |

Sources: [application lifecycle](https://github.com/Federated-Industrial-Laboratories/HyperNet/blob/master/Documentation/Applications.md), [SDK interface](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/blob/master/SDK/README.md), [Suite dependencies](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/blob/master/Cargo.toml), and [platform scope](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/blob/master/ReadMe.md).

Resolve one documentation discrepancy before fixing wire mappings: the stream guide describes actions 29 and 30 as service management and connection, while PolicyContract assigns those numbers to sealed-page actions. Reconcile the matching Core and Suite implementation, tests, and documentation; do not select numeric actions from either passage alone. [Policy contract](https://github.com/Federated-Industrial-Laboratories/HyperNet/blob/master/Documentation/PolicyContract.md)

# Identity and agent delegation

An event distinguishes the represented account from the application that actually performed the action.

| Mode | Identity recorded | Example display |
| - | - | - |
| Direct participation | Account and authenticated client or device | Peer |
| Independent agent | Agent account, authenticated application, and operator binding | Archivist · Agent |
| Delegated agent | Represented account, authenticated agent, and exact delegation reference | Peer · via Atlas |

The service derives the acting principal from verified context and checks the represented-account binding. A caller-supplied account name or delegation label is insufficient. Account classification and badges do not prove that a person personally typed a message.

Each delegation states the owner, agent, target service and network, allowed rooms or recipients, allowed operations, permitted history, validity, and applicable limits. Separate reading, replying, initiating conversations, marking messages handled, and moderation. Creating further delegations is excluded from the initial agent permission set.

Offer three operating modes: draft only, approve before sending, and act within the granted scope. Approval must bind the exact proposed action and content; changing either requires a new approval. Approved autonomous scope does not require repeated approval for each permitted message.

Effective access must satisfy current HyperNet authority, the represented user’s current room rights, the agent’s delegation, and the receiving room and federation policies. An agent cannot bypass its user’s ban or expand access through another identity. Rate limits apply to the acting agent and represented account where appropriate.

Pause is a reversible HRC control that stops subsequent delegated effects. Revocation permanently invalidates that grant; a fresh grant is required to restore access. Neither mechanism retracts messages already received. Recheck current authority when queued work is submitted, not only when an agent first connects.

Human and agent presence remain separate. The API and interface expose what an agent can currently do, what it has done, and what is waiting for the user. Natural-language purpose describes intended behaviour; enforceable room, operation, time, and rate restrictions define the actual access boundary.

# Native protocol and conversation behaviour

Define a small versioned protocol with negotiated capabilities and bounded message sizes. Select the wire encoding after the data model and HyperNet interface are fixed. Use reviewed existing cryptographic constructions; a native chat protocol is not a reason to invent cryptography.

The initial operation families are session establishment and resume, room membership, message send and history, event subscription, delegation lifecycle, moderation, and federation exchange. GUI, TUI, CLI, and agent clients use the same semantics.

Required invariants:

- Stable identities are independent of nicknames and physical hosts. Federated identities include origin network and incarnation so a recovered or different network cannot silently inherit an old identity.

- Each committed event has a stable identifier, room identity, authenticated actor, optional represented user and delegation reference, ordering position, and defined timestamp semantics.

- A repeated operation identifier with the same content resolves to the original outcome within the supported deduplication window. Reusing it with different content fails. Persistence and retention of deduplication records are specified; restarting must not silently discard protection for still-retryable operations.

- Acknowledgements distinguish queued locally, accepted by the service, and committed under the stated durability policy. Delivery and read receipts are separate optional events.

- The initial room history has one defined authoritative order at its home HRC service. Wall-clock timestamps do not decide conflicting membership or moderation actions.

- Membership changes, revocation, and messages have a defined evaluation order. A message rejected after access changes is not retrospectively accepted because it was drafted earlier.

- Resume cursors are bound to their room and access context. Gaps beyond retained history produce an explicit resynchronisation result.

- Reconnect obtains fresh permission and resolves uncertain operations before retrying effects. A transport retry cannot recreate expired authority.

- Unknown critical protocol features are rejected explicitly; optional extensions follow documented compatibility rules.

Search and history apply the same membership and delegation rules as live delivery. Retained local copies have their own explicit retention policy; revocation cannot retract content already received. Encrypted conversation search runs over authorised locally decrypted content unless a separate privacy-preserving design is explicitly adopted. A service without the content keys must not claim plaintext server-side search.

# Text history and search

Use UTF-8 for protocol text and reject malformed encodings at the decoding boundary with a bounded error. Define separate limits for bytes, user-perceived characters, and terminal display width. Editing, selection, truncation, and cursor movement must respect Unicode grapheme boundaries, including combining characters and emoji sequences. [UTF-8](https://www.rfc-editor.org/rfc/rfc3629.html) · [Unicode text segmentation](https://www.unicode.org/reports/tr29/)

Keep opaque account IDs separate from display names. Specify versioned normalisation and case-folding rules for handle lookup and search; preserve original message content and never normalise signed bytes after verification. Expose suspicious directional or invisible controls in identity-sensitive displays while supporting legitimate multilingual text. Terminal escape sequences never become executable output controls.

Persist conversation history across client reconnects and service restarts under the agreed durability and retention policy. Provide indexed search by room, sender or represented account, date range, and text, with pagination and cancellable queries. Search results must retain message IDs and open their original conversation context. Expiry or deletion must update indexes and derived previews according to the same policy.

Distinguish user-visible conversation history from operational diagnostic logs. Define configurable retention and storage quotas, protect local archives and indexes consistently with their content, and require deliberate selection for exports. Diagnostic logs must not become an accidental plaintext transcript. Persistence does not mean unlimited retention or permission to access old messages.

# Federation model

Each HyperNet retains its own administration, membership, trust, and policies. HRC proposes local rooms and rooms explicitly shared through an HRC federation agreement. The first profile gives each shared room a designated home network and HRC service responsible for its ordered conversation history.

The agreement defines participating networks, room identities, remote admission, moderator authority, history access, retention and storage locations, onward sharing, privacy mode, expiry, and withdrawal. Remote participants remain recognisable as originating from their own network. Federation does not automatically grant foreign membership or local administration.

HyperNet’s existing federation concerns approved Pages. Its bilateral trust and consent pattern informs HRC, but live chat needs an explicit application contract and consented transport arrangement. Do not assume that a Page bridge automatically forwards chat. [Existing federation contract](https://github.com/Federated-Industrial-Laboratories/HyperNet/blob/master/Documentation/Federation.md)

The design must establish how each HRC gateway or remote application is independently admitted, how its counterpart is authenticated, and how original actor and delegation evidence is bound to forwarded events. A gateway cannot establish a foreign author merely by placing an account ID in a payload.

Destination policy can further restrict an otherwise valid remote action. Federation must not expand an agent’s room or history access. Event identities and origin binding prevent duplicates, loops, and substitution during reconnect or forwarding.

On loss of connectivity or agreement validity, preserve permitted local drafts and retained history. Show that remote participation is unavailable. Resume only after current authority and agreement checks succeed; do not manufacture successful delivery or silently change network identity. Previous legitimate recipients may retain already disclosed content according to the agreed policy.

Replication, leader election, and multi-writer partition resolution remain outside required scope. The home-service durability and recovery policy still needs a clear definition.

# Privacy media and moderation

Address obfuscation is optional HyperNet relay functionality. HRC should expose the selected mode and effective privacy properties; it should not implement a parallel obfuscation system. HyperNet remains mandatory, and optional obfuscation does not authorise an unsupported direct HRC connection or a silent privacy downgrade. Transport encryption and end-to-end message encryption are separate decisions. Where relay obfuscation is selected, its actual guarantees and operator-independence assumptions still apply. [Private routes](https://github.com/Federated-Industrial-Laboratories/HyperNet/blob/master/Documentation/PrivateRoutes.md)

Proposed default: service-readable community rooms and end-to-end encrypted confidential direct conversations. Decide this during protocol design, before committing storage formats or presenting a private-conversation feature. Group encryption, multi-device onboarding, recovery, history access, and federation membership changes require explicit policies.

Suite’s OpenMLS-based mail is a useful integration reference, not a ready-made live-chat lifecycle. Assess reuse against live conversation and device requirements. [Private Mail](https://github.com/Federated-Industrial-Laboratories/HyperNetSuite/blob/master/Documentation/PrivateMail.md)

An agent reading encrypted content needs its own explicitly authorised endpoint or device, not the user’s private keys. External model disclosure requires a separate allowed destination and clear user consent; route and provider choices must respect the deployment’s HyperNet requirements.

For previews, start with approved HyperNet media. External links remain unexpanded until an approved retrieval path exists. Apply size, type, decode, and address restrictions at retrieval boundaries. Terminal output must neutralise control sequences; remote text must not become local commands.

Moderation policy states who can see content. A service cannot both lack decryption keys and transparently inspect encrypted messages. Any moderation agent with plaintext access is an authorised participant whose scope must be visible.

# IRC influences and service bots

CTCP provides precedents for action messages, client capability queries, and reachability checks; DCC negotiates direct client connections such as file transfer. Borrow useful interactions through typed HRC events and negotiated capabilities, with explicit request and response correlation. Do not import the legacy wire framing or automatically disclose client versions, local time, or addresses. The historical CTCP draft is a reference for behaviour, not an HRC specification or a current IETF standard. [CTCP historical draft](https://datatracker.ietf.org/doc/html/draft-oakley-irc-ctcp-02)

For DCC-like file exchange, use explicit offers and acceptance over an approved HyperNet transfer mechanism or consented application service. Bind offers to sender, recipient, content identity, size, and expiry; define integrity checks, cancellation, and bounded resume. Never turn an offer into an automatic connection to a payload-supplied public address, open an unsolicited listener, or execute a received file. File exchange remains a later increment after the dependable text path.

Eggdrop is a useful precedent for persistent channel assistance and moderation. HRC can support headless service bots for greetings, room help, announcements, and authorised moderation through the same scoped API. A bot can use ordinary deterministic rules; a language model is optional. Use the existing identity and delegation model, durable event cursors, and explicit operator ownership. Do not assume Eggdrop binary or script compatibility, or embed a general scripting engine in the GUI. [Eggdrop documentation](https://docs.eggheads.org/)

# Flood resistance and service isolation

HRC must stay responsive under abusive traffic within its tested operating envelope and reject excess work without multiplying it. Establish numeric budgets during protocol design for message and frame size, parsing depth, concurrency, queues, fan-out, storage, and recovery time; verify them under load.

| Control | Required behaviour |
| - | - |
| Work admission | Apply cheap framing and size checks before costly decoding, cryptographic verification, database work, or model calls. Bound unauthenticated handshakes and authentication work separately; early filtering never replaces authentication. |
| Rate and cost limits | Use burst and sustained budgets for connections, messages, bytes, joins, nickname and presence changes, metadata queries, history, search, file offers, and agent invocation. Charge expensive operations and fan-out appropriately. |
| Fairness | Apply relevant budgets per authenticated actor, represented account, room, and federation peer, with service-wide ceilings. Never treat a shared relay address as one abusive user or rely on address obfuscation being disabled. Coordinate pre-authentication protection with HyperNet. |
| Bounded execution | Bound queues, worker concurrency, database and search work, and media processing. Isolate slow consumers and saturated peers. Backpressure or disconnect the affected stream rather than stall all rooms. |
| Limited amplification | No automatic response to a response. Correlate permitted request/reply exchanges; cap error and metadata replies, notifications, federation forwarding, and agent-to-agent reply chains. Suppress repeated warnings and keep diagnostic logging bounded. |
| Recovery | Use capped reconnect backoff with jitter and honour retry guidance when safe. Rate-limit catch-up and deduplicate replays; a recovered link must not unleash an unbounded history or notification burst. |
| Responsive controls | Keep cancellation, disconnect, and moderation usable within reserved, authenticated control budgets. Prioritised control traffic still has limits. The GUI and TUI must not perform unbounded work per incoming event. |

Server-side ignore is recipient-controlled filtering: suppress matching live deliveries, notifications, preview retrieval, and agent triggers before they reach that recipient. Apply the active filter to that recipient’s history and search presentation too; it does not erase shared room history for other participants. An ignored message must not be falsely reported as delivered or read by that recipient.

Room silencing is a moderator-controlled send restriction enforced before room publication and fan-out. Keep it distinct from a local visual mute, recipient ignore, and a ban. Make scope, duration, and moderator attribution inspectable. Enforcement and audit output must themselves be bounded.

Test message floods, connection churn, join/leave storms, costly queries, malformed frames, oversized Unicode input, slow readers, federation replay, notification storms, and agent feedback loops. Record memory and queue ceilings, unaffected-client latency, rejection cost, output amplification, and recovery time against agreed thresholds. Use dependency review, parser fuzzing, and boundary tests to reduce exploit risk; avoid claiming that Rust or a passing test suite makes exploitation impossible. Link saturation and attacks on transport infrastructure also require HyperNet and host-level protections.

The ICMP comment identifies a real transport concern, but blanket blocking is not an HRC reliability feature. RFC 5927 discusses ICMP attacks against TCP and mitigations; IPv4 path MTU discovery uses a Destination Unreachable code for fragmentation-needed errors, and IPv6 depends on essential ICMPv6 messages. Leave packet handling and targeted filtering to HyperNet and the operating system, and test path-MTU changes and transient failures without silently changing firewall rules. [ICMP and TCP](https://www.rfc-editor.org/rfc/rfc5927.html) · [IPv4 path MTU discovery](https://www.rfc-editor.org/rfc/rfc1191.html) · [ICMPv6 filtering](https://www.rfc-editor.org/rfc/rfc4890.html)

# Architecture and code organisation

Organise around capabilities that change together. Proposed areas are Identity, Delegation, Conversations, Messaging, Federation, Moderation, and Media. Each owns its rules, operation handlers, errors, and tests. Their dependency contracts should be small and explicit.

Keep transport, persistence, the clock, and presentation at actual boundaries. Introduce an interface when it isolates a real external dependency, policy owner, or lifecycle. Avoid speculative frameworks, universal managers, and one implementation hidden behind several forwarding layers.

| Boundary | Owns | Must not own |
| - | - | - |
| HyperNet integration | Verified peer context, stream lifecycle, permission failure translation | Room membership or agent impersonation rules |
| HRC feature modules | Conversation operations, domain invariants, and authoritative policy decisions | GUI widgets, terminal rendering, or transport-specific framing |
| Wire and persistence adapters | Bounded decoding, representation conversion, durable operations | Independent copies of business policy |
| GUI TUI and CLI | Interaction, drafts, display, and user-facing error presentation | Final server authorisation |
| Agent API | Structured access to the same operation semantics | Broader authority than the represented user and delegation |
| Federation | Verified remote envelopes, agreement checks, origin preservation | Automatic trust in remote identifiers |

These are responsibilities, not instructions to create a crate for every row. Start with cohesive modules. Add crate boundaries only where dependency enforcement, reuse, or separate delivery warrants them.

The GUI should retain HyperNetSuite’s visual language while borrowing selected mIRC-era interaction cues: a channel and conversation switcher, compact timestamped text, a member list, a status view, keyboard navigation, and discoverable slash commands. Offer comfortable and compact density; nostalgia must not reduce accessibility or introduce legacy scripting assumptions. Contextual details show members, agents, and actual privacy properties. The TUI exposes equivalent operations through completion and status, and the CLI provides structured noninteractive output. Theme and layout differences must not change permission, filtering, or delivery behaviour.

# Code quality criteria

The following indicators are review triggers. Evaluate responsibility, dependency direction, and change cost rather than imposing arbitrary file counts or line limits.

| Indicator | Design rule | HRC review evidence |
| - | - | - |
| Implicit coupling | Declare dependencies and side effects. Avoid global mutable registries, ambient identity, and hidden call ordering. | A delegated send identifies its actor, grant, policy source, and persistence effect without depending on which screen was opened first. |
| Layer-first folders | Group primarily by feature or domain. Keep representation and I/O details near the capability they support. | A delegation change is navigable within its owning module instead of being scattered across global Models, Services, Repositories, and Managers folders. |
| Duplication | Give each business rule one authoritative owner. Reuse semantics across frontends. | Expiry, delegation, and room-policy checks do not drift among GUI, TUI, API, and federation handlers. Repeated checks at separate trust boundaries are intentional, not removed merely to reduce repetition. |
| Representable illegal states | Use distinct types, enums, private construction, and validated transitions where they reduce invalid combinations. | A direct action cannot accidentally retain another user’s delegation; an unverified remote envelope cannot be treated as authenticated; delivery status cannot be simultaneously failed and committed. |
| God files | Give modules cohesive responsibilities. Split by independently understandable behaviour, not arbitrary length. | No central ChatManager owns networking, rendering, storage, federation, and permission decisions. |
| Shotgun surgery | Keep a rule and its consumers behind a stable contract. Explain legitimate cross-cutting changes. | Adding a room restriction changes its policy owner, contract, and relevant tests without unrelated frontend and transport edits. Necessary wire and migration work remains explicit. |
| Layering violations | Feature rules depend on domain contracts, not GUI, socket, or database representations. | Messaging does not import egui, inspect raw HyperNet frames, or depend on database row layout to decide permission. |
| Pass-through wrappers | Every abstraction must enforce an invariant, translate a boundary, own a lifecycle, or provide a real substitution point. | Remove forwarding-only service chains. Keep useful adapters and identity newtypes when their contract adds protection or clarity. |
| Errors / validation not at the boundary | Validate external input where it enters, enforce domain rules before effects, and return stable errors at public boundaries. | Malformed frames, bad configuration, corrupt storage, expired grants, and invalid remote identities produce explicit outcomes without panics, secret leakage, or a false success state. |

Rust types can prevent invalid structural combinations; they cannot make a previously valid grant remain current. Expiry, revocation, membership, and federation validity require checks at the relevant operation boundary. Deserialisation must not directly construct a supposedly verified principal or grant.

Parsing, authentication, authorisation, and semantic validation are separate responsibilities. Local UI validation helps users; the service remains authoritative. Translate internal errors into stable categories such as invalid input, denied, expired, conflict, unavailable, unsupported version, rate limited, overloaded, or resynchronisation required. Retry only when the operation’s semantics permit it.

# Delivery milestones

Milestones are ordered by dependency, without speculative calendar estimates. Implementation work begins after the relevant design decisions are settled.

| Milestone | Deliverable | Exit evidence |
| - | - | - |
| 1 Integration and scope | A versioned HyperNet contract map; resolved action-number discrepancy; initial platform, scale, storage, optional relay privacy, and transport reliability choices | A documented route from verified application identity to an HRC operation, including refusal and renewal paths; capacity assumptions fit the selected topology. |
| 2 Domain and protocol design | Identity and delegation model, room events, API operations, error taxonomy, UTF-8 and Unicode rules, work budgets, persistence and search, encryption boundary, and federation agreement | Worked traces cover direct and delegated sends, revocation, unknown outcomes, reconnect, and remote admission. All nine quality criteria have an identified owner or boundary. |
| 3 Smallest complete conversation | A future implementation slice connecting two clients through actual HyperNet transport to one HRC service; human and delegated-agent sends; persistence, resume, ingress limits, and bounded queues | Repeating an interrupted send does not duplicate it; permission expiry refuses the effect; attributed history survives restart within the stated durability contract. |
| 4 Complete local experience | GUI, TUI, CLI, notifications, unread state, indexed history, Unicode-aware interaction, server-side ignore, room silencing, moderation, and agent controls | The same scenario produces equivalent permission and conversation outcomes in every interface; drafts survive transport interruptions. |
| 5 Federation and confidential conversations | Two-network shared-room exchange, remote delegated actions, agreement lifecycle, and the chosen confidential-message implementation | Remote scope cannot expand; origin tampering and replay fail; withdrawal blocks new protected exchange; authorised recovery does not silently change identity. |
| 6 Release qualification | Packaging, migrations, operational guidance, performance and adversarial-load evidence, and final architecture review | The acceptance scenarios pass at the agreed load and supported platforms; memory, latency, and recovery meet the flood-test budgets; known limits are documented; no required feature depends on a direct fallback or misleading security claim. |

Controlled media and model-assisted moderation are subsequent increments unless selected explicitly for the first release. Federation remains in the release path even when the first development slice is local.

# Verification and release gates

Use tests where they verify meaningful contracts and failure modes. Avoid tests that only restate implementation details.

- Domain tests cover delegation scope, room policy, identity bindings, moderation, and state transitions.

- Property tests and bounded-input fuzzing cover decoders, UTF-8 validation, Unicode edge cases, state transitions, and malformed boundary input.

- Integration tests use real HyperNet admission and streams for representative success, refusal, expiry, cancellation, and renewal cases.

- Persistence tests interrupt operations around durable commit and acknowledgement, then check deduplication, history, index consistency, retention, export boundaries, and migration recovery.

- Federation tests use two separately administered test networks and altered, expired, duplicated, and misbound remote events.

- Presentation checks cover keyboard operation, accessibility, Unicode editing and rendering, terminal safety, compact and comfortable layouts, and semantic parity across GUI, TUI, CLI, and agent API.

- Dependency review checks cycles, domain ownership, and the expected scope of a representative feature change.

- Adversarial-load tests measure bounded resource use, fair service to unaffected users, amplification, server-side filtering, agent-loop suppression, and recovery under the specified flood scenarios.

Release acceptance scenarios:

1. A user changes nickname without changing account identity or history attribution.

2. An agent replies on a user’s behalf only within its grant; an otherwise valid out-of-scope operation fails.

3. Pausing or revoking an agent prevents later queued effects and is distinguishable from a network outage.

4. An uncertain send and reconnect resolve to one committed event or a clear rejection.

5. History outside the permitted window or membership scope remains unavailable through search, resume, and agent APIs.

6. A federated room preserves origin and delegated attribution, applies destination restrictions, and stops new exchange after agreement withdrawal.

7. A stream limit or expired permission preserves drafts and produces an accurate state without direct transport fallback.

8. Confidential conversations satisfy the agreed encryption and device model; previews and model disclosure follow explicit policy.

9. The same policy change has a bounded, explainable set of implementation changes and passes the nine code quality criteria.

10. Invalid UTF-8 is rejected at the boundary, while combining characters and emoji remain intact through editing, persistence, search, and display.

11. Recipient ignore prevents matching delivery, notifications, previews, and agent activation; room silencing prevents publication. Neither action generates a response storm.

12. Flooding or a slow peer stays within agreed resource budgets while unaffected clients and authenticated moderation remain usable; reconnect does not create duplicate messages or unbounded catch-up.

13. Search finds retained messages after restart, respects current access and active filters, and removes expired entries according to policy. Encrypted content does not leak into plaintext service indexes or diagnostic logs.

# Decisions to settle before implementation

| Decision | Proposed starting point | Must be settled by |
| - | - | - |
| Supported platforms | Linux first, with other platforms retained as an explicit portability goal | Milestone 1 |
| Concurrent use and topology | Set a small pilot target after measuring the documented companion limits; include agent and federation connections | Milestone 1 |
| Relay obfuscation | Optional HyperNet capability with visible effective properties; preserve mandatory HyperNet integration and selected policy | Milestone 1 |
| Confidentiality | Service-readable community rooms; encrypted confidential direct conversations; assess private groups separately | Milestone 2 |
| Federation profile | Shared rooms with a designated home HRC service and explicit remote admission | Milestone 2 |
| Storage and retention | Define durable-ack meaning, history expiry, deduplication window, backups, local cache, and deletion semantics | Milestone 2 |
| Initial agent autonomy | Support draft, exact approval, and bounded autonomous modes with explicit per-agent selection | Milestone 2 |
| Flood budgets | Set numerical limits for ingress, cost, queues, fan-out, search, agents, logs, and recovery, with fairness and amplification tests | Milestone 2 |
| Unicode and search | Version text and identifier rules, define byte and grapheme limits, and choose bounded search and retention semantics | Milestone 2 |
| Wire representation | Choose after bounded event types, compatibility rules, and identity evidence are defined | Milestone 2 |

The immediate next design deliverable is the HRC protocol and permission specification: operation contracts, state transitions, federation evidence, and worked interaction traces. It should use these quality criteria as acceptance conditions and preserve the distinction between confirmed requirements and proposed defaults.
