# Release notes

## 0.3.0

HRC uses the shared HyperNet join and host windows for address, invitation link,
QR and password access. Participants choose a name and retain locally generated
keys; hosts can admit restricted members without a synchronous file exchange.
Saved servers preserve explicit offline preference and resume exact interrupted
operations. Page links use a separately admitted reader and reuse its browser
window without interrupting an active form.

The shared host workflow offers Invite only, Password and explicitly selected
Public admission, a separate owner account, welcome room and read-only Pages.
Core and Suite 0.11.0 provide explicit access until removed and hosting until
stopped or withdrawn. Finite permissions and the manual host workflow remain
available. Route vouchers, action checks and connection proofs still have finite
validity. Installing a new binary does not extend existing authority.

Live HRC enrolment runs while Home stays online. A bounded authenticated registrar
receives only the configured community-room preset. Ordinary members cannot
create rooms, moderate, publish Pages, host services or administer the computer.
Host removal retains history and exact terminal outcomes, and removing a person
also retires their scoped Agents. Native generation fences prevent slot reuse from
restoring an old identity.

Admitted operators can create separately keyed external Agents and approve their
rooms, initiation and Agent-reply permissions through the current chat controller.
The local API works through a private Unix socket or cancellable stdio, with
durable events, acknowledgements and exact sends. Desktop and `manage agent`
controls prepare, start, inspect, stop and restore saved API connections. Exported
settings contain private paths, never token or endpoint-key contents. Interrupted
credential creation recovers the original token and scope; revocation cannot be
undone by retry. The built-in model runner is optional.

Bots report specific current and historical errors, recent successful work and
bounded dependency recovery. Model startup shows readiness progress and supports
cancellation. Validated context, reply-token, message-length and request-time
settings expose the relevant limits. These operation deadlines do not introduce
a bot/model lifetime timer or alter GPU power settings.

Core 0.11.0 also aligns private replay-cache capacity with its documented bound
and recovers certified forward progress after floor/cache publication interruption.
Expiry pruning preserves unexpired replay identifiers; rollback floors and
authentication remain enforced.

### Compatibility and limits

Use HRC 0.3.0 with coordinated Core and Suite 0.11.0. Upgrade the complete native
committee before enabling persistent records. Existing HRC v1 self-service
invitations, manual pinned files and finite consent remain options. Enabling live
HRC admission advances Home to schema 2; older Home binaries refuse that state.
Keep stopped backups and independent guards/floors. See [installation and
migration](Installation.md#hrc-030-and-coordinated-native-upgrade).

The shared chat preset allows at most 32 participants including the owner. HRC
retains 256 accounts and 1024 admission claims; removed accounts continue to count
towards retained storage. Host Agent quota is one to eight per operator. Each
local API configuration has at most eight active credentials, each selecting up
to eight rooms. Agent replies require explicit causation and remain bounded to
depth four and eight effects. These limits are not throughput measurements.

Existing qualification records retain their original package versions, platforms,
topologies and workload scope. They do not establish independent operator fault
domains, an independent security assessment or support for additional platforms.
See [simple joining](SimpleJoining.md), [shared hosting](DesktopHosting.md),
[external applications](ExternalParticipants.md) and [bot controls](DesktopBots.md).

## 0.2.2

Hosts can enable optional self-service invitations and send one private code or
text file in advance. The recipient joins from the desktop with locally generated
keys, without a live request or registration exchange. Each invitation binds to
one recipient. The existing manual approval workflow remains available, and
self-service hosting starts disabled.

The separate, pinned TLS 1.3 admission service exchanges only public setup and
renewal artifacts. Native HyperNet remains the transport for chat and Pages.
Recipients receive ordinary scoped permissions; an optional Page reader uses its
own identity. Host controls bound the invitation count, expiry and native work,
and can disable admission or revoke an exact recipient.

Opted-in online profiles renew access within existing consent and membership
limits. Renewal retains keys, account identity, history and original native
requester state. Disconnect and offline mode suppress automatic reconnection.
Interrupted requests resume their original outcome; uncertain native effects
require operator inspection.

Core 0.10.4 and Suite 0.10.3 remain the supported native pair. Initial native
admission must finish within 24 hours after redemption, bounded by the host
access deadline. See [private invitations](SelfServiceInvitations.md) for setup,
recovery, expiry and limits.

## 0.2.1

Service operators can restrict new rooms, private groups and direct conversations
to an explicit list of enrolled human accounts. An empty list disables creation.
The service checks the authenticated account, including requests from older
clients. Agents and delegated actors cannot inherit an allowed operator account.
Existing conversations and their membership rules remain unchanged.

Operations adds room-creation inspection and controls to the desktop and command
line. Managed updates stop the owned service, write the reviewed policy atomically
and restore its prior running state. Existing service configurations retain their
previous creation policy until an operator changes it.

HyperNet Page links can use a separately joined reader profile selected in
**Settings > HyperNet Pages**. HRC verifies its network and distinct identity
before opening the native browser with the current theme. The chat companion
keeps its own profile. Each reader profile supports one active browser at a time.

The supported hosting pair is Core 0.10.4 and Suite 0.10.3. These native patches
correct renewed route admission and updates to approved Pages.
No transport protocol or stored conversation schema changes are required.
See [service permissions](Operations.md) for configuration and restart behaviour.

## 0.2.0

HRC now includes an application-menu launcher, guided endpoint setup and an
Operations workspace. Users can create a HyperNet, host an HRC service, invite
accounts, activate registrations and control owned services from the desktop.
Native hosting uses signed Core 0.10.3 and Suite 0.10.2 packages and explicit,
finite consent. Renewal preserves network and service identities.

Saved local model definitions support llama.cpp, Ollama and existing loopback
endpoints. Separate agent profiles, model checks and bot start/stop controls are
available in Operations. Room context survives bot restarts within its selected
retention and storage limits. Shared memory inspection and reset remain limited
to the bot operator and room moderators.

The desktop adds consistent controls, Classic message dividers, optional bubble
layout, left-aligned room and member lists, and separate connection readouts.
Drafts and the active conversation remain available while using Operations.

Appearance includes fourteen light and dark colour schemes, preserving both
original HyperNet defaults. Local JSON themes have preview, import and removal
controls, bounded storage and contrast validation. Themes contain no executable
code or external assets.

Canonical HyperNet Page addresses now appear as compact desktop links with
width-bounded labels, full-address hover details and copy controls. Opening a link
uses the chat profile's configured Suite browser and joined network profile,
with the current HRC palette shared through a private JSON snapshot. Existing
Page routes and reader permissions still apply. See [Page links](Interfaces.md#hypernet-page-links).

The external assistant harness exports reviewed setup and operations skills for
Codex, Claude Code, Gemini CLI, GitHub Copilot CLI and Cursor. Desktop controls
work independently. Provider exports follow their documented formats; live
provider discovery and model execution are not qualified by this release.
Optional hardening remains a separate choice from normal setup.

The release remains a private Apache-2.0 Linux pilot. Existing performance
qualification retains the versions and workload stated in the
[integration profile](IntegrationProfile.md). It is not a new measurement of
every 0.2.0 deployment or a qualification of additional platforms.

## 0.1.0

The initial pilot provides native HyperNet conversation, delegation, persistent
history, federation, encrypted direct conversations and private groups, with GUI,
TUI and CLI clients. Its original release and qualification records remain valid
for their stated source revisions and operating envelope.
