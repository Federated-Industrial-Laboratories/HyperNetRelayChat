# Release notes

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
