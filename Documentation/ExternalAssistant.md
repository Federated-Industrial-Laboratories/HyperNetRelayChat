# External setup and operations assistant

[Documentation](ReadMe.md) &middot; [Install](Installation.md) &middot;
[Desktop interfaces](Interfaces.md) &middot; [Service bots](ServiceBots.md)

The optional harness teaches an external coding assistant how to set up and
operate HRC, including new HyperNets, services and local-model adapters. The HRC
desktop has its own setup and management controls and works without this assistant.
This is separate from bots that participate in conversations.

## Install from the desktop

Open the desktop assistant controls, choose the installed provider and the
destination workspace, then preview the file changes. Apply that selection and
restart or reload your provider. Complete its normal workspace-trust prompts.
No model is downloaded and no provider account is created by HRC.

Workspace scope keeps the harness with the selected operations workspace. User
scope installs to the selected user's home for use across workspaces. If a
provider has a custom configuration home, place the files using that provider's
documented mechanism instead of assuming its default discovery locations.

The same native export is available without the GUI:

```sh
hrc assistant providers
hrc assistant install --provider codex --destination /absolute/operations-workspace
hrc assistant install --provider codex --destination /absolute/operations-workspace --apply
```

Replace `codex` with `claude`, `gemini`, `copilot` or `cursor`. For personal scope,
add `--scope user` and select the absolute home directory. The preview is read-only;
`--apply` performs the listed installation. No Python or source checkout is needed.

## Choose a task

| Skill | Use it for |
| --- | --- |
| `hrc-setup` | Install, create or join a HyperNet, enrol a client and verify the first conversation |
| `hrc-operations` | Inspect and operate a selected network, service or bot |
| `hrc-models` | Configure llama.cpp or Ollama, agent membership, response triggers and bounded memory |
| `hrc-security` | Review and apply explicitly selected host-security options with recovery steps |
| `hrc-recovery` | Recover interrupted clients, services and bots while preserving identity and pending outcomes |

For example: "Use hrc-setup to help me create a new HyperNet on this machine and
open HRC from the desktop." Supply the intended host and desired result. The
assistant discovers the installed `hrc manage` help, templates and validation commands before making
changes. Core 0.10.4 and Suite 0.10.3 are the supported upstream pair.

For command-line work, these entry points expose the actual saved input formats:

```sh
hrc manage model template
hrc manage bot template
hrc manage model validate --file /absolute/private/Model.json
hrc manage bot validate --file /absolute/private/Bot.json
hrc manage network template --root /absolute/private/HyperNet --output /absolute/private/Network.json
hrc manage network preview --config /absolute/private/Network.json
```

Use `save --file` for a validated model or bot definition. Managed inference
runtimes belong to `manage model`; there is no separate `manage runtime` or general
JSON-schema command. Network preview also checks the selected native prerequisites.

The `hrc-observer` role inspects supplied evidence. `hrc-local-operator` works on a
selected local host; `hrc-remote-operator` works on a separately selected remote
host with verified SSH identity. Role selection does not authorise changes or
provide credentials. Existing task approval still applies; missing authority
remains an explicit decision.

## Providers and discovery

| Provider | Workspace skills | Personal skills | Role files |
| --- | --- | --- | --- |
| Codex | `.agents/skills/` | `~/.agents/skills/` | `.codex/agents/*.toml` |
| Claude Code | `.claude/skills/` | `~/.claude/skills/` | `.claude/agents/*.md` |
| Gemini CLI | `.gemini/skills/` | `~/.gemini/skills/` | `.gemini/agents/*.md` |
| Copilot CLI | `.github/skills/` | `~/.copilot/skills/` | Workspace `.github/agents/*.agent.md`; personal `~/.copilot/agents/*.agent.md` |
| Cursor | `.cursor/skills/` | `~/.cursor/skills/` | `.cursor/agents/*.md` |

Except for the explicitly listed Copilot difference, role paths are relative to
the chosen workspace or home. Install once per provider and scope: some clients
discover other providers' skill directories too, so duplicate installations may
produce duplicate choices. Skills and roles are local files, not a marketplace
publication. No hooks, MCP server, provider settings or model selection are added.

The formats were checked against primary documentation on 6 November 2026.
They are not a claim of live discovery or successful model operation on every
provider. The bundled [compatibility metadata](../Harness/compatibility.json)
records that distinction. See the provider's current discovery instructions:

- Codex: [skills](https://learn.chatgpt.com/docs/build-skills) and
  [custom agents](https://learn.chatgpt.com/docs/agent-configuration/subagents).
- Claude Code: [skills](https://code.claude.com/docs/en/skills) and
  [subagents](https://code.claude.com/docs/en/sub-agents).
- Gemini CLI: [skills](https://geminicli.com/docs/cli/skills/) and
  [subagents](https://geminicli.com/docs/core/subagents/).
- Copilot CLI: [skills](https://docs.github.com/en/copilot/how-tos/copilot-cli/customize-copilot/add-skills)
  and [custom agents](https://docs.github.com/en/copilot/reference/custom-agents-configuration).
- Cursor: [skills](https://cursor.com/docs/skills) and
  [subagents](https://cursor.com/docs/subagents).

Claude, Gemini and Copilot observers restrict tools to file reading and search;
they cannot execute management status commands. Cursor requests its native
read-only mode. Codex inherits its parent's permissions; its observer reduces
supported capabilities but does not create an independent read-only sandbox.
Supply redacted evidence where tools are unavailable. Cloud or remote provider
sessions need their own discovery and authorised host access.

## Optional security and private data

Ordinary desktop setup does not require an extensive hardening programme. The
security skill offers relevant choices such as service accounts, narrow firewall
rules, SSH access policy, encrypted backups, confinement and retention. It explains
effects and recovery before an authorised change. Mandatory HyperNet transport,
identity, consent and message-protection checks remain enabled.

Do not provide chat transcripts, private keys, passwords or unredacted configuration
to an external provider as routine diagnostics. The harness receives no automatic
conversation access. Any disclosure of content needs separate permission and an
allowed destination. Local-model bot memory remains governed by the room and bot
policies; installing this harness changes neither.

## Updates and removal

Re-export from the selected HRC version to update the installed content. Ownership
receipts under `.hrc-harness/receipts/` let the installer distinguish its unchanged
files from unrelated or edited files. Conflicts are reported without overwriting
them. Preserve the receipt and review the conflict instead of deleting shared
provider configuration. Interrupted installations can resume from their receipt.

```sh
hrc assistant uninstall --provider codex --destination /absolute/operations-workspace
hrc assistant uninstall --provider codex --destination /absolute/operations-workspace --apply
```

Removal preserves edited files and reports them. Empty directories and the receipt
may remain. It does not remove providers, credentials, HRC profiles or services.
Use a directory you own and avoid concurrent edits during installation. Observed
symbolic and hard links are refused; this does not isolate hostile processes that
share the same operating-system account.
