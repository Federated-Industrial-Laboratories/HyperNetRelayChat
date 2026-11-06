# HRC external assistant

Portable setup and operations skills for a separately installed coding assistant.
The HRC desktop works independently. This harness does not run a model, add a chat
bot, grant permissions, install a provider or start a background service.

Install from the HRC desktop's assistant controls, or preview an export:

```sh
hrc assistant install --provider codex --destination /absolute/workspace
hrc assistant install --provider codex --destination /absolute/workspace --apply
```

Select `claude`, `gemini`, `copilot` or `cursor` for another provider. Workspace
scope is the default. For a personal installation, choose `--scope user` and the
absolute home directory of that user as the destination. Custom provider config
homes need manual placement following the provider's own documentation.

Restart or reload the selected provider, complete its normal trust prompts, and
select `hrc-setup`, `hrc-operations`, `hrc-models`, `hrc-security` or `hrc-recovery`.
Use `hrc-observer` for supplied evidence, `hrc-local-operator` for authorised local
work, or `hrc-remote-operator` for an explicitly selected remote host. No model,
subscription tier or permission mode is pinned. Cloud sessions do not acquire
local filesystem or SSH access merely by importing these files.

The native installer is embedded in `hrc`; no Python, source checkout or provider
runtime is required for export. It previews the exact file paths, refuses
conflicts, and updates only files matching its ownership receipt. It does not
overwrite an existing same-named file that it did not install, or an edited file
that it previously installed. Resolve a conflict deliberately, then preview again.
Keep the receipt under `.hrc-harness/receipts/` for future updates and removal.

To remove unchanged installed files, preview and then apply:

```sh
hrc assistant uninstall --provider codex --destination /absolute/workspace
hrc assistant uninstall --provider codex --destination /absolute/workspace --apply
```

Changed files are preserved and reported. Shared provider settings, unrelated
skills, credentials and installed providers are untouched. Empty directories and
the installation lock/receipt may remain. Do not delete a whole provider directory
to remove this harness.

The installer refuses observed symlink or hardlink destinations and uses atomic
file replacement and an installation lock. Use a directory you own, without
concurrent tools changing the selected files. It does not isolate hostile
processes that share your account. Skills and role instructions are not access
controls; existing provider and product permissions still apply.

Provider format references and compatibility status are supplied in
`compatibility.json`. Documentation checks do not establish live provider
discovery or model behaviour. No hooks or MCP servers are installed.

Licensed under Apache-2.0, together with HRC. Installation behaviour follows the
FICC harness's ownership-preserving approach, implemented here in the native HRC
binary. The repository and package distribution remain private.
