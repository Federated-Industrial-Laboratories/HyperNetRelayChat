---
name: hrc-setup
description: Set up HyperNet Relay Chat on a selected Linux desktop or host, join an existing HyperNet or create a new network, and check the first conversation.
---

# HRC setup

Read [the operating contract](references/Contract.md) first. Use this skill for
installation and first use, including a new HyperNet. The desktop setup and
management controls work without this assistant.

1. Identify the user's goal: join an existing network, create a network, host an
   HRC service, or add a client. Select the exact local or remote host and private
   installation paths. Reuse the user's existing decisions and permissions.
2. Inspect `hrc --version`, `hrc --help` and `hrc manage --help`. Read the selected
   operation's help, template and validation commands before preparing input. Use only
   capabilities the installed version actually exposes.
3. Check the pinned upstream pair: HyperNet Core 0.11.0 and Suite 0.11.0. Inspect
   their own help and the matching installation manuals. Verify release origin
   and integrity before executing an installer. Show missing prerequisites as
   separate, concrete actions; do not silently install packages or change policy.
4. Prefer the HRC desktop setup for the user's account. Its **Install native
   tools** workflow verifies the supplied coordinated Packages folder. **Join a
   server** and **Create or manage a server** open the shared HyperNet workflows.
   The earlier manual network controls remain available. Preserve generated identity and recovery material in private storage.
   Never substitute an invented network identifier or copy a trial identity.
5. For a simple server, use the host's address or pinned invitation link in
   **Join a server**, review its identity and enter a password only in the shared
   join window when required. Resume interrupted setup with its retained keys.
   For the manual workflow, obtain the operator's invitation and independently
   accepted bootstrap fingerprint. Check admission, current application consent,
   service binding and clock observation. Network access and HRC account
   registration are distinct operations; neither is implied by an open socket.
   The v1 workflow also supports optional private self-service invitations. With an
   invitation from the intended host, use **Join with a private invitation**.
   The desktop generates keys locally and retains the exact admission for retry.
   Read the installed SelfServiceInvitations manual; keep the bearer code private.
   Manual file exchange remains available.
6. Present any pending writes with their target and effect. Apply work already
   authorised; ask only for missing choices or authority. Keep optional host
   hardening separate from basic setup.
7. Launch the installed desktop entry, connect the selected profile and exchange
   one fresh message with an independently admitted participant. Check attributed
   history after reconnect. Report the actual state and any remaining refusal.

Do not open an endpoint profile in both the GUI and a bot or API process. Use
**Agents > Add an external Agent** for a separately keyed participant and explicit
operator consent. The local API works without a model runner. Keep its credential
file private and share only a local configuration path with the intended client.
Do not report setup complete because a configuration
file exists; the intended user must be able to launch and use the application.
