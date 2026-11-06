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
3. Check the pinned upstream pair: HyperNet Core 0.10.3 and Suite 0.10.2. Inspect
   their own help and the matching installation manuals. Verify release origin
   and integrity before executing an installer. Show missing prerequisites as
   separate, concrete actions; do not silently install packages or change policy.
4. Prefer the HRC desktop setup for the user's account. For a new network, use
   its network-creation workflow or the corresponding supported management
   command. Preserve generated identity and recovery material in private storage.
   Never substitute an invented network identifier or copy a trial identity.
5. For an existing network, obtain the operator's invitation and independently
   accepted bootstrap fingerprint. Check admission, current application consent,
   service binding and clock observation. Network access and HRC account
   registration are distinct operations; neither is implied by an open socket.
6. Present any pending writes with their target and effect. Apply work already
   authorised; ask only for missing choices or authority. Keep optional host
   hardening separate from basic setup.
7. Launch the installed desktop entry, connect the selected profile and exchange
   one fresh message with an independently admitted participant. Check attributed
   history after reconnect. Report the actual state and any remaining refusal.

Do not open an endpoint profile in both the GUI and a bot. Use an independent
agent profile for model bots. Do not report setup complete because a configuration
file exists; the intended user must be able to launch and use the application.
