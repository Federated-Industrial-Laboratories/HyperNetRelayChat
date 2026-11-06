---
name: hrc-recovery
description: Recover a selected HRC desktop, service or local-model bot after interruption while preserving identity, private state and uncertain operation outcomes.
---

# HRC recovery

Read [the operating contract](../hrc-setup/references/Contract.md). Establish what
failed, the last known working state and the exact affected host/profile.

1. Inspect installed management status and bounded diagnostics. Distinguish a
   stopped runtime, unavailable route, expired permission, locked profile,
   unsupported model and corrupt storage. Each has a different repair.
2. Preserve drafts, pending operation IDs and identity material. Resolve uncertain
   sends through supported client operations before retrying. Never create a
   replacement operation ID just to bypass an uncertain acknowledgement.
3. Restart only the selected managed process when appropriate. If a profile is
   already open, activate that client or stop its owner cleanly; do not delete
   lease files or copy the database to run a second owner.
4. For backup or restore, stop the selected service/profile and use the matching
   version's documented procedure. Restore into a separate private location.
   Check account/network incarnation, service identity and migration compatibility
   before directing clients to it. Retain the original until recovery is verified.
5. Restore only current authorised access. Expired consent needs renewal; revoked
   grants need a fresh grant. Account recovery does not recover earlier encrypted
   history automatically. Do not substitute private keys or change network origin.
6. Check one representative conversation or bot reply from another endpoint and
   report retained state, any irrecoverable gap and the resulting running state.

An unavailable backup, missing key or incompatible state is an explicit limitation.
Do not manufacture a successful recovery or erase evidence to clear the error.
