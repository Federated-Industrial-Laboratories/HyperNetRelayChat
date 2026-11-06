---
name: hrc-operations
description: Inspect and operate an existing HRC network, service or bot, including starts, stops, invitations and diagnosis, within the selected operator scope.
---

# HRC operations

Read [the operating contract](../hrc-setup/references/Contract.md). Select the
machine and state directory before inspecting or changing the deployment.

1. Read the installed management help, templates and validation commands. Inspect current
   status, versions, identity and process ownership through supported controls.
2. Separate local runtime health, HyperNet connectivity/admission, HRC service
   access and account permissions. A listener being alive proves none of the
   latter. Diagnose the reported boundary before changing another one.
3. Use the desktop management controls or `hrc manage` operations for the chosen
   task. Prefer explicit start, stop and status operations to broad process
   searches. Preserve other profiles, services and networks.
4. Explain interruptions before offline enrolment, backup or maintenance. Stop
   only the selected owner, perform the authorised operation, then restore its
   intended running state. Inspect an uncertain result before retrying.
5. Check that the user can resume the intended conversation or bot workflow.
   Use one fresh message if a real end-to-end check is needed; retained history
   alone does not establish present connectivity.

For an expiring grant or federation agreement, report its scope and expiry. Obtain
current authority through the supported consent process. Do not lengthen validity,
change the clock, suppress verification or replace identity to clear an error.
Keep operational logs bounded and free of conversation content and credentials.
