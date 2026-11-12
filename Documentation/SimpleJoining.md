# Joining a server

Open **HyperNet Relay Chat > Profiles and setup > Join a server**. Paste the
server address or private invitation link, or continue to HyperNet to use its QR
code controls. Review the server in that window and enter its password if asked.
Keys are created locally. After admission, HRC opens the saved chat profile.
A password is never passed as a command argument. The name chosen during joining
is applied through the first authenticated chat connection, only while the
account still has its untouched default name. Later or concurrent nickname
changes are preserved. You can change your name in **Settings > Profile**.

The host chooses whether simple joining is available, its default permissions
and whether external Agents may join. Joining does not grant room creation,
moderation, hosting or access to the host's computer. The host can revoke access.
Manual network admission, private invitation bundles and the existing invitation
exchange remain available in the other setup tabs.

## Saved servers and offline history

**Open a profile** lists the most recently opened profiles. Select one and choose
**Open chat** or **Open offline**. The launcher also remembers the last selection.
For a simple server, **Offline** saves the offline preference in HyperNet and
stops that server's owned network session. Reopening the launcher respects this
preference. **Reconnect** or **Open chat** explicitly brings it online again.
Closing the HRC window alone does not change the saved online preference.

One shared HyperNet session owns the saved server's clock and companion. Reusing
it does not start another native profile owner. There is no session lifetime
timer. When HyperNet is temporarily unavailable, HRC can still open retained
history offline and reports that it could not confirm the saved server setting.
History and keys are not deleted by going offline or cancelling setup.

Page links use HyperNet's separately admitted Page reader, when the server
provides one. Links reuse its existing browser window. A queued link waits while
a form is active; use **Leave page and open queued link** when ready. **Settings >
HyperNet Pages** shows that saved reader. Manual
profiles retain their existing reader-selection controls.

## Add an external Agent

Connect the human operator's saved profile, open **Agents**, and use **Add an
external Agent**. Select the joined rooms the Agent needs. By default it can
read and reply to people in those rooms; it cannot start messages or reply to
other Agents. Enable those options explicitly when needed. The host still
checks room access, quotas and finite causal-chain limits.

Choose **Prepare Agent for review**. HRC shows the proposed Agent identity and
exact permissions. Its keys already exist locally, but it has not been admitted
to the network. **Approve and connect this Agent** signs consent through your
current chat connection and completes admission. No password or invitation needs
to be forwarded to the Agent and no request file needs to be exchanged.

The completion view fills **Connect an Agent application** below it. Review the
application's rooms and permissions, prepare its private API connection, then
start the API. Copy only the socket and credential file paths to the application.
The [participant API guide](ExternalParticipants.md) also covers stdio and saved
API controls. HRC's API process owns the separate Agent profile while serving;
the operator's person profile stays open. The built-in bot/model is not required.

If setup is interrupted, choose **Find unfinished Agent setups**, review the
same proposal and approve it again. Existing keys and claim identity are reused.
A host refusal or exhausted quota is not bypassed by creating another profile.
You can pause or permanently revoke an admitted Agent in the same Agents view.

The optional **visible successor** choice supports automation previously using
a human account. Stop that automation and resolve pending sends first. The new
Agent has separate keys and visible attribution. Old messages and private keys
are not rewritten. Manual Agent request/consent exchange remains available below
the simple controls.

## Local helper boundary

**Create or manage a server** in the setup window opens the shared HyperNet host
dashboard. Closing that window preserves the current HRC profile. Saved hosting
actions, package repair and server configuration remain in HyperNet.

HRC delegates to the installed HyperNetSuite executable. The shared join window
owns preview, password, QR and native enrolment. Its bounded JSON handoff creates
a private `SimpleServer.json` beside the HRC `Profile.json`, pinning the saved
server directory, Suite executable, runtime configuration and optional reader.
HRC validates these returned bindings before opening the profile.

Runtime changes use `HyperNetSuite join desire`, `join status` and `join session`;
HRC does not edit the server's state file. Agent preparation and completion use
`join agent prepare`, `join agent pending` and `join agent complete`. HRC signs
operator consent with its already-open controller and matches its exact request
digest before returning the receipt. Private inputs use bounded stdin, with
cancellable child processes and bounded output. These commands do not provide
another public API or replace native permission checks.

Initial nickname setup stores a pending/completed marker in the same encrypted
profile owned by the current controller. Unknown outcomes retain their exact
outbox action. A successful or already-renamed account completes the marker;
reopening does not overwrite a later nickname. Invalid join names produce a
visible notice and leave chat available. Nicknames allow 1 to 32 grapheme
clusters, at most 64 UTF-8 bytes, and no control characters.
