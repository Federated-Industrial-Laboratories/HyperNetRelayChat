# Using HRC

Open **HyperNet Relay Chat** from the application menu. The setup wizard opens
the last profile or guides a new endpoint through admission. **Operations** is
available both before connecting and from the conversation toolbar. It contains
network creation and hosting, local service admission, model and bot controls,
and the optional external assistant installer. Return with **Back to chat**;
the conversation and drafts remain open while an operation runs. See
[desktop hosting](DesktopHosting.md) and [desktop bots](DesktopBots.md).

Choose **Join a server** for the shared address, link, QR and password workflow,
or reopen a saved profile. See [simple joining](SimpleJoining.md) for offline
preference, Pages and external Agent setup. Each open client owns its profile's
encrypted local state exclusively. Use separate enrolled profiles for simultaneous
clients or Agents. The [manual service and client setup](ConversationSetup.md)
procedure remains available.

When the host enables optional [private invitations](SelfServiceInvitations.md),
choose **Join with a private invitation** and use a fresh private setup folder.
The desktop completes native admission and HRC registration using locally
generated keys. The manual setup steps remain available.

```sh
hrc gui --profile /absolute/path/to/profile
hrc tui --profile /absolute/path/to/profile
```

Add `--offline` to inspect retained conversations and edit drafts without opening
a connection. Reconnect always uses the configured HyperNet companion and current
permission. The status view distinguishes offline state, connection preparation,
uncertain-operation resolution and reconnect backoff. A stale retained view is
labelled; cached content is not proof of current room access.

## Conversations and drafts

The conversation switcher lists available rooms and unread counts. Select a joined
room, join an available room, or create a community room when permitted. The
ordinary simple-server preset does not permit room creation. The member list distinguishes
agent accounts and announced presence. An absent presence announcement does not
prove an endpoint is disconnected or that a person is away. `/presence TEXT`
announces the current endpoint for five minutes. Account classification does not
prove who personally typed a message.

The GUI uses Ctrl+Enter to send and Enter for a new line. Ctrl+L focuses its composer,
Ctrl+F focuses search, Ctrl+Q closes, and F1 opens help. Tab moves between controls.
Right-click a message to reply, copy its full text or copy its stable event identifier. The member menu
offers bound mentions, recipient filtering and applicable moderation operations.

The TUI uses Enter to send, Ctrl+J for a new line, Tab for unambiguous completion,
Ctrl+N/P for joined rooms, Ctrl+R to refresh and Ctrl+Q to close. PageUp/PageDown
scroll history. Ctrl+A selects the draft, Shift+Left/Right extends selection, and
Ctrl+Z/Y undo or redo. Esc returns to the conversation. Terminal controls in
received text are rendered visibly and cannot execute commands or clipboard actions.

Room and event-context navigation saves the latest draft before switching. The
composer pauses while that navigation is in progress and resumes when it finishes
or fails. A delayed send result cannot clear text or mentions edited afterwards.

Editing, selection and deletion preserve whole Unicode graphemes. Completion
recognises whole Unicode whitespace characters, including in restored drafts. Drafts are limited
to 8,192 UTF-8 bytes and 2,000 graphemes. An invalid replacement paste preserves the
existing draft. The GUI uses installed system fonts for scripts and emoji missing
from its bundled fonts; terminal glyph support depends on the terminal and its fonts.

Draft saves run through the shared encrypted client store. Switching rooms and
closing wait for the local save acknowledgement. A storage failure keeps the
interface open with an explicit error. Sending preserves the draft until a matching
committed result arrives; subsequent different typing is retained. A queued local
request is not a service commit. A service commit is not a delivery or read receipt.

Choose a member completion to create a bound mention. The stored account identity
and selected spelling are checked when sending. Plain `@name` text alone does not
notify someone. Editing a selected spelling removes its binding, and a nickname
change cannot silently redirect an earlier mention.

## HyperNet Page links

Canonical `hypernet://NETWORK/AUTHOR/Namespace/PAGE` addresses appear as compact
Page links in desktop messages and search results. Hover to inspect the complete
network, author, namespace and Page identity. Right-click the link to copy its
original address; **Copy message** preserves the complete original message.
Hovering does not fetch Page content or contact a publisher.

Click a link to open the existing HyperNetSuite graphical browser. HRC uses the
trusted Suite executable retained by this chat profile's setup. A profile without
that configuration reports the missing setup.

For a simple saved server, Suite creates the separate Page reader when the host
advertises one. Links focus and reuse that reader's browser. A queued link waits
while an interactive form is active; **Leave page and open queued link** permits
explicit navigation. No reader folder or second admission exchange is required.

For a manual profile, complete normal native admission for a separate Page reader. In **Settings > HyperNet Pages > Configure reader**,
select **Use a separately admitted Page reader**. Choose its private native
`Profile.json` with **Browse**, then choose **Check and save**. This selection is
saved for the current chat profile and survives reopening HRC. It does not stop
or replace the chat companion. No manual configuration editing is required.
Entering Setup or switching chat profiles closes reader settings and cancels any
pending Page launch. Existing browser windows remain open with their own profile.

HRC uses Suite's offline `network inspect` command to verify joined membership,
the same network, incarnation and accepted bootstrap, and distinct client, device and relay public
identities. A copied chat profile is refused. HRC checks the saved selection
again when opening a link. It never copies the reader's keys or requester state.
Inspection confirms retained membership, not current Page permission; Suite
checks current authority and verifies the publication when the Page is opened.

The reader needs its own current Page and authority routes and reader grant from
the network operator. A chat link and this setting grant no access. Close the
manual reader's existing browser window before opening another Page: one native
network profile can serve only one active client. Simple saved readers use their
private navigation channel to reuse the same owner instead. Navigation within that browser remains
available while chat continues. Another-network link is refused; select the
corresponding chat and reader profiles explicitly.

Existing runtime configurations keep their original chat-profile default. Clear
**Use a separately admitted Page reader** and save to restore that default.
Its native companion must be stopped before the browser can use the same profile;
disconnecting chat alone does not stop the companion. A missing, invalid or busy
selected reader reports an error and does not fall back to another identity.
A link can also be opened from retained chat history while chat is offline; that
explicit action starts a separate browser connection.

Each new browser window receives the currently selected HRC colour palette and
outline settings. Existing windows keep their launch palette. Browser text size
and other browser preferences remain independent. See [desktop themes](Themes.md).

Only canonical addresses become links: network and author identities contain
64 lowercase hexadecimal digits; Page identities contain 32. A namespace starts
with a letter and contains up to 32 ASCII letters and digits. Each message displays
at most 16 active Page links. Other text, including HTTPS references and malformed
addresses, remains selectable text.

## Commands and search

Both interactive clients support `/join`, `/part`, `/create`, `/me`, `/nick`,
`/topic`, `/reply`, `/motd`, `/connect`, `/disconnect` and `/help`. Use `//` to send
a literal leading slash. Ambiguous names are refused; use a complete stable account
or room identifier to select the target explicitly.

The GUI search controls accept text, acting sender, represented account and UTC
date bounds in YYYY-MM-DD or ISO 8601 form; the upper bound is exclusive.
Names are accepted when unambiguous. The TUI supports the same filters with
explicit account IDs and UTC millisecond bounds:

```text
/search --sender ACCOUNT --from UTC_MILLISECONDS --until UTC_MILLISECONDS -- text
```

Use `/next`, `/cancel-search` and `/close-search` for search controls. Search uses
current access and recipient filters. A result retains its message ID; the GUI's
Open context or `/context EVENT` obtains an authorised surrounding history page.
Return to live conversation with the GUI button or `/live`. A history gap is explicit;
use Resynchronise or `/resync` to request the currently permitted retained history.

## Filtering, moderation and notifications

`/ignore ACCOUNT` suppresses that account's service delivery and history/search
presentation for the recipient. `/mute ACCOUNT` suppresses notifications. Their
`/unignore` and `/unmute` forms remove the settings. Room moderators can use
`/silence`, `/unsilence`, `/kick`, `/ban` and `/unban`. The command defaults are a
five-minute silence and a one-day ban. Scope, expiry and moderator attribution are
inspectable in Status. All service authorisation checks still apply.

Settings provide dark/light appearance, compact/comfortable density and text scale.
The desktop update adds **Classic** history with horizontal dividers and **Bubbles**
with cut-corner message panels. Settings also provide nickname editing. The bottom
readout separates connection state, TLS, relay and content protection. **LAST RTT**
measures the latest direct message frame write through its authenticated service
commit acknowledgement; it excludes UI time and is not a recipient receipt.
An unavailable measurement is shown as a dash.
Per-room notifications can include all messages, bound mentions only, or none.
Quiet mode suppresses notifications and sounds. Catch-up does not generate a burst
of alerts. Sound requires both global and room selection; it is off initially.
The TUI uses the terminal bell. The GUI uses the optional `canberra-gtk-play`
desktop sound utility with fixed arguments and a bounded worker; unavailable sound
is reported without blocking the conversation. No message content enters that process.

TUI settings use `/theme`, `/density`, `/quiet`, `/sound`, `/room-sound`, `/notify`
and `/width`; `/help` lists accepted values. The GUI Status view and `/who` show
actual observed HyperNet privacy properties. Community rooms are service-readable.
Relay obfuscation, transport protection and message encryption are separate properties.

## Agents and uncertain outcomes

Agents shows eligible owned endpoints, exact grants and pending actions. A new grant
selects one room, draft/approval/autonomous mode, allowed operations, history window,
validity and rate. Reading, replying, sending, marking handled and moderating are
separate selections. `/grant` exposes those same choices in the TUI; its full syntax
is in `/help`. The purpose describes intent and does not expand the selected scope.

Inspect a grant before approving its exact pending action and digest. Changed content
requires another approval. Pause stops subsequent delegated effects; resume restores
a paused grant, while revocation permanently invalidates that grant. No control
retracts content already received. These distinctions are visible in the agent view.

Status retains operation identities, content digests and outcomes. A current refusal
does not establish that a previous uncertain attempt failed. Stop retrying deliberately
with the GUI control or `/abandon WINDOW:OPERATION DIGEST`; the immutable request and
unknown outcome remain. `/resolve WINDOW:OPERATION DIGEST` can query a later result
without resubmitting an abandoned effect.

The [shared-client contract](LocalClient.md) documents bounds, persistence,
cancellation and inspection. The CLI provides structured noninteractive JSON
through the same operation semantics.

## Confidential conversations and network selection

Use the private-group or direct-conversation controls to create an encrypted room.
`/private NAME`, `/msg ACCOUNT` and `/whisper ACCOUNT` expose the same
workflows. Check contact fingerprints and current endpoint membership before
establishing an encrypted epoch. A pending membership barrier prevents sending;
neither the GUI nor the TUI substitutes a plaintext message. See
[confidential conversations](ConfidentialConversations.md) for the exact initial
trust, invitation and encryption controls.

Explicitly configured bilateral agreements appear in the home-service selector.
Use `/network local` or `/network AGREEMENT` in the TUI. The selection changes the
receiving home and available rooms; it does not change the account's network origin.
Local drafts, uncertain operations and filters retain their service context.
Switch back to the account's origin for its identity lifecycle operations.
An unavailable or withdrawn agreement remains a failed remote path, with no direct
transport fallback. The [federation guide](FederationRuntime.md) describes gateway
admission and the two separately observed HyperNet transport legs.

These development workflows still require release qualification. Use the exact
release's documented platform and capacity limits when deploying it.
