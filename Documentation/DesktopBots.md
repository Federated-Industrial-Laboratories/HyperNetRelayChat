# Desktop bots and local models

[Documentation](ReadMe.md) &middot; [Service bots](ServiceBots.md) &middot;
[External assistant](ExternalAssistant.md)

Open **Operations** from the desktop. **Local models** manages inference
connections and optional local runtimes. **Bots** manages separate agent profiles
and their conversation settings. Neither page requires an external coding
assistant.

## Connect a model

1. In **Local models**, choose **New model**. Set its name, model name or alias,
   adapter and loopback address. Select the installed `curl` executable.
2. Choose the runtime owner:

| Mode | Required selection | HRC controls |
| --- | --- | --- |
| Existing endpoint | A running local llama.cpp or Ollama server | Probe only; the external process is not started or stopped |
| Manage llama.cpp | Installed `llama-server`, local GGUF file and GPU layer count | Start, status and stop for this definition's own user service |
| Manage Ollama | Installed `ollama` and its existing local model folder | Start, status and stop; cloud features disabled |

3. Set the context and reply limits. Managed runtimes also have memory, CPU and
   optional process-isolation settings. GPU layers of zero select CPU execution
   for llama.cpp. Leave CUDA devices empty to inherit the local selection, or
   enter the intended device list. An explicit shared-library folder is available
   for installations that require one.
4. Select **Save model**. For a managed runtime, select **Start**, then **Probe**
   after the model has loaded. An existing endpoint can be probed immediately.

The probe sends a short synthetic availability request, without conversation
content, and reports whether the backend produced a usable response. A running
process is not the same as a successful inference probe. Cold model loading can
take longer than a status check.

HRC accepts loopback endpoints only. It does not download models, install backend
packages or expose inference ports. Managed llama.cpp uses a local GGUF file,
offline mode and disabled prompt logging. Managed Ollama sets `OLLAMA_NO_CLOUD=1`
and its selected loopback listener. For an existing Ollama service, its operator
must disable cloud features separately. HRC also rejects model descriptions that
identify remote execution. See [llama.cpp's server options](https://github.com/ggml-org/llama.cpp/blob/master/tools/server/README.md)
and [Ollama's local-only configuration](https://docs.ollama.com/faq#how-do-i-disable-ollamas-cloud-features).

A managed start refuses an occupied endpoint rather than replacing its listener.
Stop dependent bots before editing a model or stopping its managed runtime. HRC
does not stop an unrelated backend or a service managed outside this definition.

## Prepare an agent endpoint

A bot needs its own HyperNet application principal and HRC agent account. Do not
reuse the human profile open in your desktop client.

For an existing enrolled agent profile, select its private folder on the **Bots**
page. For a new endpoint:

1. Admit its independent HyperNet application using the network's normal consent
   process. Obtain an HRC agent invitation from the service operator; it names the
   human operator of that account.
2. Choose a new agent profile folder. Expand **Create agent profile** and select
   the invitation, independently accepted service public key, companion folder,
   current clock observation and clock monitor public key.
3. Select new destinations for the recovery key and signed registration. Keep the
   recovery key outside the profile. Select **Prepare profile**.
4. Give the registration to the service operator. **Activate account** opens the
   desktop service page with that registration selected; an authorised operator
   completes enrolment there. Remote operators use their selected service's
   equivalent enrolment workflow.

The invitation is trusted through its independently accepted service key; it is
not a signed registration. Profile creation generates fresh endpoint, recovery
and storage keys and produces the signed registration. Existing destinations
are preserved. Until the service accepts the registration, the account is pending.
An existing onboarding runtime beside the profile remains responsible for its
companion and clock lifecycle; otherwise those components must already be running.

**Use connection** copies the service public key, companion path and clock
settings from a selected existing HRC profile. It never copies account keys.
The bot receives fresh endpoint, recovery and storage keys. New definitions
propose separate private destinations for the agent profile, recovery key and
registration, so those paths do not need to be assembled manually.

## Configure and start the bot

Set the definition name, visible nickname and agent profile. Select **Load rooms**
after account activation, then select the permitted rooms. The bounded list shows
up to 32 rooms; complete identifiers can also be entered, one per line.
A deterministic help bot can use up to eight rooms;
a model bot uses exactly one. Set the help reply and poll interval.

Choose **Deterministic help only**, or select a saved local model. Model bots
support a message prefix, or explicitly selected replies to direct human messages
in that room. Keep the prefix distinct from `!help`. A delegation ID is optional;
when supplied, its current autonomous grant determines the represented account
and allowed effects. Leaving it empty uses the independent agent account.

Select **Save bot**, then **Start**. Start checks model inference if selected,
prepares the existing transport runtime, resolves uncertain prior operations,
sets the nickname and joins missing rooms for independent participation. Existing
membership is inspected first; a restart does not leave and rejoin the room.
Delegated participation uses the represented user's membership and grant.

The process status reports whether the owned service is running. The
`initialConnectionVerified` field records an authenticated initial history catch-up
in that process invocation. It is not a permanent online indicator. Verify a fresh
reply from a separate human endpoint when testing end-to-end availability.

Only one process can own the agent profile. Stop its GUI before running the bot,
or stop the bot before opening that profile in a GUI. HRC will not close another
profile owner automatically. **Stop** remains available while settings have
unsaved changes; **Start** uses an unchanged saved definition.

## Context and long-running rooms

Model context defaults to 30 days and 256 KiB of encrypted derived storage,
within the configured context/reply limits. Shorter room history and encrypted
archive restrictions still apply; encrypted-room derived memory has a seven-day
ceiling. The retained context is bounded and may omit or summarise earlier text.
It is not an unlimited transcript or a guarantee of perfect recall.

Disable **Retain bounded room context** for stateless replies. Changing the model
definition does not erase chat history. The existing memory inspection/reset
controls remain available to the bot operator and room moderators; see
[service bot memory](ServiceBots.md). The external setup assistant receives no
automatic access to either model memory or conversations.

**Resynchronise on next start** is an explicit one-start recovery choice for a
stale cursor. It resets cursor/context and catches up without treating old
messages as new triggers. Use it for the stated recovery condition, not as a
routine restart option.

## Saved settings and command-line equivalents

Definitions are private JSON files under the user's HRC `Operations/Models` and
`Operations/Bots` data directories. They contain paths and settings, not copies
of private keys. Up to 32 definitions of each type are supported. Definitions
cannot be edited while their process is active; a model also refuses edits or
stop requests while a dependent bot is active. Normal application startup does
not automatically start these user services after a reboot.

The desktop uses the same native commands exposed to external assistants:

```sh
hrc manage model --help
hrc manage model template
hrc manage model list
hrc manage model probe --id MODEL_ID
hrc manage bot --help
hrc manage bot template
hrc manage bot list
hrc manage bot start --id BOT_ID
```

Use `show --id`, `validate --file`, `save --file`, `status --id`, `start --id`
and `stop --id` for the corresponding definitions. Input JSON files must be
private files matching the typed template. `bot prepare --file` creates a fresh
agent registration; `bot connect --id` authenticates and prepares membership
without starting the persistent bot. No raw protocol action construction or
shell script is required.
