---
name: hrc-models
description: Configure a local llama.cpp or Ollama HRC bot, select a model, inspect bounded room memory, and diagnose missing replies without exposing private content.
---

# HRC local models

Read [the operating contract](../hrc-setup/references/Contract.md). This skill
operates a model bot; the external assistant itself remains outside the chat.

1. Select the host, existing backend installation, local model and agent profile.
   Read `hrc bot --help`, `hrc manage bot --help` and `hrc manage model --help`.
   Their `template` and `validate --file` commands describe and check saved input.
   Inspect the backend's actual version and help. Do not invent backend switches.
2. Use llama.cpp or Ollama bound to loopback. Keep prompt logging and unintended
   cloud use disabled. Downloading a model is a separate network/storage action;
   obtain permission for its source, licence, destination and size first.
3. Give the bot its own enrolled agent endpoint and consistent nickname. For a
   delegated bot, inspect the exact current grant; for an independent bot, inspect
   its operator binding. Join intended rooms using that endpoint. Avoid starting
   a GUI against the same profile while the bot owns it.
4. Configure the local adapter, model, context limit, response budget and trigger
   prefix. llama.cpp must supply its template/tokenization interfaces. Ollama
   must describe a local model and uses conservative bounded input plus explicit
   generation limits. An unsupported or remote model is refused; preserve the
   adapter's accounting rather than substituting an unbounded prompt.
5. Retain memory for 30 days by default, subject to storage, context and current
   room-history limits. Preserve the implemented bounds and expiry. Long-lived
   rooms must evict old context rather than grow without limit. Conversation
   history and model context have separate retention rules.
6. Inspect context using the supported bot controls. Only the bot operator and
   room moderators may clear shared room memory. A reset removes model context,
   not shared chat history. Warn before an authorised reset; never reset simply
   because the assistant cannot inspect the state.
7. Start the selected runtime and bot through their supported controls. Send one
   new addressed message from a separate human endpoint and verify a fresh,
   attributed reply. Check readiness, membership, prefix, model health and
   permission in that order when no reply arrives. Do not replay old room history
   as new prompts or create an agent-to-agent reply loop.

Do not expose a local inference port publicly or send room context to an external
provider as a repair. Any external disclosure requires its own allowed destination
and user consent. GPU and memory use must fit the host's other active work.
