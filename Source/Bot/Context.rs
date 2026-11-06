// SPDX-License-Identifier: Apache-2.0
//! Fresh history binds derived memory and generated replies to one authorised room audience.
use super::{
    Config, Error, Result,
    memory::{self, Entry, Memory, Policy},
    runtime::Reply,
};
use crate::{
    client::{self, Client, ConversationPage, MessageContent, SendGuard},
    clock::TimeBounds,
    delegation, messaging,
    protocol::*,
};
use std::sync::atomic::{AtomicBool, Ordering};

pub(super) struct Context {
    pub memory: Memory,
    pub guard: SendGuard,
    pub enabled: bool,
    policy: Policy,
    encrypted: bool,
    fingerprint: Id,
    head: u64,
    own_account: AccountId,
    operator: AccountId,
    members: Vec<crate::conversations::Member>,
    generated_until_ms: Option<u64>,
    sampled: TimeBounds,
}
impl Context {
    pub(super) fn load(
        client: &mut Client,
        config: &Config,
        page: &ConversationPage,
        cursor: &HistoryCursor,
        actor: &Actor,
        grant: Option<&delegation::Grant>,
        now: TimeBounds,
    ) -> Result<Self> {
        let own_account = actor.acting().account;
        let operator = match actor {
            Actor::IndependentAgent { operator, .. } | Actor::Delegated { operator, .. } => {
                *operator
            }
            _ => return Err(Error::AgentRequired),
        };
        // The full roster comes from the same signed history outcome as the prompt's room revision.
        let mut audience: Vec<_> = page.members.iter().map(|m| m.account).collect();
        audience.sort();
        audience.dedup();
        if audience.len() != page.members.len() || audience.is_empty() {
            return Err(Error::State);
        }
        let inspection: crate::conversations::Inspection = client.read_as(
            Operation::RoomInspect,
            Target::Room(cursor.room),
            &crate::home::Empty {},
            grant,
        )?;
        if inspection.room_revision != page.room_revision
            || inspection.filter_revision != cursor.filter_revision
        {
            return Err(client::Error::Rejected {
                code: ErrorCode::Conflict,
                detail: "ExpectedRevision".into(),
            }
            .into());
        }
        let encrypted = inspection.confidentiality != RoomConfidentiality::Community;
        let crypto = if encrypted {
            let view = client.crypto_inspect(cursor.room, grant)?;
            Some((
                view.remote.group,
                view.remote.epoch,
                view.remote.commit_digest,
                view.remote.history_from_ms,
                view.remote.history_until_ms,
                view.remote
                    .members
                    .iter()
                    .map(|m| m.actor.clone())
                    .collect::<Vec<_>>(),
            ))
        } else {
            None
        };
        let binding = Value::serialized(&(
            "HRC.BotMemoryScope.1",
            cursor.room,
            actor,
            grant,
            client.profile.federation,
            cursor.membership_revision,
            cursor.filter_revision,
            audience,
            &crypto,
        ))
        .map_err(|_| Error::State)?;
        let fingerprint =
            digest(&canonical_encode(&binding, CRYPTO_FRAME_BYTES).map_err(|_| Error::State)?);
        let policy = config.memory.clone().unwrap_or_default();
        let enabled = config.memory.is_some();
        let mut memory = if enabled {
            memory::load(&mut client.store, cursor.room)?
        } else {
            Memory::default()
        };
        if enabled {
            memory.bind(fingerprint, cursor.sequence);
            let entries = page.events.iter().filter_map(|event| {
                entry(
                    event,
                    page.content.get(&event.event),
                    &page.members,
                    own_account,
                )
            });
            memory.ingest(entries, cursor.sequence);
            memory.prune(now.upper_ms, policy.lifetime(encrypted), policy.max_bytes);
        }
        Ok(Self {
            memory,
            guard: SendGuard {
                room_revision: page.room_revision,
                filter_revision: cursor.filter_revision,
            },
            enabled,
            policy,
            encrypted,
            fingerprint,
            head: cursor.sequence,
            own_account,
            operator,
            members: page.members.clone(),
            generated_until_ms: None,
            sampled: now,
        })
    }
    pub(super) fn control_allowed(&self, event: &Event) -> bool {
        matches!(&event.actor, Actor::Direct { acting } if acting.account == self.operator || self.members.iter().any(|m| m.account == acting.account && m.moderator))
    }
    pub(super) fn reset(&mut self) {
        self.memory.reset(self.fingerprint, self.head);
    }
    pub(super) fn generate(
        &mut self,
        config: &Config,
        event: &Event,
        reply: Reply,
        stop: &AtomicBool,
    ) -> Result<Option<String>> {
        match reply {
            Reply::Help => Ok(Some(if self.enabled {
                format!(
                    "{}\nMemory: !memory; !memory show; !forget (operator or moderator).",
                    config.help
                )
            } else {
                config.help.clone()
            })),
            Reply::Memory { show } => {
                if !self.enabled {
                    return Ok(Some("Conversation memory is disabled.".into()));
                }
                if show && !self.control_allowed(event) {
                    return Ok(Some(
                        "Only the bot operator or a room moderator can inspect the summary.".into(),
                    ));
                }
                Ok(Some(self.memory.status(&self.policy, show, self.encrypted)))
            }
            Reply::Forget => {
                if !self.control_allowed(event) {
                    return Ok(Some(
                        "Only the bot operator or a room moderator can clear shared memory.".into(),
                    ));
                }
                self.reset();
                Ok(Some(
                    "Conversation memory cleared. Chat history is unchanged.".into(),
                ))
            }
            Reply::Model(prompt) => {
                let model = config.model.as_ref().ok_or(Error::Configuration)?;
                // Leave room for two bounded model calls; derived context never renews source expiry.
                let now = self.sampled.refresh().map_err(|_| client::Error::Clock)?;
                let lifetime = self.policy.lifetime(self.encrypted);
                self.memory.prune(
                    now.upper_ms.saturating_add(120_000),
                    lifetime,
                    self.policy.max_bytes,
                );
                self.generated_until_ms = self
                    .memory
                    .entries
                    .iter()
                    .map(|e| e.timestamp_ms)
                    .chain(
                        (!self.memory.summary.is_empty()).then_some(self.memory.summary_source_ms),
                    )
                    .min()
                    .map(|source| source.saturating_add(lifetime));
                if self.enabled
                    && let Some(compaction) = self
                        .memory
                        .compaction(model.input_budget_bytes(), event.sequence)
                {
                    match model.generate(&compaction.messages, stop) {
                        Ok(Some(summary)) => {
                            let _ = self.memory.compacted(&compaction, &summary);
                        }
                        Ok(None) => return Ok(None),
                        Err(
                            Error::ModelResponse | Error::ModelTimeout | Error::ModelUnavailable,
                        ) => {}
                        Err(error) => return Err(error),
                    }
                }
                if stop.load(Ordering::Acquire) {
                    return Ok(None);
                }
                let current = Entry {
                    event: event.event,
                    sequence: event.sequence,
                    timestamp_ms: event.timestamp_ms,
                    speaker: speaker(event, &self.members),
                    assistant: event.actor.acting().account == self.own_account,
                    text: prompt,
                };
                model.generate(
                    &self.memory.prompt(&current, model.input_budget_bytes()),
                    stop,
                )
            }
        }
    }
    pub(super) fn prune(&mut self, now: TimeBounds) {
        self.memory.prune(
            now.upper_ms,
            self.policy.lifetime(self.encrypted),
            self.policy.max_bytes,
        );
    }
    pub(super) fn generation_expired(&self, now: TimeBounds) -> bool {
        self.generated_until_ms
            .is_some_and(|until| now.upper_ms >= until)
    }
    pub(super) fn save_in(
        &self,
        db: &rusqlite::Transaction<'_>,
        room: RoomId,
    ) -> rusqlite::Result<()> {
        if self.enabled {
            memory::save_in(db, room, &self.memory)?;
        }
        Ok(())
    }
}
fn speaker(event: &Event, members: &[crate::conversations::Member]) -> String {
    let account = event.actor.represented();
    let name = members
        .iter()
        .find(|m| m.account == account)
        .map_or("Participant", |m| m.nickname.as_str());
    format!(
        "{} [{}]",
        memory::excerpt(&crate::text::identity_display(name), 128),
        &account.local.as_hex()[..12]
    )
}
fn entry(
    event: &Event,
    content: Option<&MessageContent>,
    members: &[crate::conversations::Member],
    own: AccountId,
) -> Option<Entry> {
    if !matches!(
        event.kind,
        Operation::MessageSend | Operation::MessageReply | Operation::MessageAction
    ) {
        return None;
    }
    let text = match content {
        Some(MessageContent::Decrypted(body)) => body.text.clone(),
        Some(_) => return None,
        None => event.body.deserialized::<messaging::Send>().ok()?.text,
    };
    if matches!(text.trim(), "!memory" | "!memory show" | "!forget") {
        return None;
    }
    Some(Entry {
        event: event.event,
        sequence: event.sequence,
        timestamp_ms: event.timestamp_ms,
        speaker: speaker(event, members),
        assistant: event.actor.acting().account == own,
        text,
    })
}

pub(super) fn revision_conflict(outcome: &Outcome) -> bool {
    matches!(outcome, Outcome::Rejected { code: ErrorCode::Conflict, detail } if detail == "ExpectedRevision")
}
pub(super) fn client_conflict(error: &client::Error) -> bool {
    matches!(error, client::Error::Rejected { code: ErrorCode::Conflict, detail } if detail == "ExpectedRevision")
}

#[cfg(test)]
#[path = "../../Tests/Bot/Context.rs"]
mod tests;
