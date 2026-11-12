// SPDX-License-Identifier: Apache-2.0
//! Persistent service bots share the authenticated client and exact outbox.
#[path = "Context.rs"]
mod context;
#[path = "Memory.rs"]
mod memory;
#[path = "Model.rs"]
mod model;
#[path = "Runtime.rs"]
mod runtime;
#[path = "State.rs"]
mod state;
#[path = "Status.rs"]
mod status;
use crate::{client, protocol::*, storage};
pub use memory::Policy as MemoryPolicy;
pub use model::{Adapter, LocalModel, default_reply_characters, default_request_seconds};
pub use status::{Failure, Observation, Phase};
use std::{
    path::PathBuf,
    sync::{Arc, atomic::AtomicBool},
};

#[derive(Clone, Debug)]
pub struct Config {
    pub profile: PathBuf,
    pub rooms: Vec<RoomId>,
    pub help: String,
    pub poll_interval_ms: u64,
    /// An explicitly selected grant; None participates as the independent agent account.
    pub grant: Option<Id>,
    /// Explicitly abandon a stale resume position and catch up without historical triggers.
    pub resynchronise: bool,
    /// Explicit opt-in to inference on this host; None retains deterministic help only.
    pub model: Option<LocalModel>,
    /// Derived context is scoped to the current room audience and authority.
    pub memory: Option<MemoryPolicy>,
}
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid bounded bot configuration")]
    Configuration,
    #[error("the bot requires an authenticated agent endpoint and operator binding")]
    AgentRequired,
    #[error("bot state or exact outbox is unavailable")]
    State,
    #[error("bot {operation} failed: {source}")]
    Storage {
        operation: &'static str,
        source: storage::Error,
    },
    #[error("bot state validation failed: {0}")]
    InvalidState(&'static str),
    #[error("the selected bot grant is unavailable or requires message approval")]
    Grant,
    #[error("the retained cursor requires explicit resynchronisation")]
    ResynchronisationRequired,
    #[error("a prior planned reply needs its original outcome resolved")]
    PendingOutcome,
    #[error("current service permission refused the bot operation")]
    Denied,
    #[error("the service requested bounded backoff")]
    RetryLater { delay_ms: u64 },
    #[error("the local model request failed")]
    ModelUnavailable,
    #[error("the local model exceeded its inference deadline")]
    ModelTimeout,
    #[error("the local model returned invalid or excessive output")]
    ModelResponse,
    #[error("the local model exhausted its reply token allowance")]
    ModelIncomplete,
    #[error("the local model reply exceeded the configured message length")]
    ModelReplyLimit,
    #[error("the prompt does not fit the selected model context")]
    ModelContext,
    #[error(transparent)]
    Client(#[from] client::Error),
}
pub type Result<T> = std::result::Result<T, Error>;
impl Config {
    pub fn validate(&self) -> Result<()> {
        if !self.profile.is_absolute()
            || self.rooms.is_empty()
            || self.rooms.len() > 8
            || !(1000..=60000).contains(&self.poll_interval_ms)
            || self
                .poll_interval_ms
                .saturating_mul(self.rooms.len() as u64)
                > 120000
            || self.help.len() > 1024
            || crate::text::message(&self.help).is_err()
        {
            return Err(Error::Configuration);
        }
        let mut rooms = self.rooms.clone();
        rooms.sort();
        rooms.dedup();
        if rooms.len() != self.rooms.len() {
            return Err(Error::Configuration);
        }
        if let Some(model) = &self.model {
            model.validate()?;
            if self.rooms.len() != 1 {
                return Err(Error::Configuration);
            }
        }
        if let Some(memory) = &self.memory {
            memory.validate()?;
            if self.model.is_none() {
                return Err(Error::Configuration);
            }
        }
        Ok(())
    }
}
pub fn run(config: Config, stop: Arc<AtomicBool>) -> Result<()> {
    run_observed(config, stop, || {})
}
/// Emit one historical initialization event after authenticated catch-up and startup resolution.
/// The callback does not assert continuing connectivity after the instant it runs.
pub fn run_observed(config: Config, stop: Arc<AtomicBool>, on_ready: impl FnOnce()) -> Result<()> {
    run_reporting(config, stop, on_ready, |_| {})
}

#[cfg(test)]
#[path = "../../Tests/Bot/Workflow.rs"]
mod tests;

/// Structured observations contain fixed diagnostic codes and timestamps, never chat or keys.
pub fn run_reporting(
    config: Config,
    stop: Arc<AtomicBool>,
    on_ready: impl FnOnce(),
    mut observer: impl FnMut(&Observation),
) -> Result<()> {
    config.validate()?;
    runtime::run(config, stop, on_ready, &mut observer)
}
impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Configuration => "InvalidBotConfiguration",
            Self::AgentRequired => "BotAgentRequired",
            Self::State => "BotStateUnavailable",
            Self::InvalidState(code) => code,
            Self::Storage { source, .. } => source.code(),
            Self::Grant => "BotGrantUnavailable",
            Self::ResynchronisationRequired => "BotResynchronisationRequired",
            Self::PendingOutcome => "BotOutcomeUnknown",
            Self::Denied => "BotPermissionDenied",
            Self::RetryLater { .. } => "BotTemporarilyUnavailable",
            Self::ModelUnavailable => "BotModelUnavailable",
            Self::ModelTimeout => "BotModelTimeout",
            Self::ModelResponse => "BotModelInvalidResponse",
            Self::ModelIncomplete => "BotModelReplyTokensExhausted",
            Self::ModelReplyLimit => "BotModelReplyTooLong",
            Self::ModelContext => "BotModelContextTooSmall",
            Self::Client(error) => error.code(),
        }
    }
}
