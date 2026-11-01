// SPDX-License-Identifier: Apache-2.0
//! A persistent deterministic help bot shares the authenticated client and exact outbox.
#[path = "Runtime.rs"]
mod runtime;
#[path = "State.rs"]
mod state;
use crate::{client, protocol::*};
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
}
#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid bounded bot configuration")]
    Configuration,
    #[error("the bot requires an authenticated agent endpoint and operator binding")]
    AgentRequired,
    #[error("bot state or exact outbox is unavailable")]
    State,
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
    #[error(transparent)]
    Client(#[from] client::Error),
}
pub type Result<T> = std::result::Result<T, Error>;
impl Config {
    fn validate(&self) -> Result<()> {
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
        Ok(())
    }
}
pub fn run(config: Config, stop: Arc<AtomicBool>) -> Result<()> {
    run_observed(config, stop, || {})
}
/// Emit one historical initialization event after authenticated catch-up and startup resolution.
/// The callback does not assert continuing connectivity after the instant it runs.
pub fn run_observed(config: Config, stop: Arc<AtomicBool>, on_ready: impl FnOnce()) -> Result<()> {
    config.validate()?;
    runtime::run(config, stop, on_ready)
}

#[cfg(test)]
#[path = "../../Tests/Bot/Workflow.rs"]
mod tests;
