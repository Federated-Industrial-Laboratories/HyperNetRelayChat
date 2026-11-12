// SPDX-License-Identifier: Apache-2.0
//! Observed bot state separates current work from historical failures without storing chat data.
use super::Error;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Phase {
    Starting,
    Connecting,
    CatchingUp,
    Ready,
    Generating,
    Retrying,
    Stopped,
    Failed,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Failure {
    pub code: String,
    pub operation: Option<String>,
    pub observed_ms: u64,
}
impl Failure {
    pub fn guidance(&self) -> &'static str {
        match self.code.as_str() {
            "StorageQuota" => {
                "Check free disk space and the profile storage quota. Keep the original outbox and continuity files."
            }
            "OutcomeUnknown" | "BotOutcomeUnknown" => {
                "Resolve the original pending operation before changing or resetting the profile."
            }
            "ContinuityLost" => {
                "Stop and inspect the profile's continuity files. Do not delete them to force a restart."
            }
            "ProfileInUse" => {
                "Close the other GUI, CLI or bot process using this profile, then retry."
            }
            "BotModelReplyTokensExhausted" => {
                "Increase Reply tokens within the model context or request a shorter answer."
            }
            "BotModelReplyTooLong" => {
                "Adjust Reply characters within the chat message limit or request a shorter answer."
            }
            "BotModelContextTooSmall" => {
                "Increase Context tokens in both model settings and the backend, or shorten the request."
            }
            "BotModelTimeout" => {
                "Check model readiness and the Reply deadline. The complete attempt must fit its history certificate."
            }
            "BotModelUnavailable" => "Check the local model process and use Probe in Local models.",
            "ClockUnavailable" => {
                "Waiting for a fresh authenticated clock observation; reconnection uses bounded backoff."
            }
            "BotResynchronisationRequired" => {
                "Resolve pending outcomes, then explicitly select Resynchronise on next start."
            }
            _ => {
                "Inspect the diagnostic code, current permissions and retained state before retrying."
            }
        }
    }
    fn new(error: &Error, now: u64) -> Self {
        Self {
            code: error.code().into(),
            operation: match error {
                Error::Storage { operation, .. } => Some((*operation).into()),
                _ => None,
            },
            observed_ms: now,
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Observation {
    pub phase: Phase,
    pub observed_ms: u64,
    pub last_success_ms: Option<u64>,
    pub last_model_success_ms: Option<u64>,
    pub initial_connection_verified: bool,
    pub model_failure: Option<Failure>,
    pub current_failure: Option<Failure>,
    pub last_failure: Option<Failure>,
    pub retry_in_ms: Option<u64>,
}
pub(super) struct Reporter<'a> {
    pub observation: Observation,
    emit: &'a mut dyn FnMut(&Observation),
    emitted: Instant,
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX)
}
impl<'a> Reporter<'a> {
    pub fn new(emit: &'a mut dyn FnMut(&Observation)) -> Self {
        let observation = Observation {
            phase: Phase::Starting,
            observed_ms: now(),
            last_success_ms: None,
            last_model_success_ms: None,
            initial_connection_verified: false,
            model_failure: None,
            current_failure: None,
            last_failure: None,
            retry_in_ms: None,
        };
        emit(&observation);
        Self {
            observation,
            emit,
            emitted: Instant::now(),
        }
    }
    fn publish(&mut self, changed: bool) {
        if changed || self.emitted.elapsed() >= Duration::from_secs(30) {
            self.observation.observed_ms = now();
            (self.emit)(&self.observation);
            self.emitted = Instant::now();
        }
    }
    pub fn phase(&mut self, phase: Phase) {
        let changed = self.observation.phase != phase || self.observation.current_failure.is_some();
        self.observation.phase = phase;
        self.observation.current_failure = None;
        self.observation.retry_in_ms = None;
        self.publish(changed);
    }
    pub fn success(&mut self, ready: bool) {
        self.observation.last_success_ms = Some(now());
        self.observation.initial_connection_verified |= ready;
        self.phase(if ready {
            Phase::Ready
        } else {
            Phase::CatchingUp
        });
    }
    pub fn model(&mut self, result: &super::Result<Option<String>>) {
        match result {
            Ok(Some(_)) => {
                self.observation.last_model_success_ms = Some(now());
                self.observation.model_failure = None;
                self.phase(Phase::CatchingUp);
            }
            Err(error) => {
                self.observation.model_failure = Some(Failure::new(error, now()));
                self.failure(error, Phase::CatchingUp, None);
            }
            _ => (),
        }
    }
    pub fn failure(&mut self, error: &Error, phase: Phase, retry: Option<u64>) {
        let failure = Failure::new(error, now());
        let changed = self.observation.phase != phase
            || self
                .observation
                .current_failure
                .as_ref()
                .is_none_or(|f| f.code != failure.code || f.operation != failure.operation);
        self.observation.phase = phase;
        self.observation.current_failure = Some(failure.clone());
        self.observation.last_failure = Some(failure);
        self.observation.retry_in_ms = retry;
        self.publish(changed);
    }
}
#[cfg(test)]
#[path = "../../Tests/Bot/Status.rs"]
mod tests;

impl Phase {
    pub fn label(self) -> &'static str {
        match self {
            Self::Starting => "Starting",
            Self::Connecting => "Connecting",
            Self::CatchingUp => "Catching up",
            Self::Ready => "Connected",
            Self::Generating => "Generating a reply",
            Self::Retrying => "Waiting to retry",
            Self::Stopped => "Stopped",
            Self::Failed => "Stopped after a failure",
        }
    }
}
