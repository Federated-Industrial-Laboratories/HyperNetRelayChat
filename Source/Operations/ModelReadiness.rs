// SPDX-License-Identifier: Apache-2.0
//! Cancellable cold-start observations describe readiness, never impose a process lifetime.
use super::*;
use std::{
    sync::atomic::Ordering,
    time::{Instant, SystemTime, UNIX_EPOCH},
};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Progress {
    pub phase: String,
    pub configuration: Id,
    pub started_ms: u64,
    pub observed_ms: u64,
    pub attempt: u32,
    pub retry_in_ms: Option<u64>,
    pub current_failure: Option<String>,
    pub last_failure: Option<String>,
    pub last_success_ms: Option<u64>,
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}
fn fingerprint(config: &Config) -> Result<Id> {
    Ok(hrc::protocol::digest(
        &serde_json::to_vec(config).map_err(failure)?,
    ))
}
fn path(id: Id) -> PathBuf {
    definition_path("ModelStatus", id)
}
pub(crate) fn progress(id: Id) -> Result<Option<Progress>> {
    for_config(&load(id)?)
}
pub(super) fn for_config(config: &Config) -> Result<Option<Progress>> {
    let path = path(config.id);
    if !path.try_exists().map_err(failure)? {
        return Ok(None);
    }
    let progress: Progress = read_json(&path)?;
    Ok((progress.configuration == fingerprint(config)?).then_some(progress))
}
fn save(config: &Config, progress: &mut Progress) -> Result<()> {
    progress.observed_ms = now();
    private_json(&path(config.id), progress)
}
fn begin(config: &Config) -> Result<Progress> {
    let previous = for_config(config)?;
    Ok(Progress {
        phase: "checking".into(),
        configuration: fingerprint(config)?,
        started_ms: now(),
        observed_ms: now(),
        attempt: 0,
        retry_in_ms: None,
        current_failure: None,
        last_failure: previous.as_ref().and_then(|p| p.last_failure.clone()),
        last_success_ms: previous.and_then(|p| p.last_success_ms),
    })
}
pub(super) fn stopped(config: &Config) -> Result<()> {
    let mut progress = begin(config)?;
    progress.phase = "stopped".into();
    save(config, &mut progress)
}
pub(super) fn wait(config: &Config, cancel: &AtomicBool) -> Result<()> {
    let model = config.local_model("!model", false);
    let mut state = begin(config)?;
    poll(
        cancel,
        Duration::from_secs(u64::from(config.startup_seconds)),
        |left| {
            model.probe_for(
                cancel,
                left.min(Duration::from_secs(u64::from(config.request_seconds))),
            )
        },
        |phase, attempt, retry, error| {
            state.phase = phase.into();
            state.attempt = attempt;
            state.retry_in_ms = retry;
            state.current_failure = error.map(str::to_owned);
            if let Some(error) = error {
                state.last_failure = Some(error.into());
            }
            if phase == "ready" {
                state.last_success_ms = Some(now());
            }
            save(config, &mut state)
        },
    )
}
fn poll(
    cancel: &AtomicBool,
    timeout: Duration,
    mut probe: impl FnMut(Duration) -> hrc::bot::Result<bool>,
    mut report: impl FnMut(&str, u32, Option<u64>, Option<&str>) -> Result<()>,
) -> Result<()> {
    let deadline = Instant::now() + timeout;
    let mut attempt = 0u32;
    loop {
        if cancel.load(Ordering::Acquire) {
            report("cancelled", attempt, None, None)?;
            return Err("Model readiness check cancelled.".into());
        }
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            report("timedOut", attempt, None, Some("ModelStartupTimeout"))?;
            return Err("Model readiness wait expired. Its process was left running; inspect Status, retry Probe or use Stop.".into());
        }
        attempt += 1;
        report("loadingOrChecking", attempt, None, None)?;
        match probe(remaining) {
            Ok(true) if !cancel.load(Ordering::Acquire) => {
                report("ready", attempt, None, None)?;
                return Ok(());
            }
            Ok(_) => continue,
            Err(error) => {
                let retryable = matches!(
                    error,
                    hrc::bot::Error::ModelUnavailable | hrc::bot::Error::ModelTimeout
                );
                if !retryable {
                    report("failed", attempt, None, Some(error.code()))?;
                    return Err(format!(
                        "Model readiness refused: {}. Check adapter, model name, context and reply settings.",
                        error.code()
                    ));
                }
                let delay = Duration::from_millis((1000u64 << attempt.min(5)).min(30000))
                    .min(deadline.saturating_duration_since(Instant::now()));
                report(
                    "waiting",
                    attempt,
                    Some(delay.as_millis() as u64),
                    Some(error.code()),
                )?;
                let until = Instant::now() + delay;
                while Instant::now() < until && !cancel.load(Ordering::Acquire) {
                    std::thread::sleep(
                        Duration::from_millis(50)
                            .min(until.saturating_duration_since(Instant::now())),
                    );
                }
            }
        }
    }
}
#[cfg(test)]
#[path = "../../Tests/Unit/Operations/ModelReadiness.rs"]
mod tests;
