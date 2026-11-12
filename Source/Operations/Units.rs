// SPDX-License-Identifier: Apache-2.0
//! Fixed per-user unit controls never execute a shell or stop an unrelated service.
use super::{Result, failure, native};
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeMap,
    path::Path,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub(crate) enum Security {
    #[default]
    Standard,
    Restricted,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub(crate) struct Limits {
    pub memory_mib: u32,
    pub cpu_percent: u16,
    pub security: Security,
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            memory_mib: 512,
            cpu_percent: 200,
            security: Security::Standard,
        }
    }
}
impl Limits {
    pub fn validate(&self) -> Result<()> {
        if !(128..=131_072).contains(&self.memory_mib) || !(10..=6400).contains(&self.cpu_percent) {
            return Err(
                "Choose a memory limit from 128 MiB to 128 GiB and a CPU limit from 10% to 6400%."
                    .into(),
            );
        }
        Ok(())
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct Status {
    pub active: bool,
    pub state: String,
    pub pid: u32,
    pub exit_code: i32,
    pub initial_connection_verified: bool,
    pub bot_observation: Option<hrc::bot::Observation>,
    /// False for stopped processes and observations older than one bounded reply attempt.
    pub bot_observation_current: bool,
}
pub(crate) fn name(kind: &str, id: hrc::protocol::Id) -> String {
    format!("hrc-managed-{kind}-{}", id.as_hex())
}
fn unit(name: &str) -> Result<()> {
    if !name.starts_with("hrc-managed-")
        || name.len() > 96
        || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    {
        return Err("Invalid managed service identity.".into());
    }
    Ok(())
}
pub(crate) fn status(name: &str, cancel: &AtomicBool) -> Result<Status> {
    unit(name)?;
    let args = native::strings(&[
        "--user",
        "show",
        "--no-pager",
        "--property=LoadState,ActiveState,SubState,MainPID,ExecMainStatus,InvocationID",
        name,
    ]);
    let output = native::run(
        Path::new("/usr/bin/systemctl"),
        &args,
        cancel,
        Instant::now() + Duration::from_secs(10),
    )
    .map_err(failure)?;
    let text = std::str::from_utf8(&output).map_err(failure)?;
    let fields: BTreeMap<_, _> = text
        .lines()
        .filter_map(|line| line.split_once('='))
        .collect();
    let active = fields.get("ActiveState") == Some(&"active");
    let invocation = fields.get("InvocationID").copied().unwrap_or("");
    let mut result = Status {
        active,
        state: fields
            .get("ActiveState")
            .unwrap_or(&"unavailable")
            .to_string(),
        pid: fields
            .get("MainPID")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        exit_code: fields
            .get("ExecMainStatus")
            .and_then(|v| v.parse().ok())
            .unwrap_or(0),
        initial_connection_verified: false,
        bot_observation: None,
        bot_observation_current: false,
    };
    if fields.get("LoadState") == Some(&"not-found") {
        result.state = "stopped".into();
    }
    {
        let current_invocation =
            invocation.len() == 32 && invocation.bytes().all(|b| b.is_ascii_hexdigit());
        let selector = if current_invocation {
            format!("_SYSTEMD_INVOCATION_ID={invocation}")
        } else {
            format!("_SYSTEMD_USER_UNIT={name}.service")
        };
        let logs = native::run(
            Path::new("/usr/bin/journalctl"),
            &native::strings(&[
                "--user",
                "--no-pager",
                "--output=cat",
                "--lines=16",
                &selector,
            ]),
            cancel,
            Instant::now() + Duration::from_secs(5),
        );
        if let Ok(logs) = logs {
            result.bot_observation = observation(&logs);
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64;
            result.bot_observation_current = active
                && current_invocation
                && result.bot_observation.as_ref().is_some_and(|v| {
                    v.observed_ms <= now
                        && now.saturating_sub(v.observed_ms) <= 300_000
                        && !matches!(v.phase, hrc::bot::Phase::Failed | hrc::bot::Phase::Stopped)
                });
            result.initial_connection_verified = result
                .bot_observation
                .as_ref()
                .is_some_and(|v| v.initial_connection_verified)
                || String::from_utf8_lossy(&logs).lines().any(|line| {
                    serde_json::from_str::<serde_json::Value>(line)
                        .is_ok_and(|v| v["status"] == "BotReady")
                });
        }
    }
    Ok(result)
}
pub(crate) fn start(
    name: &str,
    program: &Path,
    args: &[String],
    environment: &[(String, String)],
    limits: &Limits,
    cancel: &AtomicBool,
) -> Result<Status> {
    unit(name)?;
    limits.validate()?;
    native::executable(program).map_err(failure)?;
    let old = status(name, cancel)?;
    if old.active {
        return Ok(old);
    }
    if old.pid != 0
        || matches!(
            old.state.as_str(),
            "activating" | "reloading" | "deactivating"
        )
    {
        return Err(
            "The managed process is changing state. Refresh its status before starting it.".into(),
        );
    }
    if old.state == "failed" {
        native::run(
            Path::new("/usr/bin/systemctl"),
            &native::strings(&["--user", "reset-failed", name]),
            cancel,
            Instant::now() + Duration::from_secs(10),
        )
        .map_err(failure)?;
    }
    let mut command = native::strings(&[
        "--user",
        "--collect",
        "--quiet",
        &format!("--unit={name}"),
        "--property=Type=exec",
        "--property=UMask=0077",
        "--property=NoNewPrivileges=yes",
        "--property=TasksMax=256",
        "--property=LogRateLimitIntervalSec=30s",
        "--property=LogRateLimitBurst=30",
        &format!("--property=MemoryMax={}M", limits.memory_mib),
        &format!("--property=CPUQuota={}%", limits.cpu_percent),
    ]);
    if limits.security == Security::Restricted {
        command.extend(native::strings(&[
            "--property=ProtectSystem=full",
            "--property=PrivateTmp=yes",
            "--property=ProtectKernelTunables=yes",
            "--property=ProtectKernelModules=yes",
            "--property=ProtectControlGroups=yes",
            "--property=LockPersonality=yes",
            "--property=RestrictSUIDSGID=yes",
        ]));
    }
    for (key, value) in environment {
        if !matches!(
            key.as_str(),
            "CUDA_VISIBLE_DEVICES"
                | "LD_LIBRARY_PATH"
                | "OLLAMA_NO_CLOUD"
                | "OLLAMA_HOST"
                | "OLLAMA_MODELS"
                | "OLLAMA_NUM_PARALLEL"
        ) || value.chars().any(char::is_control)
        {
            return Err("Invalid local runtime environment.".into());
        }
        command.push(format!("--setenv={key}={value}"));
    }
    command.push("--".into());
    command.push(native::path(program).map_err(failure)?);
    command.extend_from_slice(args);
    native::run(
        Path::new("/usr/bin/systemd-run"),
        &command,
        cancel,
        Instant::now() + Duration::from_secs(20),
    )
    .map_err(failure)?;
    status(name, cancel)
}
pub(crate) fn stop(name: &str, cancel: &AtomicBool) -> Result<Status> {
    unit(name)?;
    let old = status(name, cancel)?;
    if old.active || old.state == "activating" {
        native::run(
            Path::new("/usr/bin/systemctl"),
            &native::strings(&["--user", "stop", name]),
            cancel,
            Instant::now() + Duration::from_secs(20),
        )
        .map_err(failure)?;
    }
    status(name, cancel)
}

#[cfg(test)]
#[path = "../../Tests/Unit/Operations/Units.rs"]
mod tests;

fn observation(logs: &[u8]) -> Option<hrc::bot::Observation> {
    String::from_utf8_lossy(logs)
        .lines()
        .filter_map(|line| {
            let value: serde_json::Value = serde_json::from_str(line).ok()?;
            if value["status"] != "BotStatus" {
                return None;
            }
            serde_json::from_value(value["observation"].clone()).ok()
        })
        .next_back()
}
