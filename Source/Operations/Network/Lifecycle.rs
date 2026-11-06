// SPDX-License-Identifier: Apache-2.0
//! Owned lifecycle controls and explicitly reviewed native stopped successors.
use super::{Configuration, Error, Result, Status, engine::*, services};
use serde_json::json;
use std::{
    path::Path,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

pub(super) fn unit_active(host: &Host<'_>, purpose: &str) -> bool {
    raw(
        Path::new("/usr/bin/systemctl"),
        &bytes(&["--user", "is-active", &host.unit_name(purpose)]),
        host.cancel,
        host.end,
        "service observation",
    )
    .is_ok_and(|v| v == b"active\n")
}
pub(super) fn start_hrc(host: &Host<'_>) -> Result<()> {
    host.unit(
        "hrc",
        &std::env::current_exe().map_err(|_| Error::State)?,
        &bytes(&[
            "service",
            "run",
            "--directory",
            &text(&host.c.service_directory())?,
        ]),
    )
}
pub(super) fn start_host(host: &mut Host<'_>) -> Result<()> {
    start_hrc(host)?;
    host.wait(
        || {
            let v = host.hrc(&bytes(&[
                "profile",
                "session",
                "--profile",
                &text(&host.c.hrc_profile())?,
            ]))?;
            if v["status"] == "Authenticated" {
                Ok(())
            } else {
                Err(Error::NotReady)
            }
        },
        30,
    )?;
    if host.remembered("nickname").is_none() {
        let v = host.hrc(&bytes(&[
            "profile",
            "nickname",
            "--profile",
            &text(&host.c.hrc_profile())?,
            "--nickname",
            &host.c.nickname,
        ]))?;
        host.remember("nickname", v)?;
    }
    if host.remembered("first-room").is_none() {
        // HRC persists its exact uncertain operation before retry; never replace a requester journal.
        let v = host.hrc(&bytes(&[
            "room",
            "create",
            "--profile",
            &text(&host.c.hrc_profile())?,
            "--name",
            "general",
        ]))?;
        host.remember("first-room", v)?;
    }
    Ok(())
}
pub(super) fn observe(host: &mut Host<'_>) -> Result<Status> {
    let mut units = Vec::new();
    for n in 1..=4 {
        let name = format!("A{n}");
        let value = host.core(&bytes(&[
            "runtime",
            "status",
            "--directory",
            &text(&host.p(&name))?,
        ]));
        units.push(json!({"role":name,"unit":host.unit_name(&name.to_ascii_lowercase()),"observation":value.unwrap_or_else(|_|json!({"state":"Unavailable"}))}));
    }
    for (name, _, _, _) in services::roles() {
        let value = host.core(&bytes(&[
            "runtime",
            "services",
            "status",
            "--directory",
            &text(&host.p(name))?,
        ]));
        units.push(json!({"role":name,"unit":host.unit_name(&name.to_ascii_lowercase()),"observation":value.unwrap_or_else(|_|json!({"state":"Unavailable"}))}));
    }
    let quorum_verified = services::authority_context(host).is_ok();
    let authenticated = if host.c.hrc_profile().exists() && unit_active(host, "hrc") {
        host.hrc(&bytes(&[
            "profile",
            "session",
            "--profile",
            &text(&host.c.hrc_profile())?,
        ]))
        .is_ok_and(|v| v["status"] == "Authenticated")
    } else {
        false
    };
    let bootstrap = host.bootstrap().ok();
    let stopped = [
        "hrc",
        "client",
        "receiver",
        "relay",
        "authorityendpoint",
        "applicationendpoint",
        "a1",
        "a2",
        "a3",
        "a4",
    ]
    .iter()
    .all(|name| !unit_active(host, name))
        && units.iter().all(|v| {
            v["observation"]["running"] == false
                && (v["role"]
                    .as_str()
                    .is_some_and(|v| v.len() == 2 && v.starts_with('A'))
                    || v["observation"]["cleanupComplete"] == true)
        });
    let effective_expiry = host
        .state
        .results
        .get("client-expires-ms")
        .and_then(serde_json::Value::as_u64)
        .unwrap_or(host.state.expires_ms)
        .min(host.state.expires_ms);
    Ok(Status {
        state: if authenticated && quorum_verified {
            "Ready"
        } else if stopped {
            "Stopped"
        } else if now()? >= effective_expiry {
            "Expired"
        } else {
            "NotReady"
        }
        .into(),
        phase: host.state.phase.clone(),
        network: bootstrap
            .as_ref()
            .and_then(|v| v["network"].as_str())
            .map(str::to_owned),
        incarnation: bootstrap
            .as_ref()
            .and_then(|v| v["incarnation"].as_str())
            .map(str::to_owned),
        expires_ms: Some(effective_expiry),
        quorum_verified,
        client_authenticated: authenticated,
        profile: host.c.hrc_profile(),
        service_directory: host.c.service_directory(),
        units,
    })
}
pub fn status(c: &Configuration, cancel: &AtomicBool) -> Result<Status> {
    let mut host = Host::open(c, cancel, None)?;
    host.end = Instant::now() + Duration::from_secs(45);
    observe(&mut host)
}
pub fn start(c: &Configuration, cancel: &AtomicBool) -> Result<Status> {
    let mut host = Host::open(c, cancel, None)?;
    if !host.state.completed {
        return Err(Error::Configuration(
            "resume setup with its reviewed preview",
        ));
    }
    if now()? >= host.state.expires_ms {
        return Err(Error::RenewalRequired);
    }
    super::bootstrap::clock(&mut host)?;
    super::bootstrap::activate(&mut host)?;
    services::activate(&mut host)?;
    super::clients::start_client(&host)?;
    start_host(&mut host)?;
    host.phase("Ready")?;
    let status = observe(&mut host)?;
    if !status.client_authenticated || !status.quorum_verified {
        return Err(Error::NotReady);
    }
    Ok(status)
}
pub fn stop(c: &Configuration, cancel: &AtomicBool) -> Result<Status> {
    let mut host = Host::open(c, cancel, None)?;
    stop_host(&mut host)?;
    observe(&mut host)
}
fn stop_host(host: &mut Host<'_>) -> Result<()> {
    host.phase("Stopping")?;
    for purpose in ["hrc", "client"] {
        if unit_active(host, purpose) {
            host.stop_unit(purpose)?;
        }
    }
    for (name, _, _, _) in services::roles().into_iter().rev() {
        let directory = host.p(name);
        if directory.exists() {
            host.core(&bytes(&[
                "runtime",
                "services",
                "stop",
                "--directory",
                &text(&directory)?,
            ]))?;
            let observed = host.core(&bytes(&[
                "runtime",
                "services",
                "status",
                "--directory",
                &text(&directory)?,
            ]))?;
            if observed["running"] != false || observed["cleanupComplete"] != true {
                return Err(Error::NotReady);
            }
        }
        let purpose = name.to_ascii_lowercase();
        if unit_active(host, &purpose) {
            host.stop_unit(&purpose)?;
        }
    }
    if unit_active(host, "receiver") {
        host.stop_unit("receiver")?;
    }
    for n in (1..=4).rev() {
        let folder = host.p(&format!("A{n}"));
        if folder.exists() {
            let current = host.core(&bytes(&[
                "runtime",
                "status",
                "--directory",
                &text(&folder)?,
            ]))?;
            if current["running"] == true {
                let preview = host.core(&bytes(&[
                    "runtime",
                    "preview",
                    "--directory",
                    &text(&folder)?,
                ]))?;
                let op = host.id(&format!("stop/A{n}/{}", number(&current, "generation")?))?;
                host.core(&bytes(&[
                    "runtime",
                    "stop",
                    "--directory",
                    &text(&folder)?,
                    "--operation-id",
                    &op[..32],
                    "--expected-generation",
                    &number(&current, "generation")?.to_string(),
                    "--profile-digest",
                    &string(&preview, "profileDigest")?,
                ]))?;
            }
        }
        let purpose = format!("a{n}");
        if unit_active(host, &purpose) {
            host.stop_unit(&purpose)?;
        }
    }
    if unit_active(host, "clock") {
        host.stop_unit("clock")?;
    }
    host.phase("Stopped")
}
