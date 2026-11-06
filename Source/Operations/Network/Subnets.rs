// SPDX-License-Identifier: Apache-2.0
//! Fresh hosting checks the explicit authority subnets in Core's Podman context.
use super::{Configuration, Error, Requirement, Result, engine};
use hrc::service::files;
use serde::Deserialize;
use std::{fs, net::Ipv4Addr, sync::atomic::AtomicBool, time::Instant};

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Inventory {
    version: u32,
    complete: bool,
    ipv4_subnets: Vec<String>,
}
fn range(cidr: &str) -> Result<(u32, u32)> {
    let (address, prefix) = cidr.split_once('/').ok_or(Error::State)?;
    let address: Ipv4Addr = address.parse().map_err(|_| Error::State)?;
    let prefix: u32 = prefix.parse().map_err(|_| Error::State)?;
    if prefix > 32 || format!("{address}/{prefix}") != cidr {
        return Err(Error::State);
    }
    let mask = if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    };
    let first = u32::from(address);
    if first & mask != first {
        return Err(Error::State);
    }
    Ok((first, first | !mask))
}
fn conflicts(c: &Configuration, bytes: &[u8]) -> Result<Vec<String>> {
    if bytes.len() > 65536 {
        return Err(Error::State);
    }
    let inventory: Inventory = serde_json::from_slice(bytes).map_err(|_| Error::State)?;
    if inventory.version != 1 || !inventory.complete || inventory.ipv4_subnets.len() > 1024 {
        return Err(Error::State);
    }
    let occupied = inventory
        .ipv4_subnets
        .iter()
        .map(|cidr| range(cidr))
        .collect::<Result<Vec<_>>>()?;
    let mut conflicts = Vec::new();
    // Services use native automatic allocation. Only the four authority /24s
    // are requested explicitly from this setting.
    for n in 0..4 {
        let octet = c.subnet_octet.checked_add(n).ok_or(Error::State)?;
        let cidr = format!("10.89.{octet}.0/24");
        let (first, last) = range(&cidr)?;
        if occupied
            .iter()
            .any(|(start, end)| first <= *end && *start <= last)
        {
            conflicts.push(cidr);
        }
    }
    Ok(conflicts)
}
fn resuming(c: &Configuration) -> Result<bool> {
    let path = c.root.join("Hosting.json");
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(_) => return Err(Error::State),
        Ok(_) => {}
    }
    files::directory(&c.root, false).map_err(|_| Error::State)?;
    let journal: engine::Journal =
        serde_json::from_value(engine::read(&path)?).map_err(|_| Error::State)?;
    if journal.format != "HrcHosting/1" || journal.configuration_digest != engine::config_digest(c)?
    {
        return Err(Error::State);
    }
    Ok(true)
}
pub(super) fn requirement(
    c: &Configuration,
    cancel: &AtomicBool,
    end: Instant,
) -> Result<Requirement> {
    if resuming(c)? {
        return Ok(Requirement {
            component: "Existing hosting configuration".into(),
            ready: true,
            action: "Resume the exact saved configuration. Native runtime checks retained reservations and every remaining allocation; free subnets are not inferred.".into(),
        });
    }
    let result = engine::raw(
        &c.core,
        &engine::bytes(&["runtime", "network-preview"]),
        cancel,
        end,
        "Subnet inspection",
    );
    engine::check(cancel, end)?;
    let (ready, action) = match result {
        Ok(bytes) => match conflicts(c, &bytes) {
            Ok(conflicts) if conflicts.is_empty() => (true, "The four requested authority subnets have no observed overlap. Native allocation still checks for later conflicts.".into()),
            Ok(conflicts) => (false, format!("Choose a different first authority subnet. Occupied requested ranges: {}. Existing networks were preserved.", conflicts.join(", "))),
            Err(_) => (false, "Core returned an incomplete or invalid subnet inventory. Check the supported Core installation and rootless Podman before creating this host.".into()),
        },
        Err(error) => (false, format!("Core could not inspect rootless Podman subnets. Correct the native error and preview again. {error}")),
    };
    Ok(Requirement {
        component: "Authority subnets".into(),
        ready,
        action,
    })
}

#[cfg(test)]
#[path = "../../../Tests/Unit/Operations/Network/Subnets.rs"]
mod tests;
