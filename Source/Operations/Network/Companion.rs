// SPDX-License-Identifier: Apache-2.0
//! Explicit stopped target replacement for the pinned Suite companion layout.
use super::{Error, Result, engine::digest};
use hrc::service::files;
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{FileTypeExt, MetadataExt, OpenOptionsExt},
            net::UnixStream,
        },
    },
    path::Path,
};

const MAXIMUM_ENDPOINT: usize = 600_000;

pub(super) fn replace_target(
    companion: &Path,
    profile: &Path,
    service: &str,
    network: &str,
    incarnation: &str,
    source: &Path,
) -> Result<()> {
    files::directory(companion, false).map_err(|_| Error::State)?;
    let routes = companion.join("Routes");
    files::directory(&routes, false).map_err(|_| Error::State)?;
    // Suite hashes the logical lock name. Retain this inode and every requester record.
    let lock = OpenOptions::new()
        .read(true)
        .write(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(companion.join(format!("Network{}.lock", digest(b"Agent.lock"))))
        .map_err(|_| Error::State)?;
    let metadata = lock.metadata().map_err(|_| Error::State)?;
    if !metadata.is_file()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o7777 != 0o600
        || metadata.nlink() != 1
    {
        return Err(Error::State);
    }
    if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(Error::Busy);
    }
    let socket = companion.join("Control.sock");
    match fs::symlink_metadata(&socket) {
        Ok(metadata) => {
            if !metadata.file_type().is_socket() || metadata.uid() != unsafe { libc::geteuid() } {
                return Err(Error::State);
            }
            match UnixStream::connect(&socket) {
                Ok(_) => return Err(Error::Busy),
                Err(error)
                    if matches!(
                        error.raw_os_error(),
                        Some(libc::ECONNREFUSED | libc::ENOENT)
                    ) => {}
                Err(_) => return Err(Error::State),
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(Error::State),
    }
    let bytes = files::read(source, MAXIMUM_ENDPOINT).map_err(|_| Error::State)?;
    let mut replacement: Value = serde_json::from_slice(&bytes).map_err(|_| Error::State)?;
    let identity = |value: &str| -> Result<Value> {
        let bytes = hex::decode(value).map_err(|_| Error::State)?;
        if bytes.len() != 32 {
            return Err(Error::State);
        }
        Ok(json!(bytes))
    };
    if replacement["format"] != "HyperNetRelayEndpoint/1"
        || replacement["profile"] != json!(profile)
        || profile.canonicalize().map_err(|_| Error::State)? != profile
        || replacement["route"]["network"] != identity(network)?
        || replacement["route"]["incarnation"] != identity(incarnation)?
        || replacement["route"]["destination"]["service"] != identity(service)?
        || replacement["route"]["protocol"] != 7
    {
        return Err(Error::State);
    }
    let destination = routes.join(format!("{service}.json"));
    let mut current: Value = serde_json::from_slice(
        &files::read(&destination, MAXIMUM_ENDPOINT).map_err(|_| Error::State)?,
    )
    .map_err(|_| Error::State)?;
    for endpoint in [&mut current, &mut replacement] {
        let route = endpoint
            .get_mut("route")
            .and_then(Value::as_object_mut)
            .ok_or(Error::State)?;
        let voucher = route.remove("voucher").ok_or(Error::State)?;
        if voucher.as_array().is_none_or(|v| v.is_empty()) {
            return Err(Error::State);
        }
    }
    if current != replacement {
        return Err(Error::State);
    }
    // Suite revalidates the full endpoint and current authority before forwarding.
    let temporary = routes.join(format!(
        ".renew-{}",
        hrc::protocol::Id::random()
            .map_err(|_| Error::State)?
            .as_hex()
    ));
    files::create(&temporary, &bytes).map_err(|_| Error::State)?;
    let result =
        fs::rename(&temporary, &destination).and_then(|_| fs::File::open(&routes)?.sync_all());
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(|_| Error::State)
}

#[cfg(test)]
#[path = "../../../Tests/Unit/Operations/Network/Companion.rs"]
mod tests;
