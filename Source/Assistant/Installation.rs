// SPDX-License-Identifier: Apache-2.0
//! Ownership-preserving file installation, following the FICC harness contract.
use super::{Provider, Scope, assets};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path, PathBuf},
};

const MAX_FILE: u64 = 1024 * 1024;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema: u32,
    provider: Provider,
    scope: Scope,
    // Two hashes allow recovery after a process stops between receipt and file publication.
    files: BTreeMap<String, Vec<String>>,
}

struct Change {
    path: String,
    action: &'static str,
    before: Option<String>,
    after: Option<Vec<u8>>,
}

fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn root(path: &Path) -> Result<(), &'static str> {
    if path
        .to_str()
        .is_none_or(|text| text.chars().any(char::is_control))
    {
        return Err("AssistantUnsupportedDestination");
    }
    if !path.is_absolute() || path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err("AssistantAbsoluteDestinationRequired");
    }
    let mut cursor = PathBuf::new();
    for part in path.components() {
        cursor.push(part);
        match fs::symlink_metadata(&cursor) {
            Ok(metadata) if !metadata.is_dir() => return Err("AssistantUnsafeDestination"),
            Ok(_) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err("AssistantDestinationUnavailable"),
        }
    }
    Ok(())
}

fn member(directory: &Path, relative: &str) -> Result<PathBuf, &'static str> {
    root(directory)?;
    if relative.is_empty()
        || relative.contains(['\\', '\0'])
        || relative
            .split('/')
            .any(|part| part.is_empty() || part == ".")
        || Path::new(relative)
            .components()
            .any(|c| !matches!(c, Component::Normal(_)))
    {
        return Err("AssistantUnsafePath");
    }
    let mut path = directory.to_path_buf();
    let parts: Vec<_> = Path::new(relative).components().collect();
    for (index, part) in parts.iter().enumerate() {
        path.push(part);
        match fs::symlink_metadata(&path) {
            Ok(metadata)
                if metadata.file_type().is_symlink()
                    || (index + 1 < parts.len() && !metadata.is_dir()) =>
            {
                return Err("AssistantUnsafeDestination");
            }
            Ok(_) => (),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => (),
            Err(_) => return Err("AssistantDestinationUnavailable"),
        }
    }
    Ok(path)
}

fn read(path: &Path) -> Result<Option<Vec<u8>>, &'static str> {
    let file = match OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
    {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err("AssistantFileUnavailable"),
    };
    let metadata = file.metadata().map_err(|_| "AssistantFileUnavailable")?;
    if !metadata.is_file() || metadata.nlink() != 1 || metadata.size() > MAX_FILE {
        return Err("AssistantUnsafeFile");
    }
    let mut bytes = Vec::new();
    file.take(MAX_FILE + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "AssistantFileUnavailable")?;
    if bytes.len() as u64 > MAX_FILE {
        return Err("AssistantUnsafeFile");
    }
    Ok(Some(bytes))
}

fn current(directory: &Path, path: &str) -> Result<Option<String>, &'static str> {
    Ok(read(&member(directory, path)?)?.map(|bytes| hash(&bytes)))
}

fn receipt_path(provider: Provider) -> String {
    format!(".hrc-harness/receipts/{}.json", provider.name())
}

fn owned(provider: Provider, scope: Scope, path: &str) -> bool {
    let (skills, agents) = provider.directories(scope);
    path.starts_with(&format!("{skills}/hrc-"))
        || path.starts_with(&format!("{agents}/hrc-"))
        || path.starts_with(&format!(".hrc-harness/providers/{}/", provider.name()))
}

fn receipt(directory: &Path, provider: Provider, scope: Scope) -> Result<Receipt, &'static str> {
    let Some(bytes) = read(&member(directory, &receipt_path(provider))?)? else {
        return Ok(Receipt {
            schema: 1,
            provider,
            scope,
            files: BTreeMap::new(),
        });
    };
    let record: Receipt = serde_json::from_slice(&bytes).map_err(|_| "AssistantInvalidReceipt")?;
    if record.schema != 1
        || record.provider != provider
        || record.scope != scope
        || record.files.len() > 128
    {
        return Err("AssistantInvalidReceipt");
    }
    for (path, hashes) in &record.files {
        member(directory, path)?;
        if !owned(provider, scope, path)
            || hashes.is_empty()
            || hashes.len() > 2
            || hashes
                .iter()
                .any(|h| h.len() != 64 || !h.bytes().all(|b| b.is_ascii_hexdigit()))
        {
            return Err("AssistantInvalidReceipt");
        }
    }
    Ok(record)
}

fn plan(directory: &Path, record: &Receipt, uninstall: bool) -> Result<Vec<Change>, &'static str> {
    let desired = if uninstall {
        BTreeMap::new()
    } else {
        assets::files(record.provider, record.scope)
    };
    let mut paths: Vec<_> = desired.keys().chain(record.files.keys()).cloned().collect();
    paths.sort();
    paths.dedup();
    paths
        .into_iter()
        .map(|path| {
            let before = current(directory, &path)?;
            let after = desired.get(&path).cloned();
            let ours = before
                .as_ref()
                .is_some_and(|hash| record.files.get(&path).is_some_and(|v| v.contains(hash)));
            let action = match (&before, &after) {
                (None, None) => "absent",
                (None, Some(_)) => "write",
                (Some(_), None) if ours => "remove",
                (Some(_), None) => "preserve",
                (Some(old), Some(bytes)) if ours && old == &hash(bytes) => "unchanged",
                (Some(_), Some(_)) if ours => "update",
                (Some(_), Some(_)) => "conflict",
            };
            Ok(Change {
                path,
                action,
                before,
                after,
            })
        })
        .collect()
}

fn make_parent(directory: &Path, relative: &str) -> Result<PathBuf, &'static str> {
    let path = member(directory, relative)?;
    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path.parent().ok_or("AssistantUnsafePath")?)
        .map_err(|_| "AssistantWriteFailed")?;
    member(directory, relative)
}

fn publish(
    directory: &Path,
    relative: &str,
    bytes: &[u8],
    expected: Option<&str>,
) -> Result<(), &'static str> {
    let path = make_parent(directory, relative)?;
    if current(directory, relative)?.as_deref() != expected {
        return Err("AssistantFileChanged");
    }
    let parent = path.parent().ok_or("AssistantUnsafePath")?;
    let mut nonce = [0; 8];
    getrandom::fill(&mut nonce).map_err(|_| "AssistantWriteFailed")?;
    let temporary = parent.join(format!(".hrc-harness-{}", hex::encode(nonce)));
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(&temporary)
            .map_err(|_| "AssistantWriteFailed")?;
        file.write_all(bytes)
            .and_then(|()| file.sync_all())
            .map_err(|_| "AssistantWriteFailed")?;
        if current(directory, relative)?.as_deref() != expected {
            return Err("AssistantFileChanged");
        }
        fs::rename(&temporary, member(directory, relative)?).map_err(|_| "AssistantWriteFailed")?;
        File::open(parent)
            .and_then(|f| f.sync_all())
            .map_err(|_| "AssistantWriteFailed")
    })();
    if result.is_err() {
        let _ = fs::remove_file(temporary);
    }
    result
}

fn lock(directory: &Path, provider: Provider) -> Result<File, &'static str> {
    let relative = format!(".hrc-harness/receipts/{}.lock", provider.name());
    let path = make_parent(directory, &relative)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .map_err(|_| "AssistantLockUnavailable")?;
    let metadata = file.metadata().map_err(|_| "AssistantLockUnavailable")?;
    if !metadata.is_file() || metadata.nlink() != 1 {
        return Err("AssistantUnsafeFile");
    }
    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err("AssistantInstallationBusy");
    }
    Ok(file)
}

fn execute(directory: &Path, record: &mut Receipt, changes: &[Change]) -> Result<(), &'static str> {
    // Publish expected old/new hashes before changing files, so interrupted installs can resume.
    for change in changes {
        if matches!(change.action, "write" | "update") {
            let mut hashes = change.before.iter().cloned().collect::<Vec<_>>();
            hashes.push(hash(change.after.as_ref().ok_or("AssistantInvalidPlan")?));
            record.files.insert(change.path.clone(), hashes);
        }
    }
    let receipt_file = receipt_path(record.provider);
    let previous = current(directory, &receipt_file)?;
    let pending = serde_json::to_vec_pretty(record).map_err(|_| "AssistantInvalidReceipt")?;
    publish(directory, &receipt_file, &pending, previous.as_deref())?;
    for change in changes {
        match change.action {
            "write" | "update" => {
                let bytes = change.after.as_ref().ok_or("AssistantInvalidPlan")?;
                publish(directory, &change.path, bytes, change.before.as_deref())?;
                record.files.insert(change.path.clone(), vec![hash(bytes)]);
            }
            "remove" => {
                if current(directory, &change.path)? != change.before {
                    return Err("AssistantFileChanged");
                }
                let path = member(directory, &change.path)?;
                fs::remove_file(&path).map_err(|_| "AssistantWriteFailed")?;
                File::open(path.parent().ok_or("AssistantUnsafePath")?)
                    .and_then(|f| f.sync_all())
                    .map_err(|_| "AssistantWriteFailed")?;
                record.files.remove(&change.path);
            }
            "absent" => {
                record.files.remove(&change.path);
            }
            "unchanged" => {
                if let Some(value) = &change.before {
                    record
                        .files
                        .insert(change.path.clone(), vec![value.clone()]);
                }
            }
            "preserve" => (),
            _ => return Err("AssistantFileConflict"),
        }
    }
    let final_bytes = serde_json::to_vec_pretty(record).map_err(|_| "AssistantInvalidReceipt")?;
    publish(
        directory,
        &receipt_file,
        &final_bytes,
        Some(&hash(&pending)),
    )
}

pub fn change(
    provider: Provider,
    scope: Scope,
    destination: &Path,
    apply: bool,
    uninstall: bool,
) -> Result<Value, &'static str> {
    root(destination)?;
    let _lock = if apply {
        Some(lock(destination, provider)?)
    } else {
        None
    };
    let mut record = receipt(destination, provider, scope)?;
    let changes = plan(destination, &record, uninstall)?;
    let can_apply = changes.iter().all(|c| c.action != "conflict");
    if apply {
        if !can_apply {
            return Err("AssistantFileConflict");
        }
        execute(destination, &mut record, &changes)?;
    }
    let files: Vec<_> = changes
        .iter()
        .map(|c| json!({"path": c.path, "action": c.action}))
        .collect();
    Ok(json!({"schema": 1, "provider": provider, "scope": scope,
        "destination": destination, "applied": apply, "can_apply": can_apply,
        "operation": if uninstall { "uninstall" } else { "install" },
        "files": files}))
}
