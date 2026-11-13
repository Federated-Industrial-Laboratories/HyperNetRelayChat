// SPDX-License-Identifier: Apache-2.0
//! User-owned setup and process control shared by the desktop and external operator commands.
pub(crate) use crate::onboarding::native;
#[path = "Bots.rs"]
pub(crate) mod bots;
#[path = "Commands.rs"]
mod commands;
#[path = "Home.rs"]
pub(crate) mod home;
#[path = "Models.rs"]
pub(crate) mod models;
#[path = "Network/Mod.rs"]
pub(crate) mod network;
#[path = "Packages.rs"]
pub(crate) mod packages;
#[path = "Participants.rs"]
pub(crate) mod participants;
#[path = "Units.rs"]
pub(crate) mod units;
pub(crate) use commands::{Command, run};

pub(crate) type Result<T> = std::result::Result<T, String>;
pub(crate) fn failure(error: impl std::fmt::Display) -> String {
    error.to_string()
}

pub(crate) fn private_json<T: serde::Serialize>(path: &std::path::Path, value: &T) -> Result<()> {
    let parent = path
        .parent()
        .ok_or("Choose a private configuration folder.")?;
    private_directory(parent)?;
    native::directory(parent).map_err(failure)?;
    native::replace_file(path, &serde_json::to_vec_pretty(value).map_err(failure)?).map_err(failure)
}
pub(crate) fn private_directory(path: &std::path::Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    if !path.is_absolute()
        || path.components().any(|c| {
            matches!(
                c,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err("Choose an absolute private folder.".into());
    }
    let mut current = std::path::PathBuf::new();
    for part in path.components() {
        current.push(part);
        match std::fs::symlink_metadata(&current) {
            Ok(m) if !m.is_dir() => {
                return Err(
                    "The folder contains a symbolic link or a non-directory component.".into(),
                );
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                std::fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&current)
                    .map_err(failure)?
            }
            Err(error) => return Err(failure(error)),
        }
    }
    native::directory(path).map_err(failure)
}
pub(crate) fn read_json<T: serde::de::DeserializeOwned>(path: &std::path::Path) -> Result<T> {
    let bytes = hrc::service::files::read(path, 65_536)
        .map_err(|_| "The private configuration is unavailable.".to_owned())?;
    serde_json::from_slice(&bytes)
        .map_err(|_| "The configuration does not match this HRC version.".to_owned())
}
pub(crate) fn root() -> std::path::PathBuf {
    std::env::var_os("XDG_DATA_HOME")
        .map(std::path::PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| {
            std::env::var_os("HOME").map(|p| std::path::PathBuf::from(p).join(".local/share"))
        })
        .unwrap_or_else(|| std::path::PathBuf::from("/"))
        .join("HyperNetRelayChat/Operations")
}

pub(crate) fn configurations(kind: &str) -> Result<Vec<std::path::PathBuf>> {
    let directory = root().join(kind);
    if !directory.exists() {
        return Ok(Vec::new());
    }
    native::directory(&directory).map_err(failure)?;
    let mut paths = Vec::new();
    for entry in std::fs::read_dir(directory).map_err(failure)?.take(129) {
        let entry = entry.map_err(failure)?;
        if entry.file_type().map_err(failure)?.is_file()
            && entry.path().extension().is_some_and(|v| v == "json")
        {
            paths.push(entry.path());
        }
        if paths.len() > 128 {
            return Err(
                "Too many saved configurations. Move unused definitions to a private archive."
                    .into(),
            );
        }
    }
    paths.sort();
    Ok(paths)
}
