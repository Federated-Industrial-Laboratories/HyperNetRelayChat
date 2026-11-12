// SPDX-License-Identifier: Apache-2.0
//! A private last-profile preference contains paths, never endpoint keys.
use hrc::service::files;
use serde::{Deserialize, Serialize};
use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Preferences {
    profile: PathBuf,
    #[serde(default)]
    profiles: Vec<PathBuf>,
}

pub(super) fn user_directory(variable: &str, fallback: &str) -> Result<PathBuf, &'static str> {
    std::env::var_os(variable)
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| {
            std::env::var_os("HOME")
                .map(|p| PathBuf::from(p).join(fallback))
                .filter(|p| p.is_absolute())
        })
        .ok_or("UserDirectoryUnavailable")
}
pub(super) fn directory() -> Result<PathBuf, &'static str> {
    let parent = user_directory("XDG_CONFIG_HOME", ".config")?;
    fs::create_dir_all(&parent).map_err(|_| "ConfigurationUnavailable")?;
    let path = parent.join("HyperNetRelayChat");
    if !path.exists() {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&path)
            .map_err(|_| "ConfigurationUnavailable")?;
    }
    files::directory(&path, false).map_err(|_| "ConfigurationUnavailable")
}
pub(super) fn last_profile() -> Option<PathBuf> {
    let config = directory().ok()?.join("Desktop.json");
    let preferences: Preferences = files::json(&config).ok()?;
    files::directory(&preferences.profile, false).ok()
}
pub(super) fn saved_profiles() -> Vec<PathBuf> {
    let Some(config) = directory().ok().map(|p| p.join("Desktop.json")) else {
        return vec![];
    };
    let Ok(mut preferences) = files::json::<Preferences>(&config) else {
        return vec![];
    };
    preferences.profiles.insert(0, preferences.profile);
    let mut profiles = Vec::new();
    for profile in preferences.profiles.into_iter().take(65) {
        if !profiles.contains(&profile) && files::directory(&profile, false).is_ok() {
            profiles.push(profile);
        }
    }
    profiles.truncate(64);
    profiles
}
pub(super) fn remember_profile(profile: &Path) -> Result<(), &'static str> {
    let profile = files::directory(profile, false).map_err(|_| "InvalidProfileDirectory")?;
    let directory = directory()?;
    let mut nonce = [0; 8];
    getrandom::fill(&mut nonce).map_err(|_| "ConfigurationUnavailable")?;
    let temporary = directory.join(format!(".Desktop-{}", hex::encode(nonce)));
    let mut profiles = saved_profiles();
    profiles.retain(|p| p != &profile);
    profiles.insert(0, profile.clone());
    profiles.truncate(64);
    files::create_json(&temporary, &Preferences { profile, profiles })
        .map_err(|_| "ConfigurationUnavailable")?;
    let result = fs::rename(&temporary, directory.join("Desktop.json"))
        .and_then(|()| fs::File::open(&directory)?.sync_all());
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result.map_err(|_| "ConfigurationUnavailable")
}
