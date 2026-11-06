// SPDX-License-Identifier: Apache-2.0
//! Embedded palettes and private, content-addressed imports without replacing user files.
use super::data::{MAX_BYTES, Palette, Result};
use hrc::service::files;
use sha2::{Digest, Sha256};
use std::{
    fs::{self, File, OpenOptions},
    os::{
        fd::AsRawFd,
        unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
    },
    path::{Component, Path, PathBuf},
};
pub const MAX_IMPORTED: usize = 64;
const BUILTINS: &[(&str, &str)] = &[
    (
        "hypernet-dark",
        include_str!("../../Themes/HyperNetDark.json"),
    ),
    (
        "hypernet-light",
        include_str!("../../Themes/HyperNetLight.json"),
    ),
    ("ocean-dark", include_str!("../../Themes/OceanDark.json")),
    ("ocean-light", include_str!("../../Themes/OceanLight.json")),
    ("forest-dark", include_str!("../../Themes/ForestDark.json")),
    (
        "forest-light",
        include_str!("../../Themes/ForestLight.json"),
    ),
    ("ember-dark", include_str!("../../Themes/EmberDark.json")),
    ("ember-light", include_str!("../../Themes/EmberLight.json")),
    ("plum-dark", include_str!("../../Themes/PlumDark.json")),
    ("plum-light", include_str!("../../Themes/PlumLight.json")),
    ("slate-dark", include_str!("../../Themes/SlateDark.json")),
    ("slate-light", include_str!("../../Themes/SlateLight.json")),
    ("sand-dark", include_str!("../../Themes/SandDark.json")),
    ("sand-light", include_str!("../../Themes/SandLight.json")),
];
pub struct Entry {
    pub id: String,
    pub palette: Palette,
    pub imported: bool,
}
impl Entry {
    pub fn original(&self) -> bool {
        matches!(self.id.as_str(), "hypernet-dark" | "hypernet-light")
    }
}
pub struct Library {
    pub entries: Vec<Entry>,
    pub problem: Option<&'static str>,
    directory: Option<PathBuf>,
}
fn identifier(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn imported_id(id: &str) -> bool {
    id.len() == 64
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn user_directory() -> Option<PathBuf> {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| {
            std::env::var_os("HOME")
                .map(|p| PathBuf::from(p).join(".config"))
                .filter(|p| p.is_absolute())
        })
        .map(|p| p.join("HyperNetRelayChat/Themes"))
}
fn directory(path: &Path, create: bool) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::CurDir))
    {
        return Err("Theme folder must be an absolute local path.");
    }
    let uid = unsafe { libc::geteuid() };
    let mut current = PathBuf::new();
    for part in path.components() {
        current.push(part);
        let metadata = match fs::symlink_metadata(&current) {
            Ok(m) => m,
            Err(e) if create && e.kind() == std::io::ErrorKind::NotFound => {
                fs::DirBuilder::new()
                    .mode(0o700)
                    .create(&current)
                    .map_err(|_| "Theme folder could not be created.")?;
                fs::symlink_metadata(&current).map_err(|_| "Theme folder is unavailable.")?
            }
            Err(_) => return Err("Theme folder is unavailable."),
        };
        let protected = metadata.mode() & 0o022 == 0
            || metadata.uid() == 0 && metadata.mode() & libc::S_ISVTX != 0;
        if !metadata.is_dir() || ![0, uid].contains(&metadata.uid()) || !protected {
            return Err("Theme folder contains an unsafe or linked directory.");
        }
    }
    files::directory(path, false)
        .map(|_| ())
        .map_err(|_| "Theme folder must be private and owned by this account.")
}
fn lock(path: &Path) -> Result<File> {
    directory(path, true)?;
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path.join(".Import.lock"))
        .map_err(|_| "Theme import lock is unavailable.")?;
    let m = file
        .metadata()
        .map_err(|_| "Theme import lock is unavailable.")?;
    if !m.is_file()
        || m.mode() & 0o7777 != 0o600
        || m.uid() != unsafe { libc::geteuid() }
        || m.nlink() != 1
        || unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0
    {
        return Err("Another theme import is active or its lock is unsafe.");
    }
    Ok(file)
}
fn paths(path: &Path) -> Result<Vec<PathBuf>> {
    directory(path, false)?;
    let mut result = Vec::new();
    for entry in fs::read_dir(path)
        .map_err(|_| "Theme folder could not be read.")?
        .take(MAX_IMPORTED + 2)
    {
        let entry = entry.map_err(|_| "Theme folder could not be read.")?;
        if entry.file_name() == ".Import.lock" {
            continue;
        }
        result.push(entry.path());
        if result.len() > MAX_IMPORTED {
            return Err("The theme folder exceeds its 64-file limit.");
        }
    }
    result.sort();
    Ok(result)
}
impl Library {
    pub fn new() -> Self {
        Self::at(user_directory())
    }
    fn at(directory: Option<PathBuf>) -> Self {
        let mut value = Self {
            entries: Vec::new(),
            problem: None,
            directory,
        };
        value.reload();
        value
    }
    fn reload(&mut self) {
        self.entries.clear();
        self.problem = None;
        for (id, bytes) in BUILTINS {
            match Palette::parse(bytes.as_bytes()) {
                Ok(palette) => self.entries.push(Entry {
                    id: (*id).into(),
                    palette,
                    imported: false,
                }),
                Err(_) => {
                    self.problem = Some(
                        "A bundled theme could not be read; the original defaults remain available.",
                    )
                }
            }
        }
        let Some(directory) = &self.directory else {
            self.problem = Some("The private theme folder is unavailable.");
            return;
        };
        if !directory.try_exists().unwrap_or(true) {
            return;
        }
        let paths = match paths(directory) {
            Ok(v) => v,
            Err(e) => {
                self.problem = Some(e);
                return;
            }
        };
        for path in paths {
            let loaded = (|| {
                let id = path
                    .file_stem()
                    .and_then(|v| v.to_str())
                    .ok_or("Invalid theme filename.")?;
                if path.extension().is_none_or(|v| v != "json") || !imported_id(id) {
                    return Err("Invalid theme filename.");
                }
                let bytes = files::read(&path, MAX_BYTES)
                    .map_err(|_| "Imported theme is not a private, owned regular file.")?;
                let palette = Palette::parse(&bytes)?;
                if identifier(&palette.bytes()?) != id {
                    return Err("An imported theme was edited; import the changed file again.");
                }
                Ok(Entry {
                    id: id.into(),
                    palette,
                    imported: true,
                })
            })();
            match loaded {
                Ok(entry) => self.entries.push(entry),
                Err(error) => self.problem = Some(error),
            }
        }
    }
    pub fn selected(&self, preferences: &hrc::client::Preferences) -> Option<&Entry> {
        let id = preferences
            .palette
            .as_deref()
            .unwrap_or(match preferences.theme {
                hrc::client::Theme::Dark => "hypernet-dark",
                hrc::client::Theme::Light => "hypernet-light",
            });
        self.entries.iter().find(|entry| entry.id == id)
    }
    pub fn read_import(path: &Path) -> Result<Palette> {
        let bytes = crate::onboarding::native::public_file(path, MAX_BYTES)
            .map_err(|_| "Choose a regular, owned JSON file of at most 16 KiB; links and shared-writable files are refused.")?;
        Palette::parse(&bytes)
    }
    pub fn import(&mut self, palette: &Palette) -> Result<String> {
        let bytes = palette.bytes()?;
        let id = identifier(&bytes);
        let directory = self
            .directory
            .as_ref()
            .ok_or("The private theme folder is unavailable.")?;
        let _lock = lock(directory)?;
        let path = directory.join(format!("{id}.json"));
        if fs::symlink_metadata(&path).is_ok() {
            if files::read(&path, MAX_BYTES)
                .map_err(|_| "Existing theme file is unsafe; it was not replaced.")?
                != bytes
            {
                return Err("Existing theme file was edited; it was not replaced.");
            }
        } else {
            if paths(directory)?.len() >= MAX_IMPORTED {
                return Err("Remove an imported theme before adding another; the limit is 64.");
            }
            files::create(&path, &bytes)
                .map_err(|_| "Theme could not be saved; no existing file was replaced.")?;
        }
        self.reload();
        Ok(id)
    }
    pub fn remove(&mut self, id: &str) -> Result<()> {
        if !imported_id(id) {
            return Err("Only imported themes can be removed.");
        }
        let directory = self
            .directory
            .as_ref()
            .ok_or("The private theme folder is unavailable.")?;
        let _lock = lock(directory)?;
        let path = directory.join(format!("{id}.json"));
        let bytes = files::read(&path, MAX_BYTES)
            .map_err(|_| "Theme file is unsafe or unavailable; it was preserved.")?;
        let palette = Palette::parse(&bytes)?;
        if identifier(&palette.bytes()?) != id {
            return Err("Theme file was edited; it was preserved.");
        }
        fs::remove_file(path)
            .and_then(|()| File::open(directory)?.sync_all())
            .map_err(|_| "Theme could not be removed.")?;
        self.reload();
        Ok(())
    }
}

#[cfg(test)]
#[path = "../../Tests/Unit/Gui/Themes.rs"]
mod tests;
