// SPDX-License-Identifier: Apache-2.0
//! Shared Suite joins and saved-server runtime ownership; HRC never implements admission crypto.
use super::{Error, Result, native};
use hrc::service::files;
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    path::{Path, PathBuf},
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Binding {
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub directory: PathBuf,
    pub suite: PathBuf,
    pub runtime_configuration: PathBuf,
    pub page_profile: Option<PathBuf>,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Joined {
    pub status: String,
    pub server_directory: PathBuf,
    pub hrc_profile: PathBuf,
    pub page_profile: Option<PathBuf>,
    pub runtime_configuration: PathBuf,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Status {
    pub status: String,
    pub desired_online: bool,
    pub runtime_ready: bool,
    pub runtime_owned: bool,
    pub hrc_profile: Option<PathBuf>,
    pub page_profile: Option<PathBuf>,
}
pub(super) fn absolute(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path.components().any(|p| {
            matches!(
                p,
                std::path::Component::ParentDir | std::path::Component::CurDir
            )
        })
    {
        return Err(Error::LocalConfiguration);
    }
    native::path(path).map(|_| ())
}
pub fn load(profile: &Path) -> Result<Option<Binding>> {
    let path = profile.join("SimpleServer.json");
    if !path.try_exists().map_err(|_| Error::LocalConfiguration)? {
        return Ok(None);
    }
    files::directory(profile, false).map_err(|_| Error::LocalConfiguration)?;
    let binding: Binding = files::json(&path).map_err(|_| Error::LocalConfiguration)?;
    if binding.version != 1
        || binding
            .name
            .as_ref()
            .is_some_and(|s| s.len() > 1024 || s.chars().any(char::is_control))
    {
        return Err(Error::LocalConfiguration);
    }
    for path in [
        &binding.directory,
        &binding.suite,
        &binding.runtime_configuration,
    ] {
        absolute(path)?;
    }
    if let Some(path) = &binding.page_profile {
        absolute(path)?;
    }
    files::directory(&binding.directory, false).map_err(|_| Error::LocalConfiguration)?;
    files::read(&binding.runtime_configuration, 65536).map_err(|_| Error::LocalConfiguration)?;
    Ok(Some(binding))
}
impl Joined {
    pub(super) fn checked(self, suite: &Path) -> Result<Self> {
        if self.status != "Joined" {
            return Err(Error::Admission);
        }
        let binding = load(&self.hrc_profile)?.ok_or(Error::LocalConfiguration)?;
        if binding.suite != suite
            || binding.directory != self.server_directory
            || binding.runtime_configuration != self.runtime_configuration
            || binding.page_profile != self.page_profile
        {
            return Err(Error::CompanionBinding);
        }
        hrc::client::Profile::load(&self.hrc_profile).map_err(|_| Error::LocalConfiguration)?;
        Ok(self)
    }
}
pub fn join(suite: &Path, location: Option<&str>, cancel: &AtomicBool) -> Result<Joined> {
    if location.is_some_and(|s| s.len() > 8192 || s.chars().any(char::is_control)) {
        return Err(Error::Admission);
    }
    let executable = std::env::current_exe().map_err(|_| Error::RuntimeMissing)?;
    native::executable(&executable)?;
    let args = native::strings(&[
        "join",
        "desktop",
        "--application",
        "hrc",
        "--hrc-executable",
        &native::path(&executable)?,
    ]);
    let joined: Joined =
        native::input_json(suite, &args, &json!({"location":location}), cancel, None)?;
    joined.checked(suite)
}
pub fn status(
    binding: &Binding,
    profile: &Path,
    cancel: &AtomicBool,
    end: Instant,
) -> Result<Status> {
    let value = native::json(
        &binding.suite,
        &native::strings(&[
            "join",
            "status",
            "--directory",
            &native::path(&binding.directory)?,
            "--config",
            &native::path(&binding.runtime_configuration)?,
        ]),
        cancel,
        end,
    )?;
    let status: Status = serde_json::from_value(value).map_err(|_| Error::NativeRefused)?;
    if status.status != "SavedServer"
        || status.hrc_profile.as_deref() != Some(profile)
        || status.page_profile != binding.page_profile
    {
        return Err(Error::CompanionBinding);
    }
    Ok(status)
}
pub fn desire(binding: &Binding, online: bool, cancel: &AtomicBool, end: Instant) -> Result<()> {
    native::run(
        &binding.suite,
        &native::strings(&[
            "join",
            "desire",
            "--directory",
            &native::path(&binding.directory)?,
            if online { "--online" } else { "--offline" },
        ]),
        cancel,
        end,
    )
    .map(|_| ())
}
fn unit(binding: &Binding) -> Result<String> {
    Ok(format!(
        "hrc-simple-server-{}",
        hrc::protocol::digest(native::path(&binding.directory)?.as_bytes()).as_hex()
    ))
}
pub fn prepare(
    binding: &Binding,
    profile: &Path,
    offline: bool,
    cancel: &AtomicBool,
    end: Instant,
) -> Result<()> {
    let initial = status(binding, profile, cancel, end)?;
    desire(binding, !offline, cancel, end)?;
    if offline {
        return Ok(());
    }
    if initial.runtime_ready && initial.desired_online {
        return Ok(());
    }
    if !initial.runtime_owned {
        let name = unit(binding)?;
        match native::run(
            Path::new("/usr/bin/systemctl"),
            &native::strings(&["--user", "is-active", "--quiet", &name]),
            cancel,
            end,
        ) {
            Ok(_) => (),
            Err(Error::NativeRefused) => {
                native::executable(&binding.suite)?;
                native::run(
                    Path::new("/usr/bin/systemd-run"),
                    &native::strings(&[
                        "--user",
                        "--collect",
                        "--quiet",
                        "--property=Restart=no",
                        "--property=UMask=0077",
                        "--property=NoNewPrivileges=yes",
                        &format!("--unit={name}"),
                        "--",
                        &native::path(&binding.suite)?,
                        "join",
                        "session",
                        "--directory",
                        &native::path(&binding.directory)?,
                        "--config",
                        &native::path(&binding.runtime_configuration)?,
                    ]),
                    cancel,
                    end,
                )?;
            }
            Err(error) => return Err(error),
        }
    }
    loop {
        native::check(cancel, end)?;
        let current = status(binding, profile, cancel, end)?;
        if !current.desired_online {
            return Err(Error::Cancelled);
        }
        if current.runtime_ready {
            return Ok(());
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}
/// Automatic reopening respects Suite's saved desire. Explicit Open chat changes it separately.
pub fn saved_offline(profile: &Path, cancel: &AtomicBool) -> Result<bool> {
    match load(profile)? {
        Some(binding) => Ok(!status(
            &binding,
            profile,
            cancel,
            Instant::now() + Duration::from_secs(10),
        )?
        .desired_online),
        None => Ok(false),
    }
}

/// Cancellable worker shared by the launcher and Agent wizard; no work runs on paint.
pub(crate) struct Job<T> {
    cancel: std::sync::Arc<AtomicBool>,
    receiver: std::sync::mpsc::Receiver<Result<T>>,
    worker: Option<std::thread::JoinHandle<()>>,
}
impl<T: Send + 'static> Job<T> {
    pub fn start(
        ctx: &eframe::egui::Context,
        work: impl FnOnce(&AtomicBool) -> Result<T> + Send + 'static,
    ) -> Self {
        let cancel = std::sync::Arc::new(AtomicBool::new(false));
        let cancelled = cancel.clone();
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let wake = ctx.clone();
        let worker = std::thread::spawn(move || {
            let _ = sender.send(work(&cancelled));
            wake.request_repaint();
        });
        Self {
            cancel,
            receiver,
            worker: Some(worker),
        }
    }
    #[cfg(test)]
    pub(crate) fn finished(&self) -> bool {
        self.worker.as_ref().is_none_or(|w| w.is_finished())
    }
    pub fn cancel(&self) {
        self.cancel
            .store(true, std::sync::atomic::Ordering::Release);
    }
    pub fn result(&self) -> Option<Result<T>> {
        match self.receiver.try_recv() {
            Ok(result) => Some(result),
            Err(std::sync::mpsc::TryRecvError::Disconnected) => Some(Err(Error::NativeRefused)),
            Err(std::sync::mpsc::TryRecvError::Empty) => None,
        }
    }
}
impl<T> Drop for Job<T> {
    fn drop(&mut self) {
        self.cancel
            .store(true, std::sync::atomic::Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

/// Suite validates the pinned read-only native identity and owns browser launch.
pub fn pages(binding: &Binding, location: Option<&str>, cancel: &AtomicBool) -> Result<()> {
    #[derive(Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Opened {
        status: String,
    }
    if binding.page_profile.is_none() {
        return Err(Error::LocalConfiguration);
    }
    let result: Opened = native::input_json(
        &binding.suite,
        &native::strings(&[
            "join",
            "pages",
            "--directory",
            &native::path(&binding.directory)?,
            "--config",
            &native::path(&binding.runtime_configuration)?,
        ]),
        &json!({"location":location}),
        cancel,
        Some(Instant::now() + Duration::from_secs(120)),
    )?;
    if result.status != "Opened" {
        return Err(Error::NativeRefused);
    }
    Ok(())
}
