// SPDX-License-Identifier: Apache-2.0
//! Explicit Page activation validates the selected native reader without changing chat authority.
use crate::{
    gui,
    onboarding::{RuntimeConfig, native},
};
use eframe::egui;
use hrc::{
    client,
    protocol::{Id, NetworkId},
    service::files,
};
use serde_json::Value;
use std::{
    fs::{self, OpenOptions},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::{Duration, Instant},
};

const SETUP: &str = "Configure this chat profile's Suite executable and joined network profile in Setup before opening Pages.";
const FAILED: &str = "The HyperNet browser could not complete this request. Check its Page route and reader permission. A network profile can serve only one active native client; choose a separate reader in Settings > HyperNet Pages or close its existing browser window.";
const PRIVATE_PROFILE: &str =
    "Choose an existing private, canonical native network Profile.json owned by this user.";
const READER_BUSY: &str = "A browser already uses this reader profile. Navigate in that window, or close it before opening another Page from chat.";

fn reader_available(reader: &Path, active: &[PathBuf]) -> Result<(), &'static str> {
    if active.iter().any(|path| path == reader) {
        Err(READER_BUSY)
    } else {
        Ok(())
    }
}

pub(super) struct Job<T> {
    cancel: Arc<AtomicBool>,
    receiver: mpsc::Receiver<Result<T, &'static str>>,
    worker: Option<thread::JoinHandle<()>>,
}
impl<T: Send + 'static> Job<T> {
    pub(super) fn start(
        ctx: &egui::Context,
        work: impl FnOnce(&AtomicBool) -> Result<T, &'static str> + Send + 'static,
    ) -> Result<Self, &'static str> {
        let cancel = Arc::new(AtomicBool::new(false));
        let cancelled = cancel.clone();
        let wake = ctx.clone();
        let (sender, receiver) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("hrc-page-profile".into())
            .spawn(move || {
                let result = work(&cancelled);
                let _ = sender.send(result);
                wake.request_repaint();
            })
            .map_err(|_| "The Page profile worker could not start.")?;
        Ok(Self {
            cancel,
            receiver,
            worker: Some(worker),
        })
    }
    pub(super) fn result(&self) -> Option<Result<T, &'static str>> {
        match self.receiver.try_recv() {
            Ok(result) => Some(result),
            Err(mpsc::TryRecvError::Empty) => None,
            Err(mpsc::TryRecvError::Disconnected) => Some(Err("The Page profile worker stopped.")),
        }
    }
}
impl<T> Drop for Job<T> {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
struct Launch {
    command: Command,
    reader: PathBuf,
    palette: PathBuf,
    colours: Vec<u8>,
}
struct Opened {
    child: Child,
    reader: PathBuf,
}
#[derive(Default)]
pub(super) struct Browser {
    children: Vec<Opened>,
    opening: Option<Job<Launch>>,
}
pub(super) fn configuration(profile: &Path) -> Result<RuntimeConfig, &'static str> {
    let path = profile
        .parent()
        .ok_or(SETUP)?
        .join("OnboardingRuntime.json");
    let config = RuntimeConfig::load(&path).map_err(|_| SETUP)?;
    if config.hrc_profile != profile {
        return Err("The browser configuration belongs to another chat profile.");
    }
    let loaded =
        client::Profile::load(profile).map_err(|_| "The selected chat profile is unavailable.")?;
    if config.companion_directory != loaded.companion
        || config.clock_observation != loaded.clock.observation
        || config.clock_monitor_key != loaded.clock.monitor_key
    {
        return Err("The browser configuration does not match this chat profile.");
    }
    Ok(config)
}
fn private_profile(path: &Path) -> Result<(), &'static str> {
    files::directory(path.parent().ok_or(PRIVATE_PROFILE)?, false).map_err(|_| PRIVATE_PROFILE)?;
    if !path.is_absolute() || path.canonicalize().map_err(|_| PRIVATE_PROFILE)? != path {
        return Err(PRIVATE_PROFILE);
    }
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| PRIVATE_PROFILE)?;
    let metadata = file.metadata().map_err(|_| PRIVATE_PROFILE)?;
    if !metadata.is_file()
        || metadata.mode() & 0o7777 != 0o600
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.nlink() != 1
        || metadata.len() > 600_000
    {
        return Err(PRIVATE_PROFILE);
    }
    Ok(())
}
#[derive(Clone, Debug, PartialEq)]
struct Identity {
    network: NetworkId,
    fingerprint: Id,
    descriptor: Id,
    client: Id,
    device: Id,
    relay: Id,
}
impl Identity {
    fn from_report(value: &Value) -> Result<Self, &'static str> {
        let invalid = "Suite did not report a joined native network profile.";
        if value["state"] != "Joined" || value["membership"] != true {
            return Err(invalid);
        }
        let id = |v: &Value| v.as_str().ok_or(invalid)?.parse().map_err(|_| invalid);
        Ok(Self {
            network: NetworkId {
                network: id(&value["trust"]["network"])?,
                incarnation: id(&value["trust"]["incarnation"])?,
            },
            fingerprint: id(&value["fingerprint"])?,
            descriptor: id(&value["descriptorDigest"])?,
            client: id(&value["client"])?,
            device: id(&value["devicePublicKey"])?,
            relay: id(&value["relayPublicKey"])?,
        })
    }
}
fn inspect(
    config: &RuntimeConfig,
    path: &Path,
    cancel: &AtomicBool,
    end: Instant,
) -> Result<Identity, &'static str> {
    private_profile(path)?;
    let value = native::json(&config.suite, &native::strings(&[
        "network", "inspect", "--profile", path.to_str().ok_or(PRIVATE_PROFILE)?
    ]), cancel, end).map_err(|_| "The selected profile could not be inspected by the configured Suite. Check the installed tools and private profile.")?;
    Identity::from_report(&value)
}
fn check_identity(
    chat: &Identity,
    reader: &Identity,
    expected: NetworkId,
    principal: Id,
    separate: bool,
) -> Result<(), &'static str> {
    if chat.network != expected
        || chat.device != principal
        || reader.network != expected
        || reader.fingerprint != chat.fingerprint
        || reader.descriptor != chat.descriptor
    {
        return Err(
            "The reader and chat profiles must belong to this chat's network and incarnation.",
        );
    }
    if separate
        && (reader.client == chat.client
            || reader.device == chat.device
            || reader.relay == chat.relay)
    {
        return Err(
            "Choose a separately admitted reader with its own client, device and relay identities. A copied chat profile cannot be used.",
        );
    }
    Ok(())
}
fn validate(config: &RuntimeConfig, cancel: &AtomicBool) -> Result<NetworkId, &'static str> {
    native::executable(&config.suite)
        .map_err(|_| "Choose a trusted installed Suite executable in Setup.")?;
    let loaded = client::Profile::load(&config.hrc_profile)
        .map_err(|_| "The selected chat profile is unavailable.")?;
    let end = Instant::now() + Duration::from_secs(15);
    let chat = inspect(config, &config.network_profile, cancel, end)?;
    let reader = match &config.page_browser_profile {
        Some(path) => {
            if path == &config.network_profile {
                return Err(
                    "Choose a separate reader profile, or select the chat-profile default explicitly.",
                );
            }
            inspect(config, path, cancel, end)?
        }
        None => chat.clone(),
    };
    check_identity(
        &chat,
        &reader,
        loaded.server.home.network,
        loaded.registration.transport_principal,
        config.page_browser_profile.is_some(),
    )?;
    Ok(reader.network)
}
pub(super) fn save_selection(
    profile: &Path,
    selected: Option<PathBuf>,
    expected: &Value,
    cancel: &AtomicBool,
) -> Result<(), &'static str> {
    let mut config = configuration(profile)?;
    let before = serde_json::to_value(&config).map_err(|_| SETUP)?;
    if &before != expected {
        return Err("The runtime settings changed. Reopen Page browser settings before saving.");
    }
    config.page_browser_profile = selected;
    validate(&config, cancel)?;
    let current = configuration(profile)?;
    if serde_json::to_value(current).map_err(|_| SETUP)? != before {
        return Err("The runtime settings changed. Reopen Page browser settings before saving.");
    }
    if cancel.load(Ordering::Acquire) {
        return Err("Saving Page browser settings was cancelled.");
    }
    config
        .save()
        .map_err(|_| "The Page browser selection could not be saved privately.")
}
fn command(config: &RuntimeConfig, palette: &Path, address: &str) -> Result<Command, &'static str> {
    gui::page_links::Address::parse(address).ok_or("Invalid HyperNet Page address.")?;
    let mut command = Command::new(&config.suite);
    command
        .args(["network", "connect", "--profile"])
        .arg(
            config
                .page_browser_profile
                .as_ref()
                .unwrap_or(&config.network_profile),
        )
        .args(["--", "browse", "--gui", "--theme-file"])
        .arg(palette)
        .arg(address)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    Ok(command)
}
fn write_palette(path: &Path, bytes: &[u8]) -> Result<(), &'static str> {
    gui::theme::Palette::parse(bytes)?;
    match fs::symlink_metadata(path) {
        Ok(_) => {
            files::read(path, 16 * 1024).map_err(
                |_| "The browser theme file is not a private owned file; it was not replaced.",
            )?;
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err("The browser theme file is unavailable."),
    }
    native::replace_file(path, bytes)
        .map_err(|_| "The selected browser theme could not be saved privately.")
}
impl Browser {
    pub(super) fn cancel_pending(&mut self) {
        self.opening = None;
    }
    pub(super) fn open(
        &mut self,
        profile: &Path,
        request: gui::page_links::Request,
        ctx: &egui::Context,
    ) -> Result<(), &'static str> {
        if self.children.len() >= 4 {
            return Err(
                "Close a browser window before opening another Page; four windows are already open.",
            );
        }
        if self.opening.is_some() {
            return Err("A Page browser is already starting. Wait for its profile check.");
        }
        let profile = profile.to_owned();
        let active_readers: Vec<_> = self
            .children
            .iter()
            .map(|opened| opened.reader.clone())
            .collect();
        self.opening = Some(Job::start(ctx, move |cancel| {
            let config = configuration(&profile)?;
            reader_available(
                config
                    .page_browser_profile
                    .as_deref()
                    .unwrap_or(&config.network_profile),
                &active_readers,
            )?;
            crate::onboarding::prepare_reader(&config, cancel)
                .map_err(|_| "Page reader access could not be renewed. Close its existing browser and retry; the same reader identity is retained.")?;
            let network = validate(&config, cancel)?;
            let address = gui::page_links::Address::parse(&request.address)
                .ok_or("Invalid HyperNet Page address.")?;
            if address.network != network.network.as_hex() {
                return Err(
                    "This Page belongs to another network. Select a chat and reader profile for that network.",
                );
            }
            let palette = super::settings::directory()?.join("BrowserTheme.json");
            Ok(Launch {
                command: command(&config, &palette, &request.address)?,
                reader: config
                    .page_browser_profile
                    .unwrap_or(config.network_profile),
                palette,
                colours: request.palette,
            })
        })?);
        Ok(())
    }
    fn launch(&mut self, mut launch: Launch) -> Result<(), &'static str> {
        if self
            .children
            .iter()
            .any(|opened| opened.reader == launch.reader)
        {
            return Err(READER_BUSY);
        }
        write_palette(&launch.palette, &launch.colours)?;
        let child = launch
            .command
            .spawn()
            .map_err(|_| "The configured HyperNet browser could not start.")?;
        self.children.push(Opened {
            child,
            reader: launch.reader,
        });
        Ok(())
    }
    pub(super) fn poll(&mut self) -> Option<&'static str> {
        let mut error = None;
        self.children
            .retain_mut(|opened| match opened.child.try_wait() {
                Ok(Some(status)) => {
                    if !status.success() {
                        error = Some(FAILED);
                    }
                    false
                }
                Ok(None) => true,
                Err(_) => {
                    error = Some("The browser process status is unavailable.");
                    true
                }
            });
        if let Some(result) = self.opening.as_ref().and_then(Job::result) {
            self.opening = None;
            if let Err(failure) = result.and_then(|launch| self.launch(launch)) {
                error = Some(failure);
            }
        }
        error
    }
}

#[cfg(test)]
#[path = "../../Tests/Unit/DesktopBrowser.rs"]
mod tests;
