// SPDX-License-Identifier: Apache-2.0
//! Explicit Page activation uses the selected profile's configured native Suite browser.
use crate::{
    gui,
    onboarding::{RuntimeConfig, native},
};
use hrc::{client, service::files};
use std::{
    fs,
    path::Path,
    process::{Child, Command, Stdio},
};

const SETUP: &str = "Configure this chat profile's Suite executable and joined network profile in Setup before opening Pages.";
const FAILED: &str = "The HyperNet browser could not complete this request. Check that the configured Suite supports Page themes and the selected network profile has a current Page route and reader permission.";

#[derive(Default)]
pub(super) struct Browser {
    children: Vec<Child>,
}
fn configuration(profile: &Path) -> Result<RuntimeConfig, &'static str> {
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
    native::executable(&config.suite)
        .map_err(|_| "Choose a trusted installed Suite executable in Setup.")?;
    files::read(&config.network_profile, 65536)
        .map_err(|_| "The configured joined network profile is unavailable or not private.")?;
    Ok(config)
}
fn command(config: &RuntimeConfig, palette: &Path, address: &str) -> Result<Command, &'static str> {
    gui::page_links::Address::parse(address).ok_or("Invalid HyperNet Page address.")?;
    let mut command = Command::new(&config.suite);
    command
        .args(["network", "connect", "--profile"])
        .arg(&config.network_profile)
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
    pub(super) fn open(
        &mut self,
        profile: &Path,
        request: gui::page_links::Request,
    ) -> Result<(), &'static str> {
        if self.children.len() >= 4 {
            return Err(
                "Close a browser window before opening another Page; four windows are already open.",
            );
        }
        let config = configuration(profile)?;
        let palette = super::settings::directory()?.join("BrowserTheme.json");
        let mut command = command(&config, &palette, &request.address)?;
        write_palette(&palette, &request.palette)?;
        let child = command
            .spawn()
            .map_err(|_| "The configured HyperNet browser could not start.")?;
        self.children.push(child);
        Ok(())
    }
    pub(super) fn poll(&mut self) -> Option<&'static str> {
        let mut error = None;
        self.children.retain_mut(|child| match child.try_wait() {
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
        error
    }
}

#[cfg(test)]
#[path = "../../Tests/Unit/DesktopBrowser.rs"]
mod tests;
