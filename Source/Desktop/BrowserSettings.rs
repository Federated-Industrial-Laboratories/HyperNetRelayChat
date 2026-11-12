// SPDX-License-Identifier: Apache-2.0
//! Per-chat Page reader selection uses normal native inspection and private runtime persistence.
use super::{browser, operations::picker::Picker};
use crate::gui::components as c;
use eframe::egui;
use serde_json::Value;
use std::path::{Path, PathBuf};

#[derive(Default)]
pub(super) struct Settings {
    visible: bool,
    simple: Option<crate::onboarding::simple::Binding>,
    profile: Option<PathBuf>,
    expected: Option<Value>,
    separate: bool,
    reader: String,
    picker: Picker,
    saving: Option<browser::Job<()>>,
    message: Option<&'static str>,
}
impl Settings {
    pub(super) fn close(&mut self) {
        // Dropping the save job settles its final write before another runtime snapshot loads.
        *self = Self::default();
    }
    pub(super) fn open(&mut self, profile: &Path) {
        self.saving = None;
        self.visible = true;
        self.profile = Some(profile.to_owned());
        self.expected = None;
        self.reader.clear();
        self.message = None;
        self.picker = Picker::default();
        self.simple = crate::onboarding::simple::load(profile).ok().flatten();
        if self.simple.is_some() {
            return;
        }
        match browser::configuration(profile) {
            Ok(config) => {
                self.separate = config.page_browser_profile.is_some();
                if let Some(path) = &config.page_browser_profile {
                    self.reader = path.display().to_string();
                }
                self.expected = serde_json::to_value(config).ok();
            }
            Err(error) => self.message = Some(error),
        }
    }
    pub(super) fn logic(&mut self, current: Option<&Path>) {
        if self.visible && current != self.profile.as_deref() {
            self.close();
            return;
        }
        if let Some(result) = self.saving.as_ref().and_then(browser::Job::result) {
            self.saving = None;
            self.message = Some(match result {
                Ok(()) => {
                    self.expected = self
                        .profile
                        .as_deref()
                        .and_then(|profile| browser::configuration(profile).ok())
                        .and_then(|config| serde_json::to_value(config).ok());
                    "Page browser settings saved for this chat profile. Existing browser windows keep their current profile."
                }
                Err(error) => error,
            });
        }
    }
    pub(super) fn ui(&mut self, ctx: &egui::Context) {
        if !self.visible {
            return;
        }
        let mut visible = true;
        if let Some(selected) = self.picker.take("page-reader") {
            self.reader = selected.display().to_string();
        }
        egui::Window::new("Page browser settings")
            .id(egui::Id::unique("page-browser-settings"))
            .open(&mut visible)
            .default_width(660.0)
            .resizable(true)
            .show(ctx, |ui| {
                if let Some(binding) = &self.simple {
                    ui.label("HyperNet manages this saved server's separate Page reader.");
                    if let Some(profile) = &binding.page_profile {
                        ui.add(egui::Label::new(profile.display().to_string()).wrap().selectable(true));
                        ui.small("Page links reuse this reader's browser window while chat stays connected. An active form is kept until you choose to leave its page.");
                    } else { ui.label("This server has not provided a Page reader."); }
                    return;
                }
                ui.label("A separate reader profile lets native Page links open while chat stays connected.");
                ui.small("Complete normal native reader admission first. This setting selects its private Profile.json; it does not create membership, copy keys or grant Page access.");
                if let Some(profile) = &self.profile {
                    ui.label(format!("Chat profile: {}", profile.display()));
                }
                if let Some(message) = self.message { ui.label(message); }
                ui.add_enabled_ui(self.saving.is_none() && self.expected.is_some(), |ui| {
                    ui.checkbox(&mut self.separate, "Use a separately admitted Page reader");
                    if self.separate {
                        ui.label("Reader network profile");
                        ui.horizontal(|ui| {
                            ui.add(egui::TextEdit::singleline(&mut self.reader)
                                .desired_width((ui.available_width() - 144.0).max(100.0)));
                            if c::button(ui, "Browse…").clicked() {
                                self.picker.open("page-reader", Path::new(&self.reader), false);
                            }
                        });
                    } else {
                        ui.label("Default: use this chat's network profile. Its companion must be stopped before the native browser can use it.");
                    }
                    ui.small("The reader must be joined to the same network with different client, device and relay identities. Close its existing browser before opening another Page.");
                    if c::primary(ui, "Check and save").clicked() {
                        let profile = self.profile.clone().expect("loaded settings have a profile");
                        let expected = self.expected.clone().expect("save is enabled only after load");
                        let reader = self.separate.then(|| PathBuf::from(self.reader.trim()));
                        self.message = None;
                        match browser::Job::start(ctx, move |cancel| browser::save_selection(&profile, reader, &expected, cancel)) {
                            Ok(job) => self.saving = Some(job),
                            Err(error) => self.message = Some(error),
                        }
                    }
                });
                if self.saving.is_some() {
                    ui.horizontal(|ui| {
                        ui.spinner();
                        ui.label("Inspecting local profile and saving…");
                        if c::button(ui, "Cancel").clicked() {
                            self.saving = None;
                            self.message = Some("Check cancelled. Reopen settings to inspect the retained selection.");
                        }
                    });
                }
            });
        self.picker.show(ctx);
        if !visible {
            self.close();
        }
    }
}

#[cfg(test)]
#[path = "../../Tests/Unit/DesktopBrowserSettings.rs"]
mod tests;
