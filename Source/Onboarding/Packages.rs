// SPDX-License-Identifier: Apache-2.0
//! One reviewed coordinated-package entry before shared joining or hosting.
use super::simple::Job;
use crate::{gui::components, operations::bootstrap};
use eframe::egui;
use std::path::PathBuf;

enum Outcome {
    Preview(bootstrap::Preview),
    Ready(bootstrap::Tools),
}
pub(super) struct Form {
    pub release: String,
    review: Option<bootstrap::Preview>,
    tools: Option<bootstrap::Tools>,
    message: Option<String>,
    job: Option<Job<std::result::Result<Outcome, String>>>,
    initial_check: bool,
}
impl Form {
    pub fn new() -> Self {
        Self {
            release: bootstrap::supplied_directory()
                .unwrap_or_else(|| {
                    std::env::var_os("HOME")
                        .map(PathBuf::from)
                        .unwrap_or_default()
                        .join("Downloads")
                })
                .display()
                .to_string(),
            review: None,
            tools: None,
            message: None,
            job: None,
            initial_check: false,
        }
    }
    pub fn ready(&self) -> bool {
        self.tools.is_some() && self.job.is_none()
    }
    pub fn select(&mut self, path: PathBuf) {
        self.release = path.display().to_string();
        self.review = None;
    }
    fn start(
        &mut self,
        ctx: &egui::Context,
        work: impl FnOnce(&std::sync::atomic::AtomicBool) -> std::result::Result<Outcome, String>
        + Send
        + 'static,
    ) {
        self.message = None;
        self.job = Some(Job::start(ctx, move |stop| Ok(work(stop))));
    }
    pub fn logic(&mut self, ctx: &egui::Context, visible: bool) {
        if !self.initial_check && visible {
            self.initial_check = true;
            if bootstrap::directory().is_ok_and(|root| root.join("Installation.json").is_file()) {
                self.start(ctx, |stop| bootstrap::inspect(stop).map(Outcome::Ready));
            }
        }
        if let Some(result) = self.job.as_ref().and_then(Job::result) {
            self.job = None;
            match result {
                Ok(Ok(Outcome::Preview(review))) => self.review = Some(review),
                Ok(Ok(Outcome::Ready(tools))) => {
                    self.tools = Some(tools);
                    self.review = None;
                }
                Ok(Err(error)) => self.message = Some(error),
                Err(error) => self.message = Some(error.to_string()),
            }
        }
    }
    /// Returns a folder-picker request; execution remains off the paint thread.
    pub fn ui(&mut self, ui: &mut egui::Ui) -> bool {
        let ctx = ui.ctx().clone();
        let mut browse = false;
        if let Some(job) = &self.job {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Verifying or installing native tools…");
                if components::button(ui, "Cancel package setup").clicked() {
                    job.cancel();
                }
            });
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
        if let Some(message) = &self.message {
            ui.colored_label(ui.visuals().error_fg_color, message);
        }
        if self.tools.is_some() {
            ui.weak("The coordinated Core and Suite installation is verified.");
        } else {
            ui.label("Install the supplied native tools once before joining or hosting. Keys and network membership are created only when you continue.");
        }
        ui.add_enabled_ui(self.job.is_none(), |ui| {
            let title = if self.tools.is_some() {
                "Repair or change native installation"
            } else {
                "Install native tools"
            };
            egui::CollapsingHeader::new(title)
                .default_open(self.tools.is_none())
                .show(ui, |ui| {
                ui.label("Coordinated Packages folder");
                if ui.text_edit_singleline(&mut self.release).changed() {
                    self.review = None;
                }
                if components::button(ui, "Choose package folder…").clicked() {
                    browse = true;
                }
                ui.small("The release supplies Core and Suite together. Server links cannot choose packages or signing keys. No system packages or network services are started by this installation.");
                if components::button(ui, "Verify supplied packages").clicked() {
                    let release = PathBuf::from(&self.release);
                    self.start(&ctx, move |stop| {
                        bootstrap::preview(&release, stop).map(Outcome::Preview)
                    });
                }
                if let Some(review) = self.review.clone() {
                    ui.label(format!(
                        "Core {} and Suite {}",
                        review.core["version"].as_str().unwrap_or(""),
                        review.suite["version"].as_str().unwrap_or("")
                    ));
                    ui.add(egui::Label::new(format!("Private installation: {}", review.installation.display())).wrap());
                    if components::primary(ui, "Install verified native tools").clicked() {
                        self.start(&ctx, move |stop| {
                            bootstrap::install(&review, stop).map(Outcome::Ready)
                        });
                    }
                }
                if self.tools.is_some()
                    && components::button(ui, "Verify installed tools again").clicked()
                {
                    self.tools = None;
                    self.start(&ctx, |stop| bootstrap::inspect(stop).map(Outcome::Ready));
                }
            });
        });
        browse
    }
}
