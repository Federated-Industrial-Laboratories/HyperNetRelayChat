// SPDX-License-Identifier: Apache-2.0
//! Desktop operator workspace; bounded background jobs keep the conversation responsive.
#[path = "Assistant.rs"]
mod assistant_ui;
#[path = "Models.rs"]
mod models_ui;
#[path = "Network.rs"]
mod network_ui;
#[path = "Packages.rs"]
mod packages_ui;
#[path = "Picker.rs"]
mod picker;
#[path = "Service.rs"]
mod service_ui;
use crate::{assistant, gui::components as c, operations as ops};
use eframe::egui;
use serde_json::Value;
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
};

#[derive(Clone, Copy, PartialEq)]
enum Page {
    Network,
    Service,
    Models,
    Bots,
    Assistant,
    Packages,
}
#[derive(Clone, Copy)]
enum Completion {
    General,
    NetworkPreview,
    NetworkStatus,
    RenewalPreview,
    AssistantPreview,
    ModelSaved,
    BotSaved,
    BotRooms,
    PackagePreview,
    PackageInstalled,
}
struct Job {
    label: String,
    cancel: Arc<AtomicBool>,
    receiver: mpsc::Receiver<ops::Result<Value>>,
    completion: Completion,
    worker: Option<thread::JoinHandle<()>>,
}
impl Drop for Job {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
pub(super) struct Workspace {
    pub visible: bool,
    pub join_requested: bool,
    pub open_profile: Option<PathBuf>,
    page: Page,
    job: Option<Job>,
    error: Option<String>,
    result: Option<Value>,
    picker: picker::Picker,
    network: network_ui::Form,
    service: service_ui::Form,
    model: models_ui::ModelForm,
    bot: models_ui::BotForm,
    assistant: assistant_ui::Form,
    packages: packages_ui::Form,
}
impl Default for Workspace {
    fn default() -> Self {
        Self {
            visible: false,
            join_requested: false,
            open_profile: None,
            page: Page::Network,
            job: None,
            error: None,
            result: None,
            picker: picker::Picker::default(),
            network: network_ui::Form::new(),
            service: service_ui::Form::default(),
            model: models_ui::ModelForm::new(),
            bot: models_ui::BotForm::new(),
            assistant: assistant_ui::Form::default(),
            packages: packages_ui::Form::default(),
        }
    }
}
impl Workspace {
    fn start(
        &mut self,
        ctx: &egui::Context,
        label: &str,
        completion: Completion,
        operation: impl FnOnce(&AtomicBool) -> ops::Result<Value> + Send + 'static,
    ) {
        if self.job.is_some() {
            return;
        }
        self.error = None;
        self.result = None;
        let cancel = Arc::new(AtomicBool::new(false));
        let stopped = cancel.clone();
        let wake = ctx.clone();
        let (tx, receiver) = mpsc::sync_channel(1);
        match thread::Builder::new()
            .name("hrc-operations".into())
            .spawn(move || {
                let result = operation(&stopped);
                let _ = tx.send(result);
                wake.request_repaint();
            }) {
            Ok(worker) => {
                self.job = Some(Job {
                    label: label.into(),
                    cancel,
                    receiver,
                    completion,
                    worker: Some(worker),
                })
            }
            Err(_) => self.error = Some("The operation worker could not start.".into()),
        }
    }
    pub fn logic(&mut self, ctx: &egui::Context) {
        let result = self
            .job
            .as_ref()
            .and_then(|job| match job.receiver.try_recv() {
                Ok(v) => Some(v),
                Err(mpsc::TryRecvError::Empty) => None,
                Err(_) => Some(Err("The operation worker stopped.".into())),
            });
        if let Some(result) = result {
            let job = self.job.take().expect("job result");
            match result {
                Err(error) => self.error = Some(error),
                Ok(value) => {
                    match job.completion {
                        Completion::NetworkPreview => {
                            self.network.preview = serde_json::from_value(value.clone()).ok()
                        }
                        Completion::NetworkStatus => {
                            self.network.status = serde_json::from_value(value.clone()).ok();
                            if let Some(status) = &self.network.status {
                                self.service.config =
                                    ops::home::Configuration::at(status.service_directory.clone());
                            }
                        }
                        Completion::RenewalPreview => {
                            if let Some(until) = value["validUntilMs"].as_u64() {
                                self.network.renew_until = until;
                                self.network.renewal = Some(value.clone());
                            } else {
                                self.network.renewal = None;
                                self.error = Some("The retained renewal review is invalid.".into());
                            }
                        }
                        Completion::AssistantPreview => {
                            self.assistant.preview = Some(value.clone())
                        }
                        Completion::ModelSaved => {
                            self.model.refresh();
                            self.bot.refresh();
                        }
                        Completion::BotSaved => self.bot.refresh(),
                        Completion::BotRooms => {
                            if let Err(error) = self.bot.receive_rooms(&value) {
                                self.error = Some(error);
                            }
                        }
                        Completion::PackagePreview => self.packages.preview = Some(value.clone()),
                        Completion::PackageInstalled => self.network.installed(&value),
                        Completion::General => {}
                    }
                    self.result = Some(value);
                }
            }
        }
        if self.job.is_some() {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
        if ctx.input(|i| i.viewport().close_requested())
            && let Some(job) = &self.job
        {
            job.cancel.store(true, Ordering::Release);
            ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
        }
    }
    pub fn ui(&mut self, ui: &mut egui::Ui) {
        egui::Panel::top("operations-toolbar")
            .frame(c::frame(ui))
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.strong("HRC / Operations");
                    ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                        if c::button(ui, "Back to chat").clicked() {
                            self.visible = false;
                        }
                    });
                })
            });
        egui::Panel::left("operations-navigation")
            .resizable(false)
            .exact_size(180.0)
            .show(ui, |ui| {
                ui.add_space(10.0);
                for (page, label) in [
                    (Page::Network, "HyperNets"),
                    (Page::Service, "HRC service"),
                    (Page::Models, "Local models"),
                    (Page::Bots, "Bots"),
                    (Page::Assistant, "External assistant"),
                    (Page::Packages, "Native packages"),
                ] {
                    if c::row(ui, self.page == page, label).clicked() {
                        self.page = page;
                        self.result = None;
                        self.error = None;
                    }
                }
                ui.separator();
                c::muted_badge(ui, "This computer");
            });
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .inner_margin(18)
                    .fill(ui.visuals().panel_fill),
            )
            .show(ui, |ui| {
                if let Some(job) = &self.job {
                    c::section(ui, &job.label, |ui| {
                        ui.horizontal(|ui| {
                            ui.spinner();
                            if matches!(job.completion, Completion::NetworkStatus)
                                && c::button(ui, "Current step").clicked()
                            {
                                match self.network.progress() {
                                    Ok(phase) => {
                                        self.result = Some(serde_json::json!({"phase":phase}))
                                    }
                                    Err(error) => self.error = Some(error),
                                }
                            }
                            if c::button(ui, "Cancel").clicked() {
                                job.cancel.store(true, Ordering::Release);
                            }
                        });
                    });
                }
                if let Some(error) = &self.error {
                    c::section(ui, "Operation refused", |ui| {
                        ui.colored_label(ui.visuals().error_fg_color, error);
                    });
                }
                egui::ScrollArea::vertical().show(ui, |ui| {
                    ui.add_enabled_ui(self.job.is_none(), |ui| match self.page {
                        Page::Network => self.network_ui(ui),
                        Page::Service => self.service_ui(ui),
                        Page::Models => self.models_ui(ui),
                        Page::Bots => self.bots_ui(ui),
                        Page::Assistant => self.assistant_ui(ui),
                        Page::Packages => self.packages_ui(ui),
                    });
                    if let Some(value) = &self.result {
                        result(ui, value);
                    }
                });
            });
        self.picker.show(ui.ctx());
    }
}
fn field(ui: &mut egui::Ui, label: &str, value: &mut String) {
    ui.horizontal(|ui| {
        ui.add_sized(
            [148.0, c::CONTROL_HEIGHT],
            egui::Label::new(label).halign(egui::Align::Min),
        );
        ui.add_sized(
            [ui.available_width(), c::CONTROL_HEIGHT],
            egui::TextEdit::singleline(value),
        );
    });
}
fn path(
    ui: &mut egui::Ui,
    label: &str,
    value: &mut PathBuf,
    picker: &mut picker::Picker,
    id: &'static str,
    folder: bool,
) {
    if let Some(selected) = picker.take(id) {
        *value = selected;
    }
    ui.horizontal(|ui| {
        ui.add_sized(
            [148.0, c::CONTROL_HEIGHT],
            egui::Label::new(label).halign(egui::Align::Min),
        );
        let mut text = value.to_string_lossy().into_owned();
        if ui
            .add_sized(
                [
                    (ui.available_width() - c::ACTION_WIDTH - 8.0).max(80.0),
                    c::CONTROL_HEIGHT,
                ],
                egui::TextEdit::singleline(&mut text),
            )
            .changed()
        {
            *value = text.into();
        }
        if c::button(ui, "Browse…").clicked() {
            picker.open(id, value, folder);
        }
    });
}
fn limits(ui: &mut egui::Ui, value: &mut ops::units::Limits) {
    ui.horizontal(|ui| {
        ui.label("Memory (MiB)");
        ui.add(egui::DragValue::new(&mut value.memory_mib).range(128..=131072));
        ui.label("CPU (%)");
        ui.add(egui::DragValue::new(&mut value.cpu_percent).range(10..=6400));
    });
    ui.horizontal(|ui| {
        ui.label("Process isolation");
        ui.selectable_value(
            &mut value.security,
            ops::units::Security::Standard,
            "Standard",
        );
        ui.selectable_value(
            &mut value.security,
            ops::units::Security::Restricted,
            "Restricted",
        );
    });
    if value.security == ops::units::Security::Restricted {
        ui.small("Requires user namespace support. System directories are read-only; GPU and network access remain available.");
    }
}
fn result(ui: &mut egui::Ui, value: &Value) {
    c::section(ui, "Result", |ui| {
        for key in [
            "status",
            "state",
            "phase",
            "name",
            "ready",
            "active",
            "managed",
            "initialConnectionVerified",
            "pid",
            "exitCode",
            "expiresMs",
            "file",
            "bundle",
            "fingerprint",
            "registrationPending",
            "applied",
            "can_apply",
        ] {
            if let Some(value) = value.get(key).filter(|v| !v.is_null()) {
                let text = value
                    .as_str()
                    .map(str::to_owned)
                    .unwrap_or_else(|| value.to_string());
                ui.horizontal_wrapped(|ui| {
                    ui.weak(key);
                    ui.add(egui::Label::new(egui::RichText::new(text).monospace()).wrap());
                });
            }
        }
        if let Some(runtime) = value.get("runtime").filter(|v| v.is_object()) {
            result(ui, runtime);
        }
    });
}
