// SPDX-License-Identifier: Apache-2.0
//! Desktop lifecycle, profile selection and activation share one native event loop.
#[path = "Installation.rs"]
mod installation;
#[path = "Instance.rs"]
mod instance;
#[path = "Settings.rs"]
mod settings;
use crate::{gui, interaction::Model, onboarding};
use eframe::egui;
pub use installation::{BundleOptions, bundle, install};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::Duration,
};

pub const APPLICATION_ID: &str = "com.federatedindustrial.HyperNetRelayChat";

#[derive(Default, Clone, clap::Args, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Options {
    /// Open this encrypted endpoint profile; otherwise use the last selection.
    #[arg(long)]
    pub profile: Option<PathBuf>,
    /// Use retained history and drafts without making a connection.
    #[arg(long)]
    pub offline: bool,
    /// Open the profile chooser and guided setup.
    #[arg(long)]
    pub setup: bool,
}

pub fn run(options: Options) -> Result<(), &'static str> {
    let Some(instance) = instance::Instance::acquire(&options)? else {
        return Ok(());
    };
    let native = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("HyperNet Relay Chat")
            .with_app_id(APPLICATION_ID)
            .with_inner_size([1180.0, 800.0])
            .with_min_inner_size([640.0, 480.0]),
        centered: true,
        ..Default::default()
    };
    eframe::run_native(
        "HyperNet Relay Chat",
        native,
        Box::new(move |cc| {
            gui::theme::configure(&cc.egui_ctx, false, false, 1.0);
            let desktop = Desktop::new(instance, options, &cc.egui_ctx);
            // Synchronize native visibility before the first UI pass.
            if let Some(window) = cc.winit_window() {
                window.set_visible(true);
                window.set_minimized(false);
                window.request_redraw();
            }
            Ok(Box::new(desktop))
        }),
    )
    .map_err(|_| "GraphicalInterfaceUnavailable")
}

struct Opening {
    profile: PathBuf,
    cancel: Arc<AtomicBool>,
    receiver: mpsc::Receiver<Result<Model, String>>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Drop for Opening {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
struct Desktop {
    instance: instance::Instance,
    wizard: onboarding::Wizard,
    chat: Option<gui::App>,
    opening: Option<Opening>,
    profile: Option<PathBuf>,
    error: Option<String>,
    activation: Option<Options>,
    next_profile: Option<Options>,
    first_logic: bool,
    install_job: Option<mpsc::Receiver<Result<serde_json::Value, &'static str>>>,
    installed: bool,
}
impl Desktop {
    fn new(instance: instance::Instance, mut options: Options, ctx: &egui::Context) -> Self {
        if options.profile.is_none() {
            options.profile = settings::last_profile();
        }
        let mut app = Self {
            instance,
            wizard: onboarding::Wizard::new(options.profile.clone()),
            chat: None,
            opening: None,
            profile: options.profile.clone(),
            error: None,
            activation: None,
            next_profile: None,
            first_logic: true,
            install_job: None,
            installed: installation::is_installed(),
        };
        if !options.setup
            && let Some(profile) = options.profile
        {
            app.open(profile, options.offline, ctx);
        }
        app
    }
    fn open(&mut self, profile: PathBuf, offline: bool, ctx: &egui::Context) {
        if self.opening.is_some() {
            return;
        }
        self.error = None;
        let cancel = Arc::new(AtomicBool::new(false));
        let cancelled = Arc::clone(&cancel);
        let path = profile.clone();
        let wake = ctx.clone();
        let (sender, receiver) = mpsc::sync_channel(1);
        let worker = thread::Builder::new()
            .name("hrc-open-profile".into())
            .spawn(move || {
                let result = onboarding::prepare_existing(&path, offline, &cancelled)
                    .map_err(|e| e.to_string())
                    .and_then(|()| {
                        if cancelled.load(Ordering::Acquire) {
                            return Err("Opening cancelled".into());
                        }
                        Model::open(&path, offline).map_err(str::to_owned)
                    });
                let _ = sender.send(result);
                wake.request_repaint();
            });
        match worker {
            Ok(worker) => {
                self.opening = Some(Opening {
                    profile,
                    cancel,
                    receiver,
                    worker: Some(worker),
                })
            }
            Err(_) => self.error = Some("Profile worker unavailable".into()),
        }
    }
    fn show(&self, ctx: &egui::Context) {
        ctx.send_viewport_cmd(egui::ViewportCommand::Visible(true));
        ctx.send_viewport_cmd(egui::ViewportCommand::Minimized(false));
        ctx.send_viewport_cmd(egui::ViewportCommand::RequestPaintWhileHidden);
        ctx.send_viewport_cmd(egui::ViewportCommand::Focus);
        ctx.request_repaint();
    }
    fn setup(&mut self, ctx: &egui::Context) {
        self.chat = None;
        self.wizard = onboarding::Wizard::new(self.profile.clone());
        gui::theme::configure(ctx, false, false, 1.0);
    }
}
impl eframe::App for Desktop {
    fn logic(&mut self, ctx: &egui::Context, frame: &mut eframe::Frame) {
        if self.first_logic {
            self.show(ctx);
            self.first_logic = false;
        }
        for request in self.instance.requests() {
            self.show(ctx);
            if request.setup
                || request
                    .profile
                    .as_ref()
                    .is_some_and(|p| self.profile.as_ref() != Some(p))
            {
                self.activation = Some(request);
            } else if request.offline {
                if let Some(chat) = &mut self.chat {
                    chat.go_offline();
                } else if let Some(job) = &self.opening {
                    job.cancel.store(true, Ordering::Release);
                    self.next_profile = Some(Options {
                        profile: Some(job.profile.clone()),
                        ..request
                    });
                } else if let Some(profile) = self.profile.clone() {
                    self.open(profile, true, ctx);
                }
            }
        }
        let opened = self
            .opening
            .as_ref()
            .and_then(|job| match job.receiver.try_recv() {
                Ok(result) => Some(result),
                Err(mpsc::TryRecvError::Empty) => None,
                Err(mpsc::TryRecvError::Disconnected) => Some(Err("Profile worker stopped".into())),
            });
        if let Some(result) = opened {
            let job = self.opening.take().expect("opening result has its job");
            if !job.cancel.load(Ordering::Acquire) {
                match result {
                    Ok(model) => {
                        self.profile = Some(job.profile.clone());
                        if settings::remember_profile(&job.profile).is_err() {
                            self.error = Some("The profile opened, but its launcher preference could not be saved.".into());
                        }
                        self.chat = Some(gui::App::new(model, ctx));
                    }
                    Err(error) => self.error = Some(error),
                }
            }
        }
        if let Some(chat) = &mut self.chat {
            chat.logic(ctx, frame);
            if chat.ready_for_setup() {
                self.setup(ctx);
            }
        } else {
            self.wizard.logic(ctx);
            if let Some(selection) = self.wizard.take_open() {
                self.open(selection.profile, selection.offline, ctx);
            }
        }
        if self.chat.is_none()
            && self.opening.is_none()
            && let Some(request) = self.next_profile.take()
        {
            if let Some(profile) = request.profile {
                self.profile = Some(profile);
            }
            self.setup(ctx);
            if !request.setup
                && let Some(profile) = self.profile.clone()
            {
                self.open(profile, request.offline, ctx);
            }
        }
        if let Some(result) = self
            .install_job
            .as_ref()
            .and_then(|job| job.try_recv().ok())
        {
            self.install_job = None;
            match result {
                Ok(_) => self.installed = true,
                Err(error) => self.error = Some(error.into()),
            }
        }
        ctx.request_repaint_after(Duration::from_millis(100));
    }
    fn ui(&mut self, ui: &mut egui::Ui, frame: &mut eframe::Frame) {
        let ctx = ui.ctx().clone();
        if let Some(error) = self.error.clone() {
            egui::Panel::top("desktop-error").show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.colored_label(ui.visuals().error_fg_color, error);
                    if ui.button("Dismiss").clicked() {
                        self.error = None;
                    }
                });
            });
        }
        if let Some(chat) = &mut self.chat {
            chat.ui(ui, frame);
        } else {
            egui::Panel::top("desktop-setup-toolbar")
                .frame(gui::components::frame(ui))
                .show(ui, |ui| {
                    ui.horizontal(|ui| {
                        ui.strong("HRC");
                        ui.separator();
                        ui.label("Setup");
                        ui.with_layout(egui::Layout::right_to_left(egui::Align::Center), |ui| {
                            if self.installed {
                                gui::components::muted_badge(ui, "Launcher installed");
                            } else if self.install_job.is_some() {
                                ui.spinner();
                            } else if gui::components::button(ui, "Install launcher").clicked() {
                                let (sender, receiver) = mpsc::sync_channel(1);
                                let wake = ctx.clone();
                                thread::spawn(move || {
                                    let _ = sender.send(install());
                                    wake.request_repaint();
                                });
                                self.install_job = Some(receiver);
                            }
                        });
                    });
                });
            egui::CentralPanel::default()
                .frame(
                    egui::Frame::new()
                        .fill(ui.visuals().panel_fill)
                        .inner_margin(24),
                )
                .show(ui, |ui| {
                    if let Some(job) = &self.opening {
                        ui.vertical_centered(|ui| {
                            ui.add_space(ui.available_height() * 0.3);
                            ui.spinner();
                            ui.heading("Opening profile");
                            if gui::components::button(ui, "Cancel").clicked() {
                                job.cancel.store(true, Ordering::Release);
                            }
                        });
                    } else {
                        egui::ScrollArea::vertical().show(ui, |ui| self.wizard.ui(ui));
                    }
                });
        }
        if self.activation.is_some() {
            egui::Modal::new(egui::Id::unique("profile-activation")).show(&ctx, |ui| {
                ui.heading("Switch profile?");
                ui.label("The current draft will be saved before leaving this profile.");
                ui.horizontal(|ui| {
                    if gui::components::primary(ui, "Continue").clicked() {
                        let request = self.activation.take().expect("activation exists");
                        self.next_profile = Some(request);
                        if let Some(chat) = &mut self.chat {
                            chat.prepare_setup();
                        }
                    }
                    if gui::components::button(ui, "Cancel").clicked() {
                        self.activation = None;
                    }
                });
            });
        }
    }
}
