// SPDX-License-Identifier: Apache-2.0
//! One event-loop setup view; native work never runs on the paint thread.
use super::{
    Error, RuntimeConfig,
    runtime::{self, Completed, Task},
};
use crate::gui::components;
use eframe::egui;
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

pub struct Selection {
    pub profile: PathBuf,
    pub offline: bool,
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum Step {
    Simple,
    Existing,
    Runtime,
    PrivateInvitation,
    Network,
    Bundle,
    Connect,
    Endpoint,
    Activation,
}
impl Step {
    const ALL: [(Self, &'static str); 9] = [
        (Self::Simple, "Join a server"),
        (Self::Existing, "Open a profile"),
        (Self::Runtime, "Local runtime"),
        (Self::PrivateInvitation, "Private invitation"),
        (Self::Network, "Request access"),
        (Self::Bundle, "Import invitation"),
        (Self::Connect, "Connect network"),
        (Self::Endpoint, "Create your account"),
        (Self::Activation, "Enter chat"),
    ];
}
struct Job {
    cancel: Arc<AtomicBool>,
    receiver: mpsc::Receiver<super::Result<Completed>>,
    thread: Option<thread::JoinHandle<()>>,
    next: Option<Step>,
    reload_runtime: bool,
}
impl Drop for Job {
    fn drop(&mut self) {
        self.cancel.store(true, Ordering::Release);
        if let Some(thread) = self.thread.take() {
            let _ = thread.join();
        }
    }
}
#[derive(Clone, Copy)]
enum Pick {
    Profile,
    Configuration,
    SetupFolder,
    Bootstrap,
    Bundle,
    PrivateInvitation,
    Suite,
    Core,
    Chronyc,
    ChronySocket,
    Chronyd,
    ChronyConfig,
}
impl Pick {
    fn folder(self) -> bool {
        matches!(self, Self::Profile | Self::SetupFolder)
    }
}
struct Browser {
    purpose: Pick,
    path: PathBuf,
    entries: Vec<(PathBuf, bool)>,
}

pub struct Wizard {
    config: RuntimeConfig,
    location: String,
    saved: Vec<(PathBuf, String)>,
    step: Step,
    profile: String,
    configuration: String,
    folder: String,
    bootstrap: String,
    bootstrap_pin: String,
    bundle: String,
    bundle_pin: String,
    private_invitation: String,
    invitation_file: String,
    private_setup: bool,
    organisational_consent: bool,
    organisational: bool,
    notice: String,
    error: Option<Error>,
    export: Option<PathBuf>,
    job: Option<Job>,
    browser: Option<Browser>,
    open: Option<Selection>,
}
fn default_root() -> PathBuf {
    std::env::var_os("XDG_DATA_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .or_else(|| std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".local/share")))
        .unwrap_or_else(|| PathBuf::from("/"))
        .join("HyperNetRelayChat")
}
impl Wizard {
    pub fn new(initial_profile: Option<PathBuf>) -> Self {
        let base = default_root();
        let configuration = initial_profile
            .as_ref()
            .and_then(|p| p.parent())
            .map(|p| p.join("OnboardingRuntime.json"))
            .filter(|p| p.is_file())
            .unwrap_or_else(|| base.join("OnboardingRuntime.json"));
        let config =
            RuntimeConfig::load(&configuration).unwrap_or_else(|_| RuntimeConfig::at(base));
        let step = if initial_profile.is_some() {
            Step::Existing
        } else {
            Step::Simple
        };
        let profile = initial_profile
            .unwrap_or_else(|| config.hrc_profile.clone())
            .display()
            .to_string();
        Self {
            folder: config.data_directory.display().to_string(),
            config,
            configuration: configuration.display().to_string(),
            profile,
            step,
            location: String::new(),
            saved: Vec::new(),
            bootstrap: String::new(),
            bootstrap_pin: String::new(),
            bundle: String::new(),
            bundle_pin: String::new(),
            private_invitation: String::new(),
            invitation_file: String::new(),
            private_setup: false,
            organisational_consent: false,
            organisational: false,
            notice: String::new(),
            error: None,
            export: None,
            job: None,
            browser: None,
            open: None,
        }
    }
    pub(crate) fn saved_profiles(&mut self, profiles: Vec<PathBuf>) {
        self.saved = profiles
            .into_iter()
            .map(|profile| {
                let name = super::simple::load(&profile)
                    .ok()
                    .flatten()
                    .and_then(|b| b.name)
                    .map(|s| hrc::text::identity_display(&s))
                    .unwrap_or_else(|| profile.display().to_string());
                (profile, name)
            })
            .collect();
    }
    pub fn take_open(&mut self) -> Option<Selection> {
        self.open.take()
    }
    fn start(&mut self, ctx: &egui::Context, task: Task, next: Option<Step>) {
        if self.job.is_some() {
            return;
        }
        self.error = None;
        self.notice.clear();
        self.export = None;
        let config = self.config.clone();
        let reload_runtime = matches!(&task, Task::PrivateInvitation { .. });
        let cancel = Arc::new(AtomicBool::new(false));
        let worker_cancel = cancel.clone();
        let (sender, receiver) = mpsc::sync_channel(1);
        let ctx = ctx.clone();
        let thread = thread::spawn(move || {
            let result = runtime::perform(task, config, &worker_cancel);
            let _ = sender.send(result);
            ctx.request_repaint();
        });
        self.job = Some(Job {
            cancel,
            receiver,
            thread: Some(thread),
            next,
            reload_runtime,
        });
    }
    pub fn logic(&mut self, ctx: &egui::Context) {
        let outcome = self
            .job
            .as_ref()
            .and_then(|job| match job.receiver.try_recv() {
                Ok(result) => Some(result),
                Err(mpsc::TryRecvError::Disconnected) => Some(Err(Error::NativeRefused)),
                Err(mpsc::TryRecvError::Empty) => None,
            });
        if let Some(outcome) = outcome {
            let job = self.job.take().expect("completed setup has a job");
            let next = job.next;
            let reload_runtime = job.reload_runtime;
            drop(job);
            match outcome {
                Ok(done) => {
                    self.folder = done.config.data_directory.display().to_string();
                    self.config = done.config;
                    self.notice = done.notice.into();
                    self.export = done.export;
                    self.open = done.open;
                    if let Some((path, entries)) = done.listing
                        && let Some(browser) = &mut self.browser
                    {
                        browser.path = path;
                        browser.entries = entries;
                    }
                    if let Some(next) = next {
                        self.step = next;
                    }
                }
                Err(error) => {
                    if reload_runtime
                        && let Ok(saved) = RuntimeConfig::load(
                            &self.config.data_directory.join("OnboardingRuntime.json"),
                        )
                        && saved.data_directory == self.config.data_directory
                    {
                        self.config = saved;
                    }
                    self.error = Some(error);
                }
            }
        }
        if self.job.is_some() {
            ctx.request_repaint_after(Duration::from_millis(50));
        }
    }
    fn browse(&mut self, ctx: &egui::Context, purpose: Pick, value: &str) {
        let path = PathBuf::from(value);
        let path = if path.is_dir() {
            path
        } else {
            path.parent()
                .filter(|p| p.is_dir())
                .map(std::path::Path::to_owned)
                .or_else(|| std::env::var_os("HOME").map(PathBuf::from))
                .unwrap_or_else(|| PathBuf::from("/"))
        };
        self.browser = Some(Browser {
            purpose,
            path: path.clone(),
            entries: vec![],
        });
        self.start(ctx, Task::Browse(path), None);
    }
    fn choose(&mut self, purpose: Pick, path: PathBuf) {
        let text = path.display().to_string();
        match purpose {
            Pick::Profile => self.profile = text,
            Pick::Configuration => self.configuration = text,
            Pick::SetupFolder => self.folder = text,
            Pick::Bootstrap => self.bootstrap = text,
            Pick::Bundle => self.bundle = text,
            Pick::PrivateInvitation => self.invitation_file = text,
            Pick::Suite => self.config.suite = path,
            Pick::Core => self.config.core = path,
            Pick::Chronyc => self.config.chronyc = path,
            Pick::ChronySocket => self.config.chrony_socket = path,
            Pick::Chronyd => {
                if let Some(observer) = &mut self.config.private_chrony {
                    observer.executable = path;
                }
            }
            Pick::ChronyConfig => {
                if let Some(observer) = &mut self.config.private_chrony {
                    observer.configuration = path;
                }
            }
        }
        self.browser = None;
    }
    fn picker(&mut self, ctx: &egui::Context) {
        let Some(browser) = &self.browser else {
            return;
        };
        let purpose = browser.purpose;
        let path = browser.path.clone();
        let entries = browser.entries.clone();
        let mut visible = true;
        let mut directory = None;
        let mut selected = None;
        egui::Window::new("Choose a local file or folder")
            .id(egui::Id::unique("hrc-setup-picker"))
            .open(&mut visible)
            .collapsible(false)
            .resizable(true)
            .default_width(540.0)
            .show(ctx, |ui| {
                ui.label(path.display().to_string());
                ui.add_enabled_ui(self.job.is_none(), |ui| {
                    ui.horizontal(|ui| {
                        if components::button(ui, "Up").clicked() {
                            directory = path.parent().map(std::path::Path::to_owned);
                        }
                        if purpose.folder()
                            && components::button(ui, "Choose this folder").clicked()
                        {
                            selected = Some(path.clone());
                        }
                    });
                    egui::ScrollArea::vertical()
                        .max_height(340.0)
                        .show(ui, |ui| {
                            for (entry, is_directory) in &entries {
                                if purpose.folder() && !is_directory {
                                    continue;
                                }
                                let name = entry.file_name().unwrap_or_default().to_string_lossy();
                                let label = if *is_directory {
                                    format!("[Folder] {name}")
                                } else {
                                    name.into_owned()
                                };
                                if components::row(ui, false, &label).clicked() {
                                    if *is_directory {
                                        directory = Some(entry.clone());
                                    } else {
                                        selected = Some(entry.clone());
                                    }
                                }
                            }
                        });
                    if entries.len() == 256 {
                        ui.small("Showing up to 256 entries. Choose a narrower folder.");
                    }
                });
            });
        if !visible {
            self.browser = None;
        }
        if let Some(path) = selected {
            self.choose(purpose, path);
        } else if let Some(path) = directory {
            self.start(ctx, Task::Browse(path), None);
        }
    }
    pub fn ui(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        ui.heading("Welcome to HyperNet Relay Chat");
        ui.horizontal_wrapped(|ui| {
            for (step, label) in Step::ALL {
                if ui
                    .add_enabled(
                        self.job.is_none(),
                        egui::Button::new(label)
                            .selected(self.step == step)
                            .min_size(egui::vec2(
                                components::ACTION_WIDTH,
                                components::CONTROL_HEIGHT,
                            )),
                    )
                    .clicked()
                {
                    self.step = step;
                    self.error = None;
                }
            }
        });
        ui.separator();
        if let Some(error) = self.error {
            ui.colored_label(ui.visuals().error_fg_color, error.to_string());
        }
        if !self.notice.is_empty() {
            ui.label(&self.notice);
        }
        if let Some(path) = &self.export {
            ui.horizontal(|ui| {
                ui.label(path.display().to_string());
                if components::button(ui, "Copy path").clicked() {
                    ui.ctx().copy_text(path.display().to_string());
                }
            });
        }
        if let Some(job) = &self.job {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(if self.step == Step::Simple {
                    "Continue in the HyperNet join window. You can cancel here."
                } else {
                    "Working…"
                });
                if components::button(ui, "Cancel").clicked() {
                    job.cancel.store(true, Ordering::Release);
                }
            });
        }
        ui.add_enabled_ui(self.job.is_none(), |ui| match self.step {
            Step::Simple => {
                ui.label("Join using a server address, private link, or QR code. HyperNet will show the server and any password request before you connect.");
                ui.label("Server address or invitation link (optional)");
                ui.add(egui::TextEdit::singleline(&mut self.location).password(true).char_limit(8192).desired_width(f32::INFINITY));
                if components::primary(ui, "Continue to HyperNet").clicked() {
                    let location = (!self.location.trim().is_empty()).then(|| self.location.trim().to_owned());
                    self.start(&ctx, Task::SimpleJoin { location }, None);
                    self.location.clear();
                }
                ui.collapsing("Installed HyperNet tools", |ui| {
                    ui.label(self.config.suite.display().to_string());
                    if components::button(ui, "Choose HyperNetSuite…").clicked() {
                        self.browse(&ctx, Pick::Suite, &self.config.suite.display().to_string());
                    }
                });
                ui.small("Manual setup and existing private invitations remain available in the other setup tabs.");
            }
            Step::Existing => {
                if !self.saved.is_empty() {
                    ui.strong("Saved profiles");
                    for (profile,name) in self.saved.clone() {
                        if ui.selectable_label(self.profile == profile.display().to_string(), name).on_hover_text(profile.display().to_string()).clicked() {
                            self.profile = profile.display().to_string();
                        }
                    }
                    ui.separator();
                }
                ui.label("Profile folder");
                ui.horizontal(|ui| {
                    ui.text_edit_singleline(&mut self.profile);
                    if components::button(ui, "Browse…").clicked() {
                        self.browse(&ctx, Pick::Profile, &self.profile.clone());
                    }
                });
                ui.horizontal_wrapped(|ui| {
                    if components::primary(ui, "Open chat").clicked() {
                        self.start(
                            &ctx,
                            Task::Existing {
                                profile: self.profile.clone().into(),
                                offline: false,
                            },
                            None,
                        );
                    }
                    if components::button(ui, "Open offline").clicked() {
                        self.start(
                            &ctx,
                            Task::Existing {
                                profile: self.profile.clone().into(),
                                offline: true,
                            },
                            None,
                        );
                    }
                    if components::button(ui, "New profile").clicked() {
                        self.private_setup = false;
                        self.step = Step::Runtime;
                    }
                    if ui.add(egui::Button::new("Join with a private invitation")
                        .min_size(egui::vec2(components::ACTION_WIDTH, components::CONTROL_HEIGHT))).clicked() {
                        self.private_setup = true;
                        self.step = Step::Runtime;
                    }
                });
            }
            Step::Runtime => self.runtime_ui(ui, &ctx),
            Step::PrivateInvitation => {
                ui.label("Paste the private invitation supplied by your host, or choose its text file.");
                ui.add(egui::TextEdit::multiline(&mut self.private_invitation).char_limit(65536).desired_rows(3).desired_width(f32::INFINITY));
                ui.horizontal(|ui| {
                    ui.text_edit_singleline(&mut self.invitation_file);
                    if components::button(ui, "Choose invitation file…").clicked() {
                        self.browse(&ctx, Pick::PrivateInvitation, &self.invitation_file.clone());
                    }
                    if components::button(ui, "Clear file").clicked() { self.invitation_file.clear(); }
                });
                ui.small("Keep this invitation private. Keys are generated on this computer. Its host admits your ordinary chat account and, when available, a separate read-only Page reader.");
                ui.checkbox(&mut self.organisational_consent, "Accept this host operating both relay and service, and automatic access renewal within this invitation's existing limits");
                if self.config.self_service.is_some() {
                    ui.label("An invitation is retained in this setup folder. Leave both fields empty to resume it with the same keys.");
                }
                if ui.add_enabled(self.organisational_consent, egui::Button::new("Join or resume invitation")).clicked() {
                    self.start(&ctx, Task::PrivateInvitation {
                        text: self.private_invitation.clone(),
                        file: (!self.invitation_file.trim().is_empty()).then(|| self.invitation_file.trim().into()),
                    }, None);
                    self.private_invitation.clear();
                }
            }
            Step::Network => {
                ui.label("Network bootstrap");
                ui.horizontal(|ui| {
                    ui.text_edit_singleline(&mut self.bootstrap);
                    if components::button(ui, "Browse…").clicked() {
                        self.browse(&ctx, Pick::Bootstrap, &self.bootstrap.clone());
                    }
                });
                ui.label("Fingerprint confirmed with the operator");
                ui.text_edit_singleline(&mut self.bootstrap_pin);
                ui.checkbox(
                    &mut self.organisational,
                    "Accept one organisation operating both relay and service",
                );
                if components::primary(ui, "Create request").clicked() {
                    self.start(
                        &ctx,
                        Task::Prepare {
                            bootstrap: self.bootstrap.clone().into(),
                            fingerprint: self.bootstrap_pin.trim().into(),
                            organisational: self.organisational,
                        },
                        Some(Step::Bundle),
                    );
                }
            }
            Step::Bundle => {
                ui.label("Operator setup bundle");
                ui.horizontal(|ui| {
                    ui.text_edit_singleline(&mut self.bundle);
                    if components::button(ui, "Browse…").clicked() {
                        self.browse(&ctx, Pick::Bundle, &self.bundle.clone());
                    }
                });
                ui.label("Bundle SHA-256 confirmed with the operator");
                ui.text_edit_singleline(&mut self.bundle_pin);
                if components::button(ui, "Verify and import").clicked() {
                    self.start(
                        &ctx,
                        Task::Import {
                            path: self.bundle.clone().into(),
                            fingerprint: self.bundle_pin.trim().into(),
                        },
                        Some(Step::Connect),
                    );
                }
            }
            Step::Connect => {
                ui.label("Join the approved network and start your local companion.");
                if components::primary(ui, "Connect").clicked() {
                    self.start(&ctx, Task::Connect, Some(Step::Endpoint));
                }
            }
            Step::Endpoint => {
                ui.label("Your endpoint and recovery keys stay on this computer.");
                ui.label(format!(
                    "Recovery key: {}",
                    self.config.recovery_key.display()
                ));
                if components::primary(ui, "Create account").clicked() {
                    self.start(&ctx, Task::CreateEndpoint, Some(Step::Activation));
                }
            }
            Step::Activation => {
                ui.label("Waiting for the service operator to enrol your signed registration.");
                ui.label(self.config.registration_file.display().to_string());
                ui.horizontal(|ui| {
                    if components::button(ui, "Copy path").clicked() {
                        ui.ctx()
                            .copy_text(self.config.registration_file.display().to_string());
                    }
                    if components::button(ui, "Check activation").clicked() {
                        self.start(&ctx, Task::Verify, None);
                    }
                    if components::button(ui, "Open offline").clicked() {
                        self.start(
                            &ctx,
                            Task::Existing {
                                profile: self.config.hrc_profile.clone(),
                                offline: true,
                            },
                            None,
                        );
                    }
                });
            }
        });
        self.picker(&ctx);
    }
    fn runtime_ui(&mut self, ui: &mut egui::Ui, ctx: &egui::Context) {
        ui.label("Private setup folder");
        ui.horizontal(|ui| {
            ui.text_edit_singleline(&mut self.folder);
            if components::button(ui, "Browse…").clicked() {
                self.browse(ctx, Pick::SetupFolder, &self.folder.clone());
            }
            if components::button(ui, "Use folder").clicked() {
                self.config = RuntimeConfig::at(self.folder.clone().into());
                self.configuration = self
                    .config
                    .data_directory
                    .join("OnboardingRuntime.json")
                    .display()
                    .to_string();
            }
        });
        ui.collapsing("Existing runtime configuration", |ui| {
            ui.horizontal(|ui| {
                ui.text_edit_singleline(&mut self.configuration);
                if components::button(ui, "Browse…").clicked() {
                    self.browse(ctx, Pick::Configuration, &self.configuration.clone());
                }
                if components::button(ui, "Load").clicked() {
                    match RuntimeConfig::load(&PathBuf::from(&self.configuration)) {
                        Ok(config) => {
                            self.folder = config.data_directory.display().to_string();
                            self.config = config;
                            self.error = None;
                        }
                        Err(error) => self.error = Some(error),
                    }
                }
            });
        });
        ui.collapsing("Installed tools and local clock", |ui| {
            let mut selection = None;
            for (label, purpose, path) in [
                ("HyperNetSuite", Pick::Suite, &mut self.config.suite),
                ("HyperNet", Pick::Core, &mut self.config.core),
                ("chronyc", Pick::Chronyc, &mut self.config.chronyc),
                (
                    "Chrony socket",
                    Pick::ChronySocket,
                    &mut self.config.chrony_socket,
                ),
            ] {
                ui.label(label);
                let mut value = path.display().to_string();
                ui.horizontal(|ui| {
                    if ui.text_edit_singleline(&mut value).changed() {
                        *path = value.clone().into();
                    }
                    if components::button(ui, &format!("Choose {label}…")).clicked() {
                        selection = Some((purpose, value));
                    }
                });
            }
            let mut private = self.config.private_chrony.is_some();
            if ui
                .checkbox(&mut private, "Restart my private clock observer")
                .changed()
            {
                self.config.private_chrony = private.then(|| super::PrivateChrony {
                    executable: super::native::discover("chronyd"),
                    configuration: self.config.data_directory.join("Chrony/chrony.conf"),
                });
            }
            if let Some(observer) = &mut self.config.private_chrony {
                ui.small("Uses your existing private configuration. System time is never changed.");
                for (label, purpose, path) in [
                    ("chronyd", Pick::Chronyd, &mut observer.executable),
                    (
                        "Private configuration",
                        Pick::ChronyConfig,
                        &mut observer.configuration,
                    ),
                ] {
                    ui.label(label);
                    let mut value = path.display().to_string();
                    ui.horizontal(|ui| {
                        if ui.text_edit_singleline(&mut value).changed() {
                            *path = value.clone().into();
                        }
                        if components::button(ui, "Browse…").clicked() {
                            selection = Some((purpose, value));
                        }
                    });
                }
            }
            if let Some((purpose, value)) = selection {
                self.browse(ctx, purpose, &value);
            }
        });
        ui.horizontal(|ui| {
            if components::button(ui, "Check installed tools").clicked() {
                self.start(ctx, Task::Preflight, None);
            }
            if components::button(ui, "Start local clock").clicked() {
                self.start(
                    ctx,
                    Task::StartClock,
                    Some(if self.private_setup {
                        Step::PrivateInvitation
                    } else {
                        Step::Network
                    }),
                );
            }
            if components::button(ui, "Use current clock").clicked() {
                self.step = if self.private_setup {
                    Step::PrivateInvitation
                } else {
                    Step::Network
                };
            }
        });
    }
}
