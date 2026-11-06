// SPDX-License-Identifier: Apache-2.0
//! Local model and bot forms share the native management definitions and lifecycle.
use super::*;
use hrc::protocol::{Id, RoomId};

pub(super) struct ModelForm {
    config: Option<ops::models::Config>,
    saved: Option<Value>,
    entries: Vec<ops::models::Summary>,
    endpoint: String,
    error: Option<String>,
}
impl ModelForm {
    pub fn new() -> Self {
        let mut form = Self {
            config: None,
            saved: None,
            entries: Vec::new(),
            endpoint: String::new(),
            error: None,
        };
        match ops::models::Config::new() {
            Ok(config) => form.adopt(config, false),
            Err(error) => form.error = Some(error),
        }
        let creation_error = form.error.take();
        form.refresh();
        if creation_error.is_some() {
            form.error = creation_error;
        }
        form
    }
    fn adopt(&mut self, config: ops::models::Config, saved: bool) {
        self.endpoint = config.endpoint.to_string();
        self.error = None;
        self.saved = if saved {
            match serde_json::to_value(&config) {
                Ok(value) => Some(value),
                Err(error) => {
                    self.error = Some(error.to_string());
                    None
                }
            }
        } else {
            None
        };
        self.config = Some(config);
    }
    fn value(&self) -> ops::Result<ops::models::Config> {
        let mut config = self
            .config
            .clone()
            .ok_or("Create a model definition first.")?;
        config.endpoint = self.endpoint.parse().map_err(|_| {
            "Enter a loopback IP address and port, such as 127.0.0.1:8080.".to_owned()
        })?;
        Ok(config)
    }
    fn unchanged(&self) -> bool {
        self.value()
            .and_then(|v| serde_json::to_value(v).map_err(ops::failure))
            .ok()
            .as_ref()
            == self.saved.as_ref()
            && self.saved.is_some()
    }
    pub fn refresh(&mut self) {
        match ops::models::list() {
            Ok(entries) => {
                self.entries = entries;
                self.error = None;
            }
            Err(error) => {
                self.error = Some(error);
                return;
            }
        }
        if let Ok(config) = self.value()
            && self.entries.iter().any(|entry| entry.id == config.id)
        {
            match ops::models::load(config.id)
                .and_then(|v| serde_json::to_value(v).map_err(ops::failure))
            {
                Ok(value) => self.saved = Some(value),
                Err(error) => self.error = Some(error),
            }
        }
    }
}

#[derive(Default)]
struct PreparationForm {
    connection_profile: PathBuf,
    invitation: PathBuf,
    service_key: String,
    recovery: PathBuf,
    registration: PathBuf,
    companion: PathBuf,
    clock_observation: PathBuf,
    clock_key: String,
}
pub(super) struct BotForm {
    config: Option<ops::bots::Config>,
    saved: Option<Value>,
    entries: Vec<ops::bots::Summary>,
    models: Vec<ops::models::Summary>,
    rooms: String,
    available_rooms: Vec<hrc::conversations::Summary>,
    grant: String,
    preparation: PreparationForm,
    resynchronise: bool,
    error: Option<String>,
}
impl BotForm {
    pub fn new() -> Self {
        let mut form = Self {
            config: None,
            saved: None,
            entries: Vec::new(),
            models: Vec::new(),
            rooms: String::new(),
            available_rooms: Vec::new(),
            grant: String::new(),
            preparation: PreparationForm::default(),
            resynchronise: false,
            error: None,
        };
        match ops::bots::Config::new() {
            Ok(config) => form.adopt(config, false),
            Err(error) => form.error = Some(error),
        }
        let creation_error = form.error.take();
        form.refresh();
        if creation_error.is_some() {
            form.error = creation_error;
        }
        form
    }
    fn adopt(&mut self, config: ops::bots::Config, saved: bool) {
        self.available_rooms.clear();
        let directory = ops::root().join("AgentEndpoints").join(config.id.as_hex());
        self.preparation = PreparationForm {
            connection_profile: super::super::settings::last_profile().unwrap_or_default(),
            recovery: directory.join("Recovery.key"),
            registration: directory.join("Registration.json"),
            ..PreparationForm::default()
        };
        let mut config = config;
        if config.profile.as_os_str().is_empty() {
            config.profile = directory.join("Profile");
        }
        self.rooms = config
            .rooms
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("\n");
        self.grant = config.grant.map(|id| id.as_hex()).unwrap_or_default();
        self.error = None;
        self.saved = if saved {
            match serde_json::to_value(&config) {
                Ok(value) => Some(value),
                Err(error) => {
                    self.error = Some(error.to_string());
                    None
                }
            }
        } else {
            None
        };
        self.config = Some(config);
        self.resynchronise = false;
    }
    fn value(&self) -> ops::Result<ops::bots::Config> {
        let mut config = self
            .config
            .clone()
            .ok_or("Create a bot definition first.")?;
        config.rooms = self
            .rooms
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                line.trim()
                    .parse::<RoomId>()
                    .map_err(|_| "Enter complete room identifiers, one per line.".to_owned())
            })
            .collect::<ops::Result<Vec<_>>>()?;
        config.grant =
            if self.grant.trim().is_empty() {
                None
            } else {
                Some(self.grant.trim().parse().map_err(|_| {
                    "Enter a valid delegation identifier or leave it empty.".to_owned()
                })?)
            };
        Ok(config)
    }
    fn unchanged(&self) -> bool {
        self.value()
            .and_then(|v| serde_json::to_value(v).map_err(ops::failure))
            .ok()
            .as_ref()
            == self.saved.as_ref()
            && self.saved.is_some()
    }
    fn preparation(&self) -> ops::Result<ops::bots::Preparation> {
        let config = self
            .config
            .as_ref()
            .ok_or("Create a bot definition first.")?;
        Ok(ops::bots::Preparation {
            invitation: self.preparation.invitation.clone(),
            trusted_service_key: self.preparation.service_key.trim().parse().map_err(|_| {
                "Enter the independently accepted HRC service public key.".to_owned()
            })?,
            profile: config.profile.clone(),
            recovery_key: self.preparation.recovery.clone(),
            registration: self.preparation.registration.clone(),
            companion: self.preparation.companion.clone(),
            clock_observation: self.preparation.clock_observation.clone(),
            clock_key: self
                .preparation
                .clock_key
                .trim()
                .parse()
                .map_err(|_| "Enter the clock monitor's public key.".to_owned())?,
        })
    }
    pub fn receive_rooms(&mut self, value: &Value) -> ops::Result<()> {
        if value["outcome"]["status"] != "result" {
            return Err(
                "Room access was refused. Activate this agent account before loading rooms.".into(),
            );
        }
        self.available_rooms = serde_json::from_value(value["outcome"]["body"][0].clone())
            .map_err(|_| "The service returned an invalid room list.".to_owned())?;
        Ok(())
    }
    pub fn refresh(&mut self) {
        match ops::bots::list() {
            Ok(entries) => {
                self.entries = entries;
                self.error = None;
            }
            Err(error) => {
                self.error = Some(error);
                return;
            }
        }
        match ops::models::list() {
            Ok(entries) => self.models = entries,
            Err(error) => self.error = Some(error),
        }
        if let Ok(config) = self.value()
            && self.entries.iter().any(|entry| entry.id == config.id)
        {
            match ops::bots::load(config.id)
                .and_then(|v| serde_json::to_value(v).map_err(ops::failure))
            {
                Ok(value) => self.saved = Some(value),
                Err(error) => self.error = Some(error),
            }
        }
    }
}

fn choice(
    ui: &mut egui::Ui,
    id: &str,
    label: &str,
    selected: Option<Id>,
    entries: impl Iterator<Item = (Id, String)>,
) -> Option<Id> {
    let mut chosen = None;
    ui.horizontal(|ui| {
        ui.add_sized(
            [148.0, c::CONTROL_HEIGHT],
            egui::Label::new(label).halign(egui::Align::Min),
        );
        egui::ComboBox::from_id_salt(id)
            .width(ui.available_width())
            .selected_text(
                selected
                    .map(|v| v.as_hex()[..12].to_owned())
                    .unwrap_or_else(|| "Choose saved definition".into()),
            )
            .show_ui(ui, |ui| {
                for (id, name) in entries {
                    if ui.selectable_label(selected == Some(id), name).clicked() {
                        chosen = Some(id);
                    }
                }
            });
    });
    chosen
}
impl Workspace {
    pub(super) fn models_ui(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        ui.heading("Local models");
        if let Some(error) = &self.model.error {
            ui.colored_label(ui.visuals().error_fg_color, error);
        }
        c::section(ui, "Saved models", |ui| {
            let selected = self
                .model
                .config
                .as_ref()
                .and_then(|c| self.model.saved.as_ref().map(|_| c.id));
            if let Some(id) = choice(
                ui,
                "model-choice",
                "Definition",
                selected,
                self.model.entries.iter().map(|e| (e.id, e.name.clone())),
            ) {
                match ops::models::load(id) {
                    Ok(config) => self.model.adopt(config, true),
                    Err(error) => self.error = Some(error),
                }
            }
            ui.horizontal_wrapped(|ui| {
                if c::button(ui, "New model").clicked() {
                    match ops::models::Config::new() {
                        Ok(c) => self.model.adopt(c, false),
                        Err(e) => self.error = Some(e),
                    }
                }
                if c::button(ui, "Refresh list").clicked() {
                    self.model.refresh();
                }
                if self.model.config.is_some() && !self.model.unchanged() {
                    c::muted_badge(ui, "Unsaved changes");
                }
            });
        });
        if let Some(config) = &mut self.model.config {
            c::section(ui, "Connection", |ui| {
                field(ui, "Name", &mut config.name);
                field(ui, "Model / alias", &mut config.model);
                field(ui, "Loopback address", &mut self.model.endpoint);
                ui.horizontal(|ui| {
                    ui.add_sized(
                        [148.0, c::CONTROL_HEIGHT],
                        egui::Label::new("Adapter").halign(egui::Align::Min),
                    );
                    ui.selectable_value(
                        &mut config.adapter,
                        hrc::bot::Adapter::LlamaCpp,
                        "llama.cpp",
                    );
                    ui.selectable_value(&mut config.adapter, hrc::bot::Adapter::Ollama, "Ollama");
                });
                path(
                    ui,
                    "curl executable",
                    &mut config.curl,
                    &mut self.picker,
                    "model-curl",
                    false,
                );
                ui.horizontal(|ui| {
                    ui.label("Context tokens");
                    ui.add(egui::DragValue::new(&mut config.context_tokens).range(2048..=32768));
                    ui.label("Reply tokens");
                    ui.add(egui::DragValue::new(&mut config.output_tokens).range(128..=2048));
                });
            });
            c::section(ui, "Runtime", |ui| {
                let current = match config.backend {
                    ops::models::Backend::External => 0,
                    ops::models::Backend::LlamaCpp { .. } => 1,
                    ops::models::Backend::Ollama { .. } => 2,
                };
                ui.horizontal_wrapped(|ui| {
                    for (kind, label) in [
                        (0, "Existing endpoint"),
                        (1, "Manage llama.cpp"),
                        (2, "Manage Ollama"),
                    ] {
                        if ui.selectable_label(current == kind, label).clicked() && current != kind
                        {
                            config.backend = match kind {
                                1 => {
                                    config.adapter = hrc::bot::Adapter::LlamaCpp;
                                    ops::models::Backend::LlamaCpp {
                                        executable: ops::native::discover("llama-server"),
                                        model_file: PathBuf::new(),
                                        gpu_layers: 0,
                                        cuda_devices: String::new(),
                                    }
                                }
                                2 => {
                                    config.adapter = hrc::bot::Adapter::Ollama;
                                    if self.model.endpoint == "127.0.0.1:8080" {
                                        self.model.endpoint = "127.0.0.1:11434".into();
                                    }
                                    ops::models::Backend::Ollama {
                                        executable: ops::native::discover("ollama"),
                                        models_directory: PathBuf::new(),
                                        cuda_devices: String::new(),
                                    }
                                }
                                _ => ops::models::Backend::External,
                            };
                        }
                    }
                });
                match &mut config.backend {
                    ops::models::Backend::External => {
                        c::muted_badge(ui, "Lifecycle owned externally");
                    }
                    ops::models::Backend::LlamaCpp {
                        executable,
                        model_file,
                        gpu_layers,
                        cuda_devices,
                    } => {
                        path(
                            ui,
                            "llama-server",
                            executable,
                            &mut self.picker,
                            "model-llama",
                            false,
                        );
                        path(
                            ui,
                            "GGUF file",
                            model_file,
                            &mut self.picker,
                            "model-gguf",
                            false,
                        );
                        field(ui, "CUDA devices", cuda_devices);
                        ui.horizontal(|ui| {
                            ui.label("GPU layers");
                            ui.add(egui::DragValue::new(gpu_layers).range(0..=1024));
                            c::muted_badge(ui, "0 = CPU");
                        });
                    }
                    ops::models::Backend::Ollama {
                        executable,
                        models_directory,
                        cuda_devices,
                    } => {
                        path(
                            ui,
                            "Ollama executable",
                            executable,
                            &mut self.picker,
                            "model-ollama",
                            false,
                        );
                        path(
                            ui,
                            "Models folder",
                            models_directory,
                            &mut self.picker,
                            "model-ollama-models",
                            true,
                        );
                        field(ui, "CUDA devices", cuda_devices);
                        c::muted_badge(ui, "Cloud disabled");
                    }
                }
                if !matches!(config.backend, ops::models::Backend::External) {
                    ui.collapsing("Libraries and resource limits", |ui| {
                        let mut enabled = config.library_directory.is_some();
                        if ui
                            .checkbox(&mut enabled, "Explicit shared-library folder")
                            .changed()
                        {
                            config.library_directory = enabled.then(PathBuf::new);
                        }
                        if let Some(path_value) = &mut config.library_directory {
                            path(
                                ui,
                                "Library folder",
                                path_value,
                                &mut self.picker,
                                "model-libraries",
                                true,
                            );
                        }
                        limits(ui, &mut config.limits);
                    });
                }
            });
        }
        c::section(ui, "Model controls", |ui| {
            ui.horizontal_wrapped(|ui| {
                if c::primary(ui, "Save model").clicked() {
                    match self.model.value() {
                        Ok(config) => {
                            self.start(&ctx, "Save model", Completion::ModelSaved, move |cancel| {
                                ops::models::save(&config, cancel)
                            })
                        }
                        Err(error) => self.error = Some(error),
                    }
                }
                let ready = self.model.unchanged();
                for (label, action) in [("Status", 0), ("Start", 1), ("Stop", 2), ("Probe", 3)] {
                    let managed = self
                        .model
                        .saved
                        .as_ref()
                        .is_some_and(|v| v["backend"]["kind"] != "external");
                    let enabled = match action {
                        0 => self.model.saved.is_some(),
                        1 => ready && managed,
                        2 => self.model.saved.is_some() && managed,
                        _ => ready,
                    };
                    ui.add_enabled_ui(enabled, |ui| {
                        if c::button(ui, label).clicked()
                            && let Some(config) = &self.model.config
                        {
                            let id = config.id;
                            self.start(&ctx, label, Completion::General, move |cancel| {
                                if action == 3 {
                                    return ops::models::probe(id, cancel);
                                }
                                serde_json::to_value(match action {
                                    0 => ops::models::status(id, cancel),
                                    1 => ops::models::start(id, cancel),
                                    _ => ops::models::stop(id, cancel),
                                }?)
                                .map_err(ops::failure)
                            });
                        }
                    });
                }
            });
        });
    }
    pub(super) fn bots_ui(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        let mut room_request = None;
        ui.heading("Bots");
        if let Some(error) = &self.bot.error {
            ui.colored_label(ui.visuals().error_fg_color, error);
        }
        c::section(ui, "Saved bots", |ui| {
            let selected = self
                .bot
                .config
                .as_ref()
                .and_then(|c| self.bot.saved.as_ref().map(|_| c.id));
            if let Some(id) = choice(
                ui,
                "bot-choice",
                "Definition",
                selected,
                self.bot.entries.iter().map(|e| (e.id, e.name.clone())),
            ) {
                match ops::bots::load(id) {
                    Ok(config) => self.bot.adopt(config, true),
                    Err(error) => self.error = Some(error),
                }
            }
            ui.horizontal_wrapped(|ui| {
                if c::button(ui, "New bot").clicked() {
                    match ops::bots::Config::new() {
                        Ok(c) => self.bot.adopt(c, false),
                        Err(e) => self.error = Some(e),
                    }
                }
                if c::button(ui, "Refresh list").clicked() {
                    self.bot.refresh();
                }
                if self.bot.config.is_some() && !self.bot.unchanged() {
                    c::muted_badge(ui, "Unsaved changes");
                }
            });
        });
        if let Some(config) = &mut self.bot.config {
            c::section(ui, "Agent endpoint", |ui| {
                field(ui, "Name", &mut config.name);
                field(ui, "Nickname", &mut config.nickname);
                path(
                    ui,
                    "Agent profile",
                    &mut config.profile,
                    &mut self.picker,
                    "bot-profile",
                    true,
                );
                field(ui, "Delegation ID", &mut self.bot.grant);
                ui.collapsing("Create agent profile", |ui| {
                    path(
                        ui,
                        "Existing connection",
                        &mut self.bot.preparation.connection_profile,
                        &mut self.picker,
                        "bot-connection",
                        true,
                    );
                    if c::button(ui, "Use connection").clicked() {
                        match hrc::client::Profile::load(&self.bot.preparation.connection_profile) {
                            Ok(profile) => {
                                self.bot.preparation.service_key = profile.server.signing_key.as_hex();
                                self.bot.preparation.companion = profile.companion;
                                self.bot.preparation.clock_observation = profile.clock.observation;
                                self.bot.preparation.clock_key = profile.clock.monitor_key;
                            }
                            Err(_) => self.error = Some("Choose an existing HRC profile with a verified service connection.".into()),
                        }
                    }
                    c::muted_badge(ui, "Connection settings only · fresh agent identity");
                    path(
                        ui,
                        "Agent invitation",
                        &mut self.bot.preparation.invitation,
                        &mut self.picker,
                        "bot-invitation",
                        false,
                    );
                    field(
                        ui,
                        "Service public key",
                        &mut self.bot.preparation.service_key,
                    );
                    path(
                        ui,
                        "Recovery key output",
                        &mut self.bot.preparation.recovery,
                        &mut self.picker,
                        "bot-recovery",
                        false,
                    );
                    path(
                        ui,
                        "Registration output",
                        &mut self.bot.preparation.registration,
                        &mut self.picker,
                        "bot-registration",
                        false,
                    );
                    path(
                        ui,
                        "Companion folder",
                        &mut self.bot.preparation.companion,
                        &mut self.picker,
                        "bot-companion",
                        true,
                    );
                    path(
                        ui,
                        "Clock observation",
                        &mut self.bot.preparation.clock_observation,
                        &mut self.picker,
                        "bot-clock",
                        false,
                    );
                    field(ui, "Clock public key", &mut self.bot.preparation.clock_key);
                });
            });
        }
        ui.horizontal_wrapped(|ui| {
            if c::button(ui, "Prepare profile").clicked() {
                match self.bot.preparation() {
                    Ok(config) => self.start(
                        &ctx,
                        "Prepare agent profile",
                        Completion::General,
                        move |cancel| ops::bots::prepare(&config, cancel),
                    ),
                    Err(error) => self.error = Some(error),
                }
            }
            if c::button(ui, "Activate account").clicked() {
                self.service.registration = self.bot.preparation.registration.clone();
                self.page = Page::Service;
            }
        });
        if let Some(config) = &mut self.bot.config {
            c::section(ui, "Rooms and replies", |ui| {
                if c::button(ui, "Load rooms").clicked() {
                    let profile = config.profile.clone();
                    let args = ops::native::strings(&["room", "list", "--profile"]);
                    self.bot.available_rooms.clear();
                    // The CLI owns bounded authentication and the current access check.
                    self.result = Some(serde_json::json!({"status":"LoadingRooms"}));
                    room_request = Some((profile, args));
                }
                for room in &self.bot.available_rooms {
                    let id = room.room.to_string();
                    let mut selected = self.bot.rooms.lines().any(|line| line.trim() == id);
                    if ui
                        .checkbox(&mut selected, &room.name)
                        .on_hover_text(&id)
                        .changed()
                    {
                        let mut ids: Vec<_> = self
                            .bot
                            .rooms
                            .lines()
                            .map(str::to_owned)
                            .filter(|line| line.trim() != id && !line.trim().is_empty())
                            .collect();
                        if selected {
                            ids.push(id);
                        }
                        self.bot.rooms = ids.join("\n");
                    }
                }
                if !self.bot.available_rooms.is_empty() {
                    ui.small("Up to 32 rooms permitted for this agent. Stop a running bot before refreshing.");
                }
                ui.label("Room identifiers / one per line");
                ui.add(
                    egui::TextEdit::multiline(&mut self.bot.rooms)
                        .desired_width(f32::INFINITY)
                        .desired_rows(3),
                );
                field(ui, "Help reply", &mut config.help_text);
                ui.horizontal(|ui| {
                    ui.label("Poll interval (ms)");
                    ui.add(egui::DragValue::new(&mut config.poll_interval_ms).range(1000..=60000));
                });
                ui.horizontal(|ui| {
                    ui.add_sized(
                        [148.0, c::CONTROL_HEIGHT],
                        egui::Label::new("Model").halign(egui::Align::Min),
                    );
                    let title = config
                        .model_id
                        .map(|id| {
                            self.bot
                                .models
                                .iter()
                                .find(|m| m.id == id)
                                .map(|m| m.name.clone())
                                .unwrap_or_else(|| "Unavailable definition".into())
                        })
                        .unwrap_or_else(|| "Deterministic help only".into());
                    egui::ComboBox::from_id_salt("bot-model-choice")
                        .width(ui.available_width())
                        .selected_text(title)
                        .show_ui(ui, |ui| {
                            ui.selectable_value(
                                &mut config.model_id,
                                None,
                                "Deterministic help only",
                            );
                            for model in &self.bot.models {
                                ui.selectable_value(
                                    &mut config.model_id,
                                    Some(model.id),
                                    &model.name,
                                );
                            }
                        });
                });
                if config.model_id.is_some() {
                    field(ui, "Message prefix", &mut config.prefix);
                    ui.checkbox(
                        &mut config.all_human_messages,
                        "Reply to all direct human messages in the selected room",
                    );
                    c::muted_badge(ui, "Model bots use one room");
                    ui.checkbox(&mut config.memory_enabled, "Retain bounded room context");
                    ui.add_enabled_ui(config.memory_enabled, |ui| {
                        ui.horizontal(|ui| {
                            ui.label("Days");
                            ui.add(egui::DragValue::new(&mut config.memory_days).range(1..=30));
                            ui.label("Storage (bytes)");
                            ui.add(
                                egui::DragValue::new(&mut config.memory_bytes)
                                    .range(16384..=1048576),
                            );
                        })
                    });
                }
                ui.collapsing("Resource and security limits", |ui| {
                    limits(ui, &mut config.limits)
                });
            });
        }
        if let Some((profile, mut args)) = room_request {
            match ops::native::path(&profile) {
                Ok(path) => {
                    args.push(path);
                    self.start(
                        &ctx,
                        "Load agent rooms",
                        Completion::BotRooms,
                        move |cancel| {
                            ops::native::json(
                                &std::env::current_exe().map_err(ops::failure)?,
                                &args,
                                cancel,
                                std::time::Instant::now() + std::time::Duration::from_secs(60),
                            )
                            .map_err(ops::failure)
                        },
                    );
                }
                Err(error) => self.error = Some(ops::failure(error)),
            }
        }
        c::section(ui, "Bot controls", |ui| {
            ui.horizontal_wrapped(|ui| {
                if c::primary(ui, "Save bot").clicked() {
                    match self.bot.value() {
                        Ok(config) => {
                            self.start(&ctx, "Save bot", Completion::BotSaved, move |cancel| {
                                ops::bots::save(&config, cancel)
                            })
                        }
                        Err(error) => self.error = Some(error),
                    }
                }
                let ready = self.bot.unchanged();
                for (label, action) in [("Status", 0), ("Start", 1), ("Stop", 2)] {
                    ui.add_enabled_ui(
                        if action == 1 {
                            ready
                        } else {
                            self.bot.saved.is_some()
                        },
                        |ui| {
                            if c::button(ui, label).clicked()
                                && let Some(config) = &self.bot.config
                            {
                                let id = config.id;
                                let resynchronise = self.bot.resynchronise;
                                if action == 1 {
                                    self.bot.resynchronise = false;
                                }
                                self.start(&ctx, label, Completion::General, move |cancel| {
                                    serde_json::to_value(match action {
                                        0 => ops::bots::status(id, cancel),
                                        1 => ops::bots::start_with(id, resynchronise, cancel),
                                        _ => ops::bots::stop(id, cancel),
                                    }?)
                                    .map_err(ops::failure)
                                });
                            }
                        },
                    );
                }
            });
            ui.checkbox(
                &mut self.bot.resynchronise,
                "Resynchronise on next start (reset stale cursor and context)",
            );
        });
    }
}
