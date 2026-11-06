// SPDX-License-Identifier: Apache-2.0
//! Native conversation interface; effects run through the shared client worker.
#[path = "Agents.rs"]
mod agents;
#[path = "Components.rs"]
pub(crate) mod components;
#[path = "Conversation.rs"]
mod conversation;
#[path = "Editor.rs"]
mod editor;
#[path = "Encryption.rs"]
mod encryption;
#[path = "Panels.rs"]
mod panels;
#[path = "Sound.rs"]
mod sound;
#[path = "Theme.rs"]
pub(crate) mod theme;
use crate::{
    display,
    interaction::{Model, Panel},
};
use eframe::egui;
use hrc::{
    client::{Command, Density, Theme},
    protocol::*,
};
use std::time::Duration;

impl App {
    pub(crate) fn new(model: Model, ctx: &egui::Context) -> Self {
        theme::configure(
            ctx,
            model.snapshot.preferences.theme == Theme::Light,
            model.snapshot.preferences.density == Density::Compact,
            model.snapshot.preferences.text_scale,
        );
        Self {
            nickname: model.snapshot.nickname.clone(),
            model,
            query: String::new(),
            room_name: String::new(),
            private_group: false,
            recipient: String::new(),
            invite_account: String::new(),
            confirm_recovery: false,
            find_sender: String::new(),
            find_represented: String::new(),
            find_from: String::new(),
            find_until: String::new(),
            grant: agents::GrantForm::default(),
            focus_composer: true,
            composer_room: None,
            applied: None,
            scroll_event: None,
            sound: sound::Sound::new(),
            setup_requested: false,
        }
    }
    pub(crate) fn prepare_setup(&mut self) {
        self.setup_requested = true;
        self.model.save();
    }
    pub(crate) fn go_offline(&mut self) {
        self.model.dispatch(Command::Disconnect);
    }
    pub(crate) fn ready_for_setup(&self) -> bool {
        self.setup_requested && self.model.draft_saved()
    }
}
pub(crate) struct App {
    model: Model,
    nickname: String,
    query: String,
    room_name: String,
    private_group: bool,
    recipient: String,
    invite_account: String,
    confirm_recovery: bool,
    find_sender: String,
    find_represented: String,
    find_from: String,
    find_until: String,
    grant: agents::GrantForm,
    focus_composer: bool,
    composer_room: Option<RoomId>,
    applied: Option<(Theme, Density, u32)>,
    scroll_event: Option<Id>,
    sound: sound::Sound,
    setup_requested: bool,
}
impl eframe::App for App {
    fn logic(&mut self, ctx: &egui::Context, _: &mut eframe::Frame) {
        if self.model.tick() {
            self.sound.play();
        }
        if self.model.notified {
            ctx.send_viewport_cmd(egui::ViewportCommand::RequestUserAttention(
                egui::UserAttentionType::Informational,
            ));
        }
        let preferences = &self.model.snapshot.preferences;
        let appearance = (
            preferences.theme,
            preferences.density,
            preferences.text_scale.to_bits(),
        );
        if self.applied != Some(appearance) {
            theme::configure(
                ctx,
                appearance.0 == Theme::Light,
                appearance.1 == Density::Compact,
                preferences.text_scale,
            );
            self.applied = Some(appearance);
        }
        if ctx.input(|input| input.viewport().close_requested()) {
            self.model.close();
        }
        if ctx.input_mut(|input| input.consume_key(egui::Modifiers::CTRL, egui::Key::Q)) {
            self.model.close();
        }
        if self.model.closing {
            if self.model.draft_saved() {
                ctx.send_viewport_cmd(egui::ViewportCommand::Close);
            } else {
                ctx.send_viewport_cmd(egui::ViewportCommand::CancelClose);
            }
        }
        if ctx.input_mut(|input| input.consume_key(egui::Modifiers::CTRL, egui::Key::L)) {
            self.focus_composer = true;
        }
        if ctx.input_mut(|input| input.consume_key(egui::Modifiers::CTRL, egui::Key::F)) {
            self.model.panel = Panel::Conversation;
            ctx.memory_mut(|m| m.request_focus(egui::Id::unique("search")));
        }
        if ctx.input_mut(|input| input.consume_key(egui::Modifiers::NONE, egui::Key::F1)) {
            self.model.panel = Panel::Help;
        }
        ctx.request_repaint_after(Duration::from_millis(100));
    }
    fn ui(&mut self, ui: &mut egui::Ui, _: &mut eframe::Frame) {
        self.toolbar(ui);
        self.status(ui);
        self.rooms(ui);
        if self.model.panel == Panel::Conversation && ui.available_width() >= 720.0 {
            self.members(ui);
        }
        egui::CentralPanel::default()
            .frame(
                egui::Frame::new()
                    .fill(ui.visuals().panel_fill)
                    .inner_margin(14),
            )
            .show(ui, |ui| {
                if let Some(error) = self.model.error.clone() {
                    ui.horizontal_wrapped(|ui| {
                        ui.colored_label(egui::Color32::LIGHT_RED, error);
                        if ui.small_button("Dismiss").clicked() {
                            self.model.error = None;
                            self.model.closing = false;
                        }
                    });
                }
                match self.model.panel {
                    Panel::Conversation => self.conversation(ui),
                    Panel::Help => self.help(ui),
                    Panel::Agents => self.agents(ui),
                    Panel::Settings => self.settings(ui),
                    Panel::Status => self.details(ui),
                    Panel::Motd => {
                        ui.heading("Message of the day");
                        ui.label(if self.model.snapshot.motd.is_empty() {
                            "No message is configured"
                        } else {
                            &self.model.snapshot.motd
                        });
                    }
                }
            });
    }
}
impl App {
    fn toolbar(&mut self, ui: &mut egui::Ui) {
        egui::Panel::top("toolbar")
            .frame(
                egui::Frame::new()
                    .fill(components::surface(ui))
                    .inner_margin(10),
            )
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.add_sized(
                        [112.0, components::CONTROL_HEIGHT],
                        egui::Label::new(
                            egui::RichText::new("HRC")
                                .strong()
                                .size(23.0)
                                .color(components::accent(ui)),
                        ),
                    );
                    for (panel, label) in [
                        (Panel::Conversation, "Conversations"),
                        (Panel::Agents, "Agents"),
                        (Panel::Settings, "Settings"),
                        (Panel::Status, "Connection"),
                        (Panel::Help, "Help"),
                    ] {
                        if components::choice(ui, self.model.panel == panel, label).clicked() {
                            if panel == Panel::Settings {
                                self.nickname = self.model.snapshot.nickname.clone();
                            }
                            self.model.panel = panel;
                            if panel == Panel::Agents {
                                self.model.dispatch(Command::Inspect);
                            }
                        }
                    }
                    ui.menu_button("Profile", |ui| {
                        if ui.button("Switch or set up…").clicked() {
                            self.prepare_setup();
                            ui.close();
                        }
                    });
                });
            });
    }
    fn status(&mut self, ui: &mut egui::Ui) {
        let snapshot = self.model.snapshot.clone();
        egui::Panel::bottom("status").frame(egui::Frame::new().inner_margin(6)).show(ui, |ui| {
            ui.spacing_mut().interact_size.y = 16.0;
            ui.horizontal_wrapped(|ui| {
                use hrc::client::ConnectionState;
                let (state, colour) = match &snapshot.connection {
                    ConnectionState::Online => ("Online", egui::Color32::from_rgb(117, 201, 153)),
                    ConnectionState::Offline => ("Offline", ui.visuals().weak_text_color()),
                    ConnectionState::Connecting => ("Connecting", egui::Color32::from_rgb(211, 170, 91)),
                    ConnectionState::Resolving => ("Resolving", egui::Color32::from_rgb(211, 170, 91)),
                    ConnectionState::Backoff { .. } => ("Reconnecting", egui::Color32::from_rgb(211, 170, 91)),
                };
                let connection = egui::Frame::new().fill(components::surface(ui)).stroke(ui.visuals().widgets.noninteractive.bg_stroke)
                    .inner_margin(egui::Margin::symmetric(9, 5)).show(ui, |ui| {
                        ui.spacing_mut().interact_size.y = 16.0;
                        ui.horizontal(|ui| { ui.colored_label(colour, "●"); ui.label(egui::RichText::new(state).size(11.0)); });
                    }).response;
                if connection.interact(egui::Sense::click()).on_hover_text(display::connection(&snapshot)).clicked() { self.model.panel = Panel::Status; }
                let last_rtt = snapshot.deliveries.iter().rev().find_map(|delivery| delivery.exchange_ns)
                    .map_or_else(|| "—".into(), |ns| format!("{:.1} ms", ns as f64 / 1_000_000.0));
                components::readout(ui, "LAST RTT", &last_rtt).on_hover_text("Last measured message: frame write to authenticated service commit acknowledgement. Excludes UI and local queues; not a recipient receipt.");
                let privacy = snapshot.privacy.as_ref().filter(|p| !p.is_historical());
                let tls = privacy.and_then(|p| p.tls()).unwrap_or("—");
                components::readout(ui, "TLS", tls);
                let relay = privacy.map_or("—", |p| match p.relay_path() {
                    hrc::hypernet::RelayPath::ApprovedAttachment => "Attached",
                    hrc::hypernet::RelayPath::NestedTlsViaRelay => "Nested TLS",
                    hrc::hypernet::RelayPath::Unknown => "Unknown",
                    hrc::hypernet::RelayPath::Unavailable => "Unavailable",
                });
                if components::readout(ui, "RELAY", relay).interact(egui::Sense::click()).on_hover_text("Open current transport and relay observations").clicked() { self.model.panel = Panel::Status; }
                if let Some(room) = &snapshot.selected {
                    components::readout(ui, "CONTENT", match room.summary.confidentiality {
                        RoomConfidentiality::Community => "Service-readable",
                        RoomConfidentiality::ConfidentialDirect | RoomConfidentiality::PrivateGroup => "E2EE",
                    }).on_hover_text(display::confidentiality(room.summary.confidentiality));
                }
                if snapshot.preferences.quiet { components::readout(ui, "ALERTS", "Quiet"); }
                if !self.model.draft_saved() { components::readout(ui, "DRAFT", "Saving"); }
                if self.model.closing { components::readout(ui, "APP", "Closing"); }
                if let Some(status) = &snapshot.status
                    && components::readout(ui, "STATUS", &status.code).interact(egui::Sense::click()).on_hover_text(&status.detail).clicked() { self.model.panel = Panel::Status; }
            });
        });
    }
    fn rooms(&mut self, ui: &mut egui::Ui) {
        let snapshot = self.model.snapshot.clone();
        egui::Panel::left("rooms")
            .resizable(true)
            .default_size(228.0)
            .size_range(180.0..=360.0)
            .show(ui, |ui| {
                ui.add_space(8.0);
                ui.label(
                    egui::RichText::new(hrc::text::identity_display(&snapshot.nickname))
                        .strong()
                        .size(17.0),
                );
                ui.weak(display::short_account(snapshot.account));
                ui.add_space(8.0);
                egui::Panel::bottom("new-conversation")
                    .frame(egui::Frame::new().inner_margin(8))
                    .show(ui, |ui| {
                        ui.collapsing("New conversation", |ui| {
                            ui.add(
                                egui::TextEdit::singleline(&mut self.room_name)
                                    .hint_text("Room name")
                                    .desired_width(ui.available_width())
                                    .char_limit(64),
                            );
                            ui.checkbox(&mut self.private_group, "Encrypted group");
                            if components::button(ui, "Create room").clicked()
                                && !self.room_name.is_empty()
                            {
                                self.model.dispatch(if self.private_group {
                                    Command::CreatePrivateGroup {
                                        name: self.room_name.clone(),
                                    }
                                } else {
                                    Command::CreateRoom {
                                        name: self.room_name.clone(),
                                    }
                                });
                            }
                            ui.separator();
                            ui.add(
                                egui::TextEdit::singleline(&mut self.recipient)
                                    .hint_text("Recipient account ID")
                                    .desired_width(ui.available_width())
                                    .char_limit(200),
                            );
                            if components::button(ui, "Confidential chat").clicked() {
                                match self.recipient.parse() {
                                    Ok(recipient) => {
                                        self.model.dispatch(Command::CreateDirect { recipient });
                                    }
                                    Err(_) => {
                                        self.model.error =
                                            Some("Enter a valid recipient account ID".into())
                                    }
                                }
                            }
                        });
                        if components::row(ui, false, "Refresh rooms").clicked() {
                            self.model.dispatch(Command::Refresh);
                        }
                    });
                egui::ScrollArea::vertical()
                    .id_salt("conversation-navigation")
                    .show(ui, |ui| {
                        for (joined, title) in [(true, "JOINED"), (false, "AVAILABLE")] {
                            if !snapshot.rooms.iter().any(|room| room.joined == joined) {
                                continue;
                            }
                            ui.label(egui::RichText::new(title).small().weak());
                            for room in &snapshot.rooms {
                                if room.joined != joined {
                                    continue;
                                }
                                let selected = snapshot
                                    .selected
                                    .as_ref()
                                    .is_some_and(|v| v.summary.room == room.room);
                                let label = format!(
                                    "{}{}{}",
                                    if room.joined { "# " } else { "+ " },
                                    hrc::text::identity_display(&room.name),
                                    if room.unread > 0 {
                                        format!(" ({})", room.unread)
                                    } else {
                                        String::new()
                                    }
                                );
                                if components::row(ui, selected, &label)
                                    .on_hover_text(room.room.to_string())
                                    .clicked()
                                {
                                    if room.joined {
                                        self.model.select(room.room);
                                        self.model.panel = Panel::Conversation;
                                    } else {
                                        self.model.dispatch(Command::Join(room.room));
                                    }
                                }
                            }
                            ui.add_space(12.0);
                        }
                    });
            });
    }
    fn members(&mut self, ui: &mut egui::Ui) {
        let snapshot = self.model.snapshot.clone();
        let Some(room) = &snapshot.selected else {
            return;
        };
        egui::Panel::right("members")
            .resizable(true)
            .default_size(210.0)
            .size_range(170.0..=330.0)
            .show(ui, |ui| {
                ui.add_space(8.0);
                ui.label(
                    egui::RichText::new(format!("MEMBERS  {}", room.members.len()))
                        .small()
                        .strong(),
                );
                ui.separator();
                self.member_list(ui);
            });
    }
    fn member_list(&mut self, ui: &mut egui::Ui) {
        let snapshot = self.model.snapshot.clone();
        let Some(room) = &snapshot.selected else {
            return;
        };
        egui::ScrollArea::vertical()
            .max_height(ui.available_height().min(420.0))
            .show(ui, |ui| {
                for member in &room.members {
                    let role = if matches!(member.classification, AccountClass::Agent { .. }) {
                        " · Agent"
                    } else {
                        ""
                    };
                    let label = format!(
                        "{}{}{}",
                        if member.present { "● " } else { "○ " },
                        hrc::text::identity_display(&member.nickname),
                        role
                    );
                    let response = components::row(ui, false, &label)
                        .on_hover_text(member.account.to_string());
                    egui::Popup::menu(&response)
                        .open_memory(
                            (response.clicked() || response.secondary_clicked())
                                .then_some(egui::SetOpenCommand::Toggle),
                        )
                        .show(|ui| {
                            ui.label(member.account.to_string());
                            if ui
                                .add_enabled(
                                    self.model.composer_enabled(),
                                    egui::Button::new("Mention"),
                                )
                                .clicked()
                            {
                                let position = self.model.editor.cursor();
                                if self
                                    .model
                                    .editor
                                    .complete_mention(
                                        position..position,
                                        member.account,
                                        &member.nickname,
                                    )
                                    .is_ok()
                                {
                                    self.model.edited();
                                    self.focus_composer = true;
                                }
                                ui.close();
                            }
                            for (label, ignored, muted) in [
                                ("Ignore", Some(true), None),
                                ("Stop ignoring", Some(false), None),
                                ("Mute notifications", None, Some(true)),
                                ("Restore notifications", None, Some(false)),
                            ] {
                                if ui.button(label).clicked() {
                                    self.model.dispatch(Command::SetFilter {
                                        subject: member.account,
                                        ignored,
                                        muted,
                                    });
                                    ui.close();
                                }
                            }
                            if room
                                .members
                                .iter()
                                .any(|m| m.account == snapshot.account && m.moderator)
                            {
                                for (label, kind, enabled, duration_ms) in [
                                    (
                                        "Silence for five minutes",
                                        hrc::client::RestrictionKind::Silence,
                                        true,
                                        300000,
                                    ),
                                    (
                                        "Remove silence",
                                        hrc::client::RestrictionKind::Silence,
                                        false,
                                        300000,
                                    ),
                                    ("Kick", hrc::client::RestrictionKind::Kick, true, 300000),
                                    (
                                        "Ban for one day",
                                        hrc::client::RestrictionKind::Ban,
                                        true,
                                        86400000,
                                    ),
                                    (
                                        "Remove ban",
                                        hrc::client::RestrictionKind::Ban,
                                        false,
                                        86400000,
                                    ),
                                ] {
                                    if ui.button(label).clicked() {
                                        self.model.dispatch(Command::SetRestriction {
                                            room: room.summary.room,
                                            kind,
                                            restriction: hrc::moderation::Restriction {
                                                subject: member.account,
                                                enabled,
                                                duration_ms,
                                                reason: "Room moderation".into(),
                                            },
                                        });
                                        ui.close();
                                    }
                                }
                            }
                        });
                }
            });
    }
}
