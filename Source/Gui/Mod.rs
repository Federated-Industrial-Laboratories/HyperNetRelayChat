// SPDX-License-Identifier: Apache-2.0
//! Native conversation interface; effects run through the shared client worker.
#[path = "Agents.rs"]
mod agents;
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
mod theme;
use crate::{
    display,
    interaction::{Model, Panel},
};
use eframe::egui;
use hrc::{
    client::{Command, Density, Theme},
    protocol::*,
};
use std::result::Result;
use std::{path::Path, time::Duration};

pub fn run(profile: &Path, offline: bool) -> Result<(), &'static str> {
    let model = Model::open(profile, offline)?;
    let options = eframe::NativeOptions {
        viewport: egui::ViewportBuilder::default()
            .with_title("HyperNet Relay Chat")
            .with_inner_size([1120.0, 760.0])
            .with_min_inner_size([640.0, 480.0]),
        ..Default::default()
    };
    eframe::run_native(
        "HyperNet Relay Chat",
        options,
        Box::new(move |cc| {
            theme::configure(
                &cc.egui_ctx,
                model.snapshot.preferences.theme == Theme::Light,
                model.snapshot.preferences.density == Density::Compact,
                model.snapshot.preferences.text_scale,
            );
            Ok(Box::new(App {
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
            }))
        }),
    )
    .map_err(|_| "GraphicalInterfaceUnavailable")
}
struct App {
    model: Model,
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
        if self.model.panel == Panel::Conversation {
            self.members(ui);
        }
        egui::CentralPanel::default().show(ui, |ui| {
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
        egui::Panel::top("toolbar").show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.strong("HRC");
                for (panel, label) in [
                    (Panel::Conversation, "Conversations"),
                    (Panel::Agents, "Agents"),
                    (Panel::Settings, "Settings"),
                    (Panel::Status, "Status"),
                    (Panel::Help, "Help"),
                ] {
                    if ui
                        .selectable_label(self.model.panel == panel, label)
                        .clicked()
                    {
                        self.model.panel = panel;
                        if panel == Panel::Agents {
                            self.model.dispatch(Command::Inspect);
                        }
                    }
                }
                if ui.button("Reconnect").clicked() {
                    self.model.dispatch(Command::Connect);
                }
                if ui.button("Disconnect").clicked() {
                    self.model.dispatch(Command::Disconnect);
                }
            });
        });
    }
    fn status(&mut self, ui: &mut egui::Ui) {
        egui::Panel::bottom("status").show(ui, |ui| {
            ui.horizontal_wrapped(|ui| {
                ui.label(display::connection(&self.model.snapshot));
                if !self.model.draft_saved() {
                    ui.label("Saving draft…");
                }
                if self.model.snapshot.preferences.quiet {
                    ui.label("Quiet");
                }
                if self.sound.unavailable() {
                    ui.label("Optional desktop sound unavailable");
                }
                if let Some(status) = &self.model.snapshot.status {
                    ui.label(format!("{}: {}", status.code, status.detail));
                }
                if self.model.closing {
                    ui.label("Waiting for the draft to be saved before closing");
                }
            });
        });
    }
    fn rooms(&mut self, ui: &mut egui::Ui) {
        let snapshot = self.model.snapshot.clone();
        egui::Panel::left("rooms")
            .resizable(true)
            .default_size(205.0)
            .size_range(150.0..=360.0)
            .show(ui, |ui| {
                ui.heading("Conversations");
                egui::ScrollArea::vertical()
                    .max_height((ui.available_height() - 100.0).max(80.0))
                    .show(ui, |ui| {
                        for room in &snapshot.rooms {
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
                            if ui
                                .selectable_label(selected, label)
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
                    });
                ui.separator();
                ui.add(
                    egui::TextEdit::singleline(&mut self.room_name)
                        .hint_text("New room name")
                        .char_limit(64),
                );
                ui.checkbox(&mut self.private_group, "Private encrypted group");
                if ui.button("Create room").clicked() && !self.room_name.is_empty() {
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
                ui.add(
                    egui::TextEdit::singleline(&mut self.recipient)
                        .hint_text("Account ID for confidential chat")
                        .char_limit(200),
                );
                if ui.button("Invite to confidential chat").clicked()
                    && let Ok(recipient) = self.recipient.parse()
                {
                    self.model.dispatch(Command::CreateDirect { recipient });
                }
                if ui.button("Refresh").clicked() {
                    self.model.dispatch(Command::Refresh);
                }
            });
    }
    fn members(&mut self, ui: &mut egui::Ui) {
        let snapshot = self.model.snapshot.clone();
        let Some(room) = &snapshot.selected else {
            return;
        };
        egui::Panel::right("members")
            .resizable(true)
            .default_size(185.0)
            .size_range(130.0..=330.0)
            .show(ui, |ui| {
                ui.heading("Members");
                egui::ScrollArea::vertical().show(ui, |ui| {
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
                        ui.button(label)
                            .on_hover_text(member.account.to_string())
                            .context_menu(|ui| {
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
            });
    }
}
