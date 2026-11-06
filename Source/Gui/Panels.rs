// SPDX-License-Identifier: Apache-2.0
//! Inspectable privacy, delivery and presentation preferences.
use super::*;
use hrc::client::{ChatLayout, NotificationMode};

impl App {
    pub(super) fn help(&self, ui: &mut egui::Ui) {
        ui.heading("Help");
        egui::ScrollArea::vertical().show(ui, |ui| {
            components::section(ui, "Keyboard", |ui| {
                egui::Grid::new("help-shortcuts").min_col_width(150.0).spacing([24.0, 12.0]).show(ui, |ui| {
                    for (key, action) in [
                        ("Ctrl+Enter", "Send message"), ("Enter", "Insert a line break"),
                        ("Ctrl+L", "Focus composer"), ("Ctrl+F", "Search conversation"),
                        ("F1", "Open help"), ("Tab / Shift+Tab", "Move between controls"),
                        ("Ctrl+Q", "Close after saving the draft"),
                    ] { ui.monospace(key); ui.label(action); ui.end_row(); }
                });
            });
            components::section(ui, "Conversation controls", |ui| {
                ui.label("Right-click a message to reply or copy its ID. Select a reply preview to open its context.");
                ui.label("Select a member for mention, ignore, notification and moderation controls. Choose a mention completion to bind the account; a typed @name alone is plain text.");
            });
            components::section(ui, "Commands", |ui| {
                egui::Grid::new("help-commands").min_col_width(150.0).spacing([24.0, 12.0]).striped(true).show(ui, |ui| {
                    for (command, description) in crate::commands::HELP {
                        ui.monospace(*command); ui.label(*description); ui.end_row();
                    }
                });
            });
        });
    }

    pub(super) fn settings(&mut self, ui: &mut egui::Ui) {
        ui.heading("Settings");
        let snapshot = self.model.snapshot.clone();
        let mut preferences = snapshot.preferences.clone();
        let before = (
            preferences.theme,
            preferences.density,
            preferences.chat_layout,
            preferences.text_scale,
            preferences.quiet,
            preferences.sound,
            preferences.ambiguous_wide,
        );
        egui::ScrollArea::vertical().show(ui, |ui| {
            components::section(ui, "Profile", |ui| {
                components::field(ui, "Nickname", |ui| {
                    ui.horizontal_wrapped(|ui| {
                        ui.add(
                            egui::TextEdit::singleline(&mut self.nickname)
                                .desired_width(264.0)
                                .char_limit(64),
                        );
                        if components::button(ui, "Apply").clicked() {
                            self.model
                                .dispatch(Command::SetNickname(self.nickname.clone()));
                        }
                    });
                });
            });
            components::section(ui, "Appearance", |ui| {
                components::field(ui, "Theme", |ui| {
                    ui.horizontal_wrapped(|ui| {
                        for (value, label) in [(Theme::Dark, "Dark"), (Theme::Light, "Light")] {
                            if components::choice(ui, preferences.theme == value, label).clicked() {
                                preferences.theme = value;
                            }
                        }
                    })
                    .inner
                });
                components::field(ui, "Conversation", |ui| {
                    ui.horizontal_wrapped(|ui| {
                        for (value, label) in [
                            (ChatLayout::Classic, "Classic"),
                            (ChatLayout::Bubbles, "Bubbles"),
                        ] {
                            if components::choice(ui, preferences.chat_layout == value, label)
                                .clicked()
                            {
                                preferences.chat_layout = value;
                            }
                        }
                    })
                    .inner
                });
                components::field(ui, "Density", |ui| {
                    ui.horizontal_wrapped(|ui| {
                        for (value, label) in [
                            (Density::Comfortable, "Comfortable"),
                            (Density::Compact, "Compact"),
                        ] {
                            if components::choice(ui, preferences.density == value, label).clicked()
                            {
                                preferences.density = value;
                            }
                        }
                    })
                    .inner
                });
                components::field(ui, "Text size", |ui| {
                    ui.add(egui::Slider::new(&mut preferences.text_scale, 0.75..=2.0).suffix("×"));
                });
            });
            components::section(ui, "Notifications", |ui| {
                ui.checkbox(&mut preferences.quiet, "Quiet mode")
                    .on_hover_text("Suppresses notifications and sounds");
                ui.checkbox(&mut preferences.sound, "Notification sounds");
                if self.sound.unavailable() {
                    ui.colored_label(
                        egui::Color32::from_rgb(211, 170, 91),
                        "Desktop sound unavailable",
                    );
                }
            });
            if let Some(room) = &snapshot.selected {
                components::section(
                    ui,
                    &format!(
                        "# {} · notifications",
                        hrc::text::identity_display(&room.summary.name)
                    ),
                    |ui| {
                        let mut room_preferences = room.preferences.clone();
                        let before = (room_preferences.notifications, room_preferences.sound);
                        ui.horizontal_wrapped(|ui| {
                            for (mode, label) in [
                                (NotificationMode::All, "All messages"),
                                (NotificationMode::Mentions, "Mentions"),
                                (NotificationMode::Off, "Off"),
                            ] {
                                if components::choice(
                                    ui,
                                    room_preferences.notifications == mode,
                                    label,
                                )
                                .clicked()
                                {
                                    room_preferences.notifications = mode;
                                }
                            }
                        });
                        ui.checkbox(&mut room_preferences.sound, "Sound for this room");
                        if before != (room_preferences.notifications, room_preferences.sound) {
                            self.model.dispatch(Command::SetRoomPreferences {
                                room: room.summary.room,
                                preferences: room_preferences,
                            });
                        }
                    },
                );
            }
            ui.collapsing("Terminal", |ui| {
                ui.checkbox(
                    &mut preferences.ambiguous_wide,
                    "Ambiguous characters occupy two columns",
                );
            });
        });
        if before
            != (
                preferences.theme,
                preferences.density,
                preferences.chat_layout,
                preferences.text_scale,
                preferences.quiet,
                preferences.sound,
                preferences.ambiguous_wide,
            )
        {
            self.model.dispatch(Command::SetPreferences(preferences));
        }
    }

    pub(super) fn details(&mut self, ui: &mut egui::Ui) {
        let snapshot = self.model.snapshot.clone();
        ui.heading("Connection");
        egui::ScrollArea::vertical().show(ui, |ui| {
            components::section(ui, "HyperNet", |ui| {
                ui.horizontal_wrapped(|ui| {
                    components::accent_badge(ui, &display::connection(&snapshot));
                    if components::button(ui, "Reconnect").clicked() { self.model.dispatch(Command::Connect); }
                    if components::button(ui, "Disconnect").clicked() { self.model.dispatch(Command::Disconnect); }
                });
                egui::Grid::new("privacy-readout").spacing([24.0, 10.0]).show(ui, |ui| {
                    for (label, value) in display::privacy(snapshot.privacy.as_ref()) {
                        ui.weak(label); ui.add(egui::Label::new(value).wrap().selectable(true)); ui.end_row();
                    }
                    for (label, value) in display::federation_privacy(snapshot.federation_privacy.as_ref()) {
                        ui.weak(label); ui.add(egui::Label::new(value).wrap().selectable(true)); ui.end_row();
                    }
                });
                if let Some(status) = &snapshot.status {
                    ui.separator();
                    ui.strong(&status.code);
                    ui.add(egui::Label::new(&status.detail).wrap().selectable(true));
                }
            });
            components::section(ui, "Service", |ui| {
                for choice in &snapshot.services {
                    let name = if choice.agreement.is_none() { "Local origin".to_owned() } else { format!("Federated home {}", choice.home) };
                    if components::row(ui, choice.selected, &name).clicked() && !choice.selected {
                        self.model.dispatch(Command::SelectService(choice.agreement));
                    }
                }
                ui.collapsing("Identity", |ui| {
                    ui.weak("Account"); ui.monospace(snapshot.account.to_string());
                    ui.weak("Home"); ui.monospace(snapshot.home.to_string());
                });
            });
            components::section(ui, "Delivery", |ui| {
                if snapshot.deliveries.is_empty() { ui.weak("No recent operations"); }
                for delivery in snapshot.deliveries.iter().rev().take(64) {
                    ui.collapsing(format!("{:?}: {}", delivery.operation, display::delivery(delivery)), |ui| {
                        ui.weak("Operation"); ui.monospace(display::operation(delivery.operation_id));
                        ui.weak("Content digest"); ui.monospace(delivery.action_digest.to_string());
                        if let Some(room) = delivery.room { ui.weak("Room"); ui.monospace(room.to_string()); }
                        if matches!(delivery.outcome, Some(Outcome::Committed { .. })) {
                            ui.label("Durably committed by the home service. Recipient delivery and reading are separate.");
                        }
                        if delivery.abandoned { ui.label("Retries stopped. The retained outcome may still be unknown."); }
                        else if !matches!(delivery.outcome, Some(Outcome::Committed { .. } | Outcome::Rejected { .. } | Outcome::Result { .. }))
                            && components::button(ui, "Stop retrying").on_hover_text("Retain the unknown outcome; this does not cancel a message already committed").clicked() {
                            self.model.dispatch(Command::AbandonPending { operation_id: delivery.operation_id, action_digest: delivery.action_digest });
                        }
                    });
                }
            });
            components::section(ui, "Filters and moderation", |ui| {
                if components::button(ui, "Refresh").clicked() { self.model.dispatch(Command::Inspect); }
                if snapshot.inspection.stale { components::badge(ui, "Retained · authority unconfirmed", egui::Color32::from_rgb(211, 170, 91)); }
                for line in display::filters(&snapshot) { ui.label(line); }
                for line in display::restrictions(&snapshot) { ui.label(line); }
            });
        });
    }
}
