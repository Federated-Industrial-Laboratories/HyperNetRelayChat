// SPDX-License-Identifier: Apache-2.0
//! Inspectable privacy, delivery and presentation preferences.
use super::*;
use hrc::client::NotificationMode;
impl App {
    pub(super) fn help(&self, ui: &mut egui::Ui) {
        ui.heading("Commands and keyboard navigation");
        ui.label("Ctrl+Enter sends; Enter starts a new line. Ctrl+L focuses the composer. Ctrl+F focuses search. F1 opens help. Tab moves between controls.");
        ui.label("Choose a completion for a bound mention. A typed @name alone is plain text. Right-click a member for mention, ignore, notification and moderation controls.");
        egui::ScrollArea::vertical().show(ui, |ui| {
            egui::Grid::new("help-commands")
                .striped(true)
                .show(ui, |ui| {
                    for (command, description) in crate::commands::HELP {
                        ui.monospace(*command);
                        ui.label(*description);
                        ui.end_row();
                    }
                });
        });
    }
    pub(super) fn settings(&mut self, ui: &mut egui::Ui) {
        ui.heading("Appearance and notifications");
        let snapshot = self.model.snapshot.clone();
        let mut preferences = snapshot.preferences.clone();
        let before = (
            preferences.theme,
            preferences.density,
            preferences.text_scale,
            preferences.quiet,
            preferences.sound,
            preferences.ambiguous_wide,
        );
        ui.horizontal(|ui| {
            ui.label("Theme");
            ui.selectable_value(&mut preferences.theme, Theme::Dark, "Dark");
            ui.selectable_value(&mut preferences.theme, Theme::Light, "Light");
        });
        ui.horizontal(|ui| {
            ui.label("Density");
            ui.selectable_value(
                &mut preferences.density,
                Density::Comfortable,
                "Comfortable",
            );
            ui.selectable_value(&mut preferences.density, Density::Compact, "Compact");
        });
        ui.add(egui::Slider::new(&mut preferences.text_scale, 0.75..=2.0).text("Text scale"));
        ui.checkbox(&mut preferences.quiet, "Quiet mode");
        ui.checkbox(
            &mut preferences.sound,
            "Enable optional notification sounds",
        );
        ui.checkbox(
            &mut preferences.ambiguous_wide,
            "Treat ambiguous terminal characters as two columns",
        );
        if before
            != (
                preferences.theme,
                preferences.density,
                preferences.text_scale,
                preferences.quiet,
                preferences.sound,
                preferences.ambiguous_wide,
            )
        {
            self.model.dispatch(Command::SetPreferences(preferences));
        }
        if let Some(room) = &snapshot.selected {
            ui.separator();
            ui.heading(format!(
                "Notifications for {}",
                hrc::text::identity_display(&room.summary.name)
            ));
            let mut preferences = room.preferences.clone();
            let before = (preferences.notifications, preferences.sound);
            for (mode, label) in [
                (NotificationMode::All, "All messages"),
                (NotificationMode::Mentions, "Bound mentions only"),
                (NotificationMode::Off, "Off"),
            ] {
                ui.radio_value(&mut preferences.notifications, mode, label);
            }
            ui.checkbox(&mut preferences.sound, "Sound for this room");
            if before != (preferences.notifications, preferences.sound) {
                self.model.dispatch(Command::SetRoomPreferences {
                    room: room.summary.room,
                    preferences,
                });
            }
        }
        ui.separator();
        ui.label("Quiet mode suppresses notifications and sounds. Recipient ignore is enforced by the service before delivery, history, search and agent triggers.");
    }
    pub(super) fn details(&mut self, ui: &mut egui::Ui) {
        let snapshot = self.model.snapshot.clone();
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.heading("Connection and privacy"); ui.label(display::connection(&snapshot));
            ui.label(format!("Account {}",snapshot.account)); ui.label(format!("Home {}",snapshot.home));
            ui.label("Conversation service");
            for choice in &snapshot.services {
                let name = if choice.agreement.is_none() { "Local origin".to_owned() } else { format!("Federated home {}", choice.home) };
                if ui.selectable_label(choice.selected, name).clicked() && !choice.selected {
                    self.model.dispatch(Command::SelectService(choice.agreement));
                }
            }
            for (label,value) in display::privacy(snapshot.privacy.as_ref()) { ui.horizontal_wrapped(|ui| { ui.strong(label); ui.label(value); }); }
            for (label,value) in display::federation_privacy(snapshot.federation_privacy.as_ref()) { ui.horizontal_wrapped(|ui| { ui.strong(label); ui.label(value); }); }
            ui.label("Community messages are readable by their home service. Confidential messages require endpoint encryption; transport protection and relay privacy are separate properties.");
            ui.separator(); ui.heading("Delivery states");
            ui.label("Committed means the home service acknowledged its durable commit. It does not mean another person received or read the message.");
            for delivery in snapshot.deliveries.iter().rev().take(64) {
                ui.collapsing(format!("{:?}: {}",delivery.operation,display::delivery(delivery)),|ui| {
                    ui.label(format!("Operation {}",crate::display::operation(delivery.operation_id))); ui.label(format!("Content digest {}",delivery.action_digest));
                    if let Some(room) = delivery.room { ui.label(format!("Room {room}")); }
                    if delivery.abandoned { ui.label("Automatic retries stopped; the retained outcome may still be unknown"); }
                    else if !matches!(delivery.outcome,Some(Outcome::Committed { .. } | Outcome::Rejected { .. } | Outcome::Result { .. })) && ui.button("Stop retrying; retain unknown outcome").clicked() {
                        self.model.dispatch(Command::AbandonPending { operation_id:delivery.operation_id,action_digest:delivery.action_digest });
                    }
                });
            }
            ui.separator(); ui.heading("Filters and moderation");
            if ui.button("Refresh current inspection").clicked() { self.model.dispatch(Command::Inspect); }
            if snapshot.inspection.stale { ui.label("Retained inspection; current authority is not confirmed"); }
            for filter in &snapshot.inspection.filters { ui.label(format!("{} · ignored={} · muted={}",filter.subject,filter.ignored,filter.muted)); }
            for line in display::restrictions(&snapshot) { ui.label(line); }
        });
    }
}
