// SPDX-License-Identifier: Apache-2.0
//! Inspectable device trust and explicit private-room membership controls.
use super::*;
use hrc::client::{
    CryptoView, RoomView,
    trust::{ContactTrust, TrustState},
};

impl App {
    pub(super) fn encryption(&mut self, ui: &mut egui::Ui) {
        let snapshot = self.model.snapshot.clone();
        let Some(room) = &snapshot.selected else {
            return;
        };
        if room.summary.confidentiality == RoomConfidentiality::Community {
            return;
        }
        let moderator = room
            .members
            .iter()
            .any(|m| m.account == snapshot.account && m.moderator);
        ui.collapsing("Encryption", |ui| {
            self.encryption_content(ui, room, moderator)
        });
    }
    fn encryption_content(&mut self, ui: &mut egui::Ui, room: &RoomView, moderator: bool) {
        let id = room.summary.room;
        ui.horizontal_wrapped(|ui| {
            if components::button(ui, "Inspect").clicked() {
                self.model.dispatch(Command::CryptoInspect {
                    room: id,
                    grant: None,
                });
            }
            if components::button(ui, "Enrol device")
                .on_hover_text("Register this endpoint's encryption key")
                .clicked()
            {
                self.model.dispatch(Command::CryptoEnrol);
            }
            if components::button(ui, "Request access")
                .on_hover_text("Request future encrypted messages on this endpoint")
                .clicked()
            {
                self.model.dispatch(Command::CryptoPublish {
                    room: id,
                    grant: None,
                });
            }
            if components::button(ui, "Synchronise").clicked() {
                self.model.dispatch(Command::CryptoSync {
                    room: id,
                    grant: None,
                });
            }
        });
        let Some(view) = &room.crypto else {
            components::muted_badge(ui, "Encryption state not inspected");
            return;
        };
        if room.stale {
            components::badge(
                ui,
                "Retained · authority unconfirmed",
                egui::Color32::from_rgb(211, 170, 91),
            );
        }
        ui.horizontal_wrapped(|ui| {
            components::readout(ui, "EPOCH", &view.remote.epoch.to_string());
            components::readout(
                ui,
                "SEND",
                if view.remote.send_barrier {
                    "Blocked"
                } else {
                    "Ready endpoints"
                },
            );
            components::readout(
                ui,
                "VERIFY",
                if view.remote.frozen {
                    "Frozen"
                } else {
                    "Active"
                },
            );
        });
        ui.collapsing("Group details", |ui| {
            if let Some(group) = view.remote.group { ui.add(egui::Label::new(group.to_string()).wrap().selectable(true)); }
            ui.label("Names, topics and membership are visible to the home service. New devices receive future encrypted messages only.");
        });
        for contact in &view.contacts {
            self.encryption_contact(ui, contact);
        }
        self.encryption_members(ui, room, view, moderator);
    }
    fn encryption_contact(&mut self, ui: &mut egui::Ui, contact: &ContactTrust) {
        let state = match contact.state {
            TrustState::UntrustedRegistration => "Untrusted",
            TrustState::LegacyAnchor => "Legacy anchor",
            TrustState::Trusted => "Trusted",
            TrustState::Changed => "Changed",
        };
        ui.collapsing(format!("{} · {state}", display::short_account(contact.account)), |ui| {
            components::frame(ui).show(ui, |ui| {
                ui.set_width(ui.available_width());
                for (label, value) in [("Account", contact.account.to_string()), ("Fingerprint", contact.anchor.to_string()), ("Recovery public key", contact.recovery_key.to_string())] {
                    ui.weak(label); ui.add(egui::Label::new(egui::RichText::new(value).monospace()).wrap().selectable(true));
                }
                match contact.state {
                    TrustState::UntrustedRegistration | TrustState::LegacyAnchor => {
                        let legacy = contact.state == TrustState::LegacyAnchor;
                        ui.label(if legacy { "No signed original registration. Independently check this fingerprint before accepting." }
                            else { "Compare this fingerprint with the intended contact before trusting it." });
                        if components::button(ui, if legacy { "Accept legacy" } else { "Trust fingerprint" }).clicked() {
                            self.model.dispatch(Command::TrustContact { account: contact.account, anchor_digest: contact.anchor, legacy });
                        }
                    }
                    TrustState::Trusted => { components::accent_badge(ui, "Signed continuity matches"); }
                    TrustState::Changed => { components::badge(ui, "Identity changed · admission blocked", egui::Color32::from_rgb(211, 170, 91)); }
                }
            });
        });
    }
    fn encryption_members(
        &mut self,
        ui: &mut egui::Ui,
        room: &RoomView,
        view: &CryptoView,
        moderator: bool,
    ) {
        let id = room.summary.room;
        for member in &view.remote.members {
            let endpoint = member.actor.acting().endpoint;
            components::frame(ui).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.label(
                    egui::RichText::new(display::actor(&member.actor, &room.members)).strong(),
                );
                ui.add(
                    egui::Label::new(
                        egui::RichText::new(endpoint.to_string())
                            .small()
                            .monospace(),
                    )
                    .wrap()
                    .selectable(true),
                );
                if view.remote.required_removals.contains(&endpoint) {
                    components::badge(
                        ui,
                        "Removal required before sending",
                        egui::Color32::from_rgb(211, 170, 91),
                    );
                }
                if moderator && components::button(ui, "Remove device").clicked() {
                    self.model.dispatch(Command::CryptoCommit {
                        room: id,
                        additions: vec![],
                        removals: vec![endpoint],
                    });
                }
            });
            ui.add_space(6.0);
        }
        if !moderator {
            return;
        }
        if view.remote.group.is_none() && components::primary(ui, "Start group").clicked() {
            self.model.dispatch(Command::CryptoInitialise {
                room: id,
                recover: false,
            });
        }
        for package in &view.remote.packages {
            components::section(ui, "Device admission", |ui| {
                ui.strong(display::actor(&package.member.actor, &room.members));
                ui.add(
                    egui::Label::new(package.member.actor.acting().endpoint.to_string())
                        .wrap()
                        .selectable(true),
                );
                if components::button(ui, "Admit device").clicked() {
                    self.model.dispatch(Command::CryptoCommit {
                        room: id,
                        additions: vec![package.digest],
                        removals: vec![],
                    });
                }
            });
        }
        if room.summary.confidentiality == RoomConfidentiality::PrivateGroup {
            components::section(ui, "Invite account", |ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.invite_account)
                        .hint_text("Account ID")
                        .desired_width(ui.available_width())
                        .char_limit(200),
                );
                if components::button(ui, "Invite").clicked() {
                    match self.invite_account.parse() {
                        Ok(account) => {
                            self.model.dispatch(Command::Invite { room: id, account });
                        }
                        Err(_) => self.model.error = Some("Enter a valid account ID".into()),
                    }
                }
            });
        }
        if view.remote.group.is_some() && (view.remote.frozen || view.remote.send_barrier) {
            components::section(ui, "Group recovery", |ui| {
                ui.checkbox(
                    &mut self.confirm_recovery,
                    "Start a new group; readmit other devices. Old history is not transferred.",
                );
                if ui
                    .add_enabled_ui(self.confirm_recovery, |ui| {
                        components::button(ui, "Recover group")
                    })
                    .inner
                    .clicked()
                {
                    self.model.dispatch(Command::CryptoInitialise {
                        room: id,
                        recover: true,
                    });
                    self.confirm_recovery = false;
                }
            });
        }
    }
}
