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
        ui.collapsing("Encryption and authorised endpoints", |ui| {
            self.encryption_content(ui, room, moderator);
        });
    }
    fn encryption_content(&mut self, ui: &mut egui::Ui, room: &RoomView, moderator: bool) {
        let id = room.summary.room;
        ui.label("Room names, topics and membership are visible to the home service. New devices receive future encrypted traffic only.");
        ui.horizontal_wrapped(|ui| {
            if ui.button("Inspect current encryption").clicked() {
                self.model.dispatch(Command::CryptoInspect {
                    room: id,
                    grant: None,
                });
            }
            if ui.button("Enrol this endpoint's encryption key").clicked() {
                self.model.dispatch(Command::CryptoEnrol);
            }
            if ui.button("Request future-message access").clicked() {
                self.model.dispatch(Command::CryptoPublish {
                    room: id,
                    grant: None,
                });
            }
            if ui.button("Synchronise encrypted history").clicked() {
                self.model.dispatch(Command::CryptoSync {
                    room: id,
                    grant: None,
                });
            }
        });
        let Some(view) = &room.crypto else {
            ui.label(
                "Inspect encryption to view fingerprints, pending endpoints and the send barrier.",
            );
            return;
        };
        if room.stale {
            ui.label("Retained encryption state; current authority is unconfirmed.");
        }
        let sending = if view.remote.send_barrier {
            "blocked"
        } else {
            "permitted for ready endpoints"
        };
        let verification = if view.remote.frozen {
            "frozen"
        } else {
            "active"
        };
        ui.label(format!(
            "Epoch {} · sending {sending} · verification {verification}",
            view.remote.epoch
        ));
        if let Some(group) = view.remote.group {
            ui.label(format!("Group {group}"));
        }
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
        let label = format!("{} · {state}", display::short_account(contact.account));
        ui.collapsing(label, |ui| {
            ui.label(contact.account.to_string());
            ui.label(format!("First-contact fingerprint {}", contact.anchor));
            ui.label(format!("Recovery public key {}", contact.recovery_key));
            match contact.state {
                TrustState::UntrustedRegistration | TrustState::LegacyAnchor => {
                    let legacy = contact.state == TrustState::LegacyAnchor;
                    ui.label(if legacy {
                        "This legacy identity lacks a signed original registration. Accept only after independently checking its fingerprint."
                    } else {
                        "Compare this fingerprint with the intended contact before trusting it. A valid signature alone does not identify the person you intended."
                    });
                    let label = if legacy { "Accept this legacy anchor" } else { "Trust this exact fingerprint" };
                    if ui.button(label).clicked() {
                        self.model.dispatch(Command::TrustContact { account: contact.account, anchor_digest: contact.anchor, legacy });
                    }
                }
                TrustState::Trusted => { ui.label("The current signed continuity extends the pinned identity."); }
                TrustState::Changed => { ui.colored_label(egui::Color32::YELLOW, "Identity continuity changed; encrypted admission is blocked."); }
            }
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
            ui.horizontal_wrapped(|ui| {
                ui.label(format!(
                    "{} · endpoint {endpoint}",
                    display::actor(&member.actor, &room.members)
                ));
                if view.remote.required_removals.contains(&endpoint) {
                    ui.label("Removal required before sending");
                }
                if moderator && ui.button("Remove endpoint").clicked() {
                    self.model.dispatch(Command::CryptoCommit {
                        room: id,
                        additions: vec![],
                        removals: vec![endpoint],
                    });
                }
            });
        }
        if !moderator {
            return;
        }
        if view.remote.group.is_none() && ui.button("Start encrypted group").clicked() {
            self.model.dispatch(Command::CryptoInitialise {
                room: id,
                recover: false,
            });
        }
        for package in &view.remote.packages {
            ui.horizontal_wrapped(|ui| {
                ui.label(format!(
                    "Admission requested by {} · {}",
                    display::actor(&package.member.actor, &room.members),
                    package.member.actor.acting().endpoint
                ));
                if ui.button("Admit this endpoint").clicked() {
                    self.model.dispatch(Command::CryptoCommit {
                        room: id,
                        additions: vec![package.digest],
                        removals: vec![],
                    });
                }
            });
        }
        if room.summary.confidentiality == RoomConfidentiality::PrivateGroup {
            ui.add(
                egui::TextEdit::singleline(&mut self.invite_account)
                    .hint_text("Account ID to invite")
                    .char_limit(200),
            );
            if ui.button("Invite account").clicked()
                && let Ok(account) = self.invite_account.parse()
            {
                self.model.dispatch(Command::Invite { room: id, account });
            }
        }
        if view.remote.group.is_some() && (view.remote.frozen || view.remote.send_barrier) {
            ui.checkbox(&mut self.confirm_recovery, "Start a new group; other endpoints must be readmitted and old history is not transferred");
            if ui
                .add_enabled(
                    self.confirm_recovery,
                    egui::Button::new("Recover into a fresh encrypted group"),
                )
                .clicked()
            {
                self.model.dispatch(Command::CryptoInitialise {
                    room: id,
                    recover: true,
                });
                self.confirm_recovery = false;
            }
        }
    }
}
