// SPDX-License-Identifier: Apache-2.0
//! Explicit room-scoped grants and exact proposed actions remain inspectable.
use super::*;
use hrc::delegation::{self, Mode};
use std::time::{SystemTime, UNIX_EPOCH};
pub(super) struct GrantForm {
    agent: Option<EndpointActor>,
    mode: Mode,
    hours: u32,
    history_hours: u32,
    rate: u16,
    purpose: String,
    read: bool,
    reply: bool,
    initiate: bool,
    mark_read: bool,
    moderate: bool,
}
impl Default for GrantForm {
    fn default() -> Self {
        Self {
            agent: None,
            mode: Mode::Draft,
            hours: 1,
            history_hours: 0,
            rate: 5,
            purpose: String::new(),
            read: true,
            reply: false,
            initiate: false,
            mark_read: false,
            moderate: false,
        }
    }
}
impl App {
    pub(super) fn agents(&mut self, ui: &mut egui::Ui) {
        let snapshot = self.model.snapshot.clone();
        ui.heading("Agents and delegation");
        ui.label("Purpose describes intent. The exact room, operations, history, time and rate define the enforced permission.");
        if ui.button("Refresh agents and grants").clicked() {
            self.model.dispatch(Command::Inspect);
        }
        if snapshot.inspection.stale {
            ui.colored_label(
                egui::Color32::YELLOW,
                "Retained inspection; reconnect and refresh before acting",
            );
        }
        egui::ScrollArea::vertical().show(ui, |ui| {
            ui.collapsing("Create a grant for the selected room", |ui| self.grant_form(ui));
            for grant in &snapshot.inspection.grants {
                ui.group(|ui| {
                    ui.strong(format!("{} · {:?} · {:?}",display::short_account(grant.scope.agent.account),grant.scope.mode,grant.state));
                    ui.label(&grant.scope.purpose);
                    ui.label(format!("Expires UTC {} · {} operations/minute",display::timestamp(grant.scope.expires_ms),grant.scope.max_operations_per_minute));
                    ui.horizontal_wrapped(|ui| {
                        if ui.button("Inspect scope and approvals").clicked() { self.model.dispatch(Command::InspectGrant(grant.reference)); }
                        for (label,change) in [("Pause",hrc::client::GrantChange::Pause),("Resume",hrc::client::GrantChange::Resume),("Revoke permanently",hrc::client::GrantChange::Revoke)] {
                            if ui.button(label).clicked() { self.model.dispatch(Command::ChangeGrant { grant:grant.reference,change }); }
                        }
                    });
                });
            }
            if let Some(inspection) = &snapshot.inspection.grant {
                ui.separator(); ui.heading("Selected grant");
                let grant = &inspection.grant;
                ui.label(format!("Grant {} generation {}",grant.reference.id,grant.reference.generation));
                ui.label(format!("Owner {} · Agent {}",grant.owner,grant.scope.agent.account));
                ui.label(format!("Target service {}",grant.home));
                ui.label(format!("Rooms: {}",grant.scope.rooms.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")));
                ui.label(format!("Operations: {:?}",grant.scope.operations));
                ui.label(format!("Valid UTC {}..{}; history UTC {}..{}",display::timestamp(grant.scope.not_before_ms),display::timestamp(grant.scope.expires_ms),display::timestamp(grant.scope.history_from_ms),display::timestamp(grant.scope.history_until_ms)));
                ui.label("Pause stops later delegated effects. Revocation requires a new grant to restore access. Already received content remains received.");
                for pending in &inspection.pending {
                    ui.group(|ui| {
                        ui.strong("Exact proposed action");
                        let action = snapshot.inspection.proposed.iter().find(|action|hrc::protocol::action_digest(action).is_ok_and(|digest|digest == pending.action_digest));
                        if let Some(action) = action {
                            ui.label(format!("{:?} · {:?}",action.operation,action.target));
                            ui.label(format!("Attribution: {:?}",action.actor));
                            if let Some(hrc::client::MessageContent::Decrypted(body))=snapshot.inspection.proposed_content.get(&pending.action_digest) {ui.add(egui::Label::new(&body.text).wrap().selectable(true));}
                            else if action.body.deserialized::<hrc::crypto::EncryptedBody>().is_ok() {ui.label("Encrypted proposal cannot be approved until this endpoint verifies its plaintext.");}
                            else if let Ok(body) = action.body.deserialized::<hrc::messaging::Send>() { ui.add(egui::Label::new(body.text).wrap().selectable(true)); }
                            else if let Ok(json) = serde_json::to_string_pretty(&action.body) { ui.monospace(json); }
                        } else { ui.label("Candidate could not be verified for display"); }
                        ui.label(format!("Digest {} · expires UTC {} · state {}",pending.action_digest,display::timestamp(pending.expires_ms),pending.state));
                        ui.horizontal(|ui| {
                            if ui.add_enabled(action.is_some_and(|a|a.body.deserialized::<hrc::crypto::EncryptedBody>().is_err() || matches!(snapshot.inspection.proposed_content.get(&pending.action_digest),Some(hrc::client::MessageContent::Decrypted(_)))) && pending.state == 0,egui::Button::new("Approve this exact action")).clicked() { self.model.dispatch(Command::DecideApproval { grant:grant.reference, decision:delegation::Decision {approval:pending.approval,action_digest:pending.action_digest}, approve:true }); }
                            if ui.button("Reject").clicked() { self.model.dispatch(Command::DecideApproval { grant:grant.reference, decision:delegation::Decision {approval:pending.approval,action_digest:pending.action_digest}, approve:false }); }
                        });
                    });
                }
            }
        });
    }
    fn grant_form(&mut self, ui: &mut egui::Ui) {
        let snapshot = self.model.snapshot.clone();
        let Some(room) = &snapshot.selected else {
            ui.label("Select the room to grant access to");
            return;
        };
        ui.label(format!(
            "Only room {} ({})",
            hrc::text::identity_display(&room.summary.name),
            room.summary.room
        ));
        for agent in &snapshot.inspection.agents {
            ui.radio_value(
                &mut self.grant.agent,
                Some(agent.actor.clone()),
                format!(
                    "{} · {}",
                    hrc::text::identity_display(&agent.nickname),
                    display::short_account(agent.actor.account)
                ),
            );
        }
        for (mode, label) in [
            (Mode::Draft, "Draft only"),
            (Mode::Approve, "Approve each exact action"),
            (Mode::Autonomous, "Act within the scope below"),
        ] {
            ui.radio_value(&mut self.grant.mode, mode, label);
        }
        ui.horizontal_wrapped(|ui| {
            ui.checkbox(&mut self.grant.read, "Read history and search");
            ui.checkbox(&mut self.grant.reply, "Reply");
            ui.checkbox(&mut self.grant.initiate, "Send new messages");
            ui.checkbox(&mut self.grant.mark_read, "Mark handled/read");
            ui.checkbox(&mut self.grant.moderate, "Moderate");
        });
        ui.add(egui::Slider::new(&mut self.grant.hours, 1..=168).text("Validity hours"));
        ui.add(
            egui::Slider::new(&mut self.grant.history_hours, 0..=720)
                .text("Previous history hours (0 = future only)"),
        );
        ui.add(egui::Slider::new(&mut self.grant.rate, 1..=60).text("Operations per minute"));
        ui.add(
            egui::TextEdit::multiline(&mut self.grant.purpose)
                .hint_text("Purpose")
                .char_limit(512)
                .desired_rows(2),
        );
        if ui.button("Create this explicit grant").clicked() {
            let Some(agent) = self.grant.agent.clone() else {
                self.model.error = Some("Select an agent endpoint".into());
                return;
            };
            let Ok(now) = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis() as u64)
            else {
                self.model.error = Some("Local time is unavailable".into());
                return;
            };
            let mut operations = Vec::new();
            if self.grant.read {
                operations.extend([Operation::HistoryPage, Operation::SearchQuery]);
            }
            if self.grant.reply {
                operations.push(Operation::MessageReply);
            }
            if self.grant.initiate {
                operations.extend([Operation::MessageSend, Operation::MessageAction]);
            }
            if self.grant.mark_read {
                operations.push(Operation::UnreadSet);
            }
            if self.grant.moderate {
                operations.extend([
                    Operation::ModerationSilence,
                    Operation::ModerationKick,
                    Operation::ModerationBan,
                ]);
            }
            let expires_ms = now + u64::from(self.grant.hours) * 3600000;
            self.model
                .dispatch(Command::CreateGrant(delegation::Create {
                    agent,
                    rooms: vec![room.summary.room],
                    recipients: vec![],
                    operations,
                    mode: self.grant.mode,
                    not_before_ms: now.saturating_sub(1000),
                    expires_ms,
                    history_from_ms: now
                        .saturating_sub(u64::from(self.grant.history_hours) * 3600000),
                    history_until_ms: expires_ms,
                    max_operations_per_minute: self.grant.rate,
                    purpose: self.grant.purpose.clone(),
                }));
        }
    }
}
