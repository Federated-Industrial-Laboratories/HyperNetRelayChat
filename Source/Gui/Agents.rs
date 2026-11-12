// SPDX-License-Identifier: Apache-2.0
//! Explicit room-scoped grants and exact proposed actions remain inspectable.
use super::*;
use hrc::delegation::{self, Mode};
use std::time::{SystemTime, UNIX_EPOCH};

pub(super) struct GrantForm {
    pub(super) api: super::agent_api::Form,
    pub(super) simple: super::simple_agents::Form,
    admission_request: String,
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
            api: Default::default(),
            simple: Default::default(),
            admission_request: String::new(),
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
fn mode_name(mode: Mode) -> &'static str {
    match mode {
        Mode::Draft => "Draft only",
        Mode::Approve => "Exact approval",
        Mode::Autonomous => "Autonomous",
    }
}
impl App {
    pub(super) fn agents(&mut self, ui: &mut egui::Ui) {
        let snapshot = self.model.snapshot.clone();
        ui.horizontal(|ui| {
            ui.heading("Agents");
            if components::button(ui, "Refresh").clicked() {
                self.model.dispatch(Command::Inspect);
            }
        });
        if snapshot.inspection.stale {
            components::badge(ui, "Retained · refresh required", theme::warning(ui));
        }
        egui::ScrollArea::vertical().show(ui, |ui| {
            components::frame(ui).show(ui, |ui| {
                ui.set_width(ui.available_width());
                ui.collapsing("New room grant", |ui| self.grant_form(ui));
            });
            components::section(ui,"Add an external Agent",|ui|self.simple_agent_form(ui));
            components::section(ui,"Connect an Agent application",|ui|self.agent_api_form(ui));
            ui.collapsing("Manual Agent request and consent exchange",|ui|self.admission_form(ui));
            for agent in &snapshot.inspection.agents {
                if let Some(scope)=&agent.admission_scope {
                    components::section(ui,&hrc::text::identity_display(&agent.nickname),|ui|{
                        ui.label(if scope.revoked {"Access revoked"} else if scope.paused {"Access paused"} else {"External Agent access active"});
                        ui.weak(if scope.allow_agent_replies { "May reply to other Agents" } else { "Replies to people only" });
                        ui.weak(if scope.allow_initiate {"May start messages in its selected rooms"} else {"Replies only in its selected rooms"});
                        if let Some(old)=scope.successor_of {ui.label(format!("Successor to {old}"));}
                        if !scope.revoked {ui.horizontal(|ui|{
                            if components::button(ui,if scope.paused {"Resume access"} else {"Pause access"}).clicked(){self.model.dispatch(Command::AgentAccess(hrc::home::admission::AgentAccess{account:agent.actor.account,rooms:scope.rooms.clone(),allow_initiate:scope.allow_initiate,allow_agent_replies:scope.allow_agent_replies,paused:!scope.paused,revoke:false}));}
                            let revoke=components::button(ui,"Revoke access…");egui::Popup::menu(&revoke).show(|ui|{ui.label("Permanently revoke this Agent's Home access?");if components::button(ui,"Revoke Agent access").clicked(){self.model.dispatch(Command::AgentAccess(hrc::home::admission::AgentAccess{account:agent.actor.account,rooms:scope.rooms.clone(),allow_initiate:false,allow_agent_replies:false,paused:true,revoke:true}));ui.close();}});
                        });}
                    });
                }
            }
            ui.add_space(10.0);
            if snapshot.inspection.grants.is_empty() {
                components::section(ui, "Grants", |ui| { ui.weak("No grants in this inspection"); });
            }
            for grant in &snapshot.inspection.grants {
                let name = snapshot.inspection.agents.iter().find(|agent| agent.actor == grant.scope.agent)
                    .map(|agent| hrc::text::identity_display(&agent.nickname))
                    .unwrap_or_else(|| display::short_account(grant.scope.agent.account));
                components::section(ui, &name, |ui| {
                    ui.horizontal_wrapped(|ui| {
                        components::accent_badge(ui, mode_name(grant.scope.mode));
                        components::muted_badge(ui, &format!("{:?}", grant.state));
                        components::readout(ui, "LIMIT", &format!("{}/min", grant.scope.max_operations_per_minute));
                    });
                    if !grant.scope.purpose.is_empty() { ui.add(egui::Label::new(&grant.scope.purpose).wrap()); }
                    ui.weak(format!("Expires {}", display::timestamp(grant.scope.expires_ms)));
                    ui.horizontal_wrapped(|ui| {
                        if components::button(ui, "Inspect").clicked() { self.model.dispatch(Command::InspectGrant(grant.reference)); }
                        let change = match grant.state {
                            delegation::State::Active => Some(("Pause", hrc::client::GrantChange::Pause)),
                            delegation::State::Paused => Some(("Resume", hrc::client::GrantChange::Resume)),
                            delegation::State::Revoked => None,
                        };
                        if let Some((label, change)) = change {
                            if components::button(ui, label).on_hover_text("Pause stops subsequent delegated effects. Resume keeps the original scope and expiry.").clicked() {
                                self.model.dispatch(Command::ChangeGrant { grant: grant.reference, change });
                            }
                            let revoke = components::button(ui, "Revoke…");
                            egui::Popup::menu(&revoke).show(|ui| {
                                ui.label("Permanently revoke this grant?");
                                ui.label("Restoring access requires a new grant. Received content remains received.");
                                if components::button(ui, "Revoke grant").clicked() {
                                    self.model.dispatch(Command::ChangeGrant { grant: grant.reference, change: hrc::client::GrantChange::Revoke });
                                    ui.close();
                                }
                            });
                        }
                    });
                });
            }
            if let Some(inspection) = &snapshot.inspection.grant {
                let grant = &inspection.grant;
                components::section(ui, "Selected grant", |ui| {
                    egui::Grid::new("grant-scope").spacing([20.0, 9.0]).show(ui, |ui| {
                        for (label, value) in [
                            ("Mode", mode_name(grant.scope.mode).to_owned()),
                            ("Operations", format!("{:?}", grant.scope.operations)),
                            ("Valid from", display::timestamp(grant.scope.not_before_ms)),
                            ("Expires", display::timestamp(grant.scope.expires_ms)),
                            ("History from", display::timestamp(grant.scope.history_from_ms)),
                            ("History until", display::timestamp(grant.scope.history_until_ms)),
                        ] { ui.weak(label); ui.add(egui::Label::new(value).wrap()); ui.end_row(); }
                    });
                    ui.collapsing("Identity and scope", |ui| {
                        for (label, value) in [
                            ("Grant", format!("{} · generation {}", grant.reference.id, grant.reference.generation)),
                            ("Owner", grant.owner.to_string()), ("Agent", grant.scope.agent.account.to_string()),
                            ("Service", grant.home.to_string()),
                            ("Rooms", grant.scope.rooms.iter().map(ToString::to_string).collect::<Vec<_>>().join(", ")),
                        ] { ui.weak(label); ui.add(egui::Label::new(value).wrap().selectable(true)); }
                    });
                });
                for pending in &inspection.pending {
                    components::section(ui, "Proposed action", |ui| {
                        let action = snapshot.inspection.proposed.iter()
                            .find(|action| hrc::protocol::action_digest(action).is_ok_and(|digest| digest == pending.action_digest));
                        if let Some(action) = action {
                            ui.horizontal_wrapped(|ui| {
                                components::accent_badge(ui, &format!("{:?}", action.operation));
                                ui.label(display::actor(&action.actor, snapshot.selected.as_ref().map_or(&[][..], |room| room.members.as_slice())));
                            });
                            ui.add(egui::Label::new(format!("{:?}", action.target)).wrap().selectable(true));
                            if let Some(hrc::client::MessageContent::Decrypted(body)) = snapshot.inspection.proposed_content.get(&pending.action_digest) {
                                ui.add(egui::Label::new(&body.text).wrap().selectable(true));
                            } else if action.body.deserialized::<hrc::crypto::EncryptedBody>().is_ok() {
                                components::badge(ui, "Plaintext not verified · approval blocked", theme::warning(ui));
                            } else if let Ok(body) = action.body.deserialized::<hrc::messaging::Send>() {
                                ui.add(egui::Label::new(body.text).wrap().selectable(true));
                            } else if let Ok(json) = serde_json::to_string_pretty(&action.body) {
                                ui.add(egui::Label::new(egui::RichText::new(json).monospace()).wrap().selectable(true));
                            }
                        } else { ui.colored_label(theme::warning(ui), "Candidate verification unavailable"); }
                        ui.weak(format!("Expires {} · state {}", display::timestamp(pending.expires_ms), pending.state));
                        ui.collapsing("Identity and action digest", |ui| {
                            if let Some(action) = action { ui.add(egui::Label::new(format!("{:?}", action.actor)).wrap().selectable(true)); }
                            ui.add(egui::Label::new(pending.action_digest.to_string()).wrap().selectable(true));
                        });
                        ui.horizontal_wrapped(|ui| {
                            let verified = action.is_some_and(|a| a.body.deserialized::<hrc::crypto::EncryptedBody>().is_err()
                                || matches!(snapshot.inspection.proposed_content.get(&pending.action_digest), Some(hrc::client::MessageContent::Decrypted(_)))) && pending.state == 0;
                            if ui.add_enabled_ui(verified, |ui| components::primary(ui, "Approve exact")).inner.clicked() {
                                self.model.dispatch(Command::DecideApproval { grant: grant.reference,
                                    decision: delegation::Decision { approval: pending.approval, action_digest: pending.action_digest }, approve: true });
                            }
                            if components::button(ui, "Reject").clicked() {
                                self.model.dispatch(Command::DecideApproval { grant: grant.reference,
                                    decision: delegation::Decision { approval: pending.approval, action_digest: pending.action_digest }, approve: false });
                            }
                        });
                    });
                }
            }
        });
    }

    fn admission_form(&mut self, ui: &mut egui::Ui) {
        ui.label("Paste the public request from a new external Agent. The Agent keeps its own private keys and uses the API or CLI.");
        ui.add(
            egui::TextEdit::multiline(&mut self.grant.admission_request)
                .char_limit(16384)
                .desired_rows(4)
                .desired_width(ui.available_width()),
        );
        if let Ok(request) =
            serde_json::from_str::<hrc::home::admission::Prepare>(&self.grant.admission_request)
        {
            ui.label(format!("New Agent: {}", request.identity.account));
            ui.label(format!("Native principal: {}", request.native_principal));
            ui.label(if request.allow_initiate {
                "Permission: read, reply and start messages"
            } else {
                "Permission: read and reply"
            });
            ui.label(if request.allow_agent_replies {
                "May reply to other Agents (bounded causal chains)"
            } else {
                "May reply to people only"
            });
            for room in &request.rooms {
                let name = self
                    .model
                    .snapshot
                    .rooms
                    .iter()
                    .find(|r| r.room == *room)
                    .map(|r| r.name.as_str())
                    .unwrap_or("Unlisted room");
                ui.label(format!("{name} · {room}"));
            }
            if request.successor {
                ui.label("Create a visible successor to this account. Resolve pending sends and stop the old automation first. Old messages and keys remain unchanged.");
            }
            let own = request.classification
                == hrc::home::admission::Classification::Agent {
                    operator: self.model.snapshot.account,
                }
                && request.operator_consent.is_none();
            if ui
                .add_enabled_ui(own, |ui| {
                    components::primary(ui, "Authorize this exact Agent")
                })
                .inner
                .clicked()
            {
                self.model.dispatch(Command::ConsentAgent(request));
            }
        }
        if let Some(consent) = &self.model.snapshot.inspection.admission_consent {
            ui.label("Consent issued. Return this receipt to the join workflow before it expires.");
            if let Ok(json) = serde_json::to_string_pretty(consent)
                && components::button(ui, "Copy consent receipt").clicked()
            {
                ui.ctx().copy_text(json);
            }
        }
    }
    fn grant_form(&mut self, ui: &mut egui::Ui) {
        let snapshot = self.model.snapshot.clone();
        let Some(room) = &snapshot.selected else {
            ui.weak("Select a room first");
            return;
        };
        components::field(ui, "Room", |ui| {
            ui.label(format!(
                "# {}",
                hrc::text::identity_display(&room.summary.name)
            ))
            .on_hover_text(room.summary.room.to_string());
        });
        components::field(ui, "Agent", |ui| {
            if snapshot.inspection.agents.is_empty() {
                ui.weak("No agent endpoints in this inspection");
            }
            for agent in &snapshot.inspection.agents {
                let label = format!(
                    "{} · {}",
                    hrc::text::identity_display(&agent.nickname),
                    display::short_account(agent.actor.account)
                );
                if components::row(ui, self.grant.agent.as_ref() == Some(&agent.actor), &label)
                    .clicked()
                {
                    self.grant.agent = Some(agent.actor.clone());
                }
            }
        });
        components::field(ui, "Mode", |ui| {
            ui.horizontal_wrapped(|ui| {
                for mode in [Mode::Draft, Mode::Approve, Mode::Autonomous] {
                    if components::choice(ui, self.grant.mode == mode, mode_name(mode)).clicked() {
                        self.grant.mode = mode;
                    }
                }
            });
        });
        components::field(ui, "Operations", |ui| {
            egui::Grid::new("grant-operations")
                .min_col_width(180.0)
                .show(ui, |ui| {
                    ui.checkbox(&mut self.grant.read, "Read and search");
                    ui.checkbox(&mut self.grant.reply, "Reply");
                    ui.end_row();
                    ui.checkbox(&mut self.grant.initiate, "New messages");
                    ui.checkbox(&mut self.grant.mark_read, "Mark handled/read");
                    ui.end_row();
                    ui.checkbox(&mut self.grant.moderate, "Moderate");
                    ui.end_row();
                });
        });
        components::field(ui, "Validity", |ui| {
            ui.add(egui::Slider::new(&mut self.grant.hours, 1..=168).suffix(" h"));
        });
        components::field(ui, "Past history", |ui| {
            ui.add(egui::Slider::new(&mut self.grant.history_hours, 0..=720).suffix(" h"))
                .on_hover_text("0 grants future history only");
        });
        components::field(ui, "Rate limit", |ui| {
            ui.add(egui::Slider::new(&mut self.grant.rate, 1..=60).suffix(" / min"));
        });
        components::field(ui, "Purpose", |ui| {
            ui.add(
                egui::TextEdit::multiline(&mut self.grant.purpose)
                    .char_limit(512)
                    .desired_rows(2)
                    .desired_width(ui.available_width()),
            );
        });
        if components::primary(ui, "Create grant").clicked() {
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
