// SPDX-License-Identifier: Apache-2.0
//! Readable Agent scope review uses the already-open operator controller.
use super::*;
use crate::onboarding::{
    simple::{self, Binding, Job, Joined},
    simple_agents::{self, Pending, Proposal},
};
use std::path::Path;
#[derive(Default)]
pub(super) struct Form {
    binding: Option<Binding>,
    rooms: Vec<RoomId>,
    initiate: bool,
    agent_replies: bool,
    successor: bool,
    job: Option<Job<Outcome>>,
    pending: Vec<Pending>,
    selected: Option<Pending>,
    consent_command: Option<u64>,
    joined: Option<Joined>,
    message: Option<String>,
}
enum Outcome {
    Prepared(Box<Pending>),
    Pending(Vec<Pending>),
    Joined(Joined),
}
impl App {
    pub(crate) fn configure_simple_server(&mut self, profile: &Path) {
        match simple::load(profile) {
            Ok(binding) => {
                self.initial_nickname(binding.as_ref().and_then(|b| b.initial_nickname.clone()));
                self.grant.simple.binding = binding;
            }
            Err(error) => self.grant.simple.message = Some(error.to_string()),
        }
    }
    pub(super) fn simple_agent_logic(&mut self, ctx: &egui::Context) {
        let form = &mut self.grant.simple;
        if let Some(outcome) = form.job.as_ref().and_then(Job::result) {
            form.job = None;
            match outcome {
                Ok(Outcome::Prepared(pending)) => {
                    form.selected = Some(*pending);
                    form.joined = None;
                    form.message = None;
                }
                Ok(Outcome::Pending(pending)) => {
                    form.pending = pending;
                    form.message =
                        Some("Choose an unfinished proposal below to review and resume it.".into());
                }
                Ok(Outcome::Joined(joined)) => {
                    if let Some(pending) = &form.selected {
                        self.grant
                            .api
                            .select(joined.hrc_profile.clone(), &pending.request);
                    }
                    form.joined = Some(joined);
                    form.selected = None;
                    form.pending.clear();
                    form.message = None;
                }
                Err(error) => form.message = Some(error.to_string()),
            }
        }
        if let Some(id) = form.consent_command
            && let Some(completion) = self
                .model
                .snapshot
                .completions
                .iter()
                .find(|c| c.request_id == id)
        {
            form.consent_command = None;
            if let Some(error) = &completion.error {
                form.message = Some(format!(
                    "Agent approval failed: {}. You can retry this proposal.",
                    error.code
                ));
            } else if let (Some(binding), Some(pending), Some(receipt)) = (
                form.binding.clone(),
                form.selected.clone(),
                self.model.snapshot.inspection.admission_consent.clone(),
            ) {
                if pending.matches_consent(&receipt) {
                    form.job = Some(Job::start(ctx, move |cancel| {
                        simple_agents::complete(&binding.suite, &pending, &receipt, cancel)
                            .map(Outcome::Joined)
                    }));
                } else {
                    form.message = Some(
                        "The approval did not match this proposal. Review and approve it again."
                            .into(),
                    );
                }
            }
        }
        if form.job.is_some() || form.consent_command.is_some() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }
    pub(super) fn simple_agent_form(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        let form = &mut self.grant.simple;
        let Some(binding) = form.binding.clone() else {
            ui.label("Simple Agent setup is available for servers joined through HyperNet. Manual Agent onboarding is available below.");
            return;
        };
        if self.model.snapshot.classification != AccountClass::Human {
            ui.label("Open the admitted human operator profile to add an Agent.");
            return;
        }
        if let Some(message) = &form.message {
            ui.label(message);
        }
        let busy = form.job.is_some() || form.consent_command.is_some();
        if busy {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label(if form.consent_command.is_some() {
                    "Waiting for signed operator approval…"
                } else {
                    "Preparing or connecting the separate Agent…"
                });
                if let Some(job) = &form.job
                    && components::button(ui, "Cancel").clicked()
                {
                    job.cancel();
                }
            });
        }
        ui.add_enabled_ui(!busy, |ui| {
            if let Some(joined) = &form.joined {
                ui.strong("Agent connected and ready for an external application");
                ui.label("Prepare and start its private API in Connect an Agent application below. Leave the operator's chat profile open.");
                ui.add(egui::Label::new(joined.hrc_profile.display().to_string()).wrap().selectable(true));
                if components::button(ui,"Copy Agent profile path").clicked() { ui.ctx().copy_text(joined.hrc_profile.display().to_string()); }
                ui.small("The API guide describes the private socket and stdio interfaces. Access and message attribution remain typed as Agent. Pause or revoke access below.");
            }
            if let Some(pending) = form.selected.clone() {
                ui.strong("Review proposed Agent identity");
                ui.add(egui::Label::new(pending.request.identity.account.to_string()).wrap().selectable(true));
                ui.small("Keys were created on this computer. Network admission happens after you approve.");
                for room in &pending.request.rooms {
                    let name = self.model.snapshot.rooms.iter().find(|r|r.room==*room).map(|r|hrc::text::identity_display(&r.name)).unwrap_or_else(||"Unlisted room".into());
                    ui.label(format!("Room: {name} ({room})"));
                }
                ui.label(if pending.request.allow_initiate {"May read, reply and start messages in these rooms."} else {"May read and reply in these rooms; cannot start messages."});
                ui.label(if pending.request.allow_agent_replies {"May reply to other Agents with finite causal-chain limits."} else {"Replies to people only."});
                if pending.request.successor { ui.label("Visible successor: stop the old automation first and resolve pending sends. Old messages and private keys remain unchanged."); }
                if components::primary(ui,"Approve and connect this Agent").clicked() {
                    form.message = None;
                    form.consent_command = self.model.dispatch(Command::ConsentAgent(pending.request));
                }
                if components::button(ui,"Back to Agent options").clicked() { form.selected = None; }
            } else {
                ui.label("Choose the rooms this external Agent can use. It gets its own keys and profile; it does not need HRC's built-in model feature.");
                for room in self.model.snapshot.rooms.iter().filter(|r|r.joined) {
                    let mut selected = form.rooms.contains(&room.room);
                    if ui.checkbox(&mut selected,hrc::text::identity_display(&room.name)).changed() {
                        if selected && form.rooms.len()<16 { form.rooms.push(room.room); form.rooms.sort(); }
                        if !selected { form.rooms.retain(|r|*r!=room.room); }
                    }
                }
                ui.checkbox(&mut form.initiate,"Allow starting messages");
                ui.checkbox(&mut form.agent_replies,"Allow replies to other Agents (finite causal chains)");
                ui.checkbox(&mut form.successor,"Create a visible successor for automation previously using this human account");
                let online = self.model.online_requested;
                if ui.add_enabled_ui(online && !form.rooms.is_empty(),|ui|components::primary(ui,"Prepare Agent for review")).inner.clicked() {
                    let proposal = Proposal{operator:self.model.snapshot.account,rooms:form.rooms.clone(),allow_initiate:form.initiate,allow_agent_replies:form.agent_replies,successor:form.successor};
                    let binding=binding.clone(); form.message=None;
                    form.job=Some(Job::start(&ctx,move |cancel|simple_agents::prepare(&binding,&proposal,cancel).map(|pending|Outcome::Prepared(Box::new(pending)))));
                }
                if !online { ui.weak("Connect your operator profile to approve an Agent."); }
                if components::button(ui,"Find unfinished Agent setups").clicked() {
                    let operator=self.model.snapshot.account;let binding=binding.clone();
                    form.job=Some(Job::start(&ctx,move |cancel|simple_agents::pending(&binding,operator,cancel).map(Outcome::Pending)));
                }
                for pending in &form.pending {
                    if ui.button(format!("Review {}",display::short_account(pending.request.identity.account))).clicked() { form.selected=Some(pending.clone()); }
                }
            }
        });
    }
}
