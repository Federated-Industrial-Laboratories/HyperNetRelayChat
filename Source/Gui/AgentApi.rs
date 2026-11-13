// SPDX-License-Identifier: Apache-2.0
//! Agent API preparation and launch expose private paths, never token or endpoint-key contents.
use super::*;
use crate::{onboarding::simple::Job, operations::participants as api};
use std::path::PathBuf;
#[derive(Default)]
pub(super) struct Form {
    profile: String,
    rooms: Vec<RoomId>,
    initiate: bool,
    history: bool,
    agent_replies: bool,
    entries: Vec<api::Entry>,
    entry: Option<api::Entry>,
    status: Option<api::Status>,
    job: Option<Job<std::result::Result<Completed, String>>>,
    message: Option<String>,
}
enum Completed {
    Prepared(Box<api::Entry>),
    Saved(Vec<api::Entry>),
    Status(api::Status),
}
impl Form {
    pub(super) fn select(&mut self, profile: PathBuf, request: &hrc::home::admission::Prepare) {
        self.job = None;
        self.profile = profile.display().to_string();
        self.rooms = request.rooms.iter().take(8).copied().collect();
        self.initiate = request.allow_initiate;
        self.agent_replies = request.allow_agent_replies;
        self.history = false;
        self.entry = None;
        self.status = None;
        self.message = None;
    }
    fn start(
        &mut self,
        ctx: &egui::Context,
        work: impl FnOnce(&std::sync::atomic::AtomicBool) -> std::result::Result<Completed, String>
        + Send
        + 'static,
    ) {
        self.message = None;
        self.job = Some(Job::start(ctx, move |cancel| Ok(work(cancel))));
    }
    fn poll(&mut self, ctx: &egui::Context) {
        if let Some(result) = self.job.as_ref().and_then(Job::result) {
            self.job = None;
            match result {
                Ok(Ok(Completed::Prepared(entry))) => {
                    self.entry = Some(*entry);
                    self.status = None;
                }
                Ok(Ok(Completed::Saved(entries))) => self.entries = entries,
                Ok(Ok(Completed::Status(status))) => self.status = Some(status),
                Ok(Err(error)) => self.message = Some(error),
                Err(error) => self.message = Some(error.to_string()),
            }
        }
        if self.job.is_some() {
            ctx.request_repaint_after(Duration::from_millis(100));
        }
    }
}
impl App {
    pub(super) fn agent_api_form(&mut self, ui: &mut egui::Ui) {
        if self.model.snapshot.classification != AccountClass::Human {
            ui.label("Open the human operator profile to manage its external Agents.");
            return;
        }
        let operator = self.model.snapshot.account;
        let ctx = ui.ctx().clone();
        let form = &mut self.grant.api;
        form.poll(&ctx);
        ui.label("Connect a local application through the private API, without configuring a model. HRC's API process owns the Agent profile; your application uses the socket and credential file.");
        if let Some(message) = &form.message {
            ui.colored_label(theme::warning(ui), message);
        }
        if let Some(job) = &form.job {
            ui.horizontal(|ui| {
                ui.spinner();
                ui.label("Preparing or checking the Agent API…");
                if components::button(ui, "Cancel").clicked() {
                    job.cancel();
                }
            });
        }
        ui.add_enabled_ui(form.job.is_none(),|ui|{
            if components::button(ui,"Find saved Agent APIs").clicked(){form.start(&ctx,move |_|api::saved(operator).map(Completed::Saved));}
            for entry in &form.entries {
                let label=self.model.snapshot.inspection.agents.iter().find(|a|a.actor.account==entry.account).map(|a|hrc::text::identity_display(&a.nickname)).unwrap_or_else(||display::short_account(entry.account));
                if ui.button(label).clicked(){form.profile=entry.configuration.profile.display().to_string();form.entry=Some(entry.clone());form.status=None;}
            }
            if let Some(entry)=form.entry.clone() {
                ui.strong("Private application connection");
                if let Some(status)=&form.status {
                    ui.label(if status.paused {"Last check: API requests paused by the application"} else if status.connected {"Last check: API ready and Agent connected to chat"} else if status.api_ready {"Last check: API available; Agent is reconnecting to chat"} else if status.active {"Last check: API process running; connection not yet confirmed"} else {"Last check: API stopped"});
                    if let Some(error)=&status.last_error {ui.colored_label(theme::warning(ui),error);}
                } else {ui.weak("Check status or start the API to confirm readiness.");}
                ui.horizontal(|ui|{
                    if components::primary(ui,"Start API").clicked(){let c=entry.configuration.clone();form.start(&ctx,move |cancel|api::start(&c,cancel).map(Completed::Status));}
                    if components::button(ui,"Refresh status").clicked(){let c=entry.configuration.clone();form.start(&ctx,move |cancel|api::status(&c,cancel).map(Completed::Status));}
                    if components::button(ui,"Stop API").clicked(){let c=entry.configuration.clone();form.start(&ctx,move |cancel|api::stop(&c,cancel).map(Completed::Status));}
                });
                ui.label(format!("Socket: {}",entry.socket.display()));
                if components::button(ui,"Copy socket path").clicked(){ui.ctx().copy_text(entry.socket.display().to_string());}
                ui.label(format!("Credential file: {}",entry.configuration.credential.display()));
                if components::button(ui,"Copy credential file path").clicked(){ui.ctx().copy_text(entry.configuration.credential.display().to_string());}
                if components::button(ui,"Copy stdio launch settings").clicked()
                    && let Ok(executable)=std::env::current_exe() {
                    ui.ctx().copy_text(serde_json::to_string_pretty(&serde_json::json!({"command":executable,"args":["integration","serve","--config",entry.configuration.api.to_string_lossy(),"--stdio"],"credentialFile":entry.configuration.credential,"protocol":"HRC JSON-RPC 1.0"})).unwrap_or_default());
                }
                ui.small("For stdio, stop the managed API first and let your application launch it. Keep credential files private. Stop API releases the chat profile; Home pause/revoke controls remain below.");
                if components::button(ui,"Choose another Agent").clicked(){form.entry=None;form.status=None;}
            } else {
                ui.label("Agent profile folder");ui.text_edit_singleline(&mut form.profile);
                ui.weak("The profile is filled automatically after Add Agent. You can also select a separately admitted local Agent profile.");
                for room in self.model.snapshot.rooms.iter().filter(|r|r.joined) {
                    let mut selected=form.rooms.contains(&room.room);
                    if ui.checkbox(&mut selected,hrc::text::identity_display(&room.name)).changed(){
                        if selected&&form.rooms.len()<8{form.rooms.push(room.room);form.rooms.sort();}
                        if !selected{form.rooms.retain(|r|r!=&room.room);}
                    }
                }
                ui.small("Select up to eight rooms. The server also enforces the Agent's admitted room permissions.");
                ui.checkbox(&mut form.history,"Allow history queries");
                ui.checkbox(&mut form.initiate,"Allow starting messages within admitted permissions");
                ui.checkbox(&mut form.agent_replies,"Allow replies to Agents within admitted permissions");
                if ui.add_enabled_ui(!form.profile.trim().is_empty()&&!form.rooms.is_empty(),|ui|components::primary(ui,"Prepare private API connection")).inner.clicked(){
                    let profile=PathBuf::from(&form.profile);let scope=hrc::integration::Scope{rooms:form.rooms.clone(),initiate:form.initiate,history:form.history,agent_replies:form.agent_replies};
                    form.start(&ctx,move |_|api::prepare(&profile,operator,scope).map(|entry|Completed::Prepared(Box::new(entry))));
                }
            }
        });
    }
}
