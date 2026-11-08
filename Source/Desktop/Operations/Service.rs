// SPDX-License-Identifier: Apache-2.0
//! Local service operation and explicit account admission controls.
use super::*;
#[derive(Clone, PartialEq)]
struct PolicySelection {
    generation: u64,
    directory: PathBuf,
    definition: PathBuf,
    configuration: Value,
}
pub(super) struct Form {
    pub config: ops::home::Configuration,
    file: PathBuf,
    principal: String,
    agent: bool,
    operator: String,
    invitation: PathBuf,
    pub(super) registration: PathBuf,
    restrict_creation: bool,
    creators: String,
    policy_selection: Option<PolicySelection>,
    selection_generation: u64,
}
impl Default for Form {
    fn default() -> Self {
        Self {
            config: ops::home::Configuration::at(PathBuf::new()),
            file: ops::root().join("Services/Home.json"),
            principal: String::new(),
            agent: false,
            operator: String::new(),
            invitation: ops::root().join("Exchange/Invitation.json"),
            registration: PathBuf::new(),
            restrict_creation: false,
            creators: String::new(),
            policy_selection: None,
            selection_generation: 0,
        }
    }
}
impl Form {
    pub(super) fn select_config(&mut self, config: ops::home::Configuration) {
        self.config = config;
        self.clear_policy();
    }
    fn clear_policy(&mut self) {
        self.selection_generation = self.selection_generation.wrapping_add(1);
        self.policy_selection = None;
        self.restrict_creation = false;
        self.creators.clear();
    }
    fn selection(&self) -> Option<PolicySelection> {
        let directory = self.config.directory.canonicalize().ok()?;
        if directory != self.config.directory {
            return None;
        }
        Some(PolicySelection {
            generation: self.selection_generation,
            directory,
            definition: self.file.clone(),
            configuration: serde_json::to_value(&self.config).ok()?,
        })
    }
    fn receive_policy(
        &mut self,
        selection: PolicySelection,
        policy: hrc::home::RoomCreationPolicy,
    ) -> ops::Result<()> {
        if self.selection().as_ref() != Some(&selection) {
            self.clear_policy();
            return Err("The selected service changed. Load its current policy again.".into());
        }
        match policy {
            hrc::home::RoomCreationPolicy::All => {
                self.restrict_creation = false;
                self.creators.clear();
            }
            hrc::home::RoomCreationPolicy::AllowList { accounts } => {
                self.restrict_creation = true;
                self.creators = accounts
                    .iter()
                    .map(ToString::to_string)
                    .collect::<Vec<_>>()
                    .join("\n");
            }
        }
        self.policy_selection = Some(selection);
        Ok(())
    }
    fn load_policy(&mut self) -> ops::Result<()> {
        self.clear_policy();
        let selected = self
            .selection()
            .ok_or("Select a valid canonical service folder.")?;
        let config = hrc::service::Config::load(&selected.directory)
            .map_err(|_| "Select a valid local service folder.".to_owned())?;
        self.receive_policy(selected, config.room_creation)
    }
    fn policy_ready(&self) -> bool {
        self.policy_selection.is_some() && self.policy_selection == self.selection()
    }
    fn creation_editor(&mut self, ui: &mut egui::Ui) -> egui::Response {
        if !self.policy_ready() {
            if self.policy_selection.is_some() {
                self.clear_policy();
            }
            ui.small(
                "Load the selected service's current policy before editing or applying changes.",
            );
        } else {
            ui.checkbox(
                &mut self.restrict_creation,
                "Only selected human accounts may create conversations",
            );
            if self.restrict_creation {
                ui.label("Complete account identifiers, one per line (at most 32)");
                ui.add(egui::TextEdit::multiline(&mut self.creators).desired_rows(3));
                ui.small("An empty list disables all creation. Agent accounts cannot inherit their operator's permission.");
            }
        }
        ui.small(
            "Applying the policy briefly stops this managed service and restores it afterwards.",
        );
        ui.add_enabled_ui(self.policy_ready(), |ui| {
            c::primary(ui, "Apply room creation policy")
        })
        .inner
    }
    fn take_policy(
        &mut self,
    ) -> ops::Result<(ops::home::Configuration, hrc::home::RoomCreationPolicy)> {
        if !self.policy_ready() {
            self.clear_policy();
            return Err(
                "Load the selected service's current policy before applying changes.".into(),
            );
        }
        let policy = if self.restrict_creation {
            let accounts = self
                .creators
                .split_whitespace()
                .map(str::parse)
                .collect::<std::result::Result<Vec<_>, _>>()
                .map_err(|_| "Enter complete human account identifiers.".to_owned())?;
            hrc::home::RoomCreationPolicy::AllowList { accounts }
        } else {
            hrc::home::RoomCreationPolicy::All
        };
        let config = self.config.clone();
        // Completion of this asynchronous update must never reactivate an old draft.
        self.clear_policy();
        Ok((config, policy))
    }
}
impl Workspace {
    pub(super) fn service_ui(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        ui.heading("HRC service");
        c::section(ui, "Local service", |ui| {
            path(
                ui,
                "Service folder",
                &mut self.service.config.directory,
                &mut self.picker,
                "service-directory",
                true,
            );
            path(
                ui,
                "Saved definition",
                &mut self.service.file,
                &mut self.picker,
                "service-file",
                false,
            );
            ui.horizontal_wrapped(|ui| {
                if c::button(ui, "Load").clicked() {
                    self.service.clear_policy();
                    match ops::home::Configuration::load(&self.service.file) {
                        Ok(config) => self.service.select_config(config),
                        Err(error) => self.error = Some(error),
                    }
                }
                if c::button(ui, "Save").clicked() {
                    let config = self.service.config.clone();
                    let file = self.service.file.clone();
                    self.start(&ctx, "Save service", Completion::General, move |cancel| {
                        config.save(&file, cancel)?;
                        Ok(serde_json::json!({"status":"Saved","file":file}))
                    });
                }
            });
            ui.collapsing("Resource and security limits", |ui| {
                limits(ui, &mut self.service.config.limits)
            });
            ui.horizontal_wrapped(|ui| {
                for (label, operation) in [("Refresh", 0), ("Start", 1), ("Stop", 2)] {
                    if c::button(ui, label).clicked() {
                        let config = self.service.config.clone();
                        self.start(&ctx, label, Completion::General, move |cancel| {
                            serde_json::to_value(match operation {
                                0 => ops::home::status(&config, cancel),
                                1 => ops::home::start(&config, cancel),
                                _ => ops::home::stop(&config, cancel),
                            }?)
                            .map_err(ops::failure)
                        });
                    }
                }
            });
        });
        c::section(ui, "Room creation", |ui| {
            ui.small("This service enforces the policy for new rooms and direct conversations. Existing conversations and their permissions stay unchanged.");
            if c::button(ui, "Load current policy").clicked()
                && let Err(error) = self.service.load_policy()
            {
                self.error = Some(error);
            }
            if self.service.creation_editor(ui).clicked() {
                match self.service.take_policy() {
                    Ok((config, policy)) => self.start(
                        &ctx,
                        "Apply room creation policy",
                        Completion::General,
                        move |cancel| ops::home::room_creation(&config, Some(policy), cancel),
                    ),
                    Err(error) => self.error = Some(error),
                }
            }
        });
        c::section(ui, "Account invitation", |ui| {
            field(ui, "HyperNet principal", &mut self.service.principal);
            ui.checkbox(&mut self.service.agent, "Agent account");
            if self.service.agent {
                field(ui, "Operator account", &mut self.service.operator);
            }
            path(
                ui,
                "Invitation file",
                &mut self.service.invitation,
                &mut self.picker,
                "service-invitation",
                false,
            );
            ui.small("Creating an invitation or accepting a registration briefly stops this managed HRC service. It resumes afterwards.");
            if c::primary(ui, "Create invitation").clicked() {
                let config = self.service.config.clone();
                let principal = self.service.principal.clone();
                let operator = self.service.agent.then(|| self.service.operator.clone());
                let output = self.service.invitation.clone();
                self.start(
                    &ctx,
                    "Create invitation",
                    Completion::General,
                    move |cancel| {
                        let principal = principal.parse().map_err(|_| {
                            "Enter a valid HyperNet principal identifier.".to_owned()
                        })?;
                        let operator = operator
                            .map(|v| {
                                v.parse().map_err(|_| {
                                    "Enter a complete operator account identifier.".to_owned()
                                })
                            })
                            .transpose()?;
                        if let Some(parent) = output.parent() {
                            ops::native::directory(parent).map_err(ops::failure)?;
                        }
                        ops::home::invite(&config, principal, operator, &output, cancel)
                    },
                );
            }
        });
        c::section(ui, "Activate endpoint", |ui| {
            path(
                ui,
                "Registration file",
                &mut self.service.registration,
                &mut self.picker,
                "service-registration",
                false,
            );
            if c::button(ui, "Activate account").clicked() {
                let config = self.service.config.clone();
                let registration = self.service.registration.clone();
                self.start(
                    &ctx,
                    "Activate account",
                    Completion::General,
                    move |cancel| ops::home::enrol(&config, &registration, cancel),
                );
            }
        });
    }
}

#[cfg(test)]
#[path = "../../../Tests/Unit/DesktopServicePolicy.rs"]
mod tests;
