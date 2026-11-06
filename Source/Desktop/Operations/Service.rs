// SPDX-License-Identifier: Apache-2.0
//! Local service operation and explicit account admission controls.
use super::*;
pub(super) struct Form {
    pub config: ops::home::Configuration,
    file: PathBuf,
    principal: String,
    agent: bool,
    operator: String,
    invitation: PathBuf,
    pub(super) registration: PathBuf,
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
        }
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
                    match ops::home::Configuration::load(&self.service.file) {
                        Ok(config) => self.service.config = config,
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
