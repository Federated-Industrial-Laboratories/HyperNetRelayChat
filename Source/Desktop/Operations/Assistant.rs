// SPDX-License-Identifier: Apache-2.0
//! Provider-neutral assistant export with a reviewable file plan.
use super::*;
pub(super) struct Form {
    provider: assistant::Provider,
    scope: assistant::Scope,
    destination: PathBuf,
    pub preview: Option<Value>,
    remove: bool,
}
impl Default for Form {
    fn default() -> Self {
        Self {
            provider: assistant::Provider::Codex,
            scope: assistant::Scope::Workspace,
            destination: ops::root().join("AssistantWorkspace"),
            preview: None,
            remove: false,
        }
    }
}
impl Workspace {
    pub(super) fn assistant_ui(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        ui.heading("External assistant");
        c::section(ui, "Connect your assistant", |ui| {
            ui.horizontal_wrapped(|ui| {
                for provider in assistant::Provider::ALL {
                    if c::choice(ui, self.assistant.provider == provider, provider.label())
                        .clicked()
                    {
                        self.assistant.provider = provider;
                        self.assistant.preview = None;
                    }
                }
            });
            let previous = (
                self.assistant.scope,
                self.assistant.destination.clone(),
                self.assistant.remove,
            );
            ui.horizontal(|ui| {
                ui.selectable_value(
                    &mut self.assistant.scope,
                    assistant::Scope::Workspace,
                    "One workspace",
                );
                ui.selectable_value(
                    &mut self.assistant.scope,
                    assistant::Scope::User,
                    "User scope",
                );
            });
            if previous.0 != self.assistant.scope && self.assistant.scope == assistant::Scope::User
            {
                self.assistant.destination = std::env::var_os("HOME")
                    .map(PathBuf::from)
                    .unwrap_or_default();
            }
            path(
                ui,
                "Destination",
                &mut self.assistant.destination,
                &mut self.picker,
                "assistant-destination",
                true,
            );
            ui.checkbox(&mut self.assistant.remove, "Remove this harness");
            if previous
                != (
                    self.assistant.scope,
                    self.assistant.destination.clone(),
                    self.assistant.remove,
                )
            {
                self.assistant.preview = None;
            }
            c::muted_badge(
                ui,
                "External LLM · no embedded provider · no automatic permissions",
            );
            ui.horizontal_wrapped(|ui| {
                for label in [
                    "Setup",
                    "Operations",
                    "Models",
                    "Optional security",
                    "Recovery",
                ] {
                    c::accent_badge(ui, label);
                }
            });
            if c::primary(ui, "Review files").clicked() {
                let (provider, scope, destination, remove) = (
                    self.assistant.provider,
                    self.assistant.scope,
                    self.assistant.destination.clone(),
                    self.assistant.remove,
                );
                self.start(
                    &ctx,
                    "Review assistant files",
                    Completion::AssistantPreview,
                    move |_| {
                        if remove {
                            assistant::uninstall_scoped(provider, scope, &destination, false)
                        } else {
                            assistant::install_scoped(provider, scope, &destination, false)
                        }
                        .map_err(str::to_owned)
                    },
                );
            }
        });
        if let Some(preview) = self.assistant.preview.clone() {
            c::section(ui, "File plan", |ui| {
                if let Some(files) = preview["files"].as_array() {
                    for file in files {
                        ui.horizontal_wrapped(|ui| {
                            ui.weak(file["action"].as_str().unwrap_or(""));
                            ui.monospace(file["path"].as_str().unwrap_or(""));
                        });
                    }
                }
                if ui
                    .add_enabled(
                        preview["can_apply"].as_bool().unwrap_or(false),
                        egui::Button::new(if self.assistant.remove {
                            "Remove owned files"
                        } else {
                            "Install harness"
                        })
                        .min_size(egui::vec2(c::ACTION_WIDTH, c::CONTROL_HEIGHT)),
                    )
                    .clicked()
                {
                    let (provider, scope, destination, remove) = (
                        self.assistant.provider,
                        self.assistant.scope,
                        self.assistant.destination.clone(),
                        self.assistant.remove,
                    );
                    self.start(
                        &ctx,
                        "Apply assistant files",
                        Completion::General,
                        move |_| {
                            if remove {
                                assistant::uninstall_scoped(provider, scope, &destination, true)
                            } else {
                                assistant::install_scoped(provider, scope, &destination, true)
                            }
                            .map_err(str::to_owned)
                        },
                    );
                }
                ui.small("Open this workspace in the selected assistant. Its own approvals and sandbox still control actions. Security changes are separate, optional operations.");
            });
        }
    }
}
