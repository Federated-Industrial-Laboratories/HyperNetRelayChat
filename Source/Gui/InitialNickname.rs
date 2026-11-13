// SPDX-License-Identifier: Apache-2.0
//! The joined name is applied once by the existing controller after authenticated readiness.
use super::*;
#[derive(Default)]
pub(super) struct InitialNickname {
    name: Option<String>,
    command: Option<u64>,
    attempted: bool,
    notice: Option<String>,
}
impl App {
    pub(super) fn initial_nickname(&mut self, name: Option<String>) {
        self.initial_nickname = InitialNickname {
            name,
            ..Default::default()
        };
        if self
            .initial_nickname
            .name
            .as_deref()
            .is_some_and(|s| hrc::text::handle(s).is_err())
        {
            self.initial_nickname.attempted = true;
            self.initial_nickname.notice=Some("The join name is invalid: use 1 to 32 characters, at most 64 UTF-8 bytes, without controls. Choose a nickname in Settings.".into());
            self.model.error = self.initial_nickname.notice.clone();
        }
    }
    pub(super) fn initial_nickname_logic(&mut self) {
        let state = &mut self.initial_nickname;
        if let Some(id) = state.command
            && let Some(done) = self
                .model
                .snapshot
                .completions
                .iter()
                .find(|r| r.request_id == id)
        {
            state.command = None;
            if let Some(error) = &done.error {
                state.notice = Some(format!(
                    "The initial nickname could not be confirmed ({}). Retry or choose a nickname in Settings.",
                    error.code
                ));
                self.model.error = state.notice.clone();
            } else {
                state.name = None;
                state.notice = None;
            }
        }
        if !state.attempted
            && state.name.is_some()
            && matches!(
                self.model.snapshot.connection,
                hrc::client::ConnectionState::Online
            )
        {
            state.attempted = true;
            state.command = self.model.dispatch(Command::InitializeNickname(
                state.name.clone().expect("checked name"),
            ));
            if state.command.is_none() {
                state.notice=Some("Initial nickname setup is waiting. Retry from Settings when the connection is ready.".into());
            }
        }
    }
    pub(super) fn initial_nickname_notice(&mut self, ui: &mut egui::Ui) {
        let state = &mut self.initial_nickname;
        if let Some(notice) = &state.notice {
            ui.label(notice);
            ui.horizontal(|ui| {
                if ui
                    .add_enabled(
                        state.command.is_none()
                            && state
                                .name
                                .as_deref()
                                .is_some_and(|s| hrc::text::handle(s).is_ok()),
                        egui::Button::new("Retry initial nickname"),
                    )
                    .clicked()
                {
                    state.attempted = false;
                    state.notice = None;
                }
                if ui.button("Dismiss name notice").clicked() {
                    state.notice = None;
                }
            });
        }
    }
}
