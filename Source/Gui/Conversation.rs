// SPDX-License-Identifier: Apache-2.0
//! Bounded history, search, replies and the shared Unicode composer.
use super::*;
use hrc::{messaging, text};
impl App {
    pub(super) fn conversation(&mut self, ui: &mut egui::Ui) {
        let snapshot = self.model.snapshot.clone();
        let Some(room) = &snapshot.selected else {
            ui.heading("Welcome to HyperNet Relay Chat");
            ui.label("Select a joined room or create one. Your drafts are retained when the connection is unavailable.");
            return;
        };
        egui::Panel::bottom("composer").show(ui, |ui| self.composer(ui));
        let controls_height = (ui.available_height() * 0.55).clamp(0.0, 320.0);
        egui::ScrollArea::vertical()
            .id_salt(("room-controls", room.summary.room))
            .max_height(controls_height)
            .show(ui, |ui| {
                ui.heading(format!("# {}", text::identity_display(&room.summary.name)));
                ui.label(&room.summary.topic);
                ui.horizontal_wrapped(|ui| {
                    ui.label(display::confidentiality(room.summary.confidentiality));
                    if room.stale {
                        ui.label("Retained copy; current access is not confirmed");
                    }
                    if ui.button("Leave").clicked() {
                        self.model.dispatch(Command::Leave(room.summary.room));
                    }
                    if ui.button("Mark read").clicked() {
                        self.model.dispatch(Command::MarkRead {
                            room: room.summary.room,
                            sequence: room
                                .events
                                .last()
                                .map_or(room.read_sequence, |e| e.sequence),
                        });
                    }
                });
                if let Some(gap) = &room.gap {
                    ui.horizontal_wrapped(|ui| {
                        ui.colored_label(egui::Color32::YELLOW, format!("History gap: {gap}"));
                        if ui.button("Resynchronise").clicked() {
                            self.model.dispatch(Command::Resynchronise);
                        }
                    });
                }
                self.encryption(ui);
                self.search_controls(ui);
                if room.focus.is_some() && ui.button("Return to live conversation").clicked() {
                    self.model.select(room.summary.room);
                }
            });
        if let Some(search) = &snapshot.search {
            ui.horizontal(|ui| {
                ui.strong(if search.running {
                    "Searching…"
                } else if search.cancelled {
                    "Search cancelled"
                } else {
                    "Search results"
                });
                if search.running && ui.button("Cancel search").clicked() {
                    self.model.dispatch(Command::CancelSearch);
                }
                if ui.button("Close search").clicked() {
                    self.model.dispatch(Command::CloseSearch);
                }
                if search.has_more && !search.running && ui.button("Next page").clicked() {
                    self.model.dispatch(Command::NextSearchPage);
                }
            });
            egui::ScrollArea::vertical()
                .id_salt("search-results")
                .show(ui, |ui| {
                    for event in &search.events {
                        self.event(ui, event, &room.members, true);
                    }
                    if search.events.is_empty() && !search.running {
                        ui.label("No matching retained messages");
                    }
                });
        } else {
            egui::ScrollArea::vertical()
                .id_salt(("history", room.summary.room))
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    if room.has_more && ui.button("Load more retained history").clicked() {
                        self.model.dispatch(Command::LoadMore);
                    }
                    for event in &room.events {
                        self.event(ui, event, &room.members, false);
                    }
                });
        }
    }
    fn event(
        &mut self,
        ui: &mut egui::Ui,
        event: &Event,
        members: &[hrc::conversations::Member],
        search: bool,
    ) {
        let response = ui
            .push_id(event.event, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.weak(display::time(event.timestamp_ms));
                    ui.strong(display::actor(&event.actor, members));
                    if event.kind == Operation::MessageAction {
                        ui.weak("action");
                    }
                    if search && ui.small_button("Open context").clicked() {
                        self.model.open_event(event.room, event.event);
                        self.scroll_event = Some(event.event);
                        self.model.dispatch(Command::CloseSearch);
                    }
                });
                ui.add(
                    egui::Label::new(display::event_text_with_content(
                        event,
                        self.model
                            .snapshot
                            .search
                            .as_ref()
                            .and_then(|s| s.content.get(&event.event))
                            .or_else(|| {
                                self.model
                                    .snapshot
                                    .selected
                                    .as_ref()
                                    .and_then(|r| r.content.get(&event.event))
                            }),
                    ))
                    .wrap()
                    .selectable(true),
                )
                .context_menu(|ui| {
                    if ui.button("Reply").clicked() {
                        self.model.reply = Some(event.event);
                        self.focus_composer = true;
                        ui.close();
                    }
                    if ui.button("Copy message ID").clicked() {
                        ui.ctx().copy_text(event.event.to_string());
                        ui.close();
                    }
                    ui.label(format!(
                        "Sequence {} · UTC {}",
                        event.sequence,
                        display::timestamp(event.timestamp_ms)
                    ));
                    ui.label(event.event.to_string());
                });
                if let Ok(body) = event.body.deserialized::<messaging::Send>()
                    && let Some(parent) = body.parent
                {
                    ui.weak(format!("Reply to {}", &parent.as_hex()[..12]));
                }
                ui.add_space(
                    if self.model.snapshot.preferences.density == Density::Compact {
                        3.0
                    } else {
                        9.0
                    },
                );
            })
            .response;
        if self.scroll_event == Some(event.event) {
            response.scroll_to_me(Some(egui::Align::Center));
            self.scroll_event = None;
        }
    }
    fn search_controls(&mut self, ui: &mut egui::Ui) {
        ui.horizontal(|ui| {
            let width = (ui.available_width() - 66.0).max(40.0);
            let input = ui.add(
                egui::TextEdit::singleline(&mut self.query)
                    .id(egui::Id::unique("search"))
                    .hint_text("Search this room")
                    .desired_width(width)
                    .char_limit(256),
            );
            let enter = input.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
            if ui.button("Search").clicked() || enter {
                self.start_search();
            }
        });
        ui.collapsing("Search filters", |ui| {
            for (label, value) in [
                ("Acting sender name or ID", &mut self.find_sender),
                ("Represented name or ID", &mut self.find_represented),
                ("From date (UTC or ISO 8601)", &mut self.find_from),
                ("Before date (UTC or ISO 8601)", &mut self.find_until),
            ] {
                ui.label(label);
                ui.add(
                    egui::TextEdit::singleline(value)
                        .desired_width(ui.available_width())
                        .char_limit(300),
                );
            }
        });
    }
    fn start_search(&mut self) {
        let result = (|| {
            let account = |value: &str| {
                if value.trim().is_empty() {
                    Ok(None)
                } else {
                    crate::commands::account(&self.model.snapshot, value.trim()).map(Some)
                }
            };
            Ok::<_, &'static str>(messaging::Search {
                terms: if self.query.is_empty() {
                    vec![]
                } else {
                    vec![self.query.clone()]
                },
                sender: account(&self.find_sender)?,
                represented: account(&self.find_represented)?,
                from_ms: display::date_bound(&self.find_from)?,
                until_ms: display::date_bound(&self.find_until)?,
                cursor: None,
                limit: 32,
            })
        })();
        match result {
            Ok(query) => {
                self.model.dispatch(Command::Search(query));
            }
            Err(error) => self.model.error = Some(error.into()),
        }
    }
    fn composer(&mut self, ui: &mut egui::Ui) {
        let room = self
            .model
            .snapshot
            .selected
            .as_ref()
            .map(|r| r.summary.room);
        let id = egui::Id::unique(("composer", room));
        if self.composer_room != room {
            self.composer_room = room;
            egui::text_edit::TextEditState::default().store(ui.ctx(), id);
        }
        if let Some(reply) = self.model.reply {
            ui.horizontal(|ui| {
                ui.label(format!("Reply to {}", &reply.as_hex()[..12]));
                if ui.small_button("Cancel reply").clicked() {
                    self.model.reply = None;
                }
            });
        }
        let before = self.model.editor.text().to_owned();
        let mentions_before = self.model.editor.mentions().to_vec();
        let enabled = self.model.composer_enabled();
        if !enabled {
            ui.weak("Composer paused while the room changes or the client closes");
        }
        let output = ui
            .add_enabled_ui(enabled, |ui| editor::show(ui, id, &mut self.model.editor))
            .inner;
        if self.focus_composer {
            output.response.request_focus();
            self.focus_composer = false;
        }
        if output.rejected {
            self.model.error = Some(
                "Draft limit: 8192 bytes and 2000 graphemes; terminal controls are not accepted"
                    .into(),
            );
        }
        if before != self.model.editor.text() || mentions_before != self.model.editor.mentions() {
            self.model.edited();
        }
        let send = ui.input_mut(|input| input.consume_key(egui::Modifiers::CTRL, egui::Key::Enter));
        ui.add_enabled_ui(enabled, |ui| {
            self.completion(ui);
            ui.horizontal_wrapped(|ui| {
                if ui.button("Send · Ctrl+Enter").clicked() || send {
                    self.model.submit();
                }
                ui.weak("Enter inserts a line break · /help lists commands");
                if !self.model.editor.mentions().is_empty() {
                    ui.weak(format!(
                        "{} bound mentions",
                        self.model.editor.mentions().len()
                    ));
                }
            });
        });
        for delivery in self
            .model
            .snapshot
            .deliveries
            .iter()
            .rev()
            .filter(|d| d.room == room)
            .take(3)
        {
            ui.weak(format!(
                "{}: {}",
                &crate::display::operation(delivery.operation_id)[..12],
                crate::display::delivery(delivery)
            ));
        }
    }
    fn completion(&mut self, ui: &mut egui::Ui) {
        let range = self.model.editor.completion_range();
        let (start, cursor) = (range.start, range.end);
        let prefix = &self.model.editor.text()[start..cursor];
        if let Some(prefix) = prefix.strip_prefix('@') {
            let key = text::lookup(prefix, 1024).unwrap_or_default();
            let matches = self
                .model
                .snapshot
                .selected
                .as_ref()
                .map(|room| {
                    room.members
                        .iter()
                        .filter(|m| {
                            text::lookup(&m.nickname, 1024).is_ok_and(|s| s.starts_with(&key))
                        })
                        .take(8)
                        .cloned()
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            ui.horizontal_wrapped(|ui| {
                for member in matches {
                    let label = format!(
                        "{} ({})",
                        text::identity_display(&member.nickname),
                        display::short_account(member.account)
                    );
                    if ui.small_button(label).clicked() {
                        if let Err(error) = self.model.editor.complete_mention(
                            start..cursor,
                            member.account,
                            &member.nickname,
                        ) {
                            self.model.error = Some(error.to_string());
                        } else {
                            self.model.edited();
                            self.focus_composer = true;
                        }
                    }
                }
            });
        } else if prefix.starts_with('/') && start == 0 {
            ui.horizontal_wrapped(|ui| {
                for (command, description) in crate::commands::HELP
                    .iter()
                    .filter(|(name, _)| name.starts_with(prefix))
                    .take(6)
                {
                    ui.weak(*command).on_hover_text(*description);
                }
            });
        }
    }
}
