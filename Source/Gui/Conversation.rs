// SPDX-License-Identifier: Apache-2.0
//! Bounded history, search, replies and the shared Unicode composer.
use super::*;
use hrc::{client::ChatLayout, messaging, text};
use unicode_segmentation::UnicodeSegmentation;

impl App {
    pub(super) fn conversation(&mut self, ui: &mut egui::Ui) {
        let snapshot = self.model.snapshot.clone();
        let Some(room) = &snapshot.selected else {
            ui.vertical_centered(|ui| {
                ui.add_space((ui.available_height() * 0.3).max(20.0));
                ui.heading("Conversations");
                ui.add_space(12.0);
                components::accent_badge(ui, "No room selected");
            });
            return;
        };
        egui::Panel::bottom("composer")
            .frame(
                egui::Frame::new()
                    .fill(components::surface(ui))
                    .inner_margin(12),
            )
            .show(ui, |ui| self.composer(ui));
        egui::ScrollArea::vertical()
            .id_salt(("room-controls", room.summary.room))
            .max_height((ui.available_height() * 0.45).min(230.0))
            .show(ui, |ui| {
                ui.horizontal_wrapped(|ui| {
                    ui.heading(format!("# {}", text::identity_display(&room.summary.name)));
                    let (label, colour) = match room.summary.confidentiality {
                        RoomConfidentiality::Community => {
                            ("Community", ui.visuals().weak_text_color())
                        }
                        RoomConfidentiality::ConfidentialDirect => {
                            ("Confidential", components::accent(ui))
                        }
                        RoomConfidentiality::PrivateGroup => {
                            ("Private group", components::accent(ui))
                        }
                    };
                    components::badge(ui, label, colour)
                        .on_hover_text(display::confidentiality(room.summary.confidentiality));
                    ui.menu_button("Room", |ui| {
                        ui.menu_button(format!("Members ({})", room.members.len()), |ui| {
                            ui.set_min_width(210.0);
                            ui.push_id("member-menu", |ui| self.member_list(ui));
                        });
                        if ui.button("Mark read").clicked() {
                            self.model.dispatch(Command::MarkRead {
                                room: room.summary.room,
                                sequence: room
                                    .events
                                    .last()
                                    .map_or(room.read_sequence, |e| e.sequence),
                            });
                            ui.close();
                        }
                        if ui.button("Leave room").clicked() {
                            self.model.dispatch(Command::Leave(room.summary.room));
                            ui.close();
                        }
                        ui.separator();
                        ui.monospace(room.summary.room.to_string());
                    });
                });
                if !room.summary.topic.is_empty() {
                    ui.add(
                        egui::Label::new(&room.summary.topic)
                            .wrap()
                            .selectable(true),
                    );
                }
                if room.stale {
                    components::badge(
                        ui,
                        "Retained history · access unconfirmed",
                        theme::warning(ui),
                    );
                }
                if let Some(gap) = &room.gap {
                    ui.horizontal_wrapped(|ui| {
                        components::badge(ui, "History gap", theme::warning(ui)).on_hover_text(gap);
                        if components::button(ui, "Resynchronise").clicked() {
                            self.model.dispatch(Command::Resynchronise);
                        }
                    });
                }
                self.encryption(ui);
                self.search_controls(ui);
                if room.focus.is_some() && components::button(ui, "Back to live").clicked() {
                    self.model.select(room.summary.room);
                }
            });
        ui.separator();
        if let Some(search) = &snapshot.search {
            ui.horizontal_wrapped(|ui| {
                ui.strong(if search.running {
                    "Searching…"
                } else if search.cancelled {
                    "Search cancelled"
                } else {
                    "Search results"
                });
                if search.running && components::button(ui, "Cancel").clicked() {
                    self.model.dispatch(Command::CancelSearch);
                }
                if components::button(ui, "Close search").clicked() {
                    self.model.dispatch(Command::CloseSearch);
                }
                if search.has_more
                    && !search.running
                    && components::button(ui, "Next page").clicked()
                {
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
                        ui.add_space(20.0);
                        ui.weak("No matching retained messages");
                    }
                });
        } else {
            egui::ScrollArea::vertical()
                .id_salt(("history", room.summary.room))
                .stick_to_bottom(true)
                .show(ui, |ui| {
                    ui.set_width(ui.available_width());
                    if room.has_more && components::button(ui, "Earlier messages").clicked() {
                        self.model.dispatch(Command::LoadMore);
                    }
                    let mut day = None;
                    for event in &room.events {
                        let event_day = event.timestamp_ms / 86_400_000;
                        if day != Some(event_day) {
                            ui.add_space(10.0);
                            ui.horizontal(|ui| {
                                ui.weak(
                                    display::timestamp(event.timestamp_ms)
                                        .split('T')
                                        .next()
                                        .unwrap_or("Date unavailable"),
                                );
                                ui.separator();
                            });
                            ui.add_space(6.0);
                            day = Some(event_day);
                        }
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
        let message = matches!(
            event.kind,
            Operation::MessageSend | Operation::MessageReply | Operation::MessageAction
        );
        let compact = self.model.snapshot.preferences.density == Density::Compact;
        let response = ui.push_id(event.event, |ui| {
            if !message {
                ui.horizontal_wrapped(|ui| {
                    ui.weak(display::time(event.timestamp_ms));
                    ui.weak(format!("{} {}", display::actor(&event.actor, members), self.event_text(event)));
                });
                ui.add_space(if compact { 2.0 } else { 5.0 });
                return;
            }
            if self.model.snapshot.preferences.chat_layout == ChatLayout::Classic {
                ui.horizontal_top(|ui| {
                    ui.allocate_ui_with_layout(egui::vec2(65.0, 0.0), egui::Layout::top_down(egui::Align::Min), |ui| {
                        ui.add(egui::Label::new(egui::RichText::new(display::time(event.timestamp_ms)).monospace().weak()).truncate())
                            .on_hover_text(display::timestamp(event.timestamp_ms));
                    });
                    let author_width = (ui.available_width() * 0.27).clamp(85.0, 155.0);
                    ui.allocate_ui_with_layout(egui::vec2(author_width, 0.0), egui::Layout::top_down(egui::Align::Min), |ui| {
                        ui.add(egui::Label::new(egui::RichText::new(display::actor(&event.actor, members)).strong().color(components::accent(ui))).wrap());
                    });
                    ui.vertical(|ui| self.message_body(ui, event, search));
                });
                ui.add_space(if compact { 2.0 } else { 6.0 });
                ui.separator();
            } else {
                let own = matches!(&event.actor, Actor::Direct { acting } if acting.account == self.model.snapshot.account);
                let room_width = ui.available_width();
                let bubble_width = (room_width * 0.86).max(180.0).min(room_width);
                ui.horizontal_top(|ui| {
                    if own { ui.add_space((room_width - bubble_width - ui.spacing().item_spacing.x).max(0.0)); }
                    let fill = if own { ui.visuals().selection.bg_fill.gamma_multiply(0.65) } else { components::surface(ui) };
                    egui::Frame::new().fill(fill).stroke(ui.visuals().widgets.noninteractive.bg_stroke).inner_margin(if compact { 8 } else { 12 }).show(ui, |ui| {
                        ui.vertical(|ui| {
                        ui.set_width((bubble_width - 24.0).max(80.0));
                        ui.horizontal_wrapped(|ui| {
                            ui.label(egui::RichText::new(display::actor(&event.actor, members)).strong().color(components::accent(ui)));
                            ui.weak(display::time(event.timestamp_ms)).on_hover_text(display::timestamp(event.timestamp_ms));
                        });
                        self.message_body(ui, event, search);
                        });
                    });
                });
                ui.add_space(if compact { 4.0 } else { 9.0 });
            }
        }).response;
        if self.scroll_event == Some(event.event) {
            response.scroll_to_me(Some(egui::Align::Center));
            self.scroll_event = None;
        }
    }

    fn event_text(&self, event: &Event) -> String {
        display::event_text_with_content(
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
        )
    }

    fn reply_preview(&self, id: Id) -> String {
        self.model
            .snapshot
            .selected
            .as_ref()
            .and_then(|room| {
                room.events.iter().find(|e| e.event == id).map(|event| {
                    let text = self.event_text(event);
                    let snippet = text
                        .graphemes(true)
                        .take(96)
                        .collect::<String>()
                        .replace('\n', " ");
                    format!(
                        "{}: {}",
                        display::actor(&event.actor, &room.members),
                        snippet
                    )
                })
            })
            .unwrap_or_else(|| format!("Message {}", &id.as_hex()[..12]))
    }

    fn message_body(&mut self, ui: &mut egui::Ui, event: &Event, search: bool) {
        let parent = event
            .body
            .deserialized::<messaging::Send>()
            .ok()
            .and_then(|body| body.parent)
            .or_else(|| {
                event
                    .body
                    .deserialized::<hrc::crypto::EncryptedEvent>()
                    .ok()
                    .and_then(|body| body.context.parent)
            });
        if let Some(parent) = parent {
            let preview = format!("↳ {}", self.reply_preview(parent));
            if ui
                .add(
                    egui::Label::new(egui::RichText::new(preview).small().weak())
                        .wrap()
                        .sense(egui::Sense::click()),
                )
                .clicked()
            {
                self.model.open_event(event.room, parent);
                self.scroll_event = Some(parent);
            }
        }
        let text = self.event_text(event);
        self.page_text(ui, &text, event.kind == Operation::MessageAction)
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
                if ui.button("Copy message").clicked() {
                    ui.ctx().copy_text(text.clone());
                    ui.close();
                }
                ui.separator();
                ui.weak(format!(
                    "Sequence {} · UTC {}",
                    event.sequence,
                    display::timestamp(event.timestamp_ms)
                ));
            });
        if search && components::button(ui, "Open context").clicked() {
            self.model.open_event(event.room, event.event);
            self.scroll_event = Some(event.event);
            self.model.dispatch(Command::CloseSearch);
        }
    }

    fn search_controls(&mut self, ui: &mut egui::Ui) {
        let (input, search) = egui::Sides::new().shrink_left().show(
            ui,
            |ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut self.query)
                        .id(egui::Id::unique("search"))
                        .hint_text("Search this conversation")
                        .desired_width(ui.available_width())
                        .char_limit(256),
                )
            },
            |ui| components::button(ui, "Search"),
        );
        let enter = input.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter));
        if search.clicked() || enter {
            self.start_search();
        }
        ui.collapsing("Filters", |ui| {
            for (label, value) in [
                ("Acting sender", &mut self.find_sender),
                ("Represented", &mut self.find_represented),
                ("From (UTC)", &mut self.find_from),
                ("Before (UTC)", &mut self.find_until),
            ] {
                components::field(ui, label, |ui| {
                    ui.add(
                        egui::TextEdit::singleline(value)
                            .desired_width(ui.available_width())
                            .char_limit(300),
                    );
                });
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
            ui.horizontal_wrapped(|ui| {
                ui.label(
                    egui::RichText::new(format!("↳ {}", self.reply_preview(reply)))
                        .color(components::accent(ui)),
                );
                if components::button(ui, "Cancel reply").clicked() {
                    self.model.reply = None;
                }
            });
        }
        let before = self.model.editor.text().to_owned();
        let mentions_before = self.model.editor.mentions().to_vec();
        let enabled = self.model.composer_enabled();
        if !enabled {
            components::muted_badge(ui, "Composer paused");
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
            ui.horizontal(|ui| {
                if components::primary(ui, "Send")
                    .on_hover_text("Ctrl+Enter · Enter inserts a line break")
                    .clicked()
                    || send
                {
                    self.model.submit();
                }
                ui.weak("Ctrl+Enter");
                if !self.model.editor.mentions().is_empty() {
                    components::accent_badge(
                        ui,
                        &format!("{} mentions", self.model.editor.mentions().len()),
                    );
                }
                if !self.model.draft_saved() {
                    ui.weak("Saving…");
                }
            });
        });
        if let Some(delivery) = self
            .model
            .snapshot
            .deliveries
            .iter()
            .rev()
            .find(|d| d.room == room)
        {
            let state = display::delivery(delivery);
            ui.add(egui::Label::new(egui::RichText::new(state).small().weak()).wrap())
                .on_hover_text(format!(
                    "Operation {}",
                    display::operation(delivery.operation_id)
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
                    if ui.button(label).clicked() {
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
