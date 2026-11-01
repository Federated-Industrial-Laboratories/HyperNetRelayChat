// SPDX-License-Identifier: Apache-2.0
//! Shared interactive state tracks exact sends and waits for durable drafts before leaving.
use crate::commands::{self, Interaction};
use hrc::{
    client::{Command, Controller, Snapshot},
    presentation::editor::Editor,
    protocol::*,
};
use std::result::Result;
use std::{
    collections::BTreeMap,
    path::Path,
    sync::Arc,
    time::{Duration, Instant},
};

#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub enum Panel {
    #[default]
    Conversation,
    Help,
    Agents,
    Settings,
    Status,
    Motd,
}
pub struct Model {
    pub controller: Controller,
    pub snapshot: Arc<Snapshot>,
    pub editor: Editor,
    pub panel: Panel,
    pub reply: Option<Id>,
    pub error: Option<String>,
    pub closing: bool,
    pub notified: bool,
    room: Option<RoomId>,
    switching: Option<RoomId>,
    sends: BTreeMap<u64, (RoomId, String)>,
    changed: Instant,
    save_pending: Option<(u64, String)>,
    notification: u64,
}
impl Model {
    pub fn open(profile: &Path, offline: bool) -> Result<Self, &'static str> {
        let controller = Controller::open(profile).map_err(|e| e.code())?;
        let snapshot = controller.snapshot();
        let mut model = Self {
            controller,
            snapshot,
            editor: Editor::default(),
            panel: Panel::Conversation,
            reply: None,
            error: None,
            closing: false,
            notified: false,
            room: None,
            switching: None,
            sends: BTreeMap::new(),
            changed: Instant::now(),
            save_pending: None,
            notification: 0,
        };
        if !offline {
            model.dispatch(Command::Connect);
        }
        if let Some(room) = model
            .snapshot
            .rooms
            .iter()
            .find(|room| room.joined)
            .map(|r| r.room)
        {
            model.select(room);
        }
        Ok(model)
    }
    pub fn dispatch(&mut self, command: Command) -> Option<u64> {
        match self.controller.dispatch(command) {
            Ok(id) => Some(id),
            Err(error) => {
                self.error = Some(error.to_string());
                None
            }
        }
    }
    pub fn edited(&mut self) {
        self.changed = Instant::now();
        self.save_pending = None;
    }
    pub fn draft_saved(&self) -> bool {
        self.snapshot.selected.as_ref().is_none_or(|room| {
            room.summary.room == self.room.unwrap_or(room.summary.room)
                && room.draft == self.editor.text()
                && room.draft_mentions == self.editor.mentions()
        })
    }
    pub fn save(&mut self) {
        if self.draft_saved() {
            return;
        }
        if let Some(room) = self.room {
            let text = self.editor.text().to_owned();
            if self.save_pending.as_ref().map(|(_, text)| text.as_str()) != Some(&text)
                && let Some(id) = self.dispatch(Command::SaveDraft {
                    room,
                    text: text.clone(),
                    mentions: self.editor.mentions().to_vec(),
                })
            {
                self.save_pending = Some((id, text));
            }
        }
    }
    pub fn select(&mut self, room: RoomId) {
        self.switching = Some(room);
        self.save();
    }
    pub fn close(&mut self) {
        self.closing = true;
        self.controller.disconnect();
        self.save();
    }
    pub fn tick(&mut self) -> bool {
        self.snapshot = self.controller.snapshot();
        if let Some((id, _)) = &self.save_pending
            && let Some(completion) = self
                .snapshot
                .completions
                .iter()
                .find(|c| c.request_id == *id)
            && let Some(error) = &completion.error
        {
            self.error = Some(format!("Draft was not saved: {}", error.code));
            self.closing = false;
            self.switching = None;
        }
        for completion in &self.snapshot.completions {
            if completion.error.is_some()
                && !self
                    .snapshot
                    .deliveries
                    .iter()
                    .any(|d| d.request_id == Some(completion.request_id))
            {
                self.sends.remove(&completion.request_id);
            }
        }
        let current = self
            .snapshot
            .selected
            .as_ref()
            .map(|room| room.summary.room);
        if current != self.room {
            self.room = current;
            self.reply = None;
            self.save_pending = None;
            if let Some(room) = &self.snapshot.selected {
                if let Err(error) = self.editor.reset_draft(&room.draft, &room.draft_mentions) {
                    self.error = Some(error.to_string());
                }
            } else {
                let _ = self.editor.reset("");
            }
        }
        let delivered = self
            .snapshot
            .deliveries
            .iter()
            .filter_map(|delivery| {
                let request = delivery.request_id?;
                match delivery.outcome.as_ref()? {
                    Outcome::Committed { .. } => Some((request, true)),
                    Outcome::Rejected { .. } => Some((request, false)),
                    _ => None,
                }
            })
            .collect::<Vec<_>>();
        for (id, committed) in delivered {
            if let Some((room, text)) = self.sends.remove(&id)
                && committed
                && Some(room) == self.room
                && text == self.editor.text()
            {
                let _ = self.editor.reset("");
                self.reply = None;
                self.edited();
            }
        }
        if self.changed.elapsed() >= Duration::from_millis(300)
            || self.closing
            || self.switching.is_some()
        {
            self.save();
        }
        if self.draft_saved()
            && let Some(room) = self.switching.take()
        {
            self.dispatch(Command::SelectRoom(room));
        }
        let mut sound = false;
        self.notified = false;
        for notification in &self.snapshot.notifications {
            if notification.id > self.notification {
                self.notified = !self.snapshot.preferences.quiet;
                sound |= notification.sound;
                self.notification = self.notification.max(notification.id);
            }
        }
        sound && !self.snapshot.preferences.quiet
    }
    pub fn submit(&mut self) {
        if self.editor.text().is_empty() {
            return;
        }
        match commands::parse(
            self.editor.text(),
            self.editor.mentions(),
            &self.snapshot,
            self.reply,
        ) {
            Ok(Interaction::Request(command)) => {
                let send_room = match &*command {
                    Command::Send { room, .. } => Some(*room),
                    _ => None,
                };
                if send_room.is_some()
                    && self
                        .sends
                        .values()
                        .any(|(room, text)| Some(*room) == send_room && text == self.editor.text())
                {
                    self.error = Some(
                        "This exact draft already has a pending send; inspect its delivery state"
                            .into(),
                    );
                    return;
                }
                if let Some(id) = self.dispatch(*command) {
                    if let Some(room) = send_room {
                        self.sends.insert(id, (room, self.editor.text().into()));
                    } else {
                        let _ = self.editor.reset("");
                        self.edited();
                    }
                }
            }
            Ok(Interaction::Help) => self.panel = Panel::Help,
            Ok(Interaction::Agents) => {
                self.panel = Panel::Agents;
                self.dispatch(Command::Inspect);
            }
            Ok(Interaction::Settings) => self.panel = Panel::Settings,
            Ok(Interaction::Status) => {
                self.panel = Panel::Status;
                self.dispatch(Command::Inspect);
            }
            Ok(Interaction::Motd) => self.panel = Panel::Motd,
            Ok(Interaction::Quit) => self.close(),
            Err(error) => self.error = Some(error.into()),
        }
    }
}
