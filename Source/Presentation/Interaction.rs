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
struct Draft {
    generation: u64,
    text: String,
    mentions: Vec<hrc::messaging::Mention>,
}
impl Draft {
    fn matches(&self, model: &Model) -> bool {
        self.generation == model.generation
            && self.text == model.editor.text()
            && self.mentions == model.editor.mentions()
    }
}
pub struct Model {
    pub online_requested: bool,
    pub controller: Controller,
    pub snapshot: Arc<Snapshot>,
    pub editor: Editor,
    pub panel: Panel,
    pub reply: Option<Id>,
    pub error: Option<String>,
    pub closing: bool,
    pub notified: bool,
    room: Option<RoomId>,
    switching: Option<Command>,
    selection_pending: Option<u64>,
    sends: BTreeMap<u64, (RoomId, Draft)>,
    changed: Instant,
    generation: u64,
    saved_generation: u64,
    save_pending: Option<(u64, Draft)>,
    notification: u64,
}
impl Model {
    pub fn open(profile: &Path, offline: bool) -> Result<Self, &'static str> {
        let controller = Controller::open(profile).map_err(|e| e.code())?;
        let snapshot = controller.snapshot();
        let mut model = Self {
            online_requested: !offline,
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
            selection_pending: None,
            sends: BTreeMap::new(),
            changed: Instant::now(),
            generation: 0,
            saved_generation: 0,
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
        if matches!(&command, Command::Connect) {
            self.online_requested = true;
        }
        if matches!(&command, Command::Disconnect) {
            self.online_requested = false;
        }
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
        self.generation += 1;
    }
    fn draft(&self) -> Draft {
        Draft {
            generation: self.generation,
            text: self.editor.text().into(),
            mentions: self.editor.mentions().to_vec(),
        }
    }
    pub fn composer_enabled(&self) -> bool {
        self.selection_pending.is_none() && !self.closing
    }
    pub fn edit(
        &mut self,
        edit: impl FnOnce(&mut Editor) -> Result<(), hrc::presentation::editor::InvalidDraft>,
    ) {
        if !self.composer_enabled() {
            return;
        }
        match edit(&mut self.editor) {
            Ok(()) => self.edited(),
            Err(error) => self.error = Some(error.to_string()),
        }
    }
    pub fn draft_saved(&self) -> bool {
        self.room.is_none()
            || self.snapshot.selected.as_ref().is_some_and(|room| {
                Some(room.summary.room) == self.room
                    && self.saved_generation == self.generation
                    && room.draft == self.editor.text()
                    && room.draft_mentions == self.editor.mentions()
            })
    }
    pub fn save(&mut self) {
        if self.draft_saved() {
            return;
        }
        if let Some(room) = self.room {
            let draft = self.draft();
            if !self
                .save_pending
                .as_ref()
                .is_some_and(|(_, pending)| pending.matches(self))
                && let Some(id) = self.dispatch(Command::SaveDraft {
                    room,
                    text: draft.text.clone(),
                    mentions: draft.mentions.clone(),
                })
            {
                self.save_pending = Some((id, draft));
            }
        }
    }
    pub fn select(&mut self, room: RoomId) {
        if !self.composer_enabled() || self.room == Some(room) {
            return;
        }
        self.navigate(Command::SelectRoom(room));
    }
    pub fn open_event(&mut self, room: RoomId, event: Id) {
        self.navigate(Command::OpenEvent { room, event });
    }
    fn navigate(&mut self, command: Command) {
        if !self.composer_enabled() {
            return;
        }
        self.switching = Some(command);
        self.save();
    }
    pub fn close(&mut self) {
        self.closing = true;
        self.controller.disconnect();
        self.save();
    }
    pub fn tick(&mut self) -> bool {
        self.snapshot = self.controller.snapshot();
        self.update()
    }
    fn update(&mut self) -> bool {
        if let Some((id, _)) = &self.save_pending
            && let Some(completion) = self
                .snapshot
                .completions
                .iter()
                .find(|c| c.request_id == *id)
        {
            if let Some(error) = &completion.error {
                self.error = Some(format!("Draft was not saved: {}", error.code));
                self.closing = false;
                self.switching = None;
                self.changed = Instant::now();
            } else if let Some((_, draft)) = &self.save_pending {
                self.saved_generation = draft.generation;
            }
            self.save_pending = None;
        }
        if let Some(id) = self.selection_pending
            && let Some(completion) = self
                .snapshot
                .completions
                .iter()
                .find(|c| c.request_id == id)
        {
            self.selection_pending = None;
            if let Some(error) = &completion.error {
                self.error = Some(format!("Room selection failed: {}", error.code));
            }
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
            self.generation += 1;
            self.saved_generation = self.generation;
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
            if let Some((room, draft)) = self.sends.remove(&id)
                && committed
                && Some(room) == self.room
                && draft.matches(self)
            {
                let _ = self.editor.reset("");
                self.reply = None;
                self.edited();
                self.save();
            }
        }
        if self.changed.elapsed() >= Duration::from_millis(300)
            || self.closing
            || self.switching.is_some()
        {
            self.save();
        }
        if self.draft_saved()
            && let Some(command) = self.switching.take()
        {
            self.selection_pending = self.dispatch(command);
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
        if !self.composer_enabled() || self.editor.text().is_empty() {
            return;
        }
        match commands::parse(
            self.editor.text(),
            self.editor.mentions(),
            &self.snapshot,
            self.reply,
        ) {
            Ok(Interaction::Request(command)) => {
                if matches!(*command, Command::SelectRoom(_) | Command::OpenEvent { .. }) {
                    let _ = self.editor.reset("");
                    self.edited();
                    self.navigate(*command);
                    return;
                }
                let send_room = match &*command {
                    Command::Send { room, .. } => Some(*room),
                    _ => None,
                };
                if send_room.is_some()
                    && self
                        .sends
                        .values()
                        .any(|(room, draft)| Some(*room) == send_room && draft.matches(self))
                {
                    self.error = Some(
                        "This exact draft already has a pending send; inspect its delivery state"
                            .into(),
                    );
                    return;
                }
                if let Some(id) = self.dispatch(*command) {
                    if let Some(room) = send_room {
                        self.sends.insert(id, (room, self.draft()));
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

#[cfg(test)]
#[path = "../../Tests/Presentation/Interaction.rs"]
mod tests;
