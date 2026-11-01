// SPDX-License-Identifier: Apache-2.0
//! Current filtered pulls, bounded cached views and notification admission.
use super::*;
impl Worker {
    pub(super) fn refresh(&mut self) -> Result<()> {
        self.snapshot.inspection.stale = true;
        if let Some(room) = &mut self.snapshot.selected {
            room.stale = true;
        }
        cache::maintain(&mut self.client.store).map_err(|_| Error::Storage)?;
        let mut rooms = Vec::new();
        let mut after = None;
        for _ in 0..32 {
            let page: Vec<conversations::Summary> = self.read(
                Operation::RoomList,
                Target::Service,
                &conversations::List { after, limit: 16 },
            )?;
            if page.is_empty() {
                break;
            }
            let complete = page.len() < 16;
            let last = page.last().map(|r| r.room);
            if last == after {
                return Err(Error::Input);
            }
            rooms.extend(page);
            if rooms.len() > 256 {
                return Err(Error::Input);
            }
            after = last;
            if complete {
                break;
            }
        }
        cache::save_rooms(&mut self.client.store, self.snapshot.home, &rooms)
            .map_err(|_| Error::Storage)?;
        self.snapshot.rooms = rooms;
        let account: identity::AccountView = self.read(
            Operation::AccountInspect,
            Target::Account(self.snapshot.account),
            &home::Empty {},
        )?;
        self.snapshot.nickname = account.nickname;
        let info: home::ServiceInformation =
            self.read(Operation::ServiceInspect, Target::Service, &home::Empty {})?;
        self.snapshot.motd = info.motd;
        self.inspect()?;
        if let Some(room) = self.snapshot.selected.as_ref().map(|r| r.summary.room) {
            if self
                .snapshot
                .rooms
                .iter()
                .any(|r| r.room == room && r.joined)
            {
                if let Some(event) = self.snapshot.selected.as_ref().and_then(|v| v.focus) {
                    self.open_event(room, event)?;
                }
                self.pull(room)?;
            } else {
                self.snapshot.selected = None;
                self.snapshot.search = None;
            }
        }
        let selected = self.snapshot.selected.as_ref().map(|r| r.summary.room);
        let background: Vec<_> = self
            .snapshot
            .rooms
            .iter()
            .filter(|r| r.joined && Some(r.room) != selected)
            .map(|r| r.room)
            .collect();
        if !background.is_empty() {
            let room = background[self.poll_room % background.len()];
            self.poll_room = self.poll_room.wrapping_add(1);
            self.pull(room)?;
        }
        self.snapshot.privacy = Some(self.client.session()?.refresh_privacy()?);
        // A slow or explicit refresh must not immediately schedule another full poll.
        self.poll = std::time::Instant::now();
        Ok(())
    }
    pub(super) fn pages<T: serde::de::DeserializeOwned>(
        &mut self,
        operation: Operation,
        target: Target,
    ) -> Result<Vec<T>> {
        let mut result = Vec::new();
        let mut after = None;
        for _ in 0..32 {
            let page: home::InspectionPage<T> = self.read(
                operation,
                target.clone(),
                &home::InspectPage {
                    after: after.clone(),
                    limit: 16,
                },
            )?;
            result.extend(page.items);
            if result.len() > 512 {
                return Err(Error::Input);
            }
            if page.next.is_none() {
                return Ok(result);
            }
            if page.next == after {
                return Err(Error::Input);
            }
            after = page.next;
        }
        Err(Error::Input)
    }
    pub(super) fn inspect(&mut self) -> Result<()> {
        self.snapshot.inspection.stale = true;
        let target = Target::Account(self.snapshot.account);
        self.snapshot.inspection.filters =
            self.pages(Operation::ModerationFilters, target.clone())?;
        cache::save_filters(
            &mut self.client.store,
            self.snapshot.home,
            &self.snapshot.inspection.filters,
        )
        .map_err(|_| Error::Storage)?;
        self.snapshot.inspection.grants = self.pages(Operation::DelegationList, target.clone())?;
        self.snapshot.inspection.agents = self.pages(Operation::AgentList, target)?;
        self.snapshot.inspection.stale = false;
        Ok(())
    }
    pub(super) fn select(&mut self, room: RoomId) -> Result<()> {
        let summary = self
            .snapshot
            .rooms
            .iter()
            .find(|r| r.room == room)
            .cloned()
            .ok_or(Error::Input)?;
        let cached = cache::room(&mut self.client.store, room).map_err(|_| Error::Storage)?;
        let content = super::super::archive::content(&mut self.client.store, &cached.events)
            .map_err(|_| Error::Storage)?;
        let crypto = super::super::archive::view(&mut self.client.store, room)
            .map_err(|_| Error::Storage)?;
        self.snapshot.selected = Some(RoomView {
            crypto,
            content,
            focus: None,
            summary,
            members: cached.members,
            events: cached.events,
            draft: self.client.draft(room)?.unwrap_or_default(),
            draft_mentions: self.client.draft_mentions(room)?,
            stale: true,
            gap: cached.gap,
            has_more: false,
            read_sequence: 0,
            preferences: cache::room_preferences(&mut self.client.store, room)
                .map_err(|_| Error::Storage)?,
        });
        self.snapshot.search = None;
        if self.client.session().is_ok() {
            self.pull(room)?;
        }
        Ok(())
    }
    pub(super) fn selected(&self) -> Result<RoomId> {
        self.snapshot
            .selected
            .as_ref()
            .map(|r| r.summary.room)
            .ok_or(Error::Input)
    }
    pub(super) fn pull(&mut self, room: RoomId) -> Result<()> {
        if self
            .snapshot
            .selected
            .as_ref()
            .is_some_and(|v| v.summary.room == room && v.gap.is_some())
        {
            return Ok(());
        }
        if let Some(view) = &mut self.snapshot.selected
            && view.summary.room == room
        {
            view.stale = true;
        }
        let cached = cache::room(&mut self.client.store, room).map_err(|_| Error::Storage)?;
        if cached.gap.is_some() {
            return Ok(());
        }
        let current: conversations::Inspection =
            match self.read(Operation::RoomInspect, Target::Room(room), &home::Empty {}) {
                Ok(view) => view,
                Err(error) => {
                    if cache::inspection_failed(&mut self.client.store, room, &error)
                        .map_err(|_| Error::Storage)?
                    {
                        self.caught_up.remove(&room);
                        if let Some(view) = &mut self.snapshot.selected
                            && view.summary.room == room
                        {
                            view.events.clear();
                            view.content.clear();
                            view.members.clear();
                            view.gap = Some("CurrentRoomAccessUnavailable".into());
                        }
                    }
                    return Err(error);
                }
            };
        if current.confidentiality != RoomConfidentiality::Community {
            let result = self.pull_encrypted(
                room,
                current,
                cached.events.last().map(|e| e.sequence).unwrap_or(0),
            );
            if result.is_err()
                && cache::room(&mut self.client.store, room)
                    .map_err(|_| Error::Storage)?
                    .gap
                    .is_some()
            {
                self.caught_up.remove(&room);
                if let Some(view) = &mut self.snapshot.selected
                    && view.summary.room == room
                {
                    view.events.clear();
                    view.content.clear();
                    view.members.clear();
                    view.gap = Some("CurrentRoomAccessUnavailable".into());
                }
            }
            return result;
        }
        let page = self.read::<messaging::PageResult, _>(
            Operation::EventsResume,
            Target::Room(room),
            &messaging::Page {
                cursor: cached.cursor,
                limit: 32,
            },
        );
        let page = match page {
            Ok(page) => page,
            Err(Error::Rejected {
                code: ErrorCode::ResynchronisationRequired,
                detail,
            })
            | Err(Error::Refused {
                code: ErrorCode::ResynchronisationRequired,
                detail,
                ..
            }) => {
                cache::invalidate(&mut self.client.store, room).map_err(|_| Error::Storage)?;
                self.caught_up.remove(&room);
                if let Some(view) = &mut self.snapshot.selected
                    && view.summary.room == room
                {
                    view.events.clear();
                    view.members = current.members;
                    view.stale = true;
                    view.gap = Some(detail);
                    view.has_more = false;
                }
                return Ok(());
            }
            Err(e) => return Err(e),
        };
        let key =
            VerifyingKey::from_bytes(self.client.profile.active_server().signing_key.as_bytes())
                .map_err(|_| Error::Configuration)?;
        let now = self
            .client
            .profile
            .clock
            .sample()
            .map_err(|_| Error::Clock)?
            .upper_ms;
        cache::receive(
            &mut self.client.store,
            room,
            self.snapshot.account,
            &page,
            &key,
            now,
        )
        .map_err(|_| Error::Storage)?;
        if self.caught_up.contains(&room) {
            self.notify(room, &page.events)?;
        }
        if !page.has_more {
            self.caught_up.insert(room);
        }
        let cached = cache::room(&mut self.client.store, room).map_err(|_| Error::Storage)?;
        if self
            .snapshot
            .selected
            .as_ref()
            .is_some_and(|v| v.summary.room == room)
        {
            self.snapshot.inspection.restrictions =
                self.pages(Operation::ModerationRestrictions, Target::Room(room))?;
        }
        if let Some(view) = &mut self.snapshot.selected
            && view.summary.room == room
        {
            if view.focus.is_none() {
                view.events = cached.events;
            }
            view.members = page.members;
            view.stale = false;
            view.has_more = page.has_more;
            view.read_sequence = current.read_sequence;
            if let Some(summary) = self.snapshot.rooms.iter().find(|s| s.room == room) {
                view.summary = summary.clone();
            }
        }
        Ok(())
    }
    pub(super) fn notify(&mut self, room: RoomId, events: &[Event]) -> Result<()> {
        let prefs =
            cache::room_preferences(&mut self.client.store, room).map_err(|_| Error::Storage)?;
        if self.snapshot.preferences.quiet || prefs.notifications == NotificationMode::Off {
            return Ok(());
        }
        for event in events {
            if !matches!(
                event.kind,
                Operation::MessageSend | Operation::MessageReply | Operation::MessageAction
            ) || event.actor.represented() == self.snapshot.account
                || event.actor.acting().account == self.snapshot.account
            {
                continue;
            }
            if self.snapshot.inspection.filters.iter().any(|f| {
                (f.ignored || f.muted)
                    && crate::conversations::subjects(&event.actor).contains(&f.subject)
            }) {
                continue;
            }
            let mentions = if event
                .body
                .deserialized::<crate::crypto::EncryptedEvent>()
                .is_ok()
            {
                let content = super::super::archive::content(
                    &mut self.client.store,
                    std::slice::from_ref(event),
                )
                .map_err(|_| Error::Storage)?;
                match content.get(&event.event) {
                    Some(super::super::MessageContent::Decrypted(message)) => {
                        message.mentions.clone()
                    }
                    _ => continue,
                }
            } else {
                event
                    .body
                    .deserialized::<messaging::Send>()
                    .map_err(|_| Error::Input)?
                    .mentions
            };
            let mention = mentions
                .iter()
                .any(|mention| mention.account == self.snapshot.account);
            if prefs.notifications == NotificationMode::Mentions && !mention {
                continue;
            }
            self.notification = self.notification.wrapping_add(1);
            self.snapshot.notifications.push(Notification {
                id: self.notification,
                room,
                event: event.event,
                sound: self.snapshot.preferences.sound && prefs.sound,
                mention,
            });
            if self.snapshot.notifications.len() > 64 {
                self.snapshot.notifications.remove(0);
            }
        }
        Ok(())
    }
}

impl Worker {
    pub(super) fn open_event(&mut self, room: RoomId, event: Id) -> Result<()> {
        let context = self.client.message_context(room, event, None)?;
        if !context
            .events
            .iter()
            .any(|e| e.event == event && e.room == room)
            || context.events.len() > 5
        {
            return Err(Error::Input);
        }
        if self
            .snapshot
            .selected
            .as_ref()
            .is_none_or(|v| v.summary.room != room)
        {
            self.select(room)?;
        }
        let view = self.snapshot.selected.as_mut().ok_or(Error::Input)?;
        view.events = context.events;
        view.content = context.content;
        view.members = context.members;
        view.summary.revision = context.room_revision;
        view.focus = Some(event);
        view.stale = false;
        view.gap = None;
        view.has_more = false;
        Ok(())
    }
}

impl Worker {
    fn pull_encrypted(
        &mut self,
        room: RoomId,
        current: conversations::Inspection,
        previous: u64,
    ) -> Result<()> {
        let initial = self.client.crypto_inspect(room, None)?;
        if let Some(selected) = &mut self.snapshot.selected
            && selected.summary.room == room
        {
            selected.crypto = Some(initial.clone());
        }
        if super::super::encrypted::require_trust(&initial).is_err() {
            return Ok(());
        }
        let view = self.client.crypto_sync(room, None)?;
        let mut cached = cache::room(&mut self.client.store, room).map_err(|_| Error::Storage)?;
        cached.events.retain(|e| {
            !matches!(
                e.kind,
                Operation::MessageSend | Operation::MessageReply | Operation::MessageAction
            ) || !conversations::subjects(&e.actor)
                .iter()
                .any(|a| view.remote.ignored.contains(a))
        });
        if self.caught_up.contains(&room) {
            self.notify(
                room,
                &cached
                    .events
                    .iter()
                    .filter(|e| e.sequence > previous)
                    .cloned()
                    .collect::<Vec<_>>(),
            )?;
        }
        let cursor = cached
            .cursor
            .as_ref()
            .map(|c| {
                VerifyingKey::from_bytes(self.client.profile.active_server().signing_key.as_bytes())
                    .map_err(|_| Error::Input)
                    .and_then(|k| {
                        verify_cursor(&c.0, &k)
                            .map(|c| c.value().sequence)
                            .map_err(|_| Error::Input)
                    })
            })
            .transpose()?
            .unwrap_or(0);
        let more = self
            .snapshot
            .rooms
            .iter()
            .find(|s| s.room == room)
            .is_some_and(|s| cursor < s.sequence);
        if !more {
            self.caught_up.insert(room);
        }
        let content = super::super::archive::content(&mut self.client.store, &cached.events)
            .map_err(|_| Error::Storage)?;
        if let Some(selected) = &mut self.snapshot.selected
            && selected.summary.room == room
        {
            if selected.focus.is_none() {
                selected.events = cached.events;
                selected.content = content;
            }
            selected.crypto = Some(view);
            selected.members = current.members;
            selected.read_sequence = current.read_sequence;
            selected.has_more = more;
            selected.stale = false;
        }
        Ok(())
    }
}
