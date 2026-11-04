// SPDX-License-Identifier: Apache-2.0
//! Current filtered pulls, bounded cached views and notification admission.
use super::*;
impl Worker {
    pub(super) fn refresh(&mut self) -> Result<()> {
        self.refresh_cycle = None;
        let result = self.update_view(Self::refresh_current);
        // Failed nonretryable reads also get a finite interval before another full attempt.
        self.poll = std::time::Instant::now();
        result
    }
    fn refresh_current(&mut self) -> Result<()> {
        cache::maintain(&mut self.client.store).map_err(|_| Error::Storage)?;
        if self.client.bounded_views() {
            return self.grouped_refresh();
        }
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
                self.snapshot.inspection.restrictions.clear();
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
        Ok(())
    }
    pub(super) fn refresh_sent_room(&mut self, room: RoomId, direct_commit: bool) {
        if direct_commit && self.coalescible_room(room) {
            match &mut self.pending_room {
                Some(pending) if pending.room == room => {
                    pending.committed = pending.committed.saturating_add(1);
                }
                None => {
                    self.pending_room = Some(PendingRoomRefresh {
                        room,
                        oldest: Instant::now(),
                        committed: 1,
                    });
                }
                // The command loop drains an incompatible target before admission.
                // Keep direct internal callers safe too, without losing old work.
                Some(_) => {
                    self.flush_pending_room();
                    let view = self.refresh_after_send(room);
                    self.finish_view(view);
                }
            }
            self.publish();
        } else {
            let view = self.refresh_after_send(room);
            self.finish_view(view);
        }
    }
    fn coalescible_room(&mut self, room: RoomId) -> bool {
        room.home == self.client.profile.active_server().home
            && self.snapshot.selected.as_ref().is_some_and(|view| {
                view.summary.room == room && view.focus.is_none() && view.gap.is_none()
            })
            && self.grouped_room(room)
    }
    pub(super) fn pending_room_due(&self, now: Instant) -> bool {
        self.pending_room.as_ref().is_some_and(|pending| {
            pending.committed >= 2
                || now.saturating_duration_since(pending.oldest) >= Duration::from_secs(1)
        })
    }
    pub(super) fn pending_room_allows(&mut self, command: &Command) -> bool {
        let Some(room) = self.pending_room.as_ref().map(|pending| pending.room) else {
            return true;
        };
        // These operations deliberately replace/close the current context.
        matches!(
            command,
            Command::Connect | Command::Disconnect | Command::SelectService(_)
        ) || (matches!(command, Command::Send { room: target, grant: None, .. } if *target == room)
            && self.coalescible_room(room))
    }
    pub(super) fn clear_pending_room(&mut self) {
        if let Some(pending) = self.pending_room.take()
            && let Some(view) = &mut self.snapshot.selected
            && view.summary.room == pending.room
        {
            // A discarded refresh cannot leave its unrefreshed room presented
            // as current. The normal current read must restore that state.
            view.stale = true;
        }
    }
    pub(super) fn flush_pending_room(&mut self) {
        let Some(pending) = self.pending_room.take() else {
            return;
        };
        let view = self.refresh_after_send(pending.room);
        self.finish_view(view);
        self.publish();
    }
    pub(super) fn refresh_after_send(&mut self, room: RoomId) -> Result<()> {
        self.update_view(|worker| {
            if worker.grouped_room(room) {
                worker.grouped_pull(room)?;
                if let Some(event) = worker
                    .snapshot
                    .selected
                    .as_ref()
                    .filter(|v| v.summary.room == room)
                    .and_then(|v| v.focus)
                {
                    worker.open_event(room, event)?;
                }
                worker.snapshot.privacy = Some(worker.client.session()?.refresh_privacy()?);
                return Ok(());
            }
            // Recipient filtering remains current before admitting history or notifications.
            let filters = worker.pages(
                Operation::ModerationFilters,
                Target::Account(worker.snapshot.account),
            )?;
            worker.install_filters(filters)?;
            if let Some(event) = worker
                .snapshot
                .selected
                .as_ref()
                .filter(|view| view.summary.room == room)
                .and_then(|view| view.focus)
            {
                worker.open_event(room, event)?;
            }
            worker.pull(room)?;
            worker.snapshot.privacy = Some(worker.client.session()?.refresh_privacy()?);
            // Only a full refresh advances the metadata deadline.
            Ok(())
        })
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
        self.update_view(Self::inspect_current)
    }
    fn inspect_current(&mut self) -> Result<()> {
        let target = Target::Account(self.snapshot.account);
        let filters = self.pages(Operation::ModerationFilters, target.clone())?;
        self.install_filters(filters)?;
        self.snapshot.inspection.grants = self.pages(Operation::DelegationList, target.clone())?;
        self.snapshot.inspection.agents = self.pages(Operation::AgentList, target)?;
        self.snapshot.inspection.stale = false;
        Ok(())
    }
    pub(super) fn install_filters(&mut self, filters: Vec<moderation::FilterState>) -> Result<()> {
        self.snapshot.inspection.filters = filters;
        self.snapshot.inspection.filters_stale = false;
        let filters = &self.snapshot.inspection.filters;
        if let Some(view) = &mut self.snapshot.selected {
            view.events
                .retain(|event| !cache::filtered(filters, &event.actor, false));
            if view
                .focus
                .is_some_and(|focus| !view.events.iter().any(|event| event.event == focus))
            {
                view.focus = None;
                view.events.clear();
                view.stale = true;
                view.has_more = false;
            }
            view.content
                .retain(|id, _| view.events.iter().any(|event| event.event == *id));
        }
        if let Some(view) = &mut self.snapshot.search {
            let previous = view.events.len();
            view.events
                .retain(|event| !cache::filtered(filters, &event.actor, false));
            if previous != view.events.len() {
                view.has_more = false;
                view.query.cursor = None;
            }
            view.content
                .retain(|id, _| view.events.iter().any(|event| event.event == *id));
        }
        self.snapshot
            .notifications
            .retain(|notification| !cache::filtered(filters, &notification.actor, true));
        // Current filters take effect before any fallible cache write or later
        // inspection read; an old snapshot must not remain visible during either.
        self.publish();
        cache::save_filters(
            &mut self.client.store,
            self.snapshot.home,
            &self.snapshot.inspection.filters,
        )
        .map_err(|_| Error::Storage)
    }
    pub(super) fn select(&mut self, room: RoomId) -> Result<()> {
        self.update_view(|worker| worker.select_current(room))
    }
    fn select_current(&mut self, room: RoomId) -> Result<()> {
        let summary = self
            .snapshot
            .rooms
            .iter()
            .find(|r| r.room == room)
            .cloned()
            .ok_or(Error::Input)?;
        if self
            .snapshot
            .selected
            .as_ref()
            .is_none_or(|view| view.summary.room != room)
        {
            self.snapshot.inspection.restrictions.clear();
        }
        let mut cached = cache::room(&mut self.client.store, room).map_err(|_| Error::Storage)?;
        cached.events.retain(|event| {
            !cache::filtered(&self.snapshot.inspection.filters, &event.actor, false)
        });
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
        self.update_view(|worker| worker.pull_current(room))
    }
    fn pull_current(&mut self, room: RoomId) -> Result<()> {
        if self
            .snapshot
            .selected
            .as_ref()
            .is_some_and(|v| v.summary.room == room && v.gap.is_some())
        {
            return Ok(());
        }
        let cached = cache::room(&mut self.client.store, room).map_err(|_| Error::Storage)?;
        if cached.gap.is_some() {
            return Ok(());
        }
        if self.grouped_room(room) {
            return self.grouped_pull(room);
        }
        let current: conversations::Inspection =
            match self.read(Operation::RoomInspect, Target::Room(room), &home::Empty {}) {
                Ok(view) => view,
                Err(error) => {
                    if cache::inspection_failed(
                        &mut self.client.store,
                        Operation::RoomInspect,
                        room,
                        &error,
                    )
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
            if result.is_err() {
                self.reconcile_history_gap(room)?;
            }
            return result;
        }
        let end = crate::clock::boot_ms()
            .map_err(|_| Error::Clock)?
            .saturating_add(10_000);
        let page = self.community_page(room, cached.cursor, end, |worker, page, end| {
            worker.read_until(Operation::EventsResume, Target::Room(room), &page, end)
        })?;
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
        if self
            .snapshot
            .selected
            .as_ref()
            .is_some_and(|v| v.summary.room == room)
        {
            self.snapshot.inspection.restrictions =
                self.pages(Operation::ModerationRestrictions, Target::Room(room))?;
        }
        self.present_room_page(room, current, page)
    }
    /// Install a community view only after its current room, history and restriction reads.
    pub(super) fn present_room_page(
        &mut self,
        room: RoomId,
        current: conversations::Inspection,
        page: messaging::PageResult,
    ) -> Result<()> {
        let cached = cache::room(&mut self.client.store, room).map_err(|_| Error::Storage)?;
        if let Some(view) = &mut self.snapshot.selected
            && view.summary.room == room
            && view.gap.is_none()
        {
            if view.focus.is_none() {
                view.events = cached
                    .events
                    .into_iter()
                    .filter(|event| {
                        !cache::filtered(&self.snapshot.inspection.filters, &event.actor, false)
                    })
                    .collect();
            }
            view.members = page.members;
            view.stale = self.snapshot.inspection.filters_stale;
            view.has_more = page.has_more;
            view.read_sequence = current.read_sequence;
            if let Some(summary) = self.snapshot.rooms.iter().find(|s| s.room == room) {
                view.summary = summary.clone();
            }
        }
        Ok(())
    }
    /// One current cursorless page may replace an obsolete access context. Both
    /// attempts share the original read deadline and normal service authorization.
    pub(super) fn community_page(
        &mut self,
        room: RoomId,
        mut cursor: Option<Blob>,
        end: u64,
        mut read: impl FnMut(&mut Self, messaging::Page, u64) -> Result<messaging::PageResult>,
    ) -> Result<messaging::PageResult> {
        let had_cursor = cursor.is_some();
        for attempt in 0..2 {
            if self.shared.stop.load(Ordering::Acquire)
                || self.shared.disconnect.load(Ordering::Acquire)
            {
                return Err(Error::Offline);
            }
            if crate::clock::boot_ms().map_err(|_| Error::Clock)? >= end {
                return Err(Error::Network(super::super::network::Error::Transport));
            }
            let result = read(
                self,
                messaging::Page {
                    cursor: cursor.take(),
                    limit: 32,
                },
                end,
            );
            match result {
                Err(error)
                    if attempt == 0 && had_cursor && cache::cursor_context_changed(&error) =>
                {
                    self.clear_room_presentation(room, None);
                    cache::restart_community(&mut self.client.store, room, None)
                        .map_err(|_| Error::Storage)?;
                }
                Err(error) => {
                    if cache::access_unavailable(&error) {
                        let detail = match &error {
                            Error::Rejected { detail, .. } | Error::Refused { detail, .. } => {
                                detail.as_str()
                            }
                            _ => unreachable!(),
                        };
                        self.clear_room_presentation(room, Some(detail.into()));
                        cache::restart_community(&mut self.client.store, room, Some(detail))
                            .map_err(|_| Error::Storage)?;
                    }
                    return Err(error);
                }
                Ok(page) => {
                    if self.shared.stop.load(Ordering::Acquire)
                        || self.shared.disconnect.load(Ordering::Acquire)
                    {
                        return Err(Error::Offline);
                    }
                    if crate::clock::boot_ms().map_err(|_| Error::Clock)? >= end {
                        return Err(Error::Network(super::super::network::Error::Transport));
                    }
                    return Ok(page);
                }
            }
        }
        unreachable!("community cursor restart is bounded")
    }
    pub(super) fn clear_room_presentation(&mut self, room: RoomId, gap: Option<String>) {
        self.caught_up.remove(&room);
        if let Some(view) = &mut self.snapshot.selected
            && view.summary.room == room
        {
            view.events.clear();
            view.content.clear();
            view.members.clear();
            view.focus = None;
            view.stale = true;
            view.gap = gap;
            view.has_more = false;
        }
        if self
            .snapshot
            .search
            .as_ref()
            .is_some_and(|view| view.room == room)
        {
            self.snapshot.search = None;
        }
        self.snapshot
            .notifications
            .retain(|notification| notification.room != room);
        self.publish();
    }
    pub(super) fn reconcile_history_gap(&mut self, room: RoomId) -> Result<()> {
        if let Some(gap) = cache::room(&mut self.client.store, room)
            .map_err(|_| Error::Storage)?
            .gap
        {
            self.clear_room_presentation(room, Some(gap));
        }
        Ok(())
    }
    pub(super) fn notify(&mut self, room: RoomId, events: &[Event]) -> Result<()> {
        if self.snapshot.inspection.filters_stale {
            return Ok(());
        }
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
            if cache::filtered(&self.snapshot.inspection.filters, &event.actor, true) {
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
                actor: event.actor.clone(),
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
        self.update_view(|worker| {
            let result = worker.client.message_context(room, event, None);
            worker.context_result(room, event, result)
        })
    }
    pub(super) fn context_result(
        &mut self,
        room: RoomId,
        event: Id,
        result: Result<super::super::ConversationPage>,
    ) -> Result<()> {
        let context = match result {
            Ok(context) => context,
            Err(error) => {
                if cache::access_unavailable(&error) {
                    if let Some(view) = &mut self.snapshot.selected
                        && view.summary.room == room
                        && view.focus == Some(event)
                    {
                        view.events.clear();
                        view.content.clear();
                        view.members.clear();
                        view.focus = None;
                        view.stale = true;
                        view.has_more = false;
                        view.gap = Some("CurrentHistoryAccessUnavailable".into());
                    }
                    if self
                        .snapshot
                        .search
                        .as_ref()
                        .is_some_and(|view| view.room == room)
                    {
                        self.snapshot.search = None;
                    }
                    self.snapshot
                        .notifications
                        .retain(|notification| notification.room != room);
                    self.caught_up.remove(&room);
                    self.publish();
                    cache::invalidate(&mut self.client.store, room).map_err(|_| Error::Storage)?;
                }
                return Err(error);
            }
        };
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
        view.events = context
            .events
            .into_iter()
            .filter(|event| {
                !cache::filtered(&self.snapshot.inspection.filters, &event.actor, false)
            })
            .collect();
        view.content = context.content;
        view.content
            .retain(|id, _| view.events.iter().any(|event| event.event == *id));
        view.members = context.members;
        view.summary.revision = context.room_revision;
        view.focus = view
            .events
            .iter()
            .any(|entry| entry.event == event)
            .then_some(event);
        view.stale = view.focus.is_none();
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
            if let Some(selected) = &mut self.snapshot.selected
                && selected.summary.room == room
            {
                selected.stale = true;
            }
            return Ok(());
        }
        let view = self.client.crypto_sync(room, None)?;
        let mut cached = cache::room(&mut self.client.store, room).map_err(|_| Error::Storage)?;
        cached.events.retain(|e| {
            !cache::filtered(&self.snapshot.inspection.filters, &e.actor, false)
                && view.history_visible(e)
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
