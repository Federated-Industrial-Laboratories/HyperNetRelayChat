// SPDX-License-Identifier: Apache-2.0
//! Finite view assembly never publishes incomplete recipient policy or history.
use super::*;
use home::views::{CommunityPage, CommunityRequest, MetadataPage, MetadataRequest};

fn deadline() -> Result<u64> {
    Ok(crate::clock::boot_ms()
        .map_err(|_| Error::Clock)?
        .saturating_add(10_000))
}
fn read_page<T: serde::de::DeserializeOwned + serde::Serialize, B: serde::Serialize>(
    worker: &mut Worker,
    operation: Operation,
    target: Target,
    request: &B,
    end: u64,
) -> Result<T> {
    let body: Value = worker.read_until(operation, target, request, end)?;
    home::views::decode(&body).ok_or(Error::Input)
}

fn page() -> home::InspectPage {
    home::InspectPage::default()
}
fn advance<T>(
    request: &mut Option<home::InspectPage>,
    value: Option<home::InspectionPage<T>>,
    items: &mut Vec<T>,
) -> Result<()> {
    let Some(p) = value else {
        return if request.is_none() {
            Ok(())
        } else {
            Err(Error::Input)
        };
    };
    let wanted = request.as_ref().ok_or(Error::Input)?;
    if p.items.len() > usize::from(wanted.limit)
        || p.next
            .as_ref()
            .is_some_and(|n| Some(n) == wanted.after.as_ref())
        || (p.next.is_some() && p.items.is_empty())
    {
        return Err(Error::Input);
    }
    items.extend(p.items);
    if items.len() > 512 {
        return Err(Error::Input);
    }
    *request = p.next.map(|after| home::InspectPage {
        after: Some(after),
        limit: 16,
    });
    Ok(())
}
pub(super) struct MetadataAssembly {
    request: MetadataRequest,
    rounds: u8,
    components: [u8; 4],
    rooms: Vec<conversations::Summary>,
    filters: Vec<moderation::FilterState>,
    grants: Vec<delegation::Grant>,
    agents: Vec<identity::AgentEndpoint>,
}
impl MetadataAssembly {
    fn new() -> Self {
        Self {
            request: MetadataRequest {
                rooms: Some(conversations::List {
                    after: None,
                    limit: 16,
                }),
                filters: Some(page()),
                grants: Some(page()),
                agents: Some(page()),
                filter_revision: None,
            },
            rounds: 0,
            components: [0; 4],
            rooms: Vec::new(),
            filters: Vec::new(),
            grants: Vec::new(),
            agents: Vec::new(),
        }
    }
    fn step(&mut self, worker: &mut Worker, end: u64) -> Result<bool> {
        if self.rounds >= 129 {
            return Err(Error::Input);
        }
        let mut issued = self.request.clone();
        if self.rounds != 0 {
            // A continuation gives one component the full remaining representation budget.
            if issued.rooms.is_some() {
                issued.filters = None;
                issued.grants = None;
                issued.agents = None;
            } else if issued.filters.is_some() {
                issued.grants = None;
                issued.agents = None;
            } else if issued.grants.is_some() {
                issued.agents = None;
            }
        }
        for (count, selected) in self.components.iter_mut().zip([
            issued.rooms.is_some(),
            issued.filters.is_some(),
            issued.grants.is_some(),
            issued.agents.is_some(),
        ]) {
            if selected {
                *count += 1;
                if *count > 33 {
                    return Err(Error::Input);
                }
            }
        }
        self.rounds += 1;
        let response: MetadataPage = read_page(
            worker,
            Operation::ClientMetadata,
            Target::Account(worker.snapshot.account),
            &issued,
            end,
        )?;
        if self
            .request
            .filter_revision
            .is_some_and(|r| r != response.account.filter_revision)
        {
            return Err(Error::Input);
        }
        self.request.filter_revision = Some(response.account.filter_revision);
        match (issued.rooms.as_ref(), response.rooms) {
            (Some(wanted), Some(p)) => {
                if p.items.len() > usize::from(wanted.limit)
                    || p.next.is_some_and(|n| {
                        Some(n) == wanted.after || p.items.last().map(|r| r.room) != Some(n)
                    })
                {
                    return Err(Error::Input);
                }
                self.rooms.extend(p.items);
                if self.rooms.len() > 256 {
                    return Err(Error::Input);
                }
                self.request.rooms = p.next.map(|after| conversations::List {
                    after: Some(after),
                    limit: 16,
                });
            }
            (None, None) => {}
            _ => return Err(Error::Input),
        }
        if issued.filters.is_some() {
            advance(
                &mut self.request.filters,
                response.filters,
                &mut self.filters,
            )?;
        } else if response.filters.is_some() {
            return Err(Error::Input);
        }
        if issued.grants.is_some() {
            advance(&mut self.request.grants, response.grants, &mut self.grants)?;
        } else if response.grants.is_some() {
            return Err(Error::Input);
        }
        if issued.agents.is_some() {
            advance(&mut self.request.agents, response.agents, &mut self.agents)?;
        } else if response.agents.is_some() {
            return Err(Error::Input);
        }
        if self.request.rooms.is_some()
            || self.request.filters.is_some()
            || self.request.grants.is_some()
            || self.request.agents.is_some()
        {
            return Ok(false);
        }
        cache::save_rooms(&mut worker.client.store, worker.snapshot.home, &self.rooms)
            .map_err(|_| Error::Storage)?;
        worker.snapshot.rooms = std::mem::take(&mut self.rooms);
        worker.snapshot.nickname = response.account.nickname;
        worker.snapshot.motd = response.service.motd;
        worker.install_filters(std::mem::take(&mut self.filters))?;
        worker.snapshot.inspection.grants = std::mem::take(&mut self.grants);
        worker.snapshot.inspection.agents = std::mem::take(&mut self.agents);
        worker.snapshot.inspection.stale = false;
        Ok(true)
    }
}
pub(super) struct CommunityAssembly {
    end: u64,
    room: RoomId,
    request: CommunityRequest,
    rounds: u8,
    restart_available: bool,
    initial_cursor: Option<Blob>,
    components: [u8; 2],
    filters: Vec<moderation::FilterState>,
    restrictions: Vec<moderation::RestrictionState>,
    history: Option<messaging::PageResult>,
}
impl CommunityAssembly {
    fn new(worker: &mut Worker, room: RoomId) -> Result<Self> {
        let cached = cache::room(&mut worker.client.store, room).map_err(|_| Error::Storage)?;
        Ok(Self {
            room,
            end: deadline()?,
            rounds: 0,
            restart_available: cached.cursor.is_some(),
            initial_cursor: cached.cursor.clone(),
            components: [0; 2],
            filters: Vec::new(),
            restrictions: Vec::new(),
            history: None,
            request: CommunityRequest {
                filters: Some(page()),
                history: Some(messaging::Page {
                    cursor: cached.cursor,
                    limit: 32,
                }),
                restrictions: worker
                    .snapshot
                    .selected
                    .as_ref()
                    .is_some_and(|v| v.summary.room == room)
                    .then(page),
                context: None,
            },
        })
    }
    fn step(&mut self, worker: &mut Worker, end: u64) -> Result<bool> {
        let issued = self.next_request()?;
        let response: CommunityPage = match read_page(
            worker,
            Operation::CommunitySync,
            Target::Room(self.room),
            &issued,
            end,
        ) {
            Ok(page) => page,
            Err(error) => {
                if self.restart_available && cache::cursor_context_changed(&error) {
                    self.restart_available = false;
                    self.initial_cursor = None;
                    worker.clear_room_presentation(self.room, None);
                    cache::restart_community(&mut worker.client.store, self.room, None)
                        .map_err(|_| Error::Storage)?;
                    self.request.context = None;
                    self.request.filters = Some(page());
                    self.request.history = Some(messaging::Page {
                        cursor: None,
                        limit: 32,
                    });
                    self.filters.clear();
                    self.restrictions.clear();
                    self.history = None;
                    self.request.restrictions = worker
                        .snapshot
                        .selected
                        .as_ref()
                        .is_some_and(|v| v.summary.room == self.room)
                        .then(page);
                    return Ok(false);
                }
                if cache::access_unavailable(&error) {
                    let detail = match &error {
                        Error::Rejected { detail, .. } | Error::Refused { detail, .. } => {
                            detail.as_str()
                        }
                        _ => unreachable!(),
                    };
                    worker.clear_room_presentation(self.room, Some(detail.into()));
                    cache::restart_community(&mut worker.client.store, self.room, Some(detail))
                        .map_err(|_| Error::Storage)?;
                } else if matches!(&error, Error::Rejected { detail, .. } if detail == "ViewContextChanged")
                {
                    // Keep the original cursor so a subsequent read still detects a real history gap.
                    worker.clear_room_presentation(self.room, None);
                } else if cache::inspection_failed(
                    &mut worker.client.store,
                    Operation::RoomInspect,
                    self.room,
                    &error,
                )
                .map_err(|_| Error::Storage)?
                {
                    worker.clear_room_presentation(
                        self.room,
                        Some("CurrentRoomAccessUnavailable".into()),
                    );
                }
                return Err(error);
            }
        };
        self.accept(worker, issued, response)
    }
    fn next_request(&mut self) -> Result<CommunityRequest> {
        // One initial page, one possible context restart, and at most 32 full
        // continuation pages per recipient-policy component. Counters never reset.
        if self.rounds >= 66 {
            return Err(Error::Input);
        }
        let mut issued = self.request.clone();
        if issued.history.is_none() && issued.filters.is_some() {
            issued.restrictions = None;
        }
        for (count, selected) in self
            .components
            .iter_mut()
            .zip([issued.filters.is_some(), issued.restrictions.is_some()])
        {
            if selected {
                *count += 1;
                if *count > 34 {
                    return Err(Error::Input);
                }
            }
        }
        self.rounds += 1;
        Ok(issued)
    }
    fn accept(
        &mut self,
        worker: &mut Worker,
        issued: CommunityRequest,
        response: CommunityPage,
    ) -> Result<bool> {
        if response.inspection.confidentiality != RoomConfidentiality::Community
            || self.request.context.is_some_and(|c| c != response.context)
        {
            return Err(Error::Input);
        }
        self.request.context = Some(response.context);
        match (issued.history, response.history) {
            (Some(_), Some(history)) if history.members.is_empty() => {
                self.request.history = None;
                self.history = Some(history);
            }
            (None, None) => {}
            _ => return Err(Error::Input),
        }
        if issued.filters.is_some() {
            advance(
                &mut self.request.filters,
                response.filters,
                &mut self.filters,
            )?;
        } else if response.filters.is_some() {
            return Err(Error::Input);
        }
        if issued.restrictions.is_some() {
            advance(
                &mut self.request.restrictions,
                response.restrictions,
                &mut self.restrictions,
            )?;
        } else if response.restrictions.is_some() {
            return Err(Error::Input);
        }
        if self.request.filters.is_some() || self.request.restrictions.is_some() {
            return Ok(false);
        }
        worker.install_filters(std::mem::take(&mut self.filters))?;
        let mut history = self.history.take().ok_or(Error::Input)?;
        history.members = response.inspection.members.clone();
        let key = ed25519_dalek::VerifyingKey::from_bytes(
            worker.client.profile.active_server().signing_key.as_bytes(),
        )
        .map_err(|_| Error::Configuration)?;
        let now = worker
            .client
            .profile
            .clock
            .sample()
            .map_err(|_| Error::Clock)?
            .upper_ms;
        if history.has_more {
            let next = verify_cursor(&history.cursor.0, &key).map_err(|_| Error::Input)?;
            let previous = self
                .initial_cursor
                .as_ref()
                .map(|cursor| {
                    verify_cursor(&cursor.0, &key)
                        .map(|verified| verified.value().sequence)
                        .map_err(|_| Error::Input)
                })
                .transpose()?
                .unwrap_or(0);
            if next.value().sequence <= previous {
                return Err(Error::Input);
            }
        }
        cache::receive(
            &mut worker.client.store,
            self.room,
            worker.snapshot.account,
            &history,
            &key,
            now,
        )
        .map_err(|_| Error::Storage)?;
        // This proof derives only from the strictly decoded authenticated response.
        worker
            .client
            .remember_community(self.room, response.inspection.confidentiality)?;
        if worker.caught_up.contains(&self.room) {
            worker.notify(self.room, &history.events)?;
        }
        if !history.has_more {
            worker.caught_up.insert(self.room);
        }
        if worker
            .snapshot
            .selected
            .as_ref()
            .is_some_and(|v| v.summary.room == self.room)
        {
            worker.snapshot.inspection.restrictions = std::mem::take(&mut self.restrictions);
        }
        worker.present_room_page(self.room, response.inspection.into(), history)?;
        Ok(true)
    }
}
// A continuation is view work, not a lease or an unbounded subscription. Each
// component yields to commands; a finite burst shares the first page's end.
pub(super) struct SelectedCatchup {
    room: RoomId,
    end: u64,
    pages_left: u8,
    assembly: Option<CommunityAssembly>,
}
impl SelectedCatchup {
    fn eligible(&self, worker: &Worker, now: u64) -> bool {
        now < self.end
            && self.pages_left != 0
            && !worker.shared.stop.load(Ordering::Acquire)
            && !worker.shared.disconnect.load(Ordering::Acquire)
            && worker.snapshot.connection == ConnectionState::Online
            && worker.snapshot.selected.as_ref().is_some_and(|view| {
                view.summary.room == self.room
                    && view.summary.joined
                    && view.focus.is_none()
                    && view.gap.is_none()
                    && view.summary.confidentiality == RoomConfidentiality::Community
            })
    }
}
enum Stage {
    Metadata(MetadataAssembly),
    Selected(Option<RoomId>),
    Background,
    Room(CommunityAssembly, bool),
    Privacy,
}
pub(super) struct RefreshCycle {
    stage: Stage,
}
impl RefreshCycle {
    fn new() -> Result<Self> {
        Ok(Self {
            stage: Stage::Metadata(MetadataAssembly::new()),
        })
    }
    fn room_updated(&mut self, room: RoomId) {
        if let Stage::Selected(updated) = &mut self.stage {
            // Metadata has completed. Keep the room binding until the selected
            // turn so an intervening selection or invalidation cannot be skipped.
            *updated = Some(room);
            return;
        }
        if let Stage::Room(state, background) = &self.stage
            && state.room == room
        {
            // A command already completed a fresh pull. Its newer durable cursor
            // supersedes this unfinished assembly without restarting metadata work.
            self.stage = if *background {
                Stage::Privacy
            } else {
                Stage::Background
            };
        }
    }
    fn step(&mut self, worker: &mut Worker) -> Result<bool> {
        if worker.shared.stop.load(Ordering::Acquire)
            || worker.shared.disconnect.load(Ordering::Acquire)
        {
            return Err(Error::Offline);
        }
        match &mut self.stage {
            Stage::Metadata(state) => {
                if state.step(worker, deadline()?)? {
                    self.stage = Stage::Selected(None);
                }
            }
            Stage::Selected(updated) => {
                let updated = *updated;
                self.stage = Stage::Background;
                if let Some(room) = worker.snapshot.selected.as_ref().map(|r| r.summary.room) {
                    if worker
                        .snapshot
                        .rooms
                        .iter()
                        .any(|r| r.room == room && r.joined)
                    {
                        if updated == Some(room)
                            && worker.client.bounded_views()
                            && !worker.snapshot.inspection.stale
                            && !worker.snapshot.inspection.filters_stale
                            && worker.snapshot.selected.as_ref().is_some_and(|view| {
                                view.summary.joined
                                    && view.summary.confidentiality
                                        == RoomConfidentiality::Community
                                    && !view.stale
                                    && view.gap.is_none()
                                    && view.focus.is_none()
                            })
                        {
                            return Ok(false);
                        }
                        if let Some(event) = worker.snapshot.selected.as_ref().and_then(|v| v.focus)
                        {
                            worker.open_event(room, event)?;
                        }
                        if worker.grouped_room(room) {
                            self.stage = Stage::Room(CommunityAssembly::new(worker, room)?, false);
                        } else {
                            worker.pull(room)?;
                        }
                    } else {
                        worker.snapshot.selected = None;
                        worker.snapshot.inspection.restrictions.clear();
                        worker.snapshot.search = None;
                    }
                }
            }
            Stage::Background => {
                self.stage = Stage::Privacy;
                let selected = worker.snapshot.selected.as_ref().map(|v| v.summary.room);
                let rooms: Vec<_> = worker
                    .snapshot
                    .rooms
                    .iter()
                    .filter(|r| r.joined && Some(r.room) != selected)
                    .map(|r| r.room)
                    .collect();
                if !rooms.is_empty() {
                    let room = rooms[worker.poll_room % rooms.len()];
                    worker.poll_room = worker.poll_room.wrapping_add(1);
                    if worker.grouped_room(room) {
                        self.stage = Stage::Room(CommunityAssembly::new(worker, room)?, true);
                    } else {
                        worker.pull(room)?;
                    }
                }
            }
            Stage::Room(state, background) => {
                if state.step(worker, state.end)? {
                    worker.continue_selected(state.room, state.end);
                    self.stage = if *background {
                        Stage::Privacy
                    } else {
                        Stage::Background
                    };
                }
            }
            Stage::Privacy => {
                worker.snapshot.privacy = Some(worker.client.session()?.refresh_privacy()?);
                return Ok(true);
            }
        }
        Ok(false)
    }
}
impl Worker {
    fn continue_selected(&mut self, room: RoomId, end: u64) {
        if !self.snapshot.selected.as_ref().is_some_and(|view| {
            view.summary.room == room
                && view.summary.joined
                && view.has_more
                && view.focus.is_none()
                && view.gap.is_none()
                && !view.stale
        }) {
            if self
                .selected_catchup
                .as_ref()
                .is_some_and(|pending| pending.room == room)
            {
                self.selected_catchup = None;
            }
            return;
        }
        let pending = self
            .selected_catchup
            .take()
            .filter(|pending| pending.room == room)
            .map_or(
                SelectedCatchup {
                    room,
                    end,
                    pages_left: 8,
                    assembly: None,
                },
                |mut pending| {
                    pending.end = pending.end.min(end);
                    pending.pages_left = pending.pages_left.saturating_sub(1);
                    pending.assembly = None;
                    pending
                },
            );
        // A command's completed page supersedes a partial assembly, but cannot
        // extend either the original end or its remaining page allowance.
        if pending.pages_left != 0 {
            self.selected_catchup = Some(pending);
        }
    }
    pub(super) fn catchup_turn(&mut self) -> Result<()> {
        self.catchup_turn_with(|state, worker| state.step(worker, state.end))
    }
    fn catchup_turn_with(
        &mut self,
        read: impl FnOnce(&mut CommunityAssembly, &mut Worker) -> Result<bool>,
    ) -> Result<()> {
        let Some(mut pending) = self.selected_catchup.take() else {
            return Ok(());
        };
        let room = pending.room;
        let result = self.update_view(|worker| {
            let now = crate::clock::boot_ms().map_err(|_| Error::Clock)?;
            if !pending.eligible(worker, now) || !worker.grouped_room(pending.room) {
                return Ok(());
            }
            let mut state = match pending.assembly.take() {
                Some(state) => state,
                None => {
                    let mut state = CommunityAssembly::new(worker, pending.room)?;
                    state.end = pending.end;
                    state
                }
            };
            if read(&mut state, worker)? {
                if let Some(cycle) = &mut worker.refresh_cycle {
                    cycle.room_updated(pending.room);
                }
                pending.pages_left -= 1;
                if worker
                    .snapshot
                    .selected
                    .as_ref()
                    .is_none_or(|view| !view.has_more)
                {
                    return Ok(());
                }
            } else {
                pending.assembly = Some(state);
            }
            if pending.eligible(worker, crate::clock::boot_ms().map_err(|_| Error::Clock)?) {
                worker.selected_catchup = Some(pending);
            }
            Ok(())
        });
        if result.is_err() {
            self.snapshot.notifications.clear();
            self.snapshot.search = None;
            let gap = self
                .snapshot
                .selected
                .as_ref()
                .filter(|view| view.summary.room == room)
                .and_then(|view| view.gap.clone());
            self.clear_room_presentation(room, gap);
        }
        result
    }
    pub(super) fn grouped_room(&mut self, room: RoomId) -> bool {
        self.client.bounded_views()
            && self
                .snapshot
                .rooms
                .iter()
                .any(|r| r.room == room && r.confidentiality == RoomConfidentiality::Community)
            && if let Some(view) = self
                .snapshot
                .selected
                .as_ref()
                .filter(|v| v.summary.room == room)
            {
                view.gap.is_none()
            } else {
                cache::room(&mut self.client.store, room).is_ok_and(|c| c.gap.is_none())
            }
    }
    pub(super) fn grouped_pull(&mut self, room: RoomId) -> Result<()> {
        let mut state = CommunityAssembly::new(self, room)?;
        loop {
            match state.step(self, state.end) {
                Ok(true) => break,
                Ok(false) => {}
                Err(error) => {
                    self.snapshot.inspection.filters_stale = true;
                    let gap = self
                        .snapshot
                        .selected
                        .as_ref()
                        .filter(|v| v.summary.room == room)
                        .and_then(|v| v.gap.clone());
                    self.clear_room_presentation(room, gap);
                    return Err(error);
                }
            }
        }
        if let Some(cycle) = &mut self.refresh_cycle {
            cycle.room_updated(room);
        }
        self.continue_selected(room, state.end);
        Ok(())
    }
    pub(super) fn grouped_refresh(&mut self) -> Result<()> {
        let mut cycle = RefreshCycle::new()?;
        while !cycle.step(self)? {}
        Ok(())
    }
    pub(super) fn refresh_turn(&mut self) -> Result<()> {
        if !self.client.bounded_views() {
            return self.refresh();
        }
        let pending = self.refresh_cycle.take();
        let result = self.update_view(|worker| {
            let Some(mut cycle) = pending else {
                // Local retention is one finite turn at the periodic cycle boundary.
                // It does not confer authority or repeat for each component page.
                cache::maintain(&mut worker.client.store).map_err(|_| Error::Storage)?;
                return Ok((false, RefreshCycle::new()?));
            };
            let done = cycle.step(worker)?;
            Ok((done, cycle))
        });
        match result {
            Ok((false, cycle)) => self.refresh_cycle = Some(cycle),
            Ok((true, _)) => self.poll = Instant::now(),
            Err(error) => {
                self.snapshot.notifications.clear();
                self.snapshot.search = None;
                self.poll = Instant::now();
                return Err(error);
            }
        }
        Ok(())
    }
}

#[cfg(test)]
#[path = "../../Tests/Client/Views.rs"]
mod tests;
