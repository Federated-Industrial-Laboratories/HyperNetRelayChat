// SPDX-License-Identifier: Apache-2.0
//! One client worker owns encrypted state; bounded commands never run database or network I/O on the UI.
use super::{Client, Error, Result, cache, view::*};
use crate::{conversations, delegation, home, identity, messaging, moderation, protocol::*};
use std::{
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
        mpsc::{self, SyncSender, TrySendError},
    },
    thread,
    time::{Duration, Instant},
};

#[derive(Debug, thiserror::Error)]
pub enum DispatchError {
    #[error("client command queue is full")]
    QueueFull,
    #[error("client is stopped")]
    Stopped,
    #[error("command exceeds its bound")]
    Invalid,
}
struct Shared {
    snapshot: Mutex<Arc<Snapshot>>,
    stop: AtomicBool,
    disconnect: AtomicBool,
    cancel: AtomicBool,
    search_pending: AtomicBool,
    stream: Mutex<Option<Arc<crate::hypernet::Stream>>>,
    queue: Mutex<QueueBudget>,
}
#[derive(Default)]
struct QueueBudget {
    closed: bool,
    pending: usize,
    // At most the bounded queued sends plus the single held command. Local saves
    // can overtake that lane, but cannot give an older send ownership of new text.
    draft_sends: std::collections::BTreeMap<u64, (RoomId, bool)>,
}
pub struct Controller {
    shared: Arc<Shared>,
    sender: SyncSender<Queued>,
    local_sender: SyncSender<Queued>,
    worker: Option<thread::JoinHandle<()>>,
    next_request: AtomicU64,
}
struct Queued {
    id: u64,
    command: Command,
    admission_end: Instant,
}
#[derive(Debug, PartialEq, Eq)]
enum Admission {
    Run,
    Wait,
    Expired,
}
impl Queued {
    fn local(command: &Command) -> bool {
        matches!(
            command,
            Command::SaveDraft { .. }
                | Command::SetPreferences(_)
                | Command::SetRoomPreferences { .. }
                | Command::CloseSearch
                | Command::AbandonPending { .. }
                | Command::TrustContact { .. }
        )
    }
    fn new(id: u64, command: Command) -> Self {
        Self {
            id,
            command,
            admission_end: Instant::now() + Duration::from_secs(30),
        }
    }
    fn admission(&self, desired: bool, online: bool, now: Instant) -> Admission {
        let draft_only = matches!(&self.command, Command::Send { grant: Some(grant), .. }
            if grant.scope.mode == delegation::Mode::Draft);
        let effect = !draft_only
            && matches!(
                self.command,
                Command::Send { .. }
                    | Command::MarkRead { .. }
                    | Command::CreateRoom { .. }
                    | Command::CreatePrivateGroup { .. }
                    | Command::CreateDirect { .. }
                    | Command::Invite { .. }
                    | Command::CryptoEnrol
                    | Command::CryptoPublish { .. }
                    | Command::CryptoInitialise { .. }
                    | Command::CryptoCommit { .. }
                    | Command::CryptoSync { .. }
                    | Command::Join(_)
                    | Command::Leave(_)
                    | Command::SetTopic { .. }
                    | Command::SetNickname(_)
                    | Command::SetPresence(_)
                    | Command::SetFilter { .. }
                    | Command::SetRestriction { .. }
                    | Command::CreateGrant(_)
                    | Command::ChangeGrant { .. }
                    | Command::DecideApproval { .. }
                    | Command::SubmitCandidate(_)
            );
        // Deliberately offline commands retain their existing refusal/local-draft behaviour.
        if !effect || !desired {
            Admission::Run
        } else if now >= self.admission_end {
            Admission::Expired
        } else if online {
            Admission::Run
        } else {
            Admission::Wait
        }
    }
}
impl Controller {
    pub fn open(path: &Path) -> Result<Self> {
        let mut client = Client::open_offline(path)?;
        let preferences =
            cache::preferences(&mut client.store, "global").map_err(|_| Error::Storage)?;
        if !cache::validate_preferences(&preferences) {
            return Err(Error::Storage);
        }
        let rooms = cache::rooms(&mut client.store)
            .map_err(|_| Error::Storage)?
            .into_iter()
            .filter(|room| room.room.home == client.profile.active_server().home)
            .collect();
        let filters = cache::filters(&mut client.store, client.profile.active_server().home)
            .map_err(|_| Error::Storage)?;
        let snapshot = Snapshot {
            revision: 0,
            updating: false,
            account: client.profile.registration.account,
            home: client.profile.active_server().home,
            services: client.profile.service_choices(),
            classification: client.profile.registration.classification.clone(),
            nickname: String::new(),
            motd: String::new(),
            connection: ConnectionState::Offline,
            privacy: None,
            federation_privacy: None,
            rooms,
            selected: None,
            search: None,
            deliveries: Vec::new(),
            inspection: Inspection {
                filters,
                stale: true,
                ..Inspection::default()
            },
            preferences,
            notifications: Vec::new(),
            completions: Vec::new(),
            status: None,
        };
        let shared = Arc::new(Shared {
            snapshot: Mutex::new(Arc::new(snapshot.clone())),
            stop: AtomicBool::new(false),
            disconnect: AtomicBool::new(false),
            cancel: AtomicBool::new(false),
            search_pending: AtomicBool::new(false),
            stream: Mutex::new(None),
            queue: Mutex::new(QueueBudget::default()),
        });
        let (sender, receiver) = mpsc::sync_channel::<Queued>(32);
        let (local_sender, local_receiver) = mpsc::sync_channel::<Queued>(32);
        let state = Arc::clone(&shared);
        let worker = thread::Builder::new()
            .name("hrc-client".into())
            .spawn(move || {
                let mut w = Worker {
                    client,
                    snapshot,
                    shared: state,
                    desired: false,
                    attempt: 0,
                    retry: Instant::now(),
                    poll: Instant::now(),
                    caught_up: std::collections::BTreeSet::new(),
                    notification: 0,
                    request: None,
                    operation: None,
                    delivery_room: None,
                    poll_room: 0,
                };
                if let Err(e) = w.deliveries() {
                    w.error(e);
                }
                w.publish();
                w.run(receiver, local_receiver);
            })
            .map_err(|_| Error::Configuration)?;
        Ok(Self {
            shared,
            sender,
            local_sender,
            worker: Some(worker),
            next_request: AtomicU64::new(1),
        })
    }
    pub fn snapshot(&self) -> Arc<Snapshot> {
        Arc::clone(
            &self
                .shared
                .snapshot
                .lock()
                .unwrap_or_else(|e| e.into_inner()),
        )
    }
    pub fn dispatch(&self, command: Command) -> std::result::Result<u64, DispatchError> {
        if self.shared.stop.load(Ordering::Acquire) {
            return Err(DispatchError::Stopped);
        }
        if !bounded(&command) {
            return Err(DispatchError::Invalid);
        }
        let search = matches!(command, Command::Search(_) | Command::NextSearchPage);
        match command {
            Command::Disconnect => {
                self.disconnect();
                return Ok(self.next_request.fetch_add(1, Ordering::Relaxed));
            }
            Command::CancelSearch => {
                self.shared.cancel.store(true, Ordering::Release);
                return Ok(self.next_request.fetch_add(1, Ordering::Relaxed));
            }
            Command::CloseSearch => self.shared.cancel.store(true, Ordering::Release),
            _ => {}
        }
        if search {
            if self.shared.search_pending.swap(true, Ordering::AcqRel) {
                return Err(DispatchError::QueueFull);
            }
            self.shared.cancel.store(false, Ordering::Release);
        }
        let result = (|| {
            let mut queue = self
                .shared
                .queue
                .lock()
                .map_err(|_| DispatchError::Stopped)?;
            if queue.closed {
                return Err(DispatchError::Stopped);
            }
            if queue.pending >= 32 {
                return Err(DispatchError::QueueFull);
            }
            // Number queue admission under the same lock, including concurrent callers.
            let id = self.next_request.fetch_add(1, Ordering::Relaxed);
            if let Command::Send { room, .. } = &command {
                queue.draft_sends.insert(id, (*room, false));
            }
            let sender = if Queued::local(&command) {
                &self.local_sender
            } else {
                &self.sender
            };
            queue.pending += 1;
            match sender.try_send(Queued::new(id, command)) {
                Ok(()) => Ok(id),
                Err(error) => {
                    queue.pending -= 1;
                    queue.draft_sends.remove(&id);
                    Err(match error {
                        TrySendError::Full(_) => DispatchError::QueueFull,
                        TrySendError::Disconnected(_) => DispatchError::Stopped,
                    })
                }
            }
        })();
        match result {
            Ok(id) => Ok(id),
            Err(error) => {
                if search {
                    self.shared.search_pending.store(false, Ordering::Release);
                }
                Err(error)
            }
        }
    }
    pub fn disconnect(&self) {
        self.shared.disconnect.store(true, Ordering::Release);
        if let Some(stream) = self
            .shared
            .stream
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .as_ref()
        {
            stream.close();
        }
    }
    pub fn shutdown(&mut self) {
        {
            let mut queue = self.shared.queue.lock().unwrap_or_else(|e| e.into_inner());
            queue.closed = true;
            self.shared.stop.store(true, Ordering::Release);
        }
        self.disconnect();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
impl Drop for Controller {
    fn drop(&mut self) {
        self.shutdown();
    }
}
fn bounded(c: &Command) -> bool {
    match c {
        Command::SaveDraft { text, mentions, .. } => text.len() <= 8192 && mentions.len() <= 16,
        Command::Send {
            text,
            mentions,
            grant,
            ..
        } => {
            text.len() <= 8192
                && mentions.len() <= 16
                && grant.as_ref().is_none_or(|g| bounded_scope(&g.scope))
        }
        Command::SetNickname(s) | Command::CreateRoom { name: s } => s.len() <= 256,
        Command::SetTopic { topic, .. } => topic.len() <= 1024,
        Command::Search(s) => {
            s.terms.len() <= 8
                && s.terms.iter().all(|s| s.len() <= 1024)
                && s.cursor.as_ref().is_none_or(|c| c.0.len() <= 4096)
        }
        Command::CreateGrant(g) => bounded_scope(g),
        Command::SetPresence(p) => p.status.len() <= 128,
        Command::SetRestriction { restriction, .. } => restriction.reason.len() <= 256,
        Command::SetPreferences(p) => cache::validate_preferences(p),
        _ => true,
    }
}
fn bounded_scope(g: &delegation::Create) -> bool {
    g.rooms.len() <= 32
        && g.recipients.len() <= 32
        && g.operations.len() <= 16
        && g.purpose.len() <= 1024
}
struct Worker {
    client: Client,
    snapshot: Snapshot,
    shared: Arc<Shared>,
    desired: bool,
    attempt: u8,
    retry: Instant,
    poll: Instant,
    caught_up: std::collections::BTreeSet<RoomId>,
    notification: u64,
    request: Option<u64>,
    operation: Option<Operation>,
    delivery_room: Option<RoomId>,
    poll_room: usize,
}
impl Worker {
    fn run(&mut self, receiver: mpsc::Receiver<Queued>, local_receiver: mpsc::Receiver<Queued>) {
        let mut held: Option<Queued> = None;
        while !self.shared.stop.load(Ordering::Acquire) {
            if self.shared.disconnect.swap(false, Ordering::AcqRel) {
                self.offline();
            }
            self.drain_local(&local_receiver, 4);
            if self.shared.stop.load(Ordering::Acquire) {
                break;
            }
            if self.shared.disconnect.swap(false, Ordering::AcqRel) {
                self.offline();
            }
            // Preserve the bounded local lane before servicing due metadata, even
            // with a busy command queue. Recheck controls and original admission
            // deadlines after the potentially slow reads.
            if self.metadata_due() {
                self.tick();
                continue;
            }
            if let Some(queued) = &held {
                let online = self.snapshot.connection == ConnectionState::Online
                    && self.client.session().is_ok();
                match queued.admission(self.desired, online, Instant::now()) {
                    Admission::Wait => {
                        self.tick();
                        // Stop/disconnect retain their reserved atomic control path.
                        thread::sleep(Duration::from_millis(25));
                        continue;
                    }
                    Admission::Expired => {
                        let queued = held.take().expect("held command");
                        self.admission_expired(queued.id);
                        continue;
                    }
                    Admission::Run => {}
                }
                // A reconnect can finish after admission expiry; the check above is
                // repeated before this one consumption, never after an effect begins.
                let queued = held.take().expect("held command");
                self.run_command(queued);
                continue;
            }
            match receiver.recv_timeout(Duration::from_millis(100)) {
                Ok(queued) => {
                    self.dequeued();
                    let online = self.snapshot.connection == ConnectionState::Online
                        && self.client.session().is_ok();
                    if queued.admission(self.desired, online, Instant::now()) == Admission::Wait {
                        self.snapshot.status = Some(Status {
                            request_id: Some(queued.id),
                            code: "CommandWaitingForConnection".into(),
                            detail:
                                "Waiting for the current connection before starting this command."
                                    .into(),
                        });
                        self.publish();
                    }
                    held = Some(queued);
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
                Err(mpsc::RecvTimeoutError::Timeout) => self.tick(),
            }
        }
        self.offline();
        // Shutdown closes admission under the queue mutex before this final finite drain.
        self.drain_local(&local_receiver, 32);
    }
    fn dequeued(&self) {
        let mut queue = self.shared.queue.lock().unwrap_or_else(|e| e.into_inner());
        queue.pending -= 1;
    }
    fn drain_local(&mut self, receiver: &mpsc::Receiver<Queued>, limit: usize) {
        for _ in 0..limit {
            let Ok(queued) = receiver.try_recv() else {
                break;
            };
            self.dequeued();
            self.run_command(queued);
        }
    }
    fn run_command(&mut self, queued: Queued) {
        self.request = Some(queued.id);
        let search = matches!(queued.command, Command::Search(_) | Command::NextSearchPage);
        let result = self.command(queued.command);
        self.retire_draft_send(queued.id);
        if search {
            self.shared.search_pending.store(false, Ordering::Release);
        }
        self.complete(queued.id, result);
        self.request = None;
        self.operation = None;
        self.delivery_room = None;
    }
    fn tick(&mut self) {
        if self.desired
            && (self.client.session().is_err()
                || matches!(self.snapshot.connection, ConnectionState::Backoff { .. }))
            && Instant::now() >= self.retry
        {
            if let Err(error) = self.connect() {
                self.error(error);
            }
            self.publish();
        } else if self.metadata_due() {
            if let Err(error) = self.refresh() {
                self.error(error);
            }
            self.publish();
        }
    }
    fn metadata_due(&self) -> bool {
        matches!(
            self.snapshot.connection,
            ConnectionState::Online | ConnectionState::Resolving
        ) && self.poll.elapsed() >= Duration::from_secs(5)
    }
    fn admission_expired(&mut self, id: u64) {
        self.retire_draft_send(id);
        let status = Status {
            request_id: Some(id),
            code: "CommandAdmissionExpired".into(),
            detail: "The command did not start before its connection admission deadline.".into(),
        };
        self.record_completion(id, Some(status.clone()));
        self.snapshot.status = Some(status);
        self.publish();
    }
    fn record_completion(&mut self, id: u64, error: Option<Status>) {
        self.snapshot.completions.push(Completion {
            request_id: id,
            error,
        });
        if self.snapshot.completions.len() > 64 {
            self.snapshot.completions.remove(0);
        }
    }
    fn retire_draft_send(&self, id: u64) {
        self.shared
            .queue
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .draft_sends
            .remove(&id);
    }
    fn draft_saved(&self, room: RoomId) {
        let Some(id) = self.request else { return };
        let mut queue = self.shared.queue.lock().unwrap_or_else(|e| e.into_inner());
        for (&send, (target, superseded)) in &mut queue.draft_sends {
            if send < id && *target == room {
                *superseded = true;
            }
        }
    }
    fn preserve_send_draft(
        &mut self,
        room: RoomId,
        text: &str,
        mentions: &[messaging::Mention],
    ) -> Result<bool> {
        let superseded = self.request.is_some_and(|id| {
            self.shared
                .queue
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .draft_sends
                .get(&id)
                .is_some_and(|(_, superseded)| *superseded)
        });
        if superseded {
            return Ok(false);
        }
        self.client.save_draft_mentions(room, text, mentions)?;
        if let Some(view) = &mut self.snapshot.selected
            && view.summary.room == room
        {
            view.draft = text.to_owned();
            view.draft_mentions = mentions.to_vec();
        }
        self.publish();
        Ok(true)
    }
    fn complete(&mut self, id: u64, result: Result<()>) {
        self.record_completion(
            id,
            result.as_ref().err().map(|e| Status {
                request_id: Some(id),
                code: e.code().into(),
                detail: e.to_string(),
            }),
        );
        if let Err(error) = result {
            self.error(error);
        }
        self.publish();
    }
    /// Only trailing view work comes here, after all effects and required local writes succeeded.
    fn finish_view(&mut self, result: Result<()>) {
        if let Err(error) = result {
            let request = self.request.take();
            self.stale();
            self.error(error);
            if let Some(status) = &mut self.snapshot.status {
                status.detail = format!("View refresh failed: {}: {}", status.code, status.detail);
                status.code = "ViewRefreshFailed".into();
            }
            self.request = request;
        }
    }
    /// Progress never invalidates a successful view or makes a retained view current.
    /// Nested reads share the outer progress lifetime; every failed scope is visible.
    fn update_view<T>(&mut self, work: impl FnOnce(&mut Self) -> Result<T>) -> Result<T> {
        let nested = self.snapshot.updating;
        if !nested {
            self.snapshot.updating = true;
            self.publish();
        }
        let result = work(self);
        if result.is_err() {
            self.stale();
        }
        if !nested {
            self.snapshot.updating = false;
        }
        if !nested || result.is_err() {
            self.publish();
        }
        result
    }
    fn publish(&mut self) {
        if self.snapshot.connection == ConnectionState::Online
            && !self.snapshot.inspection.stale
            && self.snapshot.privacy.is_some()
            && self
                .snapshot
                .selected
                .as_ref()
                .is_none_or(|room| !room.stale)
            && self
                .snapshot
                .status
                .as_ref()
                .is_some_and(|status| status.code == "ViewRefreshFailed")
        {
            self.snapshot.status = None;
        }
        self.snapshot.revision = self.snapshot.revision.wrapping_add(1);
        *self
            .shared
            .snapshot
            .lock()
            .unwrap_or_else(|e| e.into_inner()) = Arc::new(self.snapshot.clone());
    }
    fn stale(&mut self) {
        if let Some(room) = &mut self.snapshot.selected {
            room.stale = true;
        }
        self.snapshot.inspection.stale = true;
        self.snapshot.privacy = None;
        self.snapshot.federation_privacy = None;
    }
    fn offline(&mut self) {
        self.desired = false;
        self.client.disconnect();
        self.stale();
        self.snapshot.connection = ConnectionState::Offline;
        self.caught_up.clear();
        *self.shared.stream.lock().unwrap_or_else(|e| e.into_inner()) = None;
        // Reserved disconnect can leave an idle worker with no later command or
        // poll to publish the closed connection and invalidated live state.
        self.publish();
    }
    fn error(&mut self, e: Error) {
        self.snapshot.status = Some(Status {
            request_id: self.request,
            code: e.code().into(),
            detail: e.to_string(),
        });
        let retry = e.retry_delay_ms();
        if retry.is_some() || matches!(e, Error::Network(_) | Error::Refused { .. }) {
            if !e.can_reuse_session() {
                self.client.disconnect();
                *self.shared.stream.lock().unwrap_or_else(|e| e.into_inner()) = None;
            }
            self.stale();
            self.caught_up.clear();
            if retry.is_none() {
                self.desired = false;
                self.snapshot.connection = ConnectionState::Offline;
                return;
            }
            self.attempt = self.attempt.saturating_add(1);
            let jitter = Id::random()
                .map(|id| u64::from(id.as_bytes()[0]) * 4)
                .unwrap_or(500);
            let delay =
                ((1000u64 << self.attempt.min(5)).min(30000) + jitter).max(retry.unwrap_or(0));
            self.retry = Instant::now() + Duration::from_millis(delay);
            self.snapshot.connection = if self.desired {
                ConnectionState::Backoff {
                    attempt: self.attempt,
                    retry_in_ms: delay,
                    reason: e.code().into(),
                }
            } else {
                ConnectionState::Offline
            };
        }
    }
    fn connect(&mut self) -> Result<()> {
        let reuse = matches!(self.snapshot.connection, ConnectionState::Backoff { .. })
            && self.client.session().is_ok();
        self.desired = true;
        if reuse && Instant::now() < self.retry {
            return Ok(());
        }
        if !reuse {
            self.snapshot.connection = ConnectionState::Connecting;
            self.publish();
            self.client.connect()?;
        }
        *self.shared.stream.lock().unwrap_or_else(|e| e.into_inner()) =
            Some(self.client.session()?.stream_handle());
        self.snapshot.connection = ConnectionState::Resolving;
        self.publish();
        let pending = self.client.pending()?;
        self.deliveries()?;
        for p in pending.iter().filter(|p| !p.abandoned && !p.held) {
            let response = self
                .client
                .retry_pending(p.action.action().operation_id, p.action.digest())?;
            let original = match response.outcome {
                Outcome::Result { body } => body
                    .deserialized::<home::ResolveResult>()
                    .ok()
                    .map(|r| (r.operation_id, r.action_digest, r.outcome)),
                outcome if response.operation_id == p.action.action().operation_id => {
                    Some((response.operation_id, response.action_digest, outcome))
                }
                outcome => return Err(Error::from_outcome(outcome)),
            };
            if let Some((operation_id, action_digest, outcome)) = original {
                if p.action.action().operation_id != operation_id
                    || p.action.digest() != action_digest
                {
                    return Err(Error::Input);
                }
                let request_id = self
                    .snapshot
                    .deliveries
                    .iter()
                    .find(|d| d.operation_id == operation_id)
                    .and_then(|d| d.request_id);
                if matches!(outcome, Outcome::Committed { .. }) {
                    self.clear_matching_draft(p.action.action())?;
                }
                self.snapshot
                    .deliveries
                    .retain(|d| d.operation_id != operation_id);
                self.snapshot.deliveries.push(Delivery {
                    abandoned: p.abandoned,
                    held: p.held,
                    request_id,
                    operation: p.action.action().operation,
                    operation_id,
                    action_digest,
                    room: match p.action.action().target {
                        Target::Room(room) => Some(room),
                        _ => None,
                    },
                    outcome: Some(outcome.clone()),
                });
                // Retain each resolved identity before another read can fail.
                // Temporary non-admission must remain pending for fresh resolution.
                if matches!(
                    outcome,
                    Outcome::Refused { .. } | Outcome::Unknown | Outcome::Absent
                ) {
                    return Err(Error::from_outcome(outcome));
                }
            } else {
                return Err(Error::Input);
            }
        }
        self.snapshot.privacy = Some(self.client.session()?.privacy());
        self.snapshot.federation_privacy = self.client.session()?.remote.clone();
        self.caught_up.clear();
        self.refresh()?;
        self.snapshot.connection = ConnectionState::Online;
        self.attempt = 0;
        Ok(())
    }
    fn deliveries(&mut self) -> Result<()> {
        for p in self.client.pending()? {
            let operation_id = p.action.action().operation_id;
            let request_id = self
                .snapshot
                .deliveries
                .iter()
                .find(|d| d.operation_id == operation_id)
                .and_then(|d| d.request_id);
            self.snapshot
                .deliveries
                .retain(|d| d.operation_id != operation_id);
            self.snapshot.deliveries.push(Delivery {
                abandoned: p.abandoned,
                held: p.held,
                request_id,
                operation: p.action.action().operation,
                operation_id,
                action_digest: p.action.digest(),
                room: match p.action.action().target {
                    Target::Room(room) => Some(room),
                    _ => None,
                },
                outcome: p.last_response.map(|r| r.outcome),
            });
        }
        if self.snapshot.deliveries.len() > 320 {
            self.snapshot
                .deliveries
                .drain(..self.snapshot.deliveries.len() - 320);
        }
        Ok(())
    }
    fn remember(&mut self, action: &Action) -> Result<()> {
        self.snapshot
            .deliveries
            .retain(|d| d.operation_id != action.operation_id);
        self.snapshot.deliveries.push(Delivery {
            abandoned: false,
            held: false,
            request_id: self.request,
            operation: action.operation,
            operation_id: action.operation_id,
            action_digest: action_digest(action).map_err(|_| Error::Input)?,
            room: match action.target {
                Target::Room(room) => Some(room),
                _ => None,
            },
            outcome: None,
        });
        if self.snapshot.deliveries.len() > 320 {
            self.snapshot.deliveries.remove(0);
        }
        Ok(())
    }
    fn clear_matching_draft(&mut self, action: &Action) -> Result<()> {
        if !matches!(
            action.operation,
            Operation::MessageSend | Operation::MessageReply | Operation::MessageAction
        ) {
            return Ok(());
        }
        let Target::Room(room) = action.target else {
            return Err(Error::Input);
        };
        let message = self.client.own_plaintext(action)?;
        if super::outbox::clear_sent_draft(&mut self.client.store, action)
            .map_err(|_| Error::Storage)?
            && let Some(view) = &mut self.snapshot.selected
            && view.summary.room == room
            && view.draft == message.text
            && view.draft_mentions == message.mentions
        {
            view.draft.clear();
            view.draft_mentions.clear();
        }
        Ok(())
    }
    fn response(&mut self, r: Response) -> Result<Value> {
        self.snapshot
            .deliveries
            .retain(|d| d.operation_id != r.operation_id);
        self.snapshot.deliveries.push(Delivery {
            abandoned: false,
            held: false,
            request_id: self.request,
            operation: self.operation.unwrap_or(Operation::OperationResolve),
            operation_id: r.operation_id,
            action_digest: r.action_digest,
            room: self.delivery_room,
            outcome: Some(r.outcome.clone()),
        });
        if self.snapshot.deliveries.len() > 320 {
            self.snapshot.deliveries.remove(0);
        }
        match r.outcome {
            Outcome::Committed { body, .. } | Outcome::Result { body } => {
                self.snapshot.status = Some(Status {
                    request_id: self.request,
                    code: "Completed".into(),
                    detail: "The service confirmed this operation.".into(),
                });
                Ok(body)
            }
            outcome => Err(Error::from_outcome(outcome)),
        }
    }
    fn read<T: serde::de::DeserializeOwned, B: serde::Serialize>(
        &mut self,
        op: Operation,
        target: Target,
        body: &B,
    ) -> Result<T> {
        let end = crate::clock::boot_ms()
            .map_err(|_| Error::Clock)?
            .saturating_add(10_000);
        self.read_until(op, target, body, end)
    }
    fn read_until<T: serde::de::DeserializeOwned, B: serde::Serialize>(
        &mut self,
        op: Operation,
        target: Target,
        body: &B,
        end: u64,
    ) -> Result<T> {
        if !home::is_read_operation(op) {
            return Err(Error::Input);
        }
        let action = self.client.prepare(
            op,
            target,
            Value::serialized(body).map_err(|_| Error::Input)?,
        )?;
        let signed = self.client.sign(&action)?;
        let key =
            VerifyingKey::from_bytes(self.client.profile.registration.endpoint_key.as_bytes())
                .map_err(|_| Error::Input)?;
        let shared = Arc::clone(&self.shared);
        let r = retry_read(
            end,
            || shared.stop.load(Ordering::Acquire) || shared.disconnect.load(Ordering::Acquire),
            |end| {
                let response = self
                    .client
                    .session()?
                    .submit_read_until(&signed, &key, end)
                    .map(|response| response.value().clone())
                    .map_err(Error::from)?;
                self.observe_read(&response);
                Ok(response)
            },
        )?;
        match r.outcome {
            Outcome::Result { body } => body.deserialized().map_err(|_| Error::Input),
            outcome => Err(Error::from_outcome(outcome)),
        }
    }
    fn observe_read(&mut self, response: &Response) {
        if matches!(
            response.outcome,
            Outcome::Refused {
                code: ErrorCode::Unavailable | ErrorCode::Overloaded | ErrorCode::RateLimited,
                ..
            }
        ) {
            // Publish loss of current read evidence before any same-action retry wait.
            self.stale();
            self.publish();
        }
    }
    fn effect<B: serde::Serialize>(
        &mut self,
        op: Operation,
        target: Target,
        body: &B,
    ) -> Result<Value> {
        self.operation = Some(op);
        self.delivery_room = match target {
            Target::Room(room) => Some(room),
            _ => None,
        };
        let action = self.client.prepare(
            op,
            target,
            Value::serialized(body).map_err(|_| Error::Input)?,
        )?;
        self.remember(&action)?;
        let response = self.client.execute(&action)?;
        self.response(response)
    }
}

/// A verified temporary read refusal leaves this stream synchronized. Earlier
/// refresh results remain available while only this exact read is attempted again.
fn retry_read(
    end: u64,
    interrupted: impl Fn() -> bool,
    mut attempt: impl FnMut(u64) -> Result<Response>,
) -> Result<Response> {
    for number in 0..5 {
        if interrupted() {
            return Err(Error::Offline);
        }
        if crate::clock::boot_ms().map_err(|_| Error::Clock)? >= end {
            return Err(Error::Network(super::network::Error::Transport));
        }
        let response = attempt(end)?;
        if crate::clock::boot_ms().map_err(|_| Error::Clock)? >= end {
            return Err(Error::Network(super::network::Error::Transport));
        }
        let Outcome::Refused {
            code: ErrorCode::Unavailable | ErrorCode::Overloaded | ErrorCode::RateLimited,
            retry_after_ms,
            ..
        } = &response.outcome
        else {
            return Ok(response);
        };
        let now = crate::clock::boot_ms().map_err(|_| Error::Clock)?;
        let delay = retry_after_ms.unwrap_or(1000).max(250);
        let Some(until) = now.checked_add(delay).filter(|until| *until < end) else {
            return Ok(response);
        };
        if number == 4 {
            return Ok(response);
        }
        loop {
            if interrupted() {
                return Err(Error::Offline);
            }
            let now = crate::clock::boot_ms().map_err(|_| Error::Clock)?;
            if now >= until {
                break;
            }
            thread::sleep(Duration::from_millis((until - now).min(25)));
        }
    }
    unreachable!("read attempt count is bounded")
}

#[path = "Commands.rs"]
mod commands;
#[path = "Synchronise.rs"]
mod synchronise;

#[cfg(test)]
#[path = "../../Tests/Client/Completion.rs"]
mod completion_tests;
