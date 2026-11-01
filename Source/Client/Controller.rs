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
}
pub struct Controller {
    shared: Arc<Shared>,
    sender: SyncSender<(u64, Command)>,
    worker: Option<thread::JoinHandle<()>>,
    next_request: AtomicU64,
}
impl Controller {
    pub fn open(path: &Path) -> Result<Self> {
        let mut client = Client::open_offline(path)?;
        let preferences =
            cache::preferences(&mut client.store, "global").map_err(|_| Error::Storage)?;
        if !cache::validate_preferences(&preferences) {
            return Err(Error::Storage);
        }
        let rooms = cache::rooms(&mut client.store).map_err(|_| Error::Storage)?;
        let filters = cache::filters(&mut client.store).map_err(|_| Error::Storage)?;
        let snapshot = Snapshot {
            revision: 0,
            account: client.profile.registration.account,
            home: client.profile.server.home,
            classification: client.profile.registration.classification.clone(),
            nickname: String::new(),
            motd: String::new(),
            connection: ConnectionState::Offline,
            privacy: None,
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
        });
        let (sender, receiver) = mpsc::sync_channel(32);
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
                while !w.shared.stop.load(Ordering::Acquire) {
                    if w.shared.disconnect.swap(false, Ordering::AcqRel) {
                        w.offline();
                    }
                    match receiver.recv_timeout(Duration::from_millis(100)) {
                        Ok((id, command)) => {
                            w.request = Some(id);
                            let search =
                                matches!(command, Command::Search(_) | Command::NextSearchPage);
                            let result = w.command(command);
                            if search {
                                w.shared.search_pending.store(false, Ordering::Release);
                            }
                            w.snapshot.completions.push(Completion {
                                request_id: id,
                                error: result.as_ref().err().map(|e| Status {
                                    request_id: Some(id),
                                    code: e.code().into(),
                                    detail: e.to_string(),
                                }),
                            });
                            if w.snapshot.completions.len() > 64 {
                                w.snapshot.completions.remove(0);
                            }
                            if let Err(e) = result {
                                w.error(e);
                            }
                            w.publish();
                            w.request = None;
                            w.operation = None;
                            w.delivery_room = None;
                        }
                        Err(mpsc::RecvTimeoutError::Disconnected) => break,
                        Err(mpsc::RecvTimeoutError::Timeout) => {
                            if w.desired && w.client.session().is_err() && Instant::now() >= w.retry
                            {
                                if let Err(e) = w.connect() {
                                    w.error(e);
                                }
                                w.publish();
                            } else if w.client.session().is_ok()
                                && w.poll.elapsed() >= Duration::from_secs(5)
                            {
                                w.poll = Instant::now();
                                if let Err(e) = w.refresh() {
                                    w.error(e);
                                }
                                w.publish();
                            }
                        }
                    }
                }
                w.client.disconnect();
            })
            .map_err(|_| Error::Configuration)?;
        Ok(Self {
            shared,
            sender,
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
        let id = self.next_request.fetch_add(1, Ordering::Relaxed);
        let search = matches!(command, Command::Search(_) | Command::NextSearchPage);
        match command {
            Command::Disconnect => {
                self.disconnect();
                return Ok(id);
            }
            Command::CancelSearch => {
                self.shared.cancel.store(true, Ordering::Release);
                return Ok(id);
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
        match self.sender.try_send((id, command)) {
            Ok(()) => Ok(id),
            Err(error) => {
                if search {
                    self.shared.search_pending.store(false, Ordering::Release);
                }
                Err(match error {
                    TrySendError::Full(_) => DispatchError::QueueFull,
                    TrySendError::Disconnected(_) => DispatchError::Stopped,
                })
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
        self.shared.stop.store(true, Ordering::Release);
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
    fn publish(&mut self) {
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
    }
    fn offline(&mut self) {
        self.desired = false;
        self.client.disconnect();
        self.stale();
        self.snapshot.connection = ConnectionState::Offline;
        self.caught_up.clear();
        *self.shared.stream.lock().unwrap_or_else(|e| e.into_inner()) = None;
    }
    fn error(&mut self, e: Error) {
        self.snapshot.status = Some(Status {
            request_id: self.request,
            code: e.code().into(),
            detail: e.to_string(),
        });
        let retry = e.retry_delay_ms();
        if retry.is_some() || matches!(e, Error::Network(_) | Error::Refused { .. }) {
            self.client.disconnect();
            self.stale();
            self.caught_up.clear();
            *self.shared.stream.lock().unwrap_or_else(|e| e.into_inner()) = None;
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
        self.desired = true;
        self.snapshot.connection = ConnectionState::Connecting;
        self.publish();
        self.client.connect()?;
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
        if self.client.draft(room)?.as_deref() == Some(message.text.as_str())
            && self.client.draft_mentions(room)? == message.mentions
        {
            self.client.save_draft(room, "")?;
            if let Some(view) = &mut self.snapshot.selected
                && view.summary.room == room
                && view.draft == message.text
                && view.draft_mentions == message.mentions
            {
                view.draft.clear();
                view.draft_mentions.clear();
            }
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
        let r = self.client.call(op, target, body)?;
        match r.outcome {
            Outcome::Result { body } => body.deserialized().map_err(|_| Error::Input),
            outcome => Err(Error::from_outcome(outcome)),
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

#[path = "Commands.rs"]
mod commands;
#[path = "Synchronise.rs"]
mod synchronise;
