// SPDX-License-Identifier: Apache-2.0
//! High-level participant methods preserve native authority, event context and exact retries.
use super::{
    API_VERSION, Error, REQUEST_BYTES, Result,
    configuration::{Binding, Configuration, Credential},
    state,
};
use crate::{
    client::{self, Client},
    conversations, home, messaging,
    protocol::*,
};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value as Json, json};
use std::{
    path::{Path, PathBuf},
    time::{Duration, Instant},
};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    jsonrpc: String,
    id: Json,
    method: String,
    #[serde(default)]
    params: Json,
    auth: Credential,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Open {
    consumer: String,
    room: RoomId,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Consumer {
    consumer: String,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Acknowledge {
    consumer: String,
    batch: Id,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct History {
    room: RoomId,
    #[serde(default)]
    cursor: Option<Blob>,
    #[serde(default = "limit")]
    limit: u16,
}
fn limit() -> u16 {
    32
}
#[derive(Deserialize, serde::Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Send {
    client_request_id: u64,
    room: RoomId,
    text: String,
    #[serde(default)]
    consumer: Option<String>,
    #[serde(default)]
    batch: Option<Id>,
    #[serde(default)]
    trigger: Option<Id>,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Status {
    client_request_id: u64,
}
fn parameters<T: DeserializeOwned>(v: Json) -> Result<T> {
    serde_json::from_value(if v.is_null() { json!({}) } else { v }).map_err(|_| Error::Invalid)
}
fn display<T: serde::Serialize>(v: &T) -> Result<Json> {
    client::json::value(v).map_err(|_| Error::State)
}
pub(super) fn parse(bytes: &[u8]) -> Result<Request> {
    if bytes.len() > REQUEST_BYTES {
        return Err(Error::InvalidRpc);
    }
    let raw: Value = serde_json::from_slice(bytes).map_err(|_| Error::Parse)?;
    canonical_encode(&raw, REQUEST_BYTES).map_err(|_| Error::InvalidRpc)?;
    let r: Request = serde_json::from_slice(bytes).map_err(|_| Error::InvalidRpc)?;
    if r.jsonrpc != "2.0"
        || !(r.id.is_string() || r.id.as_u64().is_some())
        || r.id.as_str().is_some_and(|s| s.len() > 128)
        || r.method.len() > 64
    {
        return Err(Error::InvalidRpc);
    }
    Ok(r)
}
pub(super) struct Broker {
    client: Client,
    configuration: PathBuf,
    profile: PathBuf,
    account: AccountId,
    endpoint: Id,
    next_connect: Instant,
    attempt: u32,
    last_error: Option<&'static str>,
}
impl Broker {
    pub(super) fn open(path: &Path) -> Result<Self> {
        let c = Configuration::load(path)?;
        let client = Client::open_offline(&c.profile)?;
        if !matches!(
            client.profile.registration.classification,
            AccountClass::Agent { .. }
        ) {
            return Err(Error::AgentRequired);
        }
        if client.profile.registration.account != c.account
            || client.profile.registration.endpoint != c.endpoint
        {
            return Err(Error::Denied);
        }
        let mut value = Self {
            client,
            configuration: path.to_owned(),
            profile: c.profile,
            account: c.account,
            endpoint: c.endpoint,
            next_connect: Instant::now(),
            attempt: 0,
            last_error: None,
        };
        state::initialise(&mut value.client.store)?;
        Ok(value)
    }
    pub(super) fn tick(&mut self) {
        if self.client.session().is_ok() || Instant::now() < self.next_connect {
            return;
        }
        match self.client.connect() {
            Ok(()) => {
                self.attempt = 0;
                self.last_error = None;
            }
            Err(e) => {
                self.last_error = Some(e.code());
                self.client.disconnect();
                self.attempt = (self.attempt + 1).min(6);
                self.next_connect =
                    Instant::now() + Duration::from_secs((1u64 << self.attempt).min(60));
            }
        }
    }
    fn online(&mut self) -> Result<()> {
        self.tick();
        self.client.session()?;
        Ok(())
    }
    fn current(&self, key: &Credential) -> Result<Binding> {
        let c = Configuration::load(&self.configuration)?;
        if c.account != self.account || c.endpoint != self.endpoint || c.profile != self.profile {
            return Err(Error::Denied);
        }
        c.authenticate(key)
    }
    pub(super) fn handle(&mut self, bytes: &[u8]) -> Json {
        let r = match parse(bytes) {
            Ok(r) => r,
            Err(e) => return e.response(Json::Null),
        };
        let result = self
            .current(&r.auth)
            .and_then(|b| self.call(&b, &r.method, r.params));
        match result {
            Ok(value) => json!({"jsonrpc":"2.0","id":r.id,"result":value}),
            Err(e) => {
                if let Error::Client(ref error) = e {
                    self.last_error = Some(error.code());
                    if error.retry_delay_ms().is_some() && !error.can_reuse_session() {
                        self.client.disconnect();
                        self.next_connect = Instant::now()
                            + Duration::from_millis(
                                error.retry_delay_ms().unwrap_or(1000).max(1000),
                            );
                    }
                }
                e.response(r.id)
            }
        }
    }
    fn room(&self, b: &Binding, room: RoomId) -> Result<()> {
        if !b.scope.rooms.contains(&room) || room.home != self.client.profile.active_server().home {
            return Err(Error::Denied);
        }
        Ok(())
    }
    fn consumer(&mut self, b: &Binding, name: &str) -> Result<state::Consumer> {
        let c = state::consumer(&mut self.client.store, b.id, name)?.ok_or(Error::Invalid)?;
        self.room(b, c.room)?;
        Ok(c)
    }
    fn call(&mut self, b: &Binding, method: &str, params: Json) -> Result<Json> {
        let paused = state::paused(&mut self.client.store, b.id)?;
        if paused
            && !matches!(
                method,
                "api.describe" | "status" | "pause" | "resume" | "operations.status"
            )
        {
            return Err(Error::Denied);
        }
        match method {
            "api.describe" => {
                let _: Empty = parameters(params)?;
                Ok(
                    json!({"apiVersion":API_VERSION,"hrcVersion":env!("CARGO_PKG_VERSION"),"delivery":"atLeastOnce","requestBytes":REQUEST_BYTES,"eventLimit":32,"consumerLimit":32,"retainedRequests":4096,"requestRetentionDays":7,"methods":["status","rooms.list","history.page","events.open","events.next","events.ack","events.resynchronise","messages.send","messages.reply","operations.status","pause","resume"]}),
                )
            }
            "status" => {
                let _: Empty = parameters(params)?;
                Ok(
                    json!({"account":self.account,"endpoint":self.endpoint,"classification":self.client.profile.registration.classification,"connected":self.client.session().is_ok(),"paused":paused,"lastError":self.last_error,"scope":b.scope,"nextClientRequestId":state::watermark(&mut self.client.store,b.id)?.saturating_add(1)}),
                )
            }
            "pause" => {
                let _: Empty = parameters(params)?;
                state::pause(&mut self.client.store, b.id, true)?;
                Ok(json!({"paused":true}))
            }
            "resume" => {
                let _: Empty = parameters(params)?;
                state::pause(&mut self.client.store, b.id, false)?;
                self.next_connect = Instant::now();
                Ok(json!({"paused":false}))
            }
            "rooms.list" => {
                let _: Empty = parameters(params)?;
                self.online()?;
                let mut rooms = Vec::new();
                for room in &b.scope.rooms {
                    self.room(b, *room)?;
                    let v: conversations::Inspection = self.client.read_as(
                        Operation::RoomInspect,
                        Target::Room(*room),
                        &home::Empty {},
                        None,
                    )?;
                    rooms.push(json!({"room":room,"inspection":v}));
                }
                Ok(json!({"rooms":rooms}))
            }
            "history.page" => {
                let p: History = parameters(params)?;
                self.room(b, p.room)?;
                if !b.scope.history || p.limit == 0 || p.limit > 32 {
                    return Err(Error::Denied);
                }
                self.online()?;
                display(&self.client.history_messages(
                    p.room,
                    &messaging::Page {
                        cursor: p.cursor,
                        limit: p.limit,
                    },
                    None,
                )?)
            }
            "events.open" => {
                let p: Open = parameters(params)?;
                self.room(b, p.room)?;
                self.online()?;
                let _: conversations::Inspection = self.client.read_as(
                    Operation::RoomInspect,
                    Target::Room(p.room),
                    &home::Empty {},
                    None,
                )?;
                state::open(&mut self.client.store, b.id, &p.consumer, p.room)?;
                let consumer = self.consumer(b, &p.consumer)?;
                if consumer.cursor.is_none() && consumer.batch.is_none() {
                    // Subscription starts at the current head; history is a separate permission.
                    let page = self.client.history_tail(p.room, 1, None)?;
                    self.cursor(p.room, &page.cursor)?;
                    state::start(&mut self.client.store, b.id, &p.consumer, &page.cursor)?;
                }
                Ok(json!({"consumer":p.consumer,"room":p.room}))
            }
            "events.next" => {
                let p: Consumer = parameters(params)?;
                self.next(b, &p.consumer)
            }
            "events.ack" => {
                let p: Acknowledge = parameters(params)?;
                self.consumer(b, &p.consumer)?;
                state::acknowledge(&mut self.client.store, b.id, &p.consumer, p.batch)?;
                Ok(json!({"acknowledged":p.batch}))
            }
            "events.resynchronise" => {
                let p: Consumer = parameters(params)?;
                let c = self.consumer(b, &p.consumer)?;
                self.client.resynchronise_history(c.room)?;
                state::resynchronise(&mut self.client.store, b.id, &p.consumer)?;
                Ok(json!({"resynchronising":true,"historicalTriggers":false}))
            }
            "messages.send" | "messages.reply" => self.send(b, method, parameters(params)?),
            "operations.status" => {
                let p: Status = parameters(params)?;
                self.operation(b, p.client_request_id)
            }
            _ => Err(Error::Method),
        }
    }
    fn next(&mut self, b: &Binding, name: &str) -> Result<Json> {
        let c = self.consumer(b, name)?;
        self.online()?;
        if let Some(batch) = c.batch {
            // Fresh cursor validation fences changed membership, filters and retention.
            self.client.history_messages(
                c.room,
                &messaging::Page {
                    cursor: Some(batch.cursor.clone()),
                    limit: 1,
                },
                None,
            )?;
            return display(&batch);
        }
        let mut page = if c.cursor.is_none() {
            self.client.history_tail(c.room, 32, None)?
        } else {
            self.client.history_messages(
                c.room,
                &messaging::Page {
                    cursor: c.cursor,
                    limit: 32,
                },
                None,
            )?
        };
        let cursor = self.cursor(c.room, &page.cursor)?;
        if !c.live && !b.scope.history {
            page.events.clear();
            page.content.clear();
        }
        let batch = state::Batch {
            id: Id::random().map_err(|_| Error::State)?,
            room: c.room,
            events: page.events,
            content: page.content.into_iter().collect(),
            cursor: page.cursor.clone(),
            historical: !c.live,
            has_more: page.has_more,
            room_revision: page.room_revision,
            filter_revision: cursor.filter_revision,
            expires_ms: cursor.expires_ms,
        };
        state::batch(&mut self.client.store, b.id, name, &batch)?;
        display(&batch)
    }
    fn cursor(&self, room: RoomId, bytes: &Blob) -> Result<HistoryCursor> {
        let key =
            VerifyingKey::from_bytes(self.client.profile.active_server().signing_key.as_bytes())
                .map_err(|_| Error::State)?;
        let cursor = verify_cursor(&bytes.0, &key).map_err(|_| Error::State)?;
        let now = self
            .client
            .profile
            .clock
            .sample()
            .map_err(|_| client::Error::Clock)?;
        if cursor.value().account != self.account
            || cursor.value().room != room
            || now.upper_ms >= cursor.value().expires_ms
        {
            return Err(Error::ResynchronisationRequired);
        }
        Ok(cursor.value().clone())
    }
    fn operation(&mut self, b: &Binding, id: u64) -> Result<Json> {
        let Some(mut saved) = state::lookup(&mut self.client.store, b.id, id)? else {
            return if id <= state::watermark(&mut self.client.store, b.id)? {
                Err(Error::Retired)
            } else {
                Err(Error::Invalid)
            };
        };
        if saved.outcome.is_none() {
            if let Ok(Some(outcome)) =
                client::outbox::outcome(&mut self.client.store, saved.operation, saved.digest)
            {
                state::complete(&mut self.client.store, b.id, id, &outcome)?;
                saved.outcome = Some(outcome);
            } else if !state::paused(&mut self.client.store, b.id)? && self.online().is_ok() {
                let result = self.client.retry_pending(saved.operation, saved.digest);
                if let Err(e) = result {
                    self.last_error = Some(e.code());
                    if e.retry_delay_ms().is_some() {
                        self.client.disconnect();
                    }
                }
                if let Ok(Some(outcome)) =
                    client::outbox::outcome(&mut self.client.store, saved.operation, saved.digest)
                {
                    state::complete(&mut self.client.store, b.id, id, &outcome)?;
                    saved.outcome = Some(outcome);
                }
            }
        }
        Ok(
            json!({"clientRequestId":id,"operation":saved.operation,"digest":saved.digest,"status":if saved.outcome.is_some(){"terminal"}else{"unknown"},"outcome":saved.outcome.map(|o|display(&o)).transpose()?}),
        )
    }
    fn send(&mut self, b: &Binding, method: &str, p: Send) -> Result<Json> {
        self.room(b, p.room)?;
        let payload = digest(&serde_json::to_vec(&(method, &p)).map_err(|_| Error::Invalid)?);
        if let Some(saved) = state::lookup(&mut self.client.store, b.id, p.client_request_id)? {
            if saved.payload != payload {
                return Err(Error::Conflict);
            }
            return self.operation(b, p.client_request_id);
        }
        let watermark = state::watermark(&mut self.client.store, b.id)?;
        if p.client_request_id <= watermark {
            return Err(Error::Retired);
        }
        if p.client_request_id != watermark + 1
            || p.client_request_id > 9_007_199_254_740_991
            || crate::text::message(&p.text).is_err()
        {
            return Err(Error::Invalid);
        }
        let guard = if method == "messages.reply" {
            let n = p.consumer.as_deref().ok_or(Error::Invalid)?;
            let c = self.consumer(b, n)?;
            let batch = c.batch.ok_or(Error::Conflict)?;
            if batch.room != p.room || Some(batch.id) != p.batch || batch.historical {
                return Err(Error::Denied);
            }
            let trigger = batch
                .events
                .iter()
                .find(|e| Some(e.event) == p.trigger)
                .ok_or(Error::Invalid)?;
            if !matches!(
                trigger.kind,
                Operation::MessageSend | Operation::MessageReply | Operation::MessageAction
            ) || trigger.actor.acting().account == self.account
                || (!b.scope.agent_replies && !matches!(trigger.actor, Actor::Direct { .. }))
            {
                return Err(Error::Denied);
            }
            let now = self
                .client
                .profile
                .clock
                .sample()
                .map_err(|_| client::Error::Clock)?;
            if now.upper_ms >= batch.expires_ms {
                return Err(Error::ResynchronisationRequired);
            }
            Some(client::SendGuard {
                room_revision: batch.room_revision,
                filter_revision: batch.filter_revision,
            })
        } else {
            if !b.scope.initiate || p.consumer.is_some() || p.batch.is_some() || p.trigger.is_some()
            {
                return Err(Error::Denied);
            }
            None
        };
        self.online()?;
        let now = self
            .client
            .profile
            .clock
            .sample()
            .map_err(|_| client::Error::Clock)?;
        state::maintain(&mut self.client.store, now.lower_ms)?;
        let expires = self.client.session()?.ready.window.expires_ms;
        let message = messaging::Send {
            text: p.text.clone(),
            mentions: Vec::new(),
            parent: p.trigger,
            causation: p.trigger,
        };
        let finalize = |tx: &rusqlite::Transaction<'_>, action: &VerifiedAction| {
            state::prepare(
                tx,
                b.id,
                p.client_request_id,
                payload,
                action,
                expires,
                p.consumer.as_deref().zip(p.trigger),
            )
        };
        let prepared = if let Some(guard) = guard {
            self.client
                .prepare_send_guarded_with(p.room, &message, None, guard, finalize)?
        } else {
            self.client
                .prepare_send_with(p.room, &message, None, false, None, finalize)?
        };
        // The mapping and signed outbox already exist before any network publication.
        if let Err(e) = self.client.execute_signed(&prepared.signed) {
            self.last_error = Some(e.code());
            if e.retry_delay_ms().is_some() {
                self.client.disconnect();
            }
        }
        self.operation(b, p.client_request_id)
    }
}
