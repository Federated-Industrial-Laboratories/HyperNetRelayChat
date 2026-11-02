// SPDX-License-Identifier: Apache-2.0
//! Current filtered pulls feed one fixed help rule; durable plans survive interrupted submission.
use super::{Config, Error, Result, state};
use crate::{
    client::{self, Client, outbox},
    delegation, home, messaging,
    protocol::*,
};
use std::{
    collections::BTreeSet,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

pub(super) fn run(config: Config, stop: Arc<AtomicBool>, on_ready: impl FnOnce()) -> Result<()> {
    let mut client = Client::open_offline(&config.profile)?;
    let AccountClass::Agent { operator } = client.profile.registration.classification else {
        return Err(Error::AgentRequired);
    };
    if config
        .rooms
        .iter()
        .any(|r| r.home != client.profile.server.home)
    {
        return Err(Error::Configuration);
    }
    state::initialise(&mut client.store, &config)?;
    settle_local(&mut client)?;
    let mut room_index = 0;
    let mut failures = 0u8;
    let mut startup = Startup::new(config.rooms.clone(), on_ready);

    while !stop.load(Ordering::Acquire) {
        let step = (|| -> Result<()> {
            let now = client
                .profile
                .clock
                .sample()
                .map_err(|_| client::Error::Clock)?;
            if client.session().is_ok_and(|session| {
                now.upper_ms.saturating_add(300000) >= session.ready.window.expires_ms
            }) {
                // Fresh session setup may issue a new window; stored effects keep their original identity.
                client.disconnect();
            }
            if client.session().is_err() {
                client.connect()?;
                startup.connected();
                let ready = &client.session()?.ready;
                if ready.classification != (AccountClass::Agent { operator }) {
                    return Err(Error::AgentRequired);
                }
            }
            settle_local(&mut client)?;
            if stop.load(Ordering::Acquire) {
                return Ok(());
            }
            resolve_plan(&mut client, &config, &stop)?;
            let now = client
                .profile
                .clock
                .sample()
                .map_err(|_| client::Error::Clock)?;
            if state::presence_due(&mut client.store, now.lower_ms)? {
                let owner = client.profile.registration.account;
                let action = client.prepare(
                    Operation::PresenceSet,
                    Target::Account(owner),
                    Value::serialized(&crate::identity::Presence {
                        status: "Service bot: !help".into(),
                        duration_ms: 60000,
                    })
                    .map_err(|_| Error::State)?,
                )?;
                let bytes = client.sign(&action)?;
                let key =
                    VerifyingKey::from_bytes(client.profile.registration.endpoint_key.as_bytes())
                        .map_err(|_| Error::State)?;
                let verified = verify_action(&bytes, &key).map_err(|_| Error::State)?;
                let window = client.session()?.ready.window.clone();
                state::presence(&mut client.store, &verified, &window, now)?;
                resolve_plan(&mut client, &config, &stop)?;
            }
            let actor = actor(&mut client, config.grant)?;
            let room = config.rooms[room_index % config.rooms.len()];
            room_index = room_index.wrapping_add(1);
            let at_head = pull(&mut client, &config, room, actor, &stop)?;
            if !stop.load(Ordering::Acquire) {
                resolve_plan(&mut client, &config, &stop)?;
                startup.observe(
                    &mut client.store,
                    room,
                    at_head,
                    stop.load(Ordering::Acquire),
                )?;
            }
            Ok(())
        })();
        match step {
            Ok(()) => {
                failures = 0;
                wait(&stop, Duration::from_millis(config.poll_interval_ms));
            }
            Err(error) if retry_delay(&error).is_some() => {
                client.disconnect();
                failures = failures.saturating_add(1);
                let mut jitter = [0u8; 1];
                getrandom::fill(&mut jitter).map_err(|_| Error::State)?;
                wait(
                    &stop,
                    Duration::from_millis(
                        ((1000u64 << failures.min(5)).min(30000) + u64::from(jitter[0]) * 4)
                            .max(retry_delay(&error).unwrap_or(0)),
                    ),
                );
            }
            Err(error) => {
                client.disconnect();
                return Err(error);
            }
        }
    }
    client.disconnect();
    Ok(())
}
/// Readiness belongs to one initial connection's authenticated pulls, never to retained cache flags.
pub(super) struct Startup<F> {
    rooms: Vec<RoomId>,
    reached: BTreeSet<RoomId>,
    notify: Option<F>,
}
impl<F: FnOnce()> Startup<F> {
    pub(super) fn new(rooms: Vec<RoomId>, notify: F) -> Self {
        Self {
            rooms,
            reached: BTreeSet::new(),
            notify: Some(notify),
        }
    }
    pub(super) fn connected(&mut self) {
        self.reached.clear();
    }
    pub(super) fn observe(
        &mut self,
        store: &mut crate::storage::Store,
        room: RoomId,
        at_head: bool,
        stopped: bool,
    ) -> Result<()> {
        if self.notify.is_none() {
            return Ok(());
        }
        if !self.rooms.contains(&room) {
            return Err(Error::State);
        }
        if at_head {
            self.reached.insert(room);
        } else {
            self.reached.remove(&room);
        }
        if !stopped
            && self.reached.len() == self.rooms.len()
            && state::plans(store)?.is_empty()
            && let Some(notify) = self.notify.take()
        {
            notify();
        }
        Ok(())
    }
}
pub(super) fn retry_delay(error: &Error) -> Option<u64> {
    match error {
        Error::Client(client::Error::Clock) => Some(0),
        Error::Client(client::Error::Network(error)) if error.retryable_session() => Some(0),
        Error::RetryLater { delay_ms } => Some((*delay_ms).min(60000)),
        _ => None,
    }
}
fn refusal(outcome: &Outcome) -> Option<Error> {
    if let Outcome::Refused {
        code: ErrorCode::Unavailable | ErrorCode::RateLimited | ErrorCode::Overloaded,
        retry_after_ms,
        ..
    } = outcome
    {
        Some(Error::RetryLater {
            delay_ms: retry_after_ms.unwrap_or(1000).min(60000),
        })
    } else {
        None
    }
}
fn wait(stop: &AtomicBool, duration: Duration) {
    let end = Instant::now() + duration;
    while !stop.load(Ordering::Acquire) && Instant::now() < end {
        thread::sleep(
            end.saturating_duration_since(Instant::now())
                .min(Duration::from_millis(100)),
        );
    }
}
fn accepted(response: Response) -> Result<Value> {
    if let Some(error) = refusal(&response.outcome) {
        return Err(error);
    }
    match response.outcome {
        Outcome::Committed { body, .. } | Outcome::Result { body } => Ok(body),
        Outcome::Rejected {
            code: ErrorCode::ResynchronisationRequired,
            ..
        }
        | Outcome::Refused {
            code: ErrorCode::ResynchronisationRequired,
            ..
        } => Err(Error::ResynchronisationRequired),
        Outcome::Rejected { .. } | Outcome::Refused { .. } => Err(Error::Denied),
        _ => Err(Error::PendingOutcome),
    }
}
fn actor(client: &mut Client, grant: Option<Id>) -> Result<Actor> {
    let base = client
        .prepare(Operation::HistoryPage, Target::Service, Value::Null)?
        .actor;
    let Some(id) = grant else {
        return Ok(base);
    };
    let mut after = None;
    for _ in 0..32 {
        let response = client.call(
            Operation::DelegationList,
            Target::Account(client.profile.registration.account),
            &home::InspectPage {
                after: after.clone(),
                limit: 16,
            },
        )?;
        let page: home::InspectionPage<delegation::Grant> = accepted(response)?
            .deserialized()
            .map_err(|_| Error::State)?;
        if let Some(grant) = page.items.into_iter().find(|g| g.reference.id == id) {
            if grant.scope.agent != client.session()?.ready.acting
                || grant.scope.mode != delegation::Mode::Autonomous
            {
                return Err(Error::Grant);
            }
            return Ok(Actor::Delegated {
                acting: grant.scope.agent,
                operator: grant.operator,
                represented: grant.owner,
                represented_security_generation: grant.owner_security_generation,
                grant: grant.reference,
            });
        }
        if page.next.is_none() {
            return Err(Error::Grant);
        }
        if page.next == after {
            return Err(Error::State);
        }
        after = page.next;
    }
    Err(Error::Grant)
}
/// Only a direct account's original message can trigger; replies and all agent actors are excluded.
pub(super) fn trigger(event: &Event) -> bool {
    if event.kind != Operation::MessageSend || !matches!(event.actor, Actor::Direct { .. }) {
        return false;
    }
    let Ok(body) = event.body.deserialized::<messaging::Send>() else {
        return false;
    };
    body.parent.is_none() && body.causation.is_none() && body.text.trim() == "!help"
}
fn pull(
    client: &mut Client,
    config: &Config,
    room: RoomId,
    actor: Actor,
    stop: &AtomicBool,
) -> Result<bool> {
    let prior = state::room(&mut client.store, room)?;
    let mut request = client.prepare(
        Operation::HistoryPage,
        Target::Room(room),
        Value::serialized(&messaging::Page {
            cursor: prior.cursor.clone(),
            limit: 32,
        })
        .map_err(|_| Error::State)?,
    )?;
    request.actor = actor.clone();
    let response = client.execute(&request)?;
    let page: messaging::PageResult = accepted(response)?
        .deserialized()
        .map_err(|_| Error::State)?;
    let key = VerifyingKey::from_bytes(client.profile.server.signing_key.as_bytes())
        .map_err(|_| Error::State)?;
    let cursor = verify_cursor(&page.cursor.0, &key).map_err(|_| Error::State)?;
    let now = client
        .profile
        .clock
        .sample()
        .map_err(|_| client::Error::Clock)?;
    if cursor.value().room != room
        || cursor.value().home != client.profile.server.home
        || cursor.value().account != actor.represented()
        || now.upper_ms >= cursor.value().expires_ms
        || page.events.len() > 32
    {
        return Err(Error::State);
    }
    let mut previous = 0;
    for event in &page.events {
        if event.room != room
            || event.home != room.home
            || event.sequence <= previous
            || event.sequence > cursor.value().sequence
        {
            return Err(Error::State);
        }
        previous = event.sequence;
    }
    if let Some(old) = &prior.cursor {
        let old = verify_cursor(&old.0, &key).map_err(|_| Error::State)?;
        if old.value().sequence > cursor.value().sequence
            || old.value().access_digest != cursor.value().access_digest
        {
            return Err(Error::ResynchronisationRequired);
        }
    }
    if stop.load(Ordering::Acquire) {
        return Ok(false);
    }
    let mut reply = None;
    if prior.live
        && now.lower_ms >= state::next_reply(&mut client.store)?
        && let Some(event) = page.events.iter().find(|e| trigger(e))
    {
        let mut action = client.prepare(
            Operation::MessageReply,
            Target::Room(room),
            Value::serialized(&messaging::Send {
                text: config.help.clone(),
                mentions: vec![],
                parent: Some(event.event),
                causation: Some(event.event),
            })
            .map_err(|_| Error::State)?,
        )?;
        action.actor = actor;
        action.expected.insert(Revision::Room, page.room_revision);
        action
            .expected
            .insert(Revision::Filter, cursor.value().filter_revision);
        let bytes = client.sign(&action)?;
        let signer = VerifyingKey::from_bytes(client.profile.registration.endpoint_key.as_bytes())
            .map_err(|_| Error::State)?;
        reply = Some((
            verify_action(&bytes, &signer).map_err(|_| Error::State)?,
            event.event,
        ));
    }
    let window = client.session()?.ready.window.clone();
    state::advance(
        &mut client.store,
        state::Advance {
            room,
            prior: prior.cursor.as_ref(),
            cursor: &page.cursor,
            live: prior.live || !page.has_more,
            reply: reply.as_ref().map(|(r, event)| (r, *event)),
            window: &window,
            now,
        },
    )?;
    Ok(!page.has_more)
}
fn settle_local(client: &mut Client) -> Result<()> {
    let plans = state::plans(&mut client.store)?;
    if plans.len() > 1 {
        return Err(Error::State);
    }
    for plan in plans {
        if let Some(outcome) = outbox::outcome(&mut client.store, plan.operation, plan.digest)
            .map_err(|_| Error::State)?
        {
            state::complete(&mut client.store, &plan, &outcome)?;
            if matches!(outcome, Outcome::Rejected { .. }) {
                return Err(Error::Denied);
            }
        } else if client.pending()?.iter().any(|p| {
            p.action.action().operation_id == plan.operation
                && p.action.digest() == plan.digest
                && p.abandoned
        }) {
            state::abandoned(&mut client.store, &plan)?;
        }
    }
    Ok(())
}
fn resolve_plan(client: &mut Client, config: &Config, stop: &AtomicBool) -> Result<()> {
    let plans = state::plans(&mut client.store)?;
    if plans.len() > 1 {
        return Err(Error::State);
    }
    for plan in plans {
        if stop.load(Ordering::Acquire) {
            return Ok(());
        }
        if plan.room.is_some_and(|room| !config.rooms.contains(&room)) {
            return Err(Error::Configuration);
        }
        let response = client.retry_pending(plan.operation, plan.digest)?;
        let outcome = match response.outcome {
            Outcome::Result { body } => {
                let resolved: home::ResolveResult =
                    body.deserialized().map_err(|_| Error::State)?;
                if resolved.operation_id != plan.operation || resolved.action_digest != plan.digest
                {
                    return Err(Error::State);
                }
                resolved.outcome
            }
            outcome => outcome,
        };
        if let Some(error) = refusal(&outcome) {
            return Err(error);
        }
        state::complete(&mut client.store, &plan, &outcome)?;
        if matches!(outcome, Outcome::Rejected { .. }) {
            return Err(Error::Denied);
        }
    }
    Ok(())
}
