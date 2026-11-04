// SPDX-License-Identifier: Apache-2.0
//! Bounded pilot measurements over real authenticated HyperNet application streams.
use clap::Parser;
use hrc::{
    client::{self, Client, Command, ConnectionState, Controller, Snapshot},
    conversations, home, messaging, moderation,
    protocol::*,
    service::{files, io},
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::{BTreeMap, BTreeSet},
    io::Write,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

type Result<T> = std::result::Result<T, String>;
const MESSAGE_EXCHANGE_LIMIT_NS: u64 = 500_000_000;
const COHORT_OBSERVATION_SECONDS: u64 = 30;
const FLOOD_PENDING_LIMIT: usize = 8;
struct PhaseWindow {
    start: Instant,
    seconds: u64,
    pending_senders: AtomicUsize,
}
impl PhaseWindow {
    fn offer_end(&self) -> Instant {
        self.start + Duration::from_secs(self.seconds)
    }
    fn observation_end(&self) -> Instant {
        self.offer_end() + Duration::from_secs(COHORT_OBSERVATION_SECONDS)
    }
    fn finished(&self, now: Instant) -> bool {
        now >= self.observation_end()
            || (now >= self.offer_end() && self.pending_senders.load(Ordering::Acquire) == 0)
    }
}
#[derive(Parser)]
struct Arguments {
    #[arg(long)]
    request: PathBuf,
    #[arg(long, default_value_t = 360)]
    maximum_seconds: u64,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    profiles: Vec<PathBuf>,
}
struct Endpoint {
    index: usize,
    client: Client,
}
#[derive(Default, Serialize)]
#[serde(rename_all = "camelCase")]
struct Metrics {
    endpoint: usize,
    offered: usize,
    started: usize,
    committed: usize,
    committed_in_window: usize,
    committed_within_observation: usize,
    missed: usize,
    results: BTreeMap<String, usize>,
    completion_ms: Vec<u64>,
    message_exchange_ns: Vec<u64>,
    schedule_lag_ms: Vec<u64>,
    signed_action_bytes: usize,
    decoded_response_bytes: usize,
    unresolved: bool,
    controller_offers_seen_refused: usize,
    tail_offered: usize,
    tail_missed: usize,
    pressure_cost_refusals: usize,
    peak_pending_pressure: usize,
    unanswered_pressure: usize,
}
fn emit(value: serde_json::Value) {
    println!("{value}");
    let _ = std::io::stdout().flush();
}
fn ensure(ok: bool, code: &str) -> Result<()> {
    if ok { Ok(()) } else { Err(code.into()) }
}
fn net<T>(value: client::Result<T>) -> Result<T> {
    value.map_err(|e| e.code().into())
}
fn millis(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}
fn wait_until(at: Instant) {
    thread::sleep(at.saturating_duration_since(Instant::now()));
}
fn delay(error: &client::Error) -> Option<u64> {
    match error {
        client::Error::Refused {
            code: ErrorCode::Unavailable | ErrorCode::RateLimited | ErrorCode::Overloaded,
            retry_after_ms,
            ..
        }
        | client::Error::Network(client::network::Error::ForwardRefused {
            code: ErrorCode::Unavailable | ErrorCode::RateLimited | ErrorCode::Overloaded,
            retry_after_ms,
            ..
        }) => Some(retry_after_ms.unwrap_or(1000).min(60_000)),
        client::Error::Unknown | client::Error::Clock => Some(1000),
        client::Error::Network(e) if e.retryable_session() => Some(1000),
        _ => None,
    }
}
fn pause(end: Instant, ms: u64) -> Result<()> {
    ensure(
        end.saturating_duration_since(Instant::now()) > Duration::from_millis(ms),
        "OriginalDeadline",
    )?;
    thread::sleep(Duration::from_millis(ms));
    Ok(())
}
fn reconnect(c: &mut Client, end: Instant) -> Result<()> {
    c.disconnect();
    loop {
        ensure(Instant::now() < end, "ConnectionDeadline")?;
        match c.connect() {
            Ok(()) => return Ok(()),
            Err(e) => pause(end, delay(&e).ok_or_else(|| e.code().to_string())?)?,
        }
    }
}
enum ExactReply {
    Outcome(Outcome),
    RetryResolution {
        milliseconds: u64,
        code: ErrorCode,
        reason: String,
    },
}
fn bounded_reason(detail: &str) -> String {
    detail
        .chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        .take(80)
        .collect()
}
fn exact_reply(id: OperationId, digest: Id, response: Response) -> Result<ExactReply> {
    if response.operation_id == id {
        ensure(response.action_digest == digest, "ResponseBinding")?;
        return Ok(ExactReply::Outcome(response.outcome));
    }
    match response.outcome {
        Outcome::Result { body } => {
            let resolution: home::ResolveResult =
                body.deserialized().map_err(|_| "ResolutionShape")?;
            ensure(
                resolution.operation_id == id && resolution.action_digest == digest,
                "ResolutionBinding",
            )?;
            Ok(ExactReply::Outcome(resolution.outcome))
        }
        Outcome::Refused {
            code: code @ (ErrorCode::Unavailable | ErrorCode::RateLimited | ErrorCode::Overloaded),
            detail,
            retry_after_ms,
        } => Ok(ExactReply::RetryResolution {
            milliseconds: retry_after_ms.unwrap_or(1000).min(60_000),
            code,
            reason: bounded_reason(&detail),
        }),
        Outcome::Refused {
            code,
            detail,
            retry_after_ms,
        } => Err(format!(
            "ResolutionRefused:{code:?}:{}:retryMs={retry_after_ms:?}",
            bounded_reason(&detail)
        )),
        Outcome::Rejected { code, detail } => Err(format!(
            "ResolutionRejected:{code:?}:{}",
            bounded_reason(&detail)
        )),
        Outcome::Unknown => Err("ResolutionUnknown".into()),
        _ => Err("ResolutionShape".into()),
    }
}
// Staging alone may retry: the product resolves the original identity and resends only after Absent.
fn exact(c: &mut Client, action: &Action, signed: &[u8], end: Instant) -> Result<Outcome> {
    let digest = action_digest(action).map_err(|_| "ActionDigest")?;
    let mut resolution_observations = 0;
    loop {
        ensure(Instant::now() < end, "ExactOperationDeadline")?;
        let pending = !home::is_read_operation(action.operation)
            && net(c.pending())?.iter().any(|p| {
                p.action.action().operation_id == action.operation_id
                    && p.action.digest() == digest
                    && !p.abandoned
            });
        let response = if pending {
            c.retry_pending(action.operation_id, digest)
        } else {
            c.execute_signed(signed)
        };
        match response {
            Ok(r) => {
                let outcome = match exact_reply(action.operation_id, digest, r)? {
                    ExactReply::Outcome(outcome) => outcome,
                    ExactReply::RetryResolution {
                        milliseconds,
                        code,
                        reason,
                    } => {
                        if resolution_observations < 8 {
                            emit(json!({"case":"NativeLoadSetupResolutionRefused",
                                "operation":action.operation,"code":code,"reason":reason,
                                "retryMs":milliseconds,"originalEffectStillPending":true}));
                            resolution_observations += 1;
                        }
                        pause(end, milliseconds)?;
                        continue;
                    }
                };
                match outcome {
                    Outcome::Refused {
                        code:
                            ErrorCode::Unavailable | ErrorCode::RateLimited | ErrorCode::Overloaded,
                        retry_after_ms,
                        ..
                    } => pause(end, retry_after_ms.unwrap_or(1000).min(60_000))?,
                    value => return Ok(value),
                }
            }
            Err(e) => {
                pause(end, delay(&e).ok_or_else(|| e.code().to_string())?)?;
                reconnect(c, end)?;
            }
        }
    }
}
fn operation<T: Serialize>(
    c: &mut Client,
    op: Operation,
    target: Target,
    body: &T,
    end: Instant,
) -> Result<Outcome> {
    let action = net(c.prepare_as(op, target, body, None))?;
    let signed = net(c.sign(&action))?;
    exact(c, &action, &signed, end)
}
fn committed(outcome: Outcome) -> Result<(Option<Id>, Value)> {
    match outcome {
        Outcome::Committed { event, body, .. } => Ok((event, body)),
        Outcome::Refused { code, .. } | Outcome::Rejected { code, .. } => {
            Err(format!("CommitExpected:{code:?}"))
        }
        _ => Err("CommitExpected".into()),
    }
}
fn message(text: String) -> messaging::Send {
    messaging::Send {
        text,
        mentions: vec![],
        parent: None,
        causation: None,
    }
}
// Community preparation performs network reads before its outbox transaction.
// Once preparation returns, only exact() may resolve or submit those saved bytes.
fn prepare_staging_send<T>(
    end: Instant,
    mut attempt: impl FnMut(bool) -> client::Result<T>,
    mut wait: impl FnMut(Instant, u64) -> Result<()>,
) -> Result<T> {
    let mut reconnect = false;
    loop {
        ensure(Instant::now() < end, "SendPreparationDeadline")?;
        match attempt(reconnect) {
            Ok(prepared) => {
                ensure(Instant::now() < end, "SendPreparationDeadline")?;
                return Ok(prepared);
            }
            Err(error) => {
                wait(end, delay(&error).ok_or_else(|| error.code().to_string())?)?;
                reconnect = true;
            }
        }
    }
}
fn send_exact(
    c: &mut Client,
    room: RoomId,
    body: &messaging::Send,
    end: Instant,
) -> Result<Outcome> {
    let prepared = prepare_staging_send(
        end,
        |reconnect| {
            if reconnect {
                c.connect()?;
            }
            c.prepare_send(room, body, None, false, None)
        },
        pause,
    )?;
    exact(c, &prepared.action, &prepared.signed, end)
}
fn health(c: &mut Client) -> client::Result<Response> {
    c.call(
        Operation::ServiceInspect,
        Target::Service,
        &Value::Map(vec![]),
    )
}
fn pilot_support_current(endpoint: usize, result: Result<Outcome>) -> Result<()> {
    let detail = match result {
        Ok(Outcome::Result { .. }) => return Ok(()),
        Ok(Outcome::Refused {
            code,
            detail,
            retry_after_ms,
        }) => format!(
            "Refused:{code:?}:{}:retryMs={retry_after_ms:?}",
            bounded_reason(&detail)
        ),
        Ok(Outcome::Rejected { code, detail }) => {
            format!("Rejected:{code:?}:{}", bounded_reason(&detail))
        }
        Ok(Outcome::Unknown) => "Unknown".into(),
        Ok(Outcome::Absent) => "Absent".into(),
        Ok(Outcome::Committed { .. }) => "UnexpectedCommitted".into(),
        Err(error) => error,
    };
    Err(format!(
        "PilotSessionNotCurrent:endpoint={endpoint}:{detail}"
    ))
}
fn record_result(metrics: &mut Metrics, result: &client::Result<Response>) {
    let name = match result {
        Ok(response) => {
            if let Ok(v) = Value::serialized(response)
                && let Ok(bytes) = canonical_encode(&v, ORDINARY_FRAME_BYTES)
            {
                metrics.decoded_response_bytes += bytes.len();
            }
            match &response.outcome {
                Outcome::Committed { .. } => "Committed".into(),
                Outcome::Result { .. } => "Result".into(),
                Outcome::Rejected { code, detail } => format!("Rejected:{code:?}:{detail}"),
                Outcome::Refused { code, detail, .. } => format!("Refused:{code:?}:{detail}"),
                Outcome::Absent => "Absent".into(),
                Outcome::Unknown => "Unknown".into(),
            }
        }
        Err(error) => error.code().into(),
    };
    // Error details are stable protocol categories, never message text or credentials.
    *metrics.results.entry(name).or_default() += 1;
}
fn normal_send(
    c: &mut Client,
    room: RoomId,
    text: String,
    m: &mut Metrics,
) -> client::Result<Response> {
    let prepared = c.prepare_send(room, &message(text), None, false, None)?;
    m.signed_action_bytes += prepared.signed.len();
    let response = c.execute_signed(&prepared.signed);
    if matches!(
        response,
        Ok(Response {
            outcome: Outcome::Refused { .. },
            ..
        })
    ) {
        // This offered message failed admission. Retain its immutable outcome; never retry it as another offer.
        c.abandon(
            prepared.action.operation_id,
            action_digest(&prepared.action).map_err(|_| client::Error::Input)?,
        )?;
    }
    response
}
fn percentile(values: &[u64], percent: usize) -> Option<u64> {
    if values.is_empty() {
        return None;
    }
    let mut values = values.to_vec();
    values.sort_unstable();
    Some(values[(values.len() * percent).div_ceil(100).saturating_sub(1)])
}
struct Offer {
    request: u64,
    scheduled: Instant,
    identity: Option<(OperationId, Id)>,
    event: Option<Id>,
    committed_at: Option<Instant>,
    exchange_ns: Option<u64>,
    terminal: bool,
    seen_refused: bool,
    status: String,
}
struct Interactive {
    index: usize,
    controller: Controller,
    offers: Vec<Offer>,
}
fn current(view: &Snapshot, room: RoomId) -> bool {
    view.connection == ConnectionState::Online
        && !view.inspection.stale
        && !view.inspection.filters_stale
        && view.privacy.is_some()
        && view
            .selected
            .as_ref()
            .is_some_and(|v| v.summary.room == room && !v.stale && v.gap.is_none())
}
fn apply_delivery(offer: &mut Offer, d: &client::Delivery, room: RoomId) -> bool {
    if d.request_id != Some(offer.request)
        && !offer.identity.is_some_and(|(id, _)| id == d.operation_id)
    {
        return false;
    }
    let identity = (d.operation_id, d.action_digest);
    if d.operation != Operation::MessageSend
        || d.room != Some(room)
        || offer.identity.is_some_and(|saved| saved != identity)
    {
        offer.terminal = true;
        offer.status = "DeliveryBindingFailed".into();
        return true;
    }
    offer.identity = Some(identity);
    match &d.outcome {
        Some(Outcome::Committed {
            event: Some(event), ..
        }) => {
            offer.event = Some(*event);
            offer.committed_at = Some(Instant::now());
            offer.exchange_ns = d.exchange_ns;
            offer.terminal = true;
            offer.status = "Committed".into();
        }
        Some(Outcome::Rejected { code, detail }) => {
            offer.terminal = true;
            offer.status = format!("Rejected:{code:?}:{detail}");
        }
        Some(Outcome::Refused { code, detail, .. }) => {
            offer.seen_refused = true;
            offer.status = format!("Refused:{code:?}:{detail}")
        }
        _ => offer.status = "OutcomeUnknown".into(),
    }
    true
}
fn observe(ui: &mut Interactive, room: RoomId) -> Arc<Snapshot> {
    let view = ui.controller.snapshot();
    for offer in ui.offers.iter_mut().filter(|o| !o.terminal) {
        let delivery = view.deliveries.iter().find(|d| {
            d.request_id == Some(offer.request)
                || offer.identity.is_some_and(|(id, _)| id == d.operation_id)
        });
        if let Some(d) = delivery {
            apply_delivery(offer, d, room);
        } else if let Some(completion) = view
            .completions
            .iter()
            .find(|c| c.request_id == offer.request)
        {
            // A failed command without a saved delivery did not produce a retryable effect.
            offer.terminal = true;
            offer.status = completion
                .error
                .as_ref()
                .map_or("CompletionWithoutDelivery", |e| e.code.as_str())
                .into();
        }
    }
    view
}
fn dispatch_offer(
    ui: &mut Interactive,
    room: RoomId,
    scheduled: Instant,
    text: String,
) -> std::result::Result<(), client::DispatchError> {
    let request = ui.controller.dispatch(Command::Send {
        room,
        text,
        mentions: vec![],
        parent: None,
        causation: None,
        action: false,
        grant: None,
    })?;
    ui.offers.push(Offer {
        request,
        scheduled,
        identity: None,
        event: None,
        committed_at: None,
        exchange_ns: None,
        terminal: false,
        seen_refused: false,
        status: "Queued".into(),
    });
    Ok(())
}
// Network keepalives must not block observation or user-command dispatch.
fn with_keepalive<T>(
    end: Instant,
    period: Duration,
    mut keepalive: impl FnMut(&AtomicBool) + Send,
    observe: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let stopped = AtomicBool::new(false);
    thread::scope(|scope| {
        let worker = scope.spawn(|| {
            let mut next = Instant::now() + period;
            while !stopped.load(Ordering::Acquire) && Instant::now() < end {
                if Instant::now() >= next {
                    keepalive(&stopped);
                    next = Instant::now() + period;
                } else {
                    thread::sleep(Duration::from_millis(20));
                }
            }
        });
        let result = observe();
        stopped.store(true, Ordering::Release);
        worker.join().map_err(|_| "SupportingHealthWorker")?;
        result
    })
}
fn command_completed(view: &Snapshot, request: u64) -> Result<bool> {
    let Some(completion) = view.completions.iter().find(|c| c.request_id == request) else {
        return Ok(false);
    };
    if let Some(error) = &completion.error {
        return Err(format!("ControllerSetup:{}", bounded_reason(&error.code)));
    }
    Ok(true)
}
#[derive(Clone, Copy)]
struct SetupEffect {
    request: u64,
    operation: Operation,
    room: Option<RoomId>,
    identity: Option<(OperationId, Id)>,
}
impl SetupEffect {
    fn new(request: u64, operation: Operation, room: Option<RoomId>) -> Self {
        Self {
            request,
            operation,
            room,
            identity: None,
        }
    }
    fn observe(
        &mut self,
        deliveries: &[client::Delivery],
        completions: &[client::Completion],
    ) -> Result<bool> {
        let mut matching = deliveries.iter().filter(|d| {
            d.request_id == Some(self.request)
                || self.identity.is_some_and(|(id, _)| id == d.operation_id)
        });
        let Some(delivery) = matching.next() else {
            if let Some(completion) = completions.iter().find(|c| c.request_id == self.request) {
                return Err(format!(
                    "ControllerSetup:{}",
                    completion.error.as_ref().map_or_else(
                        || "CompletionWithoutDelivery".into(),
                        |error| bounded_reason(&error.code),
                    )
                ));
            }
            return Ok(false);
        };
        let identity = (delivery.operation_id, delivery.action_digest);
        ensure(
            matching.next().is_none()
                && delivery.request_id == Some(self.request)
                && delivery.operation == self.operation
                && delivery.room == self.room
                && self.identity.is_none_or(|saved| saved == identity),
            "ControllerSetupDeliveryBinding",
        )?;
        ensure(
            !delivery.held && !delivery.abandoned,
            "ControllerSetupHeldOrAbandoned",
        )?;
        self.identity = Some(identity);
        // Completion describes the original command attempt. Reconnect can resolve
        // its exact durable effect later without replacing that completion record.
        match &delivery.outcome {
            Some(Outcome::Committed { .. }) => Ok(true),
            None
            | Some(Outcome::Unknown | Outcome::Absent)
            | Some(Outcome::Refused {
                code: ErrorCode::Unavailable | ErrorCode::RateLimited | ErrorCode::Overloaded,
                ..
            }) => Ok(false),
            Some(Outcome::Rejected { code, detail }) => Err(format!(
                "ControllerSetupRejected:{code:?}:{}",
                bounded_reason(detail)
            )),
            Some(Outcome::Refused { code, detail, .. }) => Err(format!(
                "ControllerSetupRefused:{code:?}:{}",
                bounded_reason(detail)
            )),
            Some(Outcome::Result { .. }) => Err("ControllerSetupUnexpectedResult".into()),
        }
    }
}
fn wait_command(controller: &Controller, request: u64, end: Instant) -> Result<()> {
    loop {
        ensure(Instant::now() < end, "ControllerSetupDeadline")?;
        if command_completed(&controller.snapshot(), request)? {
            return Ok(());
        }
        thread::sleep(Duration::from_millis(20));
    }
}
fn readiness_state(index: usize, view: &Snapshot, room: RoomId) -> serde_json::Value {
    json!({"endpoint":index,"connection":format!("{:?}",view.connection),
        "updating":view.updating,
        "inspectionStale":view.inspection.stale,"filtersStale":view.inspection.filters_stale,"privacyPresent":view.privacy.is_some(),
        "selectedCurrent":current(view,room),
        "selectedStale":view.selected.as_ref().map(|v|v.stale),
        "selectedGap":view.selected.as_ref().and_then(|v|v.gap.as_deref()).map(bounded_reason),
        "selectedHasMore":view.selected.as_ref().map(|v|v.has_more),
        "status":view.status.as_ref().map(|s|bounded_reason(&s.code)),
        "statusRequest":view.status.as_ref().and_then(|s|s.request_id)})
}
// A current snapshot before a supporting worker joins is not the final gate.
// Re-observe after that join, without renewing the original readiness interval.
fn await_pilot_readiness(
    end: Instant,
    keepalive_period: Duration,
    mut keepalive: impl FnMut(&AtomicBool) + Send,
    mut observe: impl FnMut() -> bool,
) -> Result<()> {
    let mut next_keepalive = Instant::now() + keepalive_period;
    loop {
        with_keepalive(
            end,
            Duration::from_millis(20),
            |stopped| {
                // Rejoining the observer must not postpone supporting stream health.
                if Instant::now() >= next_keepalive {
                    keepalive(stopped);
                    next_keepalive = Instant::now() + keepalive_period;
                }
            },
            || loop {
                ensure(Instant::now() < end, "EightControllerReadinessDeadline")?;
                let ready = observe();
                ensure(Instant::now() < end, "EightControllerReadinessDeadline")?;
                if ready {
                    return Ok(());
                }
                thread::sleep(Duration::from_millis(20));
            },
        )?;
        ensure(Instant::now() < end, "EightControllerReadinessDeadline")?;
        let ready = observe();
        ensure(Instant::now() < end, "EightControllerReadinessDeadline")?;
        if ready {
            return Ok(());
        }
    }
}
fn open_controllers(
    paths: &[PathBuf],
    room: RoomId,
    ignored: AccountId,
    supporting: &mut [Endpoint],
    end: Instant,
) -> Result<Vec<Interactive>> {
    let mut controllers = Vec::new();
    emit(
        json!({"case":"NativeLoadControllerStartup", "bootMs":hrc::clock::boot_ms().ok(),
        "stage":"Begin", "maximumMilliseconds":millis(end.saturating_duration_since(Instant::now()))}),
    );
    for (index, path) in paths.iter().take(8).enumerate() {
        let controller = net(Controller::open(path))?;
        emit(
            json!({"case":"NativeLoadControllerStartup", "endpoint":index,
            "bootMs":hrc::clock::boot_ms().ok(), "stage":"ConnectDispatch"}),
        );
        controller
            .dispatch(Command::Connect)
            .map_err(|_| "ControllerConnectDispatch")?;
        controllers.push(Interactive {
            index,
            controller,
            offers: vec![],
        });
    }
    let mut selected = [false; 8];
    let mut joined: [Option<SetupEffect>; 8] = [None; 8];
    let mut filter: Option<SetupEffect> = None;
    let mut resynchronise = None;
    let mut previous = vec![None; 8];
    let mut observations = [0u8; 8];
    with_keepalive(
        end,
        Duration::from_secs(8),
        |stopped| {
            for e in supporting.iter_mut() {
                if stopped.load(Ordering::Acquire) || Instant::now() >= end {
                    break;
                }
                let _ = health(&mut e.client);
            }
        },
        || loop {
            let mut ready = 0;
            for ui in &controllers {
                let v = ui.controller.snapshot();
                let state = readiness_state(ui.index, &v, room);
                if observations[ui.index] < 8 && previous[ui.index].as_ref() != Some(&state) {
                    let mut observed = state.clone();
                    observed["case"] = json!("NativeLoadControllerStartup");
                    observed["bootMs"] = json!(hrc::clock::boot_ms().ok());
                    observed["stage"] = json!("ObservedState");
                    emit(observed);
                    observations[ui.index] += 1;
                    previous[ui.index] = Some(state);
                }
                // Retain the original effect binding even during backoff, before
                // reconnect publishes its resolved delivery and current views.
                let join_committed = if !selected[ui.index] {
                    joined[ui.index]
                        .as_mut()
                        .map(|effect| effect.observe(&v.deliveries, &v.completions))
                        .transpose()?
                        .unwrap_or(false)
                } else {
                    true
                };
                let filter_committed = if ui.index == 7 && !selected[ui.index] {
                    filter
                        .as_mut()
                        .map(|effect| effect.observe(&v.deliveries, &v.completions))
                        .transpose()?
                        .unwrap_or(false)
                } else {
                    true
                };
                if !selected[ui.index]
                    && v.connection == ConnectionState::Online
                    && !v.inspection.stale
                    && v.privacy.is_some()
                {
                    if joined[ui.index].is_none() {
                        let request = ui.controller
                            .dispatch(Command::Join(room))
                            .map_err(|_| "ControllerJoinDispatch")?;
                        joined[ui.index] = Some(SetupEffect::new(
                            request, Operation::RoomJoin, Some(room),
                        ));
                        emit(json!({"case":"NativeLoadControllerStartup","endpoint":ui.index,
                            "bootMs":hrc::clock::boot_ms().ok(),"stage":"JoinDispatch",
                            "request":request}));
                        continue;
                    }
                    if !join_committed {
                        continue;
                    }
                    if ui.index == 7 {
                        if filter.is_none() {
                            let request = ui.controller
                                .dispatch(Command::SetFilter {
                                    subject: ignored,
                                    ignored: Some(true),
                                    muted: None,
                                })
                                .map_err(|_| "ControllerFilterDispatch")?;
                            filter = Some(SetupEffect::new(
                                request, Operation::ModerationIgnore, None,
                            ));
                            emit(json!({"case":"NativeLoadControllerStartup","endpoint":ui.index,
                                "bootMs":hrc::clock::boot_ms().ok(),"stage":"FilterDispatch",
                                "request":request}));
                            continue;
                        }
                        if !filter_committed {
                            continue;
                        }
                    }
                    let request = ui.controller
                        .dispatch(Command::SelectRoom(room))
                        .map_err(|_| "ControllerSelectDispatch")?;
                    emit(json!({"case":"NativeLoadControllerStartup","endpoint":ui.index,
                        "bootMs":hrc::clock::boot_ms().ok(),"stage":"SelectDispatch","request":request}));
                    selected[ui.index] = true;
                }
                if ui.index == 7 && selected[ui.index] {
                    if let Some(request) = resynchronise {
                        if !command_completed(&v, request)? {
                            continue;
                        }
                    } else if v.selected.as_ref().is_some_and(|view|
                        view.summary.room == room && view.gap.is_some()) {
                        // Ignore invalidates the old filter-bound cursor. Use the
                        // same explicit recovery command as the interactive client.
                        resynchronise = Some(ui.controller.dispatch(Command::Resynchronise)
                            .map_err(|_| "ControllerResynchroniseDispatch")?);
                        emit(json!({"case":"NativeLoadControllerStartup", "endpoint":ui.index,
                            "bootMs":hrc::clock::boot_ms().ok(), "stage":"ResynchroniseDispatch",
                            "request":resynchronise}));
                        continue;
                    }
                }
                ready += usize::from(current(&v, room));
            }
            if ready == 8 {
                emit(
                    json!({"case":"NativeLoadControllerStartup", "bootMs":hrc::clock::boot_ms().ok(),
                "stage":"AllCurrent"}),
                );
                return Ok(controllers);
            }
            if Instant::now() >= end {
                emit(
                    json!({"case":"NativeLoadControllerReadiness","passed":false,
                    "bootMs":hrc::clock::boot_ms().ok(),"states":controllers.iter().map(|u| {
                let v=u.controller.snapshot(); readiness_state(u.index,&v,room)
            }).collect::<Vec<_>>()}),
                );
                return Err("EightControllerReadinessDeadline".into());
            }
            thread::sleep(Duration::from_millis(20));
        },
    ).and_then(|controllers| {
        ensure(Instant::now() < end, "EightControllerReadinessDeadline")?;
        Ok(controllers)
    })
}
fn interactive(
    mut ui: Interactive,
    room: RoomId,
    ignored: AccountId,
    window: &PhaseWindow,
    phase: &str,
) -> (Interactive, Metrics) {
    let (start, seconds) = (window.start, window.seconds);
    let expected = if ui.index < 5 { seconds as usize } else { 0 };
    let mut m = Metrics {
        endpoint: ui.index,
        offered: expected,
        ..Metrics::default()
    };
    let end = start + Duration::from_secs(seconds);
    let first_offer = ui.offers.len();
    let initial = ui.controller.snapshot();
    let first_sequence = initial
        .selected
        .as_ref()
        .and_then(|v| v.events.iter().map(|e| e.sequence).max())
        .unwrap_or(0);
    let mut received = BTreeSet::new();
    let mut ignored_leak = false;
    let mut next = 0;
    let mut state_ms = BTreeMap::<String, u64>::new();
    let mut revisions = BTreeSet::new();
    let mut previous = start;
    let mut cohort_reported = ui.index >= 5;
    wait_until(start);
    while !window.finished(Instant::now()) {
        let now = Instant::now();
        let view = observe(&mut ui, room);
        let state = match (&view.connection, current(&view, room)) {
            (_, true) => "OnlineCurrent",
            (ConnectionState::Online, false) => "OnlineStale",
            (ConnectionState::Backoff { .. }, _) => "Backoff",
            (ConnectionState::Offline, _) => "Offline",
            (ConnectionState::Connecting, _) => "Connecting",
            (ConnectionState::Resolving, _) => "Resolving",
        };
        *state_ms.entry(state.into()).or_default() +=
            millis(now.saturating_duration_since(previous));
        previous = now;
        revisions.insert(view.revision);
        if current(&view, room)
            && let Some(selected) = &view.selected
        {
            for e in &selected.events {
                ignored_leak |= ui.index == 7 && e.actor.acting().account == ignored;
                if e.sequence > first_sequence
                    && e.kind == Operation::MessageSend
                    && e.actor.acting().account != view.account
                {
                    received.insert(e.event);
                }
            }
        }
        while now < end && next < expected {
            let scheduled = start
                + Duration::from_secs(next as u64)
                + Duration::from_millis(ui.index as u64 * 200);
            if now < scheduled {
                break;
            }
            if now >= scheduled + Duration::from_secs(1) {
                m.missed += 1;
            } else {
                m.started += 1;
                m.schedule_lag_ms
                    .push(millis(now.saturating_duration_since(scheduled)));
                let text = format!("{phase} endpoint{} offer{next} λ", ui.index);
                if let Err(e) = dispatch_offer(&mut ui, room, scheduled, text) {
                    *m.results.entry(format!("Dispatch:{e:?}")).or_default() += 1;
                }
            }
            next += 1;
        }
        // Stop offering at the fixed boundary, but observe the entire cohort.
        // Other endpoints retain pressure until all five senders finish or the
        // fixed observation bound expires. No effect is resubmitted here.
        if now >= end
            && !cohort_reported
            && ui.offers[first_offer..].iter().all(|offer| offer.terminal)
        {
            cohort_reported = true;
            window.pending_senders.fetch_sub(1, Ordering::AcqRel);
        }
        thread::sleep(Duration::from_millis(10));
    }
    m.missed += expected - next;
    let view = observe(&mut ui, room);
    for offer in &ui.offers[first_offer..] {
        *m.results.entry(offer.status.clone()).or_default() += 1;
        m.unresolved |= !offer.terminal;
        m.controller_offers_seen_refused += usize::from(offer.seen_refused);
        if let Some(at) = offer.committed_at {
            m.committed += 1;
            m.committed_in_window += usize::from(at <= end);
            m.committed_within_observation += usize::from(at <= window.observation_end());
            m.completion_ms
                .push(millis(at.saturating_duration_since(offer.scheduled)));
            if let Some(exchange_ns) = offer.exchange_ns {
                m.message_exchange_ns.push(exchange_ns);
            }
        }
    }
    let fresh = !received.is_empty() && current(&view, room) && !ignored_leak;
    m.unresolved |= !fresh;
    emit(
        json!({"case":"NativeLoadControllerObservation","phase":phase,"endpoint":ui.index,
        "freshRemoteEvents":received.len(),"ignoredEventLeak":ignored_leak,"currentAtEnd":current(&view,room),"observedSnapshotRevisions":revisions.len(),
        "stateDurationMs":state_ms,"status":view.status.as_ref().map(|s|&s.code),
        "statusDetail":view.status.as_ref().map(|s|&s.detail),"connection":format!("{:?}",view.connection),"freshnessPassed":fresh}),
    );
    (ui, m)
}
fn keep_alive_until_end(endpoint: &mut Endpoint, m: &mut Metrics, window: &PhaseWindow) {
    let mut next = window.start + Duration::from_millis(endpoint.index as u64 * 50);
    while !window.finished(Instant::now()) {
        if Instant::now() >= next {
            let result = health(&mut endpoint.client);
            record_result(m, &result);
            next = Instant::now() + Duration::from_secs(8);
        } else {
            thread::sleep(Duration::from_millis(10));
        }
    }
}
fn idle(mut endpoint: Endpoint, window: &PhaseWindow) -> (Endpoint, Metrics) {
    let mut m = Metrics {
        endpoint: endpoint.index,
        ..Metrics::default()
    };
    keep_alive_until_end(&mut endpoint, &mut m, window);
    (endpoint, m)
}
fn query() -> messaging::Search {
    messaging::Search {
        terms: (0..16).map(|i| format!("term{i}")).collect(),
        sender: None,
        represented: None,
        from_ms: None,
        until_ms: None,
        cursor: None,
        limit: 50,
    }
}
fn record_pressure_result(metrics: &mut Metrics, result: &client::Result<Response>) {
    if matches!(
        result,
        Ok(Response {
            outcome: Outcome::Refused {
                code: ErrorCode::RateLimited | ErrorCode::Overloaded,
                ..
            } | Outcome::Rejected {
                code: ErrorCode::RateLimited | ErrorCode::Overloaded,
                ..
            },
            ..
        })
    ) {
        metrics.pressure_cost_refusals += 1;
    }
    record_result(metrics, result);
}
fn hostile(endpoint: Endpoint, room: RoomId, window: &PhaseWindow) -> (Endpoint, Metrics) {
    if endpoint.index == 8 {
        return flood(endpoint, room, window);
    }
    let (start, seconds) = (window.start, window.seconds);
    let mut m = Metrics {
        endpoint: endpoint.index,
        ..Metrics::default()
    };
    let period = 500;
    let offers = (seconds + COHORT_OBSERVATION_SECONDS) * 1000 / period;
    for index in 0..offers {
        if window.finished(Instant::now()) {
            break;
        }
        let scheduled = start + Duration::from_millis(index * period);
        wait_until(scheduled);
        if window.finished(Instant::now()) {
            break;
        }
        m.offered += 1;
        m.tail_offered += usize::from(scheduled >= window.offer_end());
        if m.unresolved || Instant::now() >= scheduled + Duration::from_millis(period) {
            m.missed += 1;
            m.tail_missed += usize::from(scheduled >= window.offer_end());
            continue;
        }
        m.started += 1;
        let action =
            endpoint
                .client
                .prepare_as(Operation::SearchQuery, Target::Room(room), &query(), None);
        let result = action.and_then(|action| {
            let signed = endpoint.client.sign(&action)?;
            m.signed_action_bytes += signed.len();
            // Deliberate hostile protocol offers do not enter an automatic client outbox/retry loop.
            let key = VerifyingKey::from_bytes(
                endpoint.client.profile.registration.endpoint_key.as_bytes(),
            )
            .map_err(|_| client::Error::Input)?;
            Ok(endpoint
                .client
                .session()?
                .submit(&signed, &key)?
                .value()
                .clone())
        });
        if matches!(
            result,
            Ok(Response {
                outcome: Outcome::Committed { .. },
                ..
            })
        ) {
            m.committed += 1;
        }
        m.unresolved = result.is_err();
        record_pressure_result(&mut m, &result);
    }
    // The last scheduled slot can finish before the hard observation boundary.
    // Wait without adding supporting traffic to the attack's evidence.
    while !window.finished(Instant::now()) {
        thread::sleep(Duration::from_millis(10));
    }
    (endpoint, m)
}

struct FloodPending {
    home: ServiceId,
    actions: BTreeMap<(Id, Id), Id>,
}
impl FloodPending {
    fn insert(&mut self, action: &Action) -> Result<()> {
        let key = (action.operation_id.window, action.operation_id.operation);
        ensure(
            action.home == self.home
                && self.actions.len() < FLOOD_PENDING_LIMIT
                && !self.actions.contains_key(&key),
            "FloodPendingBound",
        )?;
        self.actions
            .insert(key, action_digest(action).map_err(|_| "FloodDigest")?);
        Ok(())
    }
    fn accept(&mut self, response: &Response) -> Result<()> {
        let key = (
            response.operation_id.window,
            response.operation_id.operation,
        );
        ensure(
            response.home == self.home && self.actions.get(&key) == Some(&response.action_digest),
            "FloodResponseBinding",
        )?;
        self.actions.remove(&key);
        Ok(())
    }
}

fn flood(endpoint: Endpoint, room: RoomId, window: &PhaseWindow) -> (Endpoint, Metrics) {
    let mut metrics = Metrics {
        endpoint: endpoint.index,
        ..Metrics::default()
    };
    let mut pending = FloodPending {
        home: endpoint.client.profile.server.home,
        actions: BTreeMap::new(),
    };
    let result = (|| -> Result<()> {
        let stream = net(endpoint.client.session())?.stream_handle();
        let key = VerifyingKey::from_bytes(endpoint.client.profile.server.signing_key.as_bytes())
            .map_err(|_| "ServerKey")?;
        let mut index = 0;
        let mut drain_end = None;
        loop {
            let now = Instant::now();
            if drain_end.is_none() && window.finished(now) {
                // Stop offers at the original phase boundary. Only already sent
                // requests may drain, within one fixed five-second allowance.
                drain_end = Some(now + Duration::from_secs(5));
            }
            if let Some(end) = drain_end {
                if pending.actions.is_empty() {
                    return Ok(());
                }
                ensure(now < end, "FloodDrainDeadline")?;
            }
            let scheduled = window.start + Duration::from_millis(index * 100);
            if drain_end.is_none() && now >= scheduled {
                index += 1;
                metrics.offered += 1;
                let tail = usize::from(scheduled >= window.offer_end());
                metrics.tail_offered += tail;
                if now >= scheduled + Duration::from_millis(100)
                    || pending.actions.len() == FLOOD_PENDING_LIMIT
                {
                    metrics.missed += 1;
                    metrics.tail_missed += tail;
                } else {
                    let action = net(endpoint.client.prepare_as(
                        Operation::MessageSend,
                        Target::Room(room),
                        &message(format!("flood offer{}", index - 1)),
                        None,
                    ))?;
                    let signed = net(endpoint.client.sign(&action))?;
                    metrics.signed_action_bytes += signed.len();
                    let frame = Frame::new(FrameKind::Action, signed).map_err(|_| "FloodFrame")?;
                    pending.insert(&action)?;
                    // Partial writes leave an unresolved request, never an invented refusal.
                    metrics.started += 1;
                    metrics.peak_pending_pressure =
                        metrics.peak_pending_pressure.max(pending.actions.len());
                    io::send(
                        &stream,
                        &frame,
                        window
                            .observation_end()
                            .saturating_duration_since(Instant::now())
                            .min(Duration::from_secs(2)),
                    )
                    .map_err(|_| "FloodWrite")?;
                }
                continue;
            }
            let end = drain_end.unwrap_or(window.observation_end());
            let wait = end
                .saturating_duration_since(now)
                .min(Duration::from_millis(20));
            let wait = if drain_end.is_none() {
                wait.min(scheduled.saturating_duration_since(now))
            } else {
                wait
            };
            if !stream.wait_readable(wait).map_err(|_| "FloodTransport")? {
                continue;
            }
            let frame = io::receive(
                &stream,
                end.saturating_duration_since(Instant::now())
                    .min(Duration::from_secs(2)),
            )
            .map_err(|_| "FloodResponseDeadline")?;
            ensure(frame.kind == FrameKind::Response, "FloodResponseFrame")?;
            let response = verify_response(&frame.payload, &key).map_err(|_| "FloodSignature")?;
            let response = response.value();
            ensure(
                matches!(
                    response.outcome,
                    Outcome::Committed { .. } | Outcome::Rejected { .. } | Outcome::Refused { .. }
                ),
                "FloodUnknownOutcome",
            )?;
            pending.accept(response)?;
            metrics.committed += usize::from(matches!(response.outcome, Outcome::Committed { .. }));
            record_pressure_result(&mut metrics, &Ok(response.clone()));
        }
    })();
    metrics.unanswered_pressure = pending.actions.len();
    if let Err(code) = result {
        metrics.unresolved = true;
        *metrics.results.entry(code).or_default() += 1;
    }
    // A failure remains disqualifying for the whole scheduled phase.
    while !window.finished(Instant::now()) {
        thread::sleep(Duration::from_millis(10));
    }
    (endpoint, metrics)
}
fn slow_reader(
    mut endpoint: Endpoint,
    room: RoomId,
    start: Instant,
    seconds: u64,
) -> (Endpoint, Metrics) {
    let mut m = Metrics {
        endpoint: endpoint.index,
        ..Metrics::default()
    };
    wait_until(start);
    let run = || -> Result<serde_json::Value> {
        let stream = net(endpoint.client.session())?.stream_handle();
        let key = VerifyingKey::from_bytes(endpoint.client.profile.server.signing_key.as_bytes())
            .map_err(|_| "ServerKey")?;
        let mut expected = BTreeMap::new();
        let mut input = 0;
        for _ in 0..16 {
            let action = net(endpoint.client.prepare_as(
                Operation::HistoryPage,
                Target::Room(room),
                &messaging::Page {
                    cursor: None,
                    limit: 50,
                },
                None,
            ))?;
            let signed = net(endpoint.client.sign(&action))?;
            let frame = Frame::new(FrameKind::Action, signed).map_err(|_| "Frame")?;
            input += frame.encode().map_err(|_| "Frame")?.len();
            expected.insert(
                (action.operation_id.window, action.operation_id.operation),
                action_digest(&action).map_err(|_| "Digest")?,
            );
            io::send(&stream, &frame, Duration::from_secs(2)).map_err(|_| "SlowReaderWrite")?;
        }
        let sent = Instant::now();
        thread::sleep(Duration::from_secs(12));
        let deadline =
            (start + Duration::from_secs(seconds)).min(Instant::now() + Duration::from_secs(8));
        let mut output = 0;
        let mut responses = 0;
        let mut ended = None;
        while !expected.is_empty() && Instant::now() < deadline {
            match stream.wait_readable(Duration::from_millis(200)) {
                Ok(false) => continue,
                Ok(true) => (),
                Err(hrc::hypernet::Error::Closed) => {
                    ended = Some("PeerClosed");
                    break;
                }
                Err(_) => return Err("SlowReaderAuthorityOrTransport".into()),
            }
            // Read only after readability. Each complete response is signature- and request-bound.
            let frame = match io::receive(&stream, Duration::from_secs(2)) {
                Ok(f) => f,
                Err(_) => {
                    ended = Some("TransportOrFrameDeadline");
                    break;
                }
            };
            ensure(frame.kind == FrameKind::Response, "SlowReaderFrame")?;
            output += frame.encode().map_err(|_| "Frame")?.len();
            let response =
                verify_response(&frame.payload, &key).map_err(|_| "SlowReaderSignature")?;
            let response = response.value();
            ensure(
                expected.remove(&(
                    response.operation_id.window,
                    response.operation_id.operation,
                )) == Some(response.action_digest),
                "SlowReaderResponseBinding",
            )?;
            responses += 1;
        }
        ensure(
            output <= 16 * (ORDINARY_FRAME_BYTES + 4),
            "ResponseAmplificationBound",
        )?;
        Ok(
            json!({"case":"NativeLoadSlowReader","requests":16,"verifiedResponses":responses,"drainEnded":ended,
            "inputFrameBytes":input,"completeOutputFrameBytes":output,"unobservedPartialOutputPossible":ended.is_some(),
            "holdMs":12000,"drainElapsedMs":millis(sent.elapsed())-12000,"internalQueueOccupancyMeasured":false}),
        )
    }();
    match run {
        Ok(value) => emit(value),
        Err(code) => {
            *m.results.entry(code).or_default() += 1;
            m.unresolved = true;
        }
    }
    endpoint.client.disconnect();
    // Keep this hostile stream closed; a fresh connection belongs to the recovery measurement.
    wait_until(start + Duration::from_secs(seconds));
    (endpoint, m)
}
fn moderator(
    mut endpoint: Endpoint,
    room: RoomId,
    subject: AccountId,
    start: Instant,
    seconds: u64,
) -> (Endpoint, Metrics) {
    let mut m = Metrics {
        endpoint: endpoint.index,
        ..Metrics::default()
    };
    for (offset, enabled) in [(8, true), (22, false)] {
        wait_until(start + Duration::from_secs(offset));
        let began = Instant::now();
        let result = endpoint.client.call(
            Operation::ModerationSilence,
            Target::Room(room),
            &moderation::Restriction {
                subject,
                enabled,
                duration_ms: 30000,
                reason: "Native load qualification".into(),
            },
        );
        emit(
            json!({"case":"NativeLoadModeration","enabled":enabled,"elapsedMs":millis(began.elapsed()),
            "committed":matches!(result, Ok(Response {outcome:Outcome::Committed {..},..}))}),
        );
        if matches!(
            result,
            Ok(Response {
                outcome: Outcome::Committed { .. },
                ..
            })
        ) {
            m.committed += 1;
            m.completion_ms.push(millis(began.elapsed()));
        }
        record_result(&mut m, &result);
    }
    let keepalive = health(&mut endpoint.client);
    record_result(&mut m, &keepalive);
    wait_until(start + Duration::from_secs(seconds));
    (endpoint, m)
}
fn run_phase(
    controllers: Vec<Interactive>,
    endpoints: Vec<Endpoint>,
    room: RoomId,
    seconds: u64,
    overload: bool,
) -> (Vec<Interactive>, Vec<Endpoint>, bool, Instant) {
    let phase = if overload { "overload" } else { "baseline" };
    let start = Instant::now() + Duration::from_secs(1);
    let window = PhaseWindow {
        start,
        seconds,
        pending_senders: AtomicUsize::new(5),
    };
    let subject = endpoints
        .iter()
        .find(|e| e.index == 8)
        .expect("agent flood endpoint")
        .client
        .profile
        .registration
        .account;
    emit(
        json!({"case":"NativeLoadPhaseStarted","phase":phase,"seconds":seconds,"offeredNormalPerSecond":5,
        "observationBootMs":hrc::clock::boot_ms().ok(),
        "productionControllers":8,"backgroundRefreshEnabled":true,
        "maximumCohortObservationTailSeconds":COHORT_OBSERVATION_SECONDS}),
    );
    let (ui_pairs, pairs) = thread::scope(|scope| {
        let window = &window;
        let ui_handles: Vec<_> = controllers
            .into_iter()
            .map(|u| scope.spawn(move || interactive(u, room, subject, window, phase)))
            .collect();
        let handles: Vec<_> = endpoints
            .into_iter()
            .map(|e| {
                scope.spawn(move || {
                    let (endpoint, metrics) = match e.index {
                        8 | 9 if overload => hostile(e, room, window),
                        10 | 11 if overload => {
                            let (mut endpoint, mut metrics) = if e.index == 11 {
                                slow_reader(e, room, start, seconds)
                            } else {
                                moderator(e, room, subject, start, seconds)
                            };
                            keep_alive_until_end(&mut endpoint, &mut metrics, window);
                            (endpoint, metrics)
                        }
                        _ => idle(e, window),
                    };
                    (endpoint, metrics, Instant::now())
                })
            })
            .collect();
        (
            ui_handles
                .into_iter()
                .map(|h| h.join().expect("bounded Controller observer panicked"))
                .collect::<Vec<_>>(),
            handles
                .into_iter()
                .map(|h| h.join().expect("bounded load worker panicked"))
                .collect::<Vec<_>>(),
        )
    });
    let completed_at = Instant::now();
    let pressure_ended = pairs[0].2.max(pairs[1].2);
    let normal: Vec<_> = ui_pairs.iter().take(5).map(|(_, m)| m).collect();
    let completion_latencies: Vec<_> = normal
        .iter()
        .flat_map(|m| m.completion_ms.iter().copied())
        .collect();
    let exchange_latencies: Vec<_> = normal
        .iter()
        .flat_map(|m| m.message_exchange_ns.iter().copied())
        .collect();
    let offered: usize = normal.iter().map(|m| m.offered).sum();
    let committed: usize = normal.iter().map(|m| m.committed).sum();
    let in_window: usize = normal.iter().map(|m| m.committed_in_window).sum();
    let within_observation: usize = normal.iter().map(|m| m.committed_within_observation).sum();
    let missed: usize = normal.iter().map(|m| m.missed).sum();
    let started: usize = normal.iter().map(|m| m.started).sum();
    let rejected: usize = normal
        .iter()
        .flat_map(|m| &m.results)
        .filter(|(code, _)| {
            code.starts_with("Rejected:")
                || code.starts_with("Refused:")
                || code.starts_with("Operation")
                || code.starts_with("Dispatch:")
        })
        .map(|(_, count)| count)
        .sum();
    let exchange_p95_ns = percentile(&exchange_latencies, 95);
    let exchange_ms = |ns: Option<u64>| ns.map(|ns| ns as f64 / 1_000_000.0);
    let distinct_events: BTreeSet<_> = ui_pairs
        .iter()
        .take(5)
        .flat_map(|(u, _)| u.offers.iter())
        .filter(|o| o.scheduled >= start && o.scheduled < start + Duration::from_secs(seconds))
        .filter_map(|o| o.event)
        .collect();
    let moderator = &pairs[2].1;
    let attacks_exercised = !overload || attacks_pass(&pairs[0].1, &pairs[1].1, &pairs[3].1);
    let controllers_current = ui_pairs.iter().all(|(_, m)| !m.unresolved);
    let passed = cohort_pass(
        seconds,
        offered,
        within_observation,
        missed,
        exchange_latencies.len(),
        exchange_p95_ns,
    ) && attacks_exercised
        && normal.iter().all(|m| m.controller_offers_seen_refused == 0)
        && distinct_events.len() == committed
        && controllers_current
        && (!overload
            || (moderator.committed == 2 && moderator.completion_ms.iter().all(|ms| *ms < 1000)));
    emit(
        json!({"case":"NativeLoadPhaseResult","phase":phase,"passed":passed,"offered":offered,"committed":committed,
        "observationBootMs":hrc::clock::boot_ms().ok(),
        "committedWithinMeasurementWindow":in_window,"distinctCommittedEvents":distinct_events.len(),"missedOffers":missed,"commitsPerSecond":in_window as f64/seconds as f64,
        "committedAfterOfferWindow":committed-in_window,"offeredNormalPerSecond":5,
        "uncommittedAtOfferWindowEnd":offered-in_window,
        "committedWithinObservationBound":within_observation,
        "cohortObservationElapsedMs":millis(completed_at.saturating_duration_since(start)),
        "cohortObservationTailMs":millis(completed_at.saturating_duration_since(window.offer_end())),
        "maximumCohortObservationTailSeconds":COHORT_OBSERVATION_SECONDS,
        "cohortCommitsPerElapsedSecond":committed as f64/completed_at.duration_since(start).as_secs_f64(),
        "overloadPressureScheduledThroughCohortObservation":overload,
        "supportJoinAfterPressureMs":millis(completed_at.saturating_duration_since(pressure_ended)),
        "offersCurrentlyRejectedOrRefused":rejected,"fractionStartedOffersRejectedOrRefused":if started==0 {None} else {Some(rejected as f64/started as f64)},
        "uncommittedFractionOfOffered":(offered-committed) as f64/offered as f64,
        "p95MessageExchangeMs":exchange_ms(exchange_p95_ns),
        "p50MessageExchangeMs":exchange_ms(percentile(&exchange_latencies,50)),
        "maximumMessageExchangeMs":exchange_ms(exchange_latencies.iter().max().copied()),"messageExchangeSamples":exchange_latencies.len(),
        "messageExchangeCoverageComplete":exchange_latencies.len()==offered,
        "messageExchangeP95WithinLimit":exchange_p95_ns.map(|ns|ns<MESSAGE_EXCHANGE_LIMIT_NS),
        "committedWithoutDirectExchangeSample":committed.saturating_sub(exchange_latencies.len()),
        "p95ScheduledToObservedCommitMs":percentile(&completion_latencies,95),
        "p50ScheduledToObservedCommitMs":percentile(&completion_latencies,50),
        "maximumScheduledToObservedCommitMs":completion_latencies.iter().max(),
        "attacksExercised":attacks_exercised,"allEightControllersCurrentAndResolved":controllers_current,
        "messageExchangeBoundary":"already-encoded message write on authenticated stream to complete valid committed-ack payload receipt",
        "messageExchangeExcludes":"connection setup, queueing, local persistence, frame encoding, response decoding and UI work",
        "scheduledToObservedCommitIncludesClientWork":true,"controllerMetrics":ui_pairs.iter().map(|(_,m)|m).collect::<Vec<_>>(),
        "supportingEndpointMetrics":pairs.iter().map(|(_,m,_)|m).collect::<Vec<_>>(),
        "byteAccounting":"Controller bytes are unobserved; supporting sessions count signed actions and decoded response CBOR only"}),
    );
    (
        ui_pairs.into_iter().map(|(u, _)| u).collect(),
        pairs.into_iter().map(|(e, _, _)| e).collect(),
        passed,
        pressure_ended,
    )
}
fn attacks_pass(flood: &Metrics, queries: &Metrics, slow: &Metrics) -> bool {
    // A disconnected hostile stream stops its remaining schedule. Earlier
    // refusals cannot establish sustained pressure for the whole phase.
    !flood.unresolved
        && !queries.unresolved
        && !slow.unresolved
        && flood.started > 8
        && queries.started > 1
        && flood.results.contains_key("Rejected:Denied:RoomSilenced")
        && flood.pressure_cost_refusals > 0
}
fn cohort_pass(
    seconds: u64,
    offered: usize,
    cohort_committed: usize,
    missed: usize,
    exchange_samples: usize,
    exchange_p95_ns: Option<u64>,
) -> bool {
    offered == seconds as usize * 5
        && cohort_committed == offered
        && missed == 0
        && exchange_samples == offered
        && exchange_p95_ns.is_some_and(|ns| ns < MESSAGE_EXCHANGE_LIMIT_NS)
}
fn check_filter(c: &mut Client, room: RoomId, subject: AccountId, end: Instant) -> Result<()> {
    let outcome = operation(
        c,
        Operation::HistoryPage,
        Target::Room(room),
        &messaging::Page {
            cursor: None,
            limit: 50,
        },
        end,
    )?;
    let Outcome::Result { body } = outcome else {
        return Err("FilteredHistoryUnavailable".into());
    };
    let page: messaging::PageResult = body.deserialized().map_err(|_| "HistoryShape")?;
    ensure(
        page.events
            .iter()
            .all(|e| e.actor.acting().account != subject),
        "IgnoredHistoryLeak",
    )?;
    let mut search = query();
    search.terms = vec!["loadmarker".into()];
    search.sender = Some(subject);
    let outcome = operation(c, Operation::SearchQuery, Target::Room(room), &search, end)?;
    let Outcome::Result { body } = outcome else {
        return Err("FilteredSearchUnavailable".into());
    };
    let page: messaging::PageResult = body.deserialized().map_err(|_| "SearchShape")?;
    ensure(page.events.is_empty(), "IgnoredSearchLeak")
}
struct RecoveryWindow {
    began: Instant,
    deadline: Instant,
}
impl RecoveryWindow {
    fn new(overall: Instant, pressure_ended: Instant) -> Self {
        Self {
            began: pressure_ended,
            deadline: overall.min(pressure_ended + Duration::from_secs(30)),
        }
    }
    fn expired(&self, now: Instant) -> bool {
        now >= self.deadline
    }
}
fn recovery(
    controllers: &mut [Interactive],
    supporting: &mut [Endpoint],
    room: RoomId,
    overall: Instant,
    pressure_ended: Instant,
) -> Result<bool> {
    let window = RecoveryWindow::new(overall, pressure_ended);
    emit(
        json!({"case":"NativeLoadRecoveryStarted","phase":"recovery",
        "observationBootMs":hrc::clock::boot_ms().ok()}),
    );
    let mut probes = [None; 5];
    let mut last_health = Instant::now();
    let mut received = [false; 8];
    while !window.expired(Instant::now()) {
        let mut all_current = true;
        for ui in controllers.iter_mut() {
            let view = observe(ui, room);
            let ready = current(&view, room) && ui.offers.iter().all(|o| o.terminal);
            all_current &= ready;
            if ui.index < 5 && probes[ui.index].is_none() && ready {
                let scheduled = Instant::now();
                dispatch_offer(ui, room, scheduled, format!("recovery marker{}", ui.index))
                    .map_err(|_| "RecoveryDispatch")?;
                probes[ui.index] = Some(ui.offers.len() - 1);
            }
        }
        let markers: BTreeSet<_> = controllers
            .iter()
            .take(5)
            .filter_map(|u| probes[u.index].and_then(|i| u.offers[i].event))
            .collect();
        for ui in controllers.iter() {
            let v = ui.controller.snapshot();
            received[ui.index] = current(&v, room)
                && v.selected.as_ref().is_some_and(|r| {
                    r.events.iter().any(|e| {
                        markers.contains(&e.event) && e.actor.acting().account != v.account
                    })
                });
        }
        if markers.len() == 5 && all_current && received.iter().all(|v| *v) {
            break;
        }
        if last_health.elapsed() >= Duration::from_secs(8) {
            for e in supporting.iter_mut().filter(|e| e.index != 11) {
                let _ = health(&mut e.client);
            }
            last_health = Instant::now();
        }
        thread::sleep(Duration::from_millis(10));
    }
    let results:Vec<_> = controllers.iter_mut().map(|ui| {
        let view = observe(ui,room);
        let unresolved = ui.offers.iter().filter(|o|!o.terminal).count();
        let probe = if ui.index<5 {probes[ui.index].is_some_and(|i|ui.offers[i].committed_at.is_some())} else {true};
        json!({"endpoint":ui.index,"passed":current(&view,room) && unresolved==0 && probe && received[ui.index],
            "current":current(&view,room),"unresolvedOffers":unresolved,"freshRemoteRecoveryMarker":received[ui.index],
            "status":view.status.as_ref().map(|s|&s.code)})
    }).collect();
    let elapsed = millis(window.began.elapsed());
    let passed = results.iter().all(|r| r["passed"] == true) && elapsed < 30000;
    emit(
        json!({"case":"NativeLoadRecoveryResult","passed":passed,"elapsedMs":elapsed,"limitMs":30000,
        "observationBootMs":hrc::clock::boot_ms().ok(),
        "clockStartsAtAttackStop":true,"productControllerResolvesOriginalEffects":true,"helperEffectResubmissions":0,"endpointResults":results}),
    );
    Ok(passed)
}
fn malformed(c: &mut Client, oversized: bool, end: Instant) -> Result<()> {
    reconnect(c, end)?;
    let stream = net(c.session())?.stream_handle();
    let bytes = if oversized {
        vec![255, 255, 255, 255, FrameKind::Action as u8]
    } else {
        vec![0, 0, 0, 2, FrameKind::Action as u8, 255]
    };
    stream
        .send_all(&bytes, Duration::from_secs(2))
        .map_err(|_| "InvalidInputSend")?;
    let began = Instant::now();
    let mut output = 0;
    let mut closed = false;
    while began.elapsed() < Duration::from_secs(5) {
        match stream.wait_readable(Duration::from_millis(200)) {
            Ok(false) => continue,
            Err(hrc::hypernet::Error::Closed) => {
                closed = true;
                break;
            }
            Err(_) => return Err("MalformedTransportUnavailable".into()),
            Ok(true) => {
                match stream.recv_exact(&mut [0; 1], Duration::from_secs(1)) {
                    Err(hrc::hypernet::Error::Closed) => {
                        closed = true;
                        break;
                    }
                    Err(_) => return Err("MalformedReadDeadlineOrAuthority".into()),
                    Ok(()) => output += 1,
                }
                ensure(output <= 64, "UnexpectedMalformedOutput")?;
            }
        }
    }
    c.disconnect();
    emit(
        json!({"case":"NativeLoadMalformed","oversized":oversized,"closed":closed,"elapsedMs":millis(began.elapsed()),
        "inputFrameBytes":bytes.len(),"observedOutputBytes":output}),
    );
    ensure(closed, "MalformedStreamNotClosed")
}
fn loops(endpoints: &mut [Endpoint], room: RoomId, end: Instant) -> Result<()> {
    for i in [0, 8, 9] {
        if health(&mut endpoints[i].client).is_err() {
            reconnect(&mut endpoints[i].client, end)?;
        }
    }
    let root = committed(send_exact(
        &mut endpoints[0].client,
        room,
        &message("agent root".into()),
        end,
    )?)?
    .0
    .ok_or("RootEvent")?;
    let reply = |cause| messaging::Send {
        text: "bounded agent reply".into(),
        mentions: vec![],
        parent: Some(cause),
        causation: Some(cause),
    };
    let first = committed(send_exact(
        &mut endpoints[8].client,
        room,
        &reply(root),
        end,
    )?)?
    .0
    .ok_or("AgentEvent")?;
    let repeated = send_exact(&mut endpoints[8].client, room, &reply(root), end)?;
    ensure(
        matches!(repeated, Outcome::Rejected {code:ErrorCode::Denied, ref detail} if detail == "AgentTriggerRepeated"),
        "AgentDuplicateTrigger",
    )?;
    let mut cause = first;
    for actor in [9, 8, 9] {
        cause = committed(send_exact(
            &mut endpoints[actor].client,
            room,
            &reply(cause),
            end,
        )?)?
        .0
        .ok_or("AgentEvent")?;
    }
    let rejected = send_exact(&mut endpoints[8].client, room, &reply(cause), end)?;
    ensure(
        matches!(rejected, Outcome::Rejected {code:ErrorCode::Denied, ref detail} if detail == "AgentDepth"),
        "AgentDepthBound",
    )?;
    emit(
        json!({"case":"NativeLoadAgentChain","passed":true,"maximumCommittedDepth":4,"repeatedTriggerRejected":true,
        "defaultBotResponseSuppressionRetested":false}),
    );
    Ok(())
}
fn churn(endpoints: &mut [Endpoint], room: RoomId, overall: Instant) -> Result<()> {
    let end = overall.min(Instant::now() + Duration::from_secs(45));
    let mut observations = Vec::new();
    let mut passed = true;
    for attempt in 0..4 {
        if Instant::now() >= end {
            passed = false;
            break;
        }
        let c = &mut endpoints[11].client;
        c.disconnect();
        let began = Instant::now();
        // Each is one offered connection, without an additional helper retry loop.
        let result = c.connect();
        let tolerated = result.is_ok() || result.as_ref().err().is_some_and(|e| delay(e).is_some());
        let connection_ms = millis(began.elapsed());
        c.disconnect();
        let began = Instant::now();
        let send = normal_send(
            &mut endpoints[0].client,
            room,
            format!("unaffected churn{attempt}"),
            &mut Metrics::default(),
        );
        let committed = matches!(
            send,
            Ok(Response {
                outcome: Outcome::Committed { .. },
                ..
            })
        );
        observations.push(json!({"attempt":attempt,"connected":result.is_ok(),"connectionMs":connection_ms,
            "refusal":result.err().map(|e| e.code()),"unaffectedCommitted":committed,"unaffectedCommitMs":millis(began.elapsed())}));
        passed &= tolerated && committed;
        thread::sleep(Duration::from_millis(500));
    }
    passed &= observations.len() == 4 && Instant::now() < end;
    emit(
        json!({"case":"NativeLoadConnectionChurn","passed":passed,"offeredConnections":4,
        "observations":observations,"concurrentConnectionsFromChurnEndpoint":1}),
    );
    ensure(passed, "ConnectionChurnUnavailable")
}
fn run(args: &Arguments) -> Result<bool> {
    ensure(
        args.maximum_seconds > 0 && args.maximum_seconds <= 360,
        "HelperDeadlineBound",
    )?;
    let request: Request =
        serde_json::from_slice(&files::read(&args.request, 16384).map_err(|_| "RequestFile")?)
            .map_err(|_| "RequestShape")?;
    ensure(
        request.profiles.len() == 12,
        "TwelveExplicitProfilesRequired",
    )?;
    let end = Instant::now() + Duration::from_secs(args.maximum_seconds);
    emit(json!({"case":"NativeLoadStarted","phase":"setup","maximumSeconds":args.maximum_seconds}));
    let mut endpoints = Vec::new();
    for (index, path) in request.profiles.iter().enumerate() {
        emit(json!({"case":"NativeLoadSetupStep","endpoint":index,"operation":"OpenProfile"}));
        let client = net(Client::open_offline(path))?;
        endpoints.push(Endpoint { index, client });
    }
    ensure(
        endpoints
            .iter()
            .map(|e| e.client.profile.registration.account)
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == 12,
        "DistinctAccounts",
    )?;
    ensure(
        endpoints
            .iter()
            .map(|e| e.client.profile.registration.endpoint_key)
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            == 12,
        "DistinctEndpointKeys",
    )?;
    for endpoint in &endpoints {
        let registration = &endpoint.client.profile.registration;
        let expected_agent = matches!(endpoint.index, 8 | 9);
        ensure(
            matches!(registration.classification, AccountClass::Agent { .. }) == expected_agent,
            "PilotAccountClass",
        )?;
        if let AccountClass::Agent { operator } = registration.classification {
            ensure(
                operator
                    == endpoints[endpoint.index + 2]
                        .client
                        .profile
                        .registration
                        .account,
                "PilotOperatorBinding",
            )?;
        }
    }
    // Interactive profiles start directly in the production Controller. Opening
    // eight temporary streams first would exceed the reserved transition budget.
    let mut supporting = endpoints.split_off(8);
    drop(endpoints);
    for index in 0..supporting.len() {
        reconnect(
            &mut supporting[index].client,
            end.min(Instant::now() + Duration::from_secs(45)),
        )?;
        for endpoint in &mut supporting[..=index] {
            let _ = health(&mut endpoint.client);
        }
    }
    let create = operation(
        &mut supporting[2].client,
        Operation::RoomCreate,
        Target::Service,
        &conversations::Create {
            name: "Native pilot load".into(),
            confidentiality: RoomConfidentiality::Community,
        },
        end,
    )?;
    let body: messaging::Committed = committed(create)?
        .1
        .deserialized()
        .map_err(|_| "CreatedRoom")?;
    let room = body.room.ok_or("CreatedRoom")?;
    for endpoint in &mut supporting {
        if endpoint.index != 10 {
            emit(
                json!({"case":"NativeLoadSetupStep","endpoint":endpoint.index,"operation":"JoinRoom"}),
            );
            committed(operation(
                &mut endpoint.client,
                Operation::RoomJoin,
                Target::Room(room),
                &Value::Map(vec![]),
                end,
            )?)?;
        }
    }
    let subject = supporting[0].client.profile.registration.account;
    let readiness_end = end.min(Instant::now() + Duration::from_secs(45));
    let controllers = open_controllers(
        &request.profiles,
        room,
        subject,
        &mut supporting,
        readiness_end,
    )?;
    let readiness = (|| {
        let marker = committed(send_exact(
            &mut supporting[0].client,
            room,
            &message("loadmarker visible only to non-ignoring recipients".into()),
            readiness_end,
        )?)?
        .0
        .ok_or("LoadMarkerEvent")?;
        let mut marker_query = query();
        marker_query.terms = vec!["loadmarker".into()];
        marker_query.sender = Some(subject);
        let result = operation(
            &mut supporting[2].client,
            Operation::SearchQuery,
            Target::Room(room),
            &marker_query,
            readiness_end,
        )?;
        let Outcome::Result { body } = result else {
            return Err("MarkerSearchUnavailable".into());
        };
        let page: messaging::PageResult = body.deserialized().map_err(|_| "MarkerSearchShape")?;
        ensure(
            page.events.iter().any(|e| e.event == marker),
            "UnfilteredMarkerMissing",
        )?;
        // The marker exists before checking the production recipient's filtered view.
        let recipient = &controllers[7].controller;
        ensure(
            Instant::now() < readiness_end,
            "EightControllerReadinessDeadline",
        )?;
        let refresh = recipient
            .dispatch(Command::Refresh)
            .map_err(|_| "FilteredRefreshDispatch")?;
        wait_command(recipient, refresh, readiness_end)?;
        let view = recipient.snapshot();
        ensure(current(&view, room), "FilteredHistoryUnavailable")?;
        ensure(
            view.selected
                .as_ref()
                .is_some_and(|r| r.events.iter().all(|e| e.actor.acting().account != subject)),
            "IgnoredHistoryLeak",
        )?;
        let mut filtered_query = query();
        filtered_query.terms = vec!["loadmarker".into()];
        filtered_query.sender = Some(subject);
        ensure(
            Instant::now() < readiness_end,
            "EightControllerReadinessDeadline",
        )?;
        let search = recipient
            .dispatch(Command::Search(filtered_query))
            .map_err(|_| "FilteredSearchDispatch")?;
        wait_command(recipient, search, readiness_end)?;
        ensure(
            recipient.snapshot().search.as_ref().is_some_and(|s| {
                s.room == room && !s.running && !s.cancelled && s.events.is_empty()
            }),
            "IgnoredSearchLeak",
        )?;
        for endpoint in &mut supporting {
            emit(
                json!({"case":"NativeLoadSetupStep","endpoint":endpoint.index,"operation":"ServiceInspect"}),
            );
            let result = operation(
                &mut endpoint.client,
                Operation::ServiceInspect,
                Target::Service,
                &Value::Map(vec![]),
                readiness_end,
            );
            pilot_support_current(endpoint.index, result)?;
        }
        await_pilot_readiness(
            readiness_end,
            Duration::from_secs(8),
            |stopped| {
                for endpoint in &mut supporting {
                    if stopped.load(Ordering::Acquire) || Instant::now() >= readiness_end {
                        break;
                    }
                    let _ = health(&mut endpoint.client);
                }
            },
            || {
                controllers
                    .iter()
                    .all(|ui| current(&ui.controller.snapshot(), room))
            },
        )
    })();
    if let Err(error) = readiness {
        emit(
            json!({"case":"NativeLoadControllerReadiness", "passed":false,
            "stage":"PilotEntry", "code":error,
            "bootMs":hrc::clock::boot_ms().ok(),
            "states":controllers.iter().map(|ui|
                readiness_state(ui.index, &ui.controller.snapshot(), room)
            ).collect::<Vec<_>>()}),
        );
        return Err(error);
    }
    emit(
        json!({"case":"NativeLoadPilotReady","phase":"baseline","authenticatedStreams":12,
        "productionControllers":8,"backgroundRefreshEnabled":true,"room":room}),
    );
    let (controllers, supporting, baseline, _) =
        run_phase(controllers, supporting, room, 30, false);
    let (mut controllers, mut supporting, overload, pressure_ended) =
        run_phase(controllers, supporting, room, 45, true);
    let recovered = recovery(&mut controllers, &mut supporting, room, end, pressure_ended)?;
    for mut ui in controllers {
        ui.controller.shutdown();
        drop(ui);
    }
    let mut endpoints = Vec::new();
    for (index, path) in request.profiles.iter().take(8).enumerate() {
        endpoints.push(Endpoint {
            index,
            client: net(Client::open_offline(path))?,
        });
    }
    endpoints.extend(supporting);
    reconnect(&mut endpoints[0].client, end)?;
    reconnect(&mut endpoints[7].client, end)?;
    // Targeted invalid traffic cannot alter the already measured pilot offered rate.
    let mut checks = Vec::new();
    let filtered = check_filter(&mut endpoints[7].client, room, subject, end);
    checks.push(json!({"case":"ignore","passed":filtered.is_ok(),"error":filtered.err()}));
    for oversized in [false, true] {
        let result = malformed(&mut endpoints[11].client, oversized, end);
        checks.push(json!({"case":if oversized {"oversized"} else {"malformed"},"passed":result.is_ok(),"error":result.err()}));
    }
    let churn = churn(&mut endpoints, room, end);
    checks.push(json!({"case":"connectionChurn","passed":churn.is_ok(),"error":churn.err()}));
    let chain = loops(&mut endpoints, room, end);
    checks.push(json!({"case":"agentChain","passed":chain.is_ok(),"error":chain.err()}));
    let passed = baseline && overload && recovered && checks.iter().all(|v| v["passed"] == true);
    for endpoint in &mut endpoints {
        endpoint.client.disconnect();
    }
    emit(
        json!({"case":"NativeLoadSummary","phase":"complete","passed":passed,"baselinePassed":baseline,
        "overloadPassed":overload,"recoveryPassed":recovered,"boundaryChecks":checks,
        "productionControllers":8,"backgroundRefreshEnabled":true,"rssGateEvaluatedByParent":true,"simultaneousFederationQualified":false,"internalQueueOccupancyMeasured":false}),
    );
    Ok(passed)
}
fn main() {
    let args = Arguments::parse();
    let finished = Arc::new(AtomicBool::new(false));
    let watcher = finished.clone();
    let maximum = args.maximum_seconds.min(360);
    thread::spawn(move || {
        let end = Instant::now() + Duration::from_secs(maximum);
        while !watcher.load(Ordering::Acquire) {
            if Instant::now() >= end {
                emit(json!({"case":"NativeLoadDeadline","passed":false}));
                std::process::exit(124);
            }
            thread::sleep(Duration::from_millis(100));
        }
    });
    let result = run(&args);
    finished.store(true, Ordering::Release);
    match result {
        Ok(true) => (),
        Ok(false) => std::process::exit(1),
        Err(code) => {
            emit(json!({"case":"NativeLoadFailure","passed":false,"code":code}));
            std::process::exit(1);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn flood_action(number: u8) -> Action {
        let id = |n| Id::from_bytes([n; 32]);
        let home = ServiceId {
            network: NetworkId {
                network: id(1),
                incarnation: id(2),
            },
            service: id(3),
        };
        Action {
            home,
            operation_id: OperationId {
                window: id(4),
                operation: id(number),
            },
            actor: Actor::Direct {
                acting: EndpointActor {
                    account: AccountId {
                        origin: home.network,
                        local: id(5),
                    },
                    endpoint: id(6),
                    security_generation: 1,
                    enrolment_generation: 1,
                    binding_digest: id(7),
                },
            },
            target: Target::Room(RoomId { home, local: id(8) }),
            operation: Operation::MessageSend,
            body: Value::serialized(&message("pressure".into())).unwrap(),
            expected: BTreeMap::new(),
            approval: None,
            agreement: None,
        }
    }
    fn flood_reply(action: &Action) -> Response {
        Response {
            home: action.home,
            operation_id: action.operation_id,
            action_digest: action_digest(action).unwrap(),
            outcome: Outcome::Refused {
                code: ErrorCode::RateLimited,
                detail: "OperationBudget".into(),
                retry_after_ms: Some(1000),
            },
        }
    }
    #[test]
    fn flood_window_stays_bounded_until_an_exact_reply_frees_capacity() {
        let mut pending = FloodPending {
            home: flood_action(10).home,
            actions: BTreeMap::new(),
        };
        for number in 10..18 {
            pending.insert(&flood_action(number)).unwrap();
        }
        assert!(pending.insert(&flood_action(18)).is_err());
        assert!(pending.insert(&flood_action(10)).is_err());
        // Replies can arrive out of order; a later exact reply frees just its slot.
        let reply = flood_reply(&flood_action(17));
        pending.accept(&reply).unwrap();
        assert!(pending.accept(&reply).is_err());
        pending.insert(&flood_action(18)).unwrap();
        assert_eq!(pending.actions.len(), FLOOD_PENDING_LIMIT);
    }
    #[test]
    fn flood_rejects_substitution_without_losing_the_original_outstanding_request() {
        let action = flood_action(10);
        let mut pending = FloodPending {
            home: action.home,
            actions: BTreeMap::new(),
        };
        pending.insert(&action).unwrap();
        for field in 0..3 {
            let mut reply = flood_reply(&action);
            let wrong = Id::from_bytes([99; 32]);
            match field {
                0 => reply.home.service = wrong,
                1 => reply.operation_id.operation = wrong,
                _ => reply.action_digest = wrong,
            }
            assert!(pending.accept(&reply).is_err());
            assert_eq!(pending.actions.len(), 1);
        }
        pending.accept(&flood_reply(&action)).unwrap();
        assert!(pending.actions.is_empty());
    }
    fn setup_fixture() -> (SetupEffect, client::Delivery, client::Completion) {
        let id = |n| Id::from_bytes([n; 32]);
        let room = RoomId {
            home: ServiceId {
                network: NetworkId {
                    network: id(1),
                    incarnation: id(2),
                },
                service: id(3),
            },
            local: id(4),
        };
        (
            SetupEffect::new(7, Operation::RoomJoin, Some(room)),
            client::Delivery {
                exchange_ns: None,
                abandoned: false,
                held: false,
                request_id: Some(7),
                operation: Operation::RoomJoin,
                operation_id: OperationId {
                    window: id(5),
                    operation: id(6),
                },
                action_digest: id(7),
                room: Some(room),
                outcome: Some(Outcome::Refused {
                    code: ErrorCode::Unavailable,
                    detail: "CurrentAuthorityUnavailable".into(),
                    retry_after_ms: Some(1000),
                }),
            },
            client::Completion {
                request_id: 7,
                error: Some(client::Status {
                    request_id: Some(7),
                    code: "OperationTemporarilyUnavailable".into(),
                    detail: "The original attempt was refused.".into(),
                }),
            },
        )
    }
    fn setup_commit() -> Outcome {
        Outcome::Committed {
            event: None,
            position: 1,
            body: Value::Null,
        }
    }
    #[test]
    fn staging_preparation_recovers_lost_transport_before_returning_exact_bytes() {
        let end = Instant::now() + Duration::from_secs(60);
        let (_, delivery, _) = setup_fixture();
        let prepared = (
            delivery.operation_id,
            delivery.action_digest,
            vec![3u8, 5, 8],
        );
        let mut attempts = Vec::new();
        let mut waits = 0;
        let result = prepare_staging_send(
            end,
            |reconnect| {
                attempts.push(reconnect);
                if attempts.len() == 1 {
                    Err(client::Error::Network(client::network::Error::Transport))
                } else {
                    Ok(prepared.clone())
                }
            },
            |original, delay| {
                assert_eq!(original, end);
                assert_eq!(delay, 1000);
                waits += 1;
                Ok(())
            },
        )
        .unwrap();
        assert_eq!(attempts, [false, true]);
        assert_eq!(waits, 1);
        assert_eq!(result, prepared);
    }
    #[test]
    fn staging_preparation_does_not_repeat_permanent_or_storage_failures() {
        for error in [
            client::Error::Storage,
            client::Error::Network(client::network::Error::Authentication),
            client::Error::Refused {
                code: ErrorCode::Denied,
                detail: "CurrentPolicy".into(),
                retry_after_ms: Some(1000),
            },
        ] {
            let code = error.code();
            let mut error = Some(error);
            let mut attempts = 0;
            let result = prepare_staging_send::<()>(
                Instant::now() + Duration::from_secs(60),
                |reconnect| {
                    assert!(!reconnect);
                    attempts += 1;
                    Err(error.take().expect("no preparation retry"))
                },
                |_, _| panic!("permanent preparation error was retried"),
            );
            assert_eq!(result.unwrap_err(), code);
            assert_eq!(attempts, 1);
        }
    }
    #[test]
    fn staging_preparation_keeps_its_original_deadline() {
        let result = prepare_staging_send::<()>(
            Instant::now(),
            |_| panic!("expired preparation was attempted"),
            |_, _| panic!("expired preparation was retried"),
        );
        assert_eq!(result.unwrap_err(), "SendPreparationDeadline");
        let end = Instant::now() + Duration::from_secs(60);
        let mut attempts = 0;
        let result = prepare_staging_send::<()>(
            end,
            |_| {
                attempts += 1;
                Err(client::Error::Network(client::network::Error::Transport))
            },
            |original, _| {
                assert_eq!(original, end);
                Err("OriginalDeadline".into())
            },
        );
        assert_eq!(result.unwrap_err(), "OriginalDeadline");
        assert_eq!(attempts, 1);
    }
    #[test]
    fn setup_effect_accepts_only_its_recovered_commit_despite_old_attempt_error() {
        for operation in [Operation::RoomJoin, Operation::ModerationIgnore] {
            let (mut effect, mut delivery, completion) = setup_fixture();
            effect.operation = operation;
            delivery.operation = operation;
            if operation == Operation::ModerationIgnore {
                effect.room = None;
                delivery.room = None;
            }
            assert!(
                !effect
                    .observe(
                        std::slice::from_ref(&delivery),
                        std::slice::from_ref(&completion)
                    )
                    .unwrap()
            );
            assert_eq!(
                effect.identity,
                Some((delivery.operation_id, delivery.action_digest))
            );
            delivery.outcome = Some(setup_commit());
            assert!(effect.observe(&[delivery], &[completion]).unwrap());
        }
    }
    #[test]
    fn setup_effect_waits_for_retained_unknown_and_typed_temporary_outcomes() {
        let (mut effect, mut delivery, mut completion) = setup_fixture();
        let temporary = [
            ErrorCode::Unavailable,
            ErrorCode::RateLimited,
            ErrorCode::Overloaded,
        ]
        .map(|code| {
            Some(Outcome::Refused {
                code,
                detail: "Temporary".into(),
                retry_after_ms: None,
            })
        });
        for outcome in [None, Some(Outcome::Unknown), Some(Outcome::Absent)]
            .into_iter()
            .chain(temporary)
        {
            delivery.outcome = outcome;
            assert!(
                !effect
                    .observe(
                        std::slice::from_ref(&delivery),
                        std::slice::from_ref(&completion)
                    )
                    .unwrap()
            );
            // Even an apparently successful completion cannot establish commitment.
            completion.error = None;
            assert!(
                !effect
                    .observe(
                        std::slice::from_ref(&delivery),
                        std::slice::from_ref(&completion)
                    )
                    .unwrap()
            );
        }
    }
    #[test]
    fn setup_effect_rejects_terminal_outcomes_and_held_or_abandoned_work() {
        for code in [ErrorCode::Denied, ErrorCode::Expired] {
            for outcome in [
                Outcome::Rejected {
                    code,
                    detail: "CurrentPolicy".into(),
                },
                Outcome::Refused {
                    code,
                    detail: "CurrentPolicy".into(),
                    retry_after_ms: None,
                },
            ] {
                let (mut effect, mut delivery, completion) = setup_fixture();
                delivery.outcome = Some(outcome);
                assert!(effect.observe(&[delivery], &[completion]).is_err());
            }
        }
        for (held, abandoned) in [(true, false), (false, true)] {
            let (mut effect, mut delivery, completion) = setup_fixture();
            delivery.held = held;
            delivery.abandoned = abandoned;
            delivery.outcome = Some(setup_commit());
            assert_eq!(
                effect.observe(&[delivery], &[completion]).unwrap_err(),
                "ControllerSetupHeldOrAbandoned"
            );
        }
        let (mut effect, mut delivery, completion) = setup_fixture();
        delivery.outcome = Some(Outcome::Result { body: Value::Null });
        assert_eq!(
            effect.observe(&[delivery], &[completion]).unwrap_err(),
            "ControllerSetupUnexpectedResult"
        );
    }
    #[test]
    fn setup_effect_binds_request_operation_room_and_original_signed_identity() {
        let (mut effect, mut delivery, _) = setup_fixture();
        delivery.request_id = Some(effect.request + 1);
        delivery.outcome = Some(setup_commit());
        assert!(!effect.observe(&[delivery], &[]).unwrap());
        assert!(effect.identity.is_none());
        for change in 0..5 {
            let (mut effect, mut delivery, completion) = setup_fixture();
            assert!(
                !effect
                    .observe(std::slice::from_ref(&delivery), &[])
                    .unwrap()
            );
            match change {
                0 => delivery.request_id = Some(effect.request + 1),
                1 => delivery.operation = Operation::RoomLeave,
                2 => delivery.room = None,
                3 => delivery.operation_id.operation = Id::from_bytes([9; 32]),
                _ => delivery.action_digest = Id::from_bytes([9; 32]),
            }
            delivery.outcome = Some(setup_commit());
            assert_eq!(
                effect.observe(&[delivery], &[completion]).unwrap_err(),
                "ControllerSetupDeliveryBinding"
            );
        }
        let (mut effect, delivery, _) = setup_fixture();
        assert_eq!(
            effect
                .observe(&[delivery.clone(), delivery], &[])
                .unwrap_err(),
            "ControllerSetupDeliveryBinding"
        );
    }
    #[test]
    fn setup_effect_missing_delivery_does_not_hide_terminal_completion() {
        let (mut effect, _, mut completion) = setup_fixture();
        assert!(!effect.observe(&[], &[]).unwrap());
        assert_eq!(
            effect
                .observe(&[], std::slice::from_ref(&completion))
                .unwrap_err(),
            "ControllerSetup:OperationTemporarilyUnavailable"
        );
        completion.error = None;
        assert_eq!(
            effect
                .observe(&[], std::slice::from_ref(&completion))
                .unwrap_err(),
            "ControllerSetup:CompletionWithoutDelivery"
        );
        completion.request_id += 1;
        assert!(!effect.observe(&[], &[completion]).unwrap());
    }
    #[test]
    fn readiness_observer_progresses_while_a_support_read_is_blocked() {
        let (started, observed) = std::sync::mpsc::channel();
        let (release, blocked) = std::sync::mpsc::channel();
        let mut first = true;
        let result = with_keepalive(
            Instant::now() + Duration::from_secs(2),
            Duration::ZERO,
            move |_| {
                if first {
                    first = false;
                    started.send(()).unwrap();
                    blocked.recv_timeout(Duration::from_secs(1)).unwrap();
                }
            },
            || {
                observed.recv_timeout(Duration::from_secs(1)).unwrap();
                release.send(()).unwrap();
                Ok(7)
            },
        );
        assert_eq!(result.unwrap(), 7);
    }
    #[test]
    fn pilot_readiness_waits_for_transient_recovery_and_rechecks_after_join() {
        let mut observations = 0;
        await_pilot_readiness(
            Instant::now() + Duration::from_secs(10),
            Duration::from_secs(8),
            |_| panic!("short observation must not need a supporting read"),
            || {
                observations += 1;
                observations >= 2
            },
        )
        .unwrap();
        assert_eq!(observations, 3, "recovery is checked again after the join");
    }
    #[test]
    fn pilot_readiness_does_not_accept_persistent_noncurrent_views() {
        // Stale views and retained gaps both fail the unchanged current() predicate.
        // A completed setup command cannot substitute for a current observation.
        let result = await_pilot_readiness(
            Instant::now() + Duration::from_millis(40),
            Duration::from_secs(8),
            |_| panic!("bounded observation must not need a supporting read"),
            || false,
        );
        assert_eq!(result.unwrap_err(), "EightControllerReadinessDeadline");
    }
    #[test]
    fn pilot_readiness_does_not_replace_the_end_consumed_by_support_setup() {
        let result = await_pilot_readiness(
            Instant::now(),
            Duration::ZERO,
            |_| panic!("expired readiness cannot start a supporting read"),
            || panic!("expired readiness cannot accept an earlier current state"),
        );
        assert_eq!(result.unwrap_err(), "EightControllerReadinessDeadline");
    }
    #[test]
    fn pilot_readiness_observes_changes_during_support_join() {
        let (entered, started) = std::sync::mpsc::channel();
        let stale = AtomicBool::new(false);
        let mut first = true;
        let mut observations = 0;
        let end = Instant::now() + Duration::from_secs(10);
        await_pilot_readiness(
            end,
            Duration::ZERO,
            |stopped| {
                if first {
                    first = false;
                    entered.send(()).unwrap();
                    while !stopped.load(Ordering::Acquire) && Instant::now() < end {
                        thread::sleep(Duration::from_millis(1));
                    }
                    stale.store(true, Ordering::Release);
                }
            },
            || {
                observations += 1;
                if observations == 1 {
                    started.recv_timeout(Duration::from_secs(2)).unwrap();
                    return true;
                }
                if observations == 2 {
                    assert!(stale.load(Ordering::Acquire));
                    return false;
                }
                stale.store(false, Ordering::Release);
                true
            },
        )
        .unwrap();
        assert_eq!(observations, 4, "a pre-join snapshot cannot pass the gate");
    }
    #[test]
    fn pilot_entry_requires_a_current_support_result_and_retains_failure_context() {
        assert!(pilot_support_current(8, Ok(Outcome::Result { body: Value::Null })).is_ok());
        for (outcome, expected) in [
            (
                Outcome::Refused {
                    code: ErrorCode::Unavailable,
                    detail: "TransportAuthorityExpired".into(),
                    retry_after_ms: Some(1000),
                },
                "Refused:Unavailable:TransportAuthorityExpired:retryMs=Some(1000)",
            ),
            (
                Outcome::Rejected {
                    code: ErrorCode::Denied,
                    detail: "CurrentAuthority\n".into(),
                },
                "Rejected:Denied:CurrentAuthority",
            ),
            (Outcome::Unknown, "Unknown"),
            (Outcome::Absent, "Absent"),
            (
                Outcome::Committed {
                    event: None,
                    position: 1,
                    body: Value::Null,
                },
                "UnexpectedCommitted",
            ),
        ] {
            assert_eq!(
                pilot_support_current(11, Ok(outcome)).unwrap_err(),
                format!("PilotSessionNotCurrent:endpoint=11:{expected}")
            );
        }
        assert_eq!(
            pilot_support_current(9, Err("OriginalDeadline".into())).unwrap_err(),
            "PilotSessionNotCurrent:endpoint=9:OriginalDeadline"
        );
    }
    #[test]
    fn a_commit_must_bind_the_original_controller_request_and_digest() {
        let id = |n| Id::from_bytes([n; 32]);
        let room = RoomId {
            home: ServiceId {
                network: NetworkId {
                    network: id(1),
                    incarnation: id(2),
                },
                service: id(3),
            },
            local: id(4),
        };
        let offer = || Offer {
            request: 7,
            scheduled: Instant::now(),
            identity: None,
            event: None,
            committed_at: None,
            exchange_ns: None,
            terminal: false,
            seen_refused: false,
            status: "Queued".into(),
        };
        let mut delivery = client::Delivery {
            exchange_ns: None,
            abandoned: false,
            held: false,
            request_id: Some(8),
            operation: Operation::MessageSend,
            operation_id: OperationId {
                window: id(5),
                operation: id(6),
            },
            action_digest: id(7),
            room: Some(room),
            outcome: Some(Outcome::Committed {
                event: Some(id(8)),
                position: 1,
                body: Value::Map(vec![]),
            }),
        };
        let mut wrong_request = offer();
        assert!(!apply_delivery(&mut wrong_request, &delivery, room));
        assert!(wrong_request.committed_at.is_none());
        delivery.request_id = Some(7);
        let mut good = offer();
        assert!(apply_delivery(&mut good, &delivery, room));
        assert!(good.committed_at.is_some());
        let mut substituted = offer();
        delivery.outcome = None;
        apply_delivery(&mut substituted, &delivery, room);
        delivery.action_digest = id(9);
        delivery.outcome = Some(Outcome::Committed {
            event: Some(id(8)),
            position: 1,
            body: Value::Map(vec![]),
        });
        apply_delivery(&mut substituted, &delivery, room);
        assert_eq!(substituted.status, "DeliveryBindingFailed");
        assert!(substituted.committed_at.is_none());
    }
    #[test]
    fn resolver_refusals_remain_separate_from_the_original_effect_outcome() {
        let id = |n| Id::from_bytes([n; 32]);
        let original = OperationId {
            window: id(1),
            operation: id(2),
        };
        let digest = id(3);
        let response = |outcome| Response {
            home: ServiceId {
                network: NetworkId {
                    network: id(4),
                    incarnation: id(5),
                },
                service: id(6),
            },
            operation_id: OperationId {
                window: id(1),
                operation: id(7),
            },
            action_digest: id(8),
            outcome,
        };
        for code in [
            ErrorCode::Unavailable,
            ErrorCode::RateLimited,
            ErrorCode::Overloaded,
        ] {
            assert!(matches!(
                exact_reply(
                    original,
                    digest,
                    response(Outcome::Refused {
                        code,
                        detail: "CurrentAuthorityUnavailable".into(),
                        retry_after_ms: Some(17),
                    })
                )
                .unwrap(),
                ExactReply::RetryResolution {
                    milliseconds: 17,
                    ..
                }
            ));
        }
        for code in [ErrorCode::Denied, ErrorCode::Expired] {
            assert!(
                matches!(exact_reply(original, digest, response(Outcome::Refused {
                code, detail: "CurrentBinding".into(), retry_after_ms: None,
            })), Err(error) if error.starts_with("ResolutionRefused:"))
            );
            assert!(
                matches!(exact_reply(original, digest, response(Outcome::Rejected {
                code, detail: "CurrentBinding".into(),
            })), Err(error) if error.starts_with("ResolutionRejected:"))
            );
        }
        assert!(
            matches!(exact_reply(original, digest, response(Outcome::Unknown)),
            Err(error) if error == "ResolutionUnknown")
        );
        let mut resolved = home::ResolveResult {
            operation_id: original,
            action_digest: digest,
            outcome: Outcome::Committed {
                event: Some(id(9)),
                position: 1,
                body: Value::Null,
            },
        };
        let resolved_response = |value: &home::ResolveResult| {
            response(Outcome::Result {
                body: Value::serialized(value).unwrap(),
            })
        };
        assert!(matches!(
            exact_reply(original, digest, resolved_response(&resolved)).unwrap(),
            ExactReply::Outcome(Outcome::Committed { .. })
        ));
        resolved.operation_id.operation = id(10);
        assert!(
            matches!(exact_reply(original, digest, resolved_response(&resolved)),
            Err(error) if error == "ResolutionBinding")
        );
        resolved.operation_id = original;
        resolved.action_digest = id(11);
        assert!(
            matches!(exact_reply(original, digest, resolved_response(&resolved)),
            Err(error) if error == "ResolutionBinding")
        );
        let mut direct = response(Outcome::Rejected {
            code: ErrorCode::Denied,
            detail: "Membership".into(),
        });
        direct.operation_id = original;
        direct.action_digest = digest;
        assert!(matches!(
            exact_reply(original, digest, direct).unwrap(),
            ExactReply::Outcome(Outcome::Rejected {
                code: ErrorCode::Denied,
                ..
            })
        ));
    }
    #[test]
    fn earlier_refusals_cannot_hide_an_attack_stream_that_stopped_early() {
        let mut flood = Metrics {
            started: 9,
            pressure_cost_refusals: 1,
            results: BTreeMap::from([
                ("Rejected:Denied:RoomSilenced".into(), 1),
                ("Refused:RateLimited".into(), 1),
            ]),
            ..Metrics::default()
        };
        let mut queries = Metrics {
            started: 2,
            ..Metrics::default()
        };
        let mut slow = Metrics::default();
        assert!(attacks_pass(&flood, &queries, &slow));
        flood.unresolved = true;
        flood.missed = 441;
        assert!(!attacks_pass(&flood, &queries, &slow));
        flood.unresolved = false;
        queries.unresolved = true;
        queries.missed = 88;
        assert!(!attacks_pass(&flood, &queries, &slow));
        queries.unresolved = false;
        slow.unresolved = true;
        assert!(!attacks_pass(&flood, &queries, &slow));
    }
    #[test]
    fn supporting_refusal_cannot_qualify_an_unlimited_flood() {
        let (_, delivery, _) = setup_fixture();
        let refusal = Ok(Response {
            home: delivery.room.unwrap().home,
            operation_id: delivery.operation_id,
            action_digest: delivery.action_digest,
            outcome: Outcome::Refused {
                code: ErrorCode::Overloaded,
                detail: "AuthorityAdmissionBusy".into(),
                retry_after_ms: Some(1000),
            },
        });
        let mut flood = Metrics {
            started: 9,
            results: BTreeMap::from([("Rejected:Denied:RoomSilenced".into(), 1)]),
            ..Metrics::default()
        };
        let queries = Metrics {
            started: 2,
            ..Metrics::default()
        };
        let slow = Metrics::default();
        record_result(&mut flood, &refusal);
        assert!(!attacks_pass(&flood, &queries, &slow));
        record_pressure_result(&mut flood, &refusal);
        assert!(attacks_pass(&flood, &queries, &slow));
    }
    #[test]
    fn delayed_support_join_cannot_restart_recovery_time() {
        let stopped = Instant::now();
        let joined = stopped + Duration::from_secs(8);
        let window = RecoveryWindow::new(stopped + Duration::from_secs(90), stopped);
        assert_eq!(
            window.deadline.duration_since(joined),
            Duration::from_secs(22)
        );
        assert!(!window.expired(stopped + Duration::from_secs(29)));
        assert!(window.expired(stopped + Duration::from_secs(30)));
        assert!(window.expired(joined + Duration::from_secs(23)));
        let clipped = RecoveryWindow::new(joined, stopped);
        assert!(clipped.expired(joined));
    }
    #[test]
    fn message_exchange_samples_exclude_controller_wait_and_recovery() {
        let (_, mut delivery, _) = setup_fixture();
        let room = delivery.room.unwrap();
        delivery.operation = Operation::MessageSend;
        delivery.outcome = Some(Outcome::Committed {
            event: Some(Id::from_bytes([8; 32])),
            position: 1,
            body: Value::Null,
        });
        delivery.exchange_ns = Some(250_000_000);
        let offer = || Offer {
            request: 7,
            scheduled: Instant::now() - Duration::from_secs(30),
            identity: None,
            event: None,
            committed_at: None,
            exchange_ns: None,
            terminal: false,
            seen_refused: false,
            status: "Queued".into(),
        };
        let mut direct = offer();
        assert!(apply_delivery(&mut direct, &delivery, room));
        assert_eq!(direct.exchange_ns, Some(250_000_000));
        assert!(direct.committed_at.unwrap() - direct.scheduled >= Duration::from_secs(30));
        delivery.exchange_ns = None;
        let mut recovered = offer();
        assert!(apply_delivery(&mut recovered, &delivery, room));
        assert!(recovered.committed_at.is_some());
        assert_eq!(recovered.exchange_ns, None);
    }
    #[test]
    fn final_offer_keeps_a_bounded_observation_tail_with_pressure() {
        let start = Instant::now();
        let window = PhaseWindow {
            start,
            seconds: 30,
            pending_senders: AtomicUsize::new(1),
        };
        let last_offer = start + Duration::from_millis(29_800);
        let last_commit = last_offer + Duration::from_millis(499);
        assert!(!window.finished(last_commit));
        assert!(last_commit > window.offer_end());
        assert!(cohort_pass(30, 150, 150, 0, 150, Some(499_000_000)));
        window.pending_senders.store(0, Ordering::Release);
        assert!(!window.finished(last_offer));
        assert!(window.finished(last_commit));
        window.pending_senders.store(1, Ordering::Release);
        assert!(!window.finished(window.observation_end() - Duration::from_nanos(1)));
        assert!(window.finished(window.observation_end()));
    }
    #[test]
    fn offered_load_cannot_pass_with_missing_or_slow_commits() {
        assert!(cohort_pass(30, 150, 150, 0, 150, Some(499_999_999)));
        assert!(!cohort_pass(30, 149, 149, 0, 149, Some(1)));
        assert!(!cohort_pass(30, 150, 149, 0, 149, Some(1)));
        assert!(!cohort_pass(30, 150, 150, 1, 150, Some(1)));
        assert!(!cohort_pass(30, 150, 150, 0, 150, Some(500_000_000)));
        assert!(!cohort_pass(30, 150, 150, 0, 150, None));
        assert!(!cohort_pass(30, 150, 150, 0, 149, Some(1)));
        assert_eq!(percentile(&(1..=100).collect::<Vec<_>>(), 95), Some(95));
    }
}
