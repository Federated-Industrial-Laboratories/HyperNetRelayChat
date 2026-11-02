// SPDX-License-Identifier: Apache-2.0
//! Bounded Controller qualification against provisioned native profiles and a live home.
use clap::Parser;
use hrc::{client::*, messaging, protocol::*};
use serde::Deserialize;
use serde_json::json;
use std::{
    cell::{Cell, RefCell},
    collections::BTreeSet,
    ops::{Deref, DerefMut},
    path::Path,
    path::PathBuf,
    sync::{Arc, Mutex},
    thread,
    time::{Duration, Instant},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;
static LAST_OBSERVATION: Mutex<String> = Mutex::new(String::new());

#[derive(Parser)]
struct Arguments {
    #[arg(long)]
    request: PathBuf,
    #[arg(long, default_value_t = 240)]
    maximum_seconds: u64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct Request {
    alice: PathBuf,
    bob: PathBuf,
    agent: PathBuf,
    room: RoomId,
}

struct Probe {
    principal: &'static str,
    controller: Controller,
    backoffs: Cell<u32>,
    last_backoff: RefCell<Option<(u8, String)>>,
    resolved_deliveries: Cell<u32>,
    recovered_selections: Cell<u32>,
    command: Cell<&'static str>,
    phase: Cell<&'static str>,
    request: Cell<Option<u64>>,
    last_state: RefCell<String>,
    trace: RefCell<std::collections::VecDeque<String>>,
}

impl Probe {
    fn open(principal: &'static str, path: &Path) -> Result<Self> {
        Ok(Self {
            principal,
            controller: Controller::open(path).map_err(|error| {
                format!(
                    "principal={principal} command=Open lastVisible={}: {error}",
                    error.code()
                )
            })?,
            backoffs: Cell::new(0),
            last_backoff: RefCell::new(None),
            resolved_deliveries: Cell::new(0),
            recovered_selections: Cell::new(0),
            command: Cell::new("Open"),
            phase: Cell::new("Opening"),
            request: Cell::new(None),
            last_state: RefCell::new(String::new()),
            trace: RefCell::new(Default::default()),
        })
    }
    fn reopen(&mut self, path: &Path) -> Result<()> {
        self.controller = Controller::open(path).map_err(|error| {
            format!(
                "principal={} command=Reopen lastVisible={}: {error}",
                self.principal,
                error.code()
            )
        })?;
        self.command.set("Reopen");
        self.phase.set("Opening");
        self.request.set(None);
        *self.last_backoff.borrow_mut() = None;
        Ok(())
    }
}
impl Deref for Probe {
    type Target = Controller;
    fn deref(&self) -> &Self::Target {
        &self.controller
    }
}
impl DerefMut for Probe {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.controller
    }
}

fn context(controller: &Probe, command: &str, view: &Snapshot) -> String {
    let status = view
        .status
        .as_ref()
        .map(|s| format!("{}: {}", s.code, s.detail));
    let selected = view.selected.as_ref().map_or_else(
        || "selected=none".into(),
        |room| {
            format!(
                "selected={{room={:?},stale={},gap={:?},has_more={}}}",
                room.summary.room, room.stale, room.gap, room.has_more
            )
        },
    );
    format!(
        "principal={} command={command} phase={} request={:?} connection={:?} lastVisible={} {selected} inspectionStale={} privacyPresent={} recent={:?}",
        controller.principal,
        controller.phase.get(),
        controller.request.get(),
        view.connection,
        status.as_deref().unwrap_or("none"),
        view.inspection.stale,
        view.privacy.is_some(),
        controller.trace.borrow()
    )
}

fn command_name(command: &Command) -> &'static str {
    match command {
        Command::Connect => "Connect",
        Command::SelectRoom(_) => "SelectRoom",
        Command::SetNickname(_) => "SetNickname",
        Command::SetRoomPreferences { .. } => "SetRoomPreferences",
        Command::MarkRead { .. } => "MarkRead",
        Command::Send { .. } => "Send",
        Command::Search(_) => "Search",
        Command::OpenEvent { .. } => "OpenEvent",
        Command::SetFilter { .. } => "SetFilter",
        Command::Resynchronise => "Resynchronise",
        Command::Refresh => "Refresh",
        Command::CloseSearch => "CloseSearch",
        Command::SaveDraft { .. } => "SaveDraft",
        Command::CancelSearch => "CancelSearch",
        _ => "OtherCommand",
    }
}

fn snapshot(controller: &Probe) -> Arc<Snapshot> {
    let view = controller.snapshot();
    let state = format!(
        "command={} phase={} request={:?} connection={:?} status={:?}",
        controller.command.get(),
        controller.phase.get(),
        controller.request.get(),
        view.connection,
        view.status
            .as_ref()
            .map(|status| (status.request_id, &status.code))
    );
    if *controller.last_state.borrow() != state {
        let mut trace = controller.trace.borrow_mut();
        if trace.len() == 16 {
            trace.pop_front();
        }
        trace.push_back(format!("bootMs={:?} {state}", hrc::clock::boot_ms().ok()));
        *controller.last_state.borrow_mut() = state;
    }
    *LAST_OBSERVATION.lock().unwrap_or_else(|e| e.into_inner()) =
        context(controller, controller.command.get(), &view);
    let backoff = match &view.connection {
        ConnectionState::Backoff {
            attempt, reason, ..
        } => Some((*attempt, reason.clone())),
        _ => None,
    };
    if backoff.is_some() && *controller.last_backoff.borrow() != backoff {
        controller
            .backoffs
            .set(controller.backoffs.get().saturating_add(1));
    }
    *controller.last_backoff.borrow_mut() = backoff;
    assert!(view.completions.len() <= 64 && view.notifications.len() <= 64);
    assert!(view.rooms.len() <= 256);
    if let Some(room) = &view.selected {
        assert!(room.events.len() <= 256 && room.members.len() <= 32);
    }
    if let Some(search) = &view.search {
        assert!(search.events.len() <= 256);
    }
    view
}

fn wait(
    controller: &Probe,
    label: &str,
    end: Instant,
    test: impl Fn(&Snapshot) -> bool,
) -> Arc<Snapshot> {
    let end = end.min(Instant::now() + Duration::from_secs(40));
    loop {
        let view = snapshot(controller);
        *LAST_OBSERVATION.lock().unwrap_or_else(|e| e.into_inner()) =
            context(controller, label, &view);
        if test(&view) {
            return view;
        }
        assert!(
            Instant::now() < end,
            "{}: observable result deadline",
            context(controller, label, &view)
        );
        thread::sleep(Duration::from_millis(5));
    }
}

fn completion(controller: &Probe, id: u64, label: &str, end: Instant) -> Arc<Snapshot> {
    controller.phase.set("Completion");
    controller.request.set(Some(id));
    let view = wait(controller, label, end, |v| {
        v.completions.iter().any(|c| c.request_id == id)
    });
    let matching: Vec<_> = view
        .completions
        .iter()
        .filter(|c| c.request_id == id)
        .collect();
    assert_eq!(
        matching.len(),
        1,
        "{}: one completion for request {id}",
        context(controller, label, &view)
    );
    view
}

fn completed(controller: &Probe, id: u64, label: &str, end: Instant) -> Arc<Snapshot> {
    let view = completion(controller, id, label, end);
    let completion = view
        .completions
        .iter()
        .find(|c| c.request_id == id)
        .unwrap();
    if let Some(error) = &completion.error {
        assert_eq!(error.request_id, Some(id));
        panic!(
            "{}: request {id} failed: {}: {}",
            context(controller, label, &view),
            error.code,
            error.detail
        );
    }
    view
}

fn dispatch(controller: &Probe, action: Command) -> u64 {
    let label = command_name(&action);
    controller.command.set(label);
    controller.phase.set("Dispatch");
    controller.request.set(None);
    let id = controller.dispatch(action).unwrap_or_else(|error| {
        panic!(
            "{}: dispatch failed: {error}",
            context(controller, label, &snapshot(controller))
        )
    });
    controller.request.set(Some(id));
    id
}

fn command(controller: &Probe, action: Command, end: Instant) -> (u64, Arc<Snapshot>) {
    let end = end.min(Instant::now() + Duration::from_secs(40));
    let label = command_name(&action);
    controller.command.set(label);
    let connect = matches!(action, Command::Connect);
    let selection = match &action {
        Command::SelectRoom(room) => Some(*room),
        _ => None,
    };
    if !matches!(
        action,
        Command::Connect
            | Command::SelectRoom(_)
            | Command::Disconnect
            | Command::SaveDraft { .. }
            | Command::SetPreferences(_)
            | Command::SetRoomPreferences { .. }
            | Command::CancelSearch
            | Command::CloseSearch
    ) {
        online(controller, label, end);
    }
    let id = dispatch(controller, action);
    if !connect && selection.is_none() {
        return (id, completed(controller, id, label, end));
    }
    let view = completion(controller, id, label, end);
    let completion = view
        .completions
        .iter()
        .find(|c| c.request_id == id)
        .unwrap();
    // Successful offline selection exposes stale cached state by design.
    if !connect && completion.error.is_none() {
        return (id, view);
    }
    // Only these commands retain state for automatic read recovery. A transient
    // pre-admission refusal never makes the helper redispatch the command.
    if let Some(error) = &completion.error {
        assert_eq!(error.request_id, Some(id));
        assert_eq!(
            error.code,
            "OperationTemporarilyUnavailable",
            "{}: read recovery refused for request {id}: {}",
            context(controller, label, &view),
            error.detail
        );
    }
    controller.phase.set("ReadRecovery");
    let ready = wait(controller, label, end, |v| {
        assert_ne!(
            v.connection,
            ConnectionState::Offline,
            "{}: automatic connection stopped",
            context(controller, label, v)
        );
        let selected_current = selection.is_none_or(|room| {
            let selected = v.selected.as_ref().unwrap_or_else(|| {
                panic!("{}: selected room was lost", context(controller, label, v))
            });
            assert_eq!(
                selected.summary.room,
                room,
                "{}: selected room changed during recovery",
                context(controller, label, v)
            );
            !selected.stale && selected.gap.is_none()
        });
        v.connection == ConnectionState::Online
            && !v.inspection.stale
            && v.privacy.is_some()
            && selected_current
    });
    if selection.is_some() {
        controller
            .recovered_selections
            .set(controller.recovered_selections.get().saturating_add(1));
    }
    (id, ready)
}

fn online(controller: &Probe, label: &'static str, end: Instant) {
    controller.command.set(label);
    controller.phase.set("BeforeDispatch");
    controller.request.set(None);
    wait(controller, label, end, |view| {
        assert_ne!(
            view.connection,
            ConnectionState::Offline,
            "{}: automatic connection stopped before dispatch",
            context(controller, label, view)
        );
        view.connection == ConnectionState::Online
            && !view.inspection.stale
            && view.privacy.is_some()
    });
}

fn body(event: &Event) -> Option<messaging::Send> {
    event.body.deserialized().ok()
}

fn matching(events: &[Event], text: &str) -> Vec<Event> {
    events
        .iter()
        .filter(|e| body(e).is_some_and(|b| b.text == text))
        .cloned()
        .collect()
}

fn received(controller: &Probe, text: &str, end: Instant) -> Event {
    let view = wait(controller, "live receive", end, |v| {
        v.connection == ConnectionState::Online
            && v.selected
                .as_ref()
                .is_some_and(|r| !r.stale && !matching(&r.events, text).is_empty())
    });
    let events = matching(&view.selected.as_ref().unwrap().events, text);
    assert_eq!(
        events.len(),
        1,
        "one observed event for the submitted effect"
    );
    events[0].clone()
}

fn send(
    controller: &Probe,
    room: RoomId,
    text: &str,
    mentions: Vec<messaging::Mention>,
    parent: Option<Id>,
    end: Instant,
) -> Delivery {
    let end = end.min(Instant::now() + Duration::from_secs(40));
    online(controller, "Send readiness", end);
    let id = dispatch(
        controller,
        Command::Send {
            room,
            text: text.into(),
            mentions,
            parent,
            causation: None,
            action: false,
            grant: None,
        },
    );
    let view = completion(controller, id, "Send", end);
    let original = view
        .deliveries
        .iter()
        .find(|d| d.request_id == Some(id))
        .unwrap_or_else(|| {
            panic!(
                "{}: request {id} has no delivery identity",
                context(controller, "Send", &view)
            )
        })
        .clone();
    let completion = view
        .completions
        .iter()
        .find(|c| c.request_id == id)
        .unwrap();
    let view = if let Some(error) = &completion.error {
        assert_eq!(error.request_id, Some(id));
        let unresolved = matches!(
            original.outcome,
            None | Some(Outcome::Unknown)
                | Some(Outcome::Refused {
                    code: ErrorCode::Unavailable | ErrorCode::RateLimited | ErrorCode::Overloaded,
                    ..
                })
        );
        assert!(
            unresolved
                && matches!(
                    error.code.as_str(),
                    "OperationTemporarilyUnavailable" | "OutcomeUnknown" | "TransportUnavailable"
                ),
            "{}: request {id} failed without a recoverable pending delivery: {}: {}",
            context(controller, "Send", &view),
            error.code,
            error.detail
        );
        let resolved = wait(controller, "Send resolve original identity", end, |v| {
            for delivery in v.deliveries.iter().filter(|d| d.request_id == Some(id)) {
                assert_eq!(
                    delivery.operation_id,
                    original.operation_id,
                    "{}: replacement operation",
                    context(controller, "Send", v)
                );
                assert_eq!(
                    delivery.action_digest,
                    original.action_digest,
                    "{}: replacement digest",
                    context(controller, "Send", v)
                );
                assert!(
                    !delivery.abandoned,
                    "{}: delivery abandoned",
                    context(controller, "Send", v)
                );
                assert!(
                    !matches!(delivery.outcome, Some(Outcome::Rejected { .. }))
                        && !matches!(&delivery.outcome, Some(Outcome::Refused { code, .. })
                            if !matches!(code, ErrorCode::Unavailable | ErrorCode::RateLimited | ErrorCode::Overloaded)),
                    "{}: original effect refused permanently",
                    context(controller, "Send", v)
                );
            }
            v.connection == ConnectionState::Online
                && v.deliveries.iter().any(|d| {
                    d.request_id == Some(id)
                        && d.operation_id == original.operation_id
                        && d.action_digest == original.action_digest
                        && matches!(d.outcome, Some(Outcome::Committed { .. }))
                })
        });
        controller
            .resolved_deliveries
            .set(controller.resolved_deliveries.get().saturating_add(1));
        resolved
    } else {
        view
    };
    let delivery = view
        .deliveries
        .iter()
        .find(|d| d.request_id == Some(id))
        .unwrap();
    assert!(matches!(delivery.outcome, Some(Outcome::Committed { .. })));
    assert!(!delivery.abandoned);
    assert_eq!(delivery.room, Some(room));
    delivery.clone()
}

fn query(term: &str) -> messaging::Search {
    messaging::Search {
        terms: vec![term.into()],
        sender: None,
        represented: None,
        from_ms: None,
        until_ms: None,
        cursor: None,
        limit: 16,
    }
}

fn search(controller: &Probe, term: &str, end: Instant) -> Arc<Snapshot> {
    let (_, view) = command(controller, Command::Search(query(term)), end);
    let result = view.search.as_ref().expect("search view");
    assert!(!result.running && !result.cancelled && !result.has_more);
    view
}

fn mention(account: AccountId, nickname: &str) -> (String, messaging::Mention) {
    let text = format!("@{nickname}");
    let span = messaging::Mention {
        account,
        start: 0,
        end: text.len() as u32,
    };
    (text, span)
}

fn run(args: Arguments) -> Result<serde_json::Value> {
    if !(30..=300).contains(&args.maximum_seconds) {
        return Err("maximum-seconds must be between 30 and 300".into());
    }
    let started = Instant::now();
    let limit = Duration::from_secs(args.maximum_seconds);
    let end = started + limit;
    // A blocked worker or shutdown cannot outlive the fixture's process budget.
    thread::spawn(move || {
        thread::sleep(limit);
        if let Ok(last) = LAST_OBSERVATION.try_lock() {
            eprintln!("native Controller qualification deadline: {last}");
        }
        std::process::exit(124);
    });
    if std::fs::metadata(&args.request)?.len() > 16 * 1024 {
        return Err("request exceeds bound".into());
    }
    let bytes = std::fs::read(args.request)?;
    if bytes.len() > 16 * 1024 {
        return Err("request exceeds bound".into());
    }
    let request: Request = serde_json::from_slice(&bytes)?;
    let mut alice = Probe::open("Alice", &request.alice)?;
    let mut bob = Probe::open("Bob", &request.bob)?;
    let mut agent = Probe::open("Agent", &request.agent)?;
    let accounts = [
        snapshot(&alice).account,
        snapshot(&bob).account,
        snapshot(&agent).account,
    ];
    assert_eq!(accounts.into_iter().collect::<BTreeSet<_>>().len(), 3);
    assert!(matches!(
        snapshot(&alice).classification,
        AccountClass::Human
    ));
    assert!(matches!(snapshot(&bob).classification, AccountClass::Human));
    assert!(
        matches!(snapshot(&agent).classification, AccountClass::Agent { operator } if operator == accounts[0])
    );
    for controller in [&alice, &bob, &agent] {
        assert_eq!(snapshot(controller).connection, ConnectionState::Offline);
        let (_, view) = command(controller, Command::Connect, end);
        assert_eq!(view.connection, ConnectionState::Online);
        assert_eq!(view.home, request.room.home);
        let (_, view) = command(controller, Command::SelectRoom(request.room), end);
        let selected = view.selected.as_ref().unwrap();
        assert!(!selected.stale && selected.gap.is_none() && !selected.has_more);
        assert!(
            accounts
                .iter()
                .all(|a| selected.members.iter().any(|m| m.account == *a))
        );
    }
    command(&alice, Command::SetNickname("Alice界".into()), end);
    command(&bob, Command::SetNickname("Bób界".into()), end);
    command(
        &bob,
        Command::SetRoomPreferences {
            room: request.room,
            preferences: RoomPreferences {
                notifications: NotificationMode::Mentions,
                sound: false,
            },
        },
        end,
    );
    let initial_sequence = snapshot(&bob).selected.as_ref().unwrap().summary.sequence;
    let (_, view) = command(
        &bob,
        Command::MarkRead {
            room: request.room,
            sequence: initial_sequence,
        },
        end,
    );
    assert_eq!(view.selected.as_ref().unwrap().summary.unread, 0);

    let marker = format!("Local{}", Id::random()?.as_hex());
    let (bob_name, bob_mention) = mention(accounts[1], &snapshot(&bob).nickname);
    let text = format!("{bob_name} {marker} café e\u{301} 👩🏽‍🚀 مرحبا");
    let delivery = send(
        &alice,
        request.room,
        &text,
        vec![bob_mention.clone()],
        None,
        end,
    );
    // No Refresh command: the same Controller's ordinary live polling must deliver it.
    let event = received(&bob, &text, end);
    assert_eq!(event.operation_id, delivery.operation_id);
    assert_eq!(event.action_digest, delivery.action_digest);
    assert_eq!(event.actor.acting().account, accounts[0]);
    assert_eq!(body(&event).unwrap().mentions, vec![bob_mention]);
    let view = wait(&bob, "typed mention and unread", end, |v| {
        v.connection == ConnectionState::Online
            && v.selected
                .as_ref()
                .is_some_and(|r| !r.stale && r.summary.unread > 0)
            && v.notifications
                .iter()
                .any(|n| n.event == event.event && n.mention && !n.sound)
    });
    assert!(view.selected.as_ref().unwrap().read_sequence >= initial_sequence);
    let reply = format!("{marker} persistent Bob reply");
    let reply_delivery = send(&bob, request.room, &reply, vec![], Some(event.event), end);
    let reply_event = received(&alice, &reply, end);
    assert_eq!(reply_event.operation_id, reply_delivery.operation_id);
    assert_eq!(reply_event.actor.acting().account, accounts[1]);
    assert_eq!(body(&reply_event).unwrap().parent, Some(event.event));
    let automated = format!("{marker} independent agent");
    send(&agent, request.room, &automated, vec![], None, end);
    let agent_event = received(&bob, &automated, end);
    assert!(
        matches!(agent_event.actor, Actor::IndependentAgent { operator, .. } if operator == accounts[0])
    );

    let (_, view) = command(
        &bob,
        Command::Search(messaging::Search {
            terms: vec![marker.clone(), "CAFÉ".into()],
            ..query(&marker)
        }),
        end,
    );
    assert_eq!(
        matching(&view.search.as_ref().unwrap().events, &text).len(),
        1
    );
    let (_, view) = command(
        &bob,
        Command::OpenEvent {
            room: request.room,
            event: event.event,
        },
        end,
    );
    let context = view.selected.as_ref().unwrap();
    assert_eq!(context.focus, Some(event.event));
    assert!(context.events.len() <= 5 && context.events.iter().any(|e| e.event == event.event));
    command(&bob, Command::SelectRoom(request.room), end);

    command(
        &bob,
        Command::SetFilter {
            subject: accounts[0],
            ignored: Some(true),
            muted: None,
        },
        end,
    );
    command(&bob, Command::Resynchronise, end);
    let hidden = format!("{marker} hidden by current ignore");
    send(&alice, request.room, &hidden, vec![], None, end);
    assert!(
        search(&bob, &hidden, end)
            .search
            .as_ref()
            .unwrap()
            .events
            .is_empty()
    );
    assert_eq!(
        matching(
            &search(&alice, &hidden, end).search.as_ref().unwrap().events,
            &hidden
        )
        .len(),
        1
    );
    command(&bob, Command::Refresh, end);
    assert!(matching(&snapshot(&bob).selected.as_ref().unwrap().events, &hidden).is_empty());
    command(
        &bob,
        Command::SetFilter {
            subject: accounts[0],
            ignored: Some(false),
            muted: None,
        },
        end,
    );
    command(&bob, Command::Resynchronise, end);
    assert_eq!(
        matching(
            &search(&bob, &hidden, end).search.as_ref().unwrap().events,
            &hidden
        )
        .len(),
        1
    );

    let cancel_end = end.min(Instant::now() + Duration::from_secs(40));
    let id = dispatch(&bob, Command::Search(query(&marker)));
    let observed = wait(&bob, "search started or completed", cancel_end, |v| {
        v.search.as_ref().is_some_and(|s| s.running)
            || v.completions.iter().any(|c| c.request_id == id)
    });
    let started_before_cancel = observed.search.as_ref().is_some_and(|s| s.running);
    if started_before_cancel {
        dispatch(&bob, Command::CancelSearch);
    }
    let view = completed(&bob, id, "Search cancellation", cancel_end);
    let cancelled = view.search.as_ref().unwrap().cancelled;
    if cancelled {
        assert!(view.search.as_ref().unwrap().events.is_empty());
    }
    assert!(!view.search.as_ref().unwrap().running);
    // A successful query after cancellation also proves the stream stayed correlated.
    assert!(
        !search(&bob, &marker, end)
            .search
            .as_ref()
            .unwrap()
            .events
            .is_empty()
    );
    command(&bob, Command::CloseSearch, end);

    let before = snapshot(&bob);
    let retained: BTreeSet<_> = before
        .selected
        .as_ref()
        .unwrap()
        .events
        .iter()
        .map(|e| e.event)
        .collect();
    let sequence = before.selected.as_ref().unwrap().summary.sequence;
    command(
        &bob,
        Command::MarkRead {
            room: request.room,
            sequence,
        },
        end,
    );
    bob.command.set("Disconnect");
    bob.phase.set("ReservedControl");
    bob.request.set(None);
    bob.disconnect();
    wait(&bob, "disconnect", end, |v| {
        v.connection == ConnectionState::Offline
    });
    let (alice_name, alice_mention) = mention(accounts[0], &snapshot(&alice).nickname);
    let draft = format!("{alice_name} {marker} offline draft 日本語");
    let (_, saved) = command(
        &bob,
        Command::SaveDraft {
            room: request.room,
            text: draft.clone(),
            mentions: vec![alice_mention.clone()],
        },
        end,
    );
    assert_eq!(saved.selected.as_ref().unwrap().draft, draft);
    assert!(matches!(
        bob.dispatch(Command::SaveDraft {
            room: request.room,
            text: "x".repeat(8193),
            mentions: vec![],
        }),
        Err(DispatchError::Invalid)
    ));
    bob.shutdown();
    let offline_message = format!("{marker} delivered while Bob offline");
    send(&alice, request.room, &offline_message, vec![], None, end);
    bob.reopen(&request.bob)?;
    let (_, cached) = command(&bob, Command::SelectRoom(request.room), end);
    assert_eq!(cached.connection, ConnectionState::Offline);
    let cached_room = cached.selected.as_ref().unwrap();
    assert!(cached_room.stale);
    assert_eq!(cached_room.draft, draft);
    assert_eq!(cached_room.draft_mentions, vec![alice_mention.clone()]);
    assert!(matching(&cached_room.events, &offline_message).is_empty());
    command(&bob, Command::Connect, end);
    let resumed = received(&bob, &offline_message, end);
    let view = snapshot(&bob);
    let current = view.selected.as_ref().unwrap();
    assert!(current.gap.is_none() && !current.stale);
    assert_eq!(current.draft, draft);
    assert!(current.read_sequence >= sequence && current.summary.unread > 0);
    let ids: BTreeSet<_> = current.events.iter().map(|e| e.event).collect();
    assert_eq!(ids.len(), current.events.len());
    assert!(retained.is_subset(&ids) && ids.contains(&resumed.event));
    send(&bob, request.room, &draft, vec![alice_mention], None, end);
    received(&alice, &draft, end);
    assert!(snapshot(&bob).selected.as_ref().unwrap().draft.is_empty());
    for controller in [&mut alice, &mut bob, &mut agent] {
        controller.shutdown();
    }
    Ok(json!({
        "case": "NativeLocalController", "passed": true,
        "elapsedSeconds": started.elapsed().as_secs_f64(), "distinctPrincipals": 3,
        "persistentControllers": true, "completionAndDeliveryCorrelation": true,
        "unicodeTypedMention": true, "unreadAndMentionNotification": true,
        "currentIgnoreFiltering": true, "currentSearchAndContext": true,
        "offlineDraftReopen": true, "resumeWithoutDuplicates": true,
        "cancellation": if cancelled { "observedCancelled" } else { "completedBeforeCancellation" },
        "serverQueryInterruptionClaimed": false, "helperEffectResubmissions": 0,
        "observedBackoffs": alice.backoffs.get().saturating_add(bob.backoffs.get()).saturating_add(agent.backoffs.get()),
        "automaticSelectionRecoveries": alice.recovered_selections.get().saturating_add(bob.recovered_selections.get()).saturating_add(agent.recovered_selections.get()),
        "originalDeliveryResolutions": alice.resolved_deliveries.get().saturating_add(bob.resolved_deliveries.get()).saturating_add(agent.resolved_deliveries.get())
    }))
}

fn main() {
    let prior_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        if let Ok(last) = LAST_OBSERVATION.try_lock() {
            eprintln!("native qualification last observation: {last}");
        }
        prior_hook(info);
    }));
    match run(Arguments::parse()) {
        Ok(result) => println!("{result}"),
        Err(error) => {
            let last = LAST_OBSERVATION.lock().unwrap_or_else(|e| e.into_inner());
            eprintln!("native local Controller: {error}; last observation: {last}");
            std::process::exit(1);
        }
    }
}
