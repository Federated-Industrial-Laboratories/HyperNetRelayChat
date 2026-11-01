// SPDX-License-Identifier: Apache-2.0
//! Bounded Controller qualification against provisioned native profiles and a live home.
use clap::Parser;
use hrc::{client::*, messaging, protocol::*};
use serde::Deserialize;
use serde_json::json;
use std::{
    collections::BTreeSet,
    path::PathBuf,
    sync::Arc,
    thread,
    time::{Duration, Instant},
};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

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

fn snapshot(controller: &Controller) -> Arc<Snapshot> {
    let view = controller.snapshot();
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
    controller: &Controller,
    label: &str,
    end: Instant,
    test: impl Fn(&Snapshot) -> bool,
) -> Arc<Snapshot> {
    let end = end.min(Instant::now() + Duration::from_secs(40));
    loop {
        let view = snapshot(controller);
        assert!(
            !matches!(view.connection, ConnectionState::Backoff { .. }),
            "{label}: unexpected transport backoff"
        );
        if test(&view) {
            return view;
        }
        assert!(Instant::now() < end, "{label}: observable result deadline");
        thread::sleep(Duration::from_millis(5));
    }
}

fn completed(controller: &Controller, id: u64, end: Instant) -> Arc<Snapshot> {
    let view = wait(controller, "command completion", end, |v| {
        v.completions.iter().any(|c| c.request_id == id)
    });
    let matching: Vec<_> = view
        .completions
        .iter()
        .filter(|c| c.request_id == id)
        .collect();
    assert_eq!(matching.len(), 1, "one completion per request");
    if let Some(error) = &matching[0].error {
        assert_eq!(error.request_id, Some(id));
        panic!("request {id} failed: {}: {}", error.code, error.detail);
    }
    view
}

fn command(controller: &Controller, action: Command, end: Instant) -> (u64, Arc<Snapshot>) {
    let id = controller
        .dispatch(action)
        .expect("bounded command admitted once");
    (id, completed(controller, id, end))
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

fn received(controller: &Controller, text: &str, end: Instant) -> Event {
    let view = wait(controller, "live receive", end, |v| {
        v.selected
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
    controller: &Controller,
    room: RoomId,
    text: &str,
    mentions: Vec<messaging::Mention>,
    parent: Option<Id>,
    end: Instant,
) -> Delivery {
    let (id, view) = command(
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
        end,
    );
    let delivery = view
        .deliveries
        .iter()
        .find(|d| d.request_id == Some(id))
        .expect("correlated delivery");
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

fn search(controller: &Controller, term: &str, end: Instant) -> Arc<Snapshot> {
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
        eprintln!("native Controller qualification deadline");
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
    let mut alice = Controller::open(&request.alice)?;
    let mut bob = Controller::open(&request.bob)?;
    let mut agent = Controller::open(&request.agent)?;
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
        v.selected.as_ref().is_some_and(|r| r.summary.unread > 0)
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

    let id = bob.dispatch(Command::Search(query(&marker)))?;
    let observed = wait(&bob, "search started or completed", end, |v| {
        v.search.as_ref().is_some_and(|s| s.running)
            || v.completions.iter().any(|c| c.request_id == id)
    });
    let started_before_cancel = observed.search.as_ref().is_some_and(|s| s.running);
    if started_before_cancel {
        bob.dispatch(Command::CancelSearch)?;
    }
    let view = completed(&bob, id, end);
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
    bob = Controller::open(&request.bob)?;
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
        "serverQueryInterruptionClaimed": false, "effectResubmissions": 0
    }))
}

fn main() {
    match run(Arguments::parse()) {
        Ok(result) => println!("{result}"),
        Err(error) => {
            eprintln!("native local Controller: {error}");
            std::process::exit(1);
        }
    }
}
