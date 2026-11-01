// SPDX-License-Identifier: Apache-2.0
//! Bot cursor/outbox failure contracts use the real encrypted store and signature codec.
use super::*;
use crate::{
    client::outbox,
    clock::TimeBounds,
    messaging,
    storage::{self, Commit, Store},
};
use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt, path::PathBuf};
fn id(n: u8) -> Id {
    Id::from_bytes([n; 32])
}
fn room() -> RoomId {
    RoomId {
        home: ServiceId {
            network: NetworkId {
                network: id(1),
                incarnation: id(2),
            },
            service: id(3),
        },
        local: id(4),
    }
}
fn account(n: u8) -> AccountId {
    AccountId {
        origin: room().home.network,
        local: id(n),
    }
}
fn acting(n: u8) -> EndpointActor {
    EndpointActor {
        account: account(n),
        endpoint: id(n + 1),
        security_generation: 1,
        enrolment_generation: 1,
        binding_digest: id(n + 2),
    }
}
fn reply(window: &RetryWindow) -> VerifiedAction {
    let key = SigningKey::from_bytes(&[10; 32]);
    let action = Action {
        home: room().home,
        operation_id: OperationId {
            window: window.id,
            operation: id(11),
        },
        actor: Actor::IndependentAgent {
            acting: acting(10),
            operator: account(20),
        },
        target: Target::Room(room()),
        operation: Operation::MessageReply,
        body: Value::serialized(&messaging::Send {
            text: "Use !help for room assistance.".into(),
            mentions: vec![],
            parent: Some(id(12)),
            causation: Some(id(12)),
        })
        .unwrap(),
        expected: BTreeMap::new(),
        approval: None,
        agreement: None,
    };
    verify_action(&sign_action(&action, &key).unwrap(), &key.verifying_key()).unwrap()
}
struct Fixture {
    root: PathBuf,
    key: storage::Key,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!("hrc-bot-{}", Id::random().unwrap()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["Data", "Guard"] {
            fs::create_dir(root.join(name)).unwrap();
            fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let key = storage::Key::create(root.join("Key")).unwrap();
        Self { root, key }
    }
    fn store(&self, create: bool) -> Store {
        let mut store = if create {
            Store::create(
                self.root.join("Data"),
                self.root.join("Guard"),
                &self.key,
                [10; 32],
                storage::Limits::default(),
            )
        } else {
            Store::open(
                self.root.join("Data"),
                self.root.join("Guard"),
                &self.key,
                [10; 32],
                storage::Limits::default(),
            )
        }
        .unwrap();
        if create {
            outbox::initialize(&mut store).unwrap();
        }
        store
    }
    fn config(&self) -> Config {
        Config {
            profile: self.root.clone(),
            rooms: vec![room()],
            help: "Use !help for room assistance.".into(),
            poll_interval_ms: 1000,
            grant: None,
            resynchronise: false,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}

#[test]
fn reply_cursor_and_outbox_are_atomic_and_restart_recovers_late_commit() {
    let fixture = Fixture::new();
    let mut store = fixture.store(true);
    let config = fixture.config();
    state::initialise(&mut store, &config).unwrap();
    let window = RetryWindow {
        id: id(9),
        expires_ms: TimeBounds::test_now().upper_ms + 120000,
    };
    let reply = reply(&window);
    let caught_up = Blob(vec![1]);
    let next = Blob(vec![2]);
    assert!(
        state::advance(
            &mut store,
            state::Advance {
                room: room(),
                prior: None,
                cursor: &caught_up,
                live: true,
                reply: Some((&reply, id(12))),
                window: &window,
                now: TimeBounds::test_now()
            }
        )
        .is_err()
    );
    state::advance(
        &mut store,
        state::Advance {
            room: room(),
            prior: None,
            cursor: &caught_up,
            live: true,
            reply: None,
            window: &window,
            now: TimeBounds::test_now(),
        },
    )
    .unwrap();
    store.write(|db|{db.execute_batch("CREATE TRIGGER abort_cursor BEFORE UPDATE OF cursor ON bot_rooms BEGIN SELECT RAISE(ABORT,'fixture'); END;")?;Ok(Commit::new((),b"abort cursor fixture".to_vec()))}).unwrap();
    let before = store.usage().unwrap().commit_counter;
    assert!(
        state::advance(
            &mut store,
            state::Advance {
                room: room(),
                prior: Some(&caught_up),
                cursor: &next,
                live: true,
                reply: Some((&reply, id(12))),
                window: &window,
                now: TimeBounds::test_now()
            }
        )
        .is_err()
    );
    assert_eq!(store.usage().unwrap().commit_counter, before);
    assert_eq!(
        state::room(&mut store, room()).unwrap().cursor.unwrap(),
        caught_up
    );
    assert!(
        outbox::pending(
            &mut store,
            &SigningKey::from_bytes(&[10; 32]).verifying_key()
        )
        .unwrap()
        .is_empty()
    );
    assert!(state::plans(&mut store).unwrap().is_empty());
    store
        .write(|db| {
            db.execute_batch("DROP TRIGGER abort_cursor")?;
            Ok(Commit::new((), b"remove abort fixture".to_vec()))
        })
        .unwrap();
    state::advance(
        &mut store,
        state::Advance {
            room: room(),
            prior: Some(&caught_up),
            cursor: &next,
            live: true,
            reply: Some((&reply, id(12))),
            window: &window,
            now: TimeBounds::test_now(),
        },
    )
    .unwrap();
    let reserved = state::next_reply(&mut store).unwrap();
    drop(store);
    let mut store = fixture.store(false);
    state::initialise(&mut store, &config).unwrap();
    assert_eq!(state::next_reply(&mut store).unwrap(), reserved);
    assert_eq!(
        state::room(&mut store, room()).unwrap().cursor.unwrap(),
        next
    );
    let pending = outbox::pending(
        &mut store,
        &SigningKey::from_bytes(&[10; 32]).verifying_key(),
    )
    .unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].action.signed_bytes(), reply.signed_bytes());
    let signer = SigningKey::from_bytes(&[30; 32]);
    let response = Response {
        home: room().home,
        operation_id: reply.action().operation_id,
        action_digest: reply.digest(),
        outcome: Outcome::Committed {
            event: Some(id(31)),
            position: 1,
            body: Value::Null,
        },
    };
    let response = verify_response(
        &sign_response(&response, &signer).unwrap(),
        &signer.verifying_key(),
    )
    .unwrap();
    outbox::record(&mut store, &reply, &response, TimeBounds::test_now()).unwrap();
    drop(store);
    let mut store = fixture.store(false);
    let plan = state::plans(&mut store).unwrap().pop().unwrap();
    let outcome = outbox::outcome(&mut store, plan.operation, plan.digest)
        .unwrap()
        .unwrap();
    state::complete(&mut store, &plan, &outcome).unwrap();
    assert!(state::plans(&mut store).unwrap().is_empty());
    assert!(matches!(
        outbox::outcome(&mut store, plan.operation, plan.digest).unwrap(),
        Some(Outcome::Committed { .. })
    ));
}

#[test]
fn rule_never_responds_to_agent_actors_or_reply_events() {
    let action = reply(&RetryWindow {
        id: id(9),
        expires_ms: u64::MAX,
    });
    let mut event = Event {
        home: room().home,
        room: room(),
        event: id(12),
        sequence: 1,
        timestamp_ms: 1,
        actor: Actor::Direct { acting: acting(20) },
        operation_id: action.action().operation_id,
        action_digest: action.digest(),
        kind: Operation::MessageSend,
        body: Value::serialized(&messaging::Send {
            text: "!help".into(),
            mentions: vec![],
            parent: None,
            causation: None,
        })
        .unwrap(),
    };
    assert!(runtime::trigger(&event));
    event.kind = Operation::MessageReply;
    assert!(!runtime::trigger(&event));
    event.kind = Operation::MessageSend;
    event.actor = action.action().actor.clone();
    assert!(!runtime::trigger(&event));
    event.actor = Actor::Delegated {
        acting: acting(10),
        operator: account(20),
        represented: account(20),
        represented_security_generation: 1,
        grant: GrantRef {
            id: id(40),
            generation: 1,
        },
    };
    assert!(!runtime::trigger(&event));
}

#[test]
fn encrypted_rule_requires_matching_verified_event_and_original_human_message() {
    use crate::crypto::{ApplicationMessage, EncryptedEvent, EncryptionContext};
    let mut context = EncryptionContext {
        home: room().home,
        room: room(),
        operation_id: OperationId {
            window: id(30),
            operation: id(31),
        },
        actor: Actor::Direct { acting: acting(20) },
        operation: Operation::MessageSend,
        expected: BTreeMap::new(),
        approval: None,
        agreement: None,
        group: id(32),
        epoch: 1,
        parent: None,
        causation: None,
    };
    let content = ApplicationMessage {
        text: " !help ".into(),
        mentions: vec![],
    };
    let event = |context: &EncryptionContext| {
        let ciphertext = vec![1, 2, 3];
        Event {
            home: room().home,
            room: room(),
            event: id(33),
            sequence: 1,
            timestamp_ms: 1,
            actor: context.actor.clone(),
            operation_id: context.operation_id,
            action_digest: action_digest(&context.action(ciphertext.clone()).unwrap()).unwrap(),
            kind: context.operation,
            body: Value::serialized(&EncryptedEvent {
                context: context.clone(),
                ciphertext: Blob(ciphertext),
            })
            .unwrap(),
        }
    };
    assert!(runtime::encrypted_trigger(&event(&context), &content));
    let mut substituted = event(&context);
    substituted.action_digest = id(99);
    assert!(!runtime::encrypted_trigger(&substituted, &content));
    context.causation = Some(id(34));
    assert!(!runtime::encrypted_trigger(&event(&context), &content));
    context.causation = None;
    context.parent = Some(id(34));
    context.operation = Operation::MessageReply;
    assert!(!runtime::encrypted_trigger(&event(&context), &content));
    context.parent = None;
    context.operation = Operation::MessageSend;
    context.actor = Actor::IndependentAgent {
        acting: acting(10),
        operator: account(20),
    };
    assert!(!runtime::encrypted_trigger(&event(&context), &content));
}

#[test]
fn permanent_identity_failures_do_not_enter_reconnect_backoff() {
    use crate::client::{Error as Client, network::Error as Network};
    assert_eq!(
        runtime::retry_delay(&Error::Client(Client::Network(Network::Transport))),
        Some(0)
    );
    assert_eq!(
        runtime::retry_delay(&Error::Client(Client::Network(Network::Connect(
            crate::hypernet::Error::Timeout
        )))),
        Some(0)
    );
    for error in [
        Network::Authentication,
        Network::Frame,
        Network::Expired,
        Network::Connect(crate::hypernet::Error::Refused),
        Network::Connect(crate::hypernet::Error::Protocol),
        Network::Companion(crate::hypernet::Error::Ownership),
    ] {
        assert_eq!(
            runtime::retry_delay(&Error::Client(Client::Network(error))),
            None
        );
    }
    assert_eq!(
        runtime::retry_delay(&Error::RetryLater { delay_ms: 60000 }),
        Some(60000)
    );
    assert_eq!(runtime::retry_delay(&Error::Denied), None);
    assert_eq!(runtime::retry_delay(&Error::PendingOutcome), None);
}

#[test]
fn explicit_resynchronisation_and_configuration_change_do_not_replay_history() {
    let fixture = Fixture::new();
    let mut store = fixture.store(true);
    let mut config = fixture.config();
    state::initialise(&mut store, &config).unwrap();
    let window = RetryWindow {
        id: id(9),
        expires_ms: u64::MAX,
    };
    let cursor = Blob(vec![1]);
    state::advance(
        &mut store,
        state::Advance {
            room: room(),
            prior: None,
            cursor: &cursor,
            live: true,
            reply: None,
            window: &window,
            now: TimeBounds::test_now(),
        },
    )
    .unwrap();
    config.resynchronise = true;
    state::initialise(&mut store, &config).unwrap();
    let resumed = state::room(&mut store, room()).unwrap();
    assert!(!resumed.live);
    assert!(resumed.cursor.is_none());
    config.resynchronise = false;
    config.help = "New help text".into();
    state::initialise(&mut store, &config).unwrap();
    assert!(!state::room(&mut store, room()).unwrap().live);
    assert!(
        Config {
            rooms: vec![room(); 9],
            ..config.clone()
        }
        .validate()
        .is_err()
    );
    assert!(
        Config {
            rooms: (0..3)
                .map(|i| RoomId {
                    local: id(50 + i),
                    ..room()
                })
                .collect(),
            poll_interval_ms: 60000,
            ..config
        }
        .validate()
        .is_err()
    );
}

#[test]
fn initial_readiness_waits_for_every_room_and_the_durable_startup_plan() {
    let fixture = Fixture::new();
    let mut store = fixture.store(true);
    let second = RoomId {
        local: id(5),
        ..room()
    };
    let mut config = fixture.config();
    config.rooms.push(second);
    state::initialise(&mut store, &config).unwrap();
    let delivered = std::cell::Cell::new(0);
    let mut startup =
        runtime::Startup::new(config.rooms.clone(), || delivered.set(delivered.get() + 1));
    startup.connected();
    startup.observe(&mut store, room(), true, false).unwrap();
    startup.observe(&mut store, second, false, false).unwrap();
    assert_eq!(delivered.get(), 0);

    let window = RetryWindow {
        id: id(9),
        expires_ms: TimeBounds::test_now().upper_ms + 120000,
    };
    let mut action = reply(&window).action().clone();
    action.operation = Operation::PresenceSet;
    action.target = Target::Account(action.actor.acting().account);
    action.body = Value::serialized(&crate::identity::Presence {
        status: "Bot startup".into(),
        duration_ms: 60000,
    })
    .unwrap();
    let key = SigningKey::from_bytes(&[10; 32]);
    let action = verify_action(&sign_action(&action, &key).unwrap(), &key.verifying_key()).unwrap();
    state::presence(&mut store, &action, &window, TimeBounds::test_now()).unwrap();
    startup.observe(&mut store, second, true, false).unwrap();
    assert_eq!(
        delivered.get(),
        0,
        "an unresolved durable startup effect prevents readiness"
    );

    let plan = state::plans(&mut store).unwrap().pop().unwrap();
    outbox::abandon(&mut store, plan.operation, plan.digest).unwrap();
    state::abandoned(&mut store, &plan).unwrap();
    startup.connected();
    startup.observe(&mut store, room(), true, false).unwrap();
    assert_eq!(
        delivered.get(),
        0,
        "a previous connection's head cannot satisfy the new connection"
    );
    startup.observe(&mut store, second, true, true).unwrap();
    assert_eq!(delivered.get(), 0, "shutdown cannot emit readiness");
    startup.observe(&mut store, second, true, false).unwrap();
    assert_eq!(delivered.get(), 1);
    startup.connected();
    startup.observe(&mut store, room(), true, false).unwrap();
    startup.observe(&mut store, second, true, false).unwrap();
    assert_eq!(delivered.get(), 1, "the event is emitted only once");
}
