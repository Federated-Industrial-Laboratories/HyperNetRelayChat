use crate::{client::outbox, clock::TimeBounds, home, protocol::*, storage};
use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt, path::PathBuf};
pub(super) struct Fixture {
    pub(super) root: PathBuf,
    key: storage::Key,
}
impl Fixture {
    pub(super) fn new() -> Self {
        let root = std::env::temp_dir().join(format!("hrc-client-{}", Id::random().unwrap()));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["Data", "Guard"] {
            fs::create_dir(root.join(name)).unwrap();
            fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let key = storage::Key::create(root.join("Key")).unwrap();
        Self { root, key }
    }
    pub(super) fn create(&self) -> storage::Store {
        let mut store = storage::Store::create(
            self.root.join("Data"),
            self.root.join("Guard"),
            &self.key,
            [6; 32],
            storage::Limits::default(),
        )
        .unwrap();
        outbox::initialize(&mut store).unwrap();
        store
    }
    pub(super) fn profile(&self) {
        use crate::{
            client,
            service::{self, files},
        };
        let a = action();
        fs::rename(self.root.join("Key"), self.root.join("Database.key")).unwrap();
        let endpoint = files::create_key(&self.root.join("Endpoint.key")).unwrap();
        let profile = client::Profile {
            federation: None,
            agreements: Vec::new(),
            server: service::Descriptor {
                version: 1,
                home: a.home,
                signing_key: Id::from_bytes(
                    SigningKey::from_bytes(&[11; 32]).verifying_key().to_bytes(),
                ),
                protocol: PROTOCOL.into(),
                text_profile: crate::text::PROFILE.into(),
            },
            registration: AccountRegistration {
                home: a.home,
                account: a.actor.represented(),
                endpoint: id(6),
                endpoint_key: Id::from_bytes(endpoint.verifying_key().to_bytes()),
                transport_principal: id(12),
                recovery_key: id(13),
                classification: AccountClass::Human,
                invitation: id(14),
            },
            companion: self.root.join("AbsentCompanion"),
            clock: crate::clock::Config {
                observation: self.root.join("AbsentClock"),
                monitor_key: hex::encode([15; 32]),
            },
        };
        files::create_json(&self.root.join("Profile.json"), &profile).unwrap();
    }
    fn open(&self) -> storage::Store {
        storage::Store::open(
            self.root.join("Data"),
            self.root.join("Guard"),
            &self.key,
            [6; 32],
            storage::Limits::default(),
        )
        .unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn id(n: u8) -> Id {
    Id::from_bytes([n; 32])
}
pub(super) fn action() -> Action {
    let network = NetworkId {
        network: id(1),
        incarnation: id(2),
    };
    let home = ServiceId {
        network,
        service: id(3),
    };
    Action {
        home,
        operation_id: OperationId {
            window: id(7),
            operation: id(8),
        },
        actor: Actor::Direct {
            acting: EndpointActor {
                account: AccountId {
                    origin: network,
                    local: id(4),
                },
                endpoint: id(6),
                security_generation: 1,
                enrolment_generation: 1,
                binding_digest: id(5),
            },
        },
        target: Target::Room(RoomId { home, local: id(9) }),
        operation: Operation::MessageSend,
        body: Value::serialized(&crate::messaging::Send {
            mentions: Vec::new(),
            text: "draft e\u{301} 👩‍🚀".into(),
            parent: None,
            causation: None,
        })
        .unwrap(),
        expected: BTreeMap::new(),
        approval: None,
        agreement: None,
    }
}
fn signed(action: &Action) -> VerifiedAction {
    let key = SigningKey::from_bytes(&[10; 32]);
    verify_action(&sign_action(action, &key).unwrap(), &key.verifying_key()).unwrap()
}
fn reply(action: &VerifiedAction, outcome: Outcome) -> Verified<Response> {
    let key = SigningKey::from_bytes(&[11; 32]);
    let r = Response {
        home: action.action().home,
        operation_id: action.action().operation_id,
        action_digest: action.digest(),
        outcome,
    };
    verify_response(&sign_response(&r, &key).unwrap(), &key.verifying_key()).unwrap()
}

#[test]
fn exact_outbox_survives_restart_and_conflicting_reuse_fails() {
    let f = Fixture::new();
    let mut store = f.create();
    let action = signed(&action());
    let window = RetryWindow {
        id: action.action().operation_id.window,
        expires_ms: TimeBounds::test_now().upper_ms + 60000,
    };
    outbox::prepare(&mut store, &action, &window, TimeBounds::test_now()).unwrap();
    drop(store);
    let mut store = f.open();
    let rows = outbox::pending(
        &mut store,
        &SigningKey::from_bytes(&[10; 32]).verifying_key(),
    )
    .unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].action.signed_bytes(), action.signed_bytes());
    let mut changed = action.action().clone();
    changed.body = Value::Text("replacement".into());
    assert!(
        outbox::prepare(
            &mut store,
            &signed(&changed),
            &window,
            TimeBounds::test_now()
        )
        .is_err()
    );
    assert_eq!(
        outbox::pending(
            &mut store,
            &SigningKey::from_bytes(&[10; 32]).verifying_key()
        )
        .unwrap()[0]
            .action
            .digest(),
        action.digest()
    );
}

#[test]
fn resolver_refusal_cannot_mark_original_send_rejected() {
    let f = Fixture::new();
    let mut store = f.create();
    let original = signed(&action());
    let window = RetryWindow {
        id: original.action().operation_id.window,
        expires_ms: TimeBounds::test_now().upper_ms + 60000,
    };
    outbox::prepare(&mut store, &original, &window, TimeBounds::test_now()).unwrap();
    let mut query = original.action().clone();
    query.operation_id.operation = id(12);
    query.operation = Operation::OperationResolve;
    query.target = Target::Service;
    query.body = Value::serialized(&home::Resolve {
        operation_id: original.action().operation_id,
        action_digest: original.digest(),
    })
    .unwrap();
    let query = signed(&query);
    let refused = reply(
        &query,
        Outcome::Rejected {
            code: ErrorCode::Denied,
            detail: "CurrentBinding".into(),
        },
    );
    outbox::record_resolution(
        &mut store,
        &original,
        &query,
        &refused,
        TimeBounds::test_now(),
    )
    .unwrap();
    assert_eq!(
        outbox::pending(
            &mut store,
            &SigningKey::from_bytes(&[10; 32]).verifying_key()
        )
        .unwrap()
        .len(),
        1
    );
    let resolved = reply(
        &query,
        Outcome::Result {
            body: Value::serialized(&home::ResolveResult {
                operation_id: original.action().operation_id,
                action_digest: original.digest(),
                outcome: Outcome::Committed {
                    event: Some(id(13)),
                    position: 1,
                    body: Value::Null,
                },
            })
            .unwrap(),
        },
    );
    outbox::record_resolution(
        &mut store,
        &original,
        &query,
        &resolved,
        TimeBounds::test_now(),
    )
    .unwrap();
    drop(store);
    let mut store = f.open();
    assert!(
        outbox::pending(
            &mut store,
            &SigningKey::from_bytes(&[10; 32]).verifying_key()
        )
        .unwrap()
        .is_empty()
    );
}

#[test]
fn draft_survives_restart_without_a_clock_or_network() {
    let f = Fixture::new();
    let mut store = f.create();
    let Target::Room(room) = action().target else {
        unreachable!()
    };
    let text = "Saved offline e\u{301} 👩‍🚀";
    outbox::save_draft(&mut store, room, text).unwrap();
    drop(store);
    let mut store = f.open();
    assert_eq!(
        outbox::draft(&mut store, room).unwrap().as_deref(),
        Some(text)
    );
    outbox::save_draft(&mut store, room, "").unwrap();
    assert!(outbox::draft(&mut store, room).unwrap().is_none());
}

#[test]
fn structured_api_preserves_ids_inside_operation_bodies() {
    let mut a = action();
    a.operation = Operation::ModerationIgnore;
    a.target = Target::Account(a.actor.acting().account);
    let input = serde_json::json!({"home":a.home,"operationId":a.operation_id,"actor":a.actor,"target":a.target,"operation":a.operation,"body":{"subject":a.actor.acting().account,"enabled":true},"expected":{},"approval":null,"agreement":null});
    let converted = crate::client::json::action(&serde_json::to_vec(&input).unwrap()).unwrap();
    let body: crate::moderation::Filter = converted.body.deserialized().unwrap();
    assert_eq!(body.subject, a.actor.acting().account);
    let response = reply(
        &signed(&converted),
        Outcome::Result {
            body: Value::serialized(&body).unwrap(),
        },
    );
    let json = crate::client::json::value(response.value()).unwrap();
    assert_eq!(
        json["outcome"]["body"]["subject"]["local"],
        a.actor.acting().account.local.as_hex()
    );
}

#[test]
fn structured_api_rejects_duplicate_keys_before_signing() {
    let a = action();
    let json = crate::client::json::value(&a).unwrap();
    let input = serde_json::to_string(&json).unwrap();
    assert!(crate::client::json::action(input.as_bytes()).is_ok());
    let operation = format!("\"operation\":{}", json["operation"]);
    let duplicate_operation = input.replacen(&operation, &format!("{operation},{operation}"), 1);
    let duplicate_body = input.replacen("\"text\":", "\"text\":\"replacement\",\"text\":", 1);
    let duplicate_identity = input.replacen(
        "\"endpoint\":",
        "\"endpoint\":\"replacement\",\"endpoint\":",
        1,
    );
    for duplicate in [duplicate_operation, duplicate_body, duplicate_identity] {
        assert_ne!(duplicate, input);
        assert!(crate::client::json::action(duplicate.as_bytes()).is_err());
    }
}

#[test]
fn cached_pages_and_bound_drafts_survive_restart_without_clock_or_transport() {
    use crate::{
        client::{Preferences, cache},
        conversations, messaging,
    };
    let f = Fixture::new();
    let mut store = f.create();
    cache::initialize(&mut store, action().home).unwrap();
    let a = action();
    let Target::Room(room) = a.target else {
        unreachable!()
    };
    let summary = conversations::Summary {
        confidentiality: RoomConfidentiality::Community,
        invited: false,
        room,
        name: "local".into(),
        topic: String::new(),
        revision: 1,
        sequence: 1,
        joined: true,
        unread: 1,
    };
    cache::save_rooms(&mut store, room.home, &[summary]).unwrap();
    let mention = messaging::Mention {
        account: a.actor.represented(),
        start: 0,
        end: 6,
    };
    outbox::save_draft_mentions(
        &mut store,
        room,
        "@Alice draft",
        std::slice::from_ref(&mention),
    )
    .unwrap();
    let prefs = Preferences {
        text_scale: 1.25,
        quiet: true,
        ..Default::default()
    };
    cache::save_preferences(&mut store, "global", &prefs).unwrap();
    let key = SigningKey::from_bytes(&[11; 32]);
    let now = TimeBounds::test_now().upper_ms;
    let cursor = HistoryCursor {
        home: a.home,
        room,
        account: a.actor.represented(),
        sequence: 1,
        membership_revision: 1,
        filter_revision: 1,
        access_digest: id(20),
        expires_ms: now + 300000,
    };
    let event = Event {
        home: a.home,
        room,
        event: id(21),
        sequence: 1,
        timestamp_ms: now,
        actor: a.actor.clone(),
        operation_id: a.operation_id,
        action_digest: action_digest(&a).unwrap(),
        kind: Operation::MessageSend,
        body: a.body,
    };
    let page = messaging::PageResult {
        events: vec![event.clone()],
        cursor: Blob(sign_cursor(&cursor, &key).unwrap()),
        has_more: false,
        room_revision: 1,
        members: vec![],
    };
    cache::receive(
        &mut store,
        room,
        a.actor.represented(),
        &page,
        &key.verifying_key(),
        now,
    )
    .unwrap();
    drop(store);
    let mut store = f.open();
    cache::initialize(&mut store, action().home).unwrap();
    let saved = cache::room(&mut store, room).unwrap();
    assert_eq!(
        cache::encode(&saved.events).unwrap(),
        cache::encode(&vec![event]).unwrap()
    );
    assert_eq!(saved.cursor.unwrap(), page.cursor);
    assert_eq!(
        outbox::draft_mentions(&mut store, room).unwrap(),
        vec![mention]
    );
    assert_eq!(
        outbox::draft(&mut store, room).unwrap().as_deref(),
        Some("@Alice draft")
    );
    let prefs: Preferences = cache::preferences(&mut store, "global").unwrap();
    assert_eq!(prefs.text_scale, 1.25);
    assert!(prefs.quiet);
    let before = store.usage().unwrap().commit_counter;
    let mut altered = page.clone();
    altered.events[0].body = Value::Text("substitution".into());
    assert!(
        cache::receive(
            &mut store,
            room,
            a.actor.represented(),
            &altered,
            &key.verifying_key(),
            now
        )
        .is_err()
    );
    assert_eq!(store.usage().unwrap().commit_counter, before);
    let mut wrong = cursor.clone();
    wrong.account.local = id(22);
    let mut other = page;
    other.cursor = Blob(sign_cursor(&wrong, &key).unwrap());
    assert!(
        cache::receive(
            &mut store,
            room,
            a.actor.represented(),
            &other,
            &key.verifying_key(),
            now
        )
        .is_err()
    );
    cache::invalidate(&mut store, room).unwrap();
    let saved = cache::room(&mut store, room).unwrap();
    assert!(saved.events.is_empty());
    assert!(saved.cursor.is_none());
    assert!(saved.gap.is_some());
    assert!(outbox::draft(&mut store, room).unwrap().is_some());
}

#[test]
fn old_draft_schema_migrates_without_changing_text_or_recreating_state() {
    let f = Fixture::new();
    let mut store = f.create();
    let Target::Room(room) = action().target else {
        unreachable!()
    };
    outbox::save_draft(&mut store, room, "preserved").unwrap();
    store
        .write(|db| {
            db.execute_batch("ALTER TABLE client_drafts DROP COLUMN mentions")?;
            Ok(storage::Commit::new((), b"old schema fixture".to_vec()))
        })
        .unwrap();
    outbox::migrate(&mut store).unwrap();
    assert_eq!(
        outbox::draft(&mut store, room).unwrap().as_deref(),
        Some("preserved")
    );
    assert!(outbox::draft_mentions(&mut store, room).unwrap().is_empty());
    let before = store.usage().unwrap().commit_counter;
    outbox::migrate(&mut store).unwrap();
    assert_eq!(store.usage().unwrap().commit_counter, before);
}

#[test]
fn controller_starts_offline_and_preserves_correlated_drafts_with_one_store_owner() {
    use crate::client::{self, Command, ConnectionState, Controller, cache};
    let f = Fixture::new();
    let mut store = f.create();
    cache::initialize(&mut store, action().home).unwrap();
    let a = action();
    let Target::Room(room) = a.target else {
        unreachable!()
    };
    cache::save_rooms(
        &mut store,
        room.home,
        &[crate::conversations::Summary {
            confidentiality: RoomConfidentiality::Community,
            invited: false,
            room,
            name: "offline".into(),
            topic: String::new(),
            revision: 1,
            sequence: 0,
            joined: true,
            unread: 0,
        }],
    )
    .unwrap();
    drop(store);
    f.profile();
    let mut controller = Controller::open(&f.root).unwrap();
    assert_eq!(controller.snapshot().connection, ConnectionState::Offline);
    assert!(client::Client::open_offline(&f.root).is_err());
    let select = controller.dispatch(Command::SelectRoom(room)).unwrap();
    let draft = controller
        .dispatch(Command::SaveDraft {
            room,
            text: "@Alice offline".into(),
            mentions: vec![crate::messaging::Mention {
                account: a.actor.represented(),
                start: 0,
                end: 6,
            }],
        })
        .unwrap();
    assert!(draft > select);
    let end = std::time::Instant::now() + std::time::Duration::from_secs(3);
    while controller
        .snapshot()
        .selected
        .as_ref()
        .is_none_or(|v| v.draft != "@Alice offline")
        && std::time::Instant::now() < end
    {
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
    let snapshot = controller.snapshot();
    assert!(
        snapshot
            .completions
            .iter()
            .any(|c| c.request_id == draft && c.error.is_none())
    );
    let view = snapshot.selected.as_ref().unwrap();
    assert_eq!(view.draft, "@Alice offline");
    assert_eq!(view.draft_mentions.len(), 1);
    assert!(view.stale);
    assert_eq!(snapshot.connection, ConnectionState::Offline);
    assert!(
        controller
            .dispatch(Command::SaveDraft {
                room,
                text: "x".repeat(8193),
                mentions: vec![]
            })
            .is_err()
    );
    controller.shutdown();
    let mut reopened = client::Client::open_offline(&f.root).unwrap();
    assert_eq!(
        reopened.draft(room).unwrap().as_deref(),
        Some("@Alice offline")
    );
    assert_eq!(reopened.draft_mentions(room).unwrap().len(), 1);
}

#[test]
fn recipient_ignore_and_expiry_remove_local_presentations_without_erasing_drafts() {
    use crate::{client::cache, moderation::FilterState};
    let f = Fixture::new();
    let mut store = f.create();
    cache::initialize(&mut store, action().home).unwrap();
    let a = action();
    let Target::Room(room) = a.target else {
        unreachable!()
    };
    let event = Event {
        home: a.home,
        room,
        event: id(30),
        sequence: 1,
        timestamp_ms: 0,
        actor: a.actor.clone(),
        operation_id: a.operation_id,
        action_digest: action_digest(&a).unwrap(),
        kind: Operation::MessageSend,
        body: a.body,
    };
    let bytes = cache::encode(&event).unwrap();
    store
        .write(|db| {
            db.execute(
                "INSERT INTO client_events VALUES(?1,?2,1,0,?3,?4)",
                rusqlite::params![event.event.as_hex(), room.to_string(), bytes, bytes.len()],
            )?;
            Ok(storage::Commit::new((), b"old received copy".to_vec()))
        })
        .unwrap();
    outbox::save_draft(&mut store, room, "keep draft").unwrap();
    cache::save_filters(
        &mut store,
        action().home,
        &[FilterState {
            subject: event.actor.represented(),
            ignored: true,
            muted: false,
        }],
    )
    .unwrap();
    assert!(cache::room(&mut store, room).unwrap().events.is_empty());
    assert!(cache::filters(&mut store, action().home).unwrap()[0].ignored);
    cache::maintain(&mut store).unwrap();
    assert_eq!(
        outbox::draft(&mut store, room).unwrap().as_deref(),
        Some("keep draft")
    );
    let before = store.usage().unwrap().commit_counter;
    cache::maintain(&mut store).unwrap();
    assert_eq!(store.usage().unwrap().commit_counter, before);
}

#[test]
fn abandoned_unknown_operations_remain_exact_and_can_record_a_late_outcome() {
    let f = Fixture::new();
    let mut store = f.create();
    let original = signed(&action());
    let window = RetryWindow {
        id: original.action().operation_id.window,
        expires_ms: TimeBounds::test_now().upper_ms + 60000,
    };
    outbox::prepare(&mut store, &original, &window, TimeBounds::test_now()).unwrap();
    assert!(outbox::abandon(&mut store, original.action().operation_id, id(99)).is_err());
    outbox::abandon(
        &mut store,
        original.action().operation_id,
        original.digest(),
    )
    .unwrap();
    assert!(outbox::prepare(&mut store, &original, &window, TimeBounds::test_now()).is_err());
    drop(store);
    let mut store = f.open();
    let retained = outbox::pending(
        &mut store,
        &SigningKey::from_bytes(&[10; 32]).verifying_key(),
    )
    .unwrap();
    assert_eq!(retained.len(), 1);
    assert!(retained[0].abandoned);
    assert_eq!(retained[0].action.signed_bytes(), original.signed_bytes());
    assert!(retained[0].last_response.is_none());
    let mut query = original.action().clone();
    query.operation_id.operation = id(90);
    query.operation = Operation::OperationResolve;
    query.target = Target::Service;
    query.body = Value::serialized(&home::Resolve {
        operation_id: original.action().operation_id,
        action_digest: original.digest(),
    })
    .unwrap();
    let query = signed(&query);
    let response = reply(
        &query,
        Outcome::Result {
            body: Value::serialized(&home::ResolveResult {
                operation_id: original.action().operation_id,
                action_digest: original.digest(),
                outcome: Outcome::Committed {
                    event: Some(id(91)),
                    position: 1,
                    body: Value::Null,
                },
            })
            .unwrap(),
        },
    );
    outbox::record_resolution(
        &mut store,
        &original,
        &query,
        &response,
        TimeBounds::test_now(),
    )
    .unwrap();
    assert!(
        outbox::pending(
            &mut store,
            &SigningKey::from_bytes(&[10; 32]).verifying_key()
        )
        .unwrap()
        .is_empty()
    );
    let (bytes, abandoned, terminal): (Vec<u8>, bool, bool) = store
        .read(std::time::Duration::from_secs(1), |db| {
            db.query_row(
                "SELECT action,abandoned,terminal FROM client_outbox",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )
        })
        .unwrap();
    assert_eq!(bytes, original.signed_bytes());
    assert!(abandoned && terminal);
}

#[path = "PresentationFixture.rs"]
mod presentation_fixture;

#[test]
fn transient_nonadmission_preserves_retry_guidance_but_terminal_or_invalid_input_does_not_retry() {
    use crate::client::{Error, network};
    for code in [
        ErrorCode::Unavailable,
        ErrorCode::RateLimited,
        ErrorCode::Overloaded,
    ] {
        let error = Error::from_outcome(Outcome::Refused {
            code,
            detail: "Temporary authority observation".into(),
            retry_after_ms: Some(12000),
        });
        assert_eq!(error.retry_delay_ms(), Some(12000));
        assert_eq!(error.code(), "OperationTemporarilyUnavailable");
        let terminal = Error::from_outcome(Outcome::Rejected {
            code,
            detail: "Durable rejection".into(),
        });
        assert_eq!(terminal.retry_delay_ms(), None);
    }
    let extreme = Error::from_outcome(Outcome::Refused {
        code: ErrorCode::Overloaded,
        detail: "Bounded wait".into(),
        retry_after_ms: Some(u64::MAX),
    });
    assert_eq!(extreme.retry_delay_ms(), Some(60000));
    for (code, expected) in [
        (ErrorCode::Denied, "OperationDenied"),
        (ErrorCode::Expired, "OperationExpired"),
    ] {
        for outcome in [
            Outcome::Rejected {
                code,
                detail: "Permanent policy result".into(),
            },
            Outcome::Refused {
                code,
                detail: "Permanent admission result".into(),
                retry_after_ms: None,
            },
        ] {
            let error = Error::from_outcome(outcome);
            assert_eq!(error.code(), expected);
            assert_eq!(error.retry_delay_ms(), None);
        }
    }
    for code in [
        ErrorCode::Denied,
        ErrorCode::Expired,
        ErrorCode::InvalidInput,
        ErrorCode::UnsupportedVersion,
    ] {
        assert_eq!(
            Error::from_outcome(Outcome::Refused {
                code,
                detail: "Permanent refusal".into(),
                retry_after_ms: Some(1)
            })
            .retry_delay_ms(),
            None
        );
    }
    for failure in [
        network::Error::Authentication,
        network::Error::Frame,
        network::Error::Expired,
    ] {
        assert_eq!(Error::Network(failure).retry_delay_ms(), None);
    }
}

#[test]
fn identity_api_keeps_proof_bytes_and_exact_current_state() {
    let mut a = action();
    a.operation = Operation::AccountEnrolEndpoint;
    a.target = Target::Account(a.actor.acting().account);
    a.body = Value::serialized(&crate::identity::ApproveEndpoint {
        request: Blob(vec![0, 0xff, 0x80]),
        revision: 7,
        head: id(25),
    })
    .unwrap();
    let json = crate::client::json::value(&a).unwrap();
    assert_eq!(json["body"]["request"], "00ff80");
    let converted = crate::client::json::action(&serde_json::to_vec(&json).unwrap()).unwrap();
    assert_eq!(action_bytes(&a).unwrap(), action_bytes(&converted).unwrap());
    let mut invalid = json;
    invalid["body"]["head"] = serde_json::json!([25, 25]);
    assert!(crate::client::json::action(&serde_json::to_vec(&invalid).unwrap()).is_err());
}

#[path = "EncryptedArchive.rs"]
mod encrypted_archive;
#[path = "Federation.rs"]
mod federation;
#[path = "Trust.rs"]
mod trust_checks;
