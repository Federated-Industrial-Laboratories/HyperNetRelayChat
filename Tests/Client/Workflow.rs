use crate::{client::outbox, clock::TimeBounds, home, protocol::*, storage};
use std::{collections::BTreeMap, fs, os::unix::fs::PermissionsExt, path::PathBuf};
struct Fixture {
    root: PathBuf,
    key: storage::Key,
}
impl Fixture {
    fn new() -> Self {
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
    fn create(&self) -> storage::Store {
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
fn action() -> Action {
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
