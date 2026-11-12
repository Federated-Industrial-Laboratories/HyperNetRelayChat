// SPDX-License-Identifier: Apache-2.0
//! Real encrypted-store regressions cover lost acknowledgements and exact send identity.
use super::*;
use crate::{
    client::outbox,
    clock::TimeBounds,
    protocol::*,
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
struct Fixture {
    path: PathBuf,
    key: storage::Key,
}
impl Fixture {
    fn profile(&self) -> PathBuf {
        use crate::{
            client,
            service::{Descriptor, files},
        };
        drop(self.store(true));
        fs::rename(self.path.join("Key"), self.path.join("Database.key")).unwrap();
        let endpoint = files::create_key(&self.path.join("Endpoint.key")).unwrap();
        let p = client::Profile {
            federation: None,
            agreements: vec![],
            server: Descriptor {
                version: 1,
                home: room().home,
                signing_key: id(3),
                protocol: PROTOCOL.into(),
                text_profile: crate::text::PROFILE.into(),
            },
            registration: AccountRegistration {
                home: room().home,
                account: account(5),
                endpoint: id(9),
                endpoint_key: Id::from_bytes(endpoint.verifying_key().to_bytes()),
                transport_principal: id(10),
                recovery_key: id(11),
                invitation: id(12),
                classification: AccountClass::Agent {
                    operator: account(8),
                },
            },
            companion: self.path.join("AbsentCompanion"),
            clock: crate::clock::Config {
                observation: self.path.join("AbsentClock"),
                monitor_key: hex::encode([15; 32]),
            },
        };
        files::create_json(&self.path.join("Profile.json"), &p).unwrap();
        initialise(&self.path, &self.path.join("Integration")).unwrap()
    }
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("hrc-integration-{}", Id::random().unwrap()));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["Data", "Guard"] {
            fs::create_dir(path.join(name)).unwrap();
            fs::set_permissions(path.join(name), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let key = storage::Key::create(path.join("Key")).unwrap();
        Self { path, key }
    }
    fn store(&self, create: bool) -> Store {
        let mut s = if create {
            Store::create(
                self.path.join("Data"),
                self.path.join("Guard"),
                &self.key,
                [9; 32],
                storage::Limits::default(),
            )
        } else {
            Store::open(
                self.path.join("Data"),
                self.path.join("Guard"),
                &self.key,
                [9; 32],
                storage::Limits::default(),
            )
        }
        .unwrap();
        if create {
            outbox::initialize(&mut s).unwrap();
            state::initialise(&mut s).unwrap();
        }
        s
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}
fn window() -> RetryWindow {
    RetryWindow {
        id: id(10),
        expires_ms: TimeBounds::test_now().upper_ms + 120000,
    }
}
fn action() -> VerifiedAction {
    let key = SigningKey::from_bytes(&[8; 32]);
    let a = Action {
        home: room().home,
        operation_id: OperationId {
            window: id(10),
            operation: id(11),
        },
        actor: Actor::IndependentAgent {
            acting: EndpointActor {
                account: account(5),
                endpoint: id(6),
                security_generation: 1,
                enrolment_generation: 1,
                binding_digest: id(7),
            },
            operator: account(8),
        },
        target: Target::Room(room()),
        operation: Operation::MessageReply,
        body: crate::protocol::Value::serialized(&crate::messaging::Send {
            text: "Reply".into(),
            mentions: vec![],
            parent: Some(id(12)),
            causation: Some(id(12)),
        })
        .unwrap(),
        expected: BTreeMap::new(),
        approval: None,
        agreement: None,
    };
    verify_action(&sign_action(&a, &key).unwrap(), &key.verifying_key()).unwrap()
}
fn prepare(s: &mut Store, id_number: u64, fail: bool) -> storage::Result<()> {
    let a = action();
    let window = window();
    let now = TimeBounds::test_now();
    s.write(|db| {
        outbox::prepare_transaction(db, &a, &window, now)?;
        state::prepare(
            db,
            id(20),
            id_number,
            id(21),
            &a,
            window.expires_ms,
            Some(("consumer", id(12))),
        )?;
        if fail {
            return Err(rusqlite::Error::InvalidQuery);
        }
        Ok(Commit::new((), b"integration send test".to_vec()))
    })
}
#[test]
fn exact_send_mapping_survives_restart_and_rejects_reuse() {
    let f = Fixture::new();
    let mut s = f.store(true);
    prepare(&mut s, 1, false).unwrap();
    let saved = state::lookup(&mut s, id(20), 1).unwrap().unwrap();
    assert_eq!(saved.operation, action().action().operation_id);
    assert_eq!(saved.payload, id(21));
    assert!(prepare(&mut s, 1, false).is_err());
    assert!(prepare(&mut s, 3, false).is_err());
    drop(s);
    let mut s = f.store(false);
    assert_eq!(state::watermark(&mut s, id(20)).unwrap(), 1);
    assert_eq!(
        state::lookup(&mut s, id(20), 1).unwrap().unwrap().digest,
        action().digest()
    );
}
#[test]
fn failed_send_transaction_does_not_allocate_a_request_or_outbox() {
    let f = Fixture::new();
    let mut s = f.store(true);
    assert!(prepare(&mut s, 1, true).is_err());
    assert_eq!(state::watermark(&mut s, id(20)).unwrap(), 0);
    assert!(state::lookup(&mut s, id(20), 1).unwrap().is_none());
    assert!(
        outbox::pending(&mut s, &SigningKey::from_bytes(&[8; 32]).verifying_key())
            .unwrap()
            .is_empty()
    );
    prepare(&mut s, 1, false).unwrap();
}
#[test]
fn retirement_keeps_monotonic_identity_and_preserves_unknown_outcomes() {
    let f = Fixture::new();
    let mut s = f.store(true);
    prepare(&mut s, 1, false).unwrap();
    state::maintain(&mut s, TimeBounds::test_now().upper_ms + 20 * 86400000).unwrap();
    assert!(state::lookup(&mut s, id(20), 1).unwrap().is_some());
    state::complete(
        &mut s,
        id(20),
        1,
        &Outcome::Rejected {
            code: ErrorCode::Denied,
            detail: "Denied".into(),
        },
    )
    .unwrap();
    state::maintain(&mut s, TimeBounds::test_now().upper_ms + 20 * 86400000).unwrap();
    assert!(state::lookup(&mut s, id(20), 1).unwrap().is_none());
    assert_eq!(state::watermark(&mut s, id(20)).unwrap(), 1);
    assert!(prepare(&mut s, 1, false).is_err());
}
#[test]
fn pending_event_batch_and_acknowledgement_are_durable() {
    let f = Fixture::new();
    let mut s = f.store(true);
    state::open(&mut s, id(20), "app", room()).unwrap();
    let b = state::Batch {
        id: id(30),
        room: room(),
        events: vec![Event {
            home: room().home,
            room: room(),
            event: id(31),
            sequence: 1,
            timestamp_ms: 1,
            actor: action().action().actor.clone(),
            operation_id: action().action().operation_id,
            action_digest: id(32),
            kind: Operation::MessageSend,
            body: crate::protocol::Value::Bytes(vec![1, 2, 3]),
        }],
        content: vec![],
        cursor: Blob(vec![1, 2]),
        historical: true,
        has_more: false,
        room_revision: 1,
        filter_revision: 1,
        expires_ms: 10000,
    };
    state::batch(&mut s, id(20), "app", &b).unwrap();
    drop(s);
    let mut s = f.store(false);
    let retained = state::consumer(&mut s, id(20), "app")
        .unwrap()
        .unwrap()
        .batch
        .unwrap();
    assert_eq!(retained.id, id(30));
    assert_eq!(retained.events, b.events);
    assert!(state::acknowledge(&mut s, id(20), "app", id(31)).is_err());
    state::acknowledge(&mut s, id(20), "app", id(30)).unwrap();
    state::acknowledge(&mut s, id(20), "app", id(30)).unwrap();
    let c = state::consumer(&mut s, id(20), "app").unwrap().unwrap();
    assert!(c.live);
    assert!(c.batch.is_none());
    assert_eq!(c.cursor, Some(b.cursor));
    state::resynchronise(&mut s, id(20), "app").unwrap();
    assert!(
        !state::consumer(&mut s, id(20), "app")
            .unwrap()
            .unwrap()
            .live
    );
}
#[test]
fn revoked_credential_is_refused_without_profile_key_changes() {
    let f = Fixture::new();
    let path = f.path.join("Configuration.json");
    let credential = f.path.join("Client.json");
    let c = Configuration {
        version: 1,
        profile: f.path.clone(),
        account: account(5),
        endpoint: id(6),
        credentials: vec![],
    };
    crate::service::files::create_json(&path, &c).unwrap();
    let key = issue(
        &path,
        Scope {
            rooms: vec![room()],
            initiate: false,
            history: false,
            agent_replies: false,
        },
        &credential,
    )
    .unwrap();
    let secret = Credential::load(&credential).unwrap();
    assert!(
        Configuration::load(&path)
            .unwrap()
            .authenticate(&secret)
            .is_ok()
    );
    revoke(&path, key).unwrap();
    assert!(
        Configuration::load(&path)
            .unwrap()
            .authenticate(&secret)
            .is_err()
    );
}
#[test]
fn malformed_rpc_cannot_select_a_different_actor_or_duplicate_fields() {
    let secret = "01".repeat(32);
    let auth = json!({"version":1,"id":id(1),"secret":secret});
    let good = json!({"jsonrpc":"2.0","id":1,"method":"status","params":{},"auth":auth});
    assert!(broker::parse(&serde_json::to_vec(&good).unwrap()).is_ok());
    let mut bad = good.clone();
    bad["actor"] = json!("owner");
    assert!(broker::parse(&serde_json::to_vec(&bad).unwrap()).is_err());
    let text = serde_json::to_string(&good)
        .unwrap()
        .replacen("{", "{\"id\":2,", 1);
    assert!(broker::parse(text.as_bytes()).is_err());
    let mut bad = good;
    bad["jsonrpc"] = json!("1.0");
    assert!(broker::parse(&serde_json::to_vec(&bad).unwrap()).is_err());
}
#[test]
fn broker_enforces_scopes_pause_restart_and_one_profile_owner() {
    let f = Fixture::new();
    let config = f.profile();
    let credential = f.path.join("Credential.json");
    let key = issue(
        &config,
        Scope {
            rooms: vec![room()],
            initiate: false,
            history: false,
            agent_replies: false,
        },
        &credential,
    )
    .unwrap();
    let auth = serde_json::to_value(Credential::load(&credential).unwrap()).unwrap();
    let mut broker = broker::Broker::open(&config).unwrap();
    assert!(matches!(
        broker::Broker::open(&config),
        Err(super::Error::Client(crate::client::Error::ProfileInUse))
    ));
    let rpc = |b: &mut broker::Broker, method: &str, params: serde_json::Value| {
        b.handle(
            &serde_json::to_vec(
                &json!({"jsonrpc":"2.0","id":1,"method":method,"params":params,"auth":auth}),
            )
            .unwrap(),
        )
    };
    assert_eq!(
        rpc(&mut broker, "status", json!({}))["result"]["nextClientRequestId"],
        1
    );
    assert_eq!(
        rpc(&mut broker, "history.page", json!({"room":room()}))["error"]["message"],
        "IntegrationDenied"
    );
    assert_eq!(
        rpc(
            &mut broker,
            "messages.send",
            json!({"room":room(),"clientRequestId":1,"text":"hello"})
        )["error"]["message"],
        "IntegrationDenied"
    );
    assert_eq!(
        rpc(&mut broker, "missing", json!({}))["error"]["code"],
        -32601
    );
    assert_eq!(
        rpc(&mut broker, "pause", json!({}))["result"]["paused"],
        true
    );
    drop(broker);
    let mut broker = broker::Broker::open(&config).unwrap();
    assert_eq!(
        rpc(&mut broker, "status", json!({}))["result"]["paused"],
        true
    );
    assert_eq!(
        rpc(
            &mut broker,
            "events.open",
            json!({"consumer":"test","room":room()})
        )["error"]["message"],
        "IntegrationDenied"
    );
    revoke(&config, key).unwrap();
    assert_eq!(
        rpc(&mut broker, "resume", json!({}))["error"]["message"],
        "IntegrationDenied"
    );
}
#[test]
fn private_socket_serves_version_and_stops_without_losing_profile() {
    use std::{
        sync::{
            Arc,
            atomic::{AtomicBool, Ordering},
        },
        thread,
        time::Duration,
    };
    let f = Fixture::new();
    let config = f.profile();
    let credential = f.path.join("Credential.json");
    issue(
        &config,
        Scope {
            rooms: vec![room()],
            initiate: false,
            history: false,
            agent_replies: false,
        },
        &credential,
    )
    .unwrap();
    let socket = config.parent().unwrap().join("Api.sock");
    let stop = Arc::new(AtomicBool::new(false));
    let stopped = stop.clone();
    let path = config.clone();
    let worker = thread::spawn(move || serve(&path, false, stopped));
    let response = (0..100).find_map(|_| {
        let result = request(&socket, &credential, "api.describe", json!({}));
        if result.is_err() {
            thread::sleep(Duration::from_millis(20));
        }
        result.ok()
    });
    stop.store(true, Ordering::Release);
    worker.join().unwrap().unwrap();
    assert_eq!(response.unwrap()["result"]["apiVersion"], API_VERSION);
    assert!(!socket.exists());
    assert!(broker::Broker::open(&config).is_ok());
}

#[test]
fn stdio_frames_do_not_stall_after_buffered_lines_and_cancel_partial_input() {
    use std::{
        io::Write,
        os::{fd::AsRawFd, unix::net::UnixStream},
        sync::atomic::AtomicBool,
    };
    let (mut sender, receiver) = UnixStream::pair().unwrap();
    sender.write_all(b"first\nsecond\n").unwrap();
    let stop = AtomicBool::new(false);
    assert_eq!(
        transport::input_line(receiver.as_raw_fd(), &stop)
            .unwrap()
            .unwrap(),
        b"first"
    );
    assert_eq!(
        transport::input_line(receiver.as_raw_fd(), &stop)
            .unwrap()
            .unwrap(),
        b"second"
    );
    stop.store(true, std::sync::atomic::Ordering::Release);
    assert!(
        transport::input_line(receiver.as_raw_fd(), &stop)
            .unwrap()
            .is_none()
    );
}
