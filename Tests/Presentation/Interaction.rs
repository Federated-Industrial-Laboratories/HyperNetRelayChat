use super::*;
use hrc::{
    client::{self, Delivery, Profile},
    conversations::Summary,
    service::{Descriptor, files},
    storage,
};
use std::{fs, path::PathBuf, thread};

struct Fixture {
    root: PathBuf,
    rooms: [RoomId; 2],
}
impl Fixture {
    fn new() -> Self {
        let id = |byte| Id::from_bytes([byte; 32]);
        let home = ServiceId {
            network: NetworkId {
                network: id(1),
                incarnation: id(2),
            },
            service: id(3),
        };
        let root = std::env::temp_dir().join(format!("hrc-interaction-{}", Id::random().unwrap()));
        for directory in [&root, &root.join("Data"), &root.join("Guard")] {
            files::directory(directory, true).unwrap();
        }
        let endpoint = files::create_key(&root.join("Endpoint.key")).unwrap();
        let profile = Profile {
            federation: None,
            agreements: Vec::new(),
            server: Descriptor {
                version: 1,
                home,
                signing_key: Id::from_bytes(
                    SigningKey::from_bytes(&[11; 32]).verifying_key().to_bytes(),
                ),
                protocol: PROTOCOL.into(),
                text_profile: hrc::text::PROFILE.into(),
            },
            registration: AccountRegistration {
                home,
                account: AccountId {
                    origin: home.network,
                    local: id(4),
                },
                endpoint: id(6),
                endpoint_key: Id::from_bytes(endpoint.verifying_key().to_bytes()),
                transport_principal: id(12),
                recovery_key: id(13),
                classification: AccountClass::Human,
                invitation: id(14),
            },
            companion: root.join("AbsentCompanion"),
            clock: hrc::clock::Config {
                observation: root.join("AbsentClock"),
                monitor_key: hex::encode([15; 32]),
            },
        };
        files::create_json(&root.join("Profile.json"), &profile).unwrap();
        let key = storage::Key::create(root.join("Database.key")).unwrap();
        let mut store = storage::Store::create(
            root.join("Data"),
            root.join("Guard"),
            &key,
            [6; 32],
            storage::Limits::default(),
        )
        .unwrap();
        client::outbox::initialize(&mut store).unwrap();
        drop(store);
        drop(client::Client::open_offline(&root).unwrap());
        let rooms = [
            RoomId {
                home,
                local: id(20),
            },
            RoomId {
                home,
                local: id(21),
            },
        ];
        let mut store = profile.store(&root).unwrap();
        for room in rooms {
            let summary = Summary {
                room,
                name: room.local.to_string(),
                topic: String::new(),
                revision: 1,
                sequence: 0,
                joined: true,
                unread: 0,
                confidentiality: Default::default(),
                invited: false,
            };
            let encoded =
                canonical_encode(&Value::serialized(&summary).unwrap(), CRYPTO_FRAME_BYTES)
                    .unwrap();
            store
                .write(|db| {
                    db.execute(
                        "INSERT INTO client_rooms(id,summary) VALUES(?1,?2)",
                        rusqlite::params![room.to_string(), encoded],
                    )?;
                    Ok(storage::Commit::new((), b"Interaction fixture".to_vec()))
                })
                .unwrap();
        }
        Self { root, rooms }
    }
    fn open(&self) -> Model {
        let mut model = Model::open(&self.root, true).unwrap();
        until(&mut model, |m| {
            m.room == Some(self.rooms[0]) && m.composer_enabled()
        });
        model
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn until(model: &mut Model, done: impl Fn(&Model) -> bool) {
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        model.tick();
        if done(model) {
            return;
        }
        assert!(
            Instant::now() < end,
            "interaction did not complete: {:?}",
            model.error
        );
        thread::sleep(Duration::from_millis(5));
    }
}

#[test]
fn explicit_offline_intent_controls_automatic_access_renewal() {
    let fixture = Fixture::new();
    let mut model = fixture.open();
    assert!(!model.online_requested);
    model.dispatch(Command::Connect);
    assert!(model.online_requested);
    model.dispatch(Command::Disconnect);
    assert!(!model.online_requested);
    model.save();
    assert!(!model.online_requested);
}
fn committed(model: &mut Model, request: u64, room: RoomId) {
    Arc::make_mut(&mut model.snapshot)
        .deliveries
        .push(Delivery {
            exchange_ns: None,
            abandoned: false,
            held: false,
            request_id: Some(request),
            operation: Operation::MessageSend,
            operation_id: OperationId {
                window: Id::from_bytes([30; 32]),
                operation: Id::from_bytes([31; 32]),
            },
            action_digest: Id::from_bytes([32; 32]),
            room: Some(room),
            outcome: Some(Outcome::Committed {
                event: None,
                position: 1,
                body: Value::Null,
            }),
        });
    model.update();
}

#[test]
fn room_transition_preserves_the_latest_old_room_draft_and_freezes_inflight_edits() {
    let fixture = Fixture::new();
    let mut model = fixture.open();
    model.edit(|editor| editor.insert("first"));
    model.select(fixture.rooms[1]);
    // A newer edit is accepted while the older draft save is still pending.
    model.edit(|editor| editor.insert(" latest\u{2003}@Al"));
    until(&mut model, |m| m.selection_pending.is_some());
    assert_eq!(model.editor.text(), "first latest\u{2003}@Al");
    assert!(model.draft_saved());
    model.edit(|editor| editor.insert(" rejected during selection"));
    model.submit();
    assert_eq!(model.editor.text(), "first latest\u{2003}@Al");
    assert!(model.sends.is_empty());
    until(&mut model, |m| {
        m.room == Some(fixture.rooms[1]) && m.composer_enabled()
    });
    assert_eq!(model.editor.text(), "");
    model.controller.shutdown();
    drop(model);
    let mut reopened = fixture.open();
    assert_eq!(reopened.editor.text(), "first latest\u{2003}@Al");
    assert_eq!(
        &reopened.editor.text()[reopened.editor.completion_range()],
        "@Al"
    );
    reopened.controller.shutdown();
}

#[test]
fn completed_save_is_retired_and_a_stale_snapshot_does_not_suppress_resaving() {
    let fixture = Fixture::new();
    let mut model = fixture.open();
    model.edit(|editor| editor.insert("new draft"));
    model.save();
    let first = model.save_pending.as_ref().unwrap().0;
    until(&mut model, |m| m.draft_saved());
    assert!(model.save_pending.is_none());
    // An older send used to replace the durable draft after this acknowledgement.
    Arc::make_mut(&mut model.snapshot)
        .selected
        .as_mut()
        .unwrap()
        .draft = "older send".into();
    model.save();
    assert!(model.save_pending.as_ref().unwrap().0 > first);
    until(&mut model, |m| m.save_pending.is_none() && m.draft_saved());
    model.controller.shutdown();
}

#[test]
fn an_older_save_acknowledgement_does_not_acknowledge_a_new_identical_revision() {
    let fixture = Fixture::new();
    let mut model = fixture.open();
    model.edit(|editor| editor.insert("same text"));
    model.save();
    let first = model.save_pending.as_ref().unwrap().0;
    model.edit(|editor| {
        editor.select_all();
        editor.insert("temporary edit")
    });
    model.edit(|editor| {
        editor.select_all();
        editor.insert("same text")
    });
    // Ticking while waiting could autosave the newer revision after the debounce
    // and acknowledge both saves. Consume only the original save's completion.
    let end = Instant::now() + Duration::from_secs(5);
    loop {
        model.snapshot = model.controller.snapshot();
        if model
            .snapshot
            .completions
            .iter()
            .any(|c| c.request_id == first)
        {
            break;
        }
        assert!(Instant::now() < end, "original draft save did not complete");
        thread::sleep(Duration::from_millis(5));
    }
    model.update();
    assert!(!model.draft_saved());
    model.save();
    assert!(model.save_pending.as_ref().unwrap().0 > first);
    until(&mut model, |m| m.draft_saved());
    model.controller.shutdown();
}

#[test]
fn old_send_commit_cannot_clear_a_newer_identical_draft_or_mention_binding() {
    let fixture = Fixture::new();
    let mut model = fixture.open();
    model.edit(|editor| editor.insert("@Alice "));
    model.sends.insert(900, (fixture.rooms[0], model.draft()));
    model.edit(|editor| {
        editor.select_all();
        editor.insert("other")
    });
    model.edit(|editor| {
        editor.select_all();
        editor.insert("@Alice ")
    });
    committed(&mut model, 900, fixture.rooms[0]);
    assert_eq!(model.editor.text(), "@Alice ");
    model.sends.insert(901, (fixture.rooms[0], model.draft()));
    let account = model.snapshot.account;
    model.edit(|editor| editor.complete_mention(0..7, account, "Alice"));
    committed(&mut model, 901, fixture.rooms[0]);
    assert_eq!(model.editor.mentions().len(), 1);
    model.sends.insert(902, (fixture.rooms[0], model.draft()));
    committed(&mut model, 902, fixture.rooms[0]);
    assert_eq!(model.editor.text(), "");
    until(&mut model, |m| m.draft_saved());
    model.controller.shutdown();
}

#[test]
fn selection_failure_unfreezes_the_preserved_composer() {
    let fixture = Fixture::new();
    let mut model = fixture.open();
    model.edit(|editor| editor.insert("saved draft"));
    model.save();
    until(&mut model, |m| m.draft_saved());
    model.select(RoomId {
        home: fixture.rooms[0].home,
        local: Id::from_bytes([99; 32]),
    });
    until(&mut model, |m| m.selection_pending.is_some());
    until(&mut model, |m| m.composer_enabled());
    assert_eq!(model.room, Some(fixture.rooms[0]));
    assert_eq!(model.editor.text(), "saved draft");
    assert!(
        model
            .error
            .as_deref()
            .unwrap()
            .starts_with("Room selection failed:")
    );
    model.edit(|editor| editor.insert(" continues"));
    assert_eq!(model.editor.text(), "saved draft continues");
    model.controller.shutdown();
}
