// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::client::{self, archive, cache};
use crate::{confidential, conversations, crypto, messaging, service};
use std::{sync::atomic::AtomicBool, time::Duration};
fn offline(f: &Fixture) -> client::Client {
    let store = f.create();
    drop(store);
    fs::rename(f.root.join("Key"), f.root.join("Database.key")).unwrap();
    let key = service::files::create_key(&f.root.join("Endpoint.key")).unwrap();
    let a = action();
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
            endpoint_key: Id::from_bytes(key.verifying_key().to_bytes()),
            transport_principal: id(12),
            recovery_key: Id::from_bytes(
                SigningKey::from_bytes(&[13; 32]).verifying_key().to_bytes(),
            ),
            classification: AccountClass::Human,
            invitation: id(14),
        },
        companion: f.root.join("NoCompanion"),
        clock: crate::clock::Config {
            observation: f.root.join("NoClock"),
            monitor_key: hex::encode([15; 32]),
        },
    };
    service::files::create_json(&f.root.join("Profile.json"), &profile).unwrap();
    client::Client::open_offline(&f.root).unwrap()
}
fn view(room: RoomId, now: u64) -> archive::CryptoView {
    archive::CryptoView {
        remote: confidential::Inspection {
            room,
            confidentiality: RoomConfidentiality::PrivateGroup,
            group: Some(id(33)),
            epoch: 1,
            commit_digest: Some(id(34)),
            sequence: 1,
            send_barrier: true,
            frozen: false,
            members: vec![],
            packages: vec![],
            required_removals: vec![],
            history_from_ms: now - 1000,
            history_until_ms: now + 1000,
            filter_revision: 1,
            ignored: vec![],
        },
        local: None,
        contacts: vec![],
        future_only: true,
    }
}
fn event(sequence: u64, time: u64) -> Event {
    let a = action();
    let Target::Room(room) = a.target else {
        unreachable!()
    };
    let context = crypto::EncryptionContext {
        home: a.home,
        room,
        operation_id: OperationId {
            window: id(7),
            operation: id(sequence as u8 + 40),
        },
        actor: a.actor,
        operation: Operation::MessageSend,
        expected: BTreeMap::new(),
        approval: None,
        agreement: None,
        group: id(33),
        epoch: 1,
        parent: None,
        causation: None,
    };
    let ciphertext = vec![1, 2, 3];
    let digest = action_digest(&context.action(ciphertext.clone()).unwrap()).unwrap();
    Event {
        home: room.home,
        room,
        event: id(sequence as u8 + 50),
        sequence,
        operation_id: context.operation_id,
        action_digest: digest,
        actor: context.actor.clone(),
        kind: Operation::MessageSend,
        timestamp_ms: time,
        body: Value::serialized(&crypto::EncryptedEvent {
            context,
            ciphertext: Blob(ciphertext),
        })
        .unwrap(),
    }
}
#[test]
fn encrypted_archive_search_restart_filters_and_expiry_preserve_authenticated_events() {
    let f = Fixture::new();
    let mut client = offline(&f);
    let e = event(1, TimeBounds::test_now().lower_ms);
    let room = e.room;
    let mut state = view(room, e.timestamp_ms);
    cache::save_rooms(
        &mut client.store,
        room.home,
        &[conversations::Summary {
            room,
            name: "private".into(),
            topic: String::new(),
            revision: 1,
            sequence: 2,
            joined: true,
            unread: 2,
            confidentiality: RoomConfidentiality::PrivateGroup,
            invited: false,
        }],
    )
    .unwrap();
    archive::save_view(&mut client.store, &state).unwrap();
    let text = crypto::ApplicationMessage {
        text: "café e\u{301} 👩‍🚀".into(),
        mentions: vec![],
    };
    client
        .store
        .write(|tx| {
            archive::persist_content(tx, &e, &archive::MessageContent::Decrypted(text.clone()))
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
            Ok(storage::Commit::new(
                (),
                b"authorised archive fixture".to_vec(),
            ))
        })
        .unwrap();
    let query = messaging::Search {
        terms: vec!["café".into()],
        sender: None,
        represented: None,
        from_ms: None,
        until_ms: None,
        cursor: None,
        limit: 1,
    };
    let found = client
        .search_retained(room, &query, &AtomicBool::new(false))
        .unwrap();
    assert!(found.stale);
    assert_eq!(found.events.len(), 1);
    assert_eq!(
        cache::encode(&found.events[0]).unwrap(),
        cache::encode(&e).unwrap()
    );
    assert_eq!(
        found.content[&e.event],
        archive::MessageContent::Decrypted(text)
    );
    drop(client);
    let mut client = client::Client::open_offline(&f.root).unwrap();
    assert_eq!(
        client
            .search_retained(room, &query, &AtomicBool::new(false))
            .unwrap()
            .events
            .len(),
        1
    );
    assert!(
        client
            .search_retained(room, &query, &AtomicBool::new(true))
            .is_err()
    );
    state.remote.history_until_ms = e.timestamp_ms - 1;
    archive::save_view(&mut client.store, &state).unwrap();
    assert!(
        client
            .search_retained(room, &query, &AtomicBool::new(false))
            .unwrap()
            .events
            .is_empty()
    );
    let mut next = query.clone();
    next.cursor = Some(found.cursor);
    assert!(
        client
            .search_retained(room, &next, &AtomicBool::new(false))
            .is_err()
    );
    state.remote.history_until_ms = e.timestamp_ms + 1000;
    state.remote.ignored.push(e.actor.represented());
    state.remote.filter_revision += 1;
    archive::save_view(&mut client.store, &state).unwrap();
    assert!(
        client
            .search_retained(room, &query, &AtomicBool::new(false))
            .unwrap()
            .events
            .is_empty()
    );
    let old = event(2, e.timestamp_ms - 8 * 86_400_000);
    client
        .store
        .write(|tx| {
            archive::persist_content(
                tx,
                &old,
                &archive::MessageContent::Decrypted("expired secret".into()),
            )
            .map_err(|_| rusqlite::Error::InvalidQuery)?;
            Ok(storage::Commit::new((), b"expiry fixture".to_vec()))
        })
        .unwrap();
    cache::maintain(&mut client.store).unwrap();
    assert!(
        archive::content(&mut client.store, &[old])
            .unwrap()
            .is_empty()
    );
    assert_eq!(client.store.read(Duration::from_secs(1),|db|db.query_row("SELECT count(*) FROM client_cleartext_search WHERE client_cleartext_search MATCH 'expired'",[],|r|r.get::<_,u32>(0))).unwrap(),0);
    // Transport/refusal errors do not erase retained private content or manufacture a gap.
    let before = client.store.usage().unwrap().commit_counter;
    assert!(
        !cache::inspection_failed(
            &mut client.store,
            Operation::CryptoHistory,
            room,
            &client::Error::Refused {
                code: ErrorCode::Unavailable,
                detail: "temporary".into(),
                retry_after_ms: Some(10)
            }
        )
        .unwrap()
    );
    assert_eq!(client.store.usage().unwrap().commit_counter, before);
    assert!(
        !archive::content(&mut client.store, &[e])
            .unwrap()
            .is_empty()
    );
}

#[test]
fn encrypted_cursor_restart_preserves_plaintext_pending_mls_and_drafts_after_reopen() {
    let f = Fixture::new();
    let mut client = offline(&f);
    let e = event(1, TimeBounds::test_now().lower_ms);
    let room = e.room;
    cache::save_rooms(
        &mut client.store,
        e.home,
        &[conversations::Summary {
            room,
            name: "private".into(),
            topic: String::new(),
            revision: 1,
            sequence: 1,
            joined: true,
            unread: 0,
            confidentiality: RoomConfidentiality::PrivateGroup,
            invited: false,
        }],
    )
    .unwrap();
    let key = SigningKey::from_bytes(&[11; 32]);
    let mut cursor = HistoryCursor {
        home: e.home,
        room,
        account: e.actor.represented(),
        sequence: 1,
        membership_revision: 1,
        filter_revision: 1,
        access_digest: id(70),
        expires_ms: e.timestamp_ms + 300_000,
    };
    let mut page = messaging::PageResult {
        events: vec![e.clone()],
        cursor: Blob(sign_cursor(&cursor, &key).unwrap()),
        has_more: false,
        room_revision: 1,
        members: vec![],
    };
    cache::receive(
        &mut client.store,
        room,
        e.actor.represented(),
        &page,
        &key.verifying_key(),
        e.timestamp_ms,
    )
    .unwrap();
    let text = archive::MessageContent::Decrypted("retained secret".into());
    client
        .store
        .write(|tx| {
            archive::persist_content(tx, &e, &text).map_err(|_| rusqlite::Error::InvalidQuery)?;
            Ok(storage::Commit::new(
                (),
                b"retained encrypted history".to_vec(),
            ))
        })
        .unwrap();
    client.save_draft(room, "unfinished reply").unwrap();
    let device = crypto::Device::provision(&mut client.store, e.actor.acting().clone()).unwrap();
    let roster = crypto::ApprovedRoster::new(room, vec![device.credential(room)]).unwrap();
    let group = id(71);
    device
        .create_group(&mut client.store, group, &roster, 0)
        .unwrap();
    let pending = device
        .prepare_transition(
            &mut client.store,
            group,
            0,
            &roster,
            &roster,
            crypto::Change::Update,
        )
        .unwrap();
    let state = cache::encode(&device.state(&mut client.store, group).unwrap()).unwrap();
    let changed = client::Error::Rejected {
        code: ErrorCode::ResynchronisationRequired,
        detail: "CursorContext".into(),
    };
    let before = client.store.usage().unwrap().commit_counter;
    assert!(
        !cache::inspection_failed(&mut client.store, Operation::CryptoHistory, room, &changed)
            .unwrap()
    );
    assert_eq!(client.store.usage().unwrap().commit_counter, before);
    for detail in ["CursorHistoryGap", "CursorPosition"] {
        let error = client::Error::Rejected {
            code: ErrorCode::ResynchronisationRequired,
            detail: detail.into(),
        };
        assert!(!cache::cursor_context_changed(&error));
        assert!(
            cache::inspection_failed(&mut client.store, Operation::CryptoHistory, room, &error)
                .unwrap()
        );
        let cached = cache::room(&mut client.store, room).unwrap();
        assert_eq!(cached.gap.as_deref(), Some(detail));
        assert_eq!(cached.events.len(), 1);
        assert!(cached.cursor.is_some());
        assert_eq!(
            archive::content(&mut client.store, std::slice::from_ref(&e)).unwrap()[&e.event],
            text
        );
        assert_eq!(
            cache::encode(&device.state(&mut client.store, group).unwrap()).unwrap(),
            state
        );
    }
    // Explicit acknowledgement may reset continuation but cannot recreate old
    // decryption keys, so the retained local rows and pending MLS state survive.
    client.resynchronise_history(room).unwrap();
    drop(client);
    let mut client = client::Client::open_offline(&f.root).unwrap();
    let cached = cache::room(&mut client.store, room).unwrap();
    assert!(cached.cursor.is_none());
    assert_eq!(cached.events.len(), 1);
    assert_eq!(
        archive::content(&mut client.store, std::slice::from_ref(&e)).unwrap()[&e.event],
        text
    );
    assert_eq!(
        client.draft(room).unwrap().as_deref(),
        Some("unfinished reply")
    );
    assert_eq!(
        cache::encode(&device.state(&mut client.store, group).unwrap()).unwrap(),
        state
    );
    assert_eq!(
        device
            .prepare_transition(
                &mut client.store,
                group,
                0,
                &roster,
                &roster,
                crypto::Change::Update
            )
            .unwrap()
            .commit,
        pending.commit
    );
    cursor.access_digest = id(72);
    page.cursor = Blob(sign_cursor(&cursor, &key).unwrap());
    page.room_revision += 1;
    cache::receive(
        &mut client.store,
        room,
        e.actor.represented(),
        &page,
        &key.verifying_key(),
        e.timestamp_ms,
    )
    .unwrap();
    assert_eq!(
        archive::content(&mut client.store, std::slice::from_ref(&e)).unwrap()[&e.event],
        text
    );
    assert!(
        cache::inspection_failed(
            &mut client.store,
            Operation::CryptoHistory,
            room,
            &client::Error::Rejected {
                code: ErrorCode::Denied,
                detail: "Membership".into(),
            }
        )
        .unwrap()
    );
    assert!(
        cache::room(&mut client.store, room)
            .unwrap()
            .events
            .is_empty()
    );
    assert!(
        archive::content(&mut client.store, &[e])
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        client.draft(room).unwrap().as_deref(),
        Some("unfinished reply")
    );
}

#[test]
fn current_encrypted_history_window_limits_retained_presentation() {
    let e = event(1, TimeBounds::test_now().lower_ms);
    let mut current = view(e.room, e.timestamp_ms);
    current.remote.history_from_ms = e.timestamp_ms;
    current.remote.history_until_ms = e.timestamp_ms;
    assert!(current.history_visible(&e));
    current.remote.history_from_ms += 1;
    assert!(!current.history_visible(&e));
    current.remote.history_from_ms = e.timestamp_ms - 1;
    current.remote.history_until_ms = e.timestamp_ms - 1;
    assert!(!current.history_visible(&e));
    current.remote.history_until_ms = e.timestamp_ms;
    current.remote.ignored.push(e.actor.represented());
    assert!(!current.history_visible(&e));
    current.remote.ignored.clear();
    let mut foreign = e.clone();
    foreign.room.local = id(73);
    assert!(!current.history_visible(&foreign));
    assert!(current.history_visible(&e));
}

#[test]
fn maximum_filter_and_contact_views_roundtrip_with_independent_canonical_bounds() {
    let f = Fixture::new();
    let mut client = offline(&f);
    let e = event(1, TimeBounds::test_now().lower_ms);
    let mut state = view(e.room, e.timestamp_ms);
    for n in 0..=255u8 {
        let account = AccountId {
            origin: e.home.network,
            local: id(n),
        };
        state.remote.ignored.push(account);
        state.contacts.push(client::trust::ContactTrust {
            account,
            anchor: id(60),
            head: id(61),
            recovery_key: id(62),
            state: client::trust::TrustState::Trusted,
        });
    }
    archive::save_view(&mut client.store, &state).unwrap();
    drop(client);
    let mut client = client::Client::open_offline(&f.root).unwrap();
    let restored = archive::view(&mut client.store, e.room).unwrap().unwrap();
    assert_eq!(restored.remote.ignored.len(), 256);
    assert_eq!(restored.contacts.len(), 256);
    assert_eq!(
        serde_json::to_value(&restored).unwrap(),
        serde_json::to_value(&state).unwrap()
    );
    let counter = client.store.usage().unwrap().commit_counter;
    state.contacts.push(state.contacts[0].clone());
    assert!(archive::save_view(&mut client.store, &state).is_err());
    assert_eq!(client.store.usage().unwrap().commit_counter, counter);
}
