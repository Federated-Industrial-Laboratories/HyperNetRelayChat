// SPDX-License-Identifier: Apache-2.0
//! Explicit offline presentation data; this fixture does not establish HyperNet authority.
use crate::{
    client::{self, archive, cache, outbox},
    conversations::{Member, Summary},
    messaging::{PageResult, Send},
    protocol::*,
    service::{Descriptor, files},
    storage,
};
use std::{collections::BTreeMap, fs, path::PathBuf};

#[test]
#[ignore = "requires an explicit empty HRC_PRESENTATION_FIXTURE; not a native transport qualification"]
fn export_offline_presentation_fixture() {
    let root = PathBuf::from(
        std::env::var_os("HRC_PRESENTATION_FIXTURE")
            .expect("explicit fixture destination required"),
    );
    assert!(root.is_absolute());
    if root.exists() {
        files::directory(&root, false).unwrap();
        assert!(
            fs::read_dir(&root).unwrap().next().is_none(),
            "fixture destination must be empty"
        );
    } else {
        files::directory(&root, true).unwrap();
    }
    files::directory(&root.join("Data"), true).unwrap();
    files::directory(&root.join("Guard"), true).unwrap();
    let endpoint = files::create_key(&root.join("Endpoint.key")).unwrap();
    let mut secret = [0u8; 32];
    getrandom::fill(&mut secret).unwrap();
    let service_key = SigningKey::from_bytes(&secret);
    getrandom::fill(&mut secret).unwrap();
    let recovery = SigningKey::from_bytes(&secret);
    zeroize::Zeroize::zeroize(&mut secret);
    let base = super::action();
    let home = base.home;
    let account = base.actor.represented();
    let profile = client::Profile {
        server: Descriptor {
            version: 1,
            home,
            signing_key: Id::from_bytes(service_key.verifying_key().to_bytes()),
            protocol: PROTOCOL.into(),
            text_profile: crate::text::PROFILE.into(),
        },
        registration: AccountRegistration {
            home,
            account,
            endpoint: super::id(6),
            endpoint_key: Id::from_bytes(endpoint.verifying_key().to_bytes()),
            transport_principal: super::id(12),
            recovery_key: Id::from_bytes(recovery.verifying_key().to_bytes()),
            classification: AccountClass::Human,
            invitation: super::id(14),
        },
        companion: root.join("NoHyperNetCompanion"),
        clock: crate::clock::Config {
            observation: root.join("NoClockObservation"),
            monitor_key: hex::encode([15; 32]),
        },
    };
    files::create_json(&root.join("Profile.json"), &profile).unwrap();
    let key = storage::Key::create(root.join("Database.key")).unwrap();
    let mut store = storage::Store::create(
        root.join("Data"),
        root.join("Guard"),
        &key,
        *profile.registration.endpoint.as_bytes(),
        client::storage_limits(),
    )
    .unwrap();
    outbox::initialize(&mut store).unwrap();
    cache::initialize(&mut store).unwrap();
    let confidential = std::env::var_os("HRC_PRESENTATION_CONFIDENTIAL").is_some();
    if confidential {
        crate::crypto::initialize(&mut store).unwrap();
        archive::initialize(&mut store).unwrap();
    }
    let rooms = [
        RoomId {
            home,
            local: super::id(9),
        },
        RoomId {
            home,
            local: super::id(10),
        },
    ];
    let summaries: Vec<_> = rooms
        .iter()
        .enumerate()
        .map(|(i, room)| Summary {
            confidentiality: if confidential && i == 1 {
                RoomConfidentiality::PrivateGroup
            } else {
                RoomConfidentiality::Community
            },
            invited: false,
            room: *room,
            name: ["laboratory", "休憩室"][i].into(),
            topic: "Offline interface fixture; no current network authority.".into(),
            revision: 1,
            sequence: if confidential && i == 1 { 0 } else { 3 },
            joined: true,
            unread: if confidential && i == 1 { 0 } else { 3 },
        })
        .collect();
    cache::save_rooms(&mut store, &summaries).unwrap();
    let reader = AccountId {
        origin: home.network,
        local: super::id(20),
    };
    let agent = AccountId {
        origin: home.network,
        local: super::id(21),
    };
    let members = vec![
        Member {
            account,
            nickname: "Reader".into(),
            classification: AccountClass::Human,
            present: false,
            moderator: true,
        },
        Member {
            account: reader,
            nickname: "林".into(),
            classification: AccountClass::Human,
            present: false,
            moderator: false,
        },
        Member {
            account: agent,
            nickname: "Archivist".into(),
            classification: AccountClass::Agent { operator: account },
            present: false,
            moderator: false,
        },
    ];
    let now = crate::clock::TimeBounds::test_now().upper_ms;
    for room in rooms {
        let private = confidential && room == rooms[1];
        if private {
            archive::save_view(
                &mut store,
                &archive::CryptoView {
                    remote: crate::confidential::Inspection {
                        room,
                        confidentiality: RoomConfidentiality::PrivateGroup,
                        group: None,
                        epoch: 0,
                        commit_digest: None,
                        sequence: 0,
                        send_barrier: true,
                        frozen: false,
                        members: vec![],
                        packages: vec![],
                        required_removals: vec![],
                        history_from_ms: 0,
                        history_until_ms: u64::MAX,
                        filter_revision: 1,
                        ignored: vec![],
                    },
                    local: None,
                    future_only: true,
                    contacts: (20..52)
                        .map(|n| client::trust::ContactTrust {
                            account: AccountId {
                                origin: home.network,
                                local: super::id(n),
                            },
                            anchor: super::id(n),
                            head: super::id(n),
                            recovery_key: super::id(n + 50),
                            state: client::trust::TrustState::UntrustedRegistration,
                        })
                        .collect(),
                },
            )
            .unwrap();
        }
        let mut events = Vec::new();
        for (index, text) in [
            "Welcome to the offline interface fixture.",
            "Combining: e\u{301}; family: 👩‍👩‍👧‍👦; astronaut: 👩‍🚀",
            "你好。مرحبا. Persistent history and keyboard navigation.",
        ]
        .iter()
        .take(if private { 0 } else { 3 })
        .enumerate()
        {
            let mut acting = base.actor.acting().clone();
            acting.account = [account, reader, agent][index];
            let actor = if index == 2 {
                Actor::IndependentAgent {
                    acting,
                    operator: account,
                }
            } else {
                Actor::Direct { acting }
            };
            let action = Action {
                home,
                operation_id: OperationId {
                    window: super::id(7),
                    operation: Id::random().unwrap(),
                },
                actor: actor.clone(),
                target: Target::Room(room),
                operation: Operation::MessageSend,
                body: Value::serialized(&Send {
                    text: (*text).into(),
                    mentions: vec![],
                    parent: None,
                    causation: None,
                })
                .unwrap(),
                expected: BTreeMap::new(),
                approval: None,
                agreement: None,
            };
            events.push(Event {
                home,
                room,
                event: Id::random().unwrap(),
                sequence: index as u64 + 1,
                timestamp_ms: now,
                actor,
                operation_id: action.operation_id,
                action_digest: action_digest(&action).unwrap(),
                kind: action.operation,
                body: action.body,
            });
        }
        let cursor = HistoryCursor {
            home,
            room,
            account,
            sequence: if private { 0 } else { 3 },
            membership_revision: 1,
            filter_revision: 1,
            access_digest: Id::random().unwrap(),
            expires_ms: now + 300_000,
        };
        cache::receive(
            &mut store,
            room,
            account,
            &PageResult {
                events,
                cursor: Blob(sign_cursor(&cursor, &service_key).unwrap()),
                has_more: false,
                room_revision: 1,
                members: members.clone(),
            },
            &service_key.verifying_key(),
            now,
        )
        .unwrap();
    }
    outbox::save_draft(&mut store, rooms[0], "Saved draft: e\u{301} 👩‍🚀").unwrap();
    outbox::save_draft(&mut store, rooms[1], "保存した下書き / مسودة محفوظة").unwrap();
    files::create(&root.join("Fixture.txt"), b"OFFLINE PRESENTATION FIXTURE\nSynthetic display identities and messages only. No HyperNet admission, current permission, delivery, or federation is demonstrated. The missing companion and clock paths are intentional.\n").unwrap();
}
