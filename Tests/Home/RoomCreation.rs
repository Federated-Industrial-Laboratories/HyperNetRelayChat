use super::*;
use crate::{home::RoomCreationPolicy, service};

fn create(party: &Party, mode: RoomConfidentiality) -> Action {
    action(
        party,
        Operation::RoomCreate,
        Target::Service,
        &conversations::Create {
            name: "New room".into(),
            confidentiality: mode,
        },
    )
}
fn denied(outcome: Outcome) {
    assert!(
        matches!(outcome, Outcome::Rejected { code: ErrorCode::Denied, detail } if detail == "RoomCreationPolicy")
    );
}

#[test]
fn owner_policy_blocks_members_agents_and_direct_creation_without_changing_existing_rooms() {
    let fixture = Fixture::new();
    let mut home = fixture.create();
    let owner = enrol(&mut home, 10, AccountClass::Human);
    let member = enrol(&mut home, 40, AccountClass::Human);
    let agent = enrol(
        &mut home,
        70,
        AccountClass::Agent {
            operator: owner.record.acting.account,
        },
    );
    let before_policy = room(&mut home, &member, "Existing member room");
    home = home
        .with_room_creation(RoomCreationPolicy::AllowList {
            accounts: vec![owner.record.acting.account],
        })
        .unwrap();
    let owner_room = room(&mut home, &owner, "Owner room");
    for party in [&member, &agent] {
        for mode in [
            RoomConfidentiality::Community,
            RoomConfidentiality::PrivateGroup,
        ] {
            denied(run(&mut home, party, &create(party, mode)));
        }
        denied(run(
            &mut home,
            party,
            &action(
                party,
                Operation::DirectCreate,
                Target::Service,
                &crate::confidential::Direct {
                    recipient: owner.record.acting.account,
                },
            ),
        ));
        assert!(matches!(
            run(
                &mut home,
                party,
                &action(
                    party,
                    Operation::RoomJoin,
                    Target::Room(owner_room),
                    &Empty {}
                )
            ),
            Outcome::Committed { .. }
        ));
    }
    assert!(matches!(
        run(
            &mut home,
            &member,
            &send(&member, owner_room, "Member message")
        ),
        Outcome::Committed { .. }
    ));
    assert!(matches!(
        run(
            &mut home,
            &member,
            &send(&member, before_policy, "Retained room")
        ),
        Outcome::Committed { .. }
    ));
    home.store
        .read(Duration::from_secs(1), |db| {
            let count: u64 =
                db.query_row("SELECT count(*) FROM hrc_rooms", [], |row| row.get(0))?;
            assert_eq!(count, 2);
            let moderator: bool = db.query_row(
                "SELECT moderator FROM hrc_members WHERE room=?1 AND account=?2",
                params![
                    owner_room.to_string(),
                    member.record.acting.account.to_string()
                ],
                |row| row.get(0),
            )?;
            assert!(!moderator);
            Ok(())
        })
        .unwrap();
    home = home
        .with_room_creation(RoomCreationPolicy::AllowList { accounts: vec![] })
        .unwrap();
    denied(run(
        &mut home,
        &owner,
        &create(&owner, RoomConfidentiality::Community),
    ));
}

fn service_configuration(fixture: &Fixture) -> service::Config {
    let config = service::Config {
        descriptor: service::Descriptor {
            version: 1,
            home: service(),
            signing_key: Id::from_bytes(
                SigningKey::from_bytes(&[4; 32]).verifying_key().to_bytes(),
            ),
            protocol: PROTOCOL.into(),
            text_profile: crate::text::PROFILE.into(),
        },
        companion: fixture.root.join("Companion"),
        clock: crate::clock::Config {
            observation: fixture.root.join("Clock.cbor"),
            monitor_key: hex::encode([5; 32]),
        },
        motd: String::new(),
        room_creation: RoomCreationPolicy::default(),
        admission_bridge: None,
    };
    fs::rename(fixture.root.join("Key"), fixture.root.join("Database.key")).unwrap();
    service::files::create(&fixture.root.join("Signing.key"), &[4; 32]).unwrap();
    service::files::create_json(&fixture.root.join("Service.json"), &config).unwrap();
    config
}

#[test]
fn stopped_policy_update_is_private_persistent_and_refuses_agents_and_busy_stores() {
    let fixture = Fixture::new();
    let mut home = fixture.create();
    let owner = enrol(&mut home, 10, AccountClass::Human);
    let member = enrol(&mut home, 40, AccountClass::Human);
    let agent = enrol(
        &mut home,
        70,
        AccountClass::Agent {
            operator: owner.record.acting.account,
        },
    );
    let config = service_configuration(&fixture);
    let policy = RoomCreationPolicy::AllowList {
        accounts: vec![owner.record.acting.account],
    };
    let previous = fs::read(fixture.root.join("Service.json")).unwrap();
    assert!(service::setup::room_creation(&fixture.root, policy.clone()).is_err());
    assert_eq!(
        fs::read(fixture.root.join("Service.json")).unwrap(),
        previous
    );
    drop(home);
    assert_eq!(
        service::setup::room_creation(&fixture.root, policy.clone()).unwrap(),
        policy
    );
    let saved = fs::read(fixture.root.join("Service.json")).unwrap();
    assert_eq!(
        fs::metadata(fixture.root.join("Service.json"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    for accounts in [
        vec![agent.record.acting.account],
        vec![owner.record.acting.account; 2],
        vec![AccountId {
            local: id(90),
            ..owner.record.acting.account
        }],
    ] {
        assert!(
            service::setup::room_creation(
                &fixture.root,
                RoomCreationPolicy::AllowList { accounts }
            )
            .is_err()
        );
        assert_eq!(fs::read(fixture.root.join("Service.json")).unwrap(), saved);
    }
    let restored = service::Config::load(&fixture.root).unwrap();
    assert_eq!(restored.room_creation, policy);
    let mut home = fixture
        .open()
        .with_room_creation(restored.room_creation)
        .unwrap();
    denied(run(
        &mut home,
        &member,
        &create(&member, RoomConfidentiality::Community),
    ));
    room(&mut home, &owner, "Owner after restart");
    drop(home);
    let mut old = serde_json::to_value(config).unwrap();
    old.as_object_mut().unwrap().remove("roomCreation");
    let old: service::Config = serde_json::from_value(old).unwrap();
    assert_eq!(old.room_creation, RoomCreationPolicy::All);
    assert!(
        serde_json::from_value::<RoomCreationPolicy>(serde_json::json!({"mode":"unrecognised"}))
            .is_err()
    );
}

#[test]
fn allowlist_uses_exact_direct_account_and_never_agent_operator_or_delegated_owner() {
    let fixture = Fixture::new();
    let mut home = fixture.create();
    let owner = enrol(&mut home, 10, AccountClass::Human);
    let agent = enrol(
        &mut home,
        70,
        AccountClass::Agent {
            operator: owner.record.acting.account,
        },
    );
    let policy = RoomCreationPolicy::AllowList {
        accounts: vec![owner.record.acting.account],
    };
    assert!(policy.permits(&actor(&owner)));
    assert!(!policy.permits(&actor(&agent)));
    assert!(!policy.permits(&Actor::Delegated {
        acting: agent.record.acting,
        operator: owner.record.acting.account,
        represented: owner.record.acting.account,
        represented_security_generation: 1,
        grant: GrantRef {
            id: id(100),
            generation: 1,
        },
    }));
    let foreign = RoomCreationPolicy::AllowList {
        accounts: vec![AccountId {
            origin: NetworkId {
                network: id(200),
                incarnation: id(201),
            },
            ..owner.record.acting.account
        }],
    };
    assert!(foreign.validate(service().network).is_err());
}
