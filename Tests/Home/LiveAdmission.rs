// SPDX-License-Identifier: Apache-2.0
//! Real encrypted Home state protects typed registration and current participant restrictions.
use super::*;
use crate::home::admission as a;
fn policy(rooms: Vec<RoomId>) -> a::Policy {
    a::Policy {
        enabled: true,
        registrar_key: id(200),
        rooms,
        agents_enabled: true,
        max_agents_per_operator: 1,
    }
}
fn candidate(n: u8, rooms: Vec<RoomId>, class: a::Classification) -> (a::Prepare, SigningKey) {
    let key = SigningKey::from_bytes(&[n; 32]);
    let recovery = SigningKey::from_bytes(&[n + 1; 32]);
    (
        a::Prepare {
            claim_id: id(n + 2),
            native_principal: id(n + 3),
            identity: a::Identity {
                account: AccountId {
                    origin: service().network,
                    local: id(n),
                },
                endpoint: id(n + 4),
                endpoint_key: Id::from_bytes(key.verifying_key().to_bytes()),
                recovery_key: Id::from_bytes(recovery.verifying_key().to_bytes()),
            },
            classification: class,
            rooms,
            allow_initiate: false,
            successor: false,
            operator_consent: None,
        },
        key,
    )
}
fn request(home: &mut Home, action: a::Action) -> a::Response {
    home.admission_request(&a::Request::new(action), id(200), TimeBounds::test_now())
        .unwrap()
}
fn invitation(home: &mut Home, c: &a::Prepare) -> Invitation {
    match request(home, a::Action::Prepare(c.clone().into())).result {
        a::Status::Prepared { invitation, .. } => invitation,
        other => panic!("{other:?}"),
    }
}
fn register(home: &mut Home, c: &a::Prepare, key: &SigningKey) -> (Party, a::Artifact) {
    let invitation = invitation(home, c);
    let signed = sign_registration(&c.registration(service(), invitation.id), key).unwrap();
    let artifact = a::Artifact::new(&signed);
    assert!(matches!(
        request(
            home,
            a::Action::Enrol {
                claim_id: c.claim_id,
                registration: artifact.clone()
            }
        )
        .result,
        a::Status::Complete { .. }
    ));
    let record = home
        .endpoint(c.identity.account, c.identity.endpoint)
        .unwrap()
        .unwrap();
    let session = AuthenticatedSession::new(&record, c.native_principal, id(220), 1).unwrap();
    let window = home
        .open_window(&record, TimeBounds::test_now(), &|| true)
        .unwrap();
    (
        Party {
            key: key.clone(),
            record,
            session,
            window,
        },
        artifact,
    )
}
fn consent(home: &mut Home, owner: &Party, c: &mut a::Prepare) {
    let out = run(
        home,
        owner,
        &action(
            owner,
            Operation::AgentConsent,
            Target::Account(owner.record.acting.account),
            &a::Consent { request: c.clone() },
        ),
    );
    let Outcome::Committed { body, .. } = out else {
        panic!("{out:?}")
    };
    let receipt: a::ConsentReceipt = body.deserialized().unwrap();
    c.operator_consent = Some(receipt.operator_consent);
}
fn rejected(outcome: Outcome) {
    assert!(
        matches!(
            outcome,
            Outcome::Rejected {
                code: ErrorCode::Denied,
                ..
            }
        ),
        "{outcome:?}"
    );
}
#[test]
fn exact_claim_registration_restart_and_restrictions_are_one_durable_result() {
    let fixture = Fixture::new();
    let mut home = fixture.create();
    let owner = enrol(&mut home, 10, AccountClass::Human);
    let chosen = room(&mut home, &owner, "Chosen");
    let hidden = room(&mut home, &owner, "Other");
    home.configure_admission(policy(vec![chosen]), TimeBounds::test_now())
        .unwrap();
    let (c, key) = candidate(50, vec![chosen], a::Classification::Person);
    let wrong = home
        .admission_request(
            &a::Request::new(a::Action::Prepare(c.clone().into())),
            id(201),
            TimeBounds::test_now(),
        )
        .unwrap();
    assert!(matches!(wrong.result, a::Status::Refused { .. }));
    let first = invitation(&mut home, &c);
    let mut changed = c.clone();
    changed.native_principal = id(99);
    assert!(matches!(
        request(&mut home, a::Action::Prepare(changed.into())).result,
        a::Status::Refused { .. }
    ));
    drop(home);
    home = fixture.open();
    assert_eq!(first.id, invitation(&mut home, &c).id);
    let wrong_key = SigningKey::from_bytes(&[99; 32]);
    let mut wrong_registration = c.registration(service(), first.id);
    wrong_registration.endpoint_key = Id::from_bytes(wrong_key.verifying_key().to_bytes());
    let wrong = sign_registration(&wrong_registration, &wrong_key).unwrap();
    assert!(matches!(
        request(
            &mut home,
            a::Action::Enrol {
                claim_id: c.claim_id,
                registration: a::Artifact::new(&wrong)
            }
        )
        .result,
        a::Status::Refused { .. }
    ));
    let (member, artifact) = register(&mut home, &c, &key);
    let out = run(
        &mut home,
        &member,
        &action(
            &member,
            Operation::RoomList,
            Target::Service,
            &conversations::List {
                after: None,
                limit: 50,
            },
        ),
    );
    let Outcome::Result { body } = out else {
        panic!("{out:?}")
    };
    let list: Vec<conversations::Summary> = body.deserialized().unwrap();
    assert_eq!(list.len(), 1);
    assert_eq!(list[0].room, chosen);
    assert!(list[0].joined);
    for operation in [
        Operation::RoomJoin,
        Operation::RoomInspect,
        Operation::RoomSetTopic,
        Operation::ModerationBan,
    ] {
        rejected(run(
            &mut home,
            &member,
            &action(&member, operation, Target::Room(hidden), &Empty {}),
        ));
    }
    rejected(run(
        &mut home,
        &member,
        &action(
            &member,
            Operation::RoomCreate,
            Target::Service,
            &conversations::Create {
                name: "Blocked".into(),
                confidentiality: RoomConfidentiality::Community,
            },
        ),
    ));
    assert!(matches!(
        run(
            &mut home,
            &member,
            &send(&member, chosen, "Allowed person message")
        ),
        Outcome::Committed { .. }
    ));
    home.store
        .write(|db| {
            db.execute(
                "UPDATE hrc_members SET active=0 WHERE account=?1",
                [c.identity.account.to_string()],
            )?;
            db.execute(
                "UPDATE hrc_endpoints SET disabled=1 WHERE account=?1",
                [c.identity.account.to_string()],
            )?;
            Ok(Commit::new((), b"test revoke".to_vec()))
        })
        .unwrap();
    drop(home);
    home = fixture.open();
    assert!(matches!(
        request(
            &mut home,
            a::Action::Enrol {
                claim_id: c.claim_id,
                registration: artifact
            }
        )
        .result,
        a::Status::Complete { .. }
    ));
    assert!(
        home.endpoint(c.identity.account, c.identity.endpoint)
            .unwrap()
            .is_none()
    );
    assert!(
        !home
            .store
            .read(Duration::from_secs(1), |db| db.query_row(
                "SELECT active FROM hrc_members WHERE account=?1 AND room=?2",
                params![c.identity.account.to_string(), chosen.to_string()],
                |r| r.get::<_, bool>(0)
            ))
            .unwrap()
    );
}
#[test]
fn operator_consent_quota_scope_and_successor_cannot_be_forged() {
    let fixture = Fixture::new();
    let mut home = fixture.create();
    let owner = enrol(&mut home, 10, AccountClass::Human);
    let chosen = room(&mut home, &owner, "Agents");
    home.configure_admission(policy(vec![chosen]), TimeBounds::test_now())
        .unwrap();
    let (mut c, key) = candidate(
        50,
        vec![chosen],
        a::Classification::Agent {
            operator: owner.record.acting.account,
        },
    );
    c.successor = true;
    assert!(matches!(
        request(&mut home, a::Action::Prepare(c.clone().into())).result,
        a::Status::Refused { .. }
    ));
    consent(&mut home, &owner, &mut c);
    let mut changed = c.clone();
    changed.allow_initiate = true;
    assert!(matches!(
        request(&mut home, a::Action::Prepare(changed.into())).result,
        a::Status::Refused { .. }
    ));
    let (mut second, key2) = candidate(
        60,
        vec![chosen],
        a::Classification::Agent {
            operator: owner.record.acting.account,
        },
    );
    consent(&mut home, &owner, &mut second);
    let pending = invitation(&mut home, &second);
    let (extra, _) = candidate(
        70,
        vec![chosen],
        a::Classification::Agent {
            operator: owner.record.acting.account,
        },
    );
    rejected(run(
        &mut home,
        &owner,
        &action(
            &owner,
            Operation::AgentConsent,
            Target::Account(owner.record.acting.account),
            &a::Consent { request: extra },
        ),
    ));
    let (agent, _) = register(&mut home, &c, &key);
    let bytes = sign_registration(&second.registration(service(), pending.id), &key2).unwrap();
    assert!(matches!(
        request(
            &mut home,
            a::Action::Enrol {
                claim_id: second.claim_id,
                registration: a::Artifact::new(&bytes)
            }
        )
        .result,
        a::Status::Refused { .. }
    ));
    assert!(
        home.endpoint(second.identity.account, second.identity.endpoint)
            .unwrap()
            .is_none()
    );
    rejected(run(&mut home, &agent, &send(&agent, chosen, "Unsolicited")));
    let original = run(&mut home, &owner, &send(&owner, chosen, "Please reply"));
    let Outcome::Committed {
        event: Some(event), ..
    } = original
    else {
        panic!()
    };
    let reply = action(
        &agent,
        Operation::MessageReply,
        Target::Room(chosen),
        &messaging::Send {
            text: "Reply".into(),
            parent: Some(event),
            causation: Some(event),
            mentions: vec![],
        },
    );
    assert!(matches!(
        run(&mut home, &agent, &reply),
        Outcome::Committed { .. }
    ));
    let members = home
        .store
        .read(Duration::from_secs(1), |db| {
            crate::conversations::members(db, chosen, TimeBounds::test_now()).map_err(sql_fault)
        })
        .unwrap();
    assert_eq!(
        members
            .iter()
            .find(|m| m.account == c.identity.account)
            .unwrap()
            .successor_of,
        Some(owner.record.acting.account)
    );
    assert_eq!(
        home.endpoint(owner.record.acting.account, owner.record.acting.endpoint)
            .unwrap()
            .unwrap()
            .classification,
        AccountClass::Human
    );
    let access = a::AgentAccess {
        account: c.identity.account,
        rooms: vec![chosen],
        allow_initiate: false,
        paused: true,
        revoke: false,
    };
    assert!(matches!(
        run(
            &mut home,
            &owner,
            &action(
                &owner,
                Operation::AgentSetAccess,
                Target::Account(owner.record.acting.account),
                &access
            )
        ),
        Outcome::Committed { .. }
    ));
    rejected(run(
        &mut home,
        &agent,
        &action(
            &agent,
            Operation::RoomList,
            Target::Service,
            &conversations::List {
                after: None,
                limit: 10,
            },
        ),
    ));
    let mut revoke = access;
    revoke.revoke = true;
    assert!(matches!(
        run(
            &mut home,
            &owner,
            &action(
                &owner,
                Operation::AgentSetAccess,
                Target::Account(owner.record.acting.account),
                &revoke
            )
        ),
        Outcome::Committed { .. }
    ));
    assert!(matches!(
        request(
            &mut home,
            a::Action::Enrol {
                claim_id: second.claim_id,
                registration: a::Artifact::new(&bytes)
            }
        )
        .result,
        a::Status::Complete { .. }
    ));
}
#[test]
fn disabled_operator_endpoint_and_disabled_host_agent_policy_refuse_consent_reuse() {
    let fixture = Fixture::new();
    let mut home = fixture.create();
    let owner = enrol(&mut home, 10, AccountClass::Human);
    let chosen = room(&mut home, &owner, "Agents");
    let mut p = policy(vec![chosen]);
    home.configure_admission(p.clone(), TimeBounds::test_now())
        .unwrap();
    let (mut c, _) = candidate(
        50,
        vec![chosen],
        a::Classification::Agent {
            operator: owner.record.acting.account,
        },
    );
    consent(&mut home, &owner, &mut c);
    p.agents_enabled = false;
    home.configure_admission(p.clone(), TimeBounds::test_now())
        .unwrap();
    assert!(matches!(
        request(&mut home, a::Action::Prepare(c.clone().into())).result,
        a::Status::Refused { .. }
    ));
    p.agents_enabled = true;
    home.configure_admission(p, TimeBounds::test_now()).unwrap();
    home.store
        .write(|db| {
            db.execute(
                "UPDATE hrc_endpoints SET disabled=1 WHERE account=?1",
                [owner.record.acting.account.to_string()],
            )?;
            Ok(Commit::new((), b"disabled operator".to_vec()))
        })
        .unwrap();
    assert!(matches!(
        request(&mut home, a::Action::Prepare(c.into())).result,
        a::Status::Refused { .. }
    ));
}
