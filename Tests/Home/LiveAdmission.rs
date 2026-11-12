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
            allow_agent_replies: false,
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
        allow_agent_replies: false,
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

#[test]
fn raw_agent_replies_require_exact_cause_explicit_agent_opt_in_and_finite_chains() {
    fn committed(out: Outcome) -> Id {
        match out {
            Outcome::Committed {
                event: Some(event), ..
            } => event,
            other => panic!("{other:?}"),
        }
    }
    fn refused(out: Outcome, expected: &str) {
        assert!(
            matches!(out, Outcome::Rejected { code: ErrorCode::Denied, ref detail } if detail == expected),
            "{out:?}"
        );
    }
    fn reply(
        home: &mut Home,
        agent: &Party,
        room: RoomId,
        parent: Id,
        cause: Option<Id>,
    ) -> Outcome {
        run(
            home,
            agent,
            &action(
                agent,
                Operation::MessageReply,
                Target::Room(room),
                &messaging::Send {
                    text: "Bounded reply".into(),
                    mentions: vec![],
                    parent: Some(parent),
                    causation: cause,
                },
            ),
        )
    }
    let fixture = Fixture::new();
    let mut home = fixture.create();
    let owner = enrol(&mut home, 10, AccountClass::Human);
    let room = room(&mut home, &owner, "Causal chains");
    let mut p = policy(vec![room]);
    p.max_agents_per_operator = 3;
    home.configure_admission(p, TimeBounds::test_now()).unwrap();
    let mut agents = Vec::new();
    for (n, allow_agent_replies) in [(50, false), (60, true), (70, true)] {
        let (mut c, key) = candidate(
            n,
            vec![room],
            a::Classification::Agent {
                operator: owner.record.acting.account,
            },
        );
        c.allow_agent_replies = allow_agent_replies;
        consent(&mut home, &owner, &mut c);
        let mut changed = c.clone();
        changed.allow_agent_replies = !allow_agent_replies;
        assert!(matches!(
            request(&mut home, a::Action::Prepare(changed.into())).result,
            a::Status::Refused { .. }
        ));
        agents.push(register(&mut home, &c, &key).0);
    }
    // A raw client cannot expand the original operator-approved permission.
    refused(
        run(
            &mut home,
            &owner,
            &action(
                &owner,
                Operation::AgentSetAccess,
                Target::Account(owner.record.acting.account),
                &a::AgentAccess {
                    account: agents[0].record.acting.account,
                    rooms: vec![room],
                    allow_initiate: false,
                    allow_agent_replies: true,
                    paused: false,
                    revoke: false,
                },
            ),
        ),
        "AgentOriginalScope",
    );
    let root = committed(run(&mut home, &owner, &send(&owner, room, "Human trigger")));
    let other = committed(run(
        &mut home,
        &owner,
        &send(&owner, room, "Another human trigger"),
    ));
    refused(
        reply(&mut home, &agents[0], room, root, None),
        "AgentReplyCausation",
    );
    refused(
        reply(&mut home, &agents[0], room, root, Some(other)),
        "AgentReplyCausation",
    );
    let a1 = committed(reply(&mut home, &agents[1], room, root, Some(root)));
    refused(
        reply(&mut home, &agents[0], room, a1, Some(a1)),
        "AgentRepliesDisabled",
    );
    let b1 = committed(reply(&mut home, &agents[2], room, root, Some(root)));
    let b2 = committed(reply(&mut home, &agents[2], room, a1, Some(a1)));
    let a2 = committed(reply(&mut home, &agents[1], room, b1, Some(b1)));
    let a3 = committed(reply(&mut home, &agents[1], room, b2, Some(b2)));
    let b3 = committed(reply(&mut home, &agents[2], room, a2, Some(a2)));
    let b4 = committed(reply(&mut home, &agents[2], room, a3, Some(a3)));
    let _a4 = committed(reply(&mut home, &agents[1], room, b3, Some(b3)));
    refused(
        reply(&mut home, &agents[1], room, b4, Some(b4)),
        "AgentDepth",
    );
    refused(
        reply(&mut home, &agents[1], room, root, Some(root)),
        "AgentTriggerRepeated",
    );
    refused(
        reply(&mut home, &agents[0], room, root, Some(root)),
        "AgentChainLimit",
    );
    // A separate direct trigger remains valid: refusal did not consume or disable the account.
    committed(reply(&mut home, &agents[0], room, other, Some(other)));
}

fn expire_claim(home: &mut Home, claim: Id, consent: bool) {
    home.store
        .write(|db| {
            let bytes: Vec<u8> = db.query_row(
                "SELECT invitation FROM hrc_admission_claims WHERE id=?1",
                [claim.as_hex()],
                |r| r.get(0),
            )?;
            let mut invitation: Invitation = decode(&bytes)?;
            invitation.expires_ms = 0;
            db.execute(
                "UPDATE hrc_admission_claims SET invitation=?1,expires=0 WHERE id=?2",
                params![encode(&invitation)?, claim.as_hex()],
            )?;
            db.execute(
                "UPDATE hrc_invitations SET expires=0 WHERE id=?1",
                [invitation.id.as_hex()],
            )?;
            if consent {
                db.execute(
                    "UPDATE hrc_agent_consents SET expires=0 WHERE id=?1",
                    [claim.as_hex()],
                )?;
            }
            Ok(Commit::new((), b"test expired invitation".to_vec()))
        })
        .unwrap();
}
#[test]
fn unfinished_claim_refreshes_same_invitation_but_never_revives_completed_access() {
    let fixture = Fixture::new();
    let mut home = fixture.create();
    let owner = enrol(&mut home, 10, AccountClass::Human);
    let room = room(&mut home, &owner, "Resume");
    home.configure_admission(policy(vec![room]), TimeBounds::test_now())
        .unwrap();
    let (c, key) = candidate(50, vec![room], a::Classification::Person);
    let first = invitation(&mut home, &c);
    let signed =
        a::Artifact::new(&sign_registration(&c.registration(service(), first.id), &key).unwrap());
    expire_claim(&mut home, c.claim_id, false);
    let mut disabled = policy(vec![room]);
    disabled.enabled = false;
    home.configure_admission(disabled, TimeBounds::test_now())
        .unwrap();
    assert!(matches!(
        request(&mut home, a::Action::Prepare(c.clone().into())).result,
        a::Status::Refused { .. }
    ));
    home.configure_admission(policy(vec![room]), TimeBounds::test_now())
        .unwrap();
    let mut changed = c.clone();
    changed.native_principal = id(123);
    assert!(matches!(
        request(&mut home, a::Action::Prepare(changed.into())).result,
        a::Status::Refused { .. }
    ));
    drop(home);
    home = fixture.open();
    let refreshed = invitation(&mut home, &c);
    assert_eq!(first.id, refreshed.id);
    assert!(refreshed.expires_ms > TimeBounds::test_now().upper_ms);
    let enrolled = request(
        &mut home,
        a::Action::Enrol {
            claim_id: c.claim_id,
            registration: signed,
        },
    );
    assert!(matches!(enrolled.result, a::Status::Complete { .. }));
    home.store
        .write(|db| {
            db.execute(
                "UPDATE hrc_endpoints SET disabled=1 WHERE account=?1",
                [c.identity.account.to_string()],
            )?;
            db.execute(
                "UPDATE hrc_members SET active=0 WHERE account=?1",
                [c.identity.account.to_string()],
            )?;
            Ok(Commit::new(
                (),
                b"test disable completed participant".to_vec(),
            ))
        })
        .unwrap();
    let retry = request(&mut home, a::Action::Prepare(c.clone().into()));
    assert_eq!(
        serde_json::to_value(&retry).unwrap(),
        serde_json::to_value(enrolled).unwrap()
    );
    assert!(
        home.endpoint(c.identity.account, c.identity.endpoint)
            .unwrap()
            .is_none()
    );
    assert!(
        !home
            .store
            .read(Duration::from_secs(1), |db| db.query_row(
                "SELECT active FROM hrc_members WHERE room=?1 AND account=?2",
                params![room.to_string(), c.identity.account.to_string()],
                |r| r.get::<_, bool>(0)
            ))
            .unwrap()
    );
    let (pending, _) = candidate(60, vec![room], a::Classification::Person);
    let consumed = invitation(&mut home, &pending);
    expire_claim(&mut home, pending.claim_id, false);
    home.store
        .write(|db| {
            db.execute(
                "UPDATE hrc_invitations SET used=1 WHERE id=?1",
                [consumed.id.as_hex()],
            )?;
            Ok(Commit::new(
                (),
                b"test consumed unfinished invitation".to_vec(),
            ))
        })
        .unwrap();
    assert!(matches!(
        request(&mut home, a::Action::Prepare(pending.into())).result,
        a::Status::Refused { .. }
    ));
}
#[test]
fn expired_agent_consent_requires_current_exact_reapproval_before_resume() {
    let fixture = Fixture::new();
    let mut home = fixture.create();
    let owner = enrol(&mut home, 10, AccountClass::Human);
    let room = room(&mut home, &owner, "Agent resume");
    home.configure_admission(policy(vec![room]), TimeBounds::test_now())
        .unwrap();
    let (mut c, key) = candidate(
        50,
        vec![room],
        a::Classification::Agent {
            operator: owner.record.acting.account,
        },
    );
    consent(&mut home, &owner, &mut c);
    let first = invitation(&mut home, &c);
    let old_receipt = c.operator_consent.clone();
    expire_claim(&mut home, c.claim_id, true);
    assert!(matches!(
        request(&mut home, a::Action::Prepare(c.clone().into())).result,
        a::Status::Refused { .. }
    ));
    let mut changed = c.clone();
    changed.operator_consent = None;
    changed.allow_agent_replies = true;
    assert!(matches!(
        run(
            &mut home,
            &owner,
            &action(
                &owner,
                Operation::AgentConsent,
                Target::Account(owner.record.acting.account),
                &a::Consent { request: changed }
            )
        ),
        Outcome::Rejected { .. }
    ));
    c.operator_consent = None;
    consent(&mut home, &owner, &mut c);
    assert_ne!(old_receipt, c.operator_consent);
    // Retention of consent can end before the unfinished claim. Its original scope
    // must still prevent a fresh consent record from rebinding that claim.
    expire_claim(&mut home, c.claim_id, true);
    home.store
        .write(|db| {
            db.execute(
                "DELETE FROM hrc_agent_consents WHERE id=?1",
                [c.claim_id.as_hex()],
            )?;
            Ok(Commit::new((), b"test pruned expired consent".to_vec()))
        })
        .unwrap();
    let mut changed = c.clone();
    changed.operator_consent = None;
    changed.allow_agent_replies = true;
    assert!(matches!(
        run(
            &mut home,
            &owner,
            &action(
                &owner,
                Operation::AgentConsent,
                Target::Account(owner.record.acting.account),
                &a::Consent { request: changed }
            )
        ),
        Outcome::Rejected { .. }
    ));
    c.operator_consent = None;
    consent(&mut home, &owner, &mut c);
    let renewed = invitation(&mut home, &c);
    assert_eq!(first.id, renewed.id);
    let signed =
        a::Artifact::new(&sign_registration(&c.registration(service(), first.id), &key).unwrap());
    assert!(matches!(
        request(
            &mut home,
            a::Action::Enrol {
                claim_id: c.claim_id,
                registration: signed
            }
        )
        .result,
        a::Status::Complete { .. }
    ));
    // Completed claims return the old receipt even if an interrupted caller retained old consent.
    c.operator_consent = old_receipt;
    assert!(matches!(
        request(&mut home, a::Action::Prepare(c.clone().into())).result,
        a::Status::Complete { .. }
    ));
    c.operator_consent = None;
    assert!(matches!(
        run(
            &mut home,
            &owner,
            &action(
                &owner,
                Operation::AgentConsent,
                Target::Account(owner.record.acting.account),
                &a::Consent { request: c }
            )
        ),
        Outcome::Rejected { .. }
    ));
}

#[test]
fn retirement_cascades_exact_scoped_claims_preserves_history_and_pages_largest_snapshot() {
    let fixture = Fixture::new();
    let mut home = fixture.create();
    let host = enrol(&mut home, 10, AccountClass::Human);
    let chosen = room(&mut home, &host, "Chosen");
    home.configure_admission(policy(vec![chosen]), TimeBounds::test_now())
        .unwrap();
    let (person, key) = candidate(50, vec![chosen], a::Classification::Person);
    let (member, registration) = register(&mut home, &person, &key);
    let (mut agent, agent_key) = candidate(
        80,
        vec![chosen],
        a::Classification::Agent {
            operator: person.identity.account,
        },
    );
    consent(&mut home, &member, &mut agent);
    let (agent_member, _) = register(&mut home, &agent, &agent_key);
    let original = request(
        &mut home,
        a::Action::Status {
            claim_id: person.claim_id,
        },
    );
    // Represent expired unfinished proposals retained across many normal resumptions.
    // There are exactly1024 claims, the documented hard storage bound.
    home.store.write(|db|{
        let invitation:Vec<u8>=db.query_row("SELECT invitation FROM hrc_admission_claims WHERE id=?1",[agent.claim_id.as_hex()],|r|r.get(0))?;
        for n in 0..1022 {
            let mut pending=agent.clone();pending.claim_id=digest(format!("retired-pending-{n}").as_bytes());
            pending.identity.account.local=digest(format!("retired-account-{n}").as_bytes());
            pending.operator_consent=None;
            db.execute("INSERT INTO hrc_admission_claims(id,request,invitation,expires)VALUES(?1,?2,?3,0)",rusqlite::params![pending.claim_id.as_hex(),crate::home::types::encode(&pending)?,&invitation])?;
        }
        Ok(crate::storage::Commit::new((),b"retained pending claim fixture".to_vec()))
    }).unwrap();
    let wrong = home
        .admission_request(
            &a::Request::new(a::Action::Revoke {
                claim_id: person.claim_id,
            }),
            id(201),
            TimeBounds::test_now(),
        )
        .unwrap();
    assert!(matches!(wrong.result, a::Status::Refused { .. }));
    assert!(
        home.endpoint(person.identity.account, person.identity.endpoint)
            .unwrap()
            .is_some()
    );
    let retired = request(
        &mut home,
        a::Action::Revoke {
            claim_id: person.claim_id,
        },
    );
    let a::Status::Revoked {
        account,
        affected_claim_ids,
        more_affected,
        ..
    } = &retired.result
    else {
        panic!("{retired:?}")
    };
    assert_eq!(*account, Some(person.identity.account));
    assert_eq!(affected_claim_ids.len(), 256);
    assert!(*more_affected);
    assert!(serde_json::to_vec(&retired).unwrap().len() < a::MAXIMUM);
    let mut all = affected_claim_ids.clone();
    let mut after = all.last().copied();
    let mut pages = 1;
    loop {
        let response = request(
            &mut home,
            a::Action::RetiredClaims {
                claim_id: person.claim_id,
                after,
            },
        );
        assert!(serde_json::to_vec(&response).unwrap().len() < a::MAXIMUM);
        let a::Status::RetiredClaims {
            affected_claim_ids,
            next,
            ..
        } = response.result
        else {
            panic!()
        };
        all.extend(affected_claim_ids);
        pages += 1;
        if next.is_none() {
            break;
        }
        after = next;
    }
    assert_eq!(all.len(), 1024);
    assert_eq!(pages, 4);
    assert!(all.windows(2).all(|p| p[0] < p[1]));
    assert!(all.contains(&person.claim_id) && all.contains(&agent.claim_id));
    assert!(
        home.endpoint(person.identity.account, person.identity.endpoint)
            .unwrap()
            .is_none()
    );
    assert!(
        home.endpoint(agent.identity.account, agent.identity.endpoint)
            .unwrap()
            .is_none()
    );
    assert!(
        home.endpoint(host.record.acting.account, host.record.acting.endpoint)
            .unwrap()
            .is_some()
    );
    for party in [&member, &agent_member] {
        let outcome = run(
            &mut home,
            party,
            &action(
                party,
                Operation::RoomList,
                Target::Service,
                &conversations::List {
                    after: None,
                    limit: 16,
                },
            ),
        );
        assert!(
            matches!(outcome,Outcome::Refused{code:ErrorCode::Denied,detail,..}if detail=="EndpointDisabled")
        );
    }
    home.store
        .read(Duration::from_secs(2), |db| {
            assert_eq!(
                db.query_row("SELECT count(*) FROM hrc_accounts", [], |r| r
                    .get::<_, u64>(0))?,
                3
            );
            assert_eq!(
                db.query_row(
                    "SELECT count(*) FROM hrc_members WHERE room=?1 AND active=1",
                    [chosen.to_string()],
                    |r| r.get::<_, u64>(0)
                )?,
                1
            );
            let retained: Vec<u8> = db.query_row(
                "SELECT result FROM hrc_admission_claims WHERE id=?1",
                [person.claim_id.as_hex()],
                |r| r.get(0),
            )?;
            assert_eq!(retained, crate::home::types::encode(&original)?);
            Ok(())
        })
        .unwrap();
    for action in [
        a::Action::Status {
            claim_id: person.claim_id,
        },
        a::Action::Revoke {
            claim_id: person.claim_id,
        },
        a::Action::Prepare(person.clone().into()),
        a::Action::Enrol {
            claim_id: person.claim_id,
            registration,
        },
    ] {
        assert_eq!(
            serde_json::to_value(request(&mut home, action)).unwrap(),
            serde_json::to_value(&retired).unwrap()
        );
    }
    assert!(matches!(
        request(
            &mut home,
            a::Action::RetiredClaims {
                claim_id: person.claim_id,
                after: Some(id(250))
            }
        )
        .result,
        a::Status::Refused { .. }
    ));
    drop(home);
    home = fixture.open();
    assert_eq!(
        serde_json::to_value(request(
            &mut home,
            a::Action::Revoke {
                claim_id: person.claim_id
            }
        ))
        .unwrap(),
        serde_json::to_value(retired).unwrap()
    );
}

#[test]
fn retirement_pending_and_absent_are_distinct_and_never_revive_invitation_or_operator_quota() {
    let fixture = Fixture::new();
    let mut home = fixture.create();
    let host = enrol(&mut home, 10, AccountClass::Human);
    let chosen = room(&mut home, &host, "Chosen");
    home.configure_admission(policy(vec![chosen]), TimeBounds::test_now())
        .unwrap();
    assert!(
        matches!(request(&mut home,a::Action::Revoke{claim_id:id(250)}).result,a::Status::Refused{code}if code=="AdmissionClaimAbsent")
    );
    let (pending, _) = candidate(50, vec![chosen], a::Classification::Person);
    invitation(&mut home, &pending);
    assert!(matches!(
        request(
            &mut home,
            a::Action::Revoke {
                claim_id: pending.claim_id
            }
        )
        .result,
        a::Status::Revoked { account: None, .. }
    ));
    assert!(matches!(
        request(&mut home, a::Action::Prepare(pending.into())).result,
        a::Status::Revoked { .. }
    ));
    let (person, key) = candidate(60, vec![chosen], a::Classification::Person);
    let (member, _) = register(&mut home, &person, &key);
    let (mut agent, key) = candidate(
        80,
        vec![chosen],
        a::Classification::Agent {
            operator: person.identity.account,
        },
    );
    consent(&mut home, &member, &mut agent);
    register(&mut home, &agent, &key);
    request(
        &mut home,
        a::Action::Revoke {
            claim_id: agent.claim_id,
        },
    );
    // Revoking the Agent frees its active quota while retaining its account tombstone.
    let (mut successor, key) = candidate(
        100,
        vec![chosen],
        a::Classification::Agent {
            operator: person.identity.account,
        },
    );
    consent(&mut home, &member, &mut successor);
    register(&mut home, &successor, &key);
    assert!(
        home.endpoint(person.identity.account, person.identity.endpoint)
            .unwrap()
            .is_some()
    );
}

#[test]
fn retirement_schema_upgrades_existing_admission_without_changing_completed_claims() {
    let fixture = Fixture::new();
    let mut home = fixture.create();
    let host = enrol(&mut home, 10, AccountClass::Human);
    let chosen = room(&mut home, &host, "Chosen");
    home.configure_admission(policy(vec![chosen]), TimeBounds::test_now())
        .unwrap();
    let (person, key) = candidate(50, vec![chosen], a::Classification::Person);
    register(&mut home, &person, &key);
    let complete = request(
        &mut home,
        a::Action::Status {
            claim_id: person.claim_id,
        },
    );
    home.store
        .write(|db| {
            db.execute_batch("DROP TABLE hrc_admission_retired")?;
            Ok(crate::storage::Commit::new(
                (),
                b"pre-retirement schema fixture".to_vec(),
            ))
        })
        .unwrap();
    drop(home);
    home = fixture.open();
    assert_eq!(
        serde_json::to_value(request(
            &mut home,
            a::Action::Status {
                claim_id: person.claim_id
            }
        ))
        .unwrap(),
        serde_json::to_value(complete).unwrap()
    );
    assert!(matches!(
        request(
            &mut home,
            a::Action::Revoke {
                claim_id: person.claim_id
            }
        )
        .result,
        a::Status::Revoked {
            account: Some(_),
            ..
        }
    ));
}
