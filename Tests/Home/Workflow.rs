use super::*;
use crate::{conversations, delegation, identity, messaging, moderation};
use std::{
    cell::Cell,
    collections::BTreeMap,
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::atomic::{AtomicU64, Ordering},
};
static NEXT: AtomicU64 = AtomicU64::new(0);
fn id(n: u8) -> Id {
    Id::from_bytes([n; 32])
}
fn service() -> ServiceId {
    ServiceId {
        network: NetworkId {
            network: id(1),
            incarnation: id(2),
        },
        service: id(3),
    }
}
struct Fixture {
    root: PathBuf,
    key: storage::Key,
}

#[test]
fn idle_maintenance_writes_only_when_retention_has_work() {
    let fixture = Fixture::new();
    let mut home = fixture.create();
    let before = home.usage().unwrap().commit_counter;
    home.maintain(TimeBounds::test_now()).unwrap();
    assert_eq!(home.usage().unwrap().commit_counter, before);
    home.store
        .write(|db| {
            db.execute("INSERT INTO hrc_budgets VALUES('expired',0,0)", [])?;
            Ok(Commit::new((), b"expired budget fixture".to_vec()))
        })
        .unwrap();
    let before = home.usage().unwrap().commit_counter;
    home.maintain(TimeBounds::test_now()).unwrap();
    assert_eq!(home.usage().unwrap().commit_counter, before + 1);
    let remaining: u64 = home
        .store
        .read(Duration::from_secs(1), |db| {
            db.query_row("SELECT count(*) FROM hrc_budgets", [], |r| r.get(0))
        })
        .unwrap();
    assert_eq!(remaining, 0);
    home.maintain(TimeBounds::test_now()).unwrap();
    assert_eq!(home.usage().unwrap().commit_counter, before + 1);
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "hrc-home-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["Data", "Guard"] {
            let p = root.join(name);
            fs::create_dir(&p).unwrap();
            fs::set_permissions(p, fs::Permissions::from_mode(0o700)).unwrap();
        }
        let key = storage::Key::create(root.join("Key")).unwrap();
        Self { root, key }
    }
    fn create(&self) -> Home {
        let store = Store::create(
            self.root.join("Data"),
            self.root.join("Guard"),
            &self.key,
            *service().service.as_bytes(),
            storage::Limits::default(),
        )
        .unwrap();
        Home::create(store, service(), SigningKey::from_bytes(&[4; 32])).unwrap()
    }
    fn open(&self) -> Home {
        let store = Store::open(
            self.root.join("Data"),
            self.root.join("Guard"),
            &self.key,
            *service().service.as_bytes(),
            storage::Limits::default(),
        )
        .unwrap();
        Home::open(store, service(), SigningKey::from_bytes(&[4; 32])).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
struct Party {
    key: SigningKey,
    record: EndpointRecord,
    session: AuthenticatedSession,
    window: RetryWindow,
}
fn enrol(home: &mut Home, n: u8, class: AccountClass) -> Party {
    let key = SigningKey::from_bytes(&[n; 32]);
    let recovery = SigningKey::from_bytes(&[n + 100; 32]);
    let principal = id(n + 50);
    let invitation = home
        .issue_invitation(principal, class.clone(), TimeBounds::test_now())
        .unwrap();
    let registration = AccountRegistration {
        home: service(),
        account: AccountId {
            origin: service().network,
            local: id(n),
        },
        endpoint: id(n + 1),
        endpoint_key: Id::from_bytes(key.verifying_key().to_bytes()),
        transport_principal: principal,
        recovery_key: Id::from_bytes(recovery.verifying_key().to_bytes()),
        classification: class,
        invitation: invitation.id,
    };
    let signed = sign_registration(&registration, &key).unwrap();
    let verified = verify_registration_request(&signed).unwrap();
    let record = home
        .accept_registration(&verified, TimeBounds::test_now())
        .unwrap();
    let session = AuthenticatedSession::new(&record, principal, id(n + 2), 1).unwrap();
    let window = home
        .open_window(&record, TimeBounds::test_now(), &|| true)
        .unwrap();
    Party {
        key,
        record,
        session,
        window,
    }
}
fn actor(p: &Party) -> Actor {
    match p.record.classification {
        AccountClass::Human => Actor::Direct {
            acting: p.record.acting.clone(),
        },
        AccountClass::Agent { operator } => Actor::IndependentAgent {
            acting: p.record.acting.clone(),
            operator,
        },
    }
}
fn action<T: serde::Serialize>(
    p: &Party,
    operation: Operation,
    target: Target,
    body: &T,
) -> Action {
    Action {
        home: service(),
        operation_id: OperationId {
            window: p.window.id,
            operation: Id::random().unwrap(),
        },
        actor: actor(p),
        target,
        operation,
        body: Value::serialized(body).unwrap(),
        expected: BTreeMap::new(),
        approval: None,
        agreement: None,
    }
}
fn verified(p: &Party, a: &Action) -> VerifiedAction {
    verify_action(&sign_action(a, &p.key).unwrap(), &p.key.verifying_key()).unwrap()
}
fn run(home: &mut Home, p: &Party, a: &Action) -> Outcome {
    let response = home
        .execute(&verified(p, a), &p.session, TimeBounds::test_now(), &|| {
            true
        })
        .unwrap();
    let signed = sign_response(&response, home.signing_key()).unwrap();
    let decoded = verify_response(&signed, &home.signing_key().verifying_key()).unwrap();
    assert!(
        encode(decoded.value()).unwrap() == encode(&response).unwrap(),
        "signed response changed canonical content"
    );
    response.outcome
}
fn room(home: &mut Home, p: &Party, name: &str) -> RoomId {
    let out = run(
        home,
        p,
        &action(
            p,
            Operation::RoomCreate,
            Target::Service,
            &conversations::Create {
                name: name.into(),
                confidentiality: RoomConfidentiality::Community,
            },
        ),
    );
    match out {
        Outcome::Committed { body, .. } => body
            .deserialized::<messaging::Committed>()
            .unwrap()
            .room
            .unwrap(),
        other => panic!("room result {other:?}"),
    }
}
fn send(p: &Party, room: RoomId, text: &str) -> Action {
    action(
        p,
        Operation::MessageSend,
        Target::Room(room),
        &messaging::Send {
            text: text.into(),
            parent: None,
            causation: None,
        },
    )
}
fn resolved(outcome: Outcome) -> Outcome {
    match outcome {
        Outcome::Result { body } => body.deserialized::<ResolveResult>().unwrap().outcome,
        other => panic!("resolve result {other:?}"),
    }
}
fn history(home: &mut Home, p: &Party, room: RoomId) -> messaging::PageResult {
    let out = run(
        home,
        p,
        &action(
            p,
            Operation::HistoryPage,
            Target::Room(room),
            &messaging::Page {
                cursor: None,
                limit: 50,
            },
        ),
    );
    match out {
        Outcome::Result { body } => body.deserialized().unwrap(),
        other => panic!("history result {other:?}"),
    }
}
fn grant(
    home: &mut Home,
    owner: &Party,
    agent: &Party,
    room: RoomId,
    mode: delegation::Mode,
) -> GrantRef {
    let now = TimeBounds::test_now();
    let scope = delegation::Create {
        agent: agent.record.acting.clone(),
        rooms: vec![room],
        recipients: vec![],
        operations: vec![Operation::MessageSend, Operation::HistoryPage],
        mode,
        not_before_ms: now.lower_ms.saturating_sub(1000),
        expires_ms: now.upper_ms + 60_000,
        history_from_ms: 0,
        history_until_ms: i64::MAX as u64,
        max_operations_per_minute: 120,
        purpose: "Room assistance".into(),
    };
    match run(
        home,
        owner,
        &action(
            owner,
            Operation::DelegationCreate,
            Target::Account(owner.record.acting.account),
            &scope,
        ),
    ) {
        Outcome::Committed { body, .. } => body.deserialized().unwrap(),
        other => panic!("grant result {other:?}"),
    }
}
fn delegated(mut action: Action, owner: &Party, reference: GrantRef) -> Action {
    action.actor = Actor::Delegated {
        acting: action.actor.acting().clone(),
        operator: owner.record.acting.account,
        represented: owner.record.acting.account,
        represented_security_generation: owner.record.acting.security_generation,
        grant: reference,
    };
    action
}

#[test]
fn account_enrolment_requires_exact_single_use_invitation_and_session_binding() {
    let f = Fixture::new();
    let mut home = f.create();
    let alice = enrol(&mut home, 10, AccountClass::Human);
    assert!(AuthenticatedSession::new(&alice.record, id(99), id(100), 1).is_err());
    let key = SigningKey::from_bytes(&[11; 32]);
    let invite = home
        .issue_invitation(id(61), AccountClass::Human, TimeBounds::test_now())
        .unwrap();
    let mut reg = AccountRegistration {
        home: service(),
        account: AccountId {
            origin: service().network,
            local: id(12),
        },
        endpoint: id(13),
        endpoint_key: Id::from_bytes(key.verifying_key().to_bytes()),
        transport_principal: id(62),
        recovery_key: Id::from_bytes(
            SigningKey::from_bytes(&[112; 32])
                .verifying_key()
                .to_bytes(),
        ),
        classification: AccountClass::Human,
        invitation: invite.id,
    };
    let v = verify_registration_request(&sign_registration(&reg, &key).unwrap()).unwrap();
    assert!(
        home.accept_registration(&v, TimeBounds::test_now())
            .is_err()
    );
    reg.transport_principal = invite.principal;
    let v = verify_registration_request(&sign_registration(&reg, &key).unwrap()).unwrap();
    home.accept_registration(&v, TimeBounds::test_now())
        .unwrap();
    assert!(
        home.accept_registration(&v, TimeBounds::test_now())
            .is_err()
    );
    let mut impersonated = send(
        &alice,
        RoomId {
            home: service(),
            local: id(5),
        },
        "wrong endpoint",
    );
    impersonated.actor = Actor::Direct {
        acting: EndpointActor {
            account: reg.account,
            ..alice.record.acting.clone()
        },
    };
    assert!(matches!(
        run(&mut home, &alice, &impersonated),
        Outcome::Refused {
            code: ErrorCode::Denied,
            ..
        }
    ));
}
#[test]
fn durable_send_retry_conflict_resolution_and_unicode_history_survive_restart() {
    let f = Fixture::new();
    let mut home = f.create();
    let alice = enrol(&mut home, 20, AccountClass::Human);
    let r = room(&mut home, &alice, "workshop");
    let a = send(&alice, r, "Straße e\u{301} 👩‍👩‍👧‍👧");
    let first = run(&mut home, &alice, &a);
    assert!(matches!(first, Outcome::Committed { .. }));
    assert_eq!(run(&mut home, &alice, &a), first);
    let mut altered = a.clone();
    altered.body = Value::serialized(&messaging::Send {
        text: "different".into(),
        parent: None,
        causation: None,
    })
    .unwrap();
    assert!(matches!(
        run(&mut home, &alice, &altered),
        Outcome::Rejected {
            code: ErrorCode::Conflict,
            ..
        }
    ));
    drop(home);
    let mut home = f.open();
    assert_eq!(run(&mut home, &alice, &a), first);
    let out = run(
        &mut home,
        &alice,
        &action(
            &alice,
            Operation::OperationResolve,
            Target::Service,
            &Resolve {
                operation_id: a.operation_id,
                action_digest: action_digest(&a).unwrap(),
            },
        ),
    );
    assert_eq!(resolved(out), first);
    let nick = action(
        &alice,
        Operation::AccountSetNickname,
        Target::Account(alice.record.acting.account),
        &identity::Nickname {
            nickname: "Renamed".into(),
        },
    );
    assert!(matches!(
        run(&mut home, &alice, &nick),
        Outcome::Committed { .. }
    ));
    let page = history(&mut home, &alice, r);
    let messages: Vec<_> = page
        .events
        .iter()
        .filter(|e| e.kind == Operation::MessageSend)
        .collect();
    assert_eq!(messages.len(), 1);
    assert_eq!(
        messages[0].actor.acting().account,
        alice.record.acting.account
    );
    assert_eq!(
        messages[0]
            .body
            .deserialized::<messaging::Send>()
            .unwrap()
            .text,
        "Straße e\u{301} 👩‍👩‍👧‍👧"
    );
    let search = messaging::Search {
        terms: vec!["STRASSE".into()],
        sender: None,
        represented: None,
        from_ms: None,
        until_ms: None,
        cursor: None,
        limit: 50,
    };
    let out = run(
        &mut home,
        &alice,
        &action(&alice, Operation::SearchQuery, Target::Room(r), &search),
    );
    assert!(
        matches!(out,Outcome::Result{body} if body.deserialized::<messaging::PageResult>().unwrap().events.len()==1)
    );
}
#[test]
fn delegation_pause_revoke_and_exact_approval_never_expand_scope() {
    let f = Fixture::new();
    let mut home = f.create();
    let owner = enrol(&mut home, 30, AccountClass::Human);
    let agent = enrol(
        &mut home,
        31,
        AccountClass::Agent {
            operator: owner.record.acting.account,
        },
    );
    let r = room(&mut home, &owner, "agents");
    let other = room(&mut home, &owner, "other");
    let g = grant(&mut home, &owner, &agent, r, delegation::Mode::Autonomous);
    let good = delegated(send(&agent, r, "permitted"), &owner, g);
    assert!(matches!(
        run(&mut home, &agent, &good),
        Outcome::Committed { .. }
    ));
    assert!(matches!(
        run(
            &mut home,
            &agent,
            &delegated(send(&agent, other, "outside"), &owner, g)
        ),
        Outcome::Rejected {
            code: ErrorCode::Denied,
            ..
        }
    ));
    let queued = delegated(send(&agent, r, "queued before pause"), &owner, g);
    let pause = run(
        &mut home,
        &owner,
        &action(
            &owner,
            Operation::DelegationPause,
            Target::Delegation(g),
            &Empty {},
        ),
    );
    let paused = match pause {
        Outcome::Committed { body, .. } => body.deserialized::<GrantRef>().unwrap(),
        other => panic!("{other:?}"),
    };
    assert!(
        matches!(run(&mut home,&agent,&queued),Outcome::Rejected{detail,..} if detail=="GrantPaused")
    );
    let revoked = match run(
        &mut home,
        &owner,
        &action(
            &owner,
            Operation::DelegationRevoke,
            Target::Delegation(paused),
            &Empty {},
        ),
    ) {
        Outcome::Committed { body, .. } => body.deserialized::<GrantRef>().unwrap(),
        other => panic!("{other:?}"),
    };
    assert!(matches!(
        run(
            &mut home,
            &owner,
            &action(
                &owner,
                Operation::DelegationResume,
                Target::Delegation(revoked),
                &Empty {}
            )
        ),
        Outcome::Rejected {
            code: ErrorCode::Conflict,
            ..
        }
    ));
    let g = grant(&mut home, &owner, &agent, r, delegation::Mode::Approve);
    let mut candidate = delegated(send(&agent, r, "owner checked this exact text"), &owner, g);
    candidate.approval = Some(Id::random().unwrap());
    let digest = action_digest(&candidate).unwrap();
    let prepare = delegated(
        action(
            &agent,
            Operation::ApprovalPrepare,
            Target::Delegation(g),
            &delegation::Prepare {
                candidate: Blob(sign_action(&candidate, &agent.key).unwrap()),
                expires_ms: TimeBounds::test_now().upper_ms + 30_000,
            },
        ),
        &owner,
        g,
    );
    assert!(matches!(
        run(&mut home, &agent, &prepare),
        Outcome::Committed { .. }
    ));
    let approve = action(
        &owner,
        Operation::ApprovalApprove,
        Target::Delegation(g),
        &delegation::Decision {
            approval: candidate.approval.unwrap(),
            action_digest: digest,
        },
    );
    assert!(matches!(
        run(&mut home, &owner, &approve),
        Outcome::Committed { .. }
    ));
    let mut changed = candidate.clone();
    changed.operation_id.operation = Id::random().unwrap();
    assert!(
        matches!(run(&mut home,&agent,&changed),Outcome::Rejected{detail,..} if detail=="ApprovalBinding")
    );
    let committed = run(&mut home, &agent, &candidate);
    assert!(matches!(committed, Outcome::Committed { .. }));
    assert_eq!(run(&mut home, &agent, &candidate), committed);
}
#[test]
fn final_permission_loss_rolls_back_effect_and_keeps_retry_absent() {
    let f = Fixture::new();
    let mut home = f.create();
    let alice = enrol(&mut home, 40, AccountClass::Human);
    let r = room(&mut home, &alice, "race");
    let a = send(&alice, r, "tentative");
    let calls = Cell::new(0);
    let result = home
        .execute(
            &verified(&alice, &a),
            &alice.session,
            TimeBounds::test_now(),
            &|| {
                calls.set(calls.get() + 1);
                calls.get() <= 2
            },
        )
        .unwrap();
    assert!(matches!(result.outcome, Outcome::Refused { .. }));
    let resolution = action(
        &alice,
        Operation::OperationResolve,
        Target::Service,
        &Resolve {
            operation_id: a.operation_id,
            action_digest: action_digest(&a).unwrap(),
        },
    );
    assert_eq!(
        resolved(run(&mut home, &alice, &resolution)),
        Outcome::Absent
    );
    assert!(
        history(&mut home, &alice, r)
            .events
            .iter()
            .all(|e| e.kind != Operation::MessageSend)
    );
    assert!(matches!(
        run(&mut home, &alice, &a),
        Outcome::Committed { .. }
    ));
    assert!(matches!(
        resolved(run(&mut home, &alice, &resolution)),
        Outcome::Committed { .. }
    ));
}
#[test]
fn ignore_filters_history_search_and_cursor_while_silence_prevents_publication() {
    let f = Fixture::new();
    let mut home = f.create();
    let alice = enrol(&mut home, 50, AccountClass::Human);
    let bob = enrol(&mut home, 51, AccountClass::Human);
    let r = room(&mut home, &alice, "filter");
    assert!(matches!(
        run(
            &mut home,
            &bob,
            &action(&bob, Operation::RoomJoin, Target::Room(r), &Empty {})
        ),
        Outcome::Committed { .. }
    ));
    assert!(matches!(
        run(&mut home, &bob, &send(&bob, r, "hidden pineapple")),
        Outcome::Committed { .. }
    ));
    let old = history(&mut home, &alice, r);
    let ignore = action(
        &alice,
        Operation::ModerationIgnore,
        Target::Account(alice.record.acting.account),
        &moderation::Filter {
            subject: bob.record.acting.account,
            enabled: true,
        },
    );
    assert!(matches!(
        run(&mut home, &alice, &ignore),
        Outcome::Committed { .. }
    ));
    assert!(
        history(&mut home, &alice, r)
            .events
            .iter()
            .all(|e| e.actor.acting().account != bob.record.acting.account)
    );
    let cursor = action(
        &alice,
        Operation::EventsResume,
        Target::Room(r),
        &messaging::Page {
            cursor: Some(old.cursor),
            limit: 50,
        },
    );
    assert!(matches!(
        run(&mut home, &alice, &cursor),
        Outcome::Rejected {
            code: ErrorCode::ResynchronisationRequired,
            ..
        }
    ));
    let search = messaging::Search {
        terms: vec!["pineapple".into()],
        sender: None,
        represented: None,
        from_ms: None,
        until_ms: None,
        cursor: None,
        limit: 50,
    };
    assert!(
        matches!(run(&mut home,&alice,&action(&alice,Operation::SearchQuery,Target::Room(r),&search)),Outcome::Result{body} if body.deserialized::<messaging::PageResult>().unwrap().events.is_empty())
    );
    let silence = action(
        &alice,
        Operation::ModerationSilence,
        Target::Room(r),
        &moderation::Restriction {
            subject: bob.record.acting.account,
            enabled: true,
            duration_ms: 60_000,
            reason: "quiet".into(),
        },
    );
    assert!(matches!(
        run(&mut home, &alice, &silence),
        Outcome::Committed { .. }
    ));
    assert!(
        matches!(run(&mut home,&bob,&send(&bob,r,"refused")),Outcome::Rejected{detail,..} if detail=="RoomSilenced")
    );
}
#[test]
fn expired_windows_cannot_reopen_and_confidentiality_never_downgrades() {
    let f = Fixture::new();
    let mut home = f.create();
    let alice = enrol(&mut home, 60, AccountClass::Human);
    let r = room(&mut home, &alice, "expiry");
    let a = send(&alice, r, "expired unknown");
    home.store
        .write(|db| {
            db.execute(
                "UPDATE hrc_windows SET expires=1 WHERE id=?1",
                [alice.window.id.as_hex()],
            )?;
            Ok(Commit::new((), b"expiry regression".to_vec()))
        })
        .unwrap();
    assert_eq!(run(&mut home, &alice, &a), Outcome::Unknown);
    let new = home
        .open_window(&alice.record, TimeBounds::test_now(), &|| true)
        .unwrap();
    assert_ne!(new.id, alice.window.id);
    let mut resolve = action(
        &alice,
        Operation::OperationResolve,
        Target::Service,
        &Resolve {
            operation_id: a.operation_id,
            action_digest: action_digest(&a).unwrap(),
        },
    );
    resolve.operation_id.window = new.id;
    assert_eq!(resolved(run(&mut home, &alice, &resolve)), Outcome::Unknown);
    let mut private = action(
        &alice,
        Operation::RoomCreate,
        Target::Service,
        &conversations::Create {
            name: "confidential".into(),
            confidentiality: RoomConfidentiality::PrivateGroup,
        },
    );
    private.operation_id.window = new.id;
    assert!(matches!(
        run(&mut home, &alice, &private),
        Outcome::Rejected {
            code: ErrorCode::UnsupportedFeature,
            ..
        }
    ));
}

#[test]
fn large_attribution_pages_fit_the_signed_node_limit_without_skipping_events() {
    let f = Fixture::new();
    let mut home = f.create();
    let owner = enrol(&mut home, 65, AccountClass::Human);
    let r = room(&mut home, &owner, "bounded pages");
    let mut agents = Vec::new();
    for n in 70..101 {
        let agent = enrol(
            &mut home,
            n,
            AccountClass::Agent {
                operator: owner.record.acting.account,
            },
        );
        assert!(matches!(
            run(
                &mut home,
                &agent,
                &action(&agent, Operation::RoomJoin, Target::Room(r), &Empty {})
            ),
            Outcome::Committed { .. }
        ));
        agents.push(agent);
    }
    let g = grant(
        &mut home,
        &owner,
        &agents[0],
        r,
        delegation::Mode::Autonomous,
    );
    // Seed already committed attribution to isolate representation from wall-clock send admission.
    home.store
        .write(|db| {
            for _ in 0..32 {
                let a = delegated(send(&agents[0], r, "bounded attribution"), &owner, g);
                crate::messaging::record(
                    db,
                    &a,
                    r,
                    Value::serialized(&messaging::Send {
                        text: "bounded attribution".into(),
                        parent: None,
                        causation: None,
                    })
                    .unwrap(),
                    "bounded attribution",
                    TimeBounds::test_now(),
                )
                .map_err(sql_fault)?;
            }
            Ok(Commit::new((), b"bounded history fixture".to_vec()))
        })
        .unwrap();
    let mut cursor = None;
    let mut found = std::collections::BTreeSet::new();
    let mut shortened = false;
    for _ in 0..8 {
        let request = action(
            &owner,
            Operation::HistoryPage,
            Target::Room(r),
            &messaging::Page { cursor, limit: 50 },
        );
        let Outcome::Result { body } = run(&mut home, &owner, &request) else {
            panic!("page refused");
        };
        let page: messaging::PageResult = body.deserialized().unwrap();
        assert_eq!(page.members.len(), 32);
        if page.has_more && page.events.len() < 32 {
            shortened = true;
        }
        for event in &page.events {
            if event.kind == Operation::MessageSend {
                assert!(found.insert(event.event));
            }
        }
        cursor = Some(page.cursor);
        if !page.has_more {
            break;
        }
    }
    assert!(shortened);
    assert_eq!(found.len(), 32);
}

#[test]
fn ignored_messages_do_not_count_unread_and_expiry_removes_search_and_retry_bytes() {
    let f = Fixture::new();
    let mut home = f.create();
    let owner = enrol(&mut home, 110, AccountClass::Human);
    let other = enrol(&mut home, 111, AccountClass::Human);
    let r = room(&mut home, &owner, "retention");
    assert!(matches!(
        run(
            &mut home,
            &other,
            &action(&other, Operation::RoomJoin, Target::Room(r), &Empty {})
        ),
        Outcome::Committed { .. }
    ));
    let sent = send(&other, r, "retention marker");
    assert!(matches!(
        run(&mut home, &other, &sent),
        Outcome::Committed { .. }
    ));
    let listing = action(
        &owner,
        Operation::RoomList,
        Target::Service,
        &conversations::List {
            after: None,
            limit: 50,
        },
    );
    let Outcome::Result { body } = run(&mut home, &owner, &listing) else {
        panic!("list failed");
    };
    assert_eq!(
        body.deserialized::<Vec<conversations::Summary>>().unwrap()[0].unread,
        1
    );
    let ignore = action(
        &owner,
        Operation::ModerationIgnore,
        Target::Account(owner.record.acting.account),
        &moderation::Filter {
            subject: other.record.acting.account,
            enabled: true,
        },
    );
    assert!(matches!(
        run(&mut home, &owner, &ignore),
        Outcome::Committed { .. }
    ));
    let Outcome::Result { body } = run(&mut home, &owner, &listing) else {
        panic!("list failed");
    };
    assert_eq!(
        body.deserialized::<Vec<conversations::Summary>>().unwrap()[0].unread,
        0
    );
    let now = TimeBounds::test_now();
    home.store
        .write(|db| {
            db.execute(
                "UPDATE hrc_events SET created=?1 WHERE kind=20",
                [now.lower_ms - RETENTION - 1000],
            )?;
            db.execute(
                "UPDATE hrc_operations SET created=?1 WHERE window=?2",
                params![now.lower_ms - 8 * DAY, other.window.id.as_hex()],
            )?;
            db.execute(
                "UPDATE hrc_windows SET expires=1 WHERE id=?1",
                [other.window.id.as_hex()],
            )?;
            Ok(Commit::new((), b"expiry clock fixture".to_vec()))
        })
        .unwrap();
    home.maintain(TimeBounds::test_now()).unwrap();
    let (events, index, outcomes) = home
        .store
        .read(Duration::from_secs(1), |db| {
            Ok((
                db.query_row("SELECT count(*) FROM hrc_events WHERE kind=20", [], |r| {
                    r.get::<_, u64>(0)
                })?,
                db.query_row(
                    "SELECT count(*) FROM hrc_search WHERE hrc_search MATCH 'retention'",
                    [],
                    |r| r.get::<_, u64>(0),
                )?,
                db.query_row(
                    "SELECT count(*) FROM hrc_operations WHERE window=?1",
                    [other.window.id.as_hex()],
                    |r| r.get::<_, u64>(0),
                )?,
            ))
        })
        .unwrap();
    assert_eq!((events, index, outcomes), (0, 0, 0));
}

#[test]
fn unknown_and_expired_grants_keep_a_durable_rejection() {
    let f = Fixture::new();
    let mut home = f.create();
    let owner = enrol(&mut home, 120, AccountClass::Human);
    let agent = enrol(
        &mut home,
        121,
        AccountClass::Agent {
            operator: owner.record.acting.account,
        },
    );
    let r = room(&mut home, &owner, "grant refusal");
    let unknown = delegated(
        send(&agent, r, "unknown grant"),
        &owner,
        GrantRef {
            id: Id::random().unwrap(),
            generation: 1,
        },
    );
    let rejected = run(&mut home, &agent, &unknown);
    assert!(matches!(
        rejected,
        Outcome::Rejected {
            code: ErrorCode::Denied,
            ..
        }
    ));
    assert_eq!(run(&mut home, &agent, &unknown), rejected);
    let g = grant(&mut home, &owner, &agent, r, delegation::Mode::Autonomous);
    home.store
        .write(|db| {
            let mut current = delegation::load(db, g.id).map_err(sql_fault)?;
            current.scope.expires_ms = 1;
            db.execute(
                "UPDATE hrc_grants SET grant_data=?1 WHERE id=?2",
                params![encode(&current)?, g.id.as_hex()],
            )?;
            Ok(Commit::new((), b"expired grant fixture".to_vec()))
        })
        .unwrap();
    let expired = delegated(send(&agent, r, "expired grant"), &owner, g);
    let rejected = run(&mut home, &agent, &expired);
    assert!(matches!(
        rejected,
        Outcome::Rejected {
            code: ErrorCode::Expired,
            ..
        }
    ));
    assert_eq!(run(&mut home, &agent, &expired), rejected);
}

#[test]
fn draft_mode_can_be_inspected_and_rejected_but_cannot_approve_or_send() {
    let f = Fixture::new();
    let mut home = f.create();
    let owner = enrol(&mut home, 125, AccountClass::Human);
    let agent = enrol(
        &mut home,
        126,
        AccountClass::Agent {
            operator: owner.record.acting.account,
        },
    );
    let r = room(&mut home, &owner, "drafts");
    let g = grant(&mut home, &owner, &agent, r, delegation::Mode::Draft);
    let mut candidate = delegated(send(&agent, r, "review this draft"), &owner, g);
    candidate.approval = Some(Id::random().unwrap());
    let body = delegation::Prepare {
        candidate: Blob(sign_action(&candidate, &agent.key).unwrap()),
        expires_ms: TimeBounds::test_now().upper_ms + 30_000,
    };
    assert!(matches!(
        run(
            &mut home,
            &agent,
            &action(
                &agent,
                Operation::ApprovalPrepare,
                Target::Delegation(g),
                &body
            )
        ),
        Outcome::Committed { .. }
    ));
    let inspect = action(
        &owner,
        Operation::DelegationInspect,
        Target::Delegation(g),
        &Empty {},
    );
    let Outcome::Result { body } = run(&mut home, &owner, &inspect) else {
        panic!("inspection failed");
    };
    assert_eq!(
        body.deserialized::<delegation::Inspection>()
            .unwrap()
            .pending
            .len(),
        1
    );
    let decision = delegation::Decision {
        approval: candidate.approval.unwrap(),
        action_digest: action_digest(&candidate).unwrap(),
    };
    assert!(
        matches!(run(&mut home,&owner,&action(&owner,Operation::ApprovalApprove,Target::Delegation(g),&decision)),Outcome::Rejected{detail,..} if detail=="GrantApprovalMode")
    );
    assert!(
        matches!(run(&mut home,&agent,&candidate),Outcome::Rejected{detail,..} if detail=="DraftOnly")
    );
    assert!(matches!(
        run(
            &mut home,
            &owner,
            &action(
                &owner,
                Operation::ApprovalReject,
                Target::Delegation(g),
                &decision
            )
        ),
        Outcome::Committed { .. }
    ));
    let Outcome::Result { body } = run(&mut home, &owner, &inspect) else {
        panic!("inspection failed");
    };
    assert!(
        body.deserialized::<delegation::Inspection>()
            .unwrap()
            .pending
            .is_empty()
    );
}
