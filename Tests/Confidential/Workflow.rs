// SPDX-License-Identifier: Apache-2.0
//! Real MLS, guarded storage and authoritative operations exercise private-room admission and withdrawal.
use super::*;
use crate::{confidential as c, crypto};

struct Endpoint {
    store: Store,
    device: crypto::Device,
    _fixture: Fixture,
}
impl Endpoint {
    fn new(p: &Party) -> Self {
        let fixture = Fixture::new();
        let mut store = fixture.create().store;
        let device = crypto::Device::provision(&mut store, p.record.acting.clone()).unwrap();
        Self {
            store,
            device,
            _fixture: fixture,
        }
    }
}
fn committed(outcome: Outcome) -> Option<Id> {
    match outcome {
        Outcome::Committed { event, .. } => event,
        other => panic!("expected commit: {other:?}"),
    }
}
fn inspect(home: &mut Home, p: &Party, r: RoomId) -> c::Inspection {
    match run(
        home,
        p,
        &action(p, Operation::CryptoInspect, Target::Room(r), &Empty {}),
    ) {
        Outcome::Result { body } => body.deserialized().unwrap(),
        other => panic!("inspection: {other:?}"),
    }
}
fn enrol_key(home: &mut Home, p: &Party, device: &crypto::Device) {
    committed(run(
        home,
        p,
        &action(
            p,
            Operation::CryptoEnrolEndpoint,
            Target::Account(p.record.acting.account),
            &c::EnrolKey {
                mls_key: device.mls_key,
            },
        ),
    ));
}
fn ready(home: &mut Home, p: &Party, r: RoomId, state: &c::Inspection, welcome: Option<Vec<u8>>) {
    committed(run(
        home,
        p,
        &action(
            p,
            Operation::CryptoEpochReady,
            Target::Room(r),
            &c::Ready {
                group: state.group.unwrap(),
                epoch: state.epoch,
                commit_digest: state.commit_digest.unwrap(),
                sequence: state.sequence,
                welcome: welcome.map(Blob),
            },
        ),
    ));
}
#[test]
fn private_group_requires_invitation_orders_mls_and_blocks_stale_recipient_keys() {
    let fixture = Fixture::new();
    let mut home = fixture.create();
    let alice = enrol(&mut home, 10, AccountClass::Human);
    let bob = enrol(&mut home, 20, AccountClass::Human);
    let created = run(
        &mut home,
        &alice,
        &action(
            &alice,
            Operation::RoomCreate,
            Target::Service,
            &conversations::Create {
                name: "Private".into(),
                confidentiality: RoomConfidentiality::PrivateGroup,
            },
        ),
    );
    let Outcome::Committed { body, .. } = created else {
        panic!("private room creation")
    };
    let room = body
        .deserialized::<messaging::Committed>()
        .unwrap()
        .room
        .unwrap();
    assert!(matches!(
        run(
            &mut home,
            &bob,
            &action(&bob, Operation::RoomJoin, Target::Room(room), &Empty {})
        ),
        Outcome::Rejected {
            code: ErrorCode::Denied,
            ..
        }
    ));
    let out = run(
        &mut home,
        &bob,
        &action(
            &bob,
            Operation::RoomList,
            Target::Service,
            &conversations::List {
                after: None,
                limit: 32,
            },
        ),
    );
    let Outcome::Result { body } = out else {
        panic!("room list")
    };
    assert!(
        body.deserialized::<Vec<conversations::Summary>>()
            .unwrap()
            .is_empty()
    );
    committed(run(
        &mut home,
        &alice,
        &action(
            &alice,
            Operation::RoomInvite,
            Target::Room(room),
            &c::Invite {
                account: bob.record.acting.account,
            },
        ),
    ));
    committed(run(
        &mut home,
        &bob,
        &action(&bob, Operation::RoomJoin, Target::Room(room), &Empty {}),
    ));
    let mut a = Endpoint::new(&alice);
    let mut b = Endpoint::new(&bob);
    enrol_key(&mut home, &alice, &a.device);
    enrol_key(&mut home, &bob, &b.device);
    let group = Id::random().unwrap();
    let initial = crypto::ApprovedRoster::new(room, vec![a.device.credential(room)]).unwrap();
    let info = a
        .device
        .create_group(&mut a.store, group, &initial, 0)
        .unwrap();
    committed(run(
        &mut home,
        &alice,
        &action(
            &alice,
            Operation::CryptoPropose,
            Target::Room(room),
            &c::Initialise {
                group,
                group_info: Blob(info),
            },
        ),
    ));
    let first = inspect(&mut home, &alice, room);
    assert!(first.send_barrier);
    ready(&mut home, &alice, room, &first, None);
    let history = |cursor| {
        action(
            &alice,
            Operation::CryptoHistory,
            Target::Room(room),
            &messaging::Page { cursor, limit: 16 },
        )
    };
    let Outcome::Result { body } = run(&mut home, &alice, &history(None)) else {
        panic!("initial encrypted history")
    };
    let before: messaging::PageResult = body.deserialized().unwrap();
    let package = b.device.publish_key_package(&mut b.store, room).unwrap();
    committed(run(
        &mut home,
        &bob,
        &action(
            &bob,
            Operation::CryptoPublishKeyPackage,
            Target::Room(room),
            &c::PublishPackage {
                package: Blob(package.clone()),
                expires_ms: TimeBounds::test_now().lower_ms + 600_000,
            },
        ),
    ));
    let next = crypto::ApprovedRoster::new(
        room,
        vec![a.device.credential(room), b.device.credential(room)],
    )
    .unwrap();
    let pending = a
        .device
        .prepare_transition(
            &mut a.store,
            group,
            0,
            &initial,
            &next,
            crypto::Change::Add(std::slice::from_ref(&package)),
        )
        .unwrap();
    // A valid MLS commit with a falsely declared next roster must roll back even public MLS writes.
    let invalid = action(
        &alice,
        Operation::CryptoCommit,
        Target::Room(room),
        &c::CommitEpoch {
            group,
            epoch: 0,
            commit: Blob(pending.commit.clone()),
            additions: vec![],
            removals: vec![],
        },
    );
    assert!(matches!(
        run(&mut home, &alice, &invalid),
        Outcome::Rejected { .. }
    ));
    let unchanged = inspect(&mut home, &alice, room);
    assert_eq!(unchanged.epoch, 0);
    assert_eq!(unchanged.packages.len(), 1);
    let selected = action(
        &alice,
        Operation::CryptoCommit,
        Target::Room(room),
        &c::CommitEpoch {
            group,
            epoch: 0,
            commit: Blob(pending.commit.clone()),
            additions: vec![digest(&package)],
            removals: vec![],
        },
    );
    let winner = committed(run(&mut home, &alice, &selected));
    assert_eq!(committed(run(&mut home, &alice, &selected)), winner);
    assert!(matches!(
        run(&mut home, &alice, &history(Some(before.cursor))),
        Outcome::Rejected { code: ErrorCode::ResynchronisationRequired, detail }
            if detail == "CursorContext"
    ));
    let Outcome::Result { body } = run(&mut home, &alice, &history(None)) else {
        panic!("current encrypted history")
    };
    let resumed: messaging::PageResult = body.deserialized().unwrap();
    assert!(
        resumed
            .events
            .iter()
            .any(|event| Some(event.event) == winner)
    );
    let epoch = inspect(&mut home, &alice, room);
    assert_eq!(epoch.epoch, 1);
    assert!(epoch.send_barrier);
    let receipt = a
        .device
        .accept_transition(
            &mut a.store,
            crypto::TransitionOrder {
                group,
                epoch: 0,
                previous_sequence: 0,
                sequence: epoch.sequence,
            },
            &pending.commit,
            &next,
        )
        .unwrap();
    let welcome = receipt.welcome.unwrap();
    ready(&mut home, &alice, room, &epoch, Some(welcome.clone()));
    b.device
        .join(&mut b.store, group, 1, epoch.sequence, &welcome, &next)
        .unwrap();
    ready(&mut home, &bob, room, &epoch, None);
    let base = action(
        &alice,
        Operation::MessageSend,
        Target::Room(room),
        &Empty {},
    );
    let context = crypto::EncryptionContext {
        home: base.home,
        room,
        operation_id: base.operation_id,
        actor: base.actor,
        operation: base.operation,
        expected: base.expected,
        approval: None,
        agreement: None,
        group,
        epoch: 1,
        parent: None,
        causation: None,
    };
    let plaintext = "Only endpoints receive this multilingual text: cafe\u{301} and 世界";
    let encrypted = a
        .device
        .prepare_message(&mut a.store, &context, &next, plaintext, |_, action| {
            sign_action(&action, &alice.key).map_err(|_| crypto::Error::Invalid)
        })
        .unwrap();
    let signed = verify_action(&encrypted.signed_action, &alice.key.verifying_key()).unwrap();
    let event_id = committed(run(&mut home, &alice, signed.action())).unwrap();
    let event: Event = home
        .store
        .read(Duration::from_secs(1), |db| {
            db.query_row(
                "SELECT event FROM hrc_events WHERE id=?1",
                [event_id.as_hex()],
                |r| decode(&r.get::<_, Vec<u8>>(0)?),
            )
        })
        .unwrap();
    let public: crypto::EncryptedEvent = event.body.deserialized().unwrap();
    let recent = run(
        &mut home,
        &bob,
        &action(
            &bob,
            Operation::CryptoTail,
            Target::Room(room),
            &messaging::Tail { limit: 1 },
        ),
    );
    let Outcome::Result { body } = recent else {
        panic!("encrypted tail: {recent:?}")
    };
    let recent: messaging::PageResult = body.deserialized().unwrap();
    assert_eq!(recent.events, vec![event.clone()]);
    assert!(!recent.has_more);
    assert_eq!(recent.members.len(), 2);
    let tail_cursor = verify_cursor(&recent.cursor.0, &home.signing_key().verifying_key()).unwrap();
    assert_eq!(tail_cursor.value().sequence, event.sequence);
    let resumed = run(
        &mut home,
        &bob,
        &action(
            &bob,
            Operation::CryptoHistory,
            Target::Room(room),
            &messaging::Page {
                cursor: Some(recent.cursor),
                limit: 1,
            },
        ),
    );
    let Outcome::Result { body } = resumed else {
        panic!("encrypted tail resume: {resumed:?}")
    };
    assert!(
        body.deserialized::<messaging::PageResult>()
            .unwrap()
            .events
            .is_empty()
    );
    let delivery = b
        .device
        .receive(
            &mut b.store,
            &crypto::IncomingMessage {
                context: &public.context,
                ciphertext: &public.ciphertext.0,
                action_digest: event.action_digest,
            },
            &crypto::HomeDelivery {
                previous_sequence: epoch.sequence,
                sequence: event.sequence,
                event: event.event,
                event_digest: digest(&encode(&event).unwrap()),
            },
            &next,
        )
        .unwrap();
    assert_eq!(
        delivery,
        crypto::DeliveryOutcome::Message(crypto::ApplicationMessage::from(plaintext))
    );
    home.store
        .read(Duration::from_secs(1), |db| {
            let (text, normal): (String, String) = db.query_row(
                "SELECT text,normal FROM hrc_events WHERE id=?1",
                [event_id.as_hex()],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )?;
            assert!(text.is_empty() && normal.is_empty());
            Ok(())
        })
        .unwrap();
    assert!(matches!(
        run(
            &mut home,
            &bob,
            &action(
                &bob,
                Operation::HistoryPage,
                Target::Room(room),
                &messaging::Page {
                    cursor: None,
                    limit: 10
                }
            )
        ),
        Outcome::Rejected { .. }
    ));
    committed(run(
        &mut home,
        &bob,
        &action(
            &bob,
            Operation::ModerationIgnore,
            Target::Account(bob.record.acting.account),
            &moderation::Filter {
                subject: alice.record.acting.account,
                enabled: true,
            },
        ),
    ));
    let out = run(
        &mut home,
        &bob,
        &action(
            &bob,
            Operation::CryptoHistory,
            Target::Room(room),
            &messaging::Page {
                cursor: None,
                limit: 32,
            },
        ),
    );
    let Outcome::Result { body } = out else {
        panic!("encrypted history")
    };
    let page: messaging::PageResult = body.deserialized().unwrap();
    assert!(!page.events.iter().any(|e| e.event == event_id));
    assert!(
        page.events
            .iter()
            .any(|e| e.kind == Operation::CryptoCommit)
    );
    // Separate the tail permission assertions from the preceding burst of MLS setup/read work.
    home.store
        .write(|db| {
            db.execute(
                "DELETE FROM hrc_budgets WHERE key=?1",
                [format!("operation:{}", bob.record.acting.account)],
            )?;
            Ok(Commit::new((), b"encrypted tail read phase".to_vec()))
        })
        .unwrap();
    let recent = run(
        &mut home,
        &bob,
        &action(
            &bob,
            Operation::CryptoTail,
            Target::Room(room),
            &messaging::Tail { limit: 32 },
        ),
    );
    let Outcome::Result { body } = recent else {
        panic!("filtered encrypted tail: {recent:?}")
    };
    let recent: messaging::PageResult = body.deserialized().unwrap();
    assert!(!recent.events.iter().any(|e| e.event == event_id));
    assert!(
        recent
            .events
            .iter()
            .any(|e| e.kind == Operation::CryptoCommit)
    );
    committed(run(
        &mut home,
        &alice,
        &action(
            &alice,
            Operation::ModerationKick,
            Target::Room(room),
            &moderation::Restriction {
                subject: bob.record.acting.account,
                enabled: true,
                duration_ms: 1000,
                reason: "Remove access".into(),
            },
        ),
    ));
    let blocked = inspect(&mut home, &alice, room);
    assert!(blocked.send_barrier);
    assert_eq!(blocked.required_removals, vec![bob.record.acting.endpoint]);
    let mut later = signed.action().clone();
    later.operation_id.operation = Id::random().unwrap();
    assert!(matches!(
        run(&mut home, &alice, &later),
        Outcome::Rejected {
            code: ErrorCode::Conflict,
            ..
        }
    ));
    drop(home);
    let mut reopened = fixture.open();
    let persisted = inspect(&mut reopened, &alice, room);
    assert!(persisted.send_barrier);
    assert_eq!(persisted.epoch, 1);
    a.device
        .resolve_outbox(&mut a.store, context.operation_id, true)
        .unwrap();
    let remaining = crypto::ApprovedRoster::new(room, vec![a.device.credential(room)]).unwrap();
    let removal = a
        .device
        .prepare_transition(
            &mut a.store,
            group,
            1,
            &next,
            &remaining,
            crypto::Change::Remove(&[bob.record.acting.endpoint]),
        )
        .unwrap();
    committed(run(
        &mut reopened,
        &alice,
        &action(
            &alice,
            Operation::CryptoCommit,
            Target::Room(room),
            &c::CommitEpoch {
                group,
                epoch: 1,
                commit: Blob(removal.commit.clone()),
                additions: vec![],
                removals: vec![bob.record.acting.endpoint],
            },
        ),
    ));
    let removed = inspect(&mut reopened, &alice, room);
    a.device
        .accept_transition(
            &mut a.store,
            crypto::TransitionOrder {
                group,
                epoch: 1,
                previous_sequence: epoch.sequence,
                sequence: removed.sequence,
            },
            &removal.commit,
            &remaining,
        )
        .unwrap();
    ready(&mut reopened, &alice, room, &removed, None);
    for evidence in [None, Some(event_id)] {
        assert!(matches!(
            run(
                &mut reopened,
                &alice,
                &action(
                    &alice,
                    Operation::AccountPublicIdentity,
                    Target::Account(bob.record.acting.account),
                    &identity::PublicIdentityRequest {
                        room,
                        after: 0,
                        limit: 1,
                        evidence
                    }
                )
            ),
            Outcome::Rejected {
                code: ErrorCode::Denied,
                ..
            }
        ));
    }
    // Historical verification requires an accessible roster event naming that account.
    assert!(matches!(
        run(
            &mut reopened,
            &alice,
            &action(
                &alice,
                Operation::AccountPublicIdentity,
                Target::Account(bob.record.acting.account),
                &identity::PublicIdentityRequest {
                    room,
                    after: 0,
                    limit: 1,
                    evidence: winner
                }
            )
        ),
        Outcome::Result { .. }
    ));
    assert!(matches!(
        run(
            &mut reopened,
            &bob,
            &action(
                &bob,
                Operation::AccountPublicIdentity,
                Target::Account(alice.record.acting.account),
                &identity::PublicIdentityRequest {
                    room,
                    after: 0,
                    limit: 1,
                    evidence: winner
                }
            )
        ),
        Outcome::Rejected {
            code: ErrorCode::Denied,
            ..
        }
    ));
}

#[test]
fn past_only_delegation_can_read_permitted_archive_but_cannot_join_live_epoch() {
    let fixture = Fixture::new();
    let mut home = fixture.create();
    let alice = enrol(&mut home, 10, AccountClass::Human);
    let agent = enrol(
        &mut home,
        30,
        AccountClass::Agent {
            operator: alice.record.acting.account,
        },
    );
    let Outcome::Committed { body, .. } = run(
        &mut home,
        &alice,
        &action(
            &alice,
            Operation::RoomCreate,
            Target::Service,
            &conversations::Create {
                name: "Archived private conversation".into(),
                confidentiality: RoomConfidentiality::PrivateGroup,
            },
        ),
    ) else {
        panic!("room")
    };
    let room = body
        .deserialized::<messaging::Committed>()
        .unwrap()
        .room
        .unwrap();
    let now = TimeBounds::test_now();
    let scope = delegation::Create {
        agent: agent.record.acting.clone(),
        rooms: vec![room],
        recipients: vec![],
        operations: vec![Operation::HistoryPage],
        mode: delegation::Mode::Draft,
        not_before_ms: now.lower_ms.saturating_sub(1000),
        expires_ms: now.upper_ms + 60_000,
        history_from_ms: 0,
        history_until_ms: now.lower_ms.saturating_sub(1),
        max_operations_per_minute: 120,
        purpose: "Read authorised retained history".into(),
    };
    let Outcome::Committed { body, .. } = run(
        &mut home,
        &alice,
        &action(
            &alice,
            Operation::DelegationCreate,
            Target::Account(alice.record.acting.account),
            &scope,
        ),
    ) else {
        panic!("grant")
    };
    let grant = body.deserialized::<GrantRef>().unwrap();
    let inspect = delegated(
        action(
            &agent,
            Operation::CryptoInspect,
            Target::Room(room),
            &Empty {},
        ),
        &alice,
        grant,
    );
    let Outcome::Result { body } = run(&mut home, &agent, &inspect) else {
        panic!("past-only inspection")
    };
    let inspection: c::Inspection = body.deserialized().unwrap();
    assert_eq!(inspection.history_until_ms, scope.history_until_ms);
    let history = delegated(
        action(
            &agent,
            Operation::CryptoHistory,
            Target::Room(room),
            &messaging::Page {
                cursor: None,
                limit: 10,
            },
        ),
        &alice,
        grant,
    );
    assert!(matches!(
        run(&mut home, &agent, &history),
        Outcome::Result { .. }
    ));
    let publish = delegated(
        action(
            &agent,
            Operation::CryptoPublishKeyPackage,
            Target::Room(room),
            &c::PublishPackage {
                package: Blob(vec![0]),
                expires_ms: now.upper_ms + 60_000,
            },
        ),
        &alice,
        grant,
    );
    assert!(matches!(
        run(&mut home, &agent, &publish),
        Outcome::Rejected {
            code: ErrorCode::Denied,
            ..
        }
    ));
}
