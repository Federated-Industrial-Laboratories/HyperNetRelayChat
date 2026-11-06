// SPDX-License-Identifier: Apache-2.0
//! Recent history stays bounded before filtering and resumes under current authority.
use super::*;

fn result<T: serde::de::DeserializeOwned>(outcome: Outcome) -> T {
    match outcome {
        Outcome::Result { body } | Outcome::Committed { body, .. } => body.deserialized().unwrap(),
        other => panic!("expected result: {other:?}"),
    }
}
fn tail(home: &mut Home, party: &Party, room: RoomId, limit: u16) -> messaging::PageResult {
    result(run(
        home,
        party,
        &action(
            party,
            Operation::HistoryTail,
            Target::Room(room),
            &messaging::Tail { limit },
        ),
    ))
}
fn seed(home: &mut Home, party: &Party, room: RoomId, count: usize, stamp: u64) {
    home.store
        .write(|db| {
            for i in 0..count {
                let text = format!("retained {i}");
                let action = send(party, room, &text);
                let mut now = TimeBounds::test_now();
                now.lower_ms = stamp;
                now.upper_ms = stamp;
                messaging::record(db, &action, room, action.body.clone(), &text, now)
                    .map_err(sql_fault)?;
            }
            Ok(Commit::new((), b"retained tail fixture".to_vec()))
        })
        .unwrap();
}
fn cursor(home: &Home, page: &messaging::PageResult) -> HistoryCursor {
    verify_cursor(&page.cursor.0, &home.signing_key().verifying_key())
        .unwrap()
        .value()
        .clone()
}

#[test]
fn newest_tail_survives_restart_and_resumes_from_the_observed_head() {
    let fixture = Fixture::new();
    let mut home = fixture.create();
    let alice = enrol(&mut home, 10, AccountClass::Human);
    let bob = enrol(&mut home, 20, AccountClass::Human);
    let room = room(&mut home, &alice, "tail restart");
    assert!(matches!(
        run(
            &mut home,
            &bob,
            &action(&bob, Operation::RoomJoin, Target::Room(room), &Empty {})
        ),
        Outcome::Committed { .. }
    ));
    seed(
        &mut home,
        &alice,
        room,
        500,
        TimeBounds::test_now().lower_ms,
    );
    drop(home);
    let mut home = fixture.open();
    let page = tail(&mut home, &alice, room, 3);
    assert_eq!(page.events.len(), 3);
    assert_eq!(page.members.len(), 2);
    assert!(!page.has_more);
    let head = cursor(&home, &page).sequence;
    assert_eq!(
        page.events.iter().map(|e| e.sequence).collect::<Vec<_>>(),
        vec![head - 2, head - 1, head]
    );
    let committed = run(&mut home, &alice, &send(&alice, room, "after tail"));
    let Outcome::Committed {
        event: Some(event), ..
    } = committed
    else {
        panic!("{committed:?}")
    };
    let resumed: messaging::PageResult = result(run(
        &mut home,
        &alice,
        &action(
            &alice,
            Operation::HistoryPage,
            Target::Room(room),
            &messaging::Page {
                cursor: Some(page.cursor),
                limit: 32,
            },
        ),
    ));
    assert_eq!(
        resumed.events.iter().map(|e| e.event).collect::<Vec<_>>(),
        vec![event]
    );
    assert!(!resumed.has_more);
}

#[test]
fn ignored_tail_candidates_cannot_cause_an_unbounded_archive_walk() {
    let fixture = Fixture::new();
    let mut home = fixture.create();
    let alice = enrol(&mut home, 10, AccountClass::Human);
    let bob = enrol(&mut home, 20, AccountClass::Human);
    let room = room(&mut home, &alice, "tail filtering");
    run(
        &mut home,
        &bob,
        &action(&bob, Operation::RoomJoin, Target::Room(room), &Empty {}),
    );
    seed(
        &mut home,
        &alice,
        room,
        300,
        TimeBounds::test_now().lower_ms,
    );
    seed(&mut home, &bob, room, 256, TimeBounds::test_now().lower_ms);
    let filter = |enabled| {
        action(
            &alice,
            Operation::ModerationIgnore,
            Target::Account(alice.record.acting.account),
            &moderation::Filter {
                subject: bob.record.acting.account,
                enabled,
            },
        )
    };
    assert!(matches!(
        run(&mut home, &alice, &filter(true)),
        Outcome::Committed { .. }
    ));
    let page = tail(&mut home, &alice, room, 32);
    assert!(
        page.events.is_empty(),
        "older unignored rows are outside the raw candidate allowance"
    );
    assert!(!page.has_more);
    assert!(cursor(&home, &page).sequence >= 556);
    assert_eq!(
        page.members.len(),
        2,
        "recipient filtering does not truncate membership"
    );
    assert!(matches!(
        run(&mut home, &alice, &filter(false)),
        Outcome::Committed { .. }
    ));
    let page = tail(&mut home, &alice, room, 2);
    assert_eq!(page.events.len(), 2);
    assert!(
        page.events
            .iter()
            .all(|e| e.actor.acting().account == bob.record.acting.account)
    );
}

#[test]
fn tail_rechecks_retention_membership_and_existing_history_grants() {
    let fixture = Fixture::new();
    let mut home = fixture.create();
    let alice = enrol(&mut home, 10, AccountClass::Human);
    let agent = enrol(
        &mut home,
        20,
        AccountClass::Agent {
            operator: alice.record.acting.account,
        },
    );
    let room = room(&mut home, &alice, "tail authority");
    let now = TimeBounds::test_now();
    for stamp in [
        now.lower_ms - RETENTION - 1,
        now.lower_ms - 500,
        now.lower_ms - 300,
        now.lower_ms - 100,
    ] {
        seed(&mut home, &alice, room, 1, stamp);
    }
    home.store
        .write(|db| {
            db.execute(
                "UPDATE hrc_members SET history_from=0 WHERE room=?1",
                [room.to_string()],
            )?;
            Ok(Commit::new((), b"retained membership fixture".to_vec()))
        })
        .unwrap();
    let page = tail(&mut home, &alice, room, 32);
    assert!(
        !page
            .events
            .iter()
            .any(|e| e.timestamp_ms < now.lower_ms - RETENTION)
    );
    let scope = delegation::Create {
        agent: agent.record.acting.clone(),
        rooms: vec![room],
        recipients: vec![],
        operations: vec![Operation::HistoryPage],
        mode: delegation::Mode::Autonomous,
        not_before_ms: now.lower_ms - 1000,
        expires_ms: now.upper_ms + 60000,
        history_from_ms: now.lower_ms - 400,
        history_until_ms: now.lower_ms - 200,
        max_operations_per_minute: 120,
        purpose: "Bounded context".into(),
    };
    let reference: GrantRef = result(run(
        &mut home,
        &alice,
        &action(
            &alice,
            Operation::DelegationCreate,
            Target::Account(alice.record.acting.account),
            &scope,
        ),
    ));
    let read = || {
        delegated(
            action(
                &agent,
                Operation::HistoryTail,
                Target::Room(room),
                &messaging::Tail { limit: 32 },
            ),
            &alice,
            reference,
        )
    };
    let page: messaging::PageResult = result(run(&mut home, &agent, &read()));
    assert_eq!(page.events.len(), 1);
    assert_eq!(page.events[0].timestamp_ms, now.lower_ms - 300);
    let outside = run(
        &mut home,
        &agent,
        &action(
            &agent,
            Operation::HistoryTail,
            Target::Room(room),
            &messaging::Tail { limit: 32 },
        ),
    );
    assert!(matches!(
        outside,
        Outcome::Rejected {
            code: ErrorCode::Denied,
            ..
        }
    ));
    assert!(matches!(
        run(
            &mut home,
            &alice,
            &action(
                &alice,
                Operation::DelegationRevoke,
                Target::Delegation(reference),
                &Empty {}
            )
        ),
        Outcome::Committed { .. }
    ));
    assert!(matches!(
        run(&mut home, &agent, &read()),
        Outcome::Rejected { .. }
    ));
    // The room owner must remain; exercise membership withdrawal with a non-owner.
    assert!(matches!(
        run(
            &mut home,
            &agent,
            &action(&agent, Operation::RoomJoin, Target::Room(room), &Empty {})
        ),
        Outcome::Committed { .. }
    ));
    assert!(matches!(
        run(
            &mut home,
            &agent,
            &action(&agent, Operation::RoomLeave, Target::Room(room), &Empty {})
        ),
        Outcome::Committed { .. }
    ));
    assert!(matches!(
        run(
            &mut home,
            &agent,
            &action(
                &agent,
                Operation::HistoryTail,
                Target::Room(room),
                &messaging::Tail { limit: 32 }
            )
        ),
        Outcome::Rejected {
            code: ErrorCode::Denied,
            ..
        }
    ));
}

#[test]
fn stale_prompt_room_or_filter_revision_prevents_a_committed_send() {
    for change_filter in [false, true] {
        let fixture = Fixture::new();
        let mut home = fixture.create();
        let alice = enrol(&mut home, 10, AccountClass::Human);
        let bob = enrol(&mut home, 20, AccountClass::Human);
        let room = room(&mut home, &alice, "prompt guard");
        let inspection: conversations::Inspection = result(run(
            &mut home,
            &alice,
            &action(
                &alice,
                Operation::RoomInspect,
                Target::Room(room),
                &Empty {},
            ),
        ));
        let mut proposed = send(&alice, room, "stale generated reply");
        proposed
            .expected
            .insert(Revision::Room, inspection.room_revision);
        proposed
            .expected
            .insert(Revision::Filter, inspection.filter_revision);
        if change_filter {
            run(
                &mut home,
                &alice,
                &action(
                    &alice,
                    Operation::ModerationIgnore,
                    Target::Account(alice.record.acting.account),
                    &moderation::Filter {
                        subject: bob.record.acting.account,
                        enabled: true,
                    },
                ),
            );
        } else {
            run(
                &mut home,
                &bob,
                &action(&bob, Operation::RoomJoin, Target::Room(room), &Empty {}),
            );
        }
        assert!(
            matches!(run(&mut home, &alice, &proposed), Outcome::Rejected { code: ErrorCode::Conflict, detail, .. } if detail == "ExpectedRevision")
        );
        let page = tail(&mut home, &alice, room, 32);
        assert!(
            !page
                .events
                .iter()
                .any(|e| e.operation_id == proposed.operation_id)
        );
    }
}

#[test]
fn tail_rejects_wrong_privacy_invalid_limits_and_cancellation() {
    let fixture = Fixture::new();
    let mut home = fixture.create();
    let alice = enrol(&mut home, 10, AccountClass::Human);
    let room = room(&mut home, &alice, "tail bounds");
    for (operation, limit) in [
        (Operation::HistoryTail, 0),
        (Operation::HistoryTail, 51),
        (Operation::CryptoTail, 16),
    ] {
        assert!(matches!(
            run(
                &mut home,
                &alice,
                &action(
                    &alice,
                    operation,
                    Target::Room(room),
                    &messaging::Tail { limit }
                )
            ),
            Outcome::Rejected {
                code: ErrorCode::InvalidInput,
                ..
            }
        ));
    }
    let request = action(
        &alice,
        Operation::HistoryTail,
        Target::Room(room),
        &messaging::Tail { limit: 32 },
    );
    let cancel = Cancellation::default();
    cancel.cancel();
    let response = home
        .execute_cancellable(
            &verified(&alice, &request),
            &alice.session,
            TimeBounds::test_now(),
            &|| true,
            &cancel,
        )
        .unwrap();
    assert!(matches!(
        response.outcome,
        Outcome::Refused {
            code: ErrorCode::Unavailable,
            ..
        } | Outcome::Rejected {
            code: ErrorCode::Unavailable,
            ..
        }
    ));
}
