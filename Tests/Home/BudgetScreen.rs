// SPDX-License-Identifier: Apache-2.0
//! Early rejection never becomes permission, a reservation or a retained outcome.
use super::*;

fn screen(home: &mut Home, party: &Party, action: &Action) -> bool {
    home.budget_exhausted(
        &verified(party, action),
        &party.session,
        TimeBounds::test_now(),
        Duration::from_secs(1),
    )
}
fn search(party: &Party, room: RoomId) -> Action {
    action(
        party,
        Operation::SearchQuery,
        Target::Room(room),
        &messaging::Search {
            terms: vec!["retained".into()],
            sender: None,
            represented: None,
            from_ms: None,
            until_ms: None,
            cursor: None,
            limit: 16,
        },
    )
}
fn set_credit(home: &mut Home, key: &str, credit: u64) {
    // Pin refill beyond the test, so admission assertions do not depend on disk speed.
    let updated = TimeBounds::test_now().upper_ms + 60_000;
    home.store
        .write(|db| {
            db.execute(
                "INSERT INTO hrc_budgets VALUES(?1,?2,?3) ON CONFLICT(key) DO UPDATE SET credit=excluded.credit,updated=excluded.updated",
                params![key, credit, updated],
            )?;
            Ok(Commit::new((), b"budget fixture".to_vec()))
        })
        .unwrap();
}
fn snapshot(home: &mut Home) -> (u64, Vec<(String, u64, u64)>) {
    let counter = home.usage().unwrap().commit_counter;
    let budgets = home
        .store
        .read(Duration::from_secs(1), |db| {
            db.prepare("SELECT key,credit,updated FROM hrc_budgets ORDER BY key")?
                .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
                .collect()
        })
        .unwrap();
    (counter, budgets)
}
fn budget_refusal(outcome: &Outcome) -> bool {
    matches!(outcome, Outcome::Refused { code: ErrorCode::RateLimited, detail, .. } if detail == "OperationBudget")
}

#[test]
fn exhausted_direct_and_independent_send_and_search_screens_are_read_only() {
    let fixture = Fixture::new();
    let mut home = fixture.create();
    let owner = enrol(&mut home, 10, AccountClass::Human);
    let agent = enrol(
        &mut home,
        20,
        AccountClass::Agent {
            operator: owner.record.acting.account,
        },
    );
    for party in [&owner, &agent] {
        let room = room(&mut home, party, "screened work");
        for (prefix, action) in [
            ("send", send(party, room, "retained")),
            ("search", search(party, room)),
        ] {
            set_credit(
                &mut home,
                &format!("{prefix}:{}", party.record.acting.account),
                0,
            );
            let before = snapshot(&mut home);
            assert!(screen(&mut home, party, &action));
            assert!(screen(&mut home, party, &action));
            assert_eq!(snapshot(&mut home), before);
            // The same budget owner also refuses the ordinary, fresh-authorized path.
            let calls = Cell::new(0);
            let outcome = home
                .execute(
                    &verified(party, &action),
                    &party.session,
                    TimeBounds::test_now(),
                    &|| {
                        calls.set(calls.get() + 1);
                        true
                    },
                )
                .unwrap()
                .outcome;
            assert!(calls.get() >= 2);
            assert!(budget_refusal(&outcome));
            assert_eq!(snapshot(&mut home).1, before.1);
            assert!(screen(&mut home, party, &action), "no outcome was saved");
        }
    }
}

#[test]
fn retained_outcomes_conflicts_and_reads_still_require_fresh_authority() {
    let fixture = Fixture::new();
    let mut home = fixture.create();
    let owner = enrol(&mut home, 10, AccountClass::Human);
    let room = room(&mut home, &owner, "retry outcomes");
    let sent = send(&owner, room, "retained");
    let committed = run(&mut home, &owner, &sent);
    assert!(matches!(committed, Outcome::Committed { .. }));
    let query = search(&owner, room);
    assert!(matches!(
        run(&mut home, &owner, &query),
        Outcome::Result { .. }
    ));
    set_credit(
        &mut home,
        &format!("send:{}", owner.record.acting.account),
        0,
    );
    set_credit(
        &mut home,
        &format!("search:{}", owner.record.acting.account),
        0,
    );
    let mut conflict = send(&owner, room, "different content");
    conflict.operation_id = sent.operation_id;
    let before = snapshot(&mut home);
    for action in [&sent, &conflict, &query] {
        assert!(!screen(&mut home, &owner, action));
        let response = home
            .execute(
                &verified(&owner, action),
                &owner.session,
                TimeBounds::test_now(),
                &|| false,
            )
            .unwrap();
        assert!(matches!(
            response.outcome,
            Outcome::Refused {
                code: ErrorCode::Unavailable,
                ..
            }
        ));
    }
    assert_eq!(snapshot(&mut home), before);
    assert_eq!(run(&mut home, &owner, &sent), committed);
    assert!(matches!(
        run(&mut home, &owner, &conflict),
        Outcome::Rejected {
            code: ErrorCode::Conflict,
            ..
        }
    ));
    // Retained reads must re-evaluate current policy and costs, not return saved content.
    assert!(budget_refusal(&run(&mut home, &owner, &query)));
}

#[test]
fn unbound_and_uncertain_requests_do_not_reveal_exhaustion() {
    let fixture = Fixture::new();
    let mut home = fixture.create();
    let owner = enrol(&mut home, 10, AccountClass::Human);
    let other = enrol(&mut home, 20, AccountClass::Human);
    let room = room(&mut home, &owner, "bindings");
    set_credit(
        &mut home,
        &format!("send:{}", owner.record.acting.account),
        0,
    );
    let valid = send(&owner, room, "retained");
    assert!(screen(&mut home, &owner, &valid));
    let before = snapshot(&mut home);
    assert!(!home.budget_exhausted(
        &verified(&other, &valid),
        &other.session,
        TimeBounds::test_now(),
        Duration::from_secs(1),
    ));
    assert!(!home.budget_exhausted(
        &verified(&owner, &valid),
        &other.session,
        TimeBounds::test_now(),
        Duration::from_secs(1),
    ));
    let mut wrong_window = valid.clone();
    wrong_window.operation_id.window = other.window.id;
    let mut unknown_window = valid.clone();
    unknown_window.operation_id.window = id(99);
    let mut wrong_revision = valid.clone();
    wrong_revision.expected.insert(Revision::Room, u64::MAX);
    let mut unknown_room = valid.clone();
    unknown_room.target = Target::Room(RoomId {
        local: id(99),
        ..room
    });
    for action in [wrong_window, unknown_window, wrong_revision, unknown_room] {
        assert!(!screen(&mut home, &owner, &action));
    }
    assert!(!home.budget_exhausted(
        &verified(&owner, &valid),
        &owner.session,
        TimeBounds::test_now(),
        Duration::ZERO,
    ));
    assert_eq!(snapshot(&mut home), before);
    home.store
        .write(|db| {
            db.execute(
                "UPDATE hrc_windows SET expires=1 WHERE id=?1",
                [owner.window.id.as_hex()],
            )?;
            Ok(Commit::new((), b"expired retry window".to_vec()))
        })
        .unwrap();
    let before = snapshot(&mut home);
    assert!(!screen(&mut home, &owner, &valid));
    assert_eq!(snapshot(&mut home), before);
    assert_eq!(run(&mut home, &owner, &valid), Outcome::Unknown);
}

#[test]
fn delegated_confidential_remote_and_other_work_keep_the_existing_path() {
    let fixture = Fixture::new();
    let mut home = fixture.create();
    let owner = enrol(&mut home, 10, AccountClass::Human);
    let agent = enrol(
        &mut home,
        20,
        AccountClass::Agent {
            operator: owner.record.acting.account,
        },
    );
    let room = room(&mut home, &owner, "scope");
    let grant = grant(
        &mut home,
        &owner,
        &agent,
        room,
        delegation::Mode::Autonomous,
    );
    let delegated = delegated(send(&agent, room, "delegated"), &owner, grant);
    let Outcome::Committed { body, .. } = run(
        &mut home,
        &owner,
        &action(
            &owner,
            Operation::RoomCreate,
            Target::Service,
            &conversations::Create {
                name: "confidential".into(),
                confidentiality: RoomConfidentiality::PrivateGroup,
            },
        ),
    ) else {
        panic!("private room creation")
    };
    let private = body
        .deserialized::<messaging::Committed>()
        .unwrap()
        .room
        .unwrap();
    set_credit(
        &mut home,
        &format!("send:{}", agent.record.acting.account),
        0,
    );
    set_credit(
        &mut home,
        &format!("send:{}", owner.record.acting.account),
        0,
    );
    let mut remote = send(&owner, room, "remote");
    remote.agreement = Some(AgreementRef {
        id: id(90),
        revision: 1,
        digest: id(91),
    });
    let before = snapshot(&mut home);
    assert!(!screen(&mut home, &agent, &delegated));
    assert!(!screen(&mut home, &owner, &remote));
    assert!(!screen(
        &mut home,
        &owner,
        &send(&owner, private, "no plaintext admission")
    ));
    assert!(!screen(
        &mut home,
        &owner,
        &action(
            &owner,
            Operation::RoomInspect,
            Target::Room(room),
            &Empty {}
        )
    ));
    assert_eq!(snapshot(&mut home), before);
}

#[test]
fn available_screens_reserve_nothing_and_final_authority_can_roll_back_charge() {
    let fixture = Fixture::new();
    let mut home = fixture.create();
    let owner = enrol(&mut home, 10, AccountClass::Human);
    let room = room(&mut home, &owner, "final admission");
    let key = format!("send:{}", owner.record.acting.account);
    set_credit(&mut home, &key, 1000);
    let first = send(&owner, room, "first");
    let second = send(&owner, room, "second");
    let before = snapshot(&mut home);
    assert!(!screen(&mut home, &owner, &first));
    assert!(!screen(&mut home, &owner, &second));
    assert_eq!(snapshot(&mut home), before);
    let calls = Cell::new(0);
    let response = home
        .execute(
            &verified(&owner, &first),
            &owner.session,
            TimeBounds::test_now(),
            &|| {
                calls.set(calls.get() + 1);
                calls.get() < 3
            },
        )
        .unwrap();
    assert_eq!(calls.get(), 3);
    assert!(matches!(
        response.outcome,
        Outcome::Refused {
            code: ErrorCode::Unavailable,
            ..
        }
    ));
    assert_eq!(
        snapshot(&mut home),
        before,
        "final denial rolls back the sole charge and effect"
    );
    assert!(matches!(
        run(&mut home, &owner, &first),
        Outcome::Committed { .. }
    ));
    let credit = snapshot(&mut home)
        .1
        .into_iter()
        .find(|(k, _, _)| *k == key)
        .unwrap()
        .1;
    assert_eq!(credit, 0, "one actual admission consumes one token");
    // Re-pin only refill time; the first execution's remaining credit is unchanged.
    set_credit(&mut home, &key, credit);
    let before = snapshot(&mut home);
    assert!(screen(&mut home, &owner, &second));
    assert!(
        budget_refusal(&run(&mut home, &owner, &second)),
        "a prior passing screen cannot overdraw credit"
    );
    assert_eq!(snapshot(&mut home).1, before.1);
}

#[test]
fn a_passing_screen_does_not_survive_a_current_membership_revocation() {
    let fixture = Fixture::new();
    let mut home = fixture.create();
    let owner = enrol(&mut home, 10, AccountClass::Human);
    let member = enrol(&mut home, 20, AccountClass::Human);
    let room = room(&mut home, &owner, "current membership");
    assert!(matches!(
        run(
            &mut home,
            &member,
            &action(&member, Operation::RoomJoin, Target::Room(room), &Empty {})
        ),
        Outcome::Committed { .. }
    ));
    let queued = send(&member, room, "queued before ban");
    assert!(!screen(&mut home, &member, &queued));
    assert!(matches!(
        run(
            &mut home,
            &owner,
            &action(
                &owner,
                Operation::ModerationBan,
                Target::Room(room),
                &moderation::Restriction {
                    subject: member.record.acting.account,
                    enabled: true,
                    duration_ms: 60_000,
                    reason: "current restriction".into(),
                }
            )
        ),
        Outcome::Committed { .. }
    ));
    let before = snapshot(&mut home);
    assert!(!screen(&mut home, &member, &queued));
    assert_eq!(snapshot(&mut home), before);
    assert!(
        matches!(run(&mut home, &member, &queued), Outcome::Rejected { code: ErrorCode::Denied, detail } if detail == "RoomBan")
    );
    assert!(!history(&mut home, &owner, room).events.iter().any(
        |event| event.actor.acting().account == member.record.acting.account
            && event.kind == Operation::MessageSend
    ));
}

#[test]
fn admission_owner_is_a_bound_read_only_identity_not_a_permission() {
    let fixture = Fixture::new();
    let mut home = fixture.create();
    let owner = enrol(&mut home, 10, AccountClass::Human);
    let victim = enrol(&mut home, 30, AccountClass::Human);
    let agent = enrol(
        &mut home,
        20,
        AccountClass::Agent {
            operator: owner.record.acting.account,
        },
    );
    let room = room(&mut home, &owner, "admission bindings");
    let grant = grant(
        &mut home,
        &owner,
        &agent,
        room,
        delegation::Mode::Autonomous,
    );
    let valid = delegated(
        send(&agent, room, "requires current authority"),
        &owner,
        grant,
    );
    let lookup = |home: &mut Home, action: &Action| {
        home.admission_owner(
            &verified(&agent, action),
            &agent.session,
            TimeBounds::test_now(),
            Duration::from_secs(1),
        )
    };
    let before = snapshot(&mut home);
    assert_eq!(lookup(&mut home, &valid), Some(owner.record.acting.account));
    let mut forged_owner = valid.clone();
    if let Actor::Delegated { represented, .. } = &mut forged_owner.actor {
        *represented = victim.record.acting.account;
    }
    let mut unknown_grant = valid.clone();
    if let Actor::Delegated { grant, .. } = &mut unknown_grant.actor {
        grant.id = id(99);
    }
    let mut forged_actor = valid.clone();
    if let Actor::Delegated { acting, .. } = &mut forged_actor.actor {
        *acting = victim.record.acting.clone();
    }
    for action in [&forged_owner, &unknown_grant, &forged_actor] {
        assert_eq!(lookup(&mut home, action), None);
    }
    assert_eq!(
        home.admission_owner(
            &verified(&agent, &valid),
            &agent.session,
            TimeBounds::test_now(),
            Duration::ZERO
        ),
        None
    );
    assert_eq!(snapshot(&mut home), before);
    let response = home
        .execute(
            &verified(&agent, &valid),
            &agent.session,
            TimeBounds::test_now(),
            &|| false,
        )
        .unwrap();
    assert!(matches!(
        response.outcome,
        Outcome::Refused {
            code: ErrorCode::Unavailable,
            ..
        }
    ));
    assert_eq!(
        snapshot(&mut home),
        before,
        "queue identity cannot authorize or charge work"
    );
    assert!(matches!(
        run(
            &mut home,
            &owner,
            &action(
                &owner,
                Operation::DelegationPause,
                Target::Delegation(grant),
                &Empty {}
            )
        ),
        Outcome::Committed { .. }
    ));
    let before = snapshot(&mut home);
    assert_eq!(lookup(&mut home, &valid), None);
    assert_eq!(snapshot(&mut home), before);
}
