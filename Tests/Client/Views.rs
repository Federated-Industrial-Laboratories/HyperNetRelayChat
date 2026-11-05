// SPDX-License-Identifier: Apache-2.0
//! Partial grouped reads cannot admit history, filters or a new authority lease.
use super::super::completion_tests::worker;
use super::*;

fn partial(_room: RoomId, account: AccountId) -> CommunityPage {
    CommunityPage {
        inspection: home::views::RoomInspection {
            members: vec![],
            read_sequence: 0,
            room_revision: 1,
            filter_revision: 0,
            moderator: false,
            confidentiality: RoomConfidentiality::Community,
        },
        context: Id::from_bytes([81; 32]),
        filters: Some(home::InspectionPage {
            items: vec![moderation::FilterState {
                subject: account,
                ignored: true,
                muted: false,
            }],
            next: Some(account.to_string()),
        }),
        history: Some(messaging::PageResult {
            events: vec![],
            cursor: Blob(vec![]),
            has_more: false,
            room_revision: 1,
            members: vec![],
        }),
        restrictions: Some(home::InspectionPage {
            items: vec![moderation::RestrictionState {
                subject: account,
                kind: 1,
                expires_ms: u64::MAX,
                moderator: account,
            }],
            next: Some(format!("{}:1", account)),
        }),
    }
}

#[test]
fn partial_policy_holds_history_and_continues_one_component_without_renewing_end() {
    let (fixture, mut worker, room) = worker();
    worker
        .client
        .install_closed_view_test_session(&fixture.root);
    worker.refresh_sent_room(room, true);
    worker.refresh_sent_room(room, true);
    assert!(worker.pending_room_due(Instant::now()));
    let mut state = CommunityAssembly::new(&mut worker, room).unwrap();
    let end = state.end;
    let issued = state.next_request().unwrap();
    let account = worker.snapshot.account;
    assert!(
        !state
            .accept(&mut worker, issued, partial(room, account))
            .unwrap()
    );
    assert!(worker.snapshot.inspection.filters.is_empty());
    assert!(worker.snapshot.inspection.restrictions.is_empty());
    assert!(
        cache::room(&mut worker.client.store, room)
            .unwrap()
            .cursor
            .is_none()
    );
    assert!(worker.snapshot.notifications.is_empty());
    assert!(worker.client.community_modes.is_empty());
    assert!(worker.shared.snapshot.lock().unwrap().updating);
    assert!(
        worker.pending_room_due(Instant::now()),
        "partial policy must not satisfy the queued view update"
    );
    let next = state.next_request().unwrap();
    assert!(next.filters.is_some() && next.history.is_none() && next.restrictions.is_none());
    assert_eq!(next.context, Some(Id::from_bytes([81; 32])));
    assert_eq!(state.end, end);
    state.rounds = 66;
    assert!(matches!(state.next_request(), Err(Error::Input)));
    assert_eq!(state.end, end);
}

#[test]
fn changed_context_and_invented_components_never_complete_partial_history() {
    let (_fixture, mut worker, room) = worker();
    let mut state = CommunityAssembly::new(&mut worker, room).unwrap();
    let issued = state.next_request().unwrap();
    let account = worker.snapshot.account;
    assert!(
        !state
            .accept(&mut worker, issued, partial(room, account))
            .unwrap()
    );
    let issued = state.next_request().unwrap();
    let mut changed = partial(room, account);
    changed.context = Id::from_bytes([82; 32]);
    assert!(matches!(
        state.accept(&mut worker, issued.clone(), changed),
        Err(Error::Input)
    ));
    let mut extra = partial(room, account);
    extra.history = None;
    assert!(matches!(
        state.accept(&mut worker, issued, extra),
        Err(Error::Input)
    ));
    assert!(
        cache::room(&mut worker.client.store, room)
            .unwrap()
            .cursor
            .is_none()
    );
    assert!(worker.snapshot.inspection.filters.is_empty());
}

#[test]
fn temporary_grouped_refusal_invalidates_filter_dependencies_without_clearing_metadata() {
    let (_fixture, mut worker, room) = worker();
    let action = crate::client::tests::action();
    let response = Response {
        home: action.home,
        operation_id: action.operation_id,
        action_digest: action_digest(&action).unwrap(),
        outcome: Outcome::Refused {
            code: ErrorCode::Overloaded,
            detail: "ViewBusy".into(),
            retry_after_ms: Some(1),
        },
    };
    worker.observe_read(Operation::CommunitySync, &Target::Room(room), &response);
    assert!(!worker.snapshot.inspection.stale);
    assert!(worker.snapshot.inspection.filters_stale);
    assert!(worker.snapshot.selected.as_ref().unwrap().stale);
    worker.install_filters(vec![]).unwrap();
    assert!(!worker.snapshot.inspection.filters_stale);
    assert!(
        worker.snapshot.selected.as_ref().unwrap().stale,
        "filter recovery is not room authorization"
    );
    worker.observe_read(
        Operation::ClientMetadata,
        &Target::Account(worker.snapshot.account),
        &response,
    );
    assert!(worker.snapshot.inspection.stale && worker.snapshot.inspection.filters_stale);
    worker.install_filters(vec![]).unwrap();
    assert!(
        worker.snapshot.inspection.stale,
        "room filters cannot restore failed metadata"
    );
}

#[test]
fn a_command_pull_supersedes_only_its_pending_room_group_without_restarting_metadata() {
    let (_fixture, mut worker, room) = worker();
    let mut cycle = RefreshCycle::new().unwrap();
    cycle.room_updated(room);
    assert!(matches!(cycle.stage, Stage::Metadata(_)));
    cycle.stage = Stage::Room(CommunityAssembly::new(&mut worker, room).unwrap(), false);
    cycle.room_updated(RoomId {
        local: Id::from_bytes([89; 32]),
        ..room
    });
    assert!(matches!(cycle.stage, Stage::Room(_, false)));
    cycle.room_updated(room);
    assert!(matches!(cycle.stage, Stage::Background));
    worker.shared.stop.store(false, Ordering::Release);
    worker.shared.disconnect.store(false, Ordering::Release);
    assert!(!cycle.step(&mut worker).unwrap());
    assert!(matches!(cycle.stage, Stage::Privacy));
    // An unrelated successful command cannot reset the five-second metadata timer.
    worker.poll = Instant::now() - Duration::from_secs(6);
    worker.refresh_cycle = Some(cycle);
    worker.refresh_yield = true;
    assert!(worker.metadata_due());
}

#[test]
fn completed_room_pull_satisfies_the_selected_turn_but_keeps_privacy_and_metadata_due() {
    let (fixture, mut worker, room) = worker();
    worker
        .client
        .install_closed_view_test_session(&fixture.root);
    worker.shared.stop.store(false, Ordering::Release);
    worker.shared.disconnect.store(false, Ordering::Release);
    worker.poll = Instant::now() - Duration::from_secs(6);
    let poll = worker.poll;
    let mut cycle = RefreshCycle {
        stage: Stage::Selected(None),
    };
    // The callback is used only after the grouped pull has installed every
    // filter, restriction and history component. The fixture view is current.
    cycle.room_updated(room);
    assert!(!cycle.step(&mut worker).unwrap());
    assert!(matches!(cycle.stage, Stage::Background));
    // With no other joined room, both turns succeed without touching the closed
    // session. Previously the second turn attempted a duplicate CommunitySync.
    assert!(!cycle.step(&mut worker).unwrap());
    assert!(matches!(cycle.stage, Stage::Privacy));
    assert_eq!(worker.poll, poll);
    assert!(worker.metadata_due());
    // The required companion privacy observation is still attempted separately.
    assert!(matches!(cycle.step(&mut worker), Err(Error::Network(_))));
}

#[test]
fn selected_turn_does_not_reuse_an_unfinished_or_invalidated_room_update() {
    for invalidation in ["metadata", "selection", "view", "filters", "gap"] {
        let (fixture, mut worker, room) = worker();
        worker
            .client
            .install_closed_view_test_session(&fixture.root);
        worker.shared.stop.store(false, Ordering::Release);
        worker.shared.disconnect.store(false, Ordering::Release);
        let mut cycle = if invalidation == "metadata" {
            RefreshCycle::new().unwrap()
        } else {
            RefreshCycle {
                stage: Stage::Selected(None),
            }
        };
        cycle.room_updated(room);
        match invalidation {
            "metadata" => {
                assert!(matches!(cycle.stage, Stage::Metadata(_)));
                assert!(
                    cycle.step(&mut worker).is_err(),
                    "metadata must still be read"
                );
                continue;
            }
            "selection" => {
                let other = RoomId {
                    local: Id::from_bytes([97; 32]),
                    ..room
                };
                let mut summary = worker.snapshot.rooms[0].clone();
                summary.room = other;
                worker.snapshot.rooms.push(summary.clone());
                cache::save_rooms(&mut worker.client.store, room.home, &worker.snapshot.rooms)
                    .unwrap();
                worker.snapshot.selected.as_mut().unwrap().summary = summary;
            }
            "view" => worker.snapshot.selected.as_mut().unwrap().stale = true,
            "filters" => worker.snapshot.inspection.filters_stale = true,
            "gap" => {
                worker.snapshot.selected.as_mut().unwrap().gap = Some("CursorHistoryGap".into())
            }
            _ => unreachable!(),
        }
        if invalidation == "gap" {
            assert!(!cycle.step(&mut worker).unwrap());
            assert!(matches!(cycle.stage, Stage::Background));
            assert_eq!(
                worker.snapshot.selected.as_ref().unwrap().gap.as_deref(),
                Some("CursorHistoryGap"),
                "a completed page must not clear an existing history gap"
            );
            assert!(!cycle.step(&mut worker).unwrap());
            assert!(matches!(cycle.stage, Stage::Privacy));
            assert!(matches!(cycle.step(&mut worker), Err(Error::Network(_))));
        } else {
            assert!(!cycle.step(&mut worker).unwrap());
            assert!(
                matches!(cycle.stage, Stage::Room(_, false)),
                "{invalidation}"
            );
            assert!(
                cycle.step(&mut worker).is_err(),
                "{invalidation} must still attempt its room read"
            );
        }
    }
}

#[test]
fn ordinary_bounded_polling_reclaims_expired_candidates_and_old_drafts_once_per_cycle() {
    let (fixture, mut worker, room) = worker();
    worker
        .client
        .install_closed_view_test_session(&fixture.root);
    worker.shared.stop.store(false, Ordering::Release);
    worker.shared.disconnect.store(false, Ordering::Release);
    let recent = RoomId {
        local: Id::from_bytes([93; 32]),
        ..room
    };
    worker.client.save_draft(room, "expired draft").unwrap();
    worker
        .client
        .save_draft(recent, "retained draft e\u{301} 👩‍🚀")
        .unwrap();
    worker
        .client
        .store
        .write(|db| {
            db.execute(
                "UPDATE client_drafts SET updated=0 WHERE room=?1",
                [room.to_string()],
            )?;
            for n in 0..32 {
                db.execute(
                    "INSERT INTO client_candidates VALUES(?1,?2,0)",
                    rusqlite::params![Id::from_bytes([n; 32]).as_hex(), b"expired".as_slice()],
                )?;
            }
            Ok(crate::storage::Commit::new(
                (),
                b"expired candidate and draft fixture".to_vec(),
            ))
        })
        .unwrap();
    let id = Id::from_bytes([94; 32]);
    let expires = crate::clock::TimeBounds::test_now().upper_ms + 60_000;
    assert!(cache::candidate(&mut worker.client.store, id, b"new", expires).is_err());
    worker.poll = Instant::now() - Duration::from_secs(6);
    worker.tick();
    assert!(worker.refresh_cycle.is_some());
    assert!(
        worker.metadata_due(),
        "maintenance cannot postpone the due metadata reads"
    );
    assert!(!worker.snapshot.inspection.stale && !worker.snapshot.inspection.filters_stale);
    assert!(!worker.snapshot.selected.as_ref().unwrap().stale);
    assert!(worker.client.draft(room).unwrap().is_none());
    assert_eq!(
        worker.client.draft(recent).unwrap().as_deref(),
        Some("retained draft e\u{301} 👩‍🚀")
    );
    cache::candidate(&mut worker.client.store, id, b"new", expires).unwrap();
    let count = |worker: &mut Worker| {
        worker
            .client
            .store
            .read(Duration::from_secs(1), |db| {
                db.query_row("SELECT count(*) FROM client_candidates", [], |r| {
                    r.get::<_, u64>(0)
                })
            })
            .unwrap()
    };
    assert_eq!(count(&mut worker), 1);

    cache::candidate(
        &mut worker.client.store,
        Id::from_bytes([95; 32]),
        b"later expired",
        0,
    )
    .unwrap();
    // This ordinary component turn reaches the fixture's missing current clock.
    // Its failed read must not run retention again or claim refreshed authority.
    worker.tick();
    assert_eq!(count(&mut worker), 2);
    assert!(worker.snapshot.inspection.stale && worker.snapshot.inspection.filters_stale);
    assert!(worker.refresh_cycle.is_none());
    assert!(
        !worker.metadata_due(),
        "failed component work retains its bounded retry interval"
    );
}

#[path = "Catchup.rs"]
mod catchup;
