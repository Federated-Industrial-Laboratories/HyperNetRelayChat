// SPDX-License-Identifier: Apache-2.0
//! Selected-room continuation advances authenticated cursors without monopolizing the worker.
use super::*;

fn receiver() -> (crate::client::tests::Fixture, Worker, RoomId) {
    let (fixture, mut worker, room) = worker();
    worker
        .client
        .install_closed_view_test_session(&fixture.root);
    worker.client.install_view_test_clock(&fixture.root);
    worker.shared.stop.store(false, Ordering::Release);
    worker.shared.disconnect.store(false, Ordering::Release);
    (fixture, worker, room)
}
fn history(worker: &Worker, room: RoomId, first: u8, last: u8, more: bool) -> CommunityPage {
    let now = crate::clock::TimeBounds::test_now();
    let mut actor = crate::client::tests::action().actor.acting().clone();
    actor.account.local = Id::from_bytes([99; 32]);
    let events = (first..=last)
        .map(|n| {
            let action = crate::client::tests::action();
            Event {
                home: room.home,
                room,
                event: Id::from_bytes([n; 32]),
                sequence: u64::from(n),
                timestamp_ms: now.lower_ms,
                action_digest: action_digest(&action).unwrap(),
                actor: Actor::Direct {
                    acting: actor.clone(),
                },
                operation_id: action.operation_id,
                kind: Operation::MessageSend,
                body: action.body,
            }
        })
        .collect();
    let cursor = HistoryCursor {
        home: room.home,
        room,
        account: worker.snapshot.account,
        sequence: u64::from(last),
        membership_revision: 1,
        filter_revision: 0,
        access_digest: Id::from_bytes([70; 32]),
        expires_ms: now.upper_ms + 60_000,
    };
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
            items: vec![],
            next: None,
        }),
        restrictions: Some(home::InspectionPage {
            items: vec![],
            next: None,
        }),
        history: Some(messaging::PageResult {
            events,
            cursor: Blob(sign_cursor(&cursor, &SigningKey::from_bytes(&[11; 32])).unwrap()),
            has_more: more,
            room_revision: 1,
            members: vec![],
        }),
    }
}
fn first_page(worker: &mut Worker, room: RoomId) -> u64 {
    let mut state = CommunityAssembly::new(worker, room).unwrap();
    let issued = state.next_request().unwrap();
    let response = history(worker, room, 1, 32, true);
    assert!(state.accept(worker, issued, response).unwrap());
    worker.continue_selected(room, state.end);
    state.end
}
fn complete(
    state: &mut CommunityAssembly,
    worker: &mut Worker,
    first: u8,
    last: u8,
    more: bool,
) -> Result<bool> {
    let issued = state.next_request()?;
    let response = history(worker, state.room, first, last, more);
    state.accept(worker, issued, response)
}

#[test]
fn idle_receiver_catches_up_multiple_pages_without_waiting_for_metadata_or_notifying_history() {
    let (fixture, mut worker, room) = receiver();
    let poll = worker.poll;
    let end = first_page(&mut worker, room);
    assert!(worker.view_turn_due() && !worker.metadata_due());
    worker.publish();
    assert!(worker.shared.snapshot.lock().unwrap().updating);
    for (first, last, more) in [(33, 64, true), (65, 96, false)] {
        worker.client.install_view_test_clock(&fixture.root);
        worker
            .catchup_turn_with(|state, worker| {
                assert_eq!(state.end, end);
                let request = state.request.history.as_ref().unwrap();
                let key = SigningKey::from_bytes(&[11; 32]).verifying_key();
                assert_eq!(
                    verify_cursor(&request.cursor.as_ref().unwrap().0, &key)
                        .unwrap()
                        .value()
                        .sequence,
                    u64::from(first - 1)
                );
                complete(state, worker, first, last, more)
            })
            .unwrap();
        assert_eq!(worker.poll, poll);
        assert!(!worker.snapshot.selected.as_ref().unwrap().stale);
        assert!(!worker.snapshot.inspection.filters_stale);
        assert!(worker.snapshot.notifications.is_empty());
    }
    assert!(worker.selected_catchup.is_none() && worker.caught_up.contains(&room));
    assert!(!worker.snapshot.selected.as_ref().unwrap().has_more);
    let cached = cache::room(&mut worker.client.store, room).unwrap();
    assert_eq!(cached.events.len(), 96);
    assert_eq!(cached.events.last().unwrap().sequence, 96);
    assert!(!worker.shared.snapshot.lock().unwrap().updating);
}

#[test]
fn catchup_yields_to_due_metadata_and_commands_without_extending_its_end() {
    let (fixture, mut worker, room) = receiver();
    let end = first_page(&mut worker, room);
    worker.poll = Instant::now() - Duration::from_secs(6);
    worker.tick();
    assert!(matches!(
        worker.refresh_cycle.as_ref().unwrap().stage,
        Stage::Metadata(_)
    ));
    let pending = worker.selected_catchup.as_ref().unwrap();
    assert_eq!(pending.end, end);
    assert_eq!(pending.pages_left, 8);
    assert!(
        pending.assembly.is_none(),
        "due metadata owns the first turn"
    );
    // A local command can run between pages, without a continuation consuming it.
    worker
        .command(Command::SaveDraft {
            room,
            text: "independent draft".into(),
            mentions: vec![],
        })
        .unwrap();
    assert_eq!(
        worker.client.draft(room).unwrap().as_deref(),
        Some("independent draft")
    );
    worker.client.install_view_test_clock(&fixture.root);
    worker
        .catchup_turn_with(|state, worker| complete(state, worker, 33, 64, true))
        .unwrap();
    assert!(worker.metadata_due());
    assert!(matches!(
        worker.refresh_cycle.as_ref().unwrap().stage,
        Stage::Metadata(_)
    ));
    assert_eq!(worker.selected_catchup.as_ref().unwrap().end, end);
    // A command completing another current page supersedes partial continuation,
    // without granting another burst or extending the first deadline.
    worker.continue_selected(room, end + 1000);
    assert_eq!(worker.selected_catchup.as_ref().unwrap().end, end);
    assert_eq!(worker.selected_catchup.as_ref().unwrap().pages_left, 6);
}

#[test]
fn catchup_budget_and_original_end_stop_continuous_history_without_hot_loop() {
    let (fixture, mut worker, room) = receiver();
    let end = first_page(&mut worker, room);
    for n in 33..41 {
        worker.client.install_view_test_clock(&fixture.root);
        worker
            .catchup_turn_with(|state, worker| {
                assert_eq!(state.end, end);
                complete(state, worker, n, n, true)
            })
            .unwrap();
    }
    assert!(worker.selected_catchup.is_none());
    assert!(worker.snapshot.selected.as_ref().unwrap().has_more);
    assert!(
        !worker.view_turn_due(),
        "budget exhaustion cannot schedule itself again"
    );
    worker
        .catchup_turn_with(|_, _| panic!("no ninth page"))
        .unwrap();
    worker.continue_selected(room, 0);
    worker
        .catchup_turn_with(|_, _| panic!("expired original end"))
        .unwrap();
    assert!(worker.selected_catchup.is_none());
}

#[test]
fn cancellation_room_change_and_gap_stop_catchup_before_any_read() {
    for reason in 0..5 {
        let (_fixture, mut worker, room) = receiver();
        first_page(&mut worker, room);
        match reason {
            0 => worker.shared.stop.store(true, Ordering::Release),
            1 => worker.shared.disconnect.store(true, Ordering::Release),
            2 => {
                worker
                    .snapshot
                    .selected
                    .as_mut()
                    .unwrap()
                    .summary
                    .room
                    .local = Id::from_bytes([80; 32])
            }
            3 => worker.snapshot.selected.as_mut().unwrap().gap = Some("CursorHistoryGap".into()),
            _ => worker.snapshot.selected.as_mut().unwrap().focus = Some(Id::from_bytes([81; 32])),
        }
        worker
            .catchup_turn_with(|_, _| panic!("ineligible continuation issued a read"))
            .unwrap();
        assert!(worker.selected_catchup.is_none());
    }
}

#[test]
fn catchup_failure_and_nonadvancing_cursor_never_claim_current_or_retry_forever() {
    let (_fixture, mut worker, room) = receiver();
    first_page(&mut worker, room);
    let error = worker
        .catchup_turn_with(|_, _| {
            Err(Error::Rejected {
                code: ErrorCode::Denied,
                detail: "CurrentRoomAccessUnavailable".into(),
            })
        })
        .unwrap_err();
    assert!(matches!(error, Error::Rejected { .. }));
    assert!(worker.selected_catchup.is_none());
    assert!(worker.snapshot.selected.as_ref().unwrap().stale);
    assert!(worker.snapshot.inspection.filters_stale && worker.snapshot.privacy.is_none());
    worker
        .catchup_turn_with(|_, _| panic!("failed continuation restarted"))
        .unwrap();

    let (fixture, mut worker, room) = receiver();
    first_page(&mut worker, room);
    worker.client.install_view_test_clock(&fixture.root);
    assert!(matches!(
        worker.catchup_turn_with(|state, worker| complete(state, worker, 32, 32, true)),
        Err(Error::Input)
    ));
    assert!(worker.selected_catchup.is_none());
    assert_eq!(
        cache::room(&mut worker.client.store, room)
            .unwrap()
            .events
            .len(),
        32
    );
}

#[test]
fn partial_catchup_policy_yields_without_admitting_history_or_notifications() {
    let (fixture, mut worker, room) = receiver();
    let _clock = worker.client.start_view_test_clock(&fixture.root);
    first_page(&mut worker, room);
    let ignored = history(&worker, room, 33, 64, true).history.unwrap().events[0]
        .actor
        .represented();
    worker
        .catchup_turn_with(|state, worker| {
            let issued = state.next_request()?;
            let mut response = history(worker, room, 33, 64, true);
            response.filters = Some(home::InspectionPage {
                items: vec![moderation::FilterState {
                    subject: ignored,
                    ignored: true,
                    muted: false,
                }],
                next: Some(ignored.to_string()),
            });
            state.accept(worker, issued, response)
        })
        .unwrap();
    assert!(worker.selected_catchup.as_ref().unwrap().assembly.is_some());
    assert_eq!(
        cache::room(&mut worker.client.store, room)
            .unwrap()
            .events
            .len(),
        32
    );
    worker
        .catchup_turn_with(|state, worker| {
            let issued = state.next_request()?;
            assert!(issued.history.is_none() && issued.restrictions.is_none());
            let mut response = history(worker, room, 33, 64, true);
            response.history = None;
            response.restrictions = None;
            state.accept(worker, issued, response)
        })
        .unwrap();
    assert!(worker.snapshot.selected.as_ref().unwrap().events.is_empty());
    assert!(worker.snapshot.notifications.is_empty());
    assert!(!worker.snapshot.selected.as_ref().unwrap().stale);
    assert!(!worker.snapshot.inspection.filters_stale);
    // Installing the newly active filter purges the earlier cached rows before
    // the next authenticated page is retained. Neither page reaches presentation.
    let cached = cache::room(&mut worker.client.store, room).unwrap();
    assert_eq!(cached.events.len(), 32);
    assert_eq!(cached.events.first().unwrap().sequence, 33);
    assert_eq!(cached.events.last().unwrap().sequence, 64);
}
