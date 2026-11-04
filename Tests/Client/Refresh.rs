// SPDX-License-Identifier: Apache-2.0
//! Refresh progress, failure visibility and metadata fairness share the production worker paths.
use super::*;

#[test]
fn a_waiting_view_update_preserves_validated_content_and_reports_progress() {
    let (_fixture, mut worker, _) = worker();
    worker.snapshot.selected.as_mut().unwrap().events = vec![received_event(64)];
    let shared = Arc::clone(&worker.shared);
    let (entered, started) = mpsc::sync_channel(1);
    let (release, released) = mpsc::sync_channel(1);
    thread::scope(|scope| {
        let current = &mut worker;
        let task = scope.spawn(move || {
            current.update_view(|worker| {
                entered.send(()).unwrap();
                released.recv_timeout(Duration::from_secs(2)).unwrap();
                // An inner successful read must not end the outer progress lifetime.
                worker.update_view(|_| Ok(()))?;
                assert!(worker.shared.snapshot.lock().unwrap().updating);
                Ok(())
            })
        });
        started.recv_timeout(Duration::from_secs(2)).unwrap();
        let visible = Arc::clone(&shared.snapshot.lock().unwrap());
        assert!(visible.updating);
        assert!(!visible.inspection.stale);
        let room = visible.selected.as_ref().unwrap();
        assert!(!room.stale && room.gap.is_none());
        assert_eq!(room.events.len(), 1);
        release.send(()).unwrap();
        task.join().unwrap().unwrap();
    });
    let visible = worker.shared.snapshot.lock().unwrap();
    assert!(!visible.updating && !visible.inspection.stale);
    assert!(!visible.selected.as_ref().unwrap().stale);
}

#[test]
fn successful_progress_does_not_restore_an_already_stale_or_gapped_view() {
    let (_fixture, mut worker, _) = worker();
    worker.stale();
    worker.snapshot.selected.as_mut().unwrap().gap = Some("CursorHistoryGap".into());
    worker.update_view(|_| Ok(())).unwrap();
    let visible = worker.shared.snapshot.lock().unwrap();
    assert!(!visible.updating && visible.inspection.stale);
    let room = visible.selected.as_ref().unwrap();
    assert!(room.stale);
    assert_eq!(room.gap.as_deref(), Some("CursorHistoryGap"));
}

#[test]
fn every_failed_view_scope_invalidates_before_its_caller_handles_the_error() {
    for error in [
        Error::Input,
        Error::Storage,
        Error::Offline,
        Error::Rejected {
            code: ErrorCode::Denied,
            detail: "Denied".into(),
        },
        Error::Rejected {
            code: ErrorCode::Expired,
            detail: "Expired".into(),
        },
        unavailable(),
    ] {
        let (_fixture, mut worker, _) = worker();
        let code = error.code();
        let result: Result<()> = worker.update_view(|_| Err(error));
        assert_eq!(result.unwrap_err().code(), code);
        let visible = worker.shared.snapshot.lock().unwrap();
        assert!(!visible.updating && visible.inspection.stale);
        assert!(visible.selected.as_ref().unwrap().stale);
        assert!(visible.privacy.is_none());
    }
}

#[test]
fn a_temporary_read_refusal_is_visible_before_the_same_action_retry_finishes() {
    let (_fixture, mut worker, _) = worker();
    let end = crate::clock::boot_ms().unwrap() + 2000;
    let mut calls = 0;
    worker
        .update_view(|worker| {
            let response = retry_read(
                end,
                || false,
                |passed| {
                    assert_eq!(passed, end);
                    calls += 1;
                    if calls == 2 {
                        let visible = worker.shared.snapshot.lock().unwrap();
                        assert!(visible.updating && visible.inspection.stale);
                        assert!(visible.selected.as_ref().unwrap().stale);
                        assert!(visible.privacy.is_none());
                    }
                    let response = if calls == 1 {
                        temporary_read()
                    } else {
                        read_result(Outcome::Result { body: Value::Null })
                    };
                    worker.observe_read(
                        Operation::ModerationFilters,
                        &Target::Account(worker.snapshot.account),
                        &response,
                    );
                    Ok(response)
                },
            )?;
            assert!(matches!(response.outcome, Outcome::Result { .. }));
            Ok(())
        })
        .unwrap();
    assert_eq!(calls, 2);
    // One successful read does not certify every previously invalidated view.
    assert!(worker.snapshot.inspection.stale);
}

#[test]
fn a_nonempty_command_queue_cannot_starve_due_metadata_work() {
    let (_fixture, mut worker, room) = worker();
    worker.shared.stop.store(false, Ordering::Release);
    worker.shared.disconnect.store(false, Ordering::Release);
    worker.desired = false;
    let due = Instant::now() - Duration::from_secs(6);
    worker.poll = due;
    let (sender, receiver) = mpsc::sync_channel(32);
    let (local_sender, local_receiver) = mpsc::sync_channel(32);
    for request in 1..=8 {
        sender
            .send(Queued::new(request, Command::SelectRoom(room)))
            .unwrap();
    }
    worker.shared.queue.lock().unwrap().pending = 8;
    drop(sender);
    drop(local_sender);
    // The missing live session makes the due refresh fail explicitly. The queued
    // offline selections still run; an empty-queue-only timer would never run here.
    worker.run(receiver, local_receiver);
    assert!(worker.poll > due);
    assert_eq!(worker.snapshot.completions.len(), 8);
    assert!(
        worker
            .snapshot
            .completions
            .iter()
            .all(|c| c.error.is_none())
    );
    assert!(worker.snapshot.status.is_some());
}

#[test]
fn targeted_and_selection_work_do_not_postpone_due_metadata() {
    let (_fixture, mut worker, room) = worker();
    let due = Instant::now() - Duration::from_secs(6);
    worker.poll = due;
    worker.select(room).unwrap();
    assert_eq!(worker.poll, due);
    assert!(worker.metadata_due());
    assert!(worker.refresh_after_send(room).is_err());
    assert_eq!(worker.poll, due);
    assert!(worker.metadata_due());
}

#[test]
fn a_nonretryable_cache_failure_does_not_leave_the_full_refresh_immediately_due() {
    let (_fixture, mut worker, _) = worker();
    worker.desired = false;
    worker.poll = Instant::now() - Duration::from_secs(6);
    worker
        .client
        .store
        .write(|db| {
            db.execute("DELETE FROM client_clock", [])?;
            Ok(crate::storage::Commit::new(
                (),
                b"missing-cache-clock".to_vec(),
            ))
        })
        .unwrap();
    let started = Instant::now();
    assert!(matches!(worker.refresh(), Err(Error::Storage)));
    assert!(worker.poll >= started);
    assert!(!worker.metadata_due());
    assert!(worker.snapshot.inspection.stale);
    let published = worker.snapshot.revision;
    worker.tick();
    assert_eq!(worker.snapshot.revision, published);
}

fn current_room() -> conversations::Inspection {
    conversations::Inspection {
        members: vec![],
        read_sequence: 0,
        room_revision: 1,
        filter_revision: 1,
        moderator: false,
        confidentiality: RoomConfidentiality::Community,
    }
}

#[test]
fn room_retry_recovery_keeps_unrelated_metadata_and_transport_observations() {
    let (fixture, mut worker, room) = worker();
    let (_companion, stream) = session_reuse::retained_handle(&fixture.root);
    let page = cached_community(&mut worker, room);
    worker.snapshot.privacy = Some(stream.privacy());
    let privacy = serde_json::to_value(&worker.snapshot.privacy).unwrap();
    for operation in [
        Operation::RoomInspect,
        Operation::EventsResume,
        Operation::ModerationRestrictions,
    ] {
        for metadata_stale in [false, true] {
            worker.snapshot.inspection.stale = metadata_stale;
            worker.snapshot.selected.as_mut().unwrap().stale = false;
            let end = crate::clock::boot_ms().unwrap() + 2000;
            let mut attempts = 0;
            worker
                .update_view(|worker| {
                    let response = retry_read(
                        end,
                        || false,
                        |passed| {
                            assert_eq!(passed, end);
                            attempts += 1;
                            if attempts == 2 {
                                let visible = worker.shared.snapshot.lock().unwrap();
                                assert!(
                                    visible.updating && visible.selected.as_ref().unwrap().stale
                                );
                                assert_eq!(visible.inspection.stale, metadata_stale);
                                assert_eq!(
                                    serde_json::to_value(&visible.privacy).unwrap(),
                                    privacy
                                );
                            }
                            let response = if attempts == 1 {
                                temporary_read()
                            } else {
                                read_result(Outcome::Result { body: Value::Null })
                            };
                            worker.observe_read(operation, &Target::Room(room), &response);
                            Ok(response)
                        },
                    )?;
                    assert!(matches!(response.outcome, Outcome::Result { .. }));
                    // An individual successful attempt is insufficient; installation follows
                    // the completed room read group, using a verified cached history page.
                    assert!(worker.snapshot.selected.as_ref().unwrap().stale);
                    worker.present_room_page(room, current_room(), page.clone())
                })
                .unwrap();
            assert_eq!(attempts, 2);
            assert!(!worker.snapshot.selected.as_ref().unwrap().stale);
            assert_eq!(worker.snapshot.inspection.stale, metadata_stale);
            assert_eq!(
                serde_json::to_value(&worker.snapshot.privacy).unwrap(),
                privacy
            );
        }
    }
}

#[test]
fn room_refusal_scope_requires_the_whitelisted_operation_and_matching_target() {
    let (_fixture, mut worker, room) = worker();
    let other = RoomId {
        local: Id::from_bytes([90; 32]),
        ..room
    };
    worker.observe_read(
        Operation::RoomInspect,
        &Target::Room(other),
        &temporary_read(),
    );
    assert!(!worker.snapshot.selected.as_ref().unwrap().stale);
    assert!(!worker.snapshot.inspection.stale);
    for (operation, target) in [
        (
            Operation::ModerationFilters,
            Target::Account(worker.snapshot.account),
        ),
        (Operation::AgentList, Target::Room(room)),
        (Operation::HistoryContext, Target::Room(room)),
        (Operation::SearchQuery, Target::Room(room)),
        (Operation::RoomInspect, Target::Service),
    ] {
        worker.snapshot.selected.as_mut().unwrap().stale = false;
        worker.snapshot.inspection.stale = false;
        worker.observe_read(operation, &target, &temporary_read());
        assert!(worker.snapshot.inspection.stale);
        assert!(worker.snapshot.selected.as_ref().unwrap().stale);
        assert!(worker.snapshot.privacy.is_none());
    }
}

#[test]
fn exhausted_room_refusal_still_invalidates_the_complete_failed_view() {
    let (fixture, mut worker, room) = worker();
    let (_companion, stream) = session_reuse::retained_handle(&fixture.root);
    worker.snapshot.privacy = Some(stream.privacy());
    let mut attempts = 0;
    let result: Result<()> = worker.update_view(|worker| {
        let response = retry_read(
            crate::clock::boot_ms().unwrap() + 2000,
            || false,
            |_| {
                attempts += 1;
                let response = temporary_read();
                worker.observe_read(Operation::RoomInspect, &Target::Room(room), &response);
                Ok(response)
            },
        )?;
        Err(Error::from_outcome(response.outcome))
    });
    assert!(matches!(result, Err(Error::Refused { .. })));
    assert_eq!(attempts, 5);
    let visible = worker.shared.snapshot.lock().unwrap();
    assert!(!visible.updating && visible.inspection.stale);
    assert!(visible.selected.as_ref().unwrap().stale && visible.privacy.is_none());
}

#[test]
fn restriction_refusal_and_room_changes_keep_restrictions_bound_to_the_selection() {
    let (_fixture, mut worker, room) = worker();
    worker
        .snapshot
        .inspection
        .restrictions
        .push(moderation::RestrictionState {
            subject: worker.snapshot.account,
            kind: 1,
            expires_ms: 9999,
            moderator: worker.snapshot.account,
        });
    worker.observe_read(
        Operation::ModerationRestrictions,
        &Target::Room(room),
        &temporary_read(),
    );
    assert!(!worker.snapshot.inspection.stale);
    assert!(worker.snapshot.selected.as_ref().unwrap().stale);
    assert_eq!(worker.snapshot.inspection.restrictions.len(), 1);
    let mut other = worker.snapshot.rooms[0].clone();
    other.room.local = Id::from_bytes([91; 32]);
    worker.snapshot.rooms.push(other.clone());
    worker.select(other.room).unwrap();
    assert!(worker.snapshot.inspection.restrictions.is_empty());
    assert_eq!(
        worker.snapshot.selected.as_ref().unwrap().summary.room,
        other.room
    );
    assert!(worker.snapshot.selected.as_ref().unwrap().stale);
}

#[test]
fn a_current_page_install_cannot_hide_an_existing_history_gap() {
    let (_fixture, mut worker, room) = worker();
    let page = cached_community(&mut worker, room);
    let view = worker.snapshot.selected.as_mut().unwrap();
    view.gap = Some("CursorHistoryGap".into());
    view.stale = true;
    worker
        .present_room_page(room, current_room(), page)
        .unwrap();
    let view = worker.snapshot.selected.as_ref().unwrap();
    assert!(view.stale);
    assert_eq!(view.gap.as_deref(), Some("CursorHistoryGap"));
}

fn coalescing_worker() -> (Fixture, Worker, RoomId) {
    let (fixture, mut worker, room) = worker();
    worker
        .client
        .install_closed_view_test_session(&fixture.root);
    worker.shared.stop.store(false, Ordering::Release);
    worker.shared.disconnect.store(false, Ordering::Release);
    (fixture, worker, room)
}
fn queued_send(room: RoomId) -> Command {
    Command::Send {
        room,
        text: "next".into(),
        mentions: vec![],
        parent: None,
        causation: None,
        action: false,
        grant: None,
    }
}
fn retain_committed_send(worker: &mut Worker, room: RoomId, n: u8) -> Action {
    let mut action = action();
    action.operation_id.operation = Id::from_bytes([n; 32]);
    let message: messaging::Send = action.body.deserialized().unwrap();
    worker
        .preserve_send_draft(room, &message.text, &message.mentions)
        .unwrap();
    let key = crate::service::files::key(
        &worker
            .client
            .profile
            .companion
            .parent()
            .unwrap()
            .join("Endpoint.key"),
    )
    .unwrap();
    let exact = verify_action(&sign_action(&action, &key).unwrap(), &key.verifying_key()).unwrap();
    // This is the same exact durable draft binding used by Controller preparation.
    worker
        .client
        .store
        .write(|tx| {
            super::super::super::outbox::prepare_transaction(
                tx,
                &exact,
                &RetryWindow {
                    id: action.operation_id.window,
                    expires_ms: TimeBounds::test_now().upper_ms + 60000,
                },
                TimeBounds::test_now(),
            )?;
            super::super::super::outbox::bind_draft_transaction(tx, &action, &message)?;
            Ok(crate::storage::Commit::new(
                (),
                b"exact deferred-view send".to_vec(),
            ))
        })
        .unwrap();
    outcome(
        worker,
        &action,
        Outcome::Committed {
            event: Some(Id::from_bytes([n.wrapping_add(1); 32])),
            position: u64::from(n),
            body: Value::Null,
        },
    )
    .unwrap();
    worker.clear_matching_draft(&action).unwrap();
    worker.refresh_sent_room(room, true);
    action
}

#[test]
fn deferred_room_refresh_keeps_durable_delivery_and_draft_completion_immediate() {
    let (_fixture, mut worker, room) = coalescing_worker();
    let action = retain_committed_send(&mut worker, room, 101);
    worker.complete(77, Ok(()));
    worker.request = None;
    let visible = worker.shared.snapshot.lock().unwrap().clone();
    assert!(visible.updating && !worker.snapshot.updating);
    assert!(!visible.selected.as_ref().unwrap().stale);
    assert!(!visible.inspection.stale && !visible.inspection.filters_stale);
    assert_eq!(
        visible.deliveries.last().unwrap().operation_id,
        action.operation_id
    );
    assert!(matches!(
        visible.deliveries.last().unwrap().outcome,
        Some(Outcome::Committed { .. })
    ));
    assert!(visible.completions.last().unwrap().error.is_none());
    assert!(worker.client.pending().unwrap().is_empty());
    assert!(worker.client.draft(room).unwrap().is_none());
    assert!(
        visible.selected.as_ref().unwrap().events.is_empty(),
        "the acknowledgement must not invent a history event"
    );

    // A real deferred read fails against the closed fixture peer/missing clock.
    // It cannot rewrite the completed send or recreate its durable outbox entry.
    worker.flush_pending_room();
    let visible = worker.shared.snapshot.lock().unwrap().clone();
    assert!(!visible.updating && worker.pending_room.is_none());
    assert!(visible.selected.as_ref().unwrap().stale);
    assert_eq!(visible.status.as_ref().unwrap().code, "ViewRefreshFailed");
    assert_eq!(visible.status.as_ref().unwrap().request_id, None);
    assert!(visible.completions.last().unwrap().error.is_none());
    assert!(matches!(
        visible.deliveries.last().unwrap().outcome,
        Some(Outcome::Committed { .. })
    ));
    assert!(worker.client.pending().unwrap().is_empty());
    assert!(worker.client.draft(room).unwrap().is_none());
}

#[test]
fn a_send_burst_keeps_the_first_deadline_and_stops_after_two_commits() {
    let (_fixture, mut worker, room) = coalescing_worker();
    retain_committed_send(&mut worker, room, 103);
    let oldest = worker.pending_room.as_ref().unwrap().oldest;
    assert!(!worker.pending_room_due(oldest + Duration::from_millis(999)));
    assert!(worker.pending_room_due(oldest + Duration::from_secs(1)));
    assert!(worker.pending_room_allows(&queued_send(room)));
    retain_committed_send(&mut worker, room, 105);
    assert_eq!(worker.pending_room.as_ref().unwrap().oldest, oldest);
    assert!(worker.pending_room_due(Instant::now()));
    assert_eq!(worker.client.pending().unwrap().len(), 0);
    assert_eq!(worker.snapshot.deliveries.len(), 2);
    let end = worker.poll;
    worker.flush_pending_room();
    assert!(worker.pending_room.is_none());
    assert_eq!(
        worker.poll, end,
        "a targeted flush must not postpone metadata"
    );
    assert_eq!(worker.snapshot.deliveries.len(), 2);
    assert!(worker.client.pending().unwrap().is_empty());
}

#[test]
fn pending_progress_is_separate_from_nested_read_progress_and_stale_authority() {
    let (_fixture, mut worker, room) = coalescing_worker();
    worker.stale();
    worker.refresh_sent_room(room, true);
    worker
        .update_view(|worker| {
            worker.update_view(|_| Ok(()))?;
            assert!(worker.snapshot.updating);
            Ok(())
        })
        .unwrap();
    assert!(!worker.snapshot.updating);
    let visible = worker.shared.snapshot.lock().unwrap();
    assert!(visible.updating);
    assert!(visible.selected.as_ref().unwrap().stale && visible.inspection.stale);
}

#[test]
fn incompatible_contexts_and_lost_capability_cannot_join_a_pending_burst() {
    let (_fixture, mut worker, room) = coalescing_worker();
    worker.refresh_sent_room(room, true);
    let other = RoomId {
        local: Id::from_bytes([111; 32]),
        ..room
    };
    for command in [
        queued_send(other),
        Command::SelectRoom(room),
        Command::LoadMore,
        Command::Refresh,
        Command::MarkRead { room, sequence: 1 },
        Command::Resynchronise,
        Command::SetTopic {
            room,
            topic: "new".into(),
        },
    ] {
        assert!(!worker.pending_room_allows(&command));
    }
    worker.snapshot.selected.as_mut().unwrap().gap = Some("CursorHistoryGap".into());
    assert!(!worker.pending_room_allows(&queued_send(room)));
    worker.snapshot.selected.as_mut().unwrap().gap = None;
    worker.snapshot.selected.as_mut().unwrap().focus = Some(Id::from_bytes([112; 32]));
    assert!(!worker.pending_room_allows(&queued_send(room)));
    worker.snapshot.selected.as_mut().unwrap().focus = None;
    worker.client.disconnect();
    assert!(!worker.pending_room_allows(&queued_send(room)));
    worker.offline();
    assert!(worker.pending_room.is_none());
    assert!(!worker.shared.snapshot.lock().unwrap().updating);
    assert!(worker.snapshot.selected.as_ref().unwrap().stale);
}

#[test]
fn pending_room_work_preserves_due_metadata_turns_and_existing_cache_maintenance() {
    let (_fixture, mut worker, room) = coalescing_worker();
    worker.refresh_sent_room(room, true);
    let oldest = worker.pending_room.as_ref().unwrap().oldest;
    worker.poll = Instant::now() - Duration::from_secs(6);
    let poll = worker.poll;
    // The ordinary first finite metadata turn performs local retention and starts
    // its assembly even though one compatible send is awaiting its room view.
    worker.tick();
    assert!(worker.refresh_cycle.is_some());
    assert!(worker.metadata_due());
    assert_eq!(worker.poll, poll);
    assert_eq!(worker.pending_room.as_ref().unwrap().oldest, oldest);
    assert!(worker.shared.snapshot.lock().unwrap().updating);
    // A failed scope still clears the pending context, never its committed effects.
    worker.error(Error::Input);
    assert!(worker.pending_room.is_none());
    assert!(worker.snapshot.selected.as_ref().unwrap().stale);
}

#[test]
fn worker_drains_a_full_or_aged_burst_before_starting_another_queued_send() {
    for aged in [false, true] {
        let (_fixture, mut worker, room) = coalescing_worker();
        retain_committed_send(&mut worker, room, 114);
        if aged {
            worker.pending_room.as_mut().unwrap().oldest = Instant::now() - Duration::from_secs(1);
        } else {
            retain_committed_send(&mut worker, room, 116);
        }
        worker.request = None;
        // Deliberately offline intent permits the next command's explicit Offline
        // result after the deferred read closes this failed fixture session.
        worker.desired = false;
        let committed = worker.snapshot.deliveries.len();
        let (sender, receiver) = mpsc::sync_channel(32);
        let (local_sender, local_receiver) = mpsc::sync_channel(32);
        sender.send(Queued::new(88, queued_send(room))).unwrap();
        worker.shared.queue.lock().unwrap().pending = 1;
        drop(sender);
        drop(local_sender);
        worker.run(receiver, local_receiver);
        let completion = worker
            .snapshot
            .completions
            .iter()
            .find(|c| c.request_id == 88)
            .unwrap();
        assert_eq!(completion.error.as_ref().unwrap().code, "Offline");
        assert_eq!(worker.snapshot.deliveries.len(), committed);
        assert!(
            worker
                .snapshot
                .deliveries
                .iter()
                .all(|d| matches!(d.outcome, Some(Outcome::Committed { .. })))
        );
        assert!(worker.client.pending().unwrap().is_empty());
        assert_eq!(worker.client.draft(room).unwrap().as_deref(), Some("next"));
        assert!(worker.pending_room.is_none());
    }
}

#[test]
fn idle_worker_flushes_one_committed_send_without_waiting_for_another_command() {
    let (_fixture, mut worker, room) = coalescing_worker();
    retain_committed_send(&mut worker, room, 118);
    worker.complete(77, Ok(()));
    worker.request = None;
    worker.desired = false;
    let shared = Arc::clone(&worker.shared);
    let (sender, receiver) = mpsc::sync_channel(32);
    let (local_sender, local_receiver) = mpsc::sync_channel(32);
    let flushed = thread::scope(|scope| {
        let current = &mut worker;
        let task = scope.spawn(move || current.run(receiver, local_receiver));
        let until = Instant::now() + Duration::from_secs(2);
        let flushed = loop {
            if shared
                .snapshot
                .lock()
                .unwrap()
                .status
                .as_ref()
                .is_some_and(|s| s.code == "ViewRefreshFailed")
            {
                break true;
            }
            if Instant::now() >= until {
                break false;
            }
            thread::yield_now();
        };
        shared.stop.store(true, Ordering::Release);
        drop(sender);
        drop(local_sender);
        task.join().unwrap();
        flushed
    });
    assert!(flushed);
    assert!(worker.pending_room.is_none());
    assert!(worker.snapshot.completions.last().unwrap().error.is_none());
    assert!(worker.client.pending().unwrap().is_empty());
    assert!(matches!(
        worker.snapshot.deliveries.last().unwrap().outcome,
        Some(Outcome::Committed { .. })
    ));
}

#[test]
fn worker_finishes_pending_room_work_before_changing_selection() {
    let (_fixture, mut worker, room) = coalescing_worker();
    retain_committed_send(&mut worker, room, 120);
    worker.complete(77, Ok(()));
    worker.request = None;
    worker.desired = false;
    let mut other = worker.snapshot.rooms[0].clone();
    other.room.local = Id::from_bytes([122; 32]);
    worker.snapshot.rooms.push(other.clone());
    let (sender, receiver) = mpsc::sync_channel(32);
    let (local_sender, local_receiver) = mpsc::sync_channel(32);
    sender
        .send(Queued::new(89, Command::SelectRoom(other.room)))
        .unwrap();
    worker.shared.queue.lock().unwrap().pending = 1;
    drop(sender);
    drop(local_sender);
    worker.run(receiver, local_receiver);
    // The old room's failed pull closed the fixture session before selection.
    // Selection can therefore complete from cache instead of attributing that
    // prior view failure to this new command or issuing a new room effect.
    assert!(
        worker
            .snapshot
            .completions
            .iter()
            .find(|c| c.request_id == 89)
            .unwrap()
            .error
            .is_none()
    );
    assert_eq!(
        worker.snapshot.selected.as_ref().unwrap().summary.room,
        other.room
    );
    assert!(worker.snapshot.selected.as_ref().unwrap().stale);
    assert!(worker.pending_room.is_none());
    assert!(worker.client.pending().unwrap().is_empty());
    assert_eq!(worker.snapshot.deliveries.len(), 1);
    assert!(
        worker
            .snapshot
            .completions
            .iter()
            .find(|c| c.request_id == 77)
            .unwrap()
            .error
            .is_none()
    );
}

#[test]
fn ineligible_send_paths_keep_their_synchronous_view_failure() {
    for case in 0..5 {
        let (_fixture, mut worker, room) = coalescing_worker();
        match case {
            0 => worker.snapshot.selected.as_mut().unwrap().gap = Some("CursorHistoryGap".into()),
            1 => worker.snapshot.selected.as_mut().unwrap().focus = Some(Id::from_bytes([123; 32])),
            2 => worker.snapshot.rooms[0].confidentiality = RoomConfidentiality::PrivateGroup,
            3 => worker.client.disconnect(),
            _ => {}
        }
        worker.refresh_sent_room(room, case != 4);
        assert!(worker.pending_room.is_none());
        assert_eq!(
            worker.snapshot.status.as_ref().unwrap().code,
            "ViewRefreshFailed"
        );
        assert!(worker.snapshot.selected.as_ref().unwrap().stale);
        if case == 0 {
            assert_eq!(
                worker.snapshot.selected.as_ref().unwrap().gap.as_deref(),
                Some("CursorHistoryGap")
            );
        }
    }
}
