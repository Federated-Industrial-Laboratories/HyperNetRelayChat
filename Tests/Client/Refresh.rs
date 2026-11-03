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
                    worker.observe_read(&response);
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
