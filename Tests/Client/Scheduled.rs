// SPDX-License-Identifier: Apache-2.0
//! Complete read refusals yield one stream to commands without renewing authority or deadlines.
use super::*;

fn busy(delay: u64) -> Outcome {
    Outcome::Refused {
        code: ErrorCode::Overloaded,
        detail: "ViewBusy".into(),
        retry_after_ms: Some(delay),
    }
}
fn denied() -> Outcome {
    Outcome::Rejected {
        code: ErrorCode::Denied,
        detail: "CurrentRoomAccessUnavailable".into(),
    }
}

#[test]
fn queued_send_finishes_between_a_refused_room_read_and_its_exact_retry() {
    let (fixture, mut worker, room, peer) = live_worker();
    let _clock = worker.client.start_view_test_clock(&fixture.root);
    worker
        .client
        .remember_community(room, RoomConfidentiality::Community)
        .unwrap();
    worker.request = None;
    worker.refresh_sent_room(room, true);
    worker.refresh_sent_room(room, true);
    let shared = Arc::clone(&worker.shared);
    let (times, observed) = mpsc::channel();
    let mut number = 0;
    let server = worker.client.view_test_responses(
        peer,
        vec![
            (Operation::CommunitySync, Some(busy(2000))),
            (
                Operation::MessageSend,
                Some(Outcome::Committed {
                    event: Some(Id::from_bytes([122; 32])),
                    position: 1,
                    body: Value::Null,
                }),
            ),
            (Operation::CommunitySync, Some(denied())),
        ],
        move |peer, frame| {
            times.send(Instant::now()).unwrap();
            peer.write_all(frame).unwrap();
            number += 1;
            if number == 3 {
                shared.stop.store(true, Ordering::Release);
            }
        },
    );
    let (sender, receiver) = mpsc::sync_channel(32);
    let (_local_sender, local_receiver) = mpsc::sync_channel(32);
    sender
        .send(Queued::new(
            88,
            Command::Send {
                room,
                text: "during the read retry wait".into(),
                mentions: vec![],
                parent: None,
                causation: None,
                action: false,
                grant: None,
            },
        ))
        .unwrap();
    worker.shared.queue.lock().unwrap().pending = 1;
    let (done, finish) = mpsc::channel::<()>();
    let shared = Arc::clone(&worker.shared);
    let guard = thread::spawn(move || {
        if finish.recv_timeout(Duration::from_secs(5)).is_err() {
            shared.stop.store(true, Ordering::Release);
        }
    });
    worker.run(receiver, local_receiver);
    let _ = done.send(());
    guard.join().unwrap();
    let frames = server.join().unwrap();
    let times: Vec<_> = observed.try_iter().collect();
    assert_eq!(frames.len(), 3);
    assert_eq!(
        frames[0], frames[2],
        "the scheduled retry must retain exact signed bytes"
    );
    assert!(times[1].duration_since(times[0]) < Duration::from_secs(2));
    assert!(times[2].duration_since(times[0]) >= Duration::from_secs(2));
    let completion = worker
        .snapshot
        .completions
        .iter()
        .find(|c| c.request_id == 88)
        .unwrap();
    assert!(completion.error.is_none());
    assert!(matches!(
        worker.snapshot.deliveries.last().unwrap().outcome,
        Some(Outcome::Committed { .. })
    ));
    assert!(worker.client.pending().unwrap().is_empty());
    assert!(worker.client.draft(room).unwrap().is_none());
    assert!(worker.snapshot.selected.as_ref().unwrap().stale);
}

#[test]
fn scheduled_read_wait_preserves_original_view_end_and_dispatches_no_late_retry() {
    let (fixture, mut worker, room, peer) = live_worker();
    let _clock = worker.client.start_view_test_clock(&fixture.root);
    let server = worker.client.view_test_responses(
        peer,
        vec![(Operation::CommunitySync, Some(busy(250)))],
        |peer, frame| peer.write_all(frame).unwrap(),
    );
    let mut state = CommunityAssembly::new(&mut worker, room).unwrap();
    state.end = crate::clock::boot_ms().unwrap() + 600;
    let end = state.end;
    assert!(!state.turn(&mut worker).unwrap());
    assert_eq!(state.rounds, 1);
    assert!(
        !state.turn(&mut worker).unwrap(),
        "retry guidance must defer dispatch"
    );
    assert_eq!(
        state.rounds, 1,
        "timer polls cannot consume pagination allowance"
    );
    after(end);
    assert!(matches!(
        state.turn(&mut worker),
        Err(Error::ReadDeadlineExpired)
    ));
    assert_eq!(state.end, end);
    assert_eq!(server.join().unwrap().len(), 1);
    assert!(worker.client.pending().unwrap().is_empty());
    assert!(worker.snapshot.notifications.is_empty());
    assert!(worker.snapshot.inspection.filters_stale);
}

#[test]
fn disconnect_cancels_a_scheduled_retry_before_another_frame() {
    let (fixture, mut worker, room, peer) = live_worker();
    let _clock = worker.client.start_view_test_clock(&fixture.root);
    let server = worker.client.view_test_responses(
        peer,
        vec![(Operation::CommunitySync, Some(busy(250)))],
        |peer, frame| peer.write_all(frame).unwrap(),
    );
    let mut state = CommunityAssembly::new(&mut worker, room).unwrap();
    assert!(!state.turn(&mut worker).unwrap());
    worker.shared.disconnect.store(true, Ordering::Release);
    assert!(matches!(state.turn(&mut worker), Err(Error::Offline)));
    assert_eq!(server.join().unwrap().len(), 1);
    assert!(worker.client.pending().unwrap().is_empty());
}

#[test]
fn metadata_retry_keeps_its_first_request_and_component_allowances() {
    let (fixture, mut worker, _, peer) = live_worker();
    let _clock = worker.client.start_view_test_clock(&fixture.root);
    let server = worker.client.view_test_responses(
        peer,
        vec![
            (Operation::ClientMetadata, Some(busy(250))),
            (
                Operation::ServiceInspect,
                Some(Outcome::Result { body: Value::Null }),
            ),
            (Operation::ClientMetadata, Some(denied())),
        ],
        |peer, frame| peer.write_all(frame).unwrap(),
    );
    let mut metadata = MetadataAssembly::new();
    let end = deadline().unwrap();
    assert!(
        !metadata
            .step(&mut worker, end, ReadMode::Scheduled)
            .unwrap()
    );
    let ready_after = crate::clock::boot_ms().unwrap() + 250;
    assert_eq!(metadata.components, [1; 4]);
    assert_eq!(metadata.rounds, 1);
    let _: Value = worker
        .read(Operation::ServiceInspect, Target::Service, &home::Empty {})
        .unwrap();
    after(ready_after);
    assert!(matches!(
        metadata.step(&mut worker, deadline().unwrap(), ReadMode::Scheduled),
        Err(Error::Rejected {
            code: ErrorCode::Denied,
            ..
        })
    ));
    assert_eq!(metadata.components, [1; 4]);
    assert_eq!(metadata.rounds, 1);
    let frames = server.join().unwrap();
    assert_eq!(frames.len(), 3);
    assert_eq!(frames[0], frames[2]);
    assert!(worker.client.pending().unwrap().is_empty());
}
