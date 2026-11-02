// SPDX-License-Identifier: Apache-2.0
//! Keep durable effect outcomes separate from subsequent view and connection failures.
use super::*;
use crate::{
    client::tests::{Fixture, action},
    clock::TimeBounds,
};

fn worker() -> (Fixture, Worker, RoomId) {
    let fixture = Fixture::new();
    let mut store = fixture.create();
    cache::initialize(&mut store, action().home).unwrap();
    let a = action();
    let Target::Room(room) = a.target else {
        unreachable!()
    };
    cache::save_rooms(
        &mut store,
        room.home,
        &[conversations::Summary {
            confidentiality: RoomConfidentiality::Community,
            invited: false,
            room,
            name: "completion".into(),
            topic: String::new(),
            revision: 1,
            sequence: 0,
            joined: true,
            unread: 0,
        }],
    )
    .unwrap();
    drop(store);
    fixture.profile();
    let mut controller = Controller::open(&fixture.root).unwrap();
    controller.shutdown();
    let mut worker = Worker {
        client: Client::open_offline(&fixture.root).unwrap(),
        snapshot: (*controller.snapshot()).clone(),
        shared: Arc::clone(&controller.shared),
        desired: true,
        attempt: 0,
        retry: Instant::now(),
        poll: Instant::now(),
        caught_up: Default::default(),
        notification: 0,
        request: Some(77),
        operation: None,
        delivery_room: None,
        poll_room: 0,
    };
    worker.select(room).unwrap();
    worker.snapshot.selected.as_mut().unwrap().stale = false;
    worker.snapshot.inspection.stale = false;
    worker.snapshot.connection = ConnectionState::Online;
    (fixture, worker, room)
}

fn outcome(worker: &mut Worker, action: &Action, outcome: Outcome) -> Result<Value> {
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
    let signed = verify_action(&sign_action(action, &key).unwrap(), &key.verifying_key()).unwrap();
    let now = TimeBounds::test_now();
    let window = RetryWindow {
        id: action.operation_id.window,
        expires_ms: now.upper_ms + 60000,
    };
    super::super::outbox::prepare(&mut worker.client.store, &signed, &window, now).unwrap();
    let response = Response {
        home: action.home,
        operation_id: action.operation_id,
        action_digest: signed.digest(),
        outcome,
    };
    let server = SigningKey::from_bytes(&[11; 32]);
    let verified = verify_response(
        &sign_response(&response, &server).unwrap(),
        &server.verifying_key(),
    )
    .unwrap();
    super::super::outbox::record(
        &mut worker.client.store,
        &signed,
        &verified,
        TimeBounds::test_now(),
    )
    .unwrap();
    worker.operation = Some(action.operation);
    worker.delivery_room = match action.target {
        Target::Room(room) => Some(room),
        _ => None,
    };
    worker.remember(action).unwrap();
    worker.response(response)
}

fn committed() -> Outcome {
    Outcome::Committed {
        event: None,
        position: 1,
        body: Value::serialized(&home::Empty {}).unwrap(),
    }
}
fn unavailable() -> Error {
    Error::Refused {
        code: ErrorCode::Unavailable,
        detail: "TransportAuthorityExpired".into(),
        retry_after_ms: Some(1000),
    }
}

#[test]
fn committed_send_generic_and_approval_completion_survive_failed_view_refresh() {
    for operation in [
        Operation::MessageSend,
        Operation::AccountSetNickname,
        Operation::ApprovalApprove,
    ] {
        let (_fixture, mut worker, room) = worker();
        let mut action = action();
        action.operation = operation;
        action.target = match operation {
            Operation::AccountSetNickname => Target::Account(worker.snapshot.account),
            Operation::ApprovalApprove => Target::Delegation(GrantRef {
                id: Id::from_bytes([19; 32]),
                generation: 1,
            }),
            _ => Target::Room(room),
        };
        action.body = match operation {
            Operation::AccountSetNickname => Value::serialized(&identity::Nickname {
                nickname: "Bób界".into(),
            })
            .unwrap(),
            Operation::ApprovalApprove => Value::serialized(&delegation::Decision {
                approval: Id::from_bytes([21; 32]),
                action_digest: Id::from_bytes([22; 32]),
            })
            .unwrap(),
            _ => action.body,
        };
        outcome(&mut worker, &action, committed()).unwrap();
        worker.clear_matching_draft(&action).unwrap();
        worker.finish_view(Err(unavailable()));
        worker.complete(77, Ok(()));
        let completion = worker.snapshot.completions.last().unwrap();
        assert_eq!(completion.request_id, 77);
        assert!(completion.error.is_none());
        let delivery = worker.snapshot.deliveries.last().unwrap();
        assert_eq!(delivery.request_id, Some(77));
        assert_eq!(delivery.operation, operation);
        assert_eq!(delivery.operation_id, action.operation_id);
        assert!(matches!(delivery.outcome, Some(Outcome::Committed { .. })));
        assert!(matches!(
            super::super::outbox::outcome(
                &mut worker.client.store,
                delivery.operation_id,
                delivery.action_digest
            )
            .unwrap(),
            Some(Outcome::Committed { .. })
        ));
        assert!(worker.client.pending().unwrap().is_empty());
        assert!(worker.snapshot.selected.as_ref().unwrap().stale);
        assert!(worker.snapshot.inspection.stale);
        assert!(worker.snapshot.privacy.is_none());
        assert!(matches!(
            worker.snapshot.connection,
            ConnectionState::Backoff { .. }
        ));
        let status = worker.snapshot.status.as_ref().unwrap();
        assert_eq!(status.request_id, None);
        assert_eq!(status.code, "ViewRefreshFailed");
        assert!(status.detail.contains("TransportAuthorityExpired"));
        assert_eq!(worker.request, Some(77));
    }
}

#[test]
fn failed_effect_or_required_local_write_still_fails_the_original_command() {
    let (_fixture, mut worker, _) = worker();
    let action = action();
    let refused = Outcome::Refused {
        code: ErrorCode::Denied,
        detail: "CurrentPermission".into(),
        retry_after_ms: None,
    };
    let result = outcome(&mut worker, &action, refused);
    worker.complete(77, result.map(|_| ()));
    assert!(worker.snapshot.completions.last().unwrap().error.is_some());
    assert!(matches!(
        worker.snapshot.deliveries.last().unwrap().outcome,
        Some(Outcome::Refused { .. })
    ));
    worker.request = Some(78);
    let mut next = action.clone();
    next.operation_id.operation = Id::from_bytes([23; 32]);
    outcome(&mut worker, &next, committed()).unwrap();
    worker.complete(78, Err(Error::Storage));
    assert_eq!(
        worker
            .snapshot
            .completions
            .last()
            .unwrap()
            .error
            .as_ref()
            .unwrap()
            .code,
        Error::Storage.code()
    );
    assert_ne!(
        worker.snapshot.status.as_ref().unwrap().code,
        "ViewRefreshFailed"
    );
    assert!(matches!(
        worker.snapshot.deliveries.last().unwrap().outcome,
        Some(Outcome::Committed { .. })
    ));
}

#[test]
fn later_effect_failure_does_not_turn_partial_compound_success_into_success() {
    let (_fixture, mut worker, _) = worker();
    let mut first = action();
    first.operation = Operation::ModerationIgnore;
    first.target = Target::Account(worker.snapshot.account);
    first.body = Value::serialized(&moderation::Filter {
        subject: worker.snapshot.account,
        enabled: true,
    })
    .unwrap();
    outcome(&mut worker, &first, committed()).unwrap();
    let mut second = first.clone();
    second.operation = Operation::ModerationMute;
    second.operation_id.operation = Id::from_bytes([20; 32]);
    let result = outcome(
        &mut worker,
        &second,
        Outcome::Refused {
            code: ErrorCode::Unavailable,
            detail: "TransportAuthorityExpired".into(),
            retry_after_ms: Some(1000),
        },
    );
    worker.complete(77, result.map(|_| ()));
    assert!(worker.snapshot.completions.last().unwrap().error.is_some());
    assert_eq!(worker.snapshot.deliveries.len(), 2);
    assert!(matches!(
        worker.snapshot.deliveries[0].outcome,
        Some(Outcome::Committed { .. })
    ));
    assert!(matches!(
        worker.snapshot.deliveries[1].outcome,
        Some(Outcome::Refused { .. })
    ));
    assert_ne!(
        worker.snapshot.status.as_ref().unwrap().code,
        "ViewRefreshFailed"
    );
}

#[test]
fn permanent_view_authentication_failure_keeps_commit_but_stops_reconnect() {
    let (_fixture, mut worker, _) = worker();
    outcome(&mut worker, &action(), committed()).unwrap();
    worker.finish_view(Err(Error::Network(
        crate::client::network::Error::Authentication,
    )));
    worker.complete(77, Ok(()));
    assert!(worker.snapshot.completions.last().unwrap().error.is_none());
    assert!(matches!(
        worker.snapshot.deliveries.last().unwrap().outcome,
        Some(Outcome::Committed { .. })
    ));
    assert_eq!(worker.snapshot.connection, ConnectionState::Offline);
    assert!(!worker.desired);
    assert_eq!(
        worker.snapshot.status.as_ref().unwrap().code,
        "ViewRefreshFailed"
    );
    assert!(
        worker
            .snapshot
            .status
            .as_ref()
            .unwrap()
            .detail
            .contains("SessionAuthenticationFailed")
    );
}

#[test]
fn queued_effect_uses_worker_readiness_and_original_deadline_not_published_online() {
    let (_fixture, mut worker, _) = worker();
    worker.publish();
    let queued = Queued::new(78, Command::SetNickname("Bób界".into()));
    worker.error(unavailable());
    assert_eq!(
        worker.shared.snapshot.lock().unwrap().connection,
        ConnectionState::Online
    );
    assert!(matches!(
        worker.snapshot.connection,
        ConnectionState::Backoff { .. }
    ));
    assert_eq!(
        queued.admission(worker.desired, false, Instant::now()),
        Admission::Wait
    );
    let retry = worker.retry;
    worker.tick();
    assert_eq!(worker.retry, retry);
    assert!(worker.client.pending().unwrap().is_empty());
    assert!(worker.snapshot.deliveries.is_empty());
    assert_eq!(queued.id, 78);
    assert!(matches!(&queued.command, Command::SetNickname(name) if name == "Bób界"));
    assert_eq!(
        queued.admission(true, true, queued.admission_end - Duration::from_millis(1)),
        Admission::Run
    );
    // A synchronous reconnect completing too late cannot start the held command.
    assert_eq!(
        queued.admission(true, true, queued.admission_end),
        Admission::Expired
    );
    worker.admission_expired(queued.id);
    let completion = worker.snapshot.completions.last().unwrap();
    assert_eq!(completion.request_id, queued.id);
    assert_eq!(
        completion.error.as_ref().unwrap().code,
        "CommandAdmissionExpired"
    );
    assert!(worker.snapshot.deliveries.is_empty());
    assert_eq!(worker.retry, retry);
}

#[test]
fn deliberate_offline_never_reconnects_or_prepares_a_queued_effect() {
    let (_fixture, mut worker, _) = worker();
    worker.offline();
    let queued = Queued::new(78, Command::SetNickname("Bób界".into()));
    assert_eq!(
        queued.admission(worker.desired, false, Instant::now()),
        Admission::Run
    );
    worker.run_command(queued);
    let completion = worker.snapshot.completions.last().unwrap();
    assert_eq!(completion.request_id, 78);
    assert_eq!(completion.error.as_ref().unwrap().code, "Offline");
    assert!(!worker.desired);
    assert!(worker.snapshot.deliveries.is_empty());
    assert!(worker.client.pending().unwrap().is_empty());
}

#[test]
fn idle_disconnect_publishes_offline_without_a_following_command() {
    let (_fixture, mut worker, room) = worker();
    worker.request = None;
    worker
        .command(Command::SaveDraft {
            room,
            text: "retained while disconnected".into(),
            mentions: vec![],
        })
        .unwrap();
    worker.publish();
    let before = Arc::clone(&worker.shared.snapshot.lock().unwrap());
    assert_eq!(before.connection, ConnectionState::Online);
    assert!(!before.inspection.stale);

    worker.offline();

    // No tick, completion or unrelated command may be needed to expose this.
    let visible = Arc::clone(&worker.shared.snapshot.lock().unwrap());
    assert_eq!(visible.connection, ConnectionState::Offline);
    assert!(visible.revision > before.revision);
    assert!(visible.inspection.stale && visible.privacy.is_none());
    let selected = visible.selected.as_ref().unwrap();
    assert!(selected.stale);
    assert_eq!(selected.draft, "retained while disconnected");
    assert!(!worker.desired);
    assert!(worker.client.session().is_err());
    assert_eq!(visible.completions.len(), before.completions.len());
}

#[test]
fn reserved_disconnect_releases_one_held_request_without_starting_it() {
    let (fixture, worker, room) = worker();
    drop(worker);
    let mut controller = Controller::open(&fixture.root).unwrap();
    let connect = controller.dispatch(Command::Connect).unwrap();
    let wait = |test: &dyn Fn(&Snapshot) -> bool| {
        let end = Instant::now() + Duration::from_secs(3);
        loop {
            let snapshot = controller.snapshot();
            if test(&snapshot) {
                return snapshot;
            }
            assert!(Instant::now() < end, "bounded command observation expired");
            thread::sleep(Duration::from_millis(5));
        }
    };
    wait(&|v| {
        v.completions.iter().any(|c| c.request_id == connect)
            && matches!(v.connection, ConnectionState::Backoff { .. })
    });
    let request = controller
        .dispatch(Command::SetNickname("Bób界".into()))
        .unwrap();
    let waiting = wait(&|v| {
        v.status.as_ref().is_some_and(|s| {
            s.request_id == Some(request) && s.code == "CommandWaitingForConnection"
        })
    });
    assert!(!waiting.completions.iter().any(|c| c.request_id == request));
    assert!(
        !waiting
            .deliveries
            .iter()
            .any(|d| d.request_id == Some(request))
    );
    let draft = controller
        .dispatch(Command::SaveDraft {
            room,
            text: "new typing while reconnect waits".into(),
            mentions: vec![],
        })
        .unwrap();
    let saved = wait(&|v| v.completions.iter().any(|c| c.request_id == draft));
    assert!(
        saved
            .completions
            .iter()
            .find(|c| c.request_id == draft)
            .unwrap()
            .error
            .is_none()
    );
    assert!(!saved.completions.iter().any(|c| c.request_id == request));
    // Both lanes share the original finite queue budget while one effect is held.
    for n in 0..32 {
        controller
            .dispatch(Command::SetNickname(format!("pending{n}")))
            .unwrap();
    }
    assert!(matches!(
        controller.dispatch(Command::SaveDraft {
            room,
            text: "not accepted".into(),
            mentions: vec![],
        }),
        Err(DispatchError::QueueFull)
    ));
    controller.disconnect();
    let stopped = wait(&|v| v.completions.iter().any(|c| c.request_id == request));
    assert_eq!(
        stopped
            .completions
            .iter()
            .find(|c| c.request_id == request)
            .unwrap()
            .error
            .as_ref()
            .unwrap()
            .code,
        "Offline"
    );
    assert!(
        !stopped
            .deliveries
            .iter()
            .any(|d| d.request_id == Some(request))
    );
    assert_eq!(stopped.connection, ConnectionState::Offline);
    controller.shutdown();
    let mut reopened = Client::open_offline(&fixture.root).unwrap();
    assert_eq!(
        reopened.draft(room).unwrap().as_deref(),
        Some("new typing while reconnect waits")
    );
}

#[test]
fn shutdown_persists_every_accepted_local_draft_and_closes_admission() {
    let (fixture, worker, room) = worker();
    drop(worker);
    let mut controller = Controller::open(&fixture.root).unwrap();
    let first = controller
        .dispatch(Command::SaveDraft {
            room,
            text: "older typing".into(),
            mentions: vec![],
        })
        .unwrap();
    let last = controller
        .dispatch(Command::SaveDraft {
            room,
            text: "latest typing".into(),
            mentions: vec![],
        })
        .unwrap();
    controller.shutdown();
    let snapshot = controller.snapshot();
    for id in [first, last] {
        assert!(
            snapshot
                .completions
                .iter()
                .any(|c| c.request_id == id && c.error.is_none())
        );
    }
    assert!(matches!(
        controller.dispatch(Command::SaveDraft {
            room,
            text: "too late".into(),
            mentions: vec![]
        }),
        Err(DispatchError::Stopped)
    ));
    let mut reopened = Client::open_offline(&fixture.root).unwrap();
    assert_eq!(
        reopened.draft(room).unwrap().as_deref(),
        Some("latest typing")
    );
    assert!(reopened.pending().unwrap().is_empty());
}

fn read_result(outcome: Outcome) -> Response {
    let action = action();
    Response {
        home: action.home,
        operation_id: action.operation_id,
        action_digest: action_digest(&action).unwrap(),
        outcome,
    }
}
fn temporary_read() -> Response {
    read_result(Outcome::Refused {
        code: ErrorCode::Unavailable,
        detail: "TransportAuthorityExpired".into(),
        retry_after_ms: Some(250),
    })
}
#[test]
fn temporary_read_keeps_its_original_deadline_without_restarting_completed_work() {
    let end = crate::clock::boot_ms().unwrap() + 5000;
    let mut calls = 0;
    let expected = action().operation_id;
    let response = retry_read(
        end,
        || false,
        |passed| {
            assert_eq!(passed, end);
            calls += 1;
            Ok(if calls == 1 {
                temporary_read()
            } else {
                read_result(Outcome::Result { body: Value::Null })
            })
        },
    )
    .unwrap();
    assert_eq!(calls, 2);
    assert_eq!(response.operation_id, expected);
    assert!(matches!(response.outcome, Outcome::Result { .. }));
}
#[test]
fn read_retry_respects_permanent_outcomes_and_transport_failures() {
    for outcome in [
        Outcome::Refused {
            code: ErrorCode::Denied,
            detail: "Denied".into(),
            retry_after_ms: Some(250),
        },
        Outcome::Refused {
            code: ErrorCode::Expired,
            detail: "Expired".into(),
            retry_after_ms: Some(250),
        },
        Outcome::Rejected {
            code: ErrorCode::Unavailable,
            detail: "DurableRejection".into(),
        },
    ] {
        let mut value = Some(outcome);
        retry_read(
            crate::clock::boot_ms().unwrap() + 5000,
            || false,
            |_| {
                Ok(read_result(
                    value.take().expect("permanent outcome retried"),
                ))
            },
        )
        .unwrap();
    }
    let mut calls = 0;
    let result = retry_read(
        crate::clock::boot_ms().unwrap() + 5000,
        || false,
        |_| {
            calls += 1;
            Err(Error::Network(
                crate::client::network::Error::Authentication,
            ))
        },
    );
    assert_eq!(calls, 1);
    assert!(matches!(
        result,
        Err(Error::Network(
            crate::client::network::Error::Authentication
        ))
    ));
}
#[test]
fn read_retry_has_a_finite_attempt_count_and_honours_interruption_and_retry_guidance() {
    let mut calls = 0;
    let response = retry_read(
        crate::clock::boot_ms().unwrap() + 5000,
        || false,
        |_| {
            calls += 1;
            Ok(temporary_read())
        },
    )
    .unwrap();
    assert_eq!(calls, 5);
    assert!(matches!(response.outcome, Outcome::Refused { .. }));
    let interrupted = std::cell::Cell::new(false);
    let result = retry_read(
        crate::clock::boot_ms().unwrap() + 5000,
        || interrupted.get(),
        |_| {
            interrupted.set(true);
            Ok(temporary_read())
        },
    );
    assert!(matches!(result, Err(Error::Offline)));
    calls = 0;
    let response = retry_read(
        crate::clock::boot_ms().unwrap() + 100,
        || false,
        |_| {
            calls += 1;
            Ok(temporary_read())
        },
    )
    .unwrap();
    assert_eq!(calls, 1);
    assert!(matches!(response.outcome, Outcome::Refused { .. }));
}
#[test]
fn a_read_result_after_the_original_deadline_is_not_reported_as_current() {
    let result = retry_read(
        crate::clock::boot_ms().unwrap() + 20,
        || false,
        |_| {
            thread::sleep(Duration::from_millis(30));
            Ok(read_result(Outcome::Result { body: Value::Null }))
        },
    );
    assert!(matches!(
        result,
        Err(Error::Network(crate::client::network::Error::Transport))
    ));
}

#[test]
fn current_read_api_refuses_a_mutation_before_preparation_or_outbox_write() {
    let (_fixture, mut worker, room) = worker();
    let result =
        worker.read::<Value, _>(Operation::MessageSend, Target::Room(room), &home::Empty {});
    assert!(matches!(result, Err(Error::Input)));
    assert!(worker.client.pending().unwrap().is_empty());
}
