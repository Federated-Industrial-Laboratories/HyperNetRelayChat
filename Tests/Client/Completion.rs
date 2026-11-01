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
    cache::initialize(&mut store).unwrap();
    let a = action();
    let Target::Room(room) = a.target else {
        unreachable!()
    };
    cache::save_rooms(
        &mut store,
        &[conversations::Summary {
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
    super::super::outbox::record(&mut worker.client.store, &signed, &verified, now).unwrap();
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
