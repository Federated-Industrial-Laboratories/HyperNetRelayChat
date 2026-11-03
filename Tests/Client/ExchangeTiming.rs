// SPDX-License-Identifier: Apache-2.0
//! Direct exchange timing never uses local work or a later outcome-resolution clock.
use super::super::*;

#[test]
fn exchange_interval_uses_only_write_and_complete_receipt_marks() {
    let action = crate::client::tests::action();
    let response = Response {
        home: action.home,
        operation_id: action.operation_id,
        action_digest: action_digest(&action).unwrap(),
        outcome: Outcome::Committed {
            event: Some(Id::from_bytes([90; 32])),
            position: 1,
            body: Value::Null,
        },
    };
    let queued = std::time::Instant::now();
    let written = queued + Duration::from_secs(27);
    let received = written + Duration::from_millis(7);
    let published = received + Duration::from_secs(5);
    assert_eq!(
        direct_exchange(&action, &response, written, received),
        Some(7_000_000)
    );
    assert!(published.duration_since(queued) > Duration::from_secs(30));
    assert_eq!(direct_exchange(&action, &response, received, written), None);
}
#[test]
fn refusal_bad_binding_and_resolution_cannot_supply_a_message_exchange() {
    let action = crate::client::tests::action();
    let base = Response {
        home: action.home,
        operation_id: action.operation_id,
        action_digest: action_digest(&action).unwrap(),
        outcome: Outcome::Committed {
            event: Some(Id::from_bytes([90; 32])),
            position: 1,
            body: Value::Null,
        },
    };
    let start = std::time::Instant::now();
    let end = start + Duration::from_millis(5);
    for outcome in [
        Outcome::Unknown,
        Outcome::Result { body: Value::Null },
        Outcome::Refused {
            code: ErrorCode::Unavailable,
            detail: "temporary".into(),
            retry_after_ms: None,
        },
        Outcome::Committed {
            event: None,
            position: 1,
            body: Value::Null,
        },
    ] {
        let response = Response {
            outcome,
            ..base.clone()
        };
        assert_eq!(direct_exchange(&action, &response, start, end), None);
    }
    let mut changed = base.clone();
    changed.action_digest = Id::from_bytes([91; 32]);
    assert_eq!(direct_exchange(&action, &changed, start, end), None);
    let mut resolution = action.clone();
    resolution.operation = Operation::OperationResolve;
    let response = Response {
        action_digest: action_digest(&resolution).unwrap(),
        ..base
    };
    assert_eq!(direct_exchange(&resolution, &response, start, end), None);
}
