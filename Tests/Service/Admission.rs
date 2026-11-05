// SPDX-License-Identifier: Apache-2.0
//! Exercise bounded authority admission, control fairness and cancellation cleanup.
use super::*;
use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc,
    },
    thread,
    time::Instant,
};

fn account(n: u8) -> AccountId {
    AccountId {
        origin: NetworkId {
            network: Id::from_bytes([1; 32]),
            incarnation: Id::from_bytes([2; 32]),
        },
        local: Id::from_bytes([n; 32]),
    }
}
fn request(n: u8) -> Request {
    Request::account(account(n), Class::Interactive)
}

fn queued(admission: &Admission, count: usize) {
    let end = Instant::now() + Duration::from_millis(750);
    let mut state = admission.state.lock().unwrap();
    while state.waiting.len() != count {
        let left = end.saturating_duration_since(Instant::now());
        assert!(!left.is_zero(), "callers did not reach bounded admission");
        state = admission.changed.wait_timeout(state, left).unwrap().0;
    }
}

fn fill(admission: &Admission) -> Vec<Permit<'_>> {
    (0..MAXIMUM_ACTIVE)
        .map(|n| {
            admission
                .acquire(
                    Request::account(
                        account(10 + n as u8),
                        if n < 2 {
                            Class::Read
                        } else {
                            Class::Interactive
                        },
                    ),
                    None,
                    || false,
                )
                .unwrap()
        })
        .collect()
}

#[test]
fn queued_checks_start_after_admission_and_control_is_not_overtaken() {
    let admission = Admission::default();
    let mut active = fill(&admission);
    let (events, received) = mpsc::channel();
    let (release, released) = mpsc::channel();
    thread::scope(|scope| {
        let gate = &admission;
        let control_events = events.clone();
        scope.spawn(move || {
            let control = gate.acquire(request(1), None, || false).unwrap();
            control_events
                .send(("control", control.check_deadline().unwrap()))
                .unwrap();
            released.recv_timeout(Duration::from_secs(1)).unwrap();
        });
        queued(&admission, 1);
        scope.spawn(|| {
            let next = admission.acquire(request(2), None, || false).unwrap();
            events
                .send(("next", next.check_deadline().unwrap()))
                .unwrap();
        });
        queued(&admission, 2);
        // Real queued time is not charged to the later authority check's lifetime.
        assert!(received.recv_timeout(Duration::from_millis(30)).is_err());
        drop(active.pop());
        let (name, end) = received.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(name, "control");
        assert!(end > clock::boot_ms().unwrap() + 1000);
        assert!(end <= clock::boot_ms().unwrap() + 5000);
        assert!(received.try_recv().is_err());
        release.send(()).unwrap();
        let (name, end) = received.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_eq!(name, "next");
        assert!(end > clock::boot_ms().unwrap() + 1000);
        assert!(end <= clock::boot_ms().unwrap() + 5000);
    });
    drop(active);
    assert!(admission.acquire(request(1), None, || false).is_ok());
}

#[test]
fn independent_exchanges_release_only_their_own_slot_out_of_order() {
    let admission = Admission::default();
    let mut active = fill(&admission);
    let original_end = active[0].check_deadline().unwrap();
    drop(active.remove(1));
    let replacement = admission
        .acquire(request(1), Some(original_end), || false)
        .unwrap();
    assert_eq!(replacement.check_deadline().unwrap(), original_end);
    assert!(matches!(
        admission.acquire(request(1), Some(clock::boot_ms().unwrap() + 25), || false),
        Err(Error::Expired)
    ));
    // Completing another exchange does not cancel the remaining observations
    // or grant more than one replacement admission.
    drop(active.pop());
    let next = admission.acquire(request(2), None, || false).unwrap();
    assert!(matches!(
        admission.acquire(request(1), Some(clock::boot_ms().unwrap() + 25), || false),
        Err(Error::Expired)
    ));
    drop(replacement);
    drop(active);
    drop(next);
    assert!(admission.state.lock().unwrap().active.is_empty());
    assert!(admission.state.lock().unwrap().waiting.is_empty());
}

#[test]
fn stopped_waiter_releases_its_place_without_starting_a_check() {
    let admission = Admission::default();
    let first = fill(&admission);
    let stopped = AtomicBool::new(false);
    let (done, received) = mpsc::channel();
    thread::scope(|scope| {
        scope.spawn(|| {
            let result = admission.acquire(request(1), None, || stopped.load(Ordering::Acquire));
            done.send(result.err()).unwrap();
        });
        queued(&admission, 1);
        stopped.store(true, Ordering::Release);
        assert_eq!(
            received.recv_timeout(Duration::from_secs(1)).unwrap(),
            Some(Error::Stopped)
        );
        queued(&admission, 0);
    });
    drop(first);
    assert!(admission.acquire(request(1), None, || false).is_ok());
}

#[test]
fn admission_is_bounded_and_preserves_the_original_enclosing_deadline() {
    let admission = Admission::default();
    let first = fill(&admission);
    let end = clock::boot_ms().unwrap() + 40;
    assert!(matches!(
        admission.acquire(request(1), Some(end), || false),
        Err(Error::Expired)
    ));
    assert!(admission.state.lock().unwrap().waiting.is_empty());
    let started = Instant::now();
    assert!(matches!(
        admission.acquire(request(1), None, || false),
        Err(Error::Busy)
    ));
    assert!(started.elapsed() < Duration::from_millis(1500));
    drop(first);
    let end = clock::boot_ms().unwrap() + 400;
    let permit = admission.acquire(request(1), Some(end), || false).unwrap();
    assert_eq!(permit.check_deadline().unwrap(), end);
    drop(permit);
    let permit = admission
        .acquire(request(1), Some(clock::boot_ms().unwrap() + 50), || false)
        .unwrap();
    assert_eq!(permit.check_deadline(), Err(Error::Expired));
}

#[test]
fn capacity_refuses_before_authority_work_and_shutdown_releases_waiters() {
    let admission = Arc::new(Admission::default());
    let first = fill(&admission);
    let stopped = Arc::new(AtomicBool::new(false));
    thread::scope(|scope| {
        let mut workers = Vec::new();
        for index in MAXIMUM_ACTIVE..MAXIMUM_PENDING {
            let admission = admission.clone();
            let stopped = stopped.clone();
            workers.push(scope.spawn(move || {
                admission
                    .acquire(
                        Request::account(
                            account(30 + index as u8),
                            if index % 2 == 0 {
                                Class::Read
                            } else {
                                Class::Interactive
                            },
                        ),
                        None,
                        || stopped.load(Ordering::Acquire),
                    )
                    .err()
            }));
        }
        queued(&admission, MAXIMUM_PENDING - MAXIMUM_ACTIVE);
        assert!(matches!(
            admission.acquire(request(1), None, || false),
            Err(Error::Busy)
        ));
        stopped.store(true, Ordering::Release);
        for worker in workers {
            assert_eq!(worker.join().unwrap(), Some(Error::Stopped));
        }
    });
    assert!(admission.state.lock().unwrap().waiting.is_empty());
    drop(first);
    assert!(admission.acquire(request(1), None, || false).is_ok());
}

#[test]
fn unwind_releases_the_slot_and_poison_remains_fail_closed() {
    let admission = Admission::default();
    assert!(
        std::panic::catch_unwind(|| {
            let _permit = admission.acquire(request(1), None, || false).unwrap();
            panic!("simulate an interrupted check");
        })
        .is_err()
    );
    let permit = admission.acquire(request(1), None, || false).unwrap();
    assert!(
        std::panic::catch_unwind(|| {
            let _state = admission.state.lock().unwrap();
            panic!("simulate poisoned admission state");
        })
        .is_err()
    );
    drop(permit);
    let poisoned = admission.state.lock().err().unwrap().into_inner();
    assert!(poisoned.active.is_empty());
    assert!(poisoned.waiting.is_empty());
    drop(poisoned);
    assert!(matches!(
        admission.acquire(request(1), None, || false),
        Err(Error::Unavailable)
    ));
}

#[test]
fn cancellation_at_admission_releases_the_reserved_slot() {
    let admission = Admission::default();
    let calls = std::sync::atomic::AtomicUsize::new(0);
    assert!(matches!(
        admission.acquire(request(1), None, || calls.fetch_add(1, Ordering::AcqRel)
            >= 2),
        Err(Error::Stopped)
    ));
    assert!(admission.acquire(request(1), None, || false).is_ok());
}

#[test]
fn either_class_retains_a_slot_while_the_other_has_waiters() {
    for busy_class in [Class::Read, Class::Interactive] {
        let admission = Admission::default();
        let mut held: Vec<_> = (0..MAXIMUM_CLASS_ACTIVE)
            .map(|n| {
                admission
                    .acquire(
                        Request::account(account(20 + n as u8), busy_class),
                        None,
                        || false,
                    )
                    .unwrap()
            })
            .collect();
        let (admitted, observed) = mpsc::channel();
        let (release, released) = mpsc::channel();
        thread::scope(|scope| {
            let gate = &admission;
            let blocked = scope.spawn(move || {
                let permit = gate
                    .acquire(Request::account(account(30), busy_class), None, || false)
                    .unwrap();
                admitted.send(()).unwrap();
                released.recv_timeout(Duration::from_secs(1)).unwrap();
                drop(permit);
            });
            queued(&admission, 1);
            let protected = admission
                .acquire(
                    Request::account(account(40), busy_class.other()),
                    None,
                    || false,
                )
                .unwrap();
            assert_eq!(admission.state.lock().unwrap().active.len(), MAXIMUM_ACTIVE);
            assert_eq!(admission.state.lock().unwrap().waiting.len(), 1);
            assert!(observed.try_recv().is_err());
            drop(held.pop());
            observed.recv_timeout(Duration::from_secs(1)).unwrap();
            assert_eq!(admission.state.lock().unwrap().active.len(), MAXIMUM_ACTIVE);
            release.send(()).unwrap();
            blocked.join().unwrap();
            drop(protected);
        });
        drop(held);
        assert!(admission.state.lock().unwrap().turns.is_empty());
    }
}

#[test]
fn subject_turns_and_verified_owners_bound_flooding_without_hiding_reads() {
    let mut state = State::default();
    let a = state.enqueue(request(1)).unwrap();
    state.admit(a);
    let a2 = state.enqueue(request(1)).unwrap();
    let a3 = state.enqueue(request(1)).unwrap();
    let b = state.enqueue(request(2)).unwrap();
    assert_eq!(
        state.selected(),
        Some(b),
        "another account does not wait behind an active flooder"
    );
    state.admit(b);
    state.remove(a);
    assert_eq!(state.selected(), Some(a2));
    state.admit(a2);
    let b2 = state.enqueue(request(2)).unwrap();
    state.remove(b);
    state.remove(a2);
    assert_eq!(
        state.selected(),
        Some(b2),
        "a served account rotates behind an existing peer"
    );
    state.admit(b2);
    assert_eq!(state.selected(), Some(a3));

    let mut state = State::default();
    let owner = account(9);
    let delegated = |n| Request {
        owner: Some(owner),
        ..request(n)
    };
    let active = state.enqueue(delegated(1)).unwrap();
    state.admit(active);
    let next = state.enqueue(delegated(2)).unwrap();
    state.enqueue(Request::account(owner, Class::Read)).unwrap();
    state.enqueue(delegated(3)).unwrap();
    assert_eq!(state.enqueue(delegated(4)), Err(Error::Busy));
    assert_eq!(
        state.selected(),
        None,
        "delegated agents and their owner share one active turn"
    );
    let independent = state.enqueue(request(7)).unwrap();
    assert_eq!(state.selected(), Some(independent));
    state.admit(independent);
    state.remove(active);
    assert_eq!(state.selected(), Some(next));
}

#[test]
fn class_and_subject_queue_bounds_leave_other_work_admissible() {
    let mut state = State::default();
    for n in 0..MAXIMUM_CLASS_PENDING {
        state
            .enqueue(Request::account(
                account(20 + (n / MAXIMUM_SUBJECT_PENDING) as u8),
                Class::Read,
            ))
            .unwrap();
    }
    assert_eq!(
        state.enqueue(Request::account(account(99), Class::Read)),
        Err(Error::Busy)
    );
    for n in 0..(MAXIMUM_PENDING - MAXIMUM_CLASS_PENDING) {
        state.enqueue(request(40 + n as u8)).unwrap();
    }
    assert_eq!(state.waiting.len(), MAXIMUM_PENDING);
    assert_eq!(state.enqueue(request(100)), Err(Error::Busy));
    let mut state = State::default();
    for _ in 0..MAXIMUM_SUBJECT_PENDING {
        state.enqueue(request(1)).unwrap();
    }
    assert_eq!(
        state.enqueue(Request::account(account(1), Class::Read)),
        Err(Error::Busy)
    );
    assert!(state.enqueue(request(2)).is_ok());
}

#[test]
fn request_class_is_owned_by_operation_semantics() {
    for operation in [
        Operation::CommunitySync,
        Operation::ClientMetadata,
        Operation::HistoryPage,
        Operation::SearchQuery,
    ] {
        assert_eq!(Class::operation(operation), Class::Read);
    }
    for operation in [
        Operation::MessageSend,
        Operation::ModerationSilence,
        Operation::SearchCancel,
        Operation::OperationResolve,
    ] {
        assert_eq!(Class::operation(operation), Class::Interactive);
    }
}

#[test]
fn signed_claim_cannot_change_the_authenticated_admission_account() {
    use crate::protocol::{
        AccountClass, Action, Actor, EndpointActor, OperationId, ServiceId, SigningKey, Target,
        Value, sign_action, verify_action,
    };
    let key = SigningKey::from_bytes(&[50; 32]);
    let acting = EndpointActor {
        account: account(1),
        endpoint: Id::from_bytes([3; 32]),
        security_generation: 1,
        enrolment_generation: 1,
        binding_digest: Id::from_bytes([4; 32]),
    };
    let record = home::EndpointRecord {
        acting: acting.clone(),
        classification: AccountClass::Human,
        key: key.verifying_key(),
        principal: Id::from_bytes([5; 32]),
        revision: 1,
    };
    let session =
        AuthenticatedSession::new(&record, record.principal, Id::from_bytes([6; 32]), 1).unwrap();
    let mut action = Action {
        home: ServiceId {
            network: account(1).origin,
            service: Id::from_bytes([7; 32]),
        },
        operation_id: OperationId {
            window: Id::from_bytes([8; 32]),
            operation: Id::from_bytes([9; 32]),
        },
        actor: Actor::Direct { acting },
        target: Target::Service,
        operation: Operation::MessageSend,
        body: Value::serialized(&()).unwrap(),
        expected: Default::default(),
        approval: None,
        agreement: None,
    };
    let verify = |action: &Action| {
        verify_action(&sign_action(action, &key).unwrap(), &key.verifying_key()).unwrap()
    };
    let current = Request::action(&session, &verify(&action), None);
    assert_eq!(current.class, Class::Interactive);
    assert_eq!(current.acting, Principal::Account(account(1)));
    if let Actor::Direct { acting } = &mut action.actor {
        acting.account = account(2);
    }
    let claimed = Request::action(&session, &verify(&action), Some(account(2)));
    assert_eq!(claimed.class, Class::Read);
    assert_eq!(claimed.acting, Principal::Account(account(1)));
    assert_eq!(claimed.owner, None);
    assert!(!claimed.uses(Principal::Account(account(2))));
}
