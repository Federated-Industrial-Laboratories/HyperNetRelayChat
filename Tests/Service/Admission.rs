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

fn queued(admission: &Admission, count: usize) {
    let end = Instant::now() + Duration::from_millis(750);
    let mut state = admission.state.lock().unwrap();
    while state.waiting.len() != count {
        let left = end.saturating_duration_since(Instant::now());
        assert!(!left.is_zero(), "callers did not reach bounded admission");
        state = admission.changed.wait_timeout(state, left).unwrap().0;
    }
}

#[test]
fn queued_checks_start_after_admission_and_control_is_not_overtaken() {
    let admission = Admission::default();
    let first = admission.acquire(None, || false).unwrap();
    let (events, received) = mpsc::channel();
    let (release, released) = mpsc::channel();
    thread::scope(|scope| {
        let gate = &admission;
        let control_events = events.clone();
        scope.spawn(move || {
            let control = gate.acquire(None, || false).unwrap();
            control_events
                .send(("control", control.check_deadline().unwrap()))
                .unwrap();
            released.recv_timeout(Duration::from_secs(1)).unwrap();
        });
        queued(&admission, 1);
        scope.spawn(|| {
            let next = admission.acquire(None, || false).unwrap();
            events
                .send(("next", next.check_deadline().unwrap()))
                .unwrap();
        });
        queued(&admission, 2);
        // Real queued time is not charged to the later authority check's lifetime.
        assert!(received.recv_timeout(Duration::from_millis(30)).is_err());
        drop(first);
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
    assert!(admission.acquire(None, || false).is_ok());
}

#[test]
fn stopped_waiter_releases_its_place_without_starting_a_check() {
    let admission = Admission::default();
    let first = admission.acquire(None, || false).unwrap();
    let stopped = AtomicBool::new(false);
    let (done, received) = mpsc::channel();
    thread::scope(|scope| {
        scope.spawn(|| {
            let result = admission.acquire(None, || stopped.load(Ordering::Acquire));
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
    assert!(admission.acquire(None, || false).is_ok());
}

#[test]
fn admission_is_bounded_and_preserves_the_original_enclosing_deadline() {
    let admission = Admission::default();
    let first = admission.acquire(None, || false).unwrap();
    let end = clock::boot_ms().unwrap() + 40;
    assert!(matches!(
        admission.acquire(Some(end), || false),
        Err(Error::Expired)
    ));
    assert!(admission.state.lock().unwrap().waiting.is_empty());
    let started = Instant::now();
    assert!(matches!(
        admission.acquire(None, || false),
        Err(Error::Busy)
    ));
    assert!(started.elapsed() < Duration::from_millis(1500));
    drop(first);
    let end = clock::boot_ms().unwrap() + 400;
    let permit = admission.acquire(Some(end), || false).unwrap();
    assert_eq!(permit.check_deadline().unwrap(), end);
    drop(permit);
    let permit = admission
        .acquire(Some(clock::boot_ms().unwrap() + 50), || false)
        .unwrap();
    assert_eq!(permit.check_deadline(), Err(Error::Expired));
}

#[test]
fn capacity_refuses_before_authority_work_and_shutdown_releases_waiters() {
    let admission = Arc::new(Admission::default());
    let first = admission.acquire(None, || false).unwrap();
    let stopped = Arc::new(AtomicBool::new(false));
    thread::scope(|scope| {
        let mut workers = Vec::new();
        for _ in 1..MAXIMUM_PENDING {
            let admission = admission.clone();
            let stopped = stopped.clone();
            workers.push(scope.spawn(move || {
                admission
                    .acquire(None, || stopped.load(Ordering::Acquire))
                    .err()
            }));
        }
        queued(&admission, MAXIMUM_PENDING - 1);
        assert!(matches!(
            admission.acquire(None, || false),
            Err(Error::Busy)
        ));
        stopped.store(true, Ordering::Release);
        for worker in workers {
            assert_eq!(worker.join().unwrap(), Some(Error::Stopped));
        }
    });
    assert!(admission.state.lock().unwrap().waiting.is_empty());
    drop(first);
    assert!(admission.acquire(None, || false).is_ok());
}

#[test]
fn unwind_releases_the_slot_and_poison_remains_fail_closed() {
    let admission = Admission::default();
    assert!(
        std::panic::catch_unwind(|| {
            let _permit = admission.acquire(None, || false).unwrap();
            panic!("simulate an interrupted check");
        })
        .is_err()
    );
    let permit = admission.acquire(None, || false).unwrap();
    assert!(
        std::panic::catch_unwind(|| {
            let _state = admission.state.lock().unwrap();
            panic!("simulate poisoned admission state");
        })
        .is_err()
    );
    drop(permit);
    let poisoned = admission.state.lock().err().unwrap().into_inner();
    assert!(poisoned.active.is_none());
    assert!(poisoned.waiting.is_empty());
    drop(poisoned);
    assert!(matches!(
        admission.acquire(None, || false),
        Err(Error::Unavailable)
    ));
}

#[test]
fn cancellation_at_admission_releases_the_reserved_slot() {
    let admission = Admission::default();
    let calls = std::sync::atomic::AtomicUsize::new(0);
    assert!(matches!(
        admission.acquire(None, || calls.fetch_add(1, Ordering::AcqRel) >= 2),
        Err(Error::Stopped)
    ));
    assert!(admission.acquire(None, || false).is_ok());
}
