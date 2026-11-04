// SPDX-License-Identifier: Apache-2.0
//! Foreground forwarding and freshness work share one correlated gateway stream fairly.
use super::*;
use std::cell::Cell;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
    mpsc,
};
use std::thread;
use std::time::Instant;

fn end() -> u64 {
    clock::boot_ms().unwrap() + 5000
}

fn queued(admission: &Admission, count: usize) {
    let deadline = Instant::now() + Duration::from_secs(2);
    let mut state = admission.state.lock().unwrap();
    while state.waiting.len() != count {
        let left = deadline.saturating_duration_since(Instant::now());
        assert!(!left.is_zero(), "foreground did not reach route admission");
        state = admission.changed.wait_timeout(state, left).unwrap().0;
    }
}

#[test]
fn a_waiting_foreground_turn_survives_maintenance_and_cannot_be_overtaken() {
    let admission = Admission::default();
    let maintenance = admission.maintenance(|| false).unwrap().unwrap();
    let (events, received) = mpsc::channel();
    let (release, released) = mpsc::channel();
    let (registered, registration) = mpsc::channel();
    let (resume, resumed) = mpsc::channel();
    thread::scope(|scope| {
        let route = &admission;
        scope.spawn(move || {
            let probes = Cell::new(0);
            let _turn = route
                .foreground(end(), || {
                    let probe = probes.replace(probes.get() + 1);
                    if probe == 1 {
                        registered.send(()).unwrap();
                        resumed.recv_timeout(Duration::from_secs(2)).unwrap();
                    }
                    false
                })
                .unwrap();
            events.send("foreground").unwrap();
            released.recv_timeout(Duration::from_secs(2)).unwrap();
        });
        queued(&admission, 1);
        registration.recv_timeout(Duration::from_secs(2)).unwrap();
        // The watcher still owns the request and its response; foreground work waits.
        assert!(received.try_recv().is_err());
        drop(maintenance);
        // Reacquisition cannot win merely because the waiting thread has not woken yet.
        assert!(admission.maintenance(|| false).unwrap().is_none());
        resume.send(()).unwrap();
        assert_eq!(
            received.recv_timeout(Duration::from_secs(2)).unwrap(),
            "foreground"
        );
        release.send(()).unwrap();
    });
    assert!(admission.maintenance(|| false).unwrap().is_some());
}

#[test]
fn queued_foreground_work_cannot_starve_a_reserved_maintenance_turn() {
    let admission = Admission::default();
    let first = admission.foreground(end(), || false).unwrap();
    let (events, received) = mpsc::channel();
    let (release, released) = mpsc::channel();
    thread::scope(|scope| {
        let route = &admission;
        scope.spawn(move || {
            let _turn = route.foreground(end(), || false).unwrap();
            events.send("second").unwrap();
            released.recv_timeout(Duration::from_secs(2)).unwrap();
        });
        queued(&admission, 1);
        assert!(admission.maintenance(|| false).unwrap().is_none());
        drop(first);
        let maintenance = admission.maintenance(|| false).unwrap().unwrap();
        assert!(received.try_recv().is_err());
        drop(maintenance);
        // A new periodic poll must yield back to the already waiting foreground turn.
        assert!(admission.maintenance(|| false).unwrap().is_none());
        assert_eq!(
            received.recv_timeout(Duration::from_secs(2)).unwrap(),
            "second"
        );
        release.send(()).unwrap();
    });
    assert!(admission.maintenance(|| false).unwrap().is_some());
}

#[test]
fn a_reserved_maintenance_turn_survives_polls_and_new_foreground_arrivals() {
    let admission = Admission::default();
    let first = admission.foreground(end(), || false).unwrap();
    assert!(admission.maintenance(|| false).unwrap().is_none());
    drop(first);
    // Maintenance has not reached its next poll. New foreground arrivals cannot steal its turn.
    for _ in 0..2 {
        assert!(matches!(
            admission.foreground(clock::boot_ms().unwrap() + 40, || false),
            Err(Error::Expired)
        ));
    }
    assert!(admission.maintenance(|| false).unwrap().is_some());
    assert!(admission.foreground(end(), || false).is_ok());
}

#[test]
fn foreground_order_is_fifo_and_cancellation_removes_only_its_own_place() {
    let admission = Admission::default();
    let maintenance = admission.maintenance(|| false).unwrap().unwrap();
    let cancelled = AtomicBool::new(false);
    let (events, received) = mpsc::channel();
    thread::scope(|scope| {
        scope.spawn(|| {
            let result = admission.foreground(end(), || cancelled.load(Ordering::Acquire));
            assert!(matches!(result, Err(Error::Stopped)));
        });
        queued(&admission, 1);
        scope.spawn(|| {
            let _turn = admission.foreground(end(), || false).unwrap();
            events.send(2).unwrap();
        });
        queued(&admission, 2);
        scope.spawn(|| {
            let _turn = admission.foreground(end(), || false).unwrap();
            events.send(3).unwrap();
        });
        queued(&admission, 3);
        cancelled.store(true, Ordering::Release);
        queued(&admission, 2);
        drop(maintenance);
        assert_eq!(received.recv_timeout(Duration::from_secs(2)).unwrap(), 2);
        assert_eq!(received.recv_timeout(Duration::from_secs(2)).unwrap(), 3);
    });
}

#[test]
fn an_expired_original_end_never_acquires_or_retains_a_place() {
    let admission = Admission::default();
    let maintenance = admission.maintenance(|| false).unwrap().unwrap();
    let deadline = clock::boot_ms().unwrap() + 40;
    assert!(matches!(
        admission.foreground(deadline, || false),
        Err(Error::Expired)
    ));
    queued(&admission, 0);
    drop(maintenance);
    assert!(matches!(
        admission.foreground(deadline, || false),
        Err(Error::Expired)
    ));
    assert!(admission.foreground(end(), || false).is_ok());
}

#[test]
fn cancellation_at_handoff_releases_the_turn_before_work_can_start() {
    let admission = Admission::default();
    let probes = Cell::new(0);
    let result = admission.foreground(end(), || {
        let probe = probes.replace(probes.get() + 1);
        probe == 2
    });
    assert!(matches!(result, Err(Error::Stopped)));
    queued(&admission, 0);
    assert!(admission.maintenance(|| false).unwrap().is_some());
}

#[test]
fn shutdown_and_withdrawn_maintenance_leave_no_blocked_turn() {
    let admission = Admission::default();
    let first = admission.foreground(end(), || false).unwrap();
    let stopped = AtomicBool::new(false);
    assert!(admission.maintenance(|| false).unwrap().is_none());
    thread::scope(|scope| {
        let worker = scope.spawn(|| {
            admission
                .foreground(end(), || stopped.load(Ordering::Acquire))
                .err()
        });
        queued(&admission, 1);
        stopped.store(true, Ordering::Release);
        assert_eq!(worker.join().unwrap(), Some(Error::Stopped));
    });
    queued(&admission, 0);
    assert!(matches!(
        admission.maintenance(|| true),
        Err(Error::Stopped)
    ));
    admission.cancel_maintenance();
    drop(first);
    assert!(admission.foreground(end(), || false).is_ok());
}

#[test]
fn foreground_capacity_refuses_without_starting_more_stream_work() {
    let admission = Arc::new(Admission::default());
    let first = admission.foreground(end(), || false).unwrap();
    let stopped = Arc::new(AtomicBool::new(false));
    thread::scope(|scope| {
        let mut workers = Vec::new();
        for _ in 1..MAXIMUM_FOREGROUND {
            let admission = Arc::clone(&admission);
            let stopped = Arc::clone(&stopped);
            workers.push(scope.spawn(move || {
                admission
                    .foreground(end(), || stopped.load(Ordering::Acquire))
                    .err()
            }));
        }
        queued(&admission, MAXIMUM_FOREGROUND - 1);
        assert!(matches!(
            admission.foreground(end(), || false),
            Err(Error::Busy)
        ));
        // The single maintenance reservation is independent of foreground queue capacity.
        assert!(admission.maintenance(|| false).unwrap().is_none());
        stopped.store(true, Ordering::Release);
        for worker in workers {
            assert_eq!(worker.join().unwrap(), Some(Error::Stopped));
        }
    });
    queued(&admission, 0);
    drop(first);
    assert!(admission.maintenance(|| false).unwrap().is_some());
}

#[test]
fn unwind_releases_the_turn_and_poison_does_not_admit_work() {
    let admission = Admission::default();
    assert!(
        std::panic::catch_unwind(|| {
            let _turn = admission.maintenance(|| false).unwrap().unwrap();
            panic!("interrupted exchange");
        })
        .is_err()
    );
    assert!(admission.foreground(end(), || false).is_ok());
    assert!(
        std::panic::catch_unwind(|| {
            let _state = admission.state.lock().unwrap();
            panic!("interrupted admission state");
        })
        .is_err()
    );
    assert!(matches!(
        admission.foreground(end(), || false),
        Err(Error::Unavailable)
    ));
    assert!(matches!(
        admission.maintenance(|| false),
        Err(Error::Unavailable)
    ));
    admission.cancel_maintenance();
}
