// SPDX-License-Identifier: Apache-2.0
//! Serialized Home work waits fairly without extending authority or executing cancelled work.
use super::*;
use crate::{
    home::Cancellation,
    protocol::{AccountClass, Id, NetworkId, ServiceId, SigningKey},
    storage,
};
use std::{
    cell::Cell,
    fs,
    os::unix::fs::PermissionsExt,
    path::PathBuf,
    sync::{atomic::AtomicUsize, mpsc},
    thread,
    time::Instant,
};

struct Fixture {
    root: PathBuf,
    key: storage::Key,
}
impl Fixture {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "hrc-home-access-{}",
            Id::random().unwrap().as_hex()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        for name in ["Data", "Guard"] {
            fs::create_dir(root.join(name)).unwrap();
            fs::set_permissions(root.join(name), fs::Permissions::from_mode(0o700)).unwrap();
        }
        let key = storage::Key::create(root.join("Key")).unwrap();
        Self { root, key }
    }
    fn home(&self) -> HomeAccess {
        let id = |n| Id::from_bytes([n; 32]);
        let service = ServiceId {
            network: NetworkId {
                network: id(1),
                incarnation: id(2),
            },
            service: id(3),
        };
        let store = storage::Store::create(
            self.root.join("Data"),
            self.root.join("Guard"),
            &self.key,
            *service.service.as_bytes(),
            storage::Limits::default(),
        )
        .unwrap();
        let home = Home::create(store, service, SigningKey::from_bytes(&[4; 32])).unwrap();
        HomeAccess::new(home, Arc::new(AtomicBool::new(false)))
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.root);
    }
}
fn queued(home: &HomeAccess, count: usize) {
    let end = Instant::now() + Duration::from_secs(2);
    let mut state = home.state.lock().unwrap();
    while state.waiting.len() != count {
        let left = end.saturating_duration_since(Instant::now());
        assert!(!left.is_zero(), "Home waiter did not reach admission");
        state = home.changed.wait_timeout(state, left).unwrap().0;
    }
}

#[test]
fn contended_effects_wait_fifo_and_nonblocking_work_cannot_overtake() {
    let fixture = Fixture::new();
    let home = fixture.home();
    let held = home.lock().unwrap();
    let before = held.usage().unwrap().commit_counter;
    let (sent, received) = mpsc::channel();
    let (release, released) = mpsc::channel();
    thread::scope(|scope| {
        let first_sent = sent.clone();
        let owner = &home;
        scope.spawn(move || {
            let mut guard = owner.acquire(None, || true).unwrap();
            guard
                .issue_invitation(
                    Id::from_bytes([20; 32]),
                    AccountClass::Human,
                    clock::TimeBounds::test_now(),
                )
                .unwrap();
            first_sent.send("first").unwrap();
            released.recv_timeout(Duration::from_secs(2)).unwrap();
        });
        queued(&home, 1);
        scope.spawn(|| {
            // Handshake/background blocking users share the same queue as effects.
            let mut guard = home.lock().unwrap();
            guard
                .issue_invitation(
                    Id::from_bytes([21; 32]),
                    AccountClass::Human,
                    clock::TimeBounds::test_now(),
                )
                .unwrap();
            sent.send("second").unwrap();
        });
        queued(&home, 2);
        assert!(matches!(home.try_lock(), Err(Error::Busy)));
        assert!(received.try_recv().is_err());
        drop(held);
        let first = received.recv_timeout(Duration::from_secs(2));
        let overtook = received.try_recv();
        let maintenance = home.try_lock().err();
        release.send(()).unwrap();
        assert_eq!(first.unwrap(), "first");
        assert!(overtook.is_err());
        assert_eq!(maintenance, Some(Error::Busy));
        assert_eq!(
            received.recv_timeout(Duration::from_secs(2)).unwrap(),
            "second"
        );
    });
    assert_eq!(
        home.lock().unwrap().usage().unwrap().commit_counter,
        before + 2
    );
    assert!(home.state.lock().unwrap().waiting.is_empty());
}

#[test]
fn original_end_cancellation_and_shutdown_remove_waiters_without_work() {
    let fixture = Fixture::new();
    let home = fixture.home();
    let held = home.lock().unwrap();
    let end = clock::boot_ms().unwrap() + 30;
    assert!(matches!(
        home.acquire(Some(end), || true),
        Err(Error::Expired)
    ));
    assert!(home.state.lock().unwrap().waiting.is_empty());
    let effects = AtomicUsize::new(0);
    for shutdown in [false, true] {
        let cancel = Cancellation::default();
        let (sent, received) = mpsc::channel();
        thread::scope(|scope| {
            scope.spawn(|| {
                let result = home.acquire(None, || !cancel.is_cancelled());
                if result.is_ok() {
                    effects.fetch_add(1, Ordering::Relaxed);
                }
                sent.send(result.err()).unwrap();
            });
            queued(&home, 1);
            if shutdown {
                home.stop.store(true, Ordering::Release);
            } else {
                cancel.cancel();
            }
            assert_eq!(
                received.recv_timeout(Duration::from_secs(2)).unwrap(),
                Some(if shutdown {
                    Error::Stopped
                } else {
                    Error::Invalidated
                })
            );
        });
        queued(&home, 0);
    }
    assert_eq!(effects.load(Ordering::Relaxed), 0);
    drop(held);
    assert!(matches!(home.try_lock(), Err(Error::Stopped)));
}

#[test]
fn post_acquisition_invalidation_and_poison_never_release_an_effect_guard() {
    let fixture = Fixture::new();
    let home = fixture.home();
    let before = home.lock().unwrap().usage().unwrap().commit_counter;
    let acquired = Cell::new(false);
    let result = home.acquire(None, || match home.value.try_lock() {
        Ok(_) => true,
        Err(std::sync::TryLockError::WouldBlock) => {
            acquired.set(true);
            false
        }
        Err(_) => panic!("unexpected Home poison"),
    });
    assert!(matches!(result, Err(Error::Invalidated)));
    assert!(
        acquired.get(),
        "authority must be rechecked after the Home mutex is acquired"
    );
    assert_eq!(home.lock().unwrap().usage().unwrap().commit_counter, before);
    assert!(
        std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _guard = home.lock().unwrap();
            panic!("interrupted Home operation");
        }))
        .is_err()
    );
    assert!(home.state.lock().unwrap().active.is_none());
    assert!(matches!(home.lock(), Err(Error::Unavailable)));
    assert!(matches!(home.try_lock(), Err(Error::Unavailable)));
}

#[test]
fn home_queue_capacity_and_wait_budget_are_finite() {
    let fixture = Fixture::new();
    let home = fixture.home();
    let held = home.lock().unwrap();
    let cancelled = AtomicBool::new(false);
    thread::scope(|scope| {
        let workers: Vec<_> = (1..MAXIMUM_PENDING)
            .map(|_| {
                scope.spawn(|| {
                    home.acquire(None, || !cancelled.load(Ordering::Acquire))
                        .err()
                })
            })
            .collect();
        queued(&home, MAXIMUM_PENDING - 1);
        let refused = home.acquire(None, || true).err();
        cancelled.store(true, Ordering::Release);
        assert_eq!(refused, Some(Error::Busy));
        for worker in workers {
            assert_eq!(worker.join().unwrap(), Some(Error::Invalidated));
        }
    });
    assert!(home.state.lock().unwrap().waiting.is_empty());
    let start = Instant::now();
    assert!(matches!(home.acquire(None, || true), Err(Error::Busy)));
    assert!(start.elapsed() < Duration::from_secs(2));
    drop(held);
    assert!(home.acquire(None, || true).is_ok());
}
