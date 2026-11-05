// SPDX-License-Identifier: Apache-2.0
//! One bounded FIFO for all access to the service's serialized Home owner.
use crate::{
    clock,
    home::Home,
    protocol::{ErrorCode, Outcome},
};
use std::{
    collections::VecDeque,
    ops::{Deref, DerefMut},
    sync::{
        Arc, Condvar, Mutex, MutexGuard,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

const MAXIMUM_PENDING: usize = 32;
const WAIT_MS: u64 = 1000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Error {
    Busy,
    Stopped,
    Expired,
    Invalidated,
    Unavailable,
}
impl Error {
    pub(super) fn refusal(self) -> Outcome {
        let (code, detail) = match self {
            Self::Busy => (ErrorCode::Overloaded, "OperationBusy"),
            Self::Stopped => (ErrorCode::Unavailable, "OperationStopped"),
            Self::Expired => (ErrorCode::Unavailable, "OperationDeadline"),
            Self::Invalidated => (ErrorCode::Unavailable, "TransportAuthority"),
            Self::Unavailable => (ErrorCode::Unavailable, "OperationState"),
        };
        Outcome::Refused {
            code,
            detail: detail.into(),
            retry_after_ms: Some(1000),
        }
    }
}
#[derive(Default)]
struct State {
    next: u64,
    active: Option<u64>,
    waiting: VecDeque<u64>,
}
pub(super) struct HomeAccess {
    value: Mutex<Home>,
    state: Mutex<State>,
    changed: Condvar,
    stop: Arc<AtomicBool>,
}
struct Turn<'a> {
    owner: &'a HomeAccess,
    ticket: u64,
}
pub(super) struct Guard<'a> {
    // Drop the Home mutex before releasing its turn and notifying another waiter.
    value: MutexGuard<'a, Home>,
    _turn: Turn<'a>,
}
impl HomeAccess {
    pub(super) fn new(home: Home, stop: Arc<AtomicBool>) -> Self {
        Self {
            value: Mutex::new(home),
            state: Mutex::new(State::default()),
            changed: Condvar::new(),
            stop,
        }
    }
    pub(super) fn lock(&self) -> Result<Guard<'_>, Error> {
        self.acquire(None, || true)
    }
    pub(super) fn try_lock(&self) -> Result<Guard<'_>, Error> {
        if self.stop.load(Ordering::Acquire) {
            return Err(Error::Stopped);
        }
        let mut state = self.state.lock().map_err(|_| Error::Unavailable)?;
        if state.active.is_some() || !state.waiting.is_empty() {
            return Err(Error::Busy);
        }
        let ticket = state.next;
        state.next = ticket.checked_add(1).ok_or(Error::Unavailable)?;
        state.active = Some(ticket);
        drop(state);
        self.enter(Turn {
            owner: self,
            ticket,
        })
    }
    fn enter<'a>(&'a self, turn: Turn<'a>) -> Result<Guard<'a>, Error> {
        // The sole admitted turn excludes every other Home user, including maintenance.
        // A contended inner mutex therefore cannot be waited on or interpreted as permission.
        let value = self.value.try_lock().map_err(|_| Error::Unavailable)?;
        if self.stop.load(Ordering::Acquire) {
            return Err(Error::Stopped);
        }
        Ok(Guard { value, _turn: turn })
    }
    pub(super) fn acquire(
        &self,
        outer_end: Option<u64>,
        current: impl Fn() -> bool,
    ) -> Result<Guard<'_>, Error> {
        let started = clock::boot_ms().map_err(|_| Error::Unavailable)?;
        let wait_end = started.checked_add(WAIT_MS).ok_or(Error::Unavailable)?;
        let end = outer_end.map_or(wait_end, |outer| outer.min(wait_end));
        let valid = || {
            if self.stop.load(Ordering::Acquire) {
                return Err(Error::Stopped);
            }
            let now = clock::boot_ms().map_err(|_| Error::Unavailable)?;
            if now >= end {
                return Err(if outer_end.is_some_and(|outer| now >= outer) {
                    Error::Expired
                } else {
                    Error::Busy
                });
            }
            if !current() {
                return Err(Error::Invalidated);
            }
            Ok(now)
        };
        valid()?;
        let ticket = {
            let mut state = self.state.lock().map_err(|_| Error::Unavailable)?;
            if state.waiting.len() + usize::from(state.active.is_some()) >= MAXIMUM_PENDING {
                return Err(Error::Busy);
            }
            let ticket = state.next;
            state.next = ticket.checked_add(1).ok_or(Error::Unavailable)?;
            state.waiting.push_back(ticket);
            ticket
        };
        let turn = Turn {
            owner: self,
            ticket,
        };
        self.changed.notify_all();
        loop {
            let now = valid()?;
            let mut state = self.state.lock().map_err(|_| Error::Unavailable)?;
            if state.active.is_none() && state.waiting.front() == Some(&ticket) {
                state.waiting.pop_front();
                state.active = Some(ticket);
                drop(state);
                let guard = self.enter(turn)?;
                valid()?;
                return Ok(guard);
            }
            drop(
                self.changed
                    .wait_timeout(state, Duration::from_millis((end - now).min(25)))
                    .map_err(|_| Error::Unavailable)?,
            );
        }
    }
}
impl Deref for Guard<'_> {
    type Target = Home;
    fn deref(&self) -> &Home {
        &self.value
    }
}
impl DerefMut for Guard<'_> {
    fn deref_mut(&mut self) -> &mut Home {
        &mut self.value
    }
}
impl Drop for Turn<'_> {
    fn drop(&mut self) {
        let mut state = self
            .owner
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if state.active == Some(self.ticket) {
            state.active = None;
        } else {
            state.waiting.retain(|ticket| *ticket != self.ticket);
        }
        drop(state);
        self.owner.changed.notify_all();
    }
}

#[cfg(test)]
#[path = "../../Tests/Service/HomeAccess.rs"]
mod tests;
