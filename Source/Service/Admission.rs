// SPDX-License-Identifier: Apache-2.0
//! Fair, finite admission before the serial companion authority exchange.
use crate::clock;
use std::{
    collections::VecDeque,
    sync::{Condvar, Mutex},
    time::Duration,
};

const MAXIMUM_PENDING: usize = 32;
const WAIT_MS: u64 = 1000;
const CHECK_MS: u64 = 1000;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Error {
    Busy,
    Stopped,
    Expired,
    Unavailable,
}
#[derive(Default)]
struct State {
    next: u64,
    active: Option<u64>,
    waiting: VecDeque<u64>,
}
#[derive(Default)]
pub(super) struct Admission {
    state: Mutex<State>,
    changed: Condvar,
}
pub(super) struct Permit<'a> {
    admission: &'a Admission,
    ticket: u64,
    outer_end: Option<u64>,
}
impl Admission {
    pub fn acquire(
        &self,
        outer_end: Option<u64>,
        stopped: impl Fn() -> bool,
    ) -> Result<Permit<'_>, Error> {
        let started = clock::boot_ms().map_err(|_| Error::Unavailable)?;
        let wait_end = started.checked_add(WAIT_MS).ok_or(Error::Unavailable)?;
        let end = outer_end.map_or(wait_end, |end| end.min(wait_end));
        if stopped() {
            return Err(Error::Stopped);
        }
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
        let permit = Permit {
            admission: self,
            ticket,
            outer_end,
        };
        self.changed.notify_all();
        loop {
            if stopped() {
                return Err(Error::Stopped);
            }
            let now = clock::boot_ms().map_err(|_| Error::Unavailable)?;
            if now >= end {
                return Err(if outer_end.is_some_and(|end| now >= end) {
                    Error::Expired
                } else {
                    Error::Busy
                });
            }
            let mut state = self.state.lock().map_err(|_| Error::Unavailable)?;
            if state.active.is_none() && state.waiting.front() == Some(&ticket) {
                state.waiting.pop_front();
                state.active = Some(ticket);
                drop(state);
                if stopped() {
                    return Err(Error::Stopped);
                }
                return Ok(permit);
            }
            drop(
                self.changed
                    .wait_timeout(state, Duration::from_millis((end - now).min(25)))
                    .map_err(|_| Error::Unavailable)?,
            );
        }
    }
}
impl Permit<'_> {
    /// The authority clock starts after admission; an enclosing deadline never moves.
    pub fn check_timeout(&self) -> Result<Duration, Error> {
        let now = clock::boot_ms().map_err(|_| Error::Unavailable)?;
        let ms = self
            .outer_end
            .map_or(CHECK_MS, |end| end.saturating_sub(now).min(CHECK_MS));
        if ms < 100 {
            return Err(Error::Expired);
        }
        Ok(Duration::from_millis(ms))
    }
}
impl Drop for Permit<'_> {
    fn drop(&mut self) {
        // Cleanup also removes this exact ticket after poison; new admission still fails closed.
        let mut state = self
            .admission
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if state.active == Some(self.ticket) {
            state.active = None;
        } else {
            state.waiting.retain(|ticket| *ticket != self.ticket);
        }
        drop(state);
        self.admission.changed.notify_all();
    }
}

#[cfg(test)]
#[path = "../../Tests/Service/Admission.rs"]
mod tests;
