// SPDX-License-Identifier: Apache-2.0
//! Bounded turns for foreground forwarding and periodic work on one gateway stream.
use crate::clock;
use std::{
    collections::VecDeque,
    sync::{Condvar, Mutex},
    time::Duration,
};

const MAXIMUM_FOREGROUND: usize = 32;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Error {
    Busy,
    Stopped,
    Expired,
    Unavailable,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Turn {
    Foreground(u64),
    Maintenance,
}

struct State {
    next: u64,
    active: Option<Turn>,
    waiting: VecDeque<u64>,
    maintenance_pending: bool,
    foreground_next: bool,
}
impl Default for State {
    fn default() -> Self {
        Self {
            next: 0,
            active: None,
            waiting: VecDeque::new(),
            maintenance_pending: false,
            foreground_next: true,
        }
    }
}

#[derive(Default)]
pub(super) struct Admission {
    state: Mutex<State>,
    changed: Condvar,
}

pub(super) struct Permit<'a> {
    admission: &'a Admission,
    turn: Turn,
}

impl Admission {
    pub(super) fn foreground(
        &self,
        end: u64,
        stopped: impl Fn() -> bool,
    ) -> Result<Permit<'_>, Error> {
        if stopped() {
            return Err(Error::Stopped);
        }
        if clock::boot_ms().map_err(|_| Error::Unavailable)? >= end {
            return Err(Error::Expired);
        }
        let ticket = {
            let mut state = self.state.lock().map_err(|_| Error::Unavailable)?;
            let active = usize::from(matches!(state.active, Some(Turn::Foreground(_))));
            if state.waiting.len() + active >= MAXIMUM_FOREGROUND {
                return Err(Error::Busy);
            }
            let ticket = state.next;
            state.next = ticket.checked_add(1).ok_or(Error::Unavailable)?;
            state.waiting.push_back(ticket);
            ticket
        };
        // The same guard removes a cancelled waiter or releases its admitted turn.
        let permit = Permit {
            admission: self,
            turn: Turn::Foreground(ticket),
        };
        self.changed.notify_all();
        loop {
            if stopped() {
                return Err(Error::Stopped);
            }
            let now = clock::boot_ms().map_err(|_| Error::Unavailable)?;
            if now >= end {
                return Err(Error::Expired);
            }
            let mut state = self.state.lock().map_err(|_| Error::Unavailable)?;
            if state.active.is_none()
                && state.waiting.front() == Some(&ticket)
                && (!state.maintenance_pending || state.foreground_next)
            {
                state.waiting.pop_front();
                state.active = Some(permit.turn);
                drop(state);
                if stopped() {
                    return Err(Error::Stopped);
                }
                if clock::boot_ms().map_err(|_| Error::Unavailable)? >= end {
                    return Err(Error::Expired);
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

    /// Reserve one periodic turn without blocking maintenance of the other route.
    /// A reservation survives subsequent polls until admitted or explicitly withdrawn.
    pub(super) fn maintenance(
        &self,
        stopped: impl Fn() -> bool,
    ) -> Result<Option<Permit<'_>>, Error> {
        if stopped() {
            self.cancel_maintenance();
            return Err(Error::Stopped);
        }
        let mut state = self.state.lock().map_err(|_| Error::Unavailable)?;
        state.maintenance_pending = true;
        if state.active.is_some() || (!state.waiting.is_empty() && state.foreground_next) {
            return Ok(None);
        }
        state.maintenance_pending = false;
        state.active = Some(Turn::Maintenance);
        drop(state);
        let permit = Permit {
            admission: self,
            turn: Turn::Maintenance,
        };
        if stopped() {
            return Err(Error::Stopped);
        }
        Ok(Some(permit))
    }

    pub(super) fn cancel_maintenance(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        state.maintenance_pending = false;
        drop(state);
        self.changed.notify_all();
    }
}

impl Drop for Permit<'_> {
    fn drop(&mut self) {
        let mut state = self
            .admission
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if state.active == Some(self.turn) {
            state.active = None;
            state.foreground_next = self.turn == Turn::Maintenance;
        } else if let Turn::Foreground(ticket) = self.turn {
            state.waiting.retain(|queued| *queued != ticket);
        }
        drop(state);
        self.admission.changed.notify_all();
    }
}

#[cfg(test)]
#[path = "../../Tests/Service/FederationAdmission.rs"]
mod tests;
