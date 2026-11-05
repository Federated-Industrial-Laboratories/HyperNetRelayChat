// SPDX-License-Identifier: Apache-2.0
//! Fair, finite admission before bounded companion authority exchanges.
use crate::{
    clock,
    home::{self, AuthenticatedSession},
    protocol::{AccountId, Id, NetworkId, Operation, VerifiedAction},
};
use std::{
    collections::VecDeque,
    sync::{Condvar, Mutex},
    time::Duration,
};

const MAXIMUM_PENDING: usize = 32;
const MAXIMUM_ACTIVE: usize = 4;
const MAXIMUM_CLASS_ACTIVE: usize = 3;
const MAXIMUM_CLASS_PENDING: usize = 24;
const MAXIMUM_SUBJECT_PENDING: usize = 4;
const WAIT_MS: u64 = 1000;
const CHECK_MS: u64 = 5000;

#[derive(Debug, PartialEq, Eq)]
pub(super) enum Error {
    Busy,
    Stopped,
    Expired,
    Unavailable,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Class {
    Interactive,
    Read,
}
impl Class {
    fn other(self) -> Self {
        match self {
            Self::Interactive => Self::Read,
            Self::Read => Self::Interactive,
        }
    }
    pub fn operation(operation: Operation) -> Self {
        if (home::is_read_operation(operation) || operation == Operation::FederationInspect)
            && !matches!(
                operation,
                Operation::SearchCancel | Operation::OperationResolve
            )
        {
            Self::Read
        } else {
            Self::Interactive
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Principal {
    Account(AccountId),
    Transport(NetworkId, Id),
}
#[derive(Clone, Copy, Debug)]
pub(super) struct Request {
    pub operation: &'static str,
    class: Class,
    acting: Principal,
    owner: Option<AccountId>,
}
impl Request {
    pub fn account(account: AccountId, class: Class) -> Self {
        Self {
            operation: "Authority",
            class,
            acting: Principal::Account(account),
            owner: None,
        }
    }
    pub fn transport(network: NetworkId, principal: Id, class: Class) -> Self {
        Self {
            operation: "Authority",
            class,
            acting: Principal::Transport(network, principal),
            owner: None,
        }
    }
    pub fn action(
        session: &AuthenticatedSession,
        action: &VerifiedAction,
        owner: Option<AccountId>,
    ) -> Self {
        let bound = action.action().actor.acting() == &session.acting
            && action.signer_key() == session.signer;
        Self {
            operation: action.action().operation.name(),
            class: if bound {
                Class::operation(action.action().operation)
            } else {
                Class::Read
            },
            acting: Principal::Account(session.acting.account),
            owner: bound.then_some(owner).flatten(),
        }
    }
    pub fn named(mut self, operation: &'static str) -> Self {
        self.operation = operation;
        self
    }
    fn group(self) -> Principal {
        self.owner.map_or(self.acting, Principal::Account)
    }
    fn overlaps(self, other: Self) -> bool {
        self.uses(other.acting) || self.uses(other.group())
    }
    fn uses(self, principal: Principal) -> bool {
        self.acting == principal || self.group() == principal
    }
}
#[derive(Clone, Copy)]
struct Entry {
    ticket: u64,
    request: Request,
}
struct State {
    next: u64,
    active: Vec<Entry>,
    waiting: VecDeque<Entry>,
    turns: VecDeque<Principal>,
    last_class: Class,
}
impl Default for State {
    fn default() -> Self {
        Self {
            next: 0,
            active: Vec::new(),
            waiting: VecDeque::new(),
            turns: VecDeque::new(),
            last_class: Class::Read,
        }
    }
}
impl State {
    fn enqueue(&mut self, request: Request) -> Result<u64, Error> {
        let entries = || self.active.iter().chain(self.waiting.iter());
        if self.active.len() + self.waiting.len() >= MAXIMUM_PENDING
            || entries()
                .filter(|entry| entry.request.class == request.class)
                .count()
                >= MAXIMUM_CLASS_PENDING
            || [request.acting, request.group()]
                .into_iter()
                .any(|principal| {
                    entries()
                        .filter(|entry| entry.request.uses(principal))
                        .count()
                        >= MAXIMUM_SUBJECT_PENDING
                })
        {
            return Err(Error::Busy);
        }
        let ticket = self.next;
        self.next = ticket.checked_add(1).ok_or(Error::Unavailable)?;
        if !self.turns.contains(&request.group()) {
            self.turns.push_back(request.group());
        }
        self.waiting.push_back(Entry { ticket, request });
        Ok(ticket)
    }
    fn selected(&self) -> Option<u64> {
        if self.active.len() >= MAXIMUM_ACTIVE {
            return None;
        }
        for class in [self.last_class.other(), self.last_class] {
            if self
                .active
                .iter()
                .filter(|entry| entry.request.class == class)
                .count()
                >= MAXIMUM_CLASS_ACTIVE
            {
                continue;
            }
            for group in &self.turns {
                // A subject's own commands stay in FIFO order, across both classes.
                let Some(entry) = self
                    .waiting
                    .iter()
                    .find(|entry| entry.request.group() == *group)
                else {
                    continue;
                };
                if entry.request.class == class
                    && !self
                        .waiting
                        .iter()
                        .take_while(|prior| prior.ticket != entry.ticket)
                        .any(|prior| prior.request.overlaps(entry.request))
                    && !self
                        .active
                        .iter()
                        .any(|active| active.request.overlaps(entry.request))
                {
                    return Some(entry.ticket);
                }
            }
        }
        None
    }
    fn admit(&mut self, ticket: u64) {
        let index = self
            .waiting
            .iter()
            .position(|entry| entry.ticket == ticket)
            .expect("selected waiting ticket");
        let entry = self.waiting.remove(index).expect("selected waiting entry");
        self.turns.retain(|group| *group != entry.request.group());
        self.turns.push_back(entry.request.group());
        self.last_class = entry.request.class;
        self.active.push(entry);
    }
    fn remove(&mut self, ticket: u64) {
        self.active.retain(|entry| entry.ticket != ticket);
        self.waiting.retain(|entry| entry.ticket != ticket);
        self.turns.retain(|group| {
            self.active
                .iter()
                .chain(self.waiting.iter())
                .any(|entry| entry.request.group() == *group)
        });
    }
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
        request: Request,
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
            state.enqueue(request)?
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
            if state.selected() == Some(ticket) {
                state.admit(ticket);
                drop(state);
                // Other eligible subjects can use the remaining slots immediately.
                self.changed.notify_all();
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
    pub fn check_deadline(&self) -> Result<u64, Error> {
        let now = clock::boot_ms().map_err(|_| Error::Unavailable)?;
        let check_end = now.checked_add(CHECK_MS).ok_or(Error::Unavailable)?;
        let end = self.outer_end.map_or(check_end, |end| end.min(check_end));
        if end.saturating_sub(now) < 100 {
            return Err(Error::Expired);
        }
        Ok(end)
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
        state.remove(self.ticket);
        drop(state);
        self.admission.changed.notify_all();
    }
}

#[cfg(test)]
#[path = "../../Tests/Service/Admission.rs"]
mod tests;
