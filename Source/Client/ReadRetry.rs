// SPDX-License-Identifier: Apache-2.0
//! Exact authenticated reads share one finite deadline and retry policy.
use super::{Error, Result};
use crate::protocol::{ErrorCode, Outcome, Response};
use std::{thread, time::Duration};

/// A retry wait owns no exchange. A scheduled caller can run other work only
/// after the preceding complete, authenticated response has been consumed.
pub(in crate::client) struct ReadRetry {
    end: u64,
    attempts: u8,
    ready: u64,
}
impl ReadRetry {
    pub(in crate::client) fn new(end: u64) -> Self {
        Self {
            end,
            attempts: 0,
            ready: 0,
        }
    }
    pub(in crate::client) fn poll(
        &mut self,
        interrupted: impl Fn() -> bool,
        attempt: impl FnOnce(u64) -> Result<Response>,
    ) -> Result<Option<Response>> {
        if interrupted() {
            return Err(Error::Offline);
        }
        let now = crate::clock::boot_ms().map_err(|_| Error::Clock)?;
        if now >= self.end {
            return Err(Error::ReadDeadlineExpired);
        }
        if now < self.ready {
            return Ok(None);
        }
        let response = attempt(self.end)?;
        self.attempts += 1;
        let now = crate::clock::boot_ms().map_err(|_| Error::Clock)?;
        if now >= self.end {
            // A verified terminal refusal keeps its authority meaning.
            if matches!(
                response.outcome,
                Outcome::Rejected { .. } | Outcome::Refused { .. }
            ) {
                let error = Error::from_outcome(response.outcome);
                if error.retry_delay_ms().is_none() {
                    return Err(error);
                }
            }
            return Err(Error::ReadDeadlineExpired);
        }
        if let Outcome::Refused {
            code: ErrorCode::Unavailable | ErrorCode::Overloaded | ErrorCode::RateLimited,
            retry_after_ms,
            ..
        } = &response.outcome
            && self.attempts < 5
            && let Some(until) = now
                .checked_add(retry_after_ms.unwrap_or(1000).max(250))
                .filter(|until| *until < self.end)
        {
            self.ready = until;
            return Ok(None);
        }
        Ok(Some(response))
    }
    pub(in crate::client) fn wait(&self) -> Result<()> {
        let now = crate::clock::boot_ms().map_err(|_| Error::Clock)?;
        thread::sleep(Duration::from_millis(
            self.ready.saturating_sub(now).min(25),
        ));
        Ok(())
    }
}

/// A verified temporary read refusal leaves this stream synchronized. Earlier
/// refresh results remain available while only this exact read is attempted again.
pub(in crate::client) fn retry_read(
    end: u64,
    interrupted: impl Fn() -> bool,
    mut attempt: impl FnMut(u64) -> Result<Response>,
) -> Result<Response> {
    let mut retry = ReadRetry::new(end);
    loop {
        if let Some(response) = retry.poll(&interrupted, &mut attempt)? {
            return Ok(response);
        }
        retry.wait()?;
    }
}
