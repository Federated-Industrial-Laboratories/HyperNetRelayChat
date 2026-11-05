// SPDX-License-Identifier: Apache-2.0
//! Exact authenticated reads share one finite deadline and retry policy.
use super::{Error, Result};
use crate::protocol::{ErrorCode, Outcome, Response};
use std::{thread, time::Duration};

/// A verified temporary read refusal leaves this stream synchronized. Earlier
/// refresh results remain available while only this exact read is attempted again.
pub(in crate::client) fn retry_read(
    end: u64,
    interrupted: impl Fn() -> bool,
    mut attempt: impl FnMut(u64) -> Result<Response>,
) -> Result<Response> {
    for number in 0..5 {
        if interrupted() {
            return Err(Error::Offline);
        }
        if crate::clock::boot_ms().map_err(|_| Error::Clock)? >= end {
            return Err(Error::ReadDeadlineExpired);
        }
        let response = attempt(end)?;
        if crate::clock::boot_ms().map_err(|_| Error::Clock)? >= end {
            // Late content cannot become current. A verified terminal refusal
            // still keeps its authority meaning rather than becoming retryable.
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
        let Outcome::Refused {
            code: ErrorCode::Unavailable | ErrorCode::Overloaded | ErrorCode::RateLimited,
            retry_after_ms,
            ..
        } = &response.outcome
        else {
            return Ok(response);
        };
        let now = crate::clock::boot_ms().map_err(|_| Error::Clock)?;
        let delay = retry_after_ms.unwrap_or(1000).max(250);
        let Some(until) = now.checked_add(delay).filter(|until| *until < end) else {
            return Ok(response);
        };
        if number == 4 {
            return Ok(response);
        }
        loop {
            if interrupted() {
                return Err(Error::Offline);
            }
            let now = crate::clock::boot_ms().map_err(|_| Error::Clock)?;
            if now >= until {
                break;
            }
            thread::sleep(Duration::from_millis((until - now).min(25)));
        }
    }
    unreachable!("read attempt count is bounded")
}
