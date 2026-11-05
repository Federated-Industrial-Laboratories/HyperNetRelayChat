// SPDX-License-Identifier: Apache-2.0
//! Fresh authority observations for one immutable handshake within its original lifetime.
use super::*;
use crate::hypernet::{AuthorityCheck, Disposition};

pub(super) struct Authority {
    check: AuthorityCheck,
    end: u64,
    expires_ms: u64,
}
impl Authority {
    pub(super) fn current(&self, shared: &Shared) -> bool {
        self.current_at(
            shared.config.clock.sample().map_err(|_| Error::Clock),
            shared.stop.load(Ordering::Acquire),
        )
    }

    fn current_at(&self, now: Result<clock::TimeBounds>, stopped: bool) -> bool {
        !stopped
            && super::current(&self.check, Some(self.end))
            && now.is_ok_and(|now| now.boot_ms < self.end && now.upper_ms < self.expires_ms)
    }
}

pub(super) fn authority(
    shared: &Shared,
    stream: &Stream,
    digest: Id,
    end: u64,
    expires_ms: u64,
    request: admission::Request,
) -> Result<Authority> {
    let cancel = Cancellation::default();
    recover(
        end,
        expires_ms,
        || shared.config.clock.sample().map_err(|_| Error::Clock),
        || {
            shared.stop.load(Ordering::Acquire)
                || cancel.is_cancelled()
                || !stream.check_authority_supported()
        },
        |end| shared.check_authority(stream, digest, Some(end), &cancel, request, None),
        thread::sleep,
    )
}

fn recover(
    end: u64,
    expires_ms: u64,
    mut sample: impl FnMut() -> Result<clock::TimeBounds>,
    stopped: impl Fn() -> bool,
    mut attempt: impl FnMut(u64) -> Result<AuthorityCheck>,
    mut wait: impl FnMut(Duration),
) -> Result<Authority> {
    let mut boundary = |end| {
        if stopped() {
            return Err(Error::AuthorityAdmissionStopped);
        }
        let now = sample()?;
        if now.boot_ms >= end || now.upper_ms >= expires_ms {
            return Err(Error::HandshakeExpired);
        }
        Ok(now)
    };
    let now = boundary(end)?;
    // Translation can only shorten the original boot deadline. Later samples never renew it.
    let end = end.min(now.boot_ms.saturating_add(expires_ms - now.upper_ms));
    for index in 0..3 {
        boundary(end)?;
        let result = attempt(end);
        let now = boundary(end)?;
        let failure = match result {
            Ok(check) => {
                // A certified denial stays terminal even when its local observation expires.
                if check
                    .authority()
                    .is_some_and(|authority| authority.code() != 0)
                {
                    return Err(Error::Authority);
                }
                if check.permitted() {
                    return Ok(Authority {
                        check,
                        end,
                        expires_ms,
                    });
                }
                if !matches!(
                    check.disposition(),
                    Disposition::Unavailable | Disposition::Expired
                ) {
                    return Err(Error::Authority);
                }
                Error::Authority
            }
            Err(Error::AuthorityAdmissionBusy) => Error::AuthorityAdmissionBusy,
            Err(error) => return Err(error),
        };
        if index == 2 {
            return Err(failure);
        }
        wait(Duration::from_millis((end - now.boot_ms).min(50)));
    }
    unreachable!("the final bounded attempt returns its outcome")
}

#[cfg(test)]
#[path = "../../Tests/Service/Handshake.rs"]
mod tests;
