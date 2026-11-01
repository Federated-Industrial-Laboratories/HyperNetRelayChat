// SPDX-License-Identifier: Apache-2.0
//! Pre-session device proofs enter the same guarded identity writer as authenticated operations.
use super::*;
use crate::identity::lifecycle;
use std::cell::Cell;
#[derive(Clone, Copy)]
pub(crate) struct DeviceTransport {
    pub principal: Id,
    pub session: Id,
    pub generation: u64,
    pub service_boot: Id,
}
impl Home {
    pub(crate) fn device_challenge(
        &mut self,
        request: &Verified<DeviceRequest>,
        transport: DeviceTransport,
        clock: TimeBounds,
    ) -> Result<Verified<DeviceChallenge>> {
        let r = request.value();
        if r.home != self.home || r.principal != transport.principal || transport.generation == 0 {
            return Err(Error::Refused("DeviceTransport"));
        }
        let now = clock
            .refresh()
            .map_err(|_| Error::Refused("ClockUnavailable"))?;
        let mut reason = None;
        let state = self.store.read(Duration::from_secs(1), |db| {
            let floor: u64 = db.query_row(
                "SELECT clock_floor FROM hrc_meta WHERE singleton=1",
                [],
                |r| r.get(0),
            )?;
            now.after_floor(floor)
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
            let result = lifecycle::eligibility(db, request, now).map_err(|e| match e {
                Fault::Sql(e) => e,
                Fault::Reject(_, detail) => {
                    reason = Some(detail);
                    rusqlite::Error::InvalidQuery
                }
            })?;
            let ticket_expiry = if r.purpose == DevicePurpose::Enrol && result.1.is_none() {
                db.query_row(
                    "SELECT expires FROM identity_tickets WHERE request=?1",
                    [r.request.as_hex()],
                    |r| r.get::<_, u64>(0),
                )?
            } else {
                u64::MAX
            };
            Ok((result, ticket_expiry))
        });
        let ((state, saved), ticket_expiry) = match state {
            Ok(s) => s,
            Err(_) if reason.is_some() => return Err(Error::Refused(reason.unwrap())),
            Err(e) => return Err(Error::Storage(e)),
        };
        let value = DeviceChallenge {
            home: self.home,
            account: r.account,
            request: r.request,
            request_digest: request.digest(),
            nonce: Id::random().map_err(|_| Error::Invalid)?,
            service_boot: transport.service_boot,
            principal: transport.principal,
            session: transport.session,
            transport_generation: transport.generation,
            security_generation: state.security_generation,
            account_revision: state.revision,
            recovery_generation: state.recovery_generation,
            recovery_key: state.recovery_key,
            continuity_head: state.head.ok_or(Error::Invalid)?,
            recorded: saved.is_some(),
            issued_ms: now.lower_ms,
            expires_ms: (now.lower_ms + 5000).min(r.expires_ms).min(ticket_expiry),
        };
        let bytes = sign_device_challenge(&value, &self.signer).map_err(|_| Error::Invalid)?;
        verify_device_challenge(&bytes, &self.signer.verifying_key()).map_err(|_| Error::Invalid)
    }
    pub(crate) fn activate_device(
        &mut self,
        request: &Verified<DeviceRequest>,
        challenge: &Verified<DeviceChallenge>,
        proofs: &DeviceProofs,
        transport: DeviceTransport,
        clock: TimeBounds,
        permit: &dyn Fn() -> bool,
    ) -> Result<DeviceReceipt> {
        let r = request.value();
        let c = challenge.value();
        let refused = |code, detail: &str| DeviceReceipt {
            home: self.home,
            account: r.account,
            request: r.request,
            request_digest: request.digest(),
            outcome: Outcome::Refused {
                code,
                detail: detail.into(),
                retry_after_ms: None,
            },
        };
        if r.home != self.home
            || c.home != self.home
            || r.principal != transport.principal
            || c.principal != transport.principal
            || c.session != transport.session
            || c.transport_generation != transport.generation
            || c.service_boot != transport.service_boot
            || challenge.signer_key() != Id::from_bytes(self.signer.verifying_key().to_bytes())
        {
            return Ok(refused(ErrorCode::Denied, "DeviceTransport"));
        }
        let reason = Cell::new(None);
        let result = self.store.write(|db| {
            let now = clock.refresh().map_err(|_| rusqlite::Error::InvalidQuery)?;
            let floor: u64 = db.query_row(
                "SELECT clock_floor FROM hrc_meta WHERE singleton=1",
                [],
                |r| r.get(0),
            )?;
            if !permit() || now.after_floor(floor).is_err() {
                reason.set(Some((ErrorCode::Unavailable, "AuthorityUnavailable")));
                return Err(rusqlite::Error::InvalidQuery);
            }
            let result =
                lifecycle::activate(db, request, challenge, proofs, now).map_err(|e| match e {
                    Fault::Sql(e) => e,
                    Fault::Reject(code, detail) => {
                        reason.set(Some((code, detail)));
                        rusqlite::Error::InvalidQuery
                    }
                })?;
            let final_time = clock.refresh().map_err(|_| rusqlite::Error::InvalidQuery)?;
            if !permit()
                || final_time.after_floor(floor).is_err()
                || final_time.upper_ms >= c.expires_ms
                || final_time.upper_ms >= r.expires_ms
            {
                reason.set(Some((ErrorCode::Unavailable, "DeviceAuthorityExpired")));
                return Err(rusqlite::Error::InvalidQuery);
            }
            db.execute(
                "UPDATE hrc_meta SET clock_floor=?1 WHERE singleton=1",
                [final_time.lower_ms],
            )?;
            Ok(Commit::new(
                result.clone(),
                encode(&(
                    "HRC.Device",
                    request.digest(),
                    challenge.digest(),
                    digest(&encode(&result)?),
                ))?,
            ))
        });
        match result {
            Ok(r) => Ok(r),
            Err(_) if reason.get().is_some() => {
                let (code, detail) = reason.get().unwrap();
                Ok(refused(code, detail))
            }
            Err(storage::Error::Fenced) => Ok(DeviceReceipt {
                home: self.home,
                account: r.account,
                request: r.request,
                request_digest: request.digest(),
                outcome: Outcome::Unknown,
            }),
            Err(storage::Error::Busy | storage::Error::Quota | storage::Error::Deadline) => {
                Ok(refused(ErrorCode::Overloaded, "StorageCapacity"))
            }
            Err(e) => Err(Error::Storage(e)),
        }
    }
}
