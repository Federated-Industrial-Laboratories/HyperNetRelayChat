// SPDX-License-Identifier: Apache-2.0
//! Exact local admission recovery never grants a second account or extends an invitation.
use super::*;

impl Home {
    /// The caller must retain this exact identifier and expiry before attempting admission.
    pub fn issue_invitation_exact(
        &mut self,
        id: Id,
        principal: Id,
        classification: AccountClass,
        expires_ms: u64,
        clock: TimeBounds,
    ) -> Result<Invitation> {
        let invitation = Invitation {
            home: self.home,
            service_key: Id::from_bytes(self.signer.verifying_key().to_bytes()),
            id,
            principal,
            classification,
            expires_ms,
        };
        let retained = self.store.read(Duration::from_secs(2), |db| {
            db.query_row(
                "SELECT principal,class,expires FROM hrc_invitations WHERE id=?1",
                [id.as_hex()],
                |r| {
                    Ok((
                        r.get::<_, String>(0)?,
                        r.get::<_, Vec<u8>>(1)?,
                        r.get::<_, u64>(2)?,
                    ))
                },
            )
            .optional()
        })?;
        if let Some((subject, class, expiry)) = retained {
            if subject != principal.as_hex()
                || decode::<AccountClass>(&class).map_err(storage::Error::from)?
                    != invitation.classification
                || expiry != expires_ms
            {
                return Err(Error::Refused("InvitationRetryBinding"));
            }
            return Ok(invitation);
        }
        let class = encode(&invitation.classification).map_err(storage::Error::from)?;
        let outcome = self.store.write(|db| {
            let now = clock.refresh().map_err(|_| rusqlite::Error::InvalidQuery)?;
            let floor: u64 = db.query_row(
                "SELECT clock_floor FROM hrc_meta WHERE singleton=1",
                [],
                |r| r.get(0),
            )?;
            if now.after_floor(floor).is_err()
                || expires_ms <= now.upper_ms
                || expires_ms > now.lower_ms.saturating_add(DAY)
            {
                return Ok(Commit::new(false, b"HRC.Invitation.Clock".to_vec()));
            }
            let count: u64 = db.query_row(
                "SELECT count(*) FROM hrc_invitations WHERE expires>?1",
                [now.lower_ms],
                |r| r.get(0),
            )?;
            if count >= 128 {
                return Ok(Commit::new(false, b"HRC.Invitation.Capacity".to_vec()));
            }
            db.execute(
                "INSERT INTO hrc_invitations(id,principal,class,expires) VALUES(?1,?2,?3,?4)",
                params![id.as_hex(), principal.as_hex(), class, expires_ms],
            )?;
            db.execute(
                "UPDATE hrc_meta SET clock_floor=?1 WHERE singleton=1",
                [now.lower_ms],
            )?;
            Ok(Commit::new(true, encode(&invitation)?))
        })?;
        if !outcome {
            return Err(Error::Refused("InvitationUnavailable"));
        }
        Ok(invitation)
    }

    /// Recover only the original, byte-identical registration outcome, without changing authority.
    pub fn registration_outcome(
        &mut self,
        registration: &Verified<AccountRegistration>,
    ) -> Result<Option<EndpointActor>> {
        let request = registration.value();
        if request.home != self.home {
            return Err(Error::Refused("RegistrationBinding"));
        }
        let retained: Option<Vec<u8>> = self.store.read(Duration::from_secs(2), |db| {
            db.query_row(
                "SELECT record FROM identity_records WHERE account=?1 AND number=1",
                [request.account.to_string()],
                |r| r.get(0),
            )
            .optional()
        })?;
        let Some(bytes) = retained else {
            return Ok(None);
        };
        let record: ContinuityRecord = decode(&bytes).map_err(storage::Error::from)?;
        if record.change != IdentityChange::Registered
            || record.state.home != self.home
            || record.state.account != request.account
            || record.authorizations.len() != 1
            || record.authorizations[0].0 != registration.signed_bytes()
        {
            return Err(Error::Refused("RegistrationRetryBinding"));
        }
        let endpoint = record
            .state
            .endpoints
            .iter()
            .find(|endpoint| {
                endpoint.actor.endpoint == request.endpoint
                    && endpoint.key == request.endpoint_key
                    && endpoint.principal == request.transport_principal
            })
            .ok_or(Error::Refused("RegistrationRetryBinding"))?;
        Ok(Some(endpoint.actor.clone()))
    }
}
