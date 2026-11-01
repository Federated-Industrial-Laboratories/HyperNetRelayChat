// SPDX-License-Identifier: Apache-2.0
//! Source checks inspect current local identity; they never execute a foreign action.
use super::*;
use crate::home::AuthenticatedSession;
use std::time::Duration;

fn subject_in(
    db: &Connection,
    home: ServiceId,
    session: &AuthenticatedSession,
    source: &SourceSubject,
    agreement: &AgreementState,
    now: TimeBounds,
) -> Domain<(FederationSubject, EndpointActor, Vec<AccountId>)> {
    if home != agreement.agreement.origin || session.acting.account.origin != home.network {
        return deny("OriginSession");
    }
    let ep = crate::identity::endpoint(db, session.acting.account, session.acting.endpoint)?
        .ok_or(Fault::Reject(ErrorCode::Denied, "EndpointDisabled"))?;
    if ep.acting != session.acting
        || ep.principal != session.principal
        || Id::from_bytes(ep.key.to_bytes()) != session.signer
    {
        return deny("OriginEndpoint");
    }
    let mut accounts = vec![ep.acting.account];
    if let AccountClass::Agent { operator } = ep.classification {
        accounts.push(operator)
    }
    let subject = match source {
        SourceSubject::Action(blob) => {
            let verified = verify_action(&blob.0, &ep.key)
                .map_err(|_| Fault::Reject(ErrorCode::Denied, "OriginActionSignature"))?;
            let action = verified.action();
            if action.home != agreement.agreement.home
                || action.agreement != Some(agreement.reference)
            {
                return deny("OriginActionHome");
            }
            crate::identity::authenticate_source(db, &verified, session)?;
            if let Actor::Delegated { represented, .. } = action.actor {
                if represented.origin == home.network {
                    accounts.push(represented)
                } else if represented.origin != agreement.agreement.home.network {
                    return deny("ThirdOrigin");
                }
            }
            FederationSubject::Action {
                action_digest: verified.digest(),
                operation_id: action.operation_id,
            }
        }
        SourceSubject::Session(blob) => {
            let verified = verify_remote_session_request(&blob.0, &ep.key)
                .map_err(|_| Fault::Reject(ErrorCode::Denied, "OriginSessionSignature"))?;
            let r = verified.value();
            if r.home != agreement.agreement.home
                || r.origin != home
                || r.agreement != agreement.reference
                || r.account != ep.acting.account
                || r.endpoint != ep.acting.endpoint
                || r.endpoint_binding_digest != ep.acting.binding_digest
                || !now.permits(r.created_ms, r.expires_ms)
            {
                return deny("OriginSessionRequest");
            }
            FederationSubject::Session {
                request_digest: verified.digest(),
                request: r.request,
            }
        }
    };
    accounts.sort();
    accounts.dedup();
    if accounts.len() > 3 {
        return invalid("OriginIdentityCount");
    }
    Ok((subject, ep.acting, accounts))
}
impl Home {
    pub fn federation_origin_subject(
        &mut self,
        session: &AuthenticatedSession,
        source: SourceSubject,
        agreement: AgreementRef,
        clock: TimeBounds,
    ) -> Result<OriginSubject> {
        let state = self.federation_agreement(agreement, clock)?;
        let t = now(clock)?;
        let (subject, acting, accounts) = self
            .store
            .read(Duration::from_secs(2), |db| {
                Ok(subject_in(db, self.home, session, &source, &state, t))
            })?
            .map_err(convert)?;
        let raw: Vec<u8> = self
            .store
            .read(Duration::from_secs(2), |db| {
                db.query_row(
                    "SELECT binding FROM federation_bindings WHERE account=?1 AND endpoint=?2",
                    rusqlite::params![acting.account.to_string(), acting.endpoint.as_hex()],
                    |r| r.get(0),
                )
            })
            .map_err(|_| refused("EndpointBindingUnavailable"))?;
        let binding: EndpointBinding = decode(&raw)?;
        if binding_digest(&binding)? != acting.binding_digest {
            return Err(refused("OriginBindingDigest"));
        }
        let mut checkpoints = Vec::new();
        let mut states = Vec::new();
        for account in accounts {
            let blob = self.federation_checkpoint(account, agreement, clock)?;
            let cp = verify_origin_identity_checkpoint(&blob.0, &self.signer.verifying_key())?;
            checkpoints.push(CheckpointRef {
                account,
                checkpoint_digest: cp.digest(),
            });
            states.push(cp.value().state.clone());
        }
        let result = OriginSubject {
            subject,
            endpoint_binding: Blob(sign_endpoint_binding(&binding, &self.signer)?),
            checkpoints,
            acting,
            agreement,
            source,
            states,
        };
        self.federation_origin_current(&result, session, clock)?;
        Ok(result)
    }
    pub fn federation_origin_current(
        &mut self,
        prepared: &OriginSubject,
        session: &AuthenticatedSession,
        clock: TimeBounds,
    ) -> Result<()> {
        let t = now(clock)?;
        self.store
            .read(Duration::from_secs(2), |db| {
                let run = || -> Domain<()> {
                    let agreement = current(db, prepared.agreement, t)?;
                    let (subject, acting, accounts) =
                        subject_in(db, self.home, session, &prepared.source, &agreement, t)?;
                    if subject != prepared.subject
                        || acting != prepared.acting
                        || accounts.len() != prepared.states.len()
                    {
                        return deny("OriginChanged");
                    }
                    for (account, old) in accounts.iter().zip(&prepared.states) {
                        let state = crate::identity::continuity::snapshot(db, self.home, *account)?;
                        if encode(&state)? != encode(old)? {
                            return conflict("OriginIdentityChanged");
                        }
                    }
                    Ok(())
                };
                Ok(run())
            })?
            .map_err(convert)
    }
}
