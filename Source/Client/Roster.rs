// SPDX-License-Identifier: Apache-2.0
//! MLS leaves require pinned account continuity and endpoint-signed key enrolment evidence.
use super::{Client, Error, Result, cache, encrypted::failure};
use crate::{confidential as domain, crypto, delegation, protocol::*};
impl Client {
    pub(super) fn trusted_roster(
        &mut self,
        room: RoomId,
        members: &[domain::Member],
        current: bool,
    ) -> Result<crypto::ApprovedRoster> {
        for member in members {
            self.verify_member(room, member, current)?;
        }
        crypto::ApprovedRoster::new(room, members.iter().map(|m| m.credential.clone()).collect())
            .map_err(failure)
    }
    fn verify_member(
        &mut self,
        room: RoomId,
        member: &domain::Member,
        current: bool,
    ) -> Result<()> {
        let actor = member.actor.acting();
        if member.credential.room != room || member.credential.actor != *actor {
            return Err(Error::Input);
        }
        let chain = self.trusted_chain(actor.account)?;
        let eligible = if current {
            vec![chain.latest()]
        } else {
            chain.records.iter().map(|r| &r.state).collect()
        };
        let endpoint = eligible
            .iter()
            .find_map(|state| state.endpoints.iter().find(|e| e.actor == *actor))
            .ok_or_else(|| Error::Rejected {
                code: ErrorCode::Denied,
                detail: "UntrustedEndpointGeneration".into(),
            })?;
        let key = VerifyingKey::from_bytes(endpoint.key.as_bytes()).map_err(|_| Error::Input)?;
        let registration = verify_action(&member.registration.0, &key).map_err(|_| Error::Input)?;
        let action = registration.action();
        let body: domain::EnrolKey = action.body.deserialized().map_err(|_| Error::Input)?;
        if action.home != room.home
            || action.operation != Operation::CryptoEnrolEndpoint
            || action.target != Target::Account(actor.account)
            || action.actor.acting() != actor
            || body.mls_key != member.credential.mls_key
        {
            return Err(Error::Input);
        }
        match (&chain.latest().classification, &member.actor) {
            (AccountClass::Human, Actor::Direct { .. }) => {
                if member.delegation.is_some() {
                    return Err(Error::Input);
                }
            }
            (AccountClass::Agent { operator: a }, Actor::IndependentAgent { operator: b, .. })
                if a == b =>
            {
                if member.delegation.is_some() {
                    return Err(Error::Input);
                }
            }
            (
                AccountClass::Agent { operator: a },
                Actor::Delegated {
                    operator: b,
                    represented,
                    represented_security_generation,
                    grant,
                    ..
                },
            ) if a == b => {
                let evidence = member.delegation.as_ref().ok_or(Error::Input)?;
                let authorized = &evidence.grant;
                if authorized.reference != *grant
                    || authorized.home != room.home
                    || authorized.owner != *represented
                    || authorized.owner_security_generation != *represented_security_generation
                    || authorized.operator != *b
                    || authorized.scope.agent != *actor
                    || !authorized.scope.rooms.contains(&room)
                    || !authorized.scope.operations.iter().any(|op| {
                        matches!(
                            op,
                            Operation::HistoryPage
                                | Operation::EventsSubscribe
                                | Operation::EventsResume
                                | Operation::CryptoHistory
                        )
                    })
                {
                    return Err(Error::Input);
                }
                let owner = self.trusted_chain(*represented)?;
                let previous = owner.at(evidence.position).ok_or(Error::Input)?;
                if previous.classification != AccountClass::Human
                    || previous.security_generation != *represented_security_generation
                {
                    return Err(Error::Input);
                }
                let mut verified = None;
                for endpoint in &previous.endpoints {
                    if let Ok(key) = VerifyingKey::from_bytes(endpoint.key.as_bytes())
                        && let Ok(signed) = verify_action(&evidence.authorization.0, &key)
                        && signed.action().actor
                            == (Actor::Direct {
                                acting: endpoint.actor.clone(),
                            })
                    {
                        verified = Some(signed);
                        break;
                    }
                }
                let creation = verified.ok_or(Error::Input)?;
                let action = creation.action();
                let scope: delegation::Create =
                    action.body.deserialized().map_err(|_| Error::Input)?;
                if action.operation != Operation::DelegationCreate
                    || action.home != room.home
                    || action.target != Target::Account(*represented)
                    || cache::encode(&scope).map_err(|_| Error::Input)?
                        != cache::encode(&authorized.scope).map_err(|_| Error::Input)?
                {
                    return Err(Error::Input);
                }
                if current {
                    let now = self.profile.clock.sample().map_err(|_| Error::Clock)?;
                    if authorized.state != delegation::State::Active
                        || !now.permits(scope.not_before_ms, scope.expires_ms)
                        || !now.permits(scope.history_from_ms, scope.history_until_ms)
                        || owner.latest().security_generation != *represented_security_generation
                    {
                        return Err(Error::Rejected {
                            code: ErrorCode::Expired,
                            detail: "EncryptedDelegationUnavailable".into(),
                        });
                    }
                }
            }
            _ => return Err(Error::Input),
        }
        Ok(())
    }
}
