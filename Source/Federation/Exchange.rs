// SPDX-License-Identifier: Apache-2.0
//! A verified foreign request retains its exact evidence through the home transaction.
use super::*;
use rusqlite::{OptionalExtension, params};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct VerifiedRemoteSubmission {
    verified: VerifiedAction,
    gateway: GatewayContext,
    binding: Verified<EndpointBinding>,
    challenge: Verified<FederationChallenge>,
    assertion: Verified<OriginAssertion>,
    destination_privacy: FederationPrivacy,
}
impl VerifiedRemoteSubmission {
    pub fn action(&self) -> &VerifiedAction {
        &self.verified
    }
    pub fn agreement(&self) -> AgreementRef {
        self.gateway.agreement
    }
}
pub(crate) fn gateway_binding(
    a: &AgreementState,
    g: &GatewayContext,
    receiver: ServiceId,
) -> Domain<()> {
    let expected = if receiver == a.agreement.home {
        &a.agreement.home_gateway
    } else if receiver == a.agreement.origin {
        &a.agreement.origin_gateway
    } else {
        return deny("GatewayReceiver");
    };
    if a.reference != g.agreement
        || g.transport.destination != receiver
        || g.transport.network != expected.network
        || g.transport.principal != expected.principal
        || g.transport.service_endpoint != expected.service_endpoint
        || g.transport.generation == 0
    {
        return deny("GatewayBinding");
    }
    Ok(())
}
fn challenge_current(
    db: &Connection,
    challenge: &Verified<FederationChallenge>,
    gateway: &GatewayContext,
    boot: Id,
    now: TimeBounds,
) -> Domain<()> {
    let c = challenge.value();
    if c.service_boot != boot
        || c.gateway != gateway.principal()
        || c.agreement != gateway.agreement
        || !now.permits(c.issued_ms, c.expires_ms)
    {
        return Err(Fault::Reject(
            ErrorCode::Unavailable,
            "FederationChallengeExpired",
        ));
    }
    let row:Option<(Vec<u8>,u64,bool)>=db.query_row("SELECT signed,deadline,consumed FROM federation_challenges WHERE nonce=?1 AND boot=?2 AND gateway=?3",params![c.nonce.as_hex(),boot.as_hex(),gateway.principal().as_hex()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
    if !row.is_some_and(|(bytes, deadline, used)| {
        !used && bytes == challenge.signed_bytes() && now.boot_ms < deadline
    }) {
        return deny("FederationChallengeConsumed");
    }
    Ok(())
}
#[derive(Clone, Copy)]
struct Evidence<'a> {
    binding: &'a Verified<EndpointBinding>,
    challenge: &'a Verified<FederationChallenge>,
    assertion: &'a Verified<OriginAssertion>,
    gateway: &'a GatewayContext,
    privacy: &'a FederationPrivacy,
}
fn evidence_in(
    db: &Connection,
    a: &AgreementState,
    evidence: Evidence<'_>,
    boot: Id,
    now: TimeBounds,
) -> Domain<RemoteAdmission> {
    let Evidence {
        binding,
        challenge,
        assertion,
        gateway,
        privacy,
    } = evidence;
    gateway_binding(a, gateway, a.agreement.home)?;
    challenge_current(db, challenge, gateway, boot, now)?;
    let b = binding.value();
    let c = challenge.value();
    let s = assertion.value();
    if now.upper_ms >= s.source_not_after_ms {
        return Err(Fault::Reject(
            ErrorCode::Unavailable,
            "SourceAuthorityExpired",
        ));
    }
    let adm = admission(db, c.admission, now)?;
    if adm.agreement != a.reference
        || s.admission != adm.reference
        || s.agreement != a.reference
        || c.home != a.agreement.home
        || c.origin != a.agreement.origin
        || s.home != c.home
        || s.origin != c.origin
        || s.subject != c.subject
        || s.challenge_digest != challenge.digest()
        || s.endpoint_binding_digest != binding.digest()
        || b.origin != a.agreement.origin
        || b.account != adm.acting.account
        || b.endpoint != adm.acting.endpoint
        || binding.digest() != adm.acting.binding_digest
        || b.security_generation != adm.acting.security_generation
        || b.enrolment_generation != adm.acting.enrolment_generation
        || s.endpoint != b.endpoint
        || s.security_generation != b.security_generation
        || s.enrolment_generation != b.enrolment_generation
        || s.transport_network != a.agreement.origin.network
        || s.transport_principal != b.transport_principal
        || s.transport_generation == 0
        || s.transport_grant_generation == 0
        || !now.permits(b.not_before_ms, b.expires_ms)
        || s.source_evaluated_ms > now.upper_ms
        || s.source_not_after_ms > s.authority.expires_at_ms
    {
        return deny("FederationEvidence");
    }
    privacy
        .validate()
        .map_err(|_| Fault::Reject(ErrorCode::Denied, "DestinationPrivacy"))?;
    let endpoint = crate::identity::endpoint(db, b.account, b.endpoint)?
        .ok_or(Fault::Reject(ErrorCode::Denied, "EndpointDisabled"))?;
    if endpoint.acting != adm.acting
        || endpoint.key.to_bytes() != *b.endpoint_key.as_bytes()
        || endpoint.principal != b.transport_principal
    {
        return deny("ForeignEndpointBinding");
    }
    for reference in &s.checkpoints {
        let cp = identities::checkpoint(db, reference.checkpoint_digest)?;
        let retained: String = db.query_row(
            "SELECT checkpoint FROM federation_identities WHERE account=?1",
            [reference.account.to_string()],
            |r| r.get(0),
        )?;
        if cp.account != reference.account
            || cp.origin != a.agreement.origin
            || retained != reference.checkpoint_digest.as_hex()
            || !now.permits(cp.issued_ms, cp.expires_ms)
        {
            return deny("OriginCheckpointCurrent");
        }
    }
    Ok(adm)
}
fn actor_in(
    db: &Connection,
    verified: &VerifiedAction,
    admission: &RemoteAdmission,
    assertion: &OriginAssertion,
) -> Domain<()> {
    let action = verified.action();
    let acting = action.actor.acting();
    if *acting != admission.acting
        || action.home != admission.home
        || action.agreement != Some(admission.agreement)
    {
        return deny("RemoteActionBinding");
    }
    let current = crate::identity::endpoint(db, acting.account, acting.endpoint)?
        .ok_or(Fault::Reject(ErrorCode::Denied, "EndpointDisabled"))?;
    if verified.signer_key() != Id::from_bytes(current.key.to_bytes()) {
        return deny("RemoteSigner");
    }
    match (&current.classification, &action.actor) {
        (AccountClass::Human, Actor::Direct { .. }) => {}
        (
            AccountClass::Agent { operator: a },
            Actor::IndependentAgent { operator: b, .. } | Actor::Delegated { operator: b, .. },
        ) if a == b => {}
        _ => return deny("ActorClassification"),
    }
    if crate::conversations::subjects(&action.actor)
        .iter()
        .any(|a| a.origin != admission.home.network && a.origin != admission.origin.network)
    {
        return deny("ThirdOrigin");
    }
    let mut expected = crate::conversations::subjects(&action.actor)
        .into_iter()
        .filter(|a| a.origin == admission.origin.network)
        .collect::<Vec<_>>();
    expected.sort();
    expected.dedup();
    if expected
        != assertion
            .checkpoints
            .iter()
            .map(|c| c.account)
            .collect::<Vec<_>>()
    {
        return deny("OriginCheckpointSubjects");
    }
    if let Actor::Delegated {
        represented,
        represented_security_generation,
        ..
    } = action.actor
    {
        let security: Option<u64> = db
            .query_row(
                "SELECT security FROM hrc_accounts WHERE id=?1",
                [represented.to_string()],
                |r| r.get(0),
            )
            .optional()?;
        if security != Some(represented_security_generation) {
            return deny("RepresentedBinding");
        }
    }
    match action.target {
        Target::Room(room) => {
            if !admission.rooms.contains(&room) {
                return deny("AdmissionRoomScope");
            }
        }
        Target::Account(account) => {
            if account != acting.account
                && account != action.actor.represented()
                && !matches!(action.operation, Operation::AccountPublicIdentity)
            {
                return deny("AdmissionAccountScope");
            }
        }
        Target::Service => {
            if matches!(
                action.operation,
                Operation::RoomCreate | Operation::DirectCreate
            ) {
                return deny("SharedRoomCreation");
            }
        }
        Target::Delegation(_) => {}
        Target::Endpoint(_) => return deny("OriginOwnedEndpoint"),
    }
    if matches!(
        action.operation,
        Operation::AccountSetNickname
            | Operation::AccountRecover
            | Operation::AccountRotateRecovery
            | Operation::AccountEnrolEndpoint
            | Operation::AccountDisableEndpoint
            | Operation::AccountDevices
            | Operation::AccountContinuity
            | Operation::AccountLifecycleOutcome
    ) {
        return deny("OriginOwnedOperation");
    }
    Ok(())
}
fn room_in(
    db: &Connection,
    agreement: &AgreementState,
    admission: &RemoteAdmission,
    remote: &VerifiedRemoteSubmission,
    room: RoomId,
) -> Domain<()> {
    if admission.agreement != agreement.reference || !admission.rooms.contains(&room) {
        return deny("AdmissionRoomScope");
    }
    let shared = agreement
        .agreement
        .rooms
        .iter()
        .find(|shared| shared.room == room)
        .ok_or(Fault::Reject(ErrorCode::Denied, "SharedRoom"))?;
    if shared.privacy == PrivacyRequirement::AttestedRelayArrival
        && (!remote.destination_privacy.attested_relay()
            || !remote.assertion.value().source_privacy.attested_relay())
    {
        return deny("FederationPrivacy");
    }
    let mode: u8 = db.query_row(
        "SELECT mode FROM hrc_rooms WHERE id=?1",
        [room.to_string()],
        |r| r.get(0),
    )?;
    if !crate::conversations::mode_value(mode).is_ok_and(|value| value == shared.confidentiality) {
        return deny("FederationRoomMode");
    }
    Ok(())
}

pub(crate) fn list_rooms(
    db: &Transaction<'_>,
    remote: &VerifiedRemoteSubmission,
    now: TimeBounds,
) -> Domain<Outcome> {
    let agreement = current(db, remote.agreement(), now)?;
    let admission = admission(db, remote.challenge.value().admission, now)?;
    crate::conversations::list(db, remote.verified.action(), now, |room| {
        room_in(db, &agreement, &admission, remote, room)
    })
}

pub(crate) fn authenticate_in(
    db: &Connection,
    remote: &VerifiedRemoteSubmission,
    boot: Id,
    now: TimeBounds,
) -> Domain<()> {
    let a = current(db, remote.gateway.agreement, now)?;
    let adm = evidence_in(
        db,
        &a,
        Evidence {
            binding: &remote.binding,
            challenge: &remote.challenge,
            assertion: &remote.assertion,
            gateway: &remote.gateway,
            privacy: &remote.destination_privacy,
        },
        boot,
        now,
    )?;
    actor_in(db, &remote.verified, &adm, remote.assertion.value())?;
    let action = remote.verified.action();
    let room = match action.target {
        Target::Room(room) => Some(room),
        Target::Account(_) if action.operation == Operation::AccountPublicIdentity => {
            Some(unpack::<crate::identity::PublicIdentityRequest>(&action.body)?.room)
        }
        _ => None,
    };
    if let Some(room) = room {
        room_in(db, &a, &adm, remote, room)?;
    }
    let window = remote.verified.action().operation_id.window;
    let row:Option<(String,String,u64,Vec<u8>)>=db.query_row("SELECT agreement,admission,admission_revision,actor FROM federation_windows WHERE id=?1",[window.as_hex()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
    if !row.is_some_and(|(agreement, admission, revision, actor)| {
        agreement == remote.gateway.agreement.id.as_hex()
            && admission == adm.reference.id.as_hex()
            && revision == adm.reference.revision
            && decode::<EndpointActor>(&actor).is_ok_and(|a| a == adm.acting)
    }) {
        return deny("RemoteRetryWindow");
    }
    Ok(())
}
pub(crate) fn final_check(
    db: &Connection,
    remote: &VerifiedRemoteSubmission,
    boot: Id,
    now: TimeBounds,
) -> Domain<()> {
    authenticate_in(db, remote, boot, now)
}
pub(crate) fn consume_in(
    db: &Transaction<'_>,
    remote: &VerifiedRemoteSubmission,
) -> rusqlite::Result<()> {
    if db.execute(
        "UPDATE federation_challenges SET consumed=1 WHERE nonce=?1 AND consumed=0",
        [remote.challenge.value().nonce.as_hex()],
    )? != 1
    {
        return Err(rusqlite::Error::InvalidQuery);
    }
    Ok(())
}
pub(crate) fn creation_evidence(
    db: &Connection,
    remote: &VerifiedRemoteSubmission,
) -> Domain<Option<OwnerCheckpointEvidence>> {
    if remote.verified.action().operation != Operation::DelegationCreate {
        return Ok(None);
    }
    let account = remote.verified.action().actor.acting().account;
    let reference = remote
        .assertion
        .value()
        .checkpoints
        .iter()
        .find(|c| c.account == account)
        .ok_or(Fault::Reject(ErrorCode::Denied, "OwnerCheckpoint"))?;
    let cp = identities::checkpoint(db, reference.checkpoint_digest)?;
    let signed: Vec<u8> = db.query_row(
        "SELECT signed FROM federation_checkpoints WHERE digest=?1",
        [reference.checkpoint_digest.as_hex()],
        |r| r.get(0),
    )?;
    Ok(Some(OwnerCheckpointEvidence {
        origin: cp.origin,
        checkpoint_digest: reference.checkpoint_digest,
        head: cp.head,
        checkpoint: Blob(signed),
        creation_assertion: Blob(remote.assertion.signed_bytes().to_vec()),
    }))
}
pub(crate) fn record_creation(
    db: &Transaction<'_>,
    remote: &VerifiedRemoteSubmission,
    outcome: &Outcome,
) -> Domain<()> {
    if let Some(evidence) = creation_evidence(db, remote)? {
        let Outcome::Committed { body, .. } = outcome else {
            return invalid("GrantCreationOutcome");
        };
        let grant: GrantRef = unpack(body)?;
        db.execute(
            "INSERT INTO federation_grant_proofs VALUES(?1,?2)",
            params![grant.id.as_hex(), encode(&evidence)?],
        )?;
    }
    Ok(())
}
pub(crate) fn constrain(
    db: &Connection,
    remote: &VerifiedRemoteSubmission,
    mut permit: crate::delegation::Permit,
    now: TimeBounds,
) -> Domain<crate::delegation::Permit> {
    let a = current(db, remote.agreement(), now)?;
    let action = remote.verified.action();
    let room = match action.target {
        Target::Room(r) => Some(r),
        Target::Account(_) if action.operation == Operation::AccountPublicIdentity => {
            Some(unpack::<crate::identity::PublicIdentityRequest>(&action.body)?.room)
        }
        _ => None,
    };
    if let Some(room) = room {
        let shared = a
            .agreement
            .rooms
            .iter()
            .find(|r| r.room == room)
            .ok_or(Fault::Reject(ErrorCode::Denied, "SharedRoom"))?;
        permit.history_from = permit
            .history_from
            .max(shared.history_from_ms)
            .max(now.upper_ms.saturating_sub(shared.retention_ms));
        if matches!(
            action.operation,
            Operation::RoomSetTopic
                | Operation::ModerationSilence
                | Operation::ModerationKick
                | Operation::ModerationBan
                | Operation::CryptoPropose
                | Operation::CryptoCommit
                | Operation::CryptoRecover
        ) && !shared
            .moderator_accounts
            .contains(&action.actor.represented())
        {
            return deny("FederationModeratorScope");
        }
    }
    Ok(permit)
}
impl Home {
    pub fn federation_challenge(
        &mut self,
        gateway: &GatewayContext,
        admission_ref: AdmissionRef,
        subject: FederationSubject,
        clock: TimeBounds,
        permit: &dyn Fn() -> bool,
    ) -> Result<Blob> {
        let home = self.home;
        let boot = self.federation_boot;
        let signer = self.signer.clone();
        write(self, "HRC.Federation.Challenge", clock, |db, now| {
            let a = current(db, gateway.agreement, now)?;
            gateway_binding(&a, gateway, home)?;
            if home != a.agreement.home || !permit() {
                return deny("GatewayAuthority");
            }
            let adm = admission(db, admission_ref, now)?;
            if adm.agreement != a.reference {
                return deny("AdmissionAgreement");
            }
            db.execute(
                "DELETE FROM federation_challenges WHERE boot<>?1 OR deadline<=?2 OR consumed=1",
                params![boot.as_hex(), now.boot_ms],
            )?;
            let encoded = encode(&subject)?;
            db.execute(
                "DELETE FROM federation_challenges WHERE gateway=?1 AND subject=?2",
                params![gateway.principal().as_hex(), encoded],
            )?;
            let total: u64 =
                db.query_row("SELECT count(*) FROM federation_challenges", [], |r| {
                    r.get(0)
                })?;
            let peer: u64 = db.query_row(
                "SELECT count(*) FROM federation_challenges WHERE gateway=?1",
                [gateway.principal().as_hex()],
                |r| r.get(0),
            )?;
            if total >= 4 || peer >= 2 {
                return Err(Fault::Reject(
                    ErrorCode::Overloaded,
                    "FederationChallengeCapacity",
                ));
            }
            if !crate::home::federation_budget(db, gateway.principal(), now.lower_ms)? {
                return Err(Fault::Reject(
                    ErrorCode::RateLimited,
                    "FederationChallengeBudget",
                ));
            }
            let challenge = FederationChallenge {
                profile: 1,
                home,
                origin: a.agreement.origin,
                agreement: a.reference,
                gateway: gateway.principal(),
                admission: admission_ref,
                subject,
                nonce: random()?,
                service_boot: boot,
                issued_ms: now.lower_ms,
                expires_ms: (now.lower_ms + 5000)
                    .min(a.agreement.expires_ms)
                    .min(adm.expires_ms),
            };
            let bytes = sign_federation_challenge(&challenge, &signer).map_err(|_| {
                Fault::Reject(ErrorCode::InvalidInput, "FederationChallengeEncoding")
            })?;
            db.execute(
                "INSERT INTO federation_challenges VALUES(?1,?2,?3,?4,?5,?6,?7,0)",
                params![
                    challenge.nonce.as_hex(),
                    boot.as_hex(),
                    gateway.principal().as_hex(),
                    encoded,
                    now.boot_ms + 5000,
                    challenge.expires_ms,
                    bytes
                ],
            )?;
            if !permit() {
                return Err(Fault::Sql(rusqlite::Error::InvalidQuery));
            }
            Ok(Blob(bytes))
        })
    }
    pub fn federation_verify(
        &mut self,
        gateway: &GatewayContext,
        envelope: &FederationEnvelope,
        privacy: &FederationPrivacy,
        clock: TimeBounds,
        permit: &dyn Fn() -> bool,
    ) -> Result<VerifiedRemoteSubmission> {
        if envelope.profile != 1 || envelope.agreement != gateway.agreement || !permit() {
            return Err(refused("FederationEnvelope"));
        }
        encode_federation(envelope)?;
        let a = self.federation_agreement(gateway.agreement, clock)?;
        let binding = verify_endpoint_binding(
            &envelope.endpoint_binding.0,
            &key(a.agreement.origin_service_key)?,
        )?;
        let verified = verify_action(&envelope.action.0, &key(binding.value().endpoint_key)?)?;
        let bound = if verified.action().operation.is_crypto_transition() {
            224 * 1024
        } else {
            48 * 1024
        };
        if envelope.action.0.len() > bound
            || envelope.endpoint_binding.0.len() > 2048
            || envelope.challenge.0.len() > 2048
            || envelope.origin_assertion.0.len() > 8192
        {
            return Err(refused("FederationEvidenceSize"));
        }
        let challenge =
            verify_federation_challenge(&envelope.challenge.0, &self.signer.verifying_key())?;
        let assertion = verify_origin_assertion(
            &envelope.origin_assertion.0,
            &key(a.agreement.origin_attestor_key)?,
        )?;
        if envelope.admission != challenge.value().admission
            || challenge.value().subject
                != (FederationSubject::Action {
                    action_digest: verified.digest(),
                    operation_id: verified.action().operation_id,
                })
        {
            return Err(refused("FederationSubject"));
        }
        let result = VerifiedRemoteSubmission {
            verified,
            gateway: gateway.clone(),
            binding,
            challenge,
            assertion,
            destination_privacy: privacy.clone(),
        };
        let t = now(clock)?;
        self.store
            .read(Duration::from_secs(2), |db| {
                Ok(authenticate_in(db, &result, self.federation_boot, t))
            })?
            .map_err(convert)?;
        Ok(result)
    }
    pub fn federation_open_remote(
        &mut self,
        gateway: &GatewayContext,
        exchange: &RemoteSessionExchange,
        privacy: &FederationPrivacy,
        clock: TimeBounds,
        permit: &dyn Fn() -> bool,
    ) -> Result<Blob> {
        let a = self.federation_agreement(gateway.agreement, clock)?;
        let binding = verify_endpoint_binding(
            &exchange.endpoint_binding.0,
            &key(a.agreement.origin_service_key)?,
        )?;
        let request = verify_remote_session_request(
            &exchange.request.0,
            &key(binding.value().endpoint_key)?,
        )?;
        let challenge =
            verify_federation_challenge(&exchange.challenge.0, &self.signer.verifying_key())?;
        let assertion = verify_origin_assertion(
            &exchange.origin_assertion.0,
            &key(a.agreement.origin_attestor_key)?,
        )?;
        let home = self.home;
        let boot = self.federation_boot;
        let signer = self.signer.clone();
        let evidence = Evidence {
            binding: &binding,
            challenge: &challenge,
            assertion: &assertion,
            gateway,
            privacy,
        };
        write(self, "HRC.Federation.RemoteSession", clock, |db, t| {
            let a = current(db, gateway.agreement, t)?;
            let adm = evidence_in(db, &a, evidence, boot, t)?;
            let r = request.value();
            if !permit()
                || r.home != home
                || r.origin != a.agreement.origin
                || r.agreement != a.reference
                || r.account != adm.acting.account
                || r.endpoint != adm.acting.endpoint
                || r.endpoint_binding_digest != binding.digest()
                || !t.permits(r.created_ms, r.expires_ms)
                || challenge.value().subject
                    != (FederationSubject::Session {
                        request_digest: request.digest(),
                        request: r.request,
                    })
            {
                return deny("RemoteSessionBinding");
            }
            let ep = crate::identity::endpoint(db, r.account, r.endpoint)?
                .ok_or(Fault::Reject(ErrorCode::Denied, "EndpointDisabled"))?;
            let mut expected = vec![r.account];
            if let AccountClass::Agent { operator } = ep.classification {
                expected.push(operator)
            }
            expected.sort();
            expected.dedup();
            if expected
                != assertion
                    .value()
                    .checkpoints
                    .iter()
                    .map(|c| c.account)
                    .collect::<Vec<_>>()
            {
                return deny("BootstrapIdentitySubjects");
            }
            let existing: Option<(Vec<u8>, Vec<u8>)> = db
                .query_row(
                    "SELECT digest,receipt FROM federation_bootstrap WHERE request=?1",
                    [r.request.as_hex()],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()?;
            let bytes = if let Some((digest, receipt)) = existing {
                if digest.as_slice() != request.digest().as_bytes() {
                    return conflict("RemoteSessionContent");
                }
                let previous = verify_remote_session_ready(&receipt, &signer.verifying_key())
                    .map_err(|_| rusqlite::Error::InvalidQuery)?;
                if previous.value().admission != adm.reference
                    || previous.value().acting != adm.acting
                    || previous.value().agreement != a.reference
                    || previous.value().window.expires_ms <= t.upper_ms
                {
                    return conflict("RemoteSessionAdmissionChanged");
                }
                receipt
            } else {
                db.execute(
                    "DELETE FROM federation_bootstrap WHERE expires<=?1",
                    [t.upper_ms.saturating_sub(7 * DAY)],
                )?;
                let receipts: u64 =
                    db.query_row("SELECT count(*) FROM federation_bootstrap", [], |r| {
                        r.get(0)
                    })?;
                if receipts >= 65536 {
                    return Err(Fault::Reject(
                        ErrorCode::Overloaded,
                        "BootstrapReceiptCapacity",
                    ));
                }
                let reusable:Option<RetryWindow>=db.query_row("SELECT w.id,w.expires FROM hrc_windows w JOIN federation_windows f ON f.id=w.id WHERE w.account=?1 AND w.endpoint=?2 AND f.agreement=?3 AND f.admission=?4 AND f.admission_revision=?5 AND f.actor=?6 AND w.expires>?7 ORDER BY w.expires DESC LIMIT 1",params![r.account.to_string(),r.endpoint.as_hex(),a.reference.id.as_hex(),adm.reference.id.as_hex(),adm.reference.revision,encode(&adm.acting)?,t.upper_ms+300_000],|row|Ok(RetryWindow{id:id_column(row,0)?,expires_ms:row.get(1)?})).optional()?;
                let window = if let Some(window) = reusable {
                    window
                } else {
                    let count:u64=db.query_row("SELECT count(*) FROM hrc_windows WHERE account=?1 AND endpoint=?2 AND expires>?3",params![r.account.to_string(),r.endpoint.as_hex(),t.upper_ms],|row|row.get(0))?;
                    if count >= 4 {
                        return Err(Fault::Reject(ErrorCode::Overloaded, "RetryWindowCapacity"));
                    }
                    let window = RetryWindow {
                        id: random()?,
                        expires_ms: (t.lower_ms + DAY)
                            .min(adm.expires_ms)
                            .min(a.agreement.expires_ms),
                    };
                    db.execute(
                        "INSERT INTO hrc_windows VALUES(?1,?2,?3,?4)",
                        params![
                            window.id.as_hex(),
                            r.account.to_string(),
                            r.endpoint.as_hex(),
                            window.expires_ms
                        ],
                    )?;
                    db.execute(
                        "INSERT INTO federation_windows VALUES(?1,?2,?3,?4,?5)",
                        params![
                            window.id.as_hex(),
                            a.reference.id.as_hex(),
                            adm.reference.id.as_hex(),
                            adm.reference.revision,
                            encode(&adm.acting)?
                        ],
                    )?;
                    window
                };
                let ready = RemoteSessionReady {
                    profile: 1,
                    home,
                    origin: a.agreement.origin,
                    agreement: a.reference,
                    admission: adm.reference,
                    request: r.request,
                    request_digest: request.digest(),
                    acting: adm.acting.clone(),
                    classification: ep.classification,
                    checkpoints: assertion.value().checkpoints.clone(),
                    window,
                    source_privacy: assertion.value().source_privacy.clone(),
                    destination_privacy: privacy.clone(),
                };
                let bytes = sign_remote_session_ready(&ready, &signer)
                    .map_err(|_| Fault::Reject(ErrorCode::InvalidInput, "RemoteSessionEncoding"))?;
                db.execute(
                    "INSERT INTO federation_bootstrap VALUES(?1,?2,?3,?4)",
                    params![
                        r.request.as_hex(),
                        request.digest().as_bytes(),
                        bytes,
                        r.expires_ms
                    ],
                )?;
                bytes
            };
            let final_time = clock.refresh().map_err(|_| rusqlite::Error::InvalidQuery)?;
            evidence_in(db, &a, evidence, boot, final_time)?;
            if !permit() || !final_time.permits(r.created_ms, r.expires_ms) {
                return Err(Fault::Sql(rusqlite::Error::InvalidQuery));
            }
            db.execute(
                "UPDATE federation_challenges SET consumed=1 WHERE nonce=?1",
                [challenge.value().nonce.as_hex()],
            )?;
            Ok(Blob(bytes))
        })
    }
}
