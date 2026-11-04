// SPDX-License-Identifier: Apache-2.0
//! Bounded origin forwarding through a separately admitted destination companion.
use super::*;
use crate::{
    federation::{self, OriginSubject, SourceSubject},
    service::federation::Route,
};
use serde::Serialize;
#[path = "FederationAdmission.rs"]
mod route_admission;
#[path = "FederationWatch.rs"]
mod watch;
pub(super) use watch::Maintenance;

pub(super) struct OutboundRoute {
    agreement: AgreementRef,
    admission: route_admission::Admission,
    outbound: Mutex<Outbound>,
}

pub(super) struct Outbound {
    route: Route,
    gateway_key: SigningKey,
    attestor: SigningKey,
    connected: Option<Connection>,
    synchronized: std::collections::BTreeMap<AccountId, Id>,
    watch_after: Option<AccountId>,
    import_progress: std::collections::BTreeMap<AccountId, (Id, u64)>,
}
struct Connection {
    _companion: Companion,
    stream: Stream,
    home_key: VerifyingKey,
    service_boot: Id,
}
pub(super) fn load(directory: &Path) -> Result<Vec<OutboundRoute>> {
    crate::service::federation::load(directory)
        .map_err(|_| Error::Configuration)?
        .into_iter()
        .map(|route| {
            let gateway_key = files::key(&route.gateway_key).map_err(|_| Error::Configuration)?;
            let attestor = files::key(&route.attestor_key).map_err(|_| Error::Configuration)?;
            Ok(OutboundRoute {
                agreement: route.agreement,
                admission: route_admission::Admission::default(),
                outbound: Mutex::new(Outbound {
                    route,
                    gateway_key,
                    attestor,
                    connected: None,
                    synchronized: Default::default(),
                    watch_after: None,
                    import_progress: Default::default(),
                }),
            })
        })
        .collect()
}
fn admission_error(error: route_admission::Error) -> Error {
    match error {
        route_admission::Error::Busy => Error::AuthorityAdmissionBusy,
        route_admission::Error::Stopped => Error::AuthorityAdmissionStopped,
        route_admission::Error::Expired => Error::AuthorityAdmissionExpired,
        route_admission::Error::Unavailable => Error::State,
    }
}
fn domain_error(error: federation::Error) -> Error {
    match error {
        federation::Error::Refused { code, detail } => Error::ForwardRefused {
            code,
            detail: detail.into(),
            retry_after_ms: matches!(
                code,
                ErrorCode::Unavailable | ErrorCode::Overloaded | ErrorCode::RateLimited
            )
            .then_some(1000),
        },
        federation::Error::Protocol(_) => Error::Authentication,
        federation::Error::Storage(_) => Error::State,
    }
}
#[derive(Clone, Copy, Debug)]
enum OriginAuthorityFailure {
    IdentityCheckpointChanged,
    IdentityAuthorityRead,
    IdentityAuthorityBeforePage,
    IdentityPageUnavailable,
    IdentityAuthorityAfterPage,
    ChallengeNotCurrent,
    OriginAuthorityRead,
    AssertionEvidenceUnavailable,
    AssertionClockOrBinding,
    AssertionLifetime,
    AssertionPrivacy,
    AssertionNoLongerPermitted,
}
impl OriginAuthorityFailure {
    fn code(self) -> &'static str {
        match self {
            Self::IdentityCheckpointChanged => "IdentityCheckpointChanged",
            Self::IdentityAuthorityRead => "IdentityAuthorityRead",
            Self::IdentityAuthorityBeforePage => "IdentityAuthorityBeforePage",
            Self::IdentityPageUnavailable => "IdentityPageUnavailable",
            Self::IdentityAuthorityAfterPage => "IdentityAuthorityAfterPage",
            Self::ChallengeNotCurrent => "ChallengeNotCurrent",
            Self::OriginAuthorityRead => "OriginAuthorityRead",
            Self::AssertionEvidenceUnavailable => "AssertionEvidenceUnavailable",
            Self::AssertionClockOrBinding => "AssertionClockOrBinding",
            Self::AssertionLifetime => "AssertionLifetime",
            Self::AssertionPrivacy => "AssertionPrivacy",
            Self::AssertionNoLongerPermitted => "AssertionNoLongerPermitted",
        }
    }
}
fn authority_failure(
    shared: &Shared,
    reason: OriginAuthorityFailure,
    check: Option<&crate::hypernet::AuthorityCheck>,
) -> Error {
    shared.report_check("FederationOriginAuthorityFailure", reason.code(), check);
    Error::Authority
}
fn key(value: Id) -> Result<VerifyingKey> {
    VerifyingKey::from_bytes(value.as_bytes()).map_err(|_| Error::Authentication)
}
impl Outbound {
    fn failed(&mut self, error: &Error) {
        // A fully verified refusal leaves framing synchronized. Reconnect only
        // when transport, framing or authentication no longer establishes that.
        if !matches!(
            error,
            Error::ForwardRefused { .. } | Error::AuthorityAdmissionBusy
        ) {
            self.connected = None;
            self.synchronized.clear();
        }
        if matches!(
            error,
            Error::ForwardRefused {
                code: ErrorCode::Conflict,
                ..
            }
        ) {
            self.import_progress.clear();
        }
    }
    fn connect(
        &mut self,
        shared: &Shared,
        agreement: &FederationAgreement,
        end: u64,
    ) -> Result<()> {
        if self.connected.is_some() {
            return Ok(());
        }
        self.synchronized.clear();
        if agreement.origin != shared.config.descriptor.home
            || self.gateway_key.verifying_key().as_bytes()
                != agreement.home_gateway.signing_key.as_bytes()
            || self.attestor.verifying_key().as_bytes() != agreement.origin_attestor_key.as_bytes()
        {
            return Err(Error::Authentication);
        }
        let companion = Companion::new(&self.route.companion).map_err(|_| Error::Transport)?;
        let stream = companion
            .connect(
                &agreement.home.service.as_hex(),
                PROTOCOL,
                remaining(end)?.min(Duration::from_secs(10)),
            )
            .map_err(|_| Error::Transport)?;
        if !matches!(stream.peer(), Peer::Outgoing(_))
            || stream.peer().network() != agreement.home.network.network.as_hex()
            || stream.peer().incarnation() != agreement.home.network.incarnation.as_hex()
            || stream.peer().service() != agreement.home.service.as_hex()
            || stream.peer().protocol() != PROTOCOL
            || stream.peer().endpoint() != agreement.home_gateway.service_endpoint.as_hex()
        {
            return Err(Error::Authentication);
        }
        let home_key = key(agreement.home_service_key)?;
        let end = end.min(clock::boot_ms().map_err(|_| Error::Clock)? + 5000);
        let nonce = Id::random().map_err(|_| Error::State)?;
        let hello = GatewayMessage::Hello {
            profile: FEDERATION_PROFILE,
            agreement: self.route.agreement,
            gateway: agreement.home_gateway.principal,
            receiver: agreement.home,
            client_nonce: nonce,
        };
        frame(
            &stream,
            FrameKind::FederationControl,
            sign_gateway_message(&hello, &self.gateway_key).map_err(|_| Error::Frame)?,
            remaining(end)?,
        )?;
        let challenge = io::receive(&stream, remaining(end)?).map_err(|_| Error::Transport)?;
        if challenge.kind != FrameKind::FederationControl {
            return Err(Error::Frame);
        }
        let challenge = verify_gateway_message(&challenge.payload, &home_key)
            .map_err(|_| Error::Authentication)?;
        let GatewayMessage::Challenge {
            agreement: reference,
            gateway,
            receiver,
            client_nonce,
            service_boot,
            principal,
            session,
            transport_generation,
            issued_ms,
            expires_ms,
            ..
        } = challenge.value()
        else {
            return Err(Error::Frame);
        };
        if *reference != self.route.agreement
            || *gateway != agreement.home_gateway.principal
            || *receiver != agreement.home
            || *client_nonce != nonce
            || *principal != agreement.home_gateway.principal
            || session.as_hex() != stream.peer().session()
            || *transport_generation != stream.peer().generation()
            || !shared
                .config
                .clock
                .sample()
                .map_err(|_| Error::Clock)?
                .permits(*issued_ms, *expires_ms)
        {
            return Err(Error::Authentication);
        }
        frame(
            &stream,
            FrameKind::FederationControl,
            sign_gateway_message(
                &GatewayMessage::Proof {
                    profile: FEDERATION_PROFILE,
                    agreement: self.route.agreement,
                    challenge_digest: challenge.digest(),
                },
                &self.gateway_key,
            )
            .map_err(|_| Error::Frame)?,
            remaining(end)?,
        )?;
        let ready = io::receive(&stream, remaining(end)?).map_err(|_| Error::Transport)?;
        if ready.kind != FrameKind::FederationControl {
            return Err(Error::Frame);
        }
        let ready =
            verify_gateway_message(&ready.payload, &home_key).map_err(|_| Error::Authentication)?;
        if !matches!(ready.value(), GatewayMessage::Ready { agreement: r, challenge_digest, service_boot: b, .. }
            if *r == self.route.agreement && *challenge_digest == challenge.digest() && b == service_boot)
        {
            return Err(Error::Authentication);
        }
        self.connected = Some(Connection {
            _companion: companion,
            stream,
            home_key,
            service_boot: *service_boot,
        });
        Ok(())
    }
    fn control<T: Serialize, R: serde::de::DeserializeOwned>(
        &mut self,
        shared: &Shared,
        agreement: &FederationAgreement,
        operation: Operation,
        body: &T,
        end: u64,
    ) -> Result<R> {
        let now = shared.config.clock.sample().map_err(|_| Error::Clock)?;
        let request_id = Id::random().map_err(|_| Error::State)?;
        let request = FederationControl::Request {
            profile: FEDERATION_PROFILE,
            home: agreement.home,
            origin: agreement.origin,
            agreement: self.route.agreement,
            request: request_id,
            operation,
            body: Value::serialized(body).map_err(|_| Error::Frame)?,
            created_ms: now.lower_ms,
            expires_ms: now.lower_ms + (remaining(end)?.as_millis() as u64).min(60_000),
        };
        let signed =
            sign_federation_control(&request, &self.gateway_key).map_err(|_| Error::Frame)?;
        let digest = verify_federation_control(&signed, &self.gateway_key.verifying_key())
            .map_err(|_| Error::Frame)?
            .digest();
        let connection = self.connected.as_ref().ok_or(Error::Transport)?;
        frame(
            &connection.stream,
            FrameKind::FederationControl,
            signed,
            remaining(end)?,
        )?;
        let received =
            io::receive(&connection.stream, remaining(end)?).map_err(|_| Error::Transport)?;
        if received.kind != FrameKind::FederationControl {
            return Err(Error::Frame);
        }
        let result = verify_federation_control(&received.payload, &connection.home_key)
            .map_err(|_| Error::Authentication)?;
        let FederationControl::Result {
            home,
            origin,
            agreement: reference,
            request,
            operation: op,
            request_digest,
            outcome,
            expires_ms,
            ..
        } = result.value()
        else {
            return Err(Error::Frame);
        };
        if *home != agreement.home
            || *origin != agreement.origin
            || *reference != self.route.agreement
            || *request != request_id
            || *op != operation
            || *request_digest != digest
            || shared
                .config
                .clock
                .sample()
                .map_err(|_| Error::Clock)?
                .upper_ms
                >= *expires_ms
        {
            return Err(Error::Authentication);
        }
        match outcome {
            Outcome::Result { body } => body.deserialized().map_err(|_| Error::Frame),
            Outcome::Refused {
                code,
                detail,
                retry_after_ms,
            } => Err(Error::ForwardRefused {
                code: *code,
                detail: detail.clone(),
                retry_after_ms: *retry_after_ms,
            }),
            Outcome::Rejected { code, detail } => Err(Error::ForwardRefused {
                code: *code,
                detail: detail.clone(),
                retry_after_ms: None,
            }),
            _ => Err(Error::Frame),
        }
    }
}

fn assertion_time(
    now: clock::TimeBounds,
    start: u64,
    after: u64,
    receipt_end: u64,
    authority_end: u64,
    challenge_end: u64,
) -> std::result::Result<(u64, u64), OriginAuthorityFailure> {
    // UTC bounds describe the captured boot instant. Verification time does not
    // widen that historical interval; it consumes remaining permission below.
    let uncertainty = now
        .upper_ms
        .checked_sub(now.lower_ms)
        .ok_or(OriginAuthorityFailure::AssertionClockOrBinding)?
        .div_ceil(2);
    if now.boot_ms < start || now.boot_ms > after || uncertainty > clock::ERROR_BOUND_MS {
        return Err(OriginAuthorityFailure::AssertionClockOrBinding);
    }
    // Map only the lifetime remaining AFTER sampling onto the earlier lower UTC
    // bound. Processing time can shorten this assertion, never extend it.
    let not_after = now
        .lower_ms
        .saturating_add(receipt_end.saturating_sub(after))
        .min(authority_end)
        .min(challenge_end);
    if not_after <= now.upper_ms || not_after.saturating_sub(now.lower_ms) > 5000 {
        return Err(OriginAuthorityFailure::AssertionLifetime);
    }
    Ok((uncertainty, not_after))
}

fn source_assertion(
    shared: &Shared,
    stream: &Stream,
    session: &AuthenticatedSession,
    prepared: &OriginSubject,
    challenge: &Verified<FederationChallenge>,
    check: &crate::hypernet::AuthorityCheck,
    attestor: &SigningKey,
) -> Result<Blob> {
    let start = clock::boot_ms().map_err(|_| Error::Clock)?;
    let now = shared.config.clock.sample().map_err(|_| Error::Clock)?;
    let after = clock::boot_ms().map_err(|_| Error::Clock)?;
    let evidence = check.attestation().ok_or_else(|| {
        authority_failure(
            shared,
            OriginAuthorityFailure::AssertionEvidenceUnavailable,
            Some(check),
        )
    })?;
    let identity = evidence.identity();
    let Peer::Incoming(peer) = stream.peer() else {
        return Err(Error::Authentication);
    };
    let challenge_digest = challenge.digest();
    let challenge = challenge.value();
    if evidence.action_digest() != prepared.subject.digest().as_hex()
        || challenge.subject != prepared.subject
        || challenge.agreement != prepared.agreement
        || identity.session != stream.peer().session()
        || identity.generation != stream.peer().generation()
    {
        return Err(authority_failure(
            shared,
            OriginAuthorityFailure::AssertionClockOrBinding,
            Some(check),
        ));
    }
    let authority = evidence.authority();
    let (uncertainty, not_after) = assertion_time(
        now,
        start,
        after,
        evidence.not_after_boot_ms(),
        authority.expires_at_ms(),
        challenge.expires_ms,
    )
    .map_err(|reason| authority_failure(shared, reason, Some(check)))?;
    let assertion = OriginAssertion {
        profile: FEDERATION_PROFILE,
        origin: shared.config.descriptor.home,
        home: challenge.home,
        agreement: prepared.agreement,
        admission: challenge.admission,
        subject: prepared.subject.clone(),
        challenge_digest,
        endpoint_binding_digest: prepared.acting.binding_digest,
        endpoint: prepared.acting.endpoint,
        security_generation: prepared.acting.security_generation,
        enrolment_generation: prepared.acting.enrolment_generation,
        transport_network: shared.config.descriptor.home.network,
        transport_principal: Id::from_hex(peer.principal()).map_err(|_| Error::Authentication)?,
        transport_session: Id::from_hex(identity.session).map_err(|_| Error::Authentication)?,
        transport_generation: identity.generation,
        transport_grant: Id::from_hex(peer.grant()).map_err(|_| Error::Authentication)?,
        transport_grant_generation: peer.grant_generation(),
        source_service_boot: shared.boot,
        control_generation: identity.control_generation,
        companion_instance: Id::from_hex(identity.companion_instance)
            .map_err(|_| Error::Authentication)?,
        endpoint_instance: Id::from_hex(identity.endpoint_instance)
            .map_err(|_| Error::Authentication)?,
        permit_nonce: Id::from_hex(evidence.nonce()).map_err(|_| Error::Authentication)?,
        authority: AuthorityEvidence {
            configuration: Id::from_hex(authority.configuration())
                .map_err(|_| Error::Authentication)?,
            epoch: authority.epoch(),
            height: authority.height(),
            state: Id::from_hex(authority.state()).map_err(|_| Error::Authentication)?,
            statement_digest: Id::from_hex(authority.statement_digest())
                .map_err(|_| Error::Authentication)?,
            evaluated_at_ms: authority.evaluated_at_ms(),
            expires_at_ms: authority.expires_at_ms(),
        },
        checkpoints: prepared.checkpoints.clone(),
        source_privacy: super::federation_gateway::privacy(check).map_err(|error| {
            if matches!(error, Error::Authority) {
                authority_failure(
                    shared,
                    OriginAuthorityFailure::AssertionPrivacy,
                    Some(check),
                )
            } else {
                error
            }
        })?,
        source_evaluated_ms: now.lower_ms,
        source_not_after_ms: not_after,
        source_uncertainty_ms: uncertainty,
    };
    shared
        .home
        .lock()
        .map_err(|_| Error::State)?
        .federation_origin_current(
            prepared,
            session,
            shared.config.clock.sample().map_err(|_| Error::Clock)?,
        )
        .map_err(domain_error)?;
    if !evidence.permitted() {
        return Err(authority_failure(
            shared,
            OriginAuthorityFailure::AssertionNoLongerPermitted,
            Some(check),
        ));
    }
    sign_origin_assertion(&assertion, attestor)
        .map(Blob)
        .map_err(|_| Error::Frame)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AdmissionRequest {
    account: AccountId,
    endpoint: Id,
    binding_digest: Id,
}
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ChallengeRequest {
    agreement: AgreementRef,
    admission: AdmissionRef,
    subject: FederationSubject,
}

fn export_proofs(
    shared: &Shared,
    source: &Stream,
    session: &AuthenticatedSession,
    prepared: &OriginSubject,
    outbound: &mut Outbound,
    agreement: &FederationAgreement,
    end: u64,
) -> Result<()> {
    for reference in &prepared.checkpoints {
        let signed = shared
            .home
            .lock()
            .map_err(|_| Error::State)?
            .federation_checkpoint(
                reference.account,
                prepared.agreement,
                shared.config.clock.sample().map_err(|_| Error::Clock)?,
            )
            .map_err(domain_error)?;
        let checkpoint =
            verify_origin_identity_checkpoint(&signed.0, &shared.signer.verifying_key())
                .map_err(|_| Error::Authentication)?;
        if checkpoint.digest() != reference.checkpoint_digest {
            return Err(authority_failure(
                shared,
                OriginAuthorityFailure::IdentityCheckpointChanged,
                None,
            ));
        }
        if outbound.synchronized.get(&reference.account) == Some(&checkpoint.digest()) {
            continue;
        }
        if outbound.synchronized.len() >= 256
            && !outbound.synchronized.contains_key(&reference.account)
        {
            return Err(Error::RateLimited);
        }
        let mut after = outbound
            .import_progress
            .get(&reference.account)
            .filter(|(digest, _)| *digest == checkpoint.digest())
            .map_or(0, |(_, after)| *after);
        loop {
            let check = shared
                .check_authority(
                    source,
                    prepared.subject.digest(),
                    Some(end),
                    &Cancellation::default(),
                    "FederationIdentityExport",
                )
                .map_err(|error| {
                    if matches!(error, Error::Authority) {
                        authority_failure(
                            shared,
                            OriginAuthorityFailure::IdentityAuthorityRead,
                            None,
                        )
                    } else {
                        error
                    }
                })?;
            if !current(&check, Some(end)) {
                return Err(authority_failure(
                    shared,
                    OriginAuthorityFailure::IdentityAuthorityBeforePage,
                    Some(&check),
                ));
            }
            let page = {
                let mut home = shared.home.lock().map_err(|_| Error::State)?;
                let now = shared.config.clock.sample().map_err(|_| Error::Clock)?;
                home.federation_origin_current(prepared, session, now)
                    .map_err(domain_error)?;
                home.federation_identity_page(
                    prepared.agreement,
                    reference.checkpoint_digest,
                    after,
                    4,
                    now,
                )
                .map_err(|_| {
                    authority_failure(
                        shared,
                        OriginAuthorityFailure::IdentityPageUnavailable,
                        Some(&check),
                    )
                })?
            };
            let verified = verify_origin_identity_page(&page.0, &shared.signer.verifying_key())
                .map_err(|_| Error::Authentication)?;
            if !current(&check, Some(end)) {
                return Err(authority_failure(
                    shared,
                    OriginAuthorityFailure::IdentityAuthorityAfterPage,
                    Some(&check),
                ));
            }
            let complete: bool = outbound.control(
                shared,
                agreement,
                Operation::FederationIdentityPage,
                &IdentityTransfer::Import {
                    checkpoint: signed.clone(),
                    page,
                },
                end,
            )?;
            if complete {
                outbound
                    .synchronized
                    .insert(reference.account, checkpoint.digest());
                outbound.import_progress.remove(&reference.account);
                shared
                    .home
                    .lock()
                    .map_err(|_| Error::State)?
                    .federation_acknowledge_identity(
                        prepared.agreement,
                        reference.account,
                        checkpoint.digest(),
                        shared.config.clock.sample().map_err(|_| Error::Clock)?,
                    )
                    .map_err(domain_error)?;
                break;
            }
            if verified.value().complete || verified.value().next <= after {
                return Err(Error::Frame);
            }
            after = verified.value().next;
            outbound
                .import_progress
                .insert(reference.account, (checkpoint.digest(), after));
        }
    }
    watch::renew(shared, outbound, agreement, &prepared.checkpoints, end)?;
    Ok(())
}

fn forward(
    shared: &Shared,
    source: &Stream,
    session: &AuthenticatedSession,
    subject: SourceSubject,
    reference: AgreementRef,
    end: u64,
) -> Result<Frame> {
    let route = shared
        .federation_routes
        .iter()
        .find(|route| route.agreement == reference)
        .ok_or(Error::Configuration)?;
    let stopped = || shared.stop.load(Ordering::Acquire) || !source.check_authority_supported();
    let _turn = route
        .admission
        .foreground(end, stopped)
        .map_err(admission_error)?;
    // Admission owns the whole correlated exchange. Release the stream lock before its turn.
    let mut outbound = route.outbound.try_lock().map_err(|_| Error::State)?;
    // Waiting grants no authority: inspect the current agreement after admission.
    let state = shared
        .home
        .lock()
        .map_err(|_| Error::State)?
        .federation_agreement(
            reference,
            shared.config.clock.sample().map_err(|_| Error::Clock)?,
        )
        .map_err(domain_error)?;
    if stopped() {
        return Err(Error::AuthorityAdmissionStopped);
    }
    remaining(end)?;
    let result = (|| {
        outbound.connect(shared, &state.agreement, end)?;
        let prepared = shared
            .home
            .lock()
            .map_err(|_| Error::State)?
            .federation_origin_subject(
                session,
                subject.clone(),
                reference,
                shared.config.clock.sample().map_err(|_| Error::Clock)?,
            )
            .map_err(domain_error)?;
        export_proofs(
            shared,
            source,
            session,
            &prepared,
            &mut outbound,
            &state.agreement,
            end,
        )?;
        let admission: federation::RemoteAdmission = outbound.control(
            shared,
            &state.agreement,
            Operation::FederationInspect,
            &AdmissionRequest {
                account: prepared.acting.account,
                endpoint: prepared.acting.endpoint,
                binding_digest: prepared.acting.binding_digest,
            },
            end,
        )?;
        if admission.agreement != reference || admission.acting != prepared.acting {
            return Err(Error::Authentication);
        }
        let challenge: Blob = outbound.control(
            shared,
            &state.agreement,
            Operation::FederationChallenge,
            &ChallengeRequest {
                agreement: reference,
                admission: admission.reference,
                subject: prepared.subject.clone(),
            },
            end,
        )?;
        let connection = outbound.connected.as_ref().ok_or(Error::Transport)?;
        let verified = verify_federation_challenge(&challenge.0, &connection.home_key)
            .map_err(|_| Error::Authentication)?;
        let c = verified.value();
        if c.home != state.agreement.home
            || c.origin != state.agreement.origin
            || c.agreement != reference
            || c.admission != admission.reference
            || c.gateway != state.agreement.home_gateway.principal
            || c.subject != prepared.subject
            || c.service_boot != connection.service_boot
        {
            return Err(Error::Authentication);
        }
        let now = shared.config.clock.sample().map_err(|_| Error::Clock)?;
        if !now.permits(c.issued_ms, c.expires_ms) {
            return Err(authority_failure(
                shared,
                OriginAuthorityFailure::ChallengeNotCurrent,
                None,
            ));
        }
        let end = end.min(
            now.boot_ms
                .saturating_add(c.expires_ms.saturating_sub(now.upper_ms)),
        );
        let check = shared
            .check_authority(
                source,
                prepared.subject.digest(),
                Some(end),
                &Cancellation::default(),
                "FederationOriginAuthority",
            )
            .map_err(|error| {
                if matches!(error, Error::Authority) {
                    authority_failure(shared, OriginAuthorityFailure::OriginAuthorityRead, None)
                } else {
                    error
                }
            })?;
        let assertion = source_assertion(
            shared,
            source,
            session,
            &prepared,
            &verified,
            &check,
            &outbound.attestor,
        )?;
        match subject {
            SourceSubject::Session(request) => {
                let ready: Blob = outbound.control(
                    shared,
                    &state.agreement,
                    Operation::FederationSession,
                    &RemoteSessionExchange {
                        request,
                        endpoint_binding: prepared.endpoint_binding,
                        challenge,
                        origin_assertion: assertion,
                    },
                    end,
                )?;
                let home_key = &outbound
                    .connected
                    .as_ref()
                    .ok_or(Error::Transport)?
                    .home_key;
                let verified = verify_remote_session_ready(&ready.0, home_key)
                    .map_err(|_| Error::Authentication)?;
                let FederationSubject::Session {
                    request_digest,
                    request,
                } = prepared.subject
                else {
                    return Err(Error::Frame);
                };
                if verified.value().home != state.agreement.home
                    || verified.value().origin != state.agreement.origin
                    || verified.value().agreement != reference
                    || verified.value().admission != admission.reference
                    || verified.value().request != request
                    || verified.value().request_digest != request_digest
                    || verified.value().acting != prepared.acting
                {
                    return Err(Error::Authentication);
                }
                Frame::new(FrameKind::FederationControl, ready.0).map_err(|_| Error::Frame)
            }
            SourceSubject::Action(action) => {
                let verified_action = verify_action(&action.0, &key(session.signer)?)
                    .map_err(|_| Error::Authentication)?;
                let crypto = verified_action.action().operation.is_crypto_transition();
                let envelope = FederationEnvelope {
                    profile: FEDERATION_PROFILE,
                    admission: admission.reference,
                    agreement: reference,
                    action,
                    endpoint_binding: prepared.endpoint_binding,
                    challenge,
                    origin_assertion: assertion,
                };
                let connection = outbound.connected.as_ref().ok_or(Error::Transport)?;
                if !current(&check, Some(end)) {
                    return Err(Error::Authority);
                }
                frame(
                    &connection.stream,
                    if crypto {
                        FrameKind::CryptoFederation
                    } else {
                        FrameKind::Federation
                    },
                    encode_federation(&envelope).map_err(|_| Error::Frame)?,
                    remaining(end)?,
                )?;
                // Durable completion may follow the last authorization; a late response remains an uncertain outcome.
                if verified_action.action().operation == Operation::SearchQuery {
                    loop {
                        let interrupted = match source.wait_readable(Duration::from_millis(1)) {
                            Ok(false) => false,
                            Ok(true) | Err(_) => true,
                        };
                        if interrupted || shared.stop.load(Ordering::Acquire) {
                            connection.stream.close();
                            return Err(Error::Transport);
                        }
                        if connection
                            .stream
                            .wait_readable(remaining(end)?.min(Duration::from_millis(25)))
                            .map_err(|_| Error::Transport)?
                        {
                            break;
                        }
                    }
                }
                let response = io::receive(&connection.stream, Duration::from_secs(5))
                    .map_err(|_| Error::Transport)?;
                let result = if crypto {
                    if response.kind != FrameKind::CryptoResponse {
                        return Err(Error::Frame);
                    }
                    verify_crypto_response(&response.payload, &connection.home_key)
                } else {
                    if response.kind != FrameKind::Response {
                        return Err(Error::Frame);
                    }
                    verify_response(&response.payload, &connection.home_key)
                }
                .map_err(|_| Error::Authentication)?;
                let action = verified_action.action();
                if result.value().home != action.home
                    || result.value().operation_id != action.operation_id
                    || result.value().action_digest != verified_action.digest()
                {
                    return Err(Error::Authentication);
                }
                Ok(response)
            }
        }
    })();
    if let Err(error) = &result {
        outbound.failed(error);
    }
    result
}

pub(super) fn bootstrap(
    shared: &Shared,
    source: &Stream,
    session: &AuthenticatedSession,
    endpoint_key: &VerifyingKey,
    bytes: &[u8],
) -> Result<()> {
    let request =
        verify_remote_session_request(bytes, endpoint_key).map_err(|_| Error::Authentication)?;
    let now = shared.config.clock.sample().map_err(|_| Error::Clock)?;
    if !now.permits(request.value().created_ms, request.value().expires_ms) {
        return Err(Error::Authority);
    }
    let end = now
        .boot_ms
        .saturating_add(request.value().expires_ms.saturating_sub(now.upper_ms))
        .min(now.boot_ms + 30_000);
    match forward(
        shared,
        source,
        session,
        SourceSubject::Session(Blob(bytes.to_vec())),
        request.value().agreement,
        end,
    ) {
        Ok(response) => io::send(source, &response, remaining(end)?).map_err(|_| Error::Transport),
        Err(error) => refusal(
            shared,
            source,
            request.value().home,
            request.value().agreement,
            FederationSubject::Session {
                request: request.value().request,
                request_digest: request.digest(),
            },
            error,
        ),
    }
}

pub(super) fn action(
    shared: &Shared,
    source: &Stream,
    session: &AuthenticatedSession,
    action: &VerifiedAction,
) -> Result<()> {
    let reference = action.action().agreement.ok_or(Error::Authentication)?;
    let end = clock::boot_ms().map_err(|_| Error::Clock)? + 10_000;
    match forward(
        shared,
        source,
        session,
        SourceSubject::Action(Blob(action.signed_bytes().to_vec())),
        reference,
        end,
    ) {
        Ok(response) => {
            io::send(source, &response, Duration::from_secs(5)).map_err(|_| Error::Transport)
        }
        Err(error) => refusal(
            shared,
            source,
            action.action().home,
            reference,
            FederationSubject::Action {
                operation_id: action.action().operation_id,
                action_digest: action.digest(),
            },
            error,
        ),
    }
}

// This origin-signed result describes only forwarding availability. It is never a home operation outcome.
fn refusal_outcome(error: Error) -> Outcome {
    let (code, detail, retry_after_ms) = match error {
        Error::ForwardRefused {
            code,
            detail,
            retry_after_ms,
        } => (code, detail, retry_after_ms),
        Error::AuthorityAdmissionBusy => (ErrorCode::Overloaded, error.code().into(), Some(1000)),
        Error::Authentication | Error::Frame => (ErrorCode::Denied, error.code().into(), None),
        _ => (ErrorCode::Unavailable, error.code().into(), Some(1000)),
    };
    Outcome::Refused {
        code,
        detail,
        retry_after_ms,
    }
}
fn refusal(
    shared: &Shared,
    source: &Stream,
    home: ServiceId,
    agreement: AgreementRef,
    subject: FederationSubject,
    error: Error,
) -> Result<()> {
    let (request, operation, request_digest) = match subject {
        FederationSubject::Session {
            request,
            request_digest,
        } => (request, Operation::FederationSession, request_digest),
        FederationSubject::Action {
            operation_id,
            action_digest,
        } => (
            operation_id.operation,
            Operation::FederationExchange,
            action_digest,
        ),
    };
    let outcome = refusal_outcome(error);
    let now = shared.config.clock.sample().map_err(|_| Error::Clock)?;
    let response = FederationControl::Result {
        profile: FEDERATION_PROFILE,
        home,
        origin: shared.config.descriptor.home,
        agreement,
        request,
        operation,
        request_digest,
        outcome,
        created_ms: now.lower_ms,
        expires_ms: now.lower_ms + 5000,
    };
    frame(
        source,
        FrameKind::FederationControl,
        sign_federation_control(&response, &shared.signer).map_err(|_| Error::Frame)?,
        Duration::from_secs(5),
    )
}

pub(super) fn notify_withdrawal(
    shared: &Shared,
    reference: AgreementRef,
) -> Result<federation::AgreementState> {
    let state = shared
        .home
        .lock()
        .map_err(|_| Error::State)?
        .federation_inspect(reference)
        .map_err(|_| Error::State)?;
    if !state.withdrawn || state.agreement.origin != shared.config.descriptor.home {
        return Err(Error::Authentication);
    }
    if state.barrier_position.is_some() {
        return Ok(state);
    }
    let end = clock::boot_ms().map_err(|_| Error::Clock)? + 15000;
    let route = shared
        .federation_routes
        .iter()
        .find(|route| route.agreement == reference)
        .ok_or(Error::Configuration)?;
    let stopped = || shared.stop.load(Ordering::Acquire);
    let _turn = route
        .admission
        .foreground(end, stopped)
        .map_err(admission_error)?;
    let mut outbound = route.outbound.try_lock().map_err(|_| Error::State)?;
    let state = shared
        .home
        .lock()
        .map_err(|_| Error::State)?
        .federation_inspect(reference)
        .map_err(|_| Error::State)?;
    if !state.withdrawn || state.agreement.origin != shared.config.descriptor.home {
        return Err(Error::Authentication);
    }
    if state.barrier_position.is_some() {
        return Ok(state);
    }
    if stopped() {
        return Err(Error::AuthorityAdmissionStopped);
    }
    remaining(end)?;
    outbound.connect(shared, &state.agreement, end)?;
    let now = shared.config.clock.sample().map_err(|_| Error::Clock)?;
    let request_id = Id::random().map_err(|_| Error::State)?;
    let request = FederationControl::Request {
        profile: FEDERATION_PROFILE,
        home: state.agreement.home,
        origin: state.agreement.origin,
        agreement: reference,
        request: request_id,
        operation: Operation::FederationWithdraw,
        body: Value::serialized(&FederationWithdrawal {
            agreement: reference,
            request: request_id,
            reason: WithdrawalReason::Administrative,
        })
        .map_err(|_| Error::Frame)?,
        created_ms: now.lower_ms,
        expires_ms: now.lower_ms + remaining(end)?.as_millis() as u64,
    };
    let signed = sign_federation_control(&request, &shared.signer).map_err(|_| Error::Frame)?;
    let request = verify_federation_control(&signed, &shared.signer.verifying_key())
        .map_err(|_| Error::Frame)?;
    let connection = outbound.connected.as_ref().ok_or(Error::Transport)?;
    frame(
        &connection.stream,
        FrameKind::FederationControl,
        signed,
        remaining(end)?,
    )?;
    let received =
        io::receive(&connection.stream, remaining(end)?).map_err(|_| Error::Transport)?;
    if received.kind != FrameKind::FederationControl {
        return Err(Error::Frame);
    }
    let result = verify_federation_control(&received.payload, &connection.home_key)
        .map_err(|_| Error::Authentication)?;
    shared
        .home
        .lock()
        .map_err(|_| Error::State)?
        .federation_record_withdrawal_ack(
            &request,
            &result,
            shared.config.clock.sample().map_err(|_| Error::Clock)?,
        )
        .map_err(|_| Error::Authority)
}

#[cfg(test)]
#[path = "../../Tests/Service/FederationOrigin.rs"]
mod tests;
