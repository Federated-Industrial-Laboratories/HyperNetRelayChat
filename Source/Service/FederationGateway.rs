// SPDX-License-Identifier: Apache-2.0
//! Incoming gateway possession and fresh destination checks before shared home execution.
use super::*;
use crate::federation::{self, GatewayContext, GatewayTransport, IdentityImport};
use serde::Deserialize;

fn key(value: Id) -> Result<VerifyingKey> {
    VerifyingKey::from_bytes(value.as_bytes()).map_err(|_| Error::Authentication)
}
pub(super) fn privacy(check: &crate::hypernet::AuthorityCheck) -> Result<FederationPrivacy> {
    let evidence = check.attestation().ok_or(Error::Authority)?;
    let privacy = evidence.privacy();
    if privacy.direction() != crate::hypernet::Direction::Incoming
        || privacy.provenance() != crate::hypernet::Provenance::EndpointAttestedArrival
    {
        return Err(Error::Authority);
    }
    let value = FederationPrivacy {
        endpoint_mode: privacy
            .endpoint_mode()
            .map(u8::try_from)
            .transpose()
            .map_err(|_| Error::Authority)?,
        transport_protection: privacy.transport_protection().map(|value| match value {
            crate::hypernet::TransportProtection::Tls13FinalService => {
                FederationProtection::Tls13FinalService
            }
        }),
        relay_arrival: match privacy.relay_path() {
            crate::hypernet::RelayPath::ApprovedAttachment => FederationRelay::ApprovedAttachment,
            crate::hypernet::RelayPath::Unknown => FederationRelay::Unknown,
            _ => return Err(Error::Authority),
        },
        relay_service: privacy
            .relay_service()
            .map(Id::from_hex)
            .transpose()
            .map_err(|_| Error::Authority)?,
        attachment_profile_digest: privacy
            .attachment_profile_digest()
            .map(Id::from_hex)
            .transpose()
            .map_err(|_| Error::Authority)?,
        provenance: "endpointAttestedArrival".into(),
        physical_independence_verified: false,
        profile_currentness_asserted: false,
    };
    value.validate().map_err(|_| Error::Authority)?;
    Ok(value)
}

pub(super) fn serve(
    shared: &Shared,
    stream: &Stream,
    incoming: Frame,
    principal: Id,
    end: u64,
    handshake: Handshake<'_>,
) -> Result<()> {
    let (reference, gateway) = gateway_hello_hint(&incoming.payload).map_err(|_| Error::Frame)?;
    let state = shared
        .home
        .lock()
        .map_err(|_| Error::State)?
        .federation_inspect(reference)
        .map_err(|_| Error::Authentication)?;
    let agreement = &state.agreement;
    let receiver = shared.config.descriptor.home;
    let binding = if receiver == agreement.home {
        &agreement.home_gateway
    } else if receiver == agreement.origin {
        &agreement.origin_gateway
    } else {
        return Err(Error::Authentication);
    };
    if principal != gateway || principal != binding.principal {
        return Err(Error::Authentication);
    }
    let hello = verify_gateway_message(&incoming.payload, &key(binding.signing_key)?)
        .map_err(|_| Error::Authentication)?;
    let GatewayMessage::Hello {
        client_nonce,
        receiver: target,
        agreement: accepted,
        ..
    } = hello.value()
    else {
        return Err(Error::Authentication);
    };
    if *target != receiver || *accepted != reference {
        return Err(Error::Authentication);
    }
    let clock = shared.config.clock.sample().map_err(|_| Error::Clock)?;
    let challenge = GatewayMessage::Challenge {
        profile: FEDERATION_PROFILE,
        agreement: reference,
        gateway,
        receiver,
        client_nonce: *client_nonce,
        server_nonce: Id::random().map_err(|_| Error::State)?,
        service_boot: shared.boot,
        principal,
        session: Id::from_hex(stream.peer().session()).map_err(|_| Error::Authentication)?,
        transport_generation: stream.peer().generation(),
        issued_ms: clock.lower_ms,
        expires_ms: clock.lower_ms + remaining(end)?.as_millis() as u64,
    };
    let signed = sign_gateway_message(&challenge, &shared.signer).map_err(|_| Error::Frame)?;
    let challenge = verify_gateway_message(&signed, &shared.signer.verifying_key())
        .map_err(|_| Error::Frame)?;
    frame(
        stream,
        FrameKind::FederationControl,
        signed,
        remaining(end)?,
    )?;
    let proof = io::receive(stream, remaining(end)?).map_err(|_| Error::Transport)?;
    if proof.kind != FrameKind::FederationControl {
        return Err(Error::Frame);
    }
    let proof = verify_gateway_message(&proof.payload, &key(binding.signing_key)?)
        .map_err(|_| Error::Authentication)?;
    let check = shared.check_authority(
        stream,
        proof.digest(),
        Some(end),
        &Cancellation::default(),
        "GatewayAuthority",
    )?;
    if !current(&check, Some(end)) {
        return Err(Error::Authority);
    }
    let accepted = verify_agreement(&state.home_signature.0, &key(agreement.home_service_key)?)
        .map_err(|_| Error::Authentication)?;
    let transport = GatewayTransport {
        network: NetworkId {
            network: Id::from_hex(stream.peer().network()).map_err(|_| Error::Authentication)?,
            incarnation: Id::from_hex(stream.peer().incarnation())
                .map_err(|_| Error::Authentication)?,
        },
        destination: receiver,
        principal,
        service_endpoint: Id::from_hex(stream.peer().endpoint())
            .map_err(|_| Error::Authentication)?,
        session: Id::from_hex(stream.peer().session()).map_err(|_| Error::Authentication)?,
        generation: stream.peer().generation(),
    };
    let context = GatewayContext::verify(
        &accepted,
        transport,
        &challenge,
        &proof,
        shared.config.clock.sample().map_err(|_| Error::Clock)?,
    )
    .map_err(|_| Error::Authentication)?;
    frame(
        stream,
        FrameKind::FederationControl,
        sign_gateway_message(
            &GatewayMessage::Ready {
                profile: FEDERATION_PROFILE,
                agreement: reference,
                challenge_digest: challenge.digest(),
                service_boot: shared.boot,
            },
            &shared.signer,
        )
        .map_err(|_| Error::Frame)?,
        remaining(end)?,
    )?;
    drop(handshake);
    let mut budget = Budget::new(16, 4);
    loop {
        let incoming =
            io::receive(stream, Duration::from_secs(60)).map_err(|_| Error::Transport)?;
        if incoming.kind == FrameKind::Close {
            return Ok(());
        }
        let now = clock::boot_ms().map_err(|_| Error::Clock)?;
        if !budget.admit(now) || !shared.ingress.lock().map_err(|_| Error::State)?.admit(now) {
            return Err(Error::RateLimited);
        }
        match incoming.kind {
            FrameKind::Federation | FrameKind::CryptoFederation => {
                exchange(shared, stream, &context, &state, incoming)?
            }
            FrameKind::FederationControl => {
                control(shared, stream, &context, &state, &incoming.payload)?
            }
            _ => return Err(Error::Frame),
        }
    }
}

fn failure(error: federation::Error) -> Outcome {
    let (code, detail) = match error {
        federation::Error::Refused { code, detail } => (code, detail),
        federation::Error::Protocol(_) => (ErrorCode::Denied, "FederationEvidence"),
        federation::Error::Storage(_) => (ErrorCode::Unavailable, "FederationState"),
    };
    Outcome::Refused {
        code,
        detail: detail.into(),
        retry_after_ms: matches!(
            code,
            ErrorCode::Unavailable | ErrorCode::Overloaded | ErrorCode::RateLimited
        )
        .then_some(1000),
    }
}
fn exchange(
    shared: &Shared,
    stream: &Stream,
    gateway: &GatewayContext,
    agreement: &federation::AgreementState,
    incoming: Frame,
) -> Result<()> {
    let envelope = decode_federation(&incoming.payload).map_err(|_| Error::Frame)?;
    let assertion = verify_origin_assertion(
        &envelope.origin_assertion.0,
        &key(agreement.agreement.origin_attestor_key)?,
    )
    .map_err(|_| Error::Authentication)?;
    let FederationSubject::Action {
        action_digest,
        operation_id,
    } = assertion.value().subject
    else {
        return Err(Error::Frame);
    };
    let check = shared.check_authority(
        stream,
        action_digest,
        None,
        &Cancellation::default(),
        "FederationExchange",
    )?;
    let mut response = Response {
        home: shared.config.descriptor.home,
        operation_id,
        action_digest,
        outcome: Outcome::Refused {
            code: ErrorCode::Unavailable,
            detail: "TransportAuthority".into(),
            retry_after_ms: Some(1000),
        },
    };
    if check.permitted() {
        let privacy = privacy(&check)?;
        let clock = shared.config.clock.sample().map_err(|_| Error::Clock)?;
        let verified = shared
            .home
            .lock()
            .map_err(|_| Error::State)?
            .federation_verify(gateway, &envelope, &privacy, clock, &|| check.permitted());
        match verified {
            Ok(verified) => {
                if (incoming.kind == FrameKind::CryptoFederation)
                    != verified.action().action().operation.is_crypto_transition()
                {
                    return Err(Error::Frame);
                }
                response = execute_remote(shared, stream, &verified, clock, &check)?;
            }
            Err(error) => response.outcome = failure(error),
        }
    }
    let (kind, signed) = if incoming.kind == FrameKind::CryptoFederation {
        (
            FrameKind::CryptoResponse,
            sign_crypto_response(&response, &shared.signer),
        )
    } else {
        (
            FrameKind::Response,
            sign_response(&response, &shared.signer),
        )
    };
    frame(
        stream,
        kind,
        signed.map_err(|_| Error::Frame)?,
        Duration::from_secs(5),
    )
}

fn execute_remote(
    shared: &Shared,
    stream: &Stream,
    verified: &federation::VerifiedRemoteSubmission,
    clock: crate::clock::TimeBounds,
    check: &crate::hypernet::AuthorityCheck,
) -> Result<Response> {
    let cancel = Cancellation::default();
    let execute = |cancel: &Cancellation| {
        let action = verified.action();
        let outcome = match shared.home.try_lock() {
            Ok(mut home) => match home.execute_remote_cancellable(
                verified,
                clock,
                &|| check.permitted(),
                cancel,
            ) {
                Ok(response) => return response,
                Err(_) => Outcome::Unknown,
            },
            Err(_) => Outcome::Refused {
                code: ErrorCode::Overloaded,
                detail: "OperationBusy".into(),
                retry_after_ms: Some(1000),
            },
        };
        Response {
            home: shared.config.descriptor.home,
            operation_id: action.action().operation_id,
            action_digest: action.digest(),
            outcome,
        }
    };
    if verified.action().action().operation != Operation::SearchQuery {
        return Ok(execute(&cancel));
    }
    let end = crate::clock::boot_ms().map_err(|_| Error::Clock)? + 10000;
    thread::scope(|scope| {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let token = cancel.clone();
        scope.spawn(move || {
            let _ = sender.send(execute(&token));
        });
        let result = (|| loop {
            if let Ok(response) = receiver.try_recv() {
                return Ok(response);
            }
            if shared.stop.load(Ordering::Acquire)
                || stream
                    .wait_readable(remaining(end)?.min(Duration::from_millis(25)))
                    .map_err(|_| Error::Transport)?
            {
                return Err(Error::Transport);
            }
        })();
        if result.is_err() {
            cancel.cancel();
            stream.close();
        }
        result
    })
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ChallengeRequest {
    agreement: AgreementRef,
    admission: AdmissionRef,
    subject: FederationSubject,
}
#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct AdmissionRequest {
    account: AccountId,
    endpoint: Id,
    binding_digest: Id,
}
fn control(
    shared: &Shared,
    stream: &Stream,
    gateway: &GatewayContext,
    state: &federation::AgreementState,
    bytes: &[u8],
) -> Result<()> {
    let agreement = &state.agreement;
    let receiver = shared.config.descriptor.home;
    let binding = if receiver == agreement.home {
        &agreement.home_gateway
    } else {
        &agreement.origin_gateway
    };
    let verified = verify_federation_control(bytes, &key(binding.signing_key)?)
        .or_else(|_| {
            verify_federation_control(
                bytes,
                &key(agreement.origin_service_key).map_err(|_| crate::protocol::Error::Binding)?,
            )
        })
        .map_err(|_| Error::Authentication)?;
    let FederationControl::Request {
        home,
        origin,
        agreement: reference,
        request,
        operation,
        body,
        created_ms,
        expires_ms,
        ..
    } = verified.value()
    else {
        return Err(Error::Frame);
    };
    let clock = shared.config.clock.sample().map_err(|_| Error::Clock)?;
    if *home != agreement.home
        || *origin != agreement.origin
        || *reference != gateway.agreement()
        || !clock.permits(*created_ms, *expires_ms)
    {
        return Err(Error::Authentication);
    }
    let required_signer = if *operation == Operation::FederationWithdraw {
        agreement.origin_service_key
    } else {
        binding.signing_key
    };
    if verified.signer_key() != required_signer {
        return Err(Error::Authentication);
    }
    let check = shared.check_authority(
        stream,
        verified.digest(),
        None,
        &Cancellation::default(),
        operation.name(),
    )?;
    let outcome = if check.permitted() {
        let privacy = privacy(&check)?;
        let mut home = shared.home.lock().map_err(|_| Error::State)?;
        let result = match operation {
            Operation::FederationChallenge => {
                let value: ChallengeRequest = body.deserialized().map_err(|_| Error::Frame)?;
                if value.agreement != *reference {
                    return Err(Error::Authentication);
                }
                home.federation_challenge(gateway, value.admission, value.subject, clock, &|| {
                    check.permitted()
                })
                .and_then(|v| {
                    Value::serialized(&v)
                        .map_err(|_| federation::Error::Protocol(crate::protocol::Error::Encoding))
                })
            }
            Operation::FederationSession => {
                let value: RemoteSessionExchange = body.deserialized().map_err(|_| Error::Frame)?;
                home.federation_open_remote(gateway, &value, &privacy, clock, &|| check.permitted())
                    .and_then(|v| {
                        Value::serialized(&v).map_err(|_| {
                            federation::Error::Protocol(crate::protocol::Error::Encoding)
                        })
                    })
            }
            Operation::FederationIdentityPage => {
                match body.deserialized().map_err(|_| Error::Frame)? {
                    IdentityTransfer::Import { checkpoint, page } => home
                        .federation_update_identity(
                            gateway,
                            &IdentityImport {
                                checkpoint,
                                page,
                                trust_anchor: None,
                            },
                            clock,
                            &|| check.permitted(),
                        )
                        .and_then(|v| {
                            Value::serialized(&v).map_err(|_| {
                                federation::Error::Protocol(crate::protocol::Error::Encoding)
                            })
                        }),
                    IdentityTransfer::Freshness { lease } => home
                        .federation_accept_freshness(gateway, &lease.0, clock, &|| {
                            check.permitted()
                        })
                        .and_then(|v| {
                            Value::serialized(&v).map_err(|_| {
                                federation::Error::Protocol(crate::protocol::Error::Encoding)
                            })
                        }),
                    IdentityTransfer::Read { .. } => return Err(Error::Frame),
                }
            }
            Operation::FederationInspect => {
                let value: AdmissionRequest = body.deserialized().map_err(|_| Error::Frame)?;
                home.federation_find_admission(
                    gateway,
                    value.account,
                    value.endpoint,
                    value.binding_digest,
                    clock,
                    &|| check.permitted(),
                )
                .and_then(|v| {
                    Value::serialized(&v)
                        .map_err(|_| federation::Error::Protocol(crate::protocol::Error::Encoding))
                })
            }
            Operation::FederationWithdraw => home
                .federation_withdraw_from_gateway(gateway, &verified, clock, &|| check.permitted())
                .and_then(|v| {
                    Value::serialized(&v)
                        .map_err(|_| federation::Error::Protocol(crate::protocol::Error::Encoding))
                }),
            _ => return Err(Error::Frame),
        };
        match result {
            Ok(body) => Outcome::Result { body },
            Err(error) => failure(error),
        }
    } else {
        Outcome::Refused {
            code: ErrorCode::Unavailable,
            detail: "TransportAuthority".into(),
            retry_after_ms: Some(1000),
        }
    };
    let response = FederationControl::Result {
        profile: FEDERATION_PROFILE,
        home: *home,
        origin: *origin,
        agreement: *reference,
        request: *request,
        operation: *operation,
        request_digest: verified.digest(),
        outcome,
        created_ms: *created_ms,
        expires_ms: *expires_ms,
    };
    frame(
        stream,
        FrameKind::FederationControl,
        sign_federation_control(&response, &shared.signer).map_err(|_| Error::Frame)?,
        Duration::from_secs(5),
    )
}
