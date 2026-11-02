// SPDX-License-Identifier: Apache-2.0
//! One authenticated HyperNet session; persistence owns retry decisions.
use super::Profile;
use crate::{
    clock,
    hypernet::{Companion, Peer, Privacy, Stream},
    protocol::*,
    service::io,
};
use std::{
    collections::BTreeMap,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("HyperNet companion preparation failed: {0}")]
    Companion(#[source] crate::hypernet::Error),
    #[error("HyperNet connection preparation failed: {0}")]
    Connect(#[source] crate::hypernet::Error),
    #[error("the HRC session exchange did not complete")]
    Handshake,
    #[error("HyperNet is unavailable; pending operation outcomes remain unresolved")]
    Transport,
    #[error("the pinned service or endpoint identity did not match")]
    Authentication,
    #[error("the service returned an invalid HRC frame")]
    Frame,
    #[error("a current clock observation is unavailable")]
    Clock,
    #[error("the retry window expired")]
    Expired,
    #[error("the federated query was cancelled; its stream is closed")]
    QueryCancelled,
    #[error("the origin could not forward this attempt: {detail}")]
    ForwardRefused {
        code: ErrorCode,
        detail: String,
        retry_after_ms: Option<u64>,
    },
}
impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Companion(_) => "CompanionUnavailable",
            Self::Connect(_) => "HyperNetPreparationUnavailable",
            Self::Handshake => "HrcHandshakeUnavailable",
            Self::Transport => "TransportUnavailable",
            Self::Authentication => "SessionAuthenticationFailed",
            Self::Frame => "InvalidSessionFrame",
            Self::Clock => "ClockUnavailable",
            Self::Expired => "RetryWindowExpired",
            Self::QueryCancelled => "QueryCancelled",
            Self::ForwardRefused { .. } => "FederationForwardRefused",
        }
    }
    /// A fresh connection may be attempted; this does not authorize replaying an operation.
    pub fn retryable_session(&self) -> bool {
        self.retryable_setup()
            || matches!(self, Self::Transport | Self::Clock | Self::QueryCancelled)
    }
    fn retryable_setup(&self) -> bool {
        use crate::hypernet::Error as HyperNet;
        matches!(self, Self::Handshake)
            || matches!(
                self,
                Self::ForwardRefused {
                    code: ErrorCode::Unavailable | ErrorCode::RateLimited | ErrorCode::Overloaded,
                    ..
                }
            )
            || matches!(
                self,
                Self::Companion(error) | Self::Connect(error)
                    if matches!(error, HyperNet::Timeout | HyperNet::Unavailable
                        | HyperNet::Closed | HyperNet::Capacity | HyperNet::Busy
                        | HyperNet::NotActive)
            )
    }
}
pub type Result<T> = std::result::Result<T, Error>;
// Automatic reconnects must not produce an unbounded diagnostic transcript.
static PREPARATION_DIAGNOSTICS: AtomicUsize = AtomicUsize::new(128);
fn preparation_failure(error: &crate::hypernet::Error, started: u64, deadline: u64) {
    if PREPARATION_DIAGNOSTICS
        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |remaining| {
            remaining.checked_sub(1)
        })
        .is_err()
    {
        return;
    }
    use std::io::Write;
    let _ = writeln!(
        std::io::stderr().lock(),
        "{}",
        serde_json::json!({"event":"ConnectionPreparationFailed", "code":error.code(),
            "startedBootMs":started, "finishedBootMs":clock::boot_ms().ok(),
            "setupDeadlineBootMs":deadline})
    );
}
pub struct Session {
    companion: Companion,
    stream: Arc<Stream>,
    server_key: VerifyingKey,
    pub ready: SessionReady,
    origin_key: VerifyingKey,
    origin: ServiceId,
    clock: clock::Config,
    pub remote: Option<RemoteSessionReady>,
}
impl Session {
    pub fn open(profile: &Profile, key: &SigningKey) -> Result<Self> {
        let end = clock::boot_ms().map_err(|_| Error::Clock)? + 30_000;
        establish(end, |end| Self::open_once(profile, key, end))
    }
    fn open_once(profile: &Profile, key: &SigningKey, overall_end: u64) -> Result<Self> {
        if Id::from_bytes(key.verifying_key().to_bytes()) != profile.registration.endpoint_key {
            return Err(Error::Authentication);
        }
        let companion = Companion::new(&profile.companion).map_err(Error::Companion)?;
        let started = clock::boot_ms().map_err(|_| Error::Clock)?;
        let stream = companion
            .connect(
                &profile.server.home.service.as_hex(),
                PROTOCOL,
                remaining(overall_end)?.min(Duration::from_secs(10)),
            )
            .map_err(|error| {
                preparation_failure(&error, started, overall_end);
                Error::Connect(error)
            })?;
        let Peer::Outgoing(_) = stream.peer() else {
            return Err(Error::Authentication);
        };
        let home = profile.server.home;
        if stream.peer().network() != home.network.network.as_hex()
            || stream.peer().incarnation() != home.network.incarnation.as_hex()
            || stream.peer().service() != home.service.as_hex()
            || stream.peer().protocol() != PROTOCOL
        {
            return Err(Error::Authentication);
        }
        let server_key = VerifyingKey::from_bytes(profile.server.signing_key.as_bytes())
            .map_err(|_| Error::Authentication)?;
        if server_key.is_weak() {
            return Err(Error::Authentication);
        }
        let end = overall_end.min(clock::boot_ms().map_err(|_| Error::Clock)? + 5000);
        let hello = SessionHello {
            home,
            account: profile.registration.account,
            endpoint: profile.registration.endpoint,
            client_nonce: Id::random().map_err(|_| Error::Authentication)?,
            versions: vec![VERSION],
            required_capabilities: Vec::new(),
            optional_capabilities: vec![
                "community-rooms".into(),
                "delegation".into(),
                "history".into(),
                "search".into(),
                "resume".into(),
            ],
        };
        send(
            &stream,
            FrameKind::Hello,
            encode_hello(&hello).map_err(|_| Error::Frame)?,
            end,
        )?;
        let incoming = io::receive(&stream, remaining(end)?).map_err(handshake_failure)?;
        if incoming.kind != FrameKind::Challenge {
            return Err(Error::Frame);
        }
        let verified =
            verify_challenge(&incoming.payload, &server_key).map_err(|_| Error::Authentication)?;
        let challenge = verified.value();
        let now = profile.clock.sample().map_err(|_| Error::Clock)?;
        if challenge.home != home
            || challenge.account != hello.account
            || challenge.endpoint != hello.endpoint
            || challenge.client_nonce != hello.client_nonce
            || challenge.transport_principal != profile.registration.transport_principal
            || challenge.transport_session.as_hex() != stream.peer().session()
            || challenge.transport_generation != stream.peer().generation()
            || now.upper_ms >= challenge.expires_ms
            || challenge.expires_ms > now.upper_ms.saturating_add(5000)
        {
            return Err(Error::Authentication);
        }
        let proof = SessionProof {
            home,
            account: hello.account,
            endpoint: hello.endpoint,
            client_nonce: hello.client_nonce,
            challenge_digest: verified.digest(),
        };
        send(
            &stream,
            FrameKind::Proof,
            sign_proof(&proof, key).map_err(|_| Error::Frame)?,
            end,
        )?;
        let incoming = io::receive(&stream, remaining(end)?).map_err(handshake_failure)?;
        if incoming.kind != FrameKind::Ready {
            return Err(Error::Frame);
        }
        let ready = verify_ready(&incoming.payload, &server_key)
            .map_err(|_| Error::Authentication)?
            .value()
            .clone();
        if ready.home != home
            || ready.session != challenge.session
            || ready.challenge_digest != verified.digest()
            || ready.acting.account != hello.account
            || ready.acting.endpoint != hello.endpoint
            || ready.classification != profile.registration.classification
            || ready.binding_digest != ready.acting.binding_digest
            || ready.maximum_frame_bytes != ORDINARY_FRAME_BYTES as u64
            || ready.maximum_crypto_frame_bytes != CRYPTO_FRAME_BYTES as u64
        {
            return Err(Error::Authentication);
        }
        if profile.clock.sample().map_err(|_| Error::Clock)?.upper_ms >= ready.window.expires_ms {
            return Err(Error::Expired);
        }
        let mut session = Self {
            companion,
            stream: Arc::new(stream),
            server_key,
            origin_key: server_key,
            origin: home,
            clock: profile.clock.clone(),
            ready,
            remote: None,
        };
        if let Some(selection) = profile.selected_federation() {
            session.open_remote(profile, selection, key, overall_end)?;
        }
        Ok(session)
    }
    fn open_remote(
        &mut self,
        profile: &Profile,
        selection: &super::federation::Selection,
        key: &SigningKey,
        end: u64,
    ) -> Result<()> {
        let agreement = selection.validate().map_err(|_| Error::Authentication)?;
        let now = profile.clock.sample().map_err(|_| Error::Clock)?;
        if !now.permits(agreement.not_before_ms, agreement.expires_ms)
            || !self
                .ready
                .capabilities
                .iter()
                .any(|c| c == FEDERATION_CAPABILITY)
        {
            return Err(Error::Authentication);
        }
        let request = RemoteSessionRequest {
            profile: FEDERATION_PROFILE,
            home: agreement.home,
            origin: agreement.origin,
            agreement: selection.agreement,
            request: Id::random().map_err(|_| Error::Authentication)?,
            account: self.ready.acting.account,
            endpoint: self.ready.acting.endpoint,
            endpoint_binding_digest: self.ready.binding_digest,
            client_nonce: Id::random().map_err(|_| Error::Authentication)?,
            created_ms: now.lower_ms,
            expires_ms: now.lower_ms + remaining(end)?.as_millis() as u64,
        };
        let signed = sign_remote_session_request(&request, key).map_err(|_| Error::Frame)?;
        let digest = verify_remote_session_request(&signed, &key.verifying_key())
            .map_err(|_| Error::Frame)?
            .digest();
        send(&self.stream, FrameKind::FederationControl, signed, end)?;
        let incoming = io::receive(&self.stream, remaining(end)?).map_err(handshake_failure)?;
        if incoming.kind != FrameKind::FederationControl {
            return Err(Error::Frame);
        }
        if let Some(error) = self.forwarding_refusal(
            &incoming,
            &request.home,
            request.agreement,
            request.request,
            Operation::FederationSession,
            digest,
        ) {
            return Err(error);
        }
        let home_key = VerifyingKey::from_bytes(selection.home.signing_key.as_bytes())
            .map_err(|_| Error::Authentication)?;
        let ready = verify_remote_session_ready(&incoming.payload, &home_key)
            .map_err(|_| Error::Authentication)?;
        let value = ready.value();
        if value.home != request.home
            || value.origin != request.origin
            || value.agreement != request.agreement
            || value.request != request.request
            || value.request_digest != digest
            || value.acting != self.ready.acting
            || value.classification != self.ready.classification
            || profile.clock.sample().map_err(|_| Error::Clock)?.upper_ms >= value.window.expires_ms
        {
            return Err(Error::Authentication);
        }
        self.ready.home = value.home;
        self.ready.window = value.window.clone();
        self.server_key = home_key;
        self.remote = Some(value.clone());
        Ok(())
    }
    fn forwarding_refusal(
        &self,
        incoming: &Frame,
        home: &ServiceId,
        agreement: AgreementRef,
        request: Id,
        operation: Operation,
        digest: Id,
    ) -> Option<Error> {
        if incoming.kind != FrameKind::FederationControl {
            return None;
        }
        let signed = verify_federation_control(&incoming.payload, &self.origin_key).ok()?;
        let FederationControl::Result {
            home: target,
            origin,
            agreement: reference,
            request: id,
            operation: op,
            request_digest,
            created_ms,
            expires_ms,
            outcome:
                Outcome::Refused {
                    code,
                    detail,
                    retry_after_ms,
                },
            ..
        } = signed.value()
        else {
            return None;
        };
        if target != home
            || *reference != agreement
            || *id != request
            || *op != operation
            || *request_digest != digest
        {
            return Some(Error::Authentication);
        }
        if *origin != self.origin
            || !self
                .clock
                .sample()
                .is_ok_and(|now| now.permits(*created_ms, *expires_ms))
        {
            return Some(Error::Authentication);
        }
        Some(Error::ForwardRefused {
            code: *code,
            detail: detail.clone(),
            retry_after_ms: *retry_after_ms,
        })
    }
    pub fn privacy(&self) -> Privacy {
        self.stream.privacy()
    }
    pub fn refresh_privacy(&self) -> Result<Privacy> {
        self.companion.status().map_err(|_| Error::Transport)?;
        Ok(self.stream.privacy())
    }
    pub fn action(&self, operation: Operation, target: Target, body: Value) -> Result<Action> {
        let actor = match self.ready.classification {
            AccountClass::Human => Actor::Direct {
                acting: self.ready.acting.clone(),
            },
            AccountClass::Agent { operator } => Actor::IndependentAgent {
                acting: self.ready.acting.clone(),
                operator,
            },
        };
        Ok(Action {
            home: self.ready.home,
            operation_id: OperationId {
                window: self.ready.window.id,
                operation: Id::random().map_err(|_| Error::Authentication)?,
            },
            actor,
            target,
            operation,
            body,
            expected: BTreeMap::new(),
            approval: None,
            agreement: self.remote.as_ref().map(|r| r.agreement),
        })
    }
    /// Submit exactly the persisted bytes. An I/O error does not imply rejection.
    pub fn submit(&self, bytes: &[u8], key: &VerifyingKey) -> Result<Verified<Response>> {
        self.submit_bounded(bytes, key, None)
    }
    /// Retry a read within its original caller budget; mutations cannot enter this path.
    pub(crate) fn submit_read_until(
        &self,
        bytes: &[u8],
        key: &VerifyingKey,
        end: u64,
    ) -> Result<Verified<Response>> {
        self.submit_bounded(bytes, key, Some(end))
    }
    fn submit_bounded(
        &self,
        bytes: &[u8],
        key: &VerifyingKey,
        end: Option<u64>,
    ) -> Result<Verified<Response>> {
        let action = verify_action(bytes, key).map_err(|_| Error::Authentication)?;
        if action.action().home != self.ready.home
            || action.action().actor.acting() != &self.ready.acting
            || end.is_some() && !crate::home::is_read_operation(action.action().operation)
        {
            return Err(Error::Authentication);
        }
        let kind = if action.action().operation.is_crypto_transition() {
            FrameKind::CryptoAction
        } else {
            FrameKind::Action
        };
        let frame = Frame::new(kind, bytes.to_vec()).map_err(|_| Error::Frame)?;
        let incoming = if let Some(end) = end {
            let send_end = end.min(
                clock::boot_ms()
                    .map_err(|_| Error::Clock)?
                    .saturating_add(5000),
            );
            io::send_before(&self.stream, &frame, send_end).map_err(transport_failure)?;
            io::receive_before(&self.stream, end).map_err(transport_failure)?
        } else {
            io::send(&self.stream, &frame, Duration::from_secs(5)).map_err(transport_failure)?;
            io::receive(&self.stream, Duration::from_secs(10)).map_err(transport_failure)?
        };
        if let Some(remote) = &self.remote
            && let Some(error) = self.forwarding_refusal(
                &incoming,
                &action.action().home,
                remote.agreement,
                action.action().operation_id.operation,
                Operation::FederationExchange,
                action.digest(),
            )
        {
            return Err(error);
        }
        let verified = if action.action().operation.is_crypto_transition() {
            if incoming.kind != FrameKind::CryptoResponse {
                return Err(Error::Frame);
            }
            verify_crypto_response(&incoming.payload, &self.server_key)
        } else {
            if incoming.kind != FrameKind::Response {
                return Err(Error::Frame);
            }
            verify_response(&incoming.payload, &self.server_key)
        }
        .map_err(|_| Error::Authentication)?;
        let response = verified.value();
        if response.home != action.action().home
            || response.operation_id != action.action().operation_id
            || response.action_digest != action.digest()
        {
            return Err(Error::Authentication);
        }
        Ok(verified)
    }
    pub fn stream_handle(&self) -> Arc<Stream> {
        Arc::clone(&self.stream)
    }
    /// The sole reader demultiplexes one query and, at most, its exact cancellation response.
    pub fn submit_cancellable(
        &self,
        bytes: &[u8],
        cancel_bytes: &[u8],
        key: &VerifyingKey,
        cancel: &AtomicBool,
    ) -> Result<Verified<Response>> {
        let query = verify_action(bytes, key).map_err(|_| Error::Authentication)?;
        let control = verify_action(cancel_bytes, key).map_err(|_| Error::Authentication)?;
        let reference: crate::home::Resolve = control
            .action()
            .body
            .deserialized()
            .map_err(|_| Error::Frame)?;
        if query.action().operation != Operation::SearchQuery
            || control.action().operation != Operation::SearchCancel
            || control.action().actor != query.action().actor
            || query.action().actor.acting() != &self.ready.acting
            || query.action().home != self.ready.home
            || control.action().home != self.ready.home
            || reference.operation_id != query.action().operation_id
            || reference.action_digest != query.digest()
        {
            return Err(Error::Authentication);
        }
        if self.remote.is_some() {
            return self.remote_query(&query, bytes, cancel);
        }
        let end = clock::boot_ms().map_err(|_| Error::Clock)? + 10000;
        io::send(
            &self.stream,
            &Frame::new(FrameKind::Action, bytes.to_vec()).map_err(|_| Error::Frame)?,
            remaining(end)?,
        )
        .map_err(transport_failure)?;
        let mut sent = false;
        let mut query_response = None;
        let mut control_response = false;
        loop {
            if cancel.load(Ordering::Acquire) && !sent && query_response.is_none() {
                io::send(
                    &self.stream,
                    &Frame::new(FrameKind::Action, cancel_bytes.to_vec())
                        .map_err(|_| Error::Frame)?,
                    remaining(end)?.min(Duration::from_secs(5)),
                )
                .map_err(transport_failure)?;
                sent = true;
            }
            if (!sent || control_response)
                && let Some(response) = query_response.take()
            {
                return Ok(response);
            }
            if !self
                .stream
                .wait_readable(remaining(end)?.min(Duration::from_millis(25)))
                .map_err(|_| Error::Transport)?
            {
                continue;
            }
            let incoming = io::receive(&self.stream, remaining(end)?).map_err(transport_failure)?;
            if incoming.kind != FrameKind::Response {
                return Err(Error::Frame);
            }
            let response = verify_response(&incoming.payload, &self.server_key)
                .map_err(|_| Error::Authentication)?;
            if response.value().home != self.ready.home {
                return Err(Error::Authentication);
            }
            if response.value().operation_id == query.action().operation_id
                && response.value().action_digest == query.digest()
                && query_response.is_none()
            {
                query_response = Some(response);
            } else if sent
                && response.value().operation_id == control.action().operation_id
                && response.value().action_digest == control.digest()
                && !control_response
            {
                control_response = true;
            } else {
                return Err(Error::Authentication);
            }
        }
    }
    pub fn close(&self) {
        self.stream.close();
    }
    // A gateway serializes one request per stream. Closing the query's stream
    // propagates cancellation without granting a second action any authority.
    fn remote_query(
        &self,
        query: &VerifiedAction,
        bytes: &[u8],
        cancel: &AtomicBool,
    ) -> Result<Verified<Response>> {
        let end = clock::boot_ms().map_err(|_| Error::Clock)? + 10000;
        if cancel.load(Ordering::Acquire) {
            return Err(Error::QueryCancelled);
        }
        send(&self.stream, FrameKind::Action, bytes.to_vec(), end)?;
        loop {
            if cancel.load(Ordering::Acquire) {
                self.close();
                return Err(Error::QueryCancelled);
            }
            if !self
                .stream
                .wait_readable(remaining(end)?.min(Duration::from_millis(25)))
                .map_err(|_| Error::Transport)?
            {
                continue;
            }
            let frame = io::receive(&self.stream, remaining(end)?).map_err(transport_failure)?;
            let remote = self.remote.as_ref().ok_or(Error::Authentication)?;
            if let Some(error) = self.forwarding_refusal(
                &frame,
                &query.action().home,
                remote.agreement,
                query.action().operation_id.operation,
                Operation::FederationExchange,
                query.digest(),
            ) {
                return Err(error);
            }
            if frame.kind != FrameKind::Response {
                return Err(Error::Frame);
            }
            let result = verify_response(&frame.payload, &self.server_key)
                .map_err(|_| Error::Authentication)?;
            if result.value().home != query.action().home
                || result.value().operation_id != query.action().operation_id
                || result.value().action_digest != query.digest()
            {
                return Err(Error::Authentication);
            }
            return Ok(result);
        }
    }
}
/// Transient preparation or a discarded handoff precedes any HRC operation.
/// Obtain a fresh stream and challenge without renewing the original deadline.
fn establish<T>(end: u64, mut attempt: impl FnMut(u64) -> Result<T>) -> Result<T> {
    for number in 0..3 {
        if remaining(end)?.as_millis() < 100 {
            return Err(Error::Handshake);
        }
        match attempt(end) {
            Err(error) if error.retryable_setup() && number < 2 => {
                let mut jitter = [0u8; 1];
                getrandom::fill(&mut jitter).map_err(|_| Error::Authentication)?;
                let backoff = 200 + number * 200 + u64::from(jitter[0]);
                let advised = match &error {
                    Error::ForwardRefused { retry_after_ms, .. } => retry_after_ms.unwrap_or(1000),
                    _ => 0,
                };
                let delay = Duration::from_millis(backoff.max(advised));
                let Ok(left) = remaining(end) else {
                    return Err(error);
                };
                if delay > left.saturating_sub(Duration::from_millis(100)) {
                    return Err(error);
                }
                std::thread::sleep(delay);
            }
            result => return result,
        }
    }
    Err(Error::Handshake)
}
fn remaining(end: u64) -> Result<Duration> {
    let now = clock::boot_ms().map_err(|_| Error::Clock)?;
    if now >= end {
        Err(Error::Handshake)
    } else {
        Ok(Duration::from_millis(end - now))
    }
}
fn send(stream: &Stream, kind: FrameKind, payload: Vec<u8>, end: u64) -> Result<()> {
    io::send(
        stream,
        &Frame::new(kind, payload).map_err(|_| Error::Frame)?,
        remaining(end)?,
    )
    .map_err(handshake_failure)
}

fn handshake_failure(error: io::Error) -> Error {
    match error {
        io::Error::Frame => Error::Frame,
        io::Error::Transport | io::Error::Deadline => Error::Handshake,
    }
}

fn transport_failure(error: io::Error) -> Error {
    match error {
        io::Error::Frame => Error::Frame,
        io::Error::Transport | io::Error::Deadline => Error::Transport,
    }
}

#[cfg(test)]
#[path = "../../Tests/Client/Connection.rs"]
mod tests;
