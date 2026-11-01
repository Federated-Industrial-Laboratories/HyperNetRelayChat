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
        atomic::{AtomicBool, Ordering},
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
        }
    }
    pub(crate) fn retryable_session(&self) -> bool {
        self.retryable_setup() || matches!(self, Self::Transport | Self::Clock)
    }
    fn retryable_setup(&self) -> bool {
        use crate::hypernet::Error as HyperNet;
        matches!(self, Self::Handshake)
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
pub struct Session {
    companion: Companion,
    stream: Arc<Stream>,
    server_key: VerifyingKey,
    pub ready: SessionReady,
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
                eprintln!(
                    "{}",
                    serde_json::json!({"event":"ConnectionPreparationFailed", "code":error.code(),
                        "startedBootMs":started, "finishedBootMs":clock::boot_ms().ok(),
                        "setupDeadlineBootMs":overall_end})
                );
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
        Ok(Self {
            companion,
            stream: Arc::new(stream),
            server_key,
            ready,
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
            agreement: None,
        })
    }
    /// Submit exactly the persisted bytes. An I/O error does not imply rejection.
    pub fn submit(&self, bytes: &[u8], key: &VerifyingKey) -> Result<Verified<Response>> {
        let action = verify_action(bytes, key).map_err(|_| Error::Authentication)?;
        if action.action().home != self.ready.home
            || action.action().actor.acting() != &self.ready.acting
        {
            return Err(Error::Authentication);
        }
        let kind = if action.action().operation.is_crypto_transition() {
            FrameKind::CryptoAction
        } else {
            FrameKind::Action
        };
        let frame = Frame::new(kind, bytes.to_vec()).map_err(|_| Error::Frame)?;
        io::send(&self.stream, &frame, Duration::from_secs(5)).map_err(transport_failure)?;
        let incoming =
            io::receive(&self.stream, Duration::from_secs(10)).map_err(transport_failure)?;
        if incoming.kind != FrameKind::Response {
            return Err(Error::Frame);
        }
        let verified = verify_response(&incoming.payload, &self.server_key)
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
                let delay = Duration::from_millis(200 + number * 200 + u64::from(jitter[0]));
                let Ok(left) = remaining(end) else {
                    return Err(error);
                };
                if left < delay + Duration::from_millis(100) {
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
