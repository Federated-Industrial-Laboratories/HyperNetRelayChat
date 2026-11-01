// SPDX-License-Identifier: Apache-2.0
//! One authenticated HyperNet session; persistence owns retry decisions.
use super::Profile;
use crate::{
    clock,
    hypernet::{Companion, Peer, Privacy, Stream},
    protocol::*,
    service::io,
};
use std::{collections::BTreeMap, time::Duration};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("the configured HyperNet companion is unavailable")]
    Companion,
    #[error("HyperNet could not prepare the authorized connection")]
    Connect,
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
            Self::Companion => "CompanionUnavailable",
            Self::Connect => "HyperNetPreparationUnavailable",
            Self::Handshake => "HrcHandshakeUnavailable",
            Self::Transport => "TransportUnavailable",
            Self::Authentication => "SessionAuthenticationFailed",
            Self::Frame => "InvalidSessionFrame",
            Self::Clock => "ClockUnavailable",
            Self::Expired => "RetryWindowExpired",
        }
    }
}
pub type Result<T> = std::result::Result<T, Error>;
pub struct Session {
    companion: Companion,
    stream: Stream,
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
        let companion = Companion::new(&profile.companion).map_err(|_| Error::Companion)?;
        let stream = companion
            .connect(
                &profile.server.home.service.as_hex(),
                PROTOCOL,
                remaining(overall_end)?.min(Duration::from_secs(10)),
            )
            .map_err(|_| Error::Connect)?;
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
            stream,
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
        io::send(&self.stream, &frame, Duration::from_secs(5)).map_err(|_| Error::Transport)?;
        let incoming =
            io::receive(&self.stream, Duration::from_secs(10)).map_err(|_| Error::Transport)?;
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
    pub fn close(&self) {
        self.stream.close();
    }
}
/// A discarded transport handoff can precede any HRC operation. Obtain a fresh
/// stream and challenge; never reuse authority or retry an operation here.
fn establish<T>(end: u64, mut attempt: impl FnMut(u64) -> Result<T>) -> Result<T> {
    for number in 0..3 {
        if remaining(end)?.as_millis() < 100 {
            return Err(Error::Handshake);
        }
        match attempt(end) {
            Err(Error::Handshake) if number < 2 => {
                let mut jitter = [0u8; 1];
                getrandom::fill(&mut jitter).map_err(|_| Error::Authentication)?;
                let delay = Duration::from_millis(200 + number * 200 + u64::from(jitter[0]));
                std::thread::sleep(delay.min(remaining(end)?));
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

#[cfg(test)]
#[path = "../../Tests/Client/Connection.rs"]
mod tests;
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
