// SPDX-License-Identifier: Apache-2.0
//! Authenticated HRC sessions over mandatory HyperNet streams.
use super::{Config, files, io};
use crate::{
    clock,
    home::{AuthenticatedSession, Home},
    hypernet::{Companion, Peer, Stream},
    protocol::*,
};
use std::{
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    thread,
    time::Duration,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid service configuration")]
    Configuration,
    #[error("service state is unavailable")]
    State,
    #[error("HyperNet transport is unavailable")]
    Transport,
    #[error("HRC session authentication failed")]
    Authentication,
    #[error("HRC session frame is invalid")]
    Frame,
    #[error("current authority is unavailable")]
    Authority,
    #[error("a current clock observation is unavailable")]
    Clock,
    #[error("the session handshake expired")]
    HandshakeExpired,
    #[error("the current retry window could not be established")]
    RetryWindow,
    #[error("the ingress budget was exceeded")]
    RateLimited,
}
impl Error {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Configuration => "ServiceConfigurationUnavailable",
            Self::State => "ServiceStateUnavailable",
            Self::Transport => "TransportUnavailable",
            Self::Authentication => "SessionAuthenticationFailed",
            Self::Frame => "InvalidSessionFrame",
            Self::Authority => "CurrentAuthorityUnavailable",
            Self::Clock => "ClockUnavailable",
            Self::HandshakeExpired => "HandshakeExpired",
            Self::RetryWindow => "RetryWindowUnavailable",
            Self::RateLimited => "IngressRateLimited",
        }
    }
}
pub type Result<T> = std::result::Result<T, Error>;

const CAPABILITIES: &[&str] = &[
    "community-rooms",
    "delegation",
    "history",
    "search",
    "resume",
];
struct Shared {
    config: Config,
    signer: SigningKey,
    home: Mutex<Home>,
    companion: Companion,
    boot: Id,
    handshakes: AtomicUsize,
    ingress: Mutex<Budget>,
    diagnostics: Option<Mutex<Budget>>,
    diagnostic_lines: AtomicUsize,
}
impl Shared {
    fn report(&self, error: &Error) {
        let Some(budget) = &self.diagnostics else {
            return;
        };
        let Ok(now) = clock::boot_ms() else { return };
        let Ok(mut budget) = budget.try_lock() else {
            return;
        };
        if !budget.admit(now)
            || self
                .diagnostic_lines
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_sub(1))
                .is_err()
        {
            return;
        }
        drop(budget);
        // Only fixed categories enter diagnostics; no peer-controlled text or identifiers.
        eprintln!(
            "{{\"event\":\"SessionClosed\",\"code\":\"{}\"}}",
            error.code()
        );
    }
}
struct Handshake<'a>(&'a AtomicUsize);
impl Drop for Handshake<'_> {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Release);
    }
}
struct Budget {
    at: u64,
    remaining: u64,
    rate: u64,
    burst: u64,
}
impl Budget {
    fn new(rate: u64, burst: u64) -> Self {
        Self {
            at: 0,
            remaining: burst * 1000,
            rate,
            burst,
        }
    }
    fn admit(&mut self, now: u64) -> bool {
        self.remaining = self
            .remaining
            .saturating_add(now.saturating_sub(self.at).saturating_mul(self.rate))
            .min(self.burst * 1000);
        self.at = now;
        if self.remaining < 1000 {
            return false;
        }
        self.remaining -= 1000;
        true
    }
}

/// Run one home service. The caller controls shutdown; no network listener is opened.
pub fn run(directory: &Path, stop: Arc<AtomicBool>) -> Result<()> {
    run_with_ready(directory, stop, false, |_| Ok(()))
}
pub fn run_with_ready(
    directory: &Path,
    stop: Arc<AtomicBool>,
    diagnostics: bool,
    ready: impl FnOnce(&super::Descriptor) -> Result<()>,
) -> Result<()> {
    let config = Config::load(directory).map_err(|_| Error::Configuration)?;
    let signer = files::key(&directory.join("Signing.key")).map_err(|_| Error::Configuration)?;
    let home = Home::open(
        config.store(directory).map_err(|_| Error::State)?,
        config.descriptor.home,
        signer.clone(),
    )
    .map_err(|_| Error::State)?;
    config.clock.sample().map_err(|_| Error::Clock)?;
    let companion = Companion::new(&config.companion).map_err(|_| Error::Transport)?;
    let status = companion.status().map_err(|_| Error::Transport)?;
    if !status.check_authority().supported() || !status.check_authority().endpoint_ready() {
        return Err(Error::Authority);
    }
    let shared = Arc::new(Shared {
        config,
        signer,
        home: Mutex::new(home),
        companion,
        boot: Id::random().map_err(|_| Error::State)?,
        handshakes: AtomicUsize::new(0),
        ingress: Mutex::new(Budget::new(64, 16)),
        diagnostics: diagnostics.then(|| Mutex::new(Budget::new(1, 8))),
        diagnostic_lines: AtomicUsize::new(128),
    });
    ready(&shared.config.descriptor)?;
    let mut connections: Vec<(Arc<Stream>, thread::JoinHandle<()>)> = Vec::new();
    let mut maintained = std::time::Instant::now();
    while !stop.load(Ordering::Acquire) {
        if maintained.elapsed() >= Duration::from_secs(1) {
            maintained = std::time::Instant::now();
            if let Ok(now) = shared.config.clock.sample()
                && let Ok(mut home) = shared.home.try_lock()
            {
                let _ = home.maintain(now);
            }
        }
        let mut i = 0;
        while i < connections.len() {
            if connections[i].1.is_finished() {
                let (_, worker) = connections.swap_remove(i);
                let _ = worker.join();
            } else {
                i += 1;
            }
        }
        let stream = match shared.companion.accept(Duration::from_secs(1)) {
            Ok(stream) => Arc::new(stream),
            Err(crate::hypernet::Error::Timeout | crate::hypernet::Error::Refused) => continue,
            Err(_) => {
                for (stream, _) in &connections {
                    stream.close();
                }
                return Err(Error::Transport);
            }
        };
        if connections.len() >= 16
            || shared
                .handshakes
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                    (n < 4).then_some(n + 1)
                })
                .is_err()
        {
            stream.close();
            continue;
        }
        let state = Arc::clone(&shared);
        let client = Arc::clone(&stream);
        let worker = thread::spawn(move || {
            if let Err(error) = serve(&state, &client) {
                state.report(&error);
            }
            client.close();
        });
        connections.push((stream, worker));
    }
    for (stream, _) in &connections {
        stream.close();
    }
    for (_, worker) in connections {
        let _ = worker.join();
    }
    Ok(())
}

fn remaining(end: u64) -> Result<Duration> {
    let now = clock::boot_ms().map_err(|_| Error::Clock)?;
    if now >= end {
        Err(Error::HandshakeExpired)
    } else {
        Ok(Duration::from_millis(end - now))
    }
}
fn frame(stream: &Stream, kind: FrameKind, payload: Vec<u8>, timeout: Duration) -> Result<()> {
    io::send(
        stream,
        &Frame::new(kind, payload).map_err(|_| Error::Frame)?,
        timeout,
    )
    .map_err(|_| Error::Transport)
}
fn serve(shared: &Shared, stream: &Stream) -> Result<()> {
    let handshake = Handshake(&shared.handshakes);
    let Peer::Incoming(peer) = stream.peer() else {
        return Err(Error::Authentication);
    };
    let home = shared.config.descriptor.home;
    if stream.peer().protocol() != PROTOCOL
        || stream.peer().network() != home.network.network.as_hex()
        || stream.peer().incarnation() != home.network.incarnation.as_hex()
        || stream.peer().service() != home.service.as_hex()
        || !stream.check_authority_supported()
    {
        return Err(Error::Authentication);
    }
    let principal = Id::from_hex(peer.principal()).map_err(|_| Error::Authentication)?;
    let end = clock::boot_ms().map_err(|_| Error::Clock)? + 5000;
    let incoming = io::receive(stream, remaining(end)?).map_err(|_| Error::Transport)?;
    if incoming.kind != FrameKind::Hello {
        return Err(Error::Frame);
    }
    let hello = decode_hello(&incoming.payload).map_err(|_| Error::Frame)?;
    if hello.home != home
        || !hello.versions.contains(&VERSION)
        || hello
            .required_capabilities
            .iter()
            .any(|v| !CAPABILITIES.contains(&v.as_str()))
    {
        return Err(Error::Authentication);
    }
    let endpoint = shared
        .home
        .lock()
        .map_err(|_| Error::State)?
        .endpoint(hello.account, hello.endpoint)
        .map_err(|_| Error::State)?
        .ok_or(Error::Authentication)?;
    if endpoint.principal != principal {
        return Err(Error::Authentication);
    }
    let now = shared.config.clock.sample().map_err(|_| Error::Clock)?;
    let challenge = SessionChallenge {
        home,
        account: hello.account,
        endpoint: hello.endpoint,
        client_nonce: hello.client_nonce,
        nonce: Id::random().map_err(|_| Error::State)?,
        session: Id::random().map_err(|_| Error::State)?,
        service_boot: shared.boot,
        transport_principal: principal,
        transport_session: Id::from_hex(stream.peer().session())
            .map_err(|_| Error::Authentication)?,
        transport_generation: stream.peer().generation(),
        expires_ms: now.lower_ms + 5000,
    };
    let signed = sign_challenge(&challenge, &shared.signer).map_err(|_| Error::Frame)?;
    let challenge_digest = verify_challenge(&signed, &shared.signer.verifying_key())
        .map_err(|_| Error::Frame)?
        .digest();
    frame(stream, FrameKind::Challenge, signed, remaining(end)?)?;
    let incoming = io::receive(stream, remaining(end)?).map_err(|_| Error::Transport)?;
    if incoming.kind != FrameKind::Proof {
        return Err(Error::Authentication);
    }
    let proof =
        verify_proof(&incoming.payload, &endpoint.key).map_err(|_| Error::Authentication)?;
    let p = proof.value();
    if p.home != home
        || p.account != hello.account
        || p.endpoint != hello.endpoint
        || p.client_nonce != hello.client_nonce
        || p.challenge_digest != challenge_digest
    {
        return Err(Error::Authentication);
    }
    let check = shared
        .companion
        .check_authority(
            stream,
            *proof.digest().as_bytes(),
            remaining(end)?.min(Duration::from_secs(1)),
        )
        .map_err(|_| Error::Authority)?;
    let now = shared.config.clock.sample().map_err(|_| Error::Clock)?;
    if now.upper_ms >= challenge.expires_ms || clock::boot_ms().map_err(|_| Error::Clock)? >= end {
        return Err(Error::HandshakeExpired);
    }
    if !check.permitted() {
        return Err(Error::Authority);
    }
    let window = shared
        .home
        .lock()
        .map_err(|_| Error::State)?
        .open_window(&endpoint, now, &|| check.permitted())
        .map_err(|_| Error::RetryWindow)?;
    let session = AuthenticatedSession::new(
        &endpoint,
        principal,
        challenge.transport_session,
        challenge.transport_generation,
    )
    .map_err(|_| Error::Authentication)?;
    let ready = SessionReady {
        home,
        session: challenge.session,
        challenge_digest,
        window,
        maximum_frame_bytes: ORDINARY_FRAME_BYTES as u64,
        maximum_crypto_frame_bytes: CRYPTO_FRAME_BYTES as u64,
        capabilities: CAPABILITIES.iter().map(|s| (*s).to_owned()).collect(),
        account_revision: endpoint.revision,
        binding_digest: endpoint.acting.binding_digest,
        acting: endpoint.acting.clone(),
        classification: endpoint.classification.clone(),
    };
    frame(
        stream,
        FrameKind::Ready,
        sign_ready(&ready, &shared.signer).map_err(|_| Error::Frame)?,
        remaining(end)?,
    )?;
    drop(handshake);
    let mut budget = Budget::new(32, 8);
    loop {
        let incoming =
            io::receive(stream, Duration::from_secs(60)).map_err(|_| Error::Transport)?;
        if incoming.kind == FrameKind::Close {
            return Ok(());
        }
        if !matches!(incoming.kind, FrameKind::Action | FrameKind::CryptoAction) {
            return Err(Error::Frame);
        }
        let now = clock::boot_ms().map_err(|_| Error::Clock)?;
        if !budget.admit(now) || !shared.ingress.lock().map_err(|_| Error::State)?.admit(now) {
            return Err(Error::RateLimited);
        }
        let verified =
            verify_action(&incoming.payload, &endpoint.key).map_err(|_| Error::Authentication)?;
        if (incoming.kind == FrameKind::CryptoAction)
            != verified.action().operation.is_crypto_transition()
        {
            return Err(Error::Frame);
        }
        let response = execute(shared, stream, &verified, &session);
        frame(
            stream,
            FrameKind::Response,
            sign_response(&response, &shared.signer).map_err(|_| Error::Frame)?,
            Duration::from_secs(5),
        )?;
    }
}
fn execute(
    shared: &Shared,
    stream: &Stream,
    action: &VerifiedAction,
    session: &AuthenticatedSession,
) -> Response {
    let base = |outcome| Response {
        home: shared.config.descriptor.home,
        operation_id: action.action().operation_id,
        action_digest: action.digest(),
        outcome,
    };
    let refused = |code, detail| {
        base(Outcome::Refused {
            code,
            detail: String::from(detail),
            retry_after_ms: Some(1000),
        })
    };
    let Ok(check) = shared.companion.check_authority(
        stream,
        *action.digest().as_bytes(),
        Duration::from_secs(1),
    ) else {
        return refused(ErrorCode::Unavailable, "TransportAuthority");
    };
    if !check.permitted() {
        use crate::hypernet::Disposition;
        let (code, detail) = match check.disposition() {
            Disposition::Denied if check.certified() => (ErrorCode::Denied, "TransportDenied"),
            Disposition::Expired => (ErrorCode::Expired, "TransportAuthorityExpired"),
            Disposition::NotActive => (ErrorCode::Unavailable, "TransportInactive"),
            _ => (ErrorCode::Unavailable, "TransportAuthority"),
        };
        return refused(code, detail);
    }
    let Ok(now) = shared.config.clock.sample() else {
        return refused(ErrorCode::Unavailable, "Clock");
    };
    let Ok(mut home) = shared.home.try_lock() else {
        return refused(ErrorCode::Overloaded, "OperationBusy");
    };
    match home.execute(action, session, now, &|| check.permitted()) {
        Ok(response) => response,
        Err(_) => base(Outcome::Unknown),
    }
}
