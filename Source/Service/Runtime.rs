// SPDX-License-Identifier: Apache-2.0
//! Authenticated HRC sessions over mandatory HyperNet streams.
use super::{Config, admission, files, io};
use crate::{
    clock,
    home::{AuthenticatedSession, Cancellation, Home},
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
#[path = "Devices.rs"]
mod devices;
#[path = "FederationGateway.rs"]
mod federation_gateway;
#[path = "FederationOrigin.rs"]
mod federation_origin;
#[path = "Handshake.rs"]
mod handshake;

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
    #[error("authority check admission is busy")]
    AuthorityAdmissionBusy,
    #[error("authority check admission was stopped")]
    AuthorityAdmissionStopped,
    #[error("the enclosing authority check deadline expired")]
    AuthorityAdmissionExpired,
    #[error("the federation peer refused the current forwarding attempt")]
    ForwardRefused {
        code: ErrorCode,
        detail: String,
        retry_after_ms: Option<u64>,
    },
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
            Self::AuthorityAdmissionBusy => "AuthorityAdmissionBusy",
            Self::AuthorityAdmissionStopped => "AuthorityAdmissionStopped",
            Self::AuthorityAdmissionExpired => "AuthorityAdmissionExpired",
            Self::ForwardRefused { .. } => "FederationForwardRefused",
        }
    }
}
pub type Result<T> = std::result::Result<T, Error>;

const CAPABILITIES: &[&str] = &[
    CLIENT_VIEWS_CAPABILITY,
    "community-rooms",
    "delegation",
    "history",
    "search",
    "resume",
    "confidential-conversations",
    "endpoint-lifecycle",
    FEDERATION_CAPABILITY,
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
    authority_admission: admission::Admission,
    federation_routes: Vec<federation_origin::OutboundRoute>,
    stop: Arc<AtomicBool>,
}
impl Shared {
    fn check_authority(
        &self,
        stream: &Stream,
        digest: Id,
        end: Option<u64>,
        cancel: &Cancellation,
        operation: &'static str,
    ) -> Result<crate::hypernet::AuthorityCheck> {
        let map = |error| match error {
            admission::Error::Busy => Error::AuthorityAdmissionBusy,
            admission::Error::Stopped => Error::AuthorityAdmissionStopped,
            admission::Error::Expired => Error::AuthorityAdmissionExpired,
            admission::Error::Unavailable => Error::State,
        };
        let permit = self
            .authority_admission
            .acquire(end, || {
                self.stop.load(Ordering::Acquire)
                    || cancel.is_cancelled()
                    || !stream.check_authority_supported()
            })
            .map_err(map)?;
        let check_end = permit.check_deadline().map_err(map)?;
        let result = self
            .companion
            .check_authority_until(stream, *digest.as_bytes(), check_end)
            .map_err(|error| {
                self.report(operation, error.code());
                if matches!(error, crate::hypernet::Error::Timeout) {
                    Error::AuthorityAdmissionExpired
                } else {
                    Error::Authority
                }
            });
        // The finite observation is used below without retaining the admission slot.
        drop(permit);
        if result.as_ref().is_ok_and(|check| check.permitted())
            && end.is_some_and(|end| !clock::boot_ms().is_ok_and(|now| now < end))
        {
            return Err(Error::AuthorityAdmissionExpired);
        }
        result
    }
    fn report(&self, event: &'static str, code: &'static str) {
        self.report_check(event, code, None);
    }
    fn report_check(
        &self,
        event: &'static str,
        code: &'static str,
        check: Option<&crate::hypernet::AuthorityCheck>,
    ) {
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
        // Only fixed categories and freshness timing enter diagnostics, never peer identifiers or content.
        let authority = check.and_then(|check| {
            let value = serde_json::to_value(check).ok()?;
            let mut fields = serde_json::Map::new();
            for name in [
                "disposition",
                "receiptDisposition",
                "companionStartedBootMs",
                "companionDeadlineBootMs",
                "receiptNotAfterBootMs",
                "usableUntilBootMs",
                "usableNow",
            ] {
                fields.insert(name.into(), value.get(name)?.clone());
            }
            fields.insert(
                "certified".into(),
                serde_json::Value::Bool(check.certified()),
            );
            Some(serde_json::Value::Object(fields))
        });
        crate::diagnostics::emit(
            &serde_json::json!({"event":event,"code":code,"bootMs":now,"authority":authority})
                .to_string(),
        );
    }
    fn authentication(&self, stage: &'static str) -> Error {
        self.report("SessionAuthenticationFailed", stage);
        Error::Authentication
    }
}
/// Own at most one periodic storage task without performing disk work on accept.
struct Maintenance {
    last: std::time::Instant,
    worker: Option<thread::JoinHandle<()>>,
}
impl Maintenance {
    fn new() -> Self {
        Self {
            last: std::time::Instant::now(),
            worker: None,
        }
    }
    fn tick(&mut self, shared: &Arc<Shared>) {
        if self.last.elapsed() < Duration::from_secs(30)
            || self
                .worker
                .as_ref()
                .is_some_and(|worker| !worker.is_finished())
        {
            return;
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        self.last = std::time::Instant::now();
        let shared = Arc::clone(shared);
        self.worker = Some(thread::spawn(move || {
            if let Ok(now) = shared.config.clock.sample()
                && let Ok(mut home) = shared.home.try_lock()
                && home.maintain(now).is_err()
            {
                shared.report("MaintenanceFailed", "ServiceStateUnavailable");
            }
        }));
    }
}
impl Drop for Maintenance {
    fn drop(&mut self) {
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
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

fn load_shared(directory: &Path, stop: Arc<AtomicBool>, diagnostics: bool) -> Result<Shared> {
    let config = Config::load(directory).map_err(|_| Error::Configuration)?;
    let signer = files::key(&directory.join("Signing.key")).map_err(|_| Error::Configuration)?;
    let home = Home::open(
        config.store(directory).map_err(|_| Error::State)?,
        config.descriptor.home,
        signer.clone(),
    )
    .map_err(|_| Error::State)?
    .with_motd(config.motd.clone())
    .map_err(|_| Error::Configuration)?;
    config.clock.sample().map_err(|_| Error::Clock)?;
    let companion = Companion::new(&config.companion).map_err(|_| Error::Transport)?;
    let boot = home.federation_boot;
    let federation_routes = federation_origin::load(directory)?;
    let shared = Shared {
        config,
        signer,
        home: Mutex::new(home),
        companion,
        boot,
        handshakes: AtomicUsize::new(0),
        ingress: Mutex::new(Budget::new(64, 16)),
        diagnostics: diagnostics.then(|| Mutex::new(Budget::new(1, 8))),
        diagnostic_lines: AtomicUsize::new(128),
        authority_admission: admission::Admission::default(),
        federation_routes,
        stop: Arc::clone(&stop),
    };
    Ok(shared)
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
    if diagnostics {
        crate::diagnostics::start();
    }
    let shared = Arc::new(load_shared(directory, Arc::clone(&stop), diagnostics)?);
    let status = shared.companion.status().map_err(|_| Error::Transport)?;
    if !status.check_authority().supported() || !status.check_authority().endpoint_ready() {
        return Err(Error::Authority);
    }
    ready(&shared.config.descriptor)?;
    let _federation = federation_origin::Maintenance::start(Arc::clone(&shared))?;
    let mut connections: Vec<(Arc<Stream>, thread::JoinHandle<()>)> = Vec::new();
    let mut maintenance = Maintenance::new();
    while !stop.load(Ordering::Acquire) {
        maintenance.tick(&shared);
        let mut i = 0;
        while i < connections.len() {
            if connections[i].1.is_finished() {
                let (_, worker) = connections.swap_remove(i);
                let _ = worker.join();
            } else {
                i += 1;
            }
        }
        let stream = match shared.companion.accept(Duration::from_secs(5)) {
            Ok(stream) => Arc::new(stream),
            Err(error @ (crate::hypernet::Error::Timeout | crate::hypernet::Error::Refused)) => {
                shared.report("AcceptWaitEnded", error.code());
                continue;
            }
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
                state.report("SessionClosed", error.code());
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
        return Err(shared.authentication("IncomingPeerRequired"));
    };
    let home = shared.config.descriptor.home;
    if stream.peer().protocol() != PROTOCOL
        || stream.peer().network() != home.network.network.as_hex()
        || stream.peer().incarnation() != home.network.incarnation.as_hex()
        || stream.peer().service() != home.service.as_hex()
        || !stream.check_authority_supported()
    {
        return Err(shared.authentication("TransportContextBinding"));
    }
    let principal =
        Id::from_hex(peer.principal()).map_err(|_| shared.authentication("PrincipalEncoding"))?;
    let end = clock::boot_ms().map_err(|_| Error::Clock)? + 5000;
    let incoming = io::receive(stream, remaining(end)?).map_err(|_| Error::Transport)?;
    if incoming.kind == FrameKind::FederationControl {
        return federation_gateway::serve(shared, stream, incoming, principal, end, handshake);
    }
    if incoming.kind == FrameKind::DeviceHello {
        return devices::serve(shared, stream, incoming, principal, end);
    }
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
        return Err(shared.authentication("HelloBinding"));
    }
    let endpoint = shared
        .home
        .lock()
        .map_err(|_| Error::State)?
        .endpoint(hello.account, hello.endpoint)
        .map_err(|_| Error::State)?
        .ok_or_else(|| shared.authentication("EndpointUnavailable"))?;
    if endpoint.principal != principal {
        return Err(shared.authentication("EndpointPrincipalBinding"));
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
            .map_err(|_| shared.authentication("TransportSessionEncoding"))?,
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
        return Err(shared.authentication("ProofFrameKind"));
    }
    let proof = verify_proof(&incoming.payload, &endpoint.key)
        .map_err(|_| shared.authentication("ProofSignature"))?;
    let p = proof.value();
    if p.home != home
        || p.account != hello.account
        || p.endpoint != hello.endpoint
        || p.client_nonce != hello.client_nonce
        || p.challenge_digest != challenge_digest
    {
        return Err(shared.authentication("ProofBinding"));
    }
    let check = handshake::authority(
        shared,
        stream,
        proof.digest(),
        end,
        challenge.expires_ms,
        "SessionAuthority",
    )?;
    let now = shared.config.clock.sample().map_err(|_| Error::Clock)?;
    if now.upper_ms >= challenge.expires_ms || clock::boot_ms().map_err(|_| Error::Clock)? >= end {
        return Err(Error::HandshakeExpired);
    }
    if !check.current(shared) {
        return Err(Error::Authority);
    }
    let window = shared
        .home
        .lock()
        .map_err(|_| Error::State)?
        .open_window(&endpoint, now, &|| check.current(shared))
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
    let ready = sign_ready(&ready, &shared.signer).map_err(|_| Error::Frame)?;
    if !check.current(shared) {
        return Err(Error::Authority);
    }
    frame(stream, FrameKind::Ready, ready, remaining(end)?)?;
    drop(handshake);
    let mut budget = Budget::new(32, 8);
    loop {
        let incoming =
            io::receive(stream, Duration::from_secs(60)).map_err(|_| Error::Transport)?;
        if incoming.kind == FrameKind::Close {
            return Ok(());
        }
        if !matches!(
            incoming.kind,
            FrameKind::Action | FrameKind::CryptoAction | FrameKind::FederationControl
        ) {
            return Err(Error::Frame);
        }
        let now = clock::boot_ms().map_err(|_| Error::Clock)?;
        if !budget.admit(now) || !shared.ingress.lock().map_err(|_| Error::State)?.admit(now) {
            return Err(Error::RateLimited);
        }
        if incoming.kind == FrameKind::FederationControl {
            federation_origin::bootstrap(
                shared,
                stream,
                &session,
                &endpoint.key,
                &incoming.payload,
            )?;
            continue;
        }
        let verified =
            verify_action(&incoming.payload, &endpoint.key).map_err(|_| Error::Authentication)?;
        if (incoming.kind == FrameKind::CryptoAction)
            != verified.action().operation.is_crypto_transition()
        {
            return Err(Error::Frame);
        }
        if verified.action().home != home {
            federation_origin::action(shared, stream, &session, &verified)?;
            continue;
        }
        if verified.action().operation == Operation::SearchQuery {
            search(
                shared,
                stream,
                &verified,
                &session,
                &endpoint.key,
                &mut budget,
            )?;
            continue;
        }
        let response = execute(
            shared,
            stream,
            &verified,
            &session,
            &Cancellation::default(),
            None,
        );
        let (kind, bytes) = if verified.action().operation.is_crypto_transition() {
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
            bytes.map_err(|_| Error::Frame)?,
            Duration::from_secs(5),
        )?;
    }
}
fn execute(
    shared: &Shared,
    stream: &Stream,
    action: &VerifiedAction,
    session: &AuthenticatedSession,
    cancel: &Cancellation,
    end: Option<u64>,
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
    let check = match shared.check_authority(
        stream,
        action.digest(),
        end,
        cancel,
        action.action().operation.name(),
    ) {
        Ok(check) => check,
        Err(error) => {
            shared.report(action.action().operation.name(), error.code());
            if matches!(error, Error::AuthorityAdmissionBusy) {
                return refused(ErrorCode::Overloaded, error.code());
            }
            if matches!(
                error,
                Error::AuthorityAdmissionStopped | Error::AuthorityAdmissionExpired
            ) {
                return refused(ErrorCode::Unavailable, error.code());
            }
            return refused(ErrorCode::Unavailable, "TransportAuthority");
        }
    };
    if !check.permitted() {
        use crate::hypernet::Disposition;
        let (code, detail) = match check.disposition() {
            Disposition::Denied if check.certified() => (ErrorCode::Denied, "TransportDenied"),
            Disposition::Expired => (ErrorCode::Unavailable, "TransportAuthorityExpired"),
            Disposition::NotActive => (ErrorCode::Unavailable, "TransportInactive"),
            _ => (ErrorCode::Unavailable, "TransportAuthority"),
        };
        shared.report_check(action.action().operation.name(), detail, Some(&check));
        return refused(code, detail);
    }
    let Ok(now) = shared.config.clock.sample() else {
        return refused(ErrorCode::Unavailable, "Clock");
    };
    let Ok(mut home) = shared.home.try_lock() else {
        return refused(ErrorCode::Overloaded, "OperationBusy");
    };
    match home.execute_cancellable(action, session, now, &|| current(&check, end), cancel) {
        Ok(response) => response,
        Err(_) => base(Outcome::Unknown),
    }
}

fn current(check: &crate::hypernet::AuthorityCheck, end: Option<u64>) -> bool {
    check.permitted() && end.is_none_or(|end| clock::boot_ms().is_ok_and(|now| now < end))
}

/// Only an exact authenticated cancellation can accompany the single in-flight query.
fn search(
    shared: &Shared,
    stream: &Stream,
    query: &VerifiedAction,
    session: &AuthenticatedSession,
    key: &VerifyingKey,
    budget: &mut Budget,
) -> Result<()> {
    let cancel = Cancellation::default();
    let end = clock::boot_ms().map_err(|_| Error::Clock)? + 10000;
    thread::scope(|scope| {
        let (sender, receiver) = std::sync::mpsc::sync_channel(1);
        let token = cancel.clone();
        scope.spawn(move || {
            let response = execute(shared, stream, query, session, &token, Some(end));
            let _ = sender.send(response);
        });
        let mut control = None;
        let result = (|| {
            loop {
                if let Ok(response) = receiver.try_recv() {
                    frame(
                        stream,
                        FrameKind::Response,
                        sign_response(&response, &shared.signer).map_err(|_| Error::Frame)?,
                        remaining(end)?.min(Duration::from_secs(5)),
                    )?;
                    if let Some(control) = control {
                        let response = execute(
                            shared,
                            stream,
                            &control,
                            session,
                            &Cancellation::accepted_control(),
                            Some(end),
                        );
                        frame(
                            stream,
                            FrameKind::Response,
                            sign_response(&response, &shared.signer).map_err(|_| Error::Frame)?,
                            remaining(end)?.min(Duration::from_secs(5)),
                        )?;
                    }
                    return Ok(());
                }
                if !stream
                    .wait_readable(remaining(end)?.min(Duration::from_millis(25)))
                    .map_err(|_| Error::Transport)?
                {
                    continue;
                }
                if control.is_some() {
                    return Err(Error::RateLimited);
                }
                let incoming = io::receive(stream, remaining(end)?.min(Duration::from_secs(5)))
                    .map_err(|_| Error::Transport)?;
                let now = clock::boot_ms().map_err(|_| Error::Clock)?;
                if incoming.kind != FrameKind::Action
                    || !budget.admit(now)
                    || !shared.ingress.lock().map_err(|_| Error::State)?.admit(now)
                {
                    return Err(Error::RateLimited);
                }
                let verified =
                    verify_action(&incoming.payload, key).map_err(|_| Error::Authentication)?;
                let body: crate::home::Resolve = verified
                    .action()
                    .body
                    .deserialized()
                    .map_err(|_| Error::Frame)?;
                if verified.action().operation != Operation::SearchCancel
                    || verified.action().target != Target::Service
                    || verified.action().home != query.action().home
                    || verified.action().actor != query.action().actor
                    || body.operation_id != query.action().operation_id
                    || body.action_digest != query.digest()
                {
                    return Err(Error::Authentication);
                }
                let authority = shared.check_authority(
                    stream,
                    verified.digest(),
                    Some(end),
                    &Cancellation::default(),
                    "SearchCancel",
                )?;
                if !current(&authority, Some(end)) {
                    return Err(Error::Authority);
                }
                // Cancellation only stops work. Its response still receives full current Home admission.
                cancel.cancel();
                control = Some(verified);
            }
        })();
        if result.is_err() {
            cancel.cancel();
            stream.close();
        }
        result
    })
}

/// Retry an already durable origin stop through its independently admitted gateway.
pub fn notify_federation_withdrawal(
    directory: &Path,
    agreement: AgreementRef,
) -> Result<crate::federation::AgreementState> {
    let shared = load_shared(directory, Arc::new(AtomicBool::new(false)), false)?;
    federation_origin::notify_withdrawal(&shared, agreement)
}
