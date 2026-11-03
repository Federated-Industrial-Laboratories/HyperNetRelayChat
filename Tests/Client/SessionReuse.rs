// SPDX-License-Identifier: Apache-2.0
//! Temporary refusal recovery preserves exact work and the reserved stream-close handle.
use super::*;
use std::{
    fs,
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixListener},
};

fn temporary_forwarding(code: ErrorCode) -> Error {
    Error::Network(super::super::super::network::Error::ForwardRefused {
        code,
        detail: "DestinationBusy".into(),
        retry_after_ms: Some(12_000),
    })
}

fn temporary_service(code: ErrorCode) -> Error {
    Error::from_outcome(Outcome::Refused {
        code,
        detail: "TransportAuthorityExpired".into(),
        retry_after_ms: Some(12_000),
    })
}

#[test]
fn only_authenticated_temporary_refusals_preserve_the_session() {
    for code in [
        ErrorCode::Unavailable,
        ErrorCode::RateLimited,
        ErrorCode::Overloaded,
    ] {
        for error in [temporary_forwarding(code), temporary_service(code)] {
            assert!(error.can_reuse_session());
            assert_eq!(error.retry_delay_ms(), Some(12_000));
        }
    }
    for code in [
        ErrorCode::Denied,
        ErrorCode::Expired,
        ErrorCode::Conflict,
        ErrorCode::InvalidInput,
    ] {
        assert!(!temporary_forwarding(code).can_reuse_session());
        assert!(!temporary_service(code).can_reuse_session());
    }
    use super::super::super::network::Error as Network;
    for error in [
        Error::Network(Network::Transport),
        Error::Network(Network::Authentication),
        Error::Network(Network::Frame),
        Error::Network(Network::Handshake),
        Error::Network(Network::QueryCancelled),
        Error::Clock,
        Error::Unknown,
        Error::Rejected {
            code: ErrorCode::Unavailable,
            detail: "TerminalOutcome".into(),
        },
    ] {
        assert!(!error.can_reuse_session(), "{}", error.code());
    }
}

// A local companion handoff supplies a real closeable adapter stream. This fixture
// does not assert HyperNet authority or authenticate an HRC foreign session.
pub(super) fn retained_handle(
    root: &Path,
) -> (crate::hypernet::Companion, Arc<crate::hypernet::Stream>) {
    let path = root.join("Companion");
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    let listener = UnixListener::bind(path.join("Control.sock")).unwrap();
    fs::set_permissions(path.join("Control.sock"), fs::Permissions::from_mode(0o600)).unwrap();
    listener.set_nonblocking(true).unwrap();
    let server = thread::spawn(move || {
        let end = Instant::now() + Duration::from_secs(2);
        let remaining = || {
            end.checked_duration_since(Instant::now())
                .filter(|left| !left.is_zero())
                .expect("companion handoff deadline expired")
        };
        let mut socket = loop {
            remaining();
            match listener.accept() {
                Ok((socket, _)) => break socket,
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("companion accept: {error}"),
            }
        };
        socket.set_read_timeout(Some(remaining())).unwrap();
        let mut size = [0; 4];
        socket.read_exact(&mut size).unwrap();
        let size = u32::from_be_bytes(size) as usize;
        assert!(size <= 16_384);
        let mut request = vec![0; size];
        socket.set_read_timeout(Some(remaining())).unwrap();
        socket.read_exact(&mut request).unwrap();
        let request: serde_json::Value = serde_json::from_slice(&request).unwrap();
        assert_eq!(request["action"], "connect");
        let id = |n| hex::encode([n; 32]);
        let response = serde_json::json!({
            "version":2,"ok":true,"id":id(18),"checkAuthority":false,
            "peer":{"network":id(1),"incarnation":id(2),"service":id(3),
                "protocol":PROTOCOL,"owner":id(4),"endpoint":id(5),"session":id(6),
                "generation":1,"expiresMs":9000000000000u64,"maximumBytes":1048576,
                "durationMs":60000,"idleMs":10000,"route":id(9)},
            "privacy":{"direction":"outgoing","transport":"HyperNet",
                "transportAuthenticated":true,"tls":"TLS1.3","relayPath":"nestedTlsViaRelay",
                "relayService":id(10),"destinationService":id(9),"selectedMinimum":"Organisation",
                "configuredAssurance":"Organisation","provenance":"observedAuthenticatedTransport",
                "certifiedEndpointProfile":null,"certifiedRelayProfile":null,
                "physicalIndependenceVerified":false,"profileCurrentnessAsserted":false,
                "endToEndMessageEncryption":"applicationDefined"}
        });
        let bytes = serde_json::to_vec(&response).unwrap();
        socket.set_write_timeout(Some(remaining())).unwrap();
        socket
            .write_all(&(bytes.len() as u32).to_be_bytes())
            .unwrap();
        socket.set_write_timeout(Some(remaining())).unwrap();
        socket.write_all(&bytes).unwrap();
        socket
    });
    let companion = crate::hypernet::Companion::new(&path).unwrap();
    let stream = companion
        .connect(&hex::encode([3; 32]), PROTOCOL, Duration::from_secs(2))
        .unwrap();
    let socket = server.join().unwrap();
    // The adapter's lifecycle remains active when its peer has closed; no read is
    // needed to prove whether the Controller retains and can close its handle.
    drop(socket);
    (companion, Arc::new(stream))
}

#[test]
fn forwarding_backoff_retains_pending_bytes_stale_views_and_reserved_disconnect() {
    retained_recovery(temporary_forwarding(ErrorCode::Overloaded));
}

#[test]
fn service_backoff_retains_pending_bytes_stale_views_and_reserved_disconnect() {
    retained_recovery(temporary_service(ErrorCode::Unavailable));
}

fn retained_recovery(error: Error) {
    let (fixture, mut worker, room) = worker();
    let (_companion, stream) = retained_handle(&fixture.root);
    *worker.shared.stream.lock().unwrap() = Some(Arc::clone(&stream));
    let pending = action();
    let _ = outcome(
        &mut worker,
        &pending,
        Outcome::Refused {
            code: ErrorCode::Unavailable,
            detail: "UncertainForwarding".into(),
            retry_after_ms: Some(1000),
        },
    );
    let before = worker.client.pending().unwrap();
    assert_eq!(before.len(), 1);
    let original_bytes = before[0].action.signed_bytes().to_vec();
    worker.caught_up.insert(room);
    worker.error(error);
    assert!(Arc::ptr_eq(
        worker.shared.stream.lock().unwrap().as_ref().unwrap(),
        &stream
    ));
    assert!(worker.snapshot.inspection.stale);
    assert!(worker.snapshot.selected.as_ref().unwrap().stale);
    assert!(worker.snapshot.privacy.is_none() && worker.snapshot.federation_privacy.is_none());
    assert!(worker.caught_up.is_empty());
    assert!(
        matches!(worker.snapshot.connection, ConnectionState::Backoff { retry_in_ms, .. } if retry_in_ms >= 12_000)
    );

    let waiting = Queued::new(78, Command::Join(room));
    let original_end = waiting.admission_end;
    assert_eq!(
        waiting.admission(worker.desired, false, Instant::now()),
        Admission::Wait
    );
    let retry = worker.retry;
    worker.poll = Instant::now() - Duration::from_secs(10);
    worker.tick();
    assert_eq!(worker.retry, retry);
    assert_eq!(waiting.admission_end, original_end);
    assert_eq!(
        waiting.admission(worker.desired, false, original_end),
        Admission::Expired
    );
    let after = worker.client.pending().unwrap();
    assert_eq!(after.len(), 1);
    assert_eq!(after[0].action.signed_bytes(), original_bytes);

    let (sender, _) = mpsc::sync_channel(1);
    let (local_sender, _) = mpsc::sync_channel(1);
    let controller = Controller {
        shared: Arc::clone(&worker.shared),
        sender,
        local_sender,
        worker: None,
        next_request: AtomicU64::new(1),
    };
    controller.disconnect();
    assert!(worker.shared.disconnect.load(Ordering::Acquire));
    assert!(matches!(
        stream.send_all(&[1], Duration::from_millis(100)),
        Err(crate::hypernet::Error::NotActive)
    ));
    worker.offline();
    assert!(!worker.desired);
    assert!(worker.shared.stream.lock().unwrap().is_none());
    assert_eq!(
        worker.client.pending().unwrap()[0].action.signed_bytes(),
        original_bytes
    );
}

#[test]
fn permanent_refusal_or_broken_transport_discards_the_reserved_handle() {
    for error in [
        temporary_forwarding(ErrorCode::Denied),
        temporary_service(ErrorCode::Denied),
        Error::Network(super::super::super::network::Error::Transport),
        Error::Network(super::super::super::network::Error::Authentication),
    ] {
        let (fixture, mut worker, _) = worker();
        let (_companion, stream) = retained_handle(&fixture.root);
        *worker.shared.stream.lock().unwrap() = Some(stream);
        worker.error(error);
        assert!(worker.shared.stream.lock().unwrap().is_none());
        assert!(worker.snapshot.inspection.stale);
    }
}
