// SPDX-License-Identifier: Apache-2.0
//! Same-stream authority recovery uses real Companion IPC decoding, without a native network.
use super::*;
use serde_json::{Value, json};
use std::{
    cell::Cell,
    fs,
    io::{Read, Write},
    os::unix::{fs::PermissionsExt, net::UnixListener},
    path::PathBuf,
};

#[derive(Clone, Copy)]
enum Reply {
    Permitted,
    Unavailable,
    Expired,
    Denied,
    ExpiredDenied,
    NotActive,
    Misbound,
}
fn id(value: u8) -> String {
    hex::encode([value; 32])
}
fn privacy() -> Value {
    json!({"direction":"incoming","transport":"HyperNet","transportAuthenticated":true,
        "relayPath":"approvedAttachment","provenance":"endpointAttestedArrival","endpointMode":3,
        "transportProtection":"tls13FinalService","relayService":id(10),"attachmentProfileDigest":id(11),
        "physicalIndependenceVerified":false,"profileCurrentnessAsserted":false,
        "endToEndMessageEncryption":"applicationDefined"})
}
fn receipt(request: &Value, reply: Reply) -> Value {
    let start = clock::boot_ms().unwrap();
    let end = start + request["timeoutMs"].as_u64().unwrap();
    let mut value = json!({"version":2,"ok":true,"id":request["id"],"nonce":request["nonce"],
        "actionDigest":request["actionDigest"],"result":{"disposition":"permitted",
        "callerStartedBootMs":start,"callerDeadlineBootMs":end,"notAfterBootMs":end,
        "authority":{"network":id(1),"incarnation":id(2),"configuration":id(15),"epoch":1,
            "height":1,"state":id(16),"statementDigest":id(17),"evaluatedAtMs":1000,"expiresAtMs":2000,"code":0},
        "session":id(6),"generation":1,"companionInstance":id(12),"endpointInstance":id(13),
        "controlGeneration":1,"kernelBoot":fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap().trim(),
        "privacy":privacy()}});
    match reply {
        Reply::Permitted => {}
        Reply::Denied | Reply::ExpiredDenied => {
            value["result"]["disposition"] = "denied".into();
            value["result"]["authority"]["code"] = 3.into();
            if matches!(reply, Reply::ExpiredDenied) {
                // A valid certified denial whose receipt is already expired on arrival.
                value["result"]["notAfterBootMs"] = (start + 1).into();
                thread::sleep(Duration::from_millis(2));
            }
        }
        Reply::Unavailable | Reply::Expired | Reply::NotActive => {
            value["result"]["authority"] = Value::Null;
            value["result"]["disposition"] = match reply {
                Reply::Unavailable => "unavailable",
                Reply::Expired => "expired",
                _ => "notActive",
            }
            .into();
        }
        Reply::Misbound => value["actionDigest"] = id(99).into(),
    }
    value
}

struct Fixture {
    path: PathBuf,
    requests: Arc<Mutex<Vec<Value>>>,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Fixture {
    fn new(replies: Vec<Reply>) -> Self {
        let mut random = [0; 8];
        getrandom::fill(&mut random).unwrap();
        let path = PathBuf::from(format!("/tmp/hrc-handshake-{}", hex::encode(random)));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let listener = UnixListener::bind(path.join("Control.sock")).unwrap();
        fs::set_permissions(path.join("Control.sock"), fs::Permissions::from_mode(0o600)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let requests = Arc::new(Mutex::new(Vec::new()));
        let done = stop.clone();
        let recorded = requests.clone();
        let worker = thread::spawn(move || {
            let mut transport = None;
            let mut replies = replies.into_iter();
            while !done.load(Ordering::Acquire) {
                let (mut socket, _) = match listener.accept() {
                    Ok(value) => value,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(error) => panic!("fixture accept failed: {error}"),
                };
                socket
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut length = [0; 4];
                socket.read_exact(&mut length).unwrap();
                let length = u32::from_be_bytes(length) as usize;
                assert!(length <= 16384);
                let mut bytes = vec![0; length];
                socket.read_exact(&mut bytes).unwrap();
                let request: Value = serde_json::from_slice(&bytes).unwrap();
                let value = match request["action"].as_str().unwrap() {
                    "accept" => {
                        assert!(
                            transport.is_none(),
                            "recovery must keep the original stream"
                        );
                        json!({"version":2,"ok":true,"id":id(14),"checkAuthority":true,"privacy":privacy(),
                            "peer":{"network":id(1),"incarnation":id(2),"service":id(3),"protocol":"hrc-probe/1",
                            "owner":id(4),"endpoint":id(5),"session":id(6),"generation":1,"principal":id(7),
                            "grant":id(8),"grantGeneration":1,"expiresMs":9000000000000u64,
                            "maximumBytes":1048576,"durationMs":60000,"idleMs":10000}})
                    }
                    "checkAuthority" => {
                        recorded.lock().unwrap().push(request.clone());
                        receipt(
                            &request,
                            replies.next().expect("unexpected authority retry"),
                        )
                    }
                    _ => panic!("unexpected fixture operation"),
                };
                let bytes = serde_json::to_vec(&value).unwrap();
                socket
                    .write_all(&(bytes.len() as u32).to_be_bytes())
                    .unwrap();
                socket.write_all(&bytes).unwrap();
                if request["action"] == "accept" {
                    transport = Some(socket);
                }
            }
        });
        Self {
            path,
            requests,
            stop,
            worker: Some(worker),
        }
    }
    fn connect(&self) -> (Companion, Stream) {
        let companion = Companion::new(&self.path).unwrap();
        let stream = companion.accept(Duration::from_secs(1)).unwrap();
        (companion, stream)
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.worker.take().unwrap().join().unwrap();
        fs::remove_dir_all(&self.path).unwrap();
    }
}
fn sample() -> Result<clock::TimeBounds> {
    Ok(clock::TimeBounds::test_now())
}
fn check(companion: &Companion, stream: &Stream, end: u64) -> Result<AuthorityCheck> {
    let admission = admission::Admission::default();
    let permit = admission.acquire(Some(end), || false).unwrap();
    companion
        .check_authority(stream, [42; 32], permit.check_timeout().unwrap())
        .map_err(|_| Error::Authority)
}

#[test]
fn temporary_observations_recover_on_the_same_stream_and_immutable_action() {
    let fixture = Fixture::new(vec![Reply::Unavailable, Reply::Expired, Reply::Permitted]);
    let (companion, stream) = fixture.connect();
    let initial = sample().unwrap();
    let effects = Cell::new(0);
    let waits = Cell::new(0);
    let authority = recover(
        initial.boot_ms + 5000,
        initial.upper_ms + 5000,
        sample,
        || false,
        |end| {
            assert_eq!(effects.get(), 0);
            check(&companion, &stream, end)
        },
        |duration| {
            assert_eq!(duration, Duration::from_millis(50));
            waits.set(waits.get() + 1);
        },
    )
    .unwrap();
    assert!(authority.current_at(sample(), false));
    effects.set(effects.get() + 1);
    assert_eq!((effects.get(), waits.get()), (1, 2));
    let requests = fixture.requests.lock().unwrap();
    assert_eq!(requests.len(), 3);
    for request in requests.iter() {
        assert_eq!(request["id"], id(14));
        assert_eq!(request["actionDigest"], id(42));
        assert!(request["timeoutMs"].as_u64().unwrap() <= 1000);
    }
    assert_ne!(requests[0]["nonce"], requests[1]["nonce"]);
    assert_ne!(requests[1]["nonce"], requests[2]["nonce"]);
    assert_ne!(requests[0]["nonce"], requests[2]["nonce"]);
    assert_eq!(stream.peer().session(), id(6));
    assert_eq!(stream.peer().generation(), 1);
}

#[test]
fn denial_including_expired_certified_denial_inactive_and_misbound_receipts_stop() {
    for reply in [
        Reply::Denied,
        Reply::ExpiredDenied,
        Reply::NotActive,
        Reply::Misbound,
    ] {
        let fixture = Fixture::new(vec![reply]);
        let (companion, stream) = fixture.connect();
        let initial = sample().unwrap();
        let result = recover(
            initial.boot_ms + 5000,
            initial.upper_ms + 5000,
            sample,
            || false,
            |end| {
                let result = check(&companion, &stream, end);
                if matches!(reply, Reply::ExpiredDenied) {
                    let check = result.as_ref().unwrap();
                    assert_eq!(check.disposition(), Disposition::Expired);
                    assert_ne!(check.authority().unwrap().code(), 0);
                }
                result
            },
            |_| panic!("terminal result must not wait or retry"),
        );
        assert!(matches!(result, Err(Error::Authority)));
        assert_eq!(fixture.requests.lock().unwrap().len(), 1);
    }
}

#[test]
fn busy_admission_can_recover_but_three_attempts_are_the_limit() {
    let initial = sample().unwrap();
    let calls = Cell::new(0);
    let waits = Cell::new(0);
    let result = recover(
        initial.boot_ms + 5000,
        initial.upper_ms + 5000,
        || Ok(initial),
        || false,
        |_| {
            calls.set(calls.get() + 1);
            Err(Error::AuthorityAdmissionBusy)
        },
        |_| waits.set(waits.get() + 1),
    );
    assert!(matches!(result, Err(Error::AuthorityAdmissionBusy)));
    assert_eq!((calls.get(), waits.get()), (3, 2));

    let fixture = Fixture::new(vec![Reply::Permitted]);
    let (companion, stream) = fixture.connect();
    calls.set(0);
    let result = recover(
        initial.boot_ms + 5000,
        initial.upper_ms + 5000,
        sample,
        || false,
        |end| {
            calls.set(calls.get() + 1);
            if calls.get() == 1 {
                Err(Error::AuthorityAdmissionBusy)
            } else {
                check(&companion, &stream, end)
            }
        },
        |_| {},
    );
    assert!(result.unwrap().current_at(sample(), false));
    assert_eq!(calls.get(), 2);
}

#[test]
fn original_and_signed_deadlines_bound_every_attempt_and_cannot_be_renewed() {
    for signed_lifetime in [30, 5000] {
        let initial = sample().unwrap();
        let now = Cell::new(initial);
        let calls = Cell::new(0);
        let outer_end = initial.boot_ms + 100;
        let expected_end = outer_end.min(initial.boot_ms + signed_lifetime);
        let result = recover(
            outer_end,
            initial.upper_ms + signed_lifetime,
            || Ok(now.get()),
            || false,
            |end| {
                assert_eq!(end, expected_end);
                calls.set(calls.get() + 1);
                Err(Error::AuthorityAdmissionBusy)
            },
            |duration| {
                assert!(duration <= Duration::from_millis(50));
                let mut next = now.get();
                next.boot_ms += duration.as_millis() as u64;
                // Even a more generous later wall-clock bound cannot renew the boot deadline.
                next.upper_ms -= 1;
                now.set(next);
            },
        );
        assert!(matches!(result, Err(Error::HandshakeExpired)));
        assert_eq!(calls.get(), if signed_lifetime == 30 { 1 } else { 2 });
    }
}

#[test]
fn cancellation_and_clock_failure_stop_before_another_attempt() {
    let initial = sample().unwrap();
    let cancel = Cancellation::default();
    let calls = Cell::new(0);
    let result = recover(
        initial.boot_ms + 5000,
        initial.upper_ms + 5000,
        || Ok(initial),
        || cancel.is_cancelled(),
        |_| {
            calls.set(calls.get() + 1);
            Err(Error::AuthorityAdmissionBusy)
        },
        |_| cancel.cancel(),
    );
    assert!(matches!(result, Err(Error::AuthorityAdmissionStopped)));
    assert_eq!(calls.get(), 1);

    let clock_failed = Cell::new(false);
    let result = recover(
        initial.boot_ms + 5000,
        initial.upper_ms + 5000,
        || {
            if clock_failed.get() {
                Err(Error::Clock)
            } else {
                Ok(initial)
            }
        },
        || false,
        |_| {
            clock_failed.set(true);
            Err(Error::AuthorityAdmissionBusy)
        },
        |_| panic!("clock failure must stop before waiting"),
    );
    assert!(matches!(result, Err(Error::Clock)));
}

#[test]
fn outer_expiry_and_typed_failures_are_terminal() {
    let initial = sample().unwrap();
    let result = recover(
        initial.boot_ms,
        initial.upper_ms + 5000,
        || Ok(initial),
        || false,
        |_| panic!("expired handshake must not enter authority admission"),
        |_| panic!("expired handshake must not wait"),
    );
    assert!(matches!(result, Err(Error::HandshakeExpired)));
    for error in [
        Error::Authority,
        Error::Authentication,
        Error::Frame,
        Error::Clock,
        Error::AuthorityAdmissionStopped,
        Error::AuthorityAdmissionExpired,
    ] {
        let expected = error.code();
        let mut error = Some(error);
        let result = recover(
            initial.boot_ms + 5000,
            initial.upper_ms + 5000,
            || Ok(initial),
            || false,
            |_| Err(error.take().expect("typed terminal error was retried")),
            |_| panic!("terminal error must not wait"),
        );
        assert_eq!(result.err().unwrap().code(), expected);
    }
}

#[test]
fn recovered_permission_keeps_the_effect_boundary_shorter_than_its_raw_receipt() {
    let fixture = Fixture::new(vec![Reply::Permitted]);
    let (companion, stream) = fixture.connect();
    let initial = sample().unwrap();
    let expires_ms = initial.upper_ms + 300;
    let authority = recover(
        initial.boot_ms + 5000,
        expires_ms,
        || Ok(initial),
        || false,
        |end| {
            assert_eq!(end, initial.boot_ms + 300);
            // Exercise a receipt that would otherwise outlive the signed challenge.
            companion
                .check_authority(&stream, [42; 32], Duration::from_secs(1))
                .map_err(|_| Error::Authority)
        },
        |_| panic!("fresh permission needs no retry"),
    )
    .unwrap();
    assert!(authority.check.permitted());
    assert!(authority.current_at(Ok(initial), false));
    let mut expired = initial;
    expired.boot_ms = authority.end;
    assert!(!authority.current_at(Ok(expired), false));
    expired = initial;
    expired.upper_ms = expires_ms;
    assert!(!authority.current_at(Ok(expired), false));
    assert!(!authority.current_at(Ok(initial), true));
    assert!(!authority.current_at(Err(Error::Clock), false));
}

#[test]
fn permission_arriving_after_stop_or_deadline_cannot_escape_recovery() {
    for stop in [false, true] {
        let fixture = Fixture::new(vec![Reply::Permitted]);
        let (companion, stream) = fixture.connect();
        let initial = sample().unwrap();
        let now = Cell::new(initial);
        let stopped = Cell::new(false);
        let end = initial.boot_ms + 5000;
        let result = recover(
            end,
            initial.upper_ms + 5000,
            || Ok(now.get()),
            || stopped.get(),
            |end| {
                let check = check(&companion, &stream, end)?;
                assert!(check.permitted());
                if stop {
                    stopped.set(true);
                } else {
                    let mut expired = initial;
                    expired.boot_ms = end;
                    now.set(expired);
                }
                Ok(check)
            },
            |_| panic!("an interrupted handshake must not wait or retry"),
        );
        assert!(if stop {
            matches!(result, Err(Error::AuthorityAdmissionStopped))
        } else {
            matches!(result, Err(Error::HandshakeExpired))
        });
        assert_eq!(fixture.requests.lock().unwrap().len(), 1);
    }
}
