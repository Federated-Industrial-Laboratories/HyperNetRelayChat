use super::*;
use std::{
    fs,
    io::{Read, Write},
    os::unix::{
        fs::{PermissionsExt, symlink},
        net::UnixListener,
    },
    sync::{atomic::AtomicU64, mpsc},
    thread,
    time::Instant,
};

fn id(n: u8) -> String {
    hex::encode([n; 32])
}
fn peer(direction: Direction) -> Value {
    let mut value = json!({"network":id(1),"incarnation":id(2),"service":id(3),"protocol":"hrc-probe/1","owner":id(4),"endpoint":id(5),"session":id(6),"generation":1,"expiresMs":9000000000000u64,"maximumBytes":1048576,"durationMs":60000,"idleMs":10000});
    match direction {
        Direction::Incoming => {
            value["principal"] = id(7).into();
            value["grant"] = id(8).into();
            value["grantGeneration"] = 1.into();
        }
        Direction::Outgoing => value["route"] = id(9).into(),
    }
    value
}
fn privacy(direction: Direction) -> Value {
    match direction {
        Direction::Incoming => {
            json!({"direction":"incoming","transport":"HyperNet","transportAuthenticated":true,"relayPath":"approvedAttachment","provenance":"endpointAttestedArrival","endpointMode":3,"transportProtection":"tls13FinalService","relayService":id(10),"attachmentProfileDigest":id(11),"physicalIndependenceVerified":false,"profileCurrentnessAsserted":false,"endToEndMessageEncryption":"applicationDefined"})
        }
        Direction::Outgoing => {
            json!({"direction":"outgoing","transport":"HyperNet","transportAuthenticated":true,"tls":"TLS1.3","relayPath":"nestedTlsViaRelay","relayService":id(10),"destinationService":id(9),"selectedMinimum":"Organisation","configuredAssurance":"Organisation","provenance":"observedAuthenticatedTransport","certifiedEndpointProfile":null,"certifiedRelayProfile":null,"physicalIndependenceVerified":false,"profileCurrentnessAsserted":false,"endToEndMessageEncryption":"applicationDefined"})
        }
    }
}
fn handoff(direction: Direction, connection: u8) -> Value {
    json!({"version":2,"ok":true,"id":id(connection),"peer":peer(direction),"privacy":privacy(direction),"checkAuthority":direction==Direction::Incoming})
}
fn status(generation: u64, eligible: bool) -> Value {
    let mut privacy = privacy(Direction::Incoming);
    for k in ["direction", "transport", "endToEndMessageEncryption"] {
        privacy.as_object_mut().unwrap().remove(k);
    }
    json!({"version":2,"ok":true,"status":"Ready","network":id(1),"incarnation":id(2),"principal":id(7),"binding":{"service":id(3),"owner":id(4),"endpoint":id(5),"protocol":"hrc-probe/1"},"uptimeMs":1,"incoming":true,"capabilities":{"checkAuthority":{"supported":true,"endpointReady":true,"capability":"checkAuthority-v2","companionInstance":id(12),"endpointInstance":id(13),"controlGeneration":generation}},"targets":[{"service":id(3),"protocol":"hrc-probe/1"}],"connections":[{"id":id(14),"direction":"incoming","service":id(3),"checkAuthority":eligible,"privacy":privacy}]})
}
fn receipt(request: &Value) -> Value {
    let start = ipc::boot_ms().unwrap();
    let end = start + request["timeoutMs"].as_u64().unwrap();
    json!({"version":2,"ok":true,"id":request["id"],"nonce":request["nonce"],"actionDigest":request["actionDigest"],"result":{"disposition":"permitted","callerStartedBootMs":start,"callerDeadlineBootMs":end,"notAfterBootMs":end,"authority":{"network":id(1),"incarnation":id(2),"configuration":id(15),"epoch":1,"height":1,"state":id(16),"statementDigest":id(17),"evaluatedAtMs":1000,"expiresAtMs":2000,"code":0},"session":id(6),"generation":1,"companionInstance":id(12),"endpointInstance":id(13),"controlGeneration":1,"kernelBoot":ipc::unshifted_boot().unwrap(),"privacy":privacy(Direction::Incoming)}})
}
enum Reply {
    Json(Value),
    Raw(Vec<u8>),
    Length(u32),
}
impl From<Value> for Reply {
    fn from(value: Value) -> Self {
        Self::Json(value)
    }
}
struct Fixture {
    path: PathBuf,
    stop: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Fixture {
    fn new(mut handler: impl FnMut(&Value) -> Reply + Send + 'static) -> Self {
        let mut random = [0; 8];
        getrandom::fill(&mut random).unwrap();
        let path = PathBuf::from(format!("/tmp/hrc-{}", hex::encode(random)));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        let listener = UnixListener::bind(path.join("Control.sock")).unwrap();
        fs::set_permissions(path.join("Control.sock"), fs::Permissions::from_mode(0o600)).unwrap();
        listener.set_nonblocking(true).unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let done = stop.clone();
        let worker = thread::spawn(move || {
            let mut payloads = Vec::new();
            while !done.load(Ordering::Acquire) {
                let (mut stream, _) = match listener.accept() {
                    Ok(v) => v,
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(1));
                        continue;
                    }
                    Err(_) => break,
                };
                stream
                    .set_read_timeout(Some(Duration::from_secs(2)))
                    .unwrap();
                let mut size = [0; 4];
                if stream.read_exact(&mut size).is_err() {
                    continue;
                }
                let size = u32::from_be_bytes(size) as usize;
                assert!(size <= ipc::MAX_FRAME);
                let mut bytes = vec![0; size];
                stream.read_exact(&mut bytes).unwrap();
                let request: Value = serde_json::from_slice(&bytes).unwrap();
                let reply = handler(&request);
                let bytes = match reply {
                    Reply::Json(v) => serde_json::to_vec(&v).unwrap(),
                    Reply::Raw(bytes) => bytes,
                    Reply::Length(n) => {
                        let _ = stream.write_all(&n.to_be_bytes());
                        continue;
                    }
                };
                let _ = stream.write_all(&(bytes.len() as u32).to_be_bytes());
                let _ = stream.write_all(&bytes);
                if request["action"] == "accept" || request["action"] == "connect" {
                    payloads.push(stream);
                }
            }
        });
        Self {
            path,
            stop,
            worker: Some(worker),
        }
    }
    fn agent(&self) -> Companion {
        Companion::new(&self.path).unwrap()
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Release);
        self.worker.take().unwrap().join().unwrap();
        fs::remove_dir_all(&self.path).unwrap();
    }
}
fn normal(r: &Value) -> Reply {
    match r["action"].as_str().unwrap() {
        "accept" => handoff(Direction::Incoming, 14).into(),
        "connect" => handoff(Direction::Outgoing, 18).into(),
        "status" => status(1, true).into(),
        "checkAuthority" => receipt(r).into(),
        "cancel" => json!({"version":2,"ok":true,"id":r["id"],"status":"Cancelling"}).into(),
        _ => panic!("unexpected request"),
    }
}
fn incoming(a: &Companion) -> Stream {
    a.accept(Duration::from_secs(1)).unwrap()
}
fn check(a: &Companion, s: &Stream) -> AuthorityCheck {
    a.check_authority(s, [1; 32], Duration::from_secs(1))
        .unwrap()
}

#[test]
fn private_paths_refuse_symlinks_and_accessible_modes() {
    let f = Fixture::new(normal);
    fs::set_permissions(&f.path, fs::Permissions::from_mode(0o750)).unwrap();
    assert!(matches!(Companion::new(&f.path), Err(Error::Ownership)));
    fs::set_permissions(&f.path, fs::Permissions::from_mode(0o700)).unwrap();
    let link = f.path.join("alias");
    symlink(&f.path, &link).unwrap();
    assert!(matches!(Companion::new(&link), Err(Error::Path)));
    let a = f.agent();
    fs::set_permissions(
        f.path.join("Control.sock"),
        fs::Permissions::from_mode(0o660),
    )
    .unwrap();
    assert!(matches!(a.status(), Err(Error::Ownership)));
}

#[test]
fn malformed_frames_and_duplicate_fields_never_reach_context() {
    for bytes in [
        b"{\"version\":2,\"ok\":true,\"ok\":false}".to_vec(),
        b"{\"version\":2,\"ok\":true,\"nested\":{\"x\":1,\"x\":2}}".to_vec(),
        vec![0xff],
        b"{} {}".to_vec(),
    ] {
        let f = Fixture::new(move |_| Reply::Raw(bytes.clone()));
        assert!(matches!(f.agent().status(), Err(Error::Protocol)));
    }
    for size in [0, 16385, u32::MAX] {
        let f = Fixture::new(move |_| Reply::Length(size));
        assert!(matches!(f.agent().status(), Err(Error::Frame)));
    }
    let f = Fixture::new(|_| json!({"version":1,"ok":true}).into());
    assert!(matches!(f.agent().status(), Err(Error::UnsupportedVersion)));
    let f = Fixture::new(|_| {
        json!({"version":2,"ok":false,"error":{"code":"Refused","message":"\u{1b}[31msecret\nprivate path"}}).into()
    });
    let error = f.agent().status().unwrap_err();
    assert_eq!(error.to_string(), "companion refused the request");
}

#[test]
fn preparation_closure_stays_temporary_without_reclassifying_other_refusals() {
    for (code, expected) in [
        ("Closed", "Closed"),
        ("Timeout", "Timeout"),
        ("Capacity", "Capacity"),
        ("Refused", "Refused"),
        ("Denied", "Refused"),
        ("FutureCode", "Refused"),
    ] {
        let fixture = Fixture::new(move |request| {
            assert_eq!(request["action"], "connect");
            json!({"version":2,"ok":false,"error":{
                "code":code,"message":"PRIVATE_CONNECTION_DIAGNOSTIC"}})
            .into()
        });
        let error = fixture
            .agent()
            .connect(&id(3), "hrc-probe/1", Duration::from_secs(1))
            .err()
            .expect("typed connection preparation failure");
        assert_eq!(error.code(), expected);
        assert!(!error.to_string().contains("PRIVATE_CONNECTION_DIAGNOSTIC"));
    }
}

#[test]
fn context_and_privacy_cannot_cross_direction_or_claim_extra_assurance() {
    assert!(Peer::parse(peer(Direction::Outgoing), Direction::Incoming).is_err());
    let mut v = privacy(Direction::Outgoing);
    v["physicalIndependenceVerified"] = true.into();
    assert!(Privacy::parse(v, Direction::Outgoing, false).is_err());
    let mut v = privacy(Direction::Incoming);
    v["endpointMode"] = 2.into();
    assert!(Privacy::parse(v, Direction::Incoming, false).is_err());
    let f = Fixture::new(|_| {
        let mut v = handoff(Direction::Outgoing, 18);
        v["peer"]["protocol"] = "another/1".into();
        v.into()
    });
    assert!(matches!(
        f.agent()
            .connect(&id(3), "hrc-probe/1", Duration::from_secs(1)),
        Err(Error::Protocol)
    ));
}

#[test]
fn fresh_checks_are_correlated_consumed_and_cancelled() {
    let f = Fixture::new(normal);
    let a = f.agent();
    a.status().unwrap();
    let s = incoming(&a);
    let first = check(&a, &s);
    assert!(first.permitted());
    let first_json = serde_json::to_value(&first).unwrap();
    let second = check(&a, &s);
    assert!(second.permitted());
    assert!(!first.permitted());
    assert_ne!(
        first_json["nonce"],
        serde_json::to_value(&second).unwrap()["nonce"]
    );
    a.cancel(&s).unwrap();
    assert!(!second.usable());
    assert_eq!(second.disposition(), Disposition::NotActive);
    assert!(matches!(
        a.check_authority(&s, [1; 32], Duration::from_secs(1)),
        Err(Error::NotActive)
    ));
}

#[test]
fn altered_receipt_bindings_and_deadlines_fail_closed() {
    for variation in 0..10 {
        let f = Fixture::new(move |r| {
            if r["action"] != "checkAuthority" {
                return normal(r);
            }
            let mut v = receipt(r);
            match variation {
                0 => v["nonce"] = id(19).into(),
                1 => v["actionDigest"] = id(19).into(),
                2 => v["result"]["session"] = id(19).into(),
                3 => v["result"]["authority"]["network"] = id(19).into(),
                4 => v["result"]["kernelBoot"] = "00000000-0000-0000-0000-000000000000".into(),
                5 => v["result"]["callerDeadlineBootMs"] = 0.into(),
                6 => v["result"]["authority"]["code"] = 2.into(),
                7 => v["result"]["authority"] = Value::Null,
                8 => v["result"]["privacy"] = Value::Null,
                9 => v["result"]["notAfterBootMs"] = u64::MAX.into(),
                _ => unreachable!(),
            }
            v.into()
        });
        let a = f.agent();
        let s = incoming(&a);
        assert!(
            matches!(
                a.check_authority(&s, [1; 32], Duration::from_secs(1)),
                Err(Error::Protocol)
            ),
            "variation {variation}"
        );
    }
}

#[test]
fn certified_denial_remains_distinct_from_local_unavailability() {
    let mode = Arc::new(AtomicU64::new(0));
    let setting = mode.clone();
    let f = Fixture::new(move |r| {
        if r["action"] != "checkAuthority" {
            return normal(r);
        }
        let mut v = receipt(r);
        if setting.load(Ordering::Acquire) == 0 {
            v["result"]["disposition"] = "denied".into();
            v["result"]["authority"]["code"] = 7.into();
        } else {
            v["result"]["disposition"] = "unavailable".into();
            v["result"]["authority"] = Value::Null;
        }
        v.into()
    });
    let a = f.agent();
    let s = incoming(&a);
    let denied = check(&a, &s);
    assert!(denied.certified());
    assert!(!denied.permitted());
    assert!(denied.attestation().is_none());
    assert_eq!(denied.authority().unwrap().code(), 7);
    mode.store(1, Ordering::Release);
    let absent = check(&a, &s);
    assert!(!absent.certified());
    assert!(!absent.usable());
    assert!(absent.attestation().is_none());
    assert_eq!(absent.disposition(), Disposition::Unavailable);
}

#[test]
fn absolute_authority_end_keeps_spent_time_and_shorter_receipt_lifetimes() {
    let (recorded, requests) = mpsc::channel();
    let fixture = Fixture::new(move |request| {
        if request["action"] != "checkAuthority" {
            return normal(request);
        }
        recorded.send(request.clone()).unwrap();
        let mut value = receipt(request);
        if request["actionDigest"] == id(2) {
            value["result"]["notAfterBootMs"] =
                (value["result"]["callerStartedBootMs"].as_u64().unwrap() + 150).into();
        }
        value.into()
    });
    let adapter = fixture.agent();
    let stream = incoming(&adapter);
    let end = ipc::boot_ms().unwrap() + 400;
    thread::sleep(Duration::from_millis(50));
    let first = adapter
        .check_authority_until(&stream, [1; 32], end)
        .unwrap();
    assert!(first.permitted());
    let request = requests.recv_timeout(Duration::from_secs(1)).unwrap();
    assert!((100..=350).contains(&request["timeoutMs"].as_u64().unwrap()));
    let first_value = serde_json::to_value(&first).unwrap();
    assert_eq!(first_value["usableUntilBootMs"], end);
    assert_eq!(first_value["actionDigest"], id(1));

    let end = ipc::boot_ms().unwrap() + 5000;
    let shorter = adapter
        .check_authority_until(&stream, [2; 32], end)
        .unwrap();
    assert!(shorter.permitted());
    assert!(!first.permitted());
    let next = requests.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_ne!(request["nonce"], next["nonce"]);
    let value = serde_json::to_value(&shorter).unwrap();
    assert_eq!(value["usableUntilBootMs"], value["receiptNotAfterBootMs"]);
    assert!(value["usableUntilBootMs"].as_u64().unwrap() < end);
    assert_eq!(value["actionDigest"], id(2));
}

#[test]
fn absolute_authority_end_refuses_expired_work_and_caps_the_supported_wait() {
    let (recorded, requests) = mpsc::channel();
    let fixture = Fixture::new(move |request| {
        if request["action"] == "checkAuthority" {
            recorded.send(request.clone()).unwrap();
        }
        normal(request)
    });
    let adapter = fixture.agent();
    let stream = incoming(&adapter);
    for end in [0, ipc::boot_ms().unwrap() + 99] {
        assert!(matches!(
            adapter.check_authority_until(&stream, [1; 32], end),
            Err(Error::Timeout)
        ));
    }
    assert!(requests.try_recv().is_err());
    let before = ipc::boot_ms().unwrap();
    let permitted = adapter
        .check_authority_until(&stream, [1; 32], before + 8000)
        .unwrap();
    assert!(permitted.permitted());
    let request = requests.recv_timeout(Duration::from_secs(1)).unwrap();
    assert_eq!(request["timeoutMs"], 5000);
    let value = serde_json::to_value(&permitted).unwrap();
    assert!(value["usableUntilBootMs"].as_u64().unwrap() <= ipc::boot_ms().unwrap() + 5000);
    assert!(value["usableUntilBootMs"].as_u64().unwrap() < before + 8000);
}

#[test]
fn original_call_deadline_survives_delayed_companion_dispatch() {
    let f = Fixture::new(|r| {
        if r["action"] == "checkAuthority" {
            thread::sleep(Duration::from_millis(250));
        }
        normal(r)
    });
    let a = f.agent();
    let s = incoming(&a);
    let start = Instant::now();
    let result = a
        .check_authority(&s, [1; 32], Duration::from_millis(100))
        .unwrap();
    assert_eq!(result.disposition(), Disposition::Expired);
    assert!(!result.certified());
    assert!(start.elapsed() < Duration::from_millis(220));
}

#[test]
fn local_close_during_check_invalidates_the_inflight_receipt() {
    let (began, wait) = mpsc::channel();
    let (proceed, gate) = mpsc::channel();
    let f = Fixture::new(move |r| {
        if r["action"] == "checkAuthority" {
            began.send(()).unwrap();
            gate.recv_timeout(Duration::from_secs(1)).unwrap();
        }
        normal(r)
    });
    let a = f.agent();
    let s = Arc::new(incoming(&a));
    let task_stream = s.clone();
    let task = thread::spawn(move || check(&a, &task_stream));
    wait.recv_timeout(Duration::from_secs(1)).unwrap();
    s.close();
    proceed.send(()).unwrap();
    let result = task.join().unwrap();
    assert_eq!(result.disposition(), Disposition::NotActive);
    assert!(!result.usable());
}

#[test]
fn status_replacement_and_loss_of_connection_eligibility_invalidate_receipts() {
    let mode = Arc::new(AtomicU64::new(0));
    let setting = mode.clone();
    let f = Fixture::new(move |r| {
        if r["action"] == "status" {
            status(
                if setting.load(Ordering::Acquire) == 1 {
                    2
                } else {
                    1
                },
                setting.load(Ordering::Acquire) != 2,
            )
            .into()
        } else {
            normal(r)
        }
    });
    let a = f.agent();
    a.status().unwrap();
    let s = incoming(&a);
    let first = check(&a, &s);
    mode.store(1, Ordering::Release);
    a.status().unwrap();
    assert!(!first.usable());
    mode.store(0, Ordering::Release);
    a.status().unwrap();
    let second = check(&a, &s);
    assert!(second.permitted());
    mode.store(2, Ordering::Release);
    a.status().unwrap();
    assert!(!second.usable());
    assert!(!s.check_authority_supported());
}

#[test]
fn observation_expires_and_cannot_authorize_a_different_stream() {
    let f = Fixture::new(normal);
    let a = f.agent();
    let s = incoming(&a);
    let observed = a
        .check_authority(&s, [1; 32], Duration::from_millis(100))
        .unwrap();
    let other = a
        .connect(&id(3), "hrc-probe/1", Duration::from_secs(1))
        .unwrap();
    assert!(matches!(
        other.send_observed(&observed, b"wrong stream"),
        Err(Error::NotActive)
    ));
    let other_adapter = f.agent();
    assert!(matches!(
        other_adapter.check_authority(&s, [1; 32], Duration::from_secs(1)),
        Err(Error::NotActive)
    ));
    thread::sleep(Duration::from_millis(110));
    assert_eq!(observed.disposition(), Disposition::Expired);
    assert!(!observed.permitted());
    assert!(observed.attestation().is_none());
    assert!(matches!(
        s.send_observed(&observed, b"expired"),
        Err(Error::NotActive)
    ));
}

#[test]
fn origin_attestation_retains_checked_receipt_identity_and_original_lifetime() {
    let fixture = Fixture::new(normal);
    let adapter = fixture.agent();
    let stream = incoming(&adapter);
    let checked = check(&adapter, &stream);
    let evidence = checked.attestation().unwrap();
    assert!(evidence.permitted());
    assert_eq!(evidence.action_digest(), id(1));
    assert_eq!(evidence.identity().session, id(6));
    assert_eq!(evidence.identity().generation, 1);
    assert_eq!(evidence.identity().companion_instance, id(12));
    assert_eq!(evidence.identity().endpoint_instance, id(13));
    assert_eq!(evidence.identity().control_generation, 1);
    assert_eq!(evidence.authority().configuration(), id(15));
    assert_eq!(evidence.authority().state(), id(16));
    assert_eq!(evidence.authority().statement_digest(), id(17));
    assert_eq!(evidence.privacy().relay_service(), Some(id(10).as_str()));
    assert_eq!(
        evidence.privacy().attachment_profile_digest(),
        Some(id(11).as_str())
    );
    assert_eq!(stream.peer().endpoint(), id(5));
    let serialized = serde_json::to_value(&checked).unwrap();
    assert_eq!(
        evidence.not_after_boot_ms(),
        serialized["usableUntilBootMs"].as_u64().unwrap()
    );
    assert_eq!(evidence.nonce(), serialized["nonce"].as_str().unwrap());
    stream.close();
    assert!(!evidence.permitted());
    assert!(checked.attestation().is_none());
}

#[test]
fn payload_half_close_keeps_reply_readable_and_partial_timeout_closes_stream() {
    let f = Fixture::new(normal);
    let a = f.agent();
    let (socket, mut remote) = UnixStream::pair().unwrap();
    socket.set_nonblocking(true).unwrap();
    let s = a
        .handoff(
            handoff(Direction::Incoming, 14),
            socket,
            Direction::Incoming,
        )
        .unwrap();
    let task = thread::spawn(move || {
        let mut input = Vec::new();
        remote.read_to_end(&mut input).unwrap();
        assert_eq!(input, b"request");
        remote.write_all(b"reply").unwrap();
    });
    s.send_all(b"request", Duration::from_secs(1)).unwrap();
    s.shutdown_write().unwrap();
    let mut reply = [0; 5];
    s.recv_exact(&mut reply, Duration::from_secs(1)).unwrap();
    assert_eq!(&reply, b"reply");
    task.join().unwrap();
    s.close();
    drop(s);
    let (socket, mut remote) = UnixStream::pair().unwrap();
    socket.set_nonblocking(true).unwrap();
    let s = a
        .handoff(
            handoff(Direction::Incoming, 14),
            socket,
            Direction::Incoming,
        )
        .unwrap();
    let task = thread::spawn(move || {
        for byte in b"abc" {
            if remote.write_all(&[*byte]).is_err() {
                break;
            }
            thread::sleep(Duration::from_millis(70));
        }
    });
    let start = Instant::now();
    let mut reply = [0; 3];
    assert!(matches!(
        s.recv_exact(&mut reply, Duration::from_millis(100)),
        Err(Error::Timeout)
    ));
    assert!(start.elapsed() < Duration::from_millis(210));
    assert!(!s.check_authority_supported());
    task.join().unwrap();
}

#[test]
fn closed_handles_release_descriptors_and_do_not_consume_live_capacity() {
    let f = Fixture::new(normal);
    let a = f.agent();
    let mut retained = Vec::new();
    for _ in 0..20 {
        let (socket, _) = UnixStream::pair().unwrap();
        let s = a
            .handoff(
                handoff(Direction::Incoming, 14),
                socket,
                Direction::Incoming,
            )
            .unwrap();
        s.close();
        assert!(s.socket.lock().unwrap().is_none());
        retained.push(s);
    }
    let (socket, _) = UnixStream::pair().unwrap();
    assert!(
        a.handoff(
            handoff(Direction::Incoming, 14),
            socket,
            Direction::Incoming
        )
        .is_ok()
    );
}

#[test]
fn known_status_loss_and_close_do_not_present_old_privacy_as_active() {
    let mode = Arc::new(AtomicU64::new(0));
    let setting = mode.clone();
    let f = Fixture::new(move |r| {
        if r["action"] != "status" {
            return normal(r);
        }
        let mut value = status(1, false);
        match setting.load(Ordering::Acquire) {
            1 => {
                value["connections"][0]["privacy"] = json!({
                "transportAuthenticated":true,"relayPath":"unknown","provenance":"unavailable",
                "physicalIndependenceVerified":false,"profileCurrentnessAsserted":false})
            }
            2 => value["connections"] = json!([]),
            3 => value["capabilities"]["checkAuthority"]["endpointReady"] = false.into(),
            _ => (),
        }
        value.into()
    });
    let a = f.agent();
    let s = incoming(&a);
    let first = check(&a, &s);
    assert!(!s.privacy().is_historical());
    mode.store(1, Ordering::Release);
    a.status().unwrap();
    assert_eq!(s.privacy().provenance(), Provenance::Unavailable);
    assert_eq!(s.privacy().relay_path(), RelayPath::Unknown);
    assert!(first.privacy().unwrap().is_historical());
    mode.store(2, Ordering::Release);
    a.status().unwrap();
    assert!(s.privacy().is_historical());
    mode.store(3, Ordering::Release);
    a.status().unwrap();
    assert!(s.privacy().is_historical());
    s.close();
    assert!(s.privacy().is_historical());
    assert_eq!(
        serde_json::to_value(s.privacy()).unwrap()["historical"],
        true
    );
    let fresh = incoming(&a);
    assert!(!fresh.privacy().is_historical());
    fresh.close();
    assert!(fresh.privacy().is_historical());
}

#[test]
fn external_frame_deadlines_cannot_restart_a_payload_wait() {
    let f = Fixture::new(normal);
    let a = f.agent();
    let s = incoming(&a);
    assert!(matches!(s.send_all_before(b"late", 0), Err(Error::Timeout)));
    assert!(matches!(
        s.recv_exact_before(&mut [0; 1], 0),
        Err(Error::Timeout)
    ));
    assert!(matches!(
        s.send_all_before(b"overlong", ipc::boot_ms().unwrap() + 60_100),
        Err(Error::InvalidInput)
    ));
}

#[test]
fn idle_readability_wait_preserves_the_live_stream() {
    let fixture = Fixture::new(normal);
    let companion = fixture.agent();
    let stream = companion
        .connect(&id(3), "hrc-probe/1", Duration::from_secs(1))
        .unwrap();
    assert!(!stream.wait_readable(Duration::from_millis(10)).unwrap());
    assert!(!stream.privacy().is_historical());
    stream
        .send_all(b"still usable", Duration::from_secs(1))
        .unwrap();
    assert!(!stream.wait_readable(Duration::from_millis(10)).unwrap());
}
