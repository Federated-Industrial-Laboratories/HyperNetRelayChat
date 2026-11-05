// SPDX-License-Identifier: Apache-2.0
//! The prepared fast path preserves durable-before-submit and unknown-outcome recovery.
use super::*;
use crate::client::tests::Fixture;
use ed25519_dalek::Signer;
use std::{fs, io::Write, os::unix::fs::OpenOptionsExt, sync::mpsc, thread, time::Duration};

fn write_clock(path: &Path, key: &SigningKey) {
    let now = crate::clock::TimeBounds::test_now();
    let boot = fs::read_to_string("/proc/sys/kernel/random/boot_id").unwrap();
    let payload = canonical_encode(
        &Value::Array(vec![
            44u64.into(),
            1u64.into(),
            Value::Text(boot.trim().into()),
            (now.lower_ms + crate::clock::ERROR_BOUND_MS).into(),
            now.boot_ms.into(),
            (now.boot_ms + 1000).into(),
            0u64.into(),
            Value::Text("192.0.2.1".into()),
        ]),
        4096,
    )
    .unwrap();
    let public = key.verifying_key().to_bytes();
    let mut message = b"HyperNet/RecordSignature/1\0".to_vec();
    message.extend((payload.len() as u32).to_be_bytes());
    message.extend(&payload);
    message.extend(public);
    let signed = canonical_encode(
        &Value::Array(vec![
            0u64.into(),
            1u64.into(),
            Value::Bytes(payload),
            Value::Array(vec![Value::Array(vec![
                Value::Bytes(public.to_vec()),
                Value::Bytes(key.sign(&message).to_bytes().to_vec()),
            ])]),
        ]),
        4096,
    )
    .unwrap();
    // A reader sees one complete signed test observation, never a partial rewrite.
    let next = path.with_extension("Next");
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(&next)
        .unwrap();
    file.write_all(&signed).unwrap();
    drop(file);
    fs::rename(next, path).unwrap();
}
fn clock(client: &mut Client, root: &Path) -> SigningKey {
    let key = SigningKey::from_bytes(&[53; 32]);
    let path = root.join("CurrentClock");
    write_clock(&path, &key);
    client.profile.clock = crate::clock::Config {
        observation: path,
        monitor_key: hex::encode(key.verifying_key().to_bytes()),
    };
    key
}

pub(in crate::client) struct ViewTestClock {
    stop: mpsc::Sender<()>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Drop for ViewTestClock {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(worker) = self.worker.take() {
            let result = worker.join();
            if !thread::panicking() {
                result.expect("signed test clock publisher failed");
            }
        }
    }
}

impl Client {
    pub(in crate::client) fn install_view_test_clock(&mut self, root: &Path) {
        clock(self, root);
    }
    pub(in crate::client) fn start_view_test_clock(&mut self, root: &Path) -> ViewTestClock {
        let key = clock(self, root);
        let path = self.profile.clock.observation.clone();
        let (stop, receive) = mpsc::channel();
        let worker = thread::spawn(move || {
            // Model the running monitor during durable cache work. Every export
            // retains the production verifier's exact one-second lifetime.
            while matches!(
                receive.recv_timeout(Duration::from_millis(100)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ) {
                write_clock(&path, &key);
            }
        });
        ViewTestClock {
            stop,
            worker: Some(worker),
        }
    }
    pub(in crate::client) fn install_closed_view_test_session(&mut self, root: &Path) {
        self.session = Some(network::tests::closed_view_session(root, &self.profile));
    }
}

fn fixture() -> (Fixture, Client, RoomId) {
    let fixture = Fixture::new();
    drop(fixture.create());
    fixture.profile();
    let mut client = Client::open_offline(&fixture.root).unwrap();
    client.install_closed_view_test_session(&fixture.root);
    let Target::Room(room) = crate::client::tests::action().target else {
        unreachable!()
    };
    clock(&mut client, &fixture.root);
    (fixture, client, room)
}

#[test]
fn private_preparation_is_durable_once_before_unknown_submission_and_restart() {
    let (fixture, mut client, room) = fixture();
    client
        .remember_community(room, RoomConfidentiality::Community)
        .unwrap();
    let body = crate::client::tests::action().body.deserialized().unwrap();
    let prepared = client
        .prepare_controller_send_with(room, &body, None, false, None, |tx, exact| {
            let bytes: Vec<u8> = tx.query_row(
                "SELECT action FROM client_outbox WHERE window=?1 AND operation=?2",
                [
                    exact.action().operation_id.window.as_hex(),
                    exact.action().operation_id.operation.as_hex(),
                ],
                |r| r.get(0),
            )?;
            assert_eq!(bytes, exact.signed_bytes());
            Ok(())
        })
        .unwrap();
    let bytes = prepared.message.signed.clone();
    let id = prepared.message.action.operation_id;
    let digest = action_digest(&prepared.message.action).unwrap();
    let before = client.store.usage().unwrap().commit_counter;
    assert!(matches!(
        client.execute_controller_send(prepared),
        Err(Error::Network(network::Error::Transport))
    ));
    assert_eq!(
        client.store.usage().unwrap().commit_counter,
        before,
        "submission must not prepare the outbox a second time"
    );
    drop(client);
    let mut reopened = Client::open_offline(&fixture.root).unwrap();
    let pending = reopened.pending().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].action.signed_bytes(), bytes);
    assert_eq!(pending[0].action.action().operation_id, id);
    assert_eq!(pending[0].action.digest(), digest);
    assert!(reopened.community_modes.is_empty());
}

#[test]
fn mode_proof_requires_current_capability_and_exact_pinned_service_identity() {
    for changed in [false, true] {
        let (_fixture, mut client, room) = fixture();
        client
            .remember_community(room, RoomConfidentiality::Community)
            .unwrap();
        if changed {
            client.profile.server.signing_key = Id::from_bytes([77; 32]);
        } else {
            client.session.as_mut().unwrap().ready.capabilities.clear();
        }
        let body = crate::client::tests::action().body.deserialized().unwrap();
        let result = client.prepare_controller_send_with(room, &body, None, false, None, |_, _| {
            panic!("unproven mode reached durable preparation")
        });
        assert!(matches!(
            result,
            Err(Error::Network(network::Error::Transport))
        ));
        assert!(client.pending().unwrap().is_empty());
    }
}

fn live_fixture() -> (
    Fixture,
    Client,
    std::os::unix::net::UnixStream,
    ViewTestClock,
) {
    let fixture = Fixture::new();
    drop(fixture.create());
    fixture.profile();
    let mut client = Client::open_offline(&fixture.root).unwrap();
    let clock = client.start_view_test_clock(&fixture.root);
    let (session, peer) = network::tests::live_view_session(&fixture.root, &client.profile);
    client.session = Some(session);
    (fixture, client, peer, clock)
}

// Reuse the companion handoff and session fixture, then authenticate real HRC
// frames. This exercises response binding without asserting HyperNet authority.
fn signed_responses(
    mut peer: std::os::unix::net::UnixStream,
    key: VerifyingKey,
    replies: Vec<(Operation, Option<Outcome>)>,
) -> thread::JoinHandle<Vec<Vec<u8>>> {
    thread::spawn(move || {
        use std::io::Read;
        peer.set_read_timeout(Some(Duration::from_secs(3))).unwrap();
        peer.set_write_timeout(Some(Duration::from_secs(3)))
            .unwrap();
        let server = SigningKey::from_bytes(&[11; 32]);
        let mut received = Vec::new();
        for (operation, outcome) in replies {
            let mut header = [0; 5];
            peer.read_exact(&mut header).unwrap();
            let header = FrameHeader::decode(header).unwrap();
            assert_eq!(header.kind, FrameKind::Action);
            let mut bytes = vec![0; header.payload_len];
            peer.read_exact(&mut bytes).unwrap();
            let action = verify_action(&bytes, &key).unwrap();
            assert_eq!(action.action().operation, operation);
            let response = outcome.map(|outcome| Response {
                home: action.action().home,
                operation_id: action.action().operation_id,
                action_digest: action.digest(),
                outcome,
            });
            received.push(bytes);
            let Some(response) = response else { break };
            let frame = Frame::new(
                FrameKind::Response,
                sign_response(&response, &server).unwrap(),
            )
            .unwrap()
            .encode()
            .unwrap();
            peer.write_all(&frame).unwrap();
        }
        received
    })
}

fn temporary_direct_read() -> Outcome {
    Outcome::Refused {
        code: ErrorCode::Unavailable,
        detail: "TransportInactive".into(),
        retry_after_ms: Some(250),
    }
}

#[test]
fn direct_message_preparation_retries_exact_inspection_before_one_effect() {
    let (_fixture, mut client, peer, _clock) = live_fixture();
    let action = crate::client::tests::action();
    let Target::Room(room) = action.target else {
        unreachable!()
    };
    let inspection = Outcome::Result {
        body: Value::serialized(&crate::conversations::Inspection {
            members: vec![],
            read_sequence: 0,
            room_revision: 1,
            filter_revision: 0,
            moderator: false,
            confidentiality: RoomConfidentiality::Community,
        })
        .unwrap(),
    };
    let server = signed_responses(
        peer,
        client.key.verifying_key(),
        vec![
            (Operation::RoomInspect, Some(temporary_direct_read())),
            (Operation::RoomInspect, Some(inspection.clone())),
            // Ordinary submission retains its independent current-mode validation.
            (Operation::RoomInspect, Some(inspection)),
            (
                Operation::MessageSend,
                Some(Outcome::Committed {
                    event: Some(Id::from_bytes([90; 32])),
                    position: 1,
                    body: Value::Null,
                }),
            ),
        ],
    );
    let session = client.session().unwrap().stream_handle();
    let message = action.body.deserialized().unwrap();
    let prepared = client
        .prepare_send(room, &message, None, false, None)
        .unwrap();
    let pending = client.pending().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].action.signed_bytes(), prepared.signed);
    assert!(matches!(
        client.execute_signed(&prepared.signed).unwrap().outcome,
        Outcome::Committed { .. }
    ));
    assert!(client.pending().unwrap().is_empty());
    assert!(std::sync::Arc::ptr_eq(
        &session,
        &client.session().unwrap().stream_handle()
    ));
    let frames = server.join().unwrap();
    assert_eq!(frames.len(), 4);
    assert_eq!(
        frames[0], frames[1],
        "read retry changed its signed identity"
    );
    assert_ne!(
        frames[1], frames[2],
        "later mode validation was replaced by an old read"
    );
    assert_eq!(
        frames[3], prepared.signed,
        "message was not submitted exactly once"
    );
}

#[test]
fn direct_signed_read_retries_at_most_five_times_without_outbox_work() {
    let (_fixture, mut client, peer, _clock) = live_fixture();
    let server = signed_responses(
        peer,
        client.key.verifying_key(),
        (0..5)
            .map(|_| (Operation::ServiceInspect, Some(temporary_direct_read())))
            .collect(),
    );
    let action = client
        .prepare(
            Operation::ServiceInspect,
            Target::Service,
            Value::Map(vec![]),
        )
        .unwrap();
    let bytes = client.sign(&action).unwrap();
    let before = client.store.usage().unwrap().commit_counter;
    assert!(matches!(
        client.execute_signed(&bytes).unwrap().outcome,
        Outcome::Refused {
            code: ErrorCode::Unavailable,
            ..
        }
    ));
    let frames = server.join().unwrap();
    assert_eq!(frames.len(), 5);
    assert!(frames.iter().all(|frame| frame == &bytes));
    assert_eq!(client.store.usage().unwrap().commit_counter, before);
    assert!(client.pending().unwrap().is_empty());
}

#[test]
fn direct_read_denial_expiry_rejection_and_transport_loss_are_not_retried() {
    for outcome in [
        Some(Outcome::Refused {
            code: ErrorCode::Denied,
            detail: "Denied".into(),
            retry_after_ms: Some(250),
        }),
        Some(Outcome::Refused {
            code: ErrorCode::Expired,
            detail: "Expired".into(),
            retry_after_ms: Some(250),
        }),
        Some(Outcome::Rejected {
            code: ErrorCode::Unavailable,
            detail: "Terminal".into(),
        }),
        None,
    ] {
        let (_fixture, mut client, peer, _clock) = live_fixture();
        let expected = outcome.clone();
        let server = signed_responses(
            peer,
            client.key.verifying_key(),
            vec![(Operation::ServiceInspect, outcome)],
        );
        let result = client.read_as::<Value, _>(
            Operation::ServiceInspect,
            Target::Service,
            &Value::Map(vec![]),
            None,
        );
        match expected {
            Some(Outcome::Refused { code, .. }) => assert!(
                matches!(result, Err(Error::Refused { code: actual, .. }) if actual == code)
            ),
            Some(Outcome::Rejected { code, .. }) => assert!(
                matches!(result, Err(Error::Rejected { code: actual, .. }) if actual == code)
            ),
            None => assert!(matches!(
                result,
                Err(Error::Network(network::Error::Transport))
            )),
            _ => unreachable!(),
        }
        assert_eq!(server.join().unwrap().len(), 1);
        assert!(client.pending().unwrap().is_empty());
    }
}

#[test]
fn direct_read_keeps_original_budget_and_never_submits_mutations_through_retry() {
    use std::io::Read;
    let (_fixture, client, mut peer, _clock) = live_fixture();
    let read = client
        .prepare(
            Operation::ServiceInspect,
            Target::Service,
            Value::Map(vec![]),
        )
        .unwrap();
    let bytes = client.sign(&read).unwrap();
    let end = crate::clock::boot_ms().unwrap();
    assert!(matches!(
        client.read_signed_until(&bytes, end),
        Err(Error::ReadDeadlineExpired)
    ));
    let mutation = crate::client::tests::action();
    let signed = client.sign(&mutation).unwrap();
    assert!(matches!(
        client.read_signed_until(&signed, end + 10_000),
        Err(Error::Network(network::Error::Authentication))
    ));
    peer.set_read_timeout(Some(Duration::from_millis(25)))
        .unwrap();
    assert!(
        matches!(peer.read(&mut [0; 1]), Err(error) if matches!(error.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut))
    );
    let server = signed_responses(
        peer,
        client.key.verifying_key(),
        vec![(
            Operation::ServiceInspect,
            Some(Outcome::Refused {
                code: ErrorCode::Unavailable,
                detail: "TransportInactive".into(),
                retry_after_ms: Some(10_000),
            }),
        )],
    );
    let end = crate::clock::boot_ms().unwrap() + 5000;
    assert!(matches!(
        client.read_signed_until(&bytes, end).unwrap().outcome,
        Outcome::Refused { .. }
    ));
    assert!(
        crate::clock::boot_ms().unwrap() < end,
        "retry guidance extended the original read budget"
    );
    assert_eq!(server.join().unwrap(), vec![bytes]);
}

#[test]
fn temporary_mutation_refusal_remains_one_submission_with_exact_pending_bytes() {
    let (_fixture, mut client, peer, _clock) = live_fixture();
    let server = signed_responses(
        peer,
        client.key.verifying_key(),
        vec![(Operation::AccountSetNickname, Some(temporary_direct_read()))],
    );
    let action = client
        .prepare(
            Operation::AccountSetNickname,
            Target::Account(client.profile.registration.account),
            Value::Null,
        )
        .unwrap();
    let bytes = client.sign(&action).unwrap();
    assert!(matches!(
        client.execute(&action).unwrap().outcome,
        Outcome::Refused { .. }
    ));
    assert_eq!(server.join().unwrap(), vec![bytes.clone()]);
    let pending = client.pending().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].action.signed_bytes(), bytes);
}
