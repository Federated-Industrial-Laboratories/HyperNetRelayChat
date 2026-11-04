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
