// SPDX-License-Identifier: Apache-2.0
//! Signed local transport verifies guarded first-name effects and durable interrupted work.
use super::*;
use std::io::Write;
fn inspected(name: String, revision: u64) -> Outcome {
    Outcome::Result {
        body: Value::serialized(&identity::AccountView {
            nickname: name,
            revision,
            filter_revision: 1,
        })
        .unwrap(),
    }
}
fn committed() -> Outcome {
    Outcome::Committed {
        event: None,
        position: 1,
        body: Value::serialized(&home::Empty {}).unwrap(),
    }
}
#[test]
fn initial_nickname_is_revision_guarded_and_done_survives_reopening() {
    let (fixture, mut worker, _) = super::super::completion_tests::worker();
    worker.shared.stop.store(false, Ordering::Release);
    worker.shared.disconnect.store(false, Ordering::Release);
    let _clock = worker.client.start_view_test_clock(&fixture.root);
    let peer = worker.client.install_live_view_test_session(&fixture.root);
    let default = format!("account-{}", &worker.snapshot.account.local.as_hex()[..12]);
    let server = worker.client.view_test_responses(
        peer,
        vec![
            (Operation::AccountInspect, Some(inspected(default, 1))),
            (Operation::AccountSetNickname, Some(committed())),
        ],
        |peer, bytes| peer.write_all(bytes).unwrap(),
    );
    worker.initialize_nickname("Haru").unwrap();
    let frames = server.join().unwrap();
    assert_eq!(frames.len(), 2);
    let key = crate::service::files::key(&fixture.root.join("Endpoint.key")).unwrap();
    let action = verify_action(&frames[1], &key.verifying_key()).unwrap();
    assert_eq!(action.action().expected.get(&Revision::Account), Some(&1));
    assert_eq!(
        action
            .action()
            .body
            .deserialized::<identity::Nickname>()
            .unwrap()
            .nickname,
        "Haru"
    );
    assert_eq!(worker.snapshot.nickname, "Haru");
    assert!(worker.client.pending().unwrap().is_empty());
    worker.client.disconnect();
    worker.initialize_nickname("Should not replace").unwrap(); // No network request after completion.
    drop(worker);
    let mut client = Client::open_offline(&fixture.root).unwrap();
    let state: State = cache::preferences(&mut client.store, KEY).unwrap();
    assert!(state.done);
    assert_eq!(state.name.as_deref(), Some("Haru"));
}
#[test]
fn initial_nickname_preserves_an_already_changed_account_without_a_mutation() {
    let (fixture, mut worker, _) = super::super::completion_tests::worker();
    worker.shared.stop.store(false, Ordering::Release);
    worker.shared.disconnect.store(false, Ordering::Release);
    let _clock = worker.client.start_view_test_clock(&fixture.root);
    let peer = worker.client.install_live_view_test_session(&fixture.root);
    let server = worker.client.view_test_responses(
        peer,
        vec![(
            Operation::AccountInspect,
            Some(inspected("Chosen later".into(), 2)),
        )],
        |peer, bytes| peer.write_all(bytes).unwrap(),
    );
    worker.initialize_nickname("Original join name").unwrap();
    assert_eq!(server.join().unwrap().len(), 1);
    assert_eq!(worker.snapshot.nickname, "Chosen later");
    assert!(
        cache::preferences::<State>(&mut worker.client.store, KEY)
            .unwrap()
            .done
    );
}
#[test]
fn uncertain_initial_nickname_keeps_exact_outbox_and_pending_marker() {
    let (fixture, mut worker, _) = super::super::completion_tests::worker();
    worker.shared.stop.store(false, Ordering::Release);
    worker.shared.disconnect.store(false, Ordering::Release);
    let _clock = worker.client.start_view_test_clock(&fixture.root);
    let peer = worker.client.install_live_view_test_session(&fixture.root);
    let default = format!("account-{}", &worker.snapshot.account.local.as_hex()[..12]);
    let server = worker.client.view_test_responses(
        peer,
        vec![
            (Operation::AccountInspect, Some(inspected(default, 1))),
            (Operation::AccountSetNickname, None),
        ],
        |peer, bytes| peer.write_all(bytes).unwrap(),
    );
    assert!(worker.initialize_nickname("Haru").is_err());
    let frames = server.join().unwrap();
    let pending = worker.client.pending().unwrap();
    assert_eq!(pending.len(), 1);
    assert_eq!(pending[0].action.signed_bytes(), frames[1]);
    assert!(matches!(
        worker.initialize_nickname("Haru"),
        Err(Error::Unknown)
    ));
    assert_eq!(
        worker.client.pending().unwrap()[0].action.signed_bytes(),
        frames[1]
    );
    drop(worker);
    let mut client = Client::open_offline(&fixture.root).unwrap();
    let state: State = cache::preferences(&mut client.store, KEY).unwrap();
    assert!(!state.done);
    assert_eq!(state.name.as_deref(), Some("Haru"));
    assert_eq!(
        client.pending().unwrap()[0].action.signed_bytes(),
        frames[1]
    );
}
