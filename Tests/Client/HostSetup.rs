// SPDX-License-Identifier: Apache-2.0
//! Signed transport and encrypted stores cover retained owner setup and uncertain room creation.
use super::*;
use crate::{client::tests::Fixture, service::host};
use std::io::Write;
fn fixture() -> (Fixture, Client, RoomId) {
    let fixture = Fixture::new();
    drop(fixture.create());
    fixture.profile();
    let client = Client::open_offline(&fixture.root).unwrap();
    let Target::Room(room) = crate::client::tests::action().target else {
        unreachable!()
    };
    (fixture, client, room)
}
fn created(room: RoomId) -> Outcome {
    Outcome::Committed {
        event: None,
        position: 2,
        body: Value::serialized(&crate::messaging::Committed { room: Some(room) }).unwrap(),
    }
}
#[test]
fn host_nickname_conflict_preserves_later_name_and_continues_setup() {
    let (fixture, mut client, room) = fixture();
    let _clock = client.start_view_test_clock(&fixture.root);
    let peer = client.install_live_view_test_session(&fixture.root);
    let default = format!(
        "account-{}",
        &client.profile.registration.account.local.as_hex()[..12]
    );
    let inspected = |nickname, revision| Outcome::Result {
        body: Value::serialized(&identity::AccountView {
            nickname,
            revision,
            filter_revision: 1,
        })
        .unwrap(),
    };
    let worker = client.view_test_responses(
        peer,
        vec![
            (Operation::AccountInspect, Some(inspected(default, 1))),
            (
                Operation::AccountSetNickname,
                Some(Outcome::Rejected {
                    code: ErrorCode::Conflict,
                    detail: "AccountRevision".into(),
                }),
            ),
            (
                Operation::AccountInspect,
                Some(inspected("Chosen elsewhere".into(), 2)),
            ),
            (Operation::RoomCreate, Some(created(room))),
        ],
        |peer, bytes| peer.write_all(bytes).unwrap(),
    );
    assert_eq!(
        client.finish_host(&fixture.root, "Initial name").unwrap(),
        room
    );
    let frames = worker.join().unwrap();
    assert_eq!(frames.len(), 4);
    assert!(files::json::<bool>(&fixture.root.join("Nickname.done")).unwrap());
    assert!(client.pending().unwrap().is_empty());
}
#[test]
fn host_owner_signed_effects_recover_terminal_outbox_before_new_session() {
    let (fixture, mut client, room) = fixture();
    let _clock = client.start_view_test_clock(&fixture.root);
    let peer = client.install_live_view_test_session(&fixture.root);
    let nickname = format!(
        "account-{}",
        &client.profile.registration.account.local.as_hex()[..12]
    );
    let worker = client.view_test_responses(
        peer,
        vec![
            (
                Operation::AccountInspect,
                Some(Outcome::Result {
                    body: Value::serialized(&identity::AccountView {
                        nickname,
                        revision: 1,
                        filter_revision: 1,
                    })
                    .unwrap(),
                }),
            ),
            (
                Operation::AccountSetNickname,
                Some(Outcome::Committed {
                    event: None,
                    position: 1,
                    body: Value::serialized(&home::Empty {}).unwrap(),
                }),
            ),
            (Operation::RoomCreate, Some(created(room))),
        ],
        |peer, bytes| peer.write_all(bytes).unwrap(),
    );
    assert_eq!(client.finish_host(&fixture.root, "Owner").unwrap(), room);
    let frames = worker.join().unwrap();
    assert_eq!(frames.len(), 3);
    assert_eq!(
        verify_action(&frames[1], &client.key.verifying_key())
            .unwrap()
            .action()
            .expected
            .get(&Revision::Account),
        Some(&1)
    );
    std::fs::remove_file(fixture.root.join("General.Outcome.cbor")).unwrap(); // Commit reached outbox; helper result write was lost.
    drop(client);
    let mut reopened = Client::open_offline(&fixture.root).unwrap();
    assert_eq!(reopened.finish_host(&fixture.root, "Owner").unwrap(), room); // No companion/session exists.
    assert_eq!(reopened.finish_host(&fixture.root, "Owner").unwrap(), room); // Retained canonical binary result.
    assert_eq!(
        files::read(
            &fixture.root.join("General.Action.cbor"),
            ORDINARY_FRAME_BYTES
        )
        .unwrap(),
        frames[2]
    );
    assert!(reopened.pending().unwrap().is_empty());
}
#[test]
fn uncertain_host_room_retains_exact_action_and_never_creates_a_replacement() {
    let (fixture, mut client, room) = fixture();
    let _clock = client.start_view_test_clock(&fixture.root);
    let clock = client.profile.clock.clone();
    exact(&fixture.root.join("Nickname.done"), &true).unwrap();
    let peer = client.install_live_view_test_session(&fixture.root);
    let worker =
        client.view_test_responses(peer, vec![(Operation::RoomCreate, None)], |peer, bytes| {
            peer.write_all(bytes).unwrap()
        });
    assert!(client.finish_host(&fixture.root, "Owner").is_err());
    let frames = worker.join().unwrap();
    assert_eq!(frames.len(), 1);
    let retained = files::read(
        &fixture.root.join("General.Action.cbor"),
        ORDINARY_FRAME_BYTES,
    )
    .unwrap();
    assert_eq!(retained, frames[0]);
    assert_eq!(client.pending().unwrap()[0].action.signed_bytes(), retained);
    drop(client);
    let mut reopened = Client::open_offline(&fixture.root).unwrap();
    assert!(reopened.finish_host(&fixture.root, "Owner").is_err());
    assert_eq!(
        files::read(
            &fixture.root.join("General.Action.cbor"),
            ORDINARY_FRAME_BYTES
        )
        .unwrap(),
        retained
    );
    assert_eq!(reopened.pending().unwrap().len(), 1);
    reopened.profile.clock = clock;
    let original = reopened.pending().unwrap().remove(0).action;
    let resumed = fixture.root.join("R");
    files::directory(&resumed, true).unwrap();
    let peer = reopened.install_live_view_test_session(&resumed);
    let worker = reopened.view_test_responses(
        peer,
        vec![(
            Operation::OperationResolve,
            Some(Outcome::Result {
                body: Value::serialized(&home::ResolveResult {
                    operation_id: original.action().operation_id,
                    action_digest: original.digest(),
                    outcome: created(room),
                })
                .unwrap(),
            }),
        )],
        |peer, bytes| peer.write_all(bytes).unwrap(),
    );
    assert_eq!(reopened.finish_host(&fixture.root, "Owner").unwrap(), room);
    assert_eq!(worker.join().unwrap().len(), 1); // Resolve only; no second room create.
    assert!(reopened.pending().unwrap().is_empty());
}
#[test]
fn host_prepare_resumes_same_owner_and_refuses_changed_native_binding() {
    let (fixture, mut clock_client, _) = fixture();
    let _clock = clock_client.start_view_test_clock(&fixture.root);
    let directory = fixture.root.join("HRC");
    let options = host::Options {
        home: clock_client.profile.server.home,
        receiver_companion: fixture.root.join("Receiver"),
        clock: clock_client.profile.clock.clone(),
        owner_principal: Id::from_bytes([18; 32]),
        owner_companion: fixture.root.join("OwnerCompanion"),
        nickname: "Owner".into(),
        motd: "Welcome".into(),
        agents_enabled: true,
        max_agents_per_operator: 2,
    };
    let prepare = |options| {
        host::request(
            &directory,
            host::Request {
                format: host::FORMAT.into(),
                action: host::Action::Prepare(Box::new(options)),
            },
        )
    };
    let first = prepare(options.clone()).unwrap();
    assert_eq!(first.status, "Prepared");
    assert!(first.rooms.is_empty());
    let owner = crate::client::Profile::load(&first.owner_profile).unwrap();
    let home_config = crate::service::Config::load(&first.service_directory).unwrap();
    assert_eq!(
        home_config.room_creation,
        home::RoomCreationPolicy::AllowList {
            accounts: vec![owner.registration.account]
        }
    );
    assert!(files::read(&first.admission_binding, 16384).unwrap().len() < 4096);
    let signing = files::read(&first.service_directory.join("Signing.key"), 32).unwrap();
    assert_ne!(
        signing,
        files::read(&directory.join("Registrar.key"), 32).unwrap()
    );
    std::fs::remove_file(directory.join("Prepared.json")).unwrap(); // Enrolment succeeded before marker write.
    let retry = prepare(options.clone()).unwrap();
    assert_eq!(
        serde_json::to_value(&first).unwrap(),
        serde_json::to_value(&retry).unwrap()
    );
    assert_eq!(
        crate::client::Profile::load(&retry.owner_profile)
            .unwrap()
            .registration,
        owner.registration
    );
    let mut changed = options;
    changed.owner_principal = Id::from_bytes([19; 32]);
    assert!(prepare(changed).is_err());
    let mut store = home_config.store(&first.service_directory).unwrap();
    let count = store
        .read(Duration::from_secs(2), |db| {
            db.query_row("SELECT count(*) FROM hrc_accounts", [], |r| {
                r.get::<_, u64>(0)
            })
        })
        .unwrap();
    assert_eq!(count, 1);
    drop(store);
    assert_eq!(
        files::read(&first.service_directory.join("Signing.key"), 32).unwrap(),
        signing
    );
}
