// SPDX-License-Identifier: Apache-2.0
//! Future-only Welcome admission must not depend on trust in superseded rosters.
use super::*;
use crate::client::tests::{Fixture, action};

fn client(fixture: &Fixture) -> Client {
    drop(fixture.create());
    fixture.profile();
    Client::open_offline(&fixture.root).unwrap()
}

#[test]
fn welcome_cursor_skips_old_untrusted_rosters_but_new_transitions_still_require_trust() {
    let creator_fixture = Fixture::new();
    let recipient_fixture = Fixture::new();
    let mut creator = client(&creator_fixture);
    let mut recipient = client(&recipient_fixture);
    let a = action();
    let Target::Room(room) = a.target else {
        unreachable!()
    };
    let original = a.actor.acting().clone();
    let mut recovered = original.clone();
    recovered.endpoint = Id::from_bytes([81; 32]);
    recovered.security_generation += 1;
    let creator_device = crypto::Device::provision(&mut creator.store, original).unwrap();
    let recovered_device = crypto::Device::provision(&mut recipient.store, recovered).unwrap();
    let group = Id::from_bytes([82; 32]);
    let first = crypto::ApprovedRoster::new(room, vec![creator_device.credential(room)]).unwrap();
    let both = crypto::ApprovedRoster::new(
        room,
        vec![
            creator_device.credential(room),
            recovered_device.credential(room),
        ],
    )
    .unwrap();
    creator_device
        .create_group(&mut creator.store, group, &first, 1)
        .unwrap();
    let package = recovered_device
        .publish_key_package(&mut recipient.store, room)
        .unwrap();
    let pending = creator_device
        .prepare_transition(
            &mut creator.store,
            group,
            0,
            &first,
            &both,
            crypto::Change::Add(&[package]),
        )
        .unwrap();
    let receipt = creator_device
        .accept_transition(
            &mut creator.store,
            crypto::TransitionOrder {
                group,
                epoch: 0,
                previous_sequence: 1,
                sequence: 10,
            },
            &pending.commit,
            &both,
        )
        .unwrap();
    recovered_device
        .join(
            &mut recipient.store,
            group,
            1,
            10,
            receipt.welcome.as_ref().unwrap(),
            &both,
        )
        .unwrap();
    let before =
        cache::encode(&recovered_device.state(&mut recipient.store, group).unwrap()).unwrap();
    let mut removed = creator_device.actor.clone();
    removed.account.local = Id::from_bytes([83; 32]);
    let mut credential = creator_device.credential(room);
    credential.actor = removed.clone();
    let mut transition = domain::TransitionEvent {
        group,
        previous_epoch: Some(0),
        epoch: 1,
        commit_digest: digest(&pending.commit),
        commit: Blob(pending.commit),
        members: vec![domain::Member {
            actor: Actor::Direct { acting: removed },
            credential,
            registration: Blob(vec![]),
            delegation: None,
        }],
        additions: vec![],
        removals: vec![],
    };
    let mut event = Event {
        home: room.home,
        room,
        event: Id::from_bytes([84; 32]),
        sequence: 5,
        operation_id: a.operation_id,
        action_digest: Id::from_bytes([85; 32]),
        actor: a.actor,
        kind: Operation::CryptoCommit,
        timestamp_ms: crate::clock::TimeBounds::test_now().lower_ms,
        body: Value::serialized(&transition).unwrap(),
    };
    // The verified Welcome already establishes the recipient's epoch and position.
    // Earlier rosters, including removed accounts, cannot advance that MLS state.
    recipient
        .receive_transition(&event, None, &recovered_device)
        .unwrap();
    event.sequence = 10;
    recipient
        .receive_transition(&event, None, &recovered_device)
        .unwrap();
    drop(recipient);
    let mut recipient = Client::open_offline(&recipient_fixture.root).unwrap();
    recipient
        .receive_transition(&event, None, &recovered_device)
        .unwrap();
    assert_eq!(
        cache::encode(&recovered_device.state(&mut recipient.store, group).unwrap()).unwrap(),
        before
    );
    assert_eq!(
        recipient
            .store
            .read(Duration::from_secs(1), |db| {
                db.query_row(
                    "SELECT count(*) FROM client_contacts WHERE trusted=1",
                    [],
                    |r| r.get::<_, u64>(0),
                )
            })
            .unwrap(),
        0
    );

    // A later roster still needs contact evidence, which this offline endpoint lacks.
    event.sequence = 11;
    assert!(matches!(
        recipient.receive_transition(&event, None, &recovered_device),
        Err(Error::Offline)
    ));
    assert_eq!(
        cache::encode(&recovered_device.state(&mut recipient.store, group).unwrap()).unwrap(),
        before
    );

    // Superseded events remain subject to bounded decoding and digest validation.
    event.sequence = 5;
    transition.commit_digest = Id::from_bytes([86; 32]);
    event.body = Value::serialized(&transition).unwrap();
    assert!(matches!(
        recipient.receive_transition(&event, None, &recovered_device),
        Err(Error::Input)
    ));
}
