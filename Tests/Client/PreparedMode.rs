// SPDX-License-Identifier: Apache-2.0
//! Only exact in-memory prepared bytes may use immutable community-mode evidence.
use super::*;

fn prepared() -> ControllerPreparedSend {
    let action = crate::client::tests::action();
    let key = SigningKey::from_bytes(&[41; 32]);
    let signed = sign_action(&action, &key).unwrap();
    let proof = verify_action(&signed, &key.verifying_key()).unwrap();
    ControllerPreparedSend {
        message: PreparedSend {
            action,
            signed,
            encrypted: false,
        },
        proof: Some(proof),
    }
}

#[test]
fn exact_prepared_mode_token_rejects_substituted_content_identity_and_encoding() {
    assert!(prepared().verified().unwrap().is_some());
    for change in 0..6 {
        let mut p = prepared();
        match change {
            0 => p.message.action.home.service = Id::from_bytes([42; 32]),
            1 => {
                let Target::Room(ref mut room) = p.message.action.target else {
                    unreachable!()
                };
                room.local = Id::from_bytes([42; 32]);
            }
            2 => p.message.action.body = Value::Null,
            3 => p.message.signed.push(0),
            4 => p.message.encrypted = true,
            5 => {
                p.message.action.actor = Actor::IndependentAgent {
                    acting: p.message.action.actor.acting().clone(),
                    operator: p.message.action.actor.represented(),
                }
            }
            _ => unreachable!(),
        }
        assert!(matches!(p.verified(), Err(Error::Input)));
    }
    let mut unproven = prepared();
    unproven.proof = None;
    assert!(
        unproven.verified().unwrap().is_none(),
        "unproven sends retain raw validation"
    );
}

#[test]
fn persisted_or_disconnected_client_cannot_turn_a_room_hint_into_mode_evidence() {
    let fixture = crate::client::tests::Fixture::new();
    drop(fixture.create());
    fixture.profile();
    let mut client = Client::open_offline(&fixture.root).unwrap();
    let Target::Room(room) = crate::client::tests::action().target else {
        unreachable!()
    };
    client
        .community_modes
        .insert(room, client.profile.active_server().signing_key);
    assert!(!client.known_community(room));
    assert!(matches!(
        client.remember_community(room, RoomConfidentiality::Community),
        Err(Error::Input)
    ));
    client.disconnect();
    assert!(client.community_modes.is_empty());
    drop(client);
    let reopened = Client::open_offline(&fixture.root).unwrap();
    assert!(reopened.community_modes.is_empty());
}
