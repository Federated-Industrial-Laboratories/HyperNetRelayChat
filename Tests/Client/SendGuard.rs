// SPDX-License-Identifier: Apache-2.0
//! Prompt policy revisions survive preparation; stale prompts create no outbox effect.
use super::*;
use std::{cell::Cell, io::Write};

#[test]
fn guarded_preparation_pins_prompt_revisions_or_stops_before_the_outbox() {
    for (room_revision, filter_revision, accepted) in [(7, 4, true), (6, 4, false), (7, 3, false)] {
        let fixture = crate::client::tests::Fixture::new();
        drop(fixture.create());
        fixture.profile();
        let mut client = Client::open_offline(&fixture.root).unwrap();
        let _clock = client.start_view_test_clock(&fixture.root);
        let peer = client.install_live_view_test_session(&fixture.root);
        let action = crate::client::tests::action();
        let Target::Room(room) = action.target else {
            unreachable!()
        };
        let message: messaging::Send = action.body.deserialized().unwrap();
        let inspection = conversations::Inspection {
            members: vec![],
            read_sequence: 0,
            room_revision: 7,
            filter_revision: 4,
            moderator: false,
            confidentiality: RoomConfidentiality::Community,
        };
        let server = client.view_test_responses(
            peer,
            vec![(
                Operation::RoomInspect,
                Some(Outcome::Result {
                    body: Value::serialized(&inspection).unwrap(),
                }),
            )],
            |peer, bytes| peer.write_all(bytes).unwrap(),
        );
        let finalized = Cell::new(false);
        let prepared = client.prepare_send_guarded_with(
            room,
            &message,
            None,
            SendGuard {
                room_revision,
                filter_revision,
            },
            |_, verified| {
                assert_eq!(
                    verified.action().expected.get(&Revision::Room),
                    Some(&room_revision)
                );
                assert_eq!(
                    verified.action().expected.get(&Revision::Filter),
                    Some(&filter_revision)
                );
                finalized.set(true);
                Ok(())
            },
        );
        let observed = server.join().unwrap();
        assert_eq!(
            observed.len(),
            1,
            "preparation sent only the authority read"
        );
        assert_eq!(finalized.get(), accepted);
        let pending = client.pending().unwrap();
        if accepted {
            let prepared = prepared.unwrap();
            let verified = verify_action(&prepared.signed, &client.key.verifying_key()).unwrap();
            assert_eq!(verified.action().expected.get(&Revision::Room), Some(&7));
            assert_eq!(verified.action().expected.get(&Revision::Filter), Some(&4));
            assert_eq!(pending.len(), 1);
            assert_eq!(pending[0].action.signed_bytes(), prepared.signed);
        } else {
            assert!(
                matches!(prepared, Err(Error::Rejected { code: ErrorCode::Conflict, detail }) if detail == "ExpectedRevision")
            );
            assert!(
                pending.is_empty(),
                "a fresh inspection cannot replace stale prompt authority"
            );
        }
    }
}

#[test]
fn absent_tail_capability_rejects_without_any_history_fallback() {
    let fixture = crate::client::tests::Fixture::new();
    drop(fixture.create());
    fixture.profile();
    let mut client = Client::open_offline(&fixture.root).unwrap();
    let mut peer = client.install_live_view_test_session(&fixture.root);
    let Target::Room(room) = crate::client::tests::action().target else {
        unreachable!()
    };
    assert!(
        matches!(client.history_tail(room, 32, None), Err(Error::Rejected { code: ErrorCode::UnsupportedFeature, detail }) if detail == "HistoryTailUnavailable")
    );
    peer.set_nonblocking(true).unwrap();
    assert_eq!(
        std::io::Read::read(&mut peer, &mut [0u8; 1])
            .unwrap_err()
            .kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert!(client.pending().unwrap().is_empty());
}
