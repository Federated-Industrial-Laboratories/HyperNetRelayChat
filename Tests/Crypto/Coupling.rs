// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::{
    client::outbox,
    clock::TimeBounds,
    protocol::{Action, RetryWindow, SigningKey, sign_action, verify_action},
};
use std::time::Duration;

fn membership_action(
    pending: &PendingTransition,
    device: &Device,
    operation: OperationId,
) -> Action {
    Action {
        home: room().home,
        operation_id: operation,
        actor: Actor::Direct {
            acting: device.actor.clone(),
        },
        target: crate::protocol::Target::Room(room()),
        operation: Operation::CryptoCommit,
        body: crate::protocol::Value::serialized(&crate::confidential::CommitEpoch {
            group: pending.group,
            epoch: pending.epoch,
            commit: crate::protocol::Blob(pending.commit.clone()),
            additions: vec![],
            removals: vec![],
        })
        .unwrap(),
        expected: BTreeMap::new(),
        approval: None,
        agreement: None,
    }
}
fn candidate_count(store: &mut Store) -> u32 {
    store
        .read(Duration::from_secs(1), |db| {
            db.query_row("SELECT count(*) FROM crypto_pending", [], |row| row.get(0))
        })
        .unwrap()
}

#[test]
fn membership_candidate_outbox_and_terminal_rejection_share_durable_boundaries() {
    use crate::protocol::{
        ErrorCode, Outcome, Response, Target, Value, sign_response, verify_response,
    };
    for resolved in [false, true] {
        let (mut alice, _bob, both) = pair();
        outbox::initialize(alice.store()).unwrap();
        let device = alice.device.clone();
        let key = SigningKey::from_bytes(&[91; 32]);
        let server = SigningKey::from_bytes(&[92; 32]);
        let operation = OperationId {
            window: id(93),
            operation: id(94),
        };
        let window = RetryWindow {
            id: operation.window,
            expires_ms: TimeBounds::test_now().upper_ms + 60000,
        };
        let prepare =
            |tx: &rusqlite::Transaction<'_>, pending: &PendingTransition| -> Result<Vec<u8>> {
                let action = membership_action(pending, &device, operation);
                let bytes = sign_action(&action, &key)?;
                let verified = verify_action(&bytes, &key.verifying_key())?;
                outbox::prepare_transaction(tx, &verified, &window, TimeBounds::test_now())?;
                bind_transition_in(tx, pending, operation, verified.digest())?;
                Ok(bytes)
            };
        assert!(
            device
                .prepare_transition_with(
                    alice.store(),
                    TransitionPreparation {
                        group: id(5),
                        epoch: 1,
                        current: &both,
                        next: &both,
                        change: Change::Update
                    },
                    |tx, pending| {
                        prepare(tx, pending)?;
                        Err(Error::Conflict)
                    }
                )
                .is_err()
        );
        alice.restart();
        assert_eq!(candidate_count(alice.store()), 0);
        assert!(
            outbox::pending(alice.store(), &key.verifying_key())
                .unwrap()
                .is_empty()
        );
        let mut signed = None;
        let pending = device
            .prepare_transition_with(
                alice.store(),
                TransitionPreparation {
                    group: id(5),
                    epoch: 1,
                    current: &both,
                    next: &both,
                    change: Change::Update,
                },
                |tx, pending| {
                    signed = Some(prepare(tx, pending)?);
                    Ok(())
                },
            )
            .unwrap();
        let signed = signed.unwrap();
        alice.restart();
        let original = verify_action(&signed, &key.verifying_key()).unwrap();
        assert_eq!(
            outbox::pending(alice.store(), &key.verifying_key()).unwrap()[0]
                .action
                .signed_bytes(),
            signed
        );
        let retained = device
            .prepare_transition_with(
                alice.store(),
                TransitionPreparation {
                    group: id(5),
                    epoch: 1,
                    current: &both,
                    next: &both,
                    change: Change::Update,
                },
                |tx, pending| {
                    assert_eq!(prepare(tx, pending)?, signed);
                    Ok(())
                },
            )
            .unwrap();
        assert_eq!(retained.commit, pending.commit);

        // Another operation carrying identical MLS bytes cannot consume this candidate.
        let other = membership_action(
            &pending,
            &device,
            OperationId {
                window: operation.window,
                operation: id(95),
            },
        );
        let other =
            verify_action(&sign_action(&other, &key).unwrap(), &key.verifying_key()).unwrap();
        outbox::prepare(alice.store(), &other, &window, TimeBounds::test_now()).unwrap();
        let rejection = Outcome::Rejected {
            code: ErrorCode::Conflict,
            detail: "RoomRevision".into(),
        };
        let response = Response {
            home: room().home,
            operation_id: other.action().operation_id,
            action_digest: other.digest(),
            outcome: rejection.clone(),
        };
        let response = verify_response(
            &sign_response(&response, &server).unwrap(),
            &server.verifying_key(),
        )
        .unwrap();
        outbox::record(alice.store(), &other, &response, TimeBounds::test_now()).unwrap();
        assert_eq!(candidate_count(alice.store()), 1);

        let mut query = original.action().clone();
        query.operation = Operation::OperationResolve;
        query.operation_id.operation = id(96);
        query.target = Target::Service;
        query.body = Value::serialized(&crate::home::Resolve {
            operation_id: operation,
            action_digest: original.digest(),
        })
        .unwrap();
        let query =
            verify_action(&sign_action(&query, &key).unwrap(), &key.verifying_key()).unwrap();
        let response = if resolved {
            Response {
                home: room().home,
                operation_id: query.action().operation_id,
                action_digest: query.digest(),
                outcome: Outcome::Result {
                    body: Value::serialized(&crate::home::ResolveResult {
                        operation_id: operation,
                        action_digest: original.digest(),
                        outcome: rejection,
                    })
                    .unwrap(),
                },
            }
        } else {
            Response {
                home: room().home,
                operation_id: operation,
                action_digest: original.digest(),
                outcome: rejection,
            }
        };
        let response = verify_response(
            &sign_response(&response, &server).unwrap(),
            &server.verifying_key(),
        )
        .unwrap();
        let record = |store: &mut Store| {
            if resolved {
                outbox::record_resolution(
                    store,
                    &original,
                    &query,
                    &response,
                    TimeBounds::test_now(),
                )
                .unwrap();
            } else {
                outbox::record(store, &original, &response, TimeBounds::test_now()).unwrap();
            }
        };
        record(alice.store());
        alice.restart();
        assert_eq!(candidate_count(alice.store()), 0);
        assert!(
            outbox::pending(alice.store(), &key.verifying_key())
                .unwrap()
                .is_empty()
        );
        assert_eq!(device.state(alice.store(), id(5)).unwrap().epoch, 1);
        // MLS also discarded its pending commit, so a new explicit transition works.
        device
            .prepare_transition(alice.store(), id(5), 1, &both, &both, Change::Update)
            .unwrap();
        record(alice.store());
        assert_eq!(candidate_count(alice.store()), 1);
    }
}

#[test]
fn legacy_pending_transition_migrates_without_replacing_its_commit() {
    let (mut alice, _bob, both) = pair();
    let device = alice.device.clone();
    let pending = device
        .prepare_transition(alice.store(), id(5), 1, &both, &both, Change::Update)
        .unwrap();
    alice.store().write(|tx| {
        tx.execute_batch("ALTER TABLE crypto_pending DROP COLUMN operation; DROP TABLE crypto_schema; CREATE TABLE crypto_schema(version INTEGER NOT NULL CHECK(version=2)); INSERT INTO crypto_schema VALUES(2);")?;
        Ok(crate::storage::Commit::new((), b"legacy schema 2 candidate".to_vec()))
    }).unwrap();
    alice.restart();
    let saved: (Vec<u8>, Option<Vec<u8>>) = alice
        .store()
        .read(Duration::from_secs(1), |db| {
            db.query_row(
                "SELECT commit_bytes,operation FROM crypto_pending WHERE group_id=?1",
                [id(5).as_bytes().as_slice()],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
        })
        .unwrap();
    assert_eq!(saved.0, pending.commit);
    assert!(saved.1.is_none());
    let before = alice.store().usage().unwrap().commit_counter;
    initialize(alice.store()).unwrap();
    assert_eq!(alice.store().usage().unwrap().commit_counter, before);
    let rebound = device
        .prepare_transition_with(
            alice.store(),
            TransitionPreparation {
                group: id(5),
                epoch: 1,
                current: &both,
                next: &both,
                change: Change::Update,
            },
            |tx, pending| {
                bind_transition_in(
                    tx,
                    pending,
                    OperationId {
                        window: id(97),
                        operation: id(98),
                    },
                    id(99),
                )
            },
        )
        .unwrap();
    assert_eq!(rebound.commit, pending.commit);
}

#[test]
fn sender_ratchet_exact_outbox_and_bot_plan_share_one_commit() {
    let (mut alice, mut bob, both) = pair();
    outbox::initialize(alice.store()).unwrap();
    alice
        .store()
        .write(|tx| {
            tx.execute_batch("CREATE TABLE bot_plan(operation BLOB PRIMARY KEY)")?;
            Ok(crate::storage::Commit::new((), b"fixture".to_vec()))
        })
        .unwrap();
    let mut context = alice.context(24, 1);
    context.approval = Some(id(54));
    let a = alice.device.clone();
    let key = SigningKey::from_bytes(&[91; 32]);
    let window = RetryWindow {
        id: context.operation_id.window,
        expires_ms: TimeBounds::test_now().upper_ms + 60_000,
    };
    let prepare = |tx: &rusqlite::Transaction<'_>, action: Action| -> Result<Vec<u8>> {
        let bytes = sign_action(&action, &key)?;
        let verified = verify_action(&bytes, &key.verifying_key())?;
        outbox::prepare_candidate_transaction(tx, &verified, &window, TimeBounds::test_now())?;
        tx.execute(
            "INSERT INTO bot_plan VALUES(?1)",
            [context.operation_id.operation.as_bytes()],
        )?;
        Ok(bytes)
    };
    assert!(
        a.prepare_message(
            alice.store(),
            &context,
            &both,
            "atomic reply",
            |tx, action| {
                prepare(tx, action)?;
                Err(Error::Conflict)
            }
        )
        .is_err()
    );
    assert!(
        outbox::pending(alice.store(), &key.verifying_key())
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        alice
            .store()
            .read(Duration::from_secs(1), |db| db.query_row(
                "SELECT count(*) FROM bot_plan",
                [],
                |r| r.get::<_, u32>(0)
            ))
            .unwrap(),
        0
    );
    let message = a
        .prepare_message(alice.store(), &context, &both, "atomic reply", prepare)
        .unwrap();
    alice.restart();
    assert_eq!(
        outbox::pending(alice.store(), &key.verifying_key()).unwrap()[0]
            .action
            .signed_bytes(),
        message.signed_action
    );
    assert!(outbox::pending(alice.store(), &key.verifying_key()).unwrap()[0].held);
    let retry = a
        .prepare_message(alice.store(), &context, &both, "atomic reply", |_, _| {
            panic!("an exact persisted retry cannot prepare a second effect")
        })
        .unwrap();
    assert_eq!(retry, message);
    let signed = verify_action(&message.signed_action, &key.verifying_key()).unwrap();
    outbox::abandon(alice.store(), signed.action().operation_id, signed.digest()).unwrap();
    let home = SigningKey::from_bytes(&[92; 32]);
    let response = crate::protocol::Response {
        home: room().home,
        operation_id: context.operation_id,
        action_digest: signed.digest(),
        outcome: crate::protocol::Outcome::Committed {
            event: Some(id(89)),
            position: 2,
            body: crate::protocol::Value::Null,
        },
    };
    let response = crate::protocol::verify_response(
        &crate::protocol::sign_response(&response, &home).unwrap(),
        &home.verifying_key(),
    )
    .unwrap();
    outbox::record(alice.store(), &signed, &response, TimeBounds::test_now()).unwrap();
    assert!(
        outbox::pending(alice.store(), &key.verifying_key())
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        alice
            .store()
            .read(Duration::from_secs(1), |db| db.query_row(
                "SELECT state FROM crypto_outbox",
                [],
                |r| r.get::<_, String>(0)
            ))
            .unwrap(),
        "committed"
    );
    assert_eq!(
        bob.receive(&message, 1, 2, &both),
        DeliveryOutcome::Message("atomic reply".into())
    );
}

#[test]
fn creation_transition_and_welcome_callbacks_roll_back_membership_and_package_use() {
    let mut alice = Client::new(10);
    let mut bob = Client::new(11);
    let a = alice.device.clone();
    let b = bob.device.clone();
    let first = roster(&[&alice]);
    let both = roster(&[&alice, &bob]);
    assert!(
        a.create_group_with(alice.store(), id(5), &first, 0, |_, _| Err(Error::Conflict))
            .is_err()
    );
    alice.restart();
    assert!(a.state(alice.store(), id(5)).is_err());
    a.create_group(alice.store(), id(5), &first, 0).unwrap();
    let package = b.publish_key_package(bob.store(), room()).unwrap();
    let pending = a
        .prepare_transition(
            alice.store(),
            id(5),
            0,
            &first,
            &both,
            Change::Add(&[package]),
        )
        .unwrap();
    let order = TransitionOrder {
        group: id(5),
        epoch: 0,
        previous_sequence: 0,
        sequence: 1,
    };
    assert!(
        a.accept_transition_with(alice.store(), order, &pending.commit, &both, |_, _| Err(
            Error::Conflict
        ))
        .is_err()
    );
    alice.restart();
    assert_eq!(a.state(alice.store(), id(5)).unwrap().epoch, 0);
    let receipt = a
        .accept_transition(alice.store(), order, &pending.commit, &both)
        .unwrap();
    let join = WelcomeJoin {
        group: id(5),
        epoch: 1,
        cursor: 1,
        welcome: receipt.welcome.as_ref().unwrap(),
        roster: &both,
    };
    assert!(
        b.join_with(bob.store(), join, |_, _| Err(Error::Conflict))
            .is_err()
    );
    bob.restart();
    assert!(b.state(bob.store(), id(5)).is_err());
    b.join(
        bob.store(),
        id(5),
        1,
        1,
        receipt.welcome.as_ref().unwrap(),
        &both,
    )
    .unwrap();
    assert_eq!(b.state(bob.store(), id(5)).unwrap().epoch, 1);
}

#[test]
fn invalid_crypto_rejection_archive_and_cursor_are_atomic() {
    let (mut alice, mut bob, both) = pair();
    let b = bob.device.clone();
    bob.store()
        .write(|tx| {
            tx.execute_batch("CREATE TABLE archived(result BLOB NOT NULL)")?;
            Ok(crate::storage::Commit::new((), b"fixture".to_vec()))
        })
        .unwrap();
    let good = alice.send(25, 1, &both, "recovered plaintext");
    let mut bad = good.clone();
    *bad.ciphertext.last_mut().unwrap() ^= 1;
    assert!(
        b.receive_with(
            bob.store(),
            &incoming(&bad),
            &delivery(1, 2),
            &both,
            |tx, outcome| {
                assert_eq!(
                    outcome,
                    &DeliveryOutcome::Rejected(Rejection::InvalidCryptography)
                );
                tx.execute("INSERT INTO archived VALUES(?1)", [encode(outcome)?])?;
                Err(Error::Conflict)
            }
        )
        .is_err()
    );
    bob.restart();
    assert_eq!(b.state(bob.store(), id(5)).unwrap().cursor, 1);
    let rejected = b
        .receive_with(
            bob.store(),
            &incoming(&bad),
            &delivery(1, 2),
            &both,
            |tx, outcome| {
                tx.execute("INSERT INTO archived VALUES(?1)", [encode(outcome)?])?;
                Ok(())
            },
        )
        .unwrap();
    assert_eq!(
        rejected,
        DeliveryOutcome::Rejected(Rejection::InvalidCryptography)
    );
    assert_eq!(
        bob.store()
            .read(Duration::from_secs(1), |db| db.query_row(
                "SELECT count(*) FROM archived",
                [],
                |r| r.get::<_, u32>(0)
            ))
            .unwrap(),
        1
    );
    bob.restart();
    assert_eq!(
        bob.receive(&good, 2, 3, &both),
        DeliveryOutcome::Message("recovered plaintext".into())
    );
}

#[test]
fn typed_plaintext_preserves_mentions_and_binds_causation() {
    let (mut alice, mut bob, both) = pair();
    let a = alice.device.clone();
    let mut context = alice.context(26, 1);
    context.causation = Some(id(40));
    let plaintext = ApplicationMessage {
        text: "@林 e\u{301} 👩‍🚀".into(),
        mentions: vec![crate::messaging::Mention {
            account: bob.device.actor.account,
            start: 0,
            end: 4,
        }],
    };
    let message = a
        .prepare_message(
            alice.store(),
            &context,
            &both,
            plaintext.clone(),
            |_, action| Ok(sign_action(&action, &SigningKey::from_bytes(&[91; 32]))?),
        )
        .unwrap();
    let mut wrong = message.clone();
    wrong.context.causation = Some(id(41));
    assert_eq!(
        bob.receive(&wrong, 1, 2, &both),
        DeliveryOutcome::Rejected(Rejection::InvalidCryptography)
    );
    assert_eq!(
        bob.receive(&message, 2, 3, &both),
        DeliveryOutcome::Message(plaintext)
    );
    assert!(
        ApplicationMessage {
            text: "e\u{301}".into(),
            mentions: vec![crate::messaging::Mention {
                account: bob.device.actor.account,
                start: 0,
                end: 1
            }]
        }
        .bytes()
        .is_err()
    );
}
