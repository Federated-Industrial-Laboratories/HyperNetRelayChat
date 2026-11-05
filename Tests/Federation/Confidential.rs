// SPDX-License-Identifier: Apache-2.0
//! Foreign admission participates in the real MLS roster and local-send barrier.
use super::*;
use crate::{confidential as c, crypto};
fn committed(outcome: Outcome) -> Option<Id> {
    match outcome {
        Outcome::Committed { event, .. } => event,
        other => panic!("expected committed: {other:?}"),
    }
}
fn inspect(p: &mut Pair) -> c::Inspection {
    let a = action(
        &p.local,
        Operation::CryptoInspect,
        Target::Room(p.room),
        &Empty {},
    );
    match run(&mut p.home, &p.local, &a) {
        Outcome::Result { body } => body.deserialized().unwrap(),
        other => panic!("inspection: {other:?}"),
    }
}
fn ready(p: &mut Pair, state: &c::Inspection, welcome: Option<Vec<u8>>) {
    p.renew_freshness();
    let a = action(
        &p.local,
        Operation::CryptoEpochReady,
        Target::Room(p.room),
        &c::Ready {
            group: state.group.unwrap(),
            epoch: state.epoch,
            commit_digest: state.commit_digest.unwrap(),
            sequence: state.sequence,
            welcome: welcome.map(Blob),
        },
    );
    committed(run(&mut p.home, &p.local, &a));
}
#[test]
fn foreign_leaf_decrypts_and_withdrawal_blocks_local_ciphertext_until_removal() {
    foreign_leaf_barrier(false);
}

#[test]
fn origin_recovery_fences_old_foreign_endpoint_and_local_mls_publication() {
    foreign_leaf_barrier(true);
}

fn recover_origin(p: &mut Pair, remote: &RemoteParty) {
    let key = SigningKey::from_bytes(&[120; 32]);
    let t = TimeBounds::test_now();
    let request = DeviceRequest {
        home: p.origin.service_id(),
        account: remote.record.acting.account,
        request: Id::random().unwrap(),
        endpoint: id(121),
        endpoint_key: Id::from_bytes(key.verifying_key().to_bytes()),
        principal: id(122),
        purpose: DevicePurpose::Recover,
        created_ms: t.lower_ms,
        expires_ms: t.lower_ms + 120_000,
        replacement: None,
    };
    let request = verify_new_device(&sign_device_request(&request, &key).unwrap()).unwrap();
    let transport = crate::home::DeviceTransport {
        principal: id(122),
        session: id(123),
        generation: 1,
        service_boot: id(124),
    };
    let challenge = p
        .origin
        .device_challenge(&request, transport, TimeBounds::test_now())
        .unwrap();
    let proof = DeviceProof {
        home: p.origin.service_id(),
        account: remote.record.acting.account,
        request: request.value().request,
        request_digest: request.digest(),
        challenge_digest: challenge.digest(),
    };
    let recovery = SigningKey::from_bytes(&[112; 32]);
    let proofs = DeviceProofs {
        endpoint: Blob(sign_device_proof(&proof, &key).unwrap()),
        recovery: Some(Blob(sign_device_proof(&proof, &recovery).unwrap())),
    };
    assert!(matches!(
        p.origin
            .activate_device(
                &request,
                &challenge,
                &proofs,
                transport,
                TimeBounds::test_now(),
                &|| true
            )
            .unwrap()
            .outcome,
        Outcome::Committed { .. }
    ));
    let checkpoint = p
        .origin
        .federation_checkpoint(
            remote.record.acting.account,
            p.agreement.reference,
            TimeBounds::test_now(),
        )
        .unwrap();
    let cp =
        verify_origin_identity_checkpoint(&checkpoint.0, &p.origin.signing_key().verifying_key())
            .unwrap();
    assert_eq!(
        cp.value().state.security_generation,
        remote.record.acting.security_generation + 1
    );
    let mut after = 0;
    loop {
        let page = p
            .origin
            .federation_identity_page(
                p.agreement.reference,
                cp.digest(),
                after,
                4,
                TimeBounds::test_now(),
            )
            .unwrap();
        let next = verify_origin_identity_page(&page.0, &p.origin.signing_key().verifying_key())
            .unwrap()
            .value()
            .next;
        if p.home
            .federation_update_identity(
                &p.gateway,
                &fed::IdentityImport {
                    checkpoint: checkpoint.clone(),
                    page,
                    trust_anchor: None,
                },
                TimeBounds::test_now(),
                &|| true,
            )
            .unwrap()
        {
            break;
        }
        after = next;
    }
}

fn foreign_leaf_barrier(recovery: bool) {
    let mut p = Pair::with_mode(RoomConfidentiality::PrivateGroup);
    let mut remote = p.remote.clone();
    let admitted = p.admit(&remote);
    p.bootstrap(&mut remote, admitted.reference);
    let invite = action(
        &p.local,
        Operation::RoomInvite,
        Target::Room(p.room),
        &c::Invite {
            account: remote.record.acting.account,
        },
    );
    committed(run(&mut p.home, &p.local, &invite));
    let join = p.action(
        &remote,
        Operation::RoomJoin,
        Target::Room(p.room),
        &Empty {},
    );
    let env = p.envelope(&remote, admitted.reference, &join);
    committed(p.run(&env).outcome);
    let af = Fixture::new();
    let bf = Fixture::new();
    let mut ast = af.create().store;
    let mut bst = bf.create().store;
    let a = crypto::Device::provision(&mut ast, p.local.record.acting.clone()).unwrap();
    let b = crypto::Device::provision(&mut bst, remote.record.acting.clone()).unwrap();
    let enrol = action(
        &p.local,
        Operation::CryptoEnrolEndpoint,
        Target::Account(p.local.record.acting.account),
        &c::EnrolKey { mls_key: a.mls_key },
    );
    committed(run(&mut p.home, &p.local, &enrol));
    let enrol = p.action(
        &remote,
        Operation::CryptoEnrolEndpoint,
        Target::Account(remote.record.acting.account),
        &c::EnrolKey { mls_key: b.mls_key },
    );
    let env = p.envelope(&remote, admitted.reference, &enrol);
    committed(p.run(&env).outcome);
    let group = Id::random().unwrap();
    let initial = crypto::ApprovedRoster::new(p.room, vec![a.credential(p.room)]).unwrap();
    let info = a.create_group(&mut ast, group, &initial, 0).unwrap();
    let init = action(
        &p.local,
        Operation::CryptoPropose,
        Target::Room(p.room),
        &c::Initialise {
            group,
            group_info: Blob(info),
        },
    );
    committed(run(&mut p.home, &p.local, &init));
    let state = inspect(&mut p);
    ready(&mut p, &state, None);
    let package = b.publish_key_package(&mut bst, p.room).unwrap();
    let publish = p.action(
        &remote,
        Operation::CryptoPublishKeyPackage,
        Target::Room(p.room),
        &c::PublishPackage {
            package: Blob(package.clone()),
            expires_ms: TimeBounds::test_now().lower_ms + 60_000,
        },
    );
    let env = p.envelope(&remote, admitted.reference, &publish);
    committed(p.run(&env).outcome);
    let roster =
        crypto::ApprovedRoster::new(p.room, vec![a.credential(p.room), b.credential(p.room)])
            .unwrap();
    let pending = a
        .prepare_transition(
            &mut ast,
            group,
            0,
            &initial,
            &roster,
            crypto::Change::Add(std::slice::from_ref(&package)),
        )
        .unwrap();
    p.renew_freshness();
    let commit = action(
        &p.local,
        Operation::CryptoCommit,
        Target::Room(p.room),
        &c::CommitEpoch {
            group,
            epoch: 0,
            commit: Blob(pending.commit.clone()),
            additions: vec![digest(&package)],
            removals: Vec::new(),
        },
    );
    committed(run(&mut p.home, &p.local, &commit));
    let state = inspect(&mut p);
    let receipt = a
        .accept_transition(
            &mut ast,
            crypto::TransitionOrder {
                group,
                epoch: 0,
                previous_sequence: 0,
                sequence: state.sequence,
            },
            &pending.commit,
            &roster,
        )
        .unwrap();
    let welcome = receipt.welcome.unwrap();
    ready(&mut p, &state, Some(welcome.clone()));
    b.join(&mut bst, group, 1, state.sequence, &welcome, &roster)
        .unwrap();
    let mark = p.action(
        &remote,
        Operation::CryptoEpochReady,
        Target::Room(p.room),
        &c::Ready {
            group,
            epoch: 1,
            commit_digest: state.commit_digest.unwrap(),
            sequence: state.sequence,
            welcome: None,
        },
    );
    let env = p.envelope(&remote, admitted.reference, &mark);
    committed(p.run(&env).outcome);
    let base = action(
        &p.local,
        Operation::MessageSend,
        Target::Room(p.room),
        &Empty {},
    );
    let mut context = crypto::EncryptionContext {
        home: base.home,
        room: p.room,
        operation_id: base.operation_id,
        actor: base.actor,
        operation: base.operation,
        expected: base.expected,
        approval: None,
        agreement: None,
        group,
        epoch: 1,
        parent: None,
        causation: None,
    };
    let text = "Confidential across origins: 世界 café 👩🏽‍💻";
    p.renew_freshness();
    let prepared = a
        .prepare_message(&mut ast, &context, &roster, text, |_, action| {
            sign_action(&action, &p.local.key).map_err(|_| crypto::Error::Invalid)
        })
        .unwrap();
    let signed = verify_action(&prepared.signed_action, &p.local.key.verifying_key()).unwrap();
    let event = committed(run(&mut p.home, &p.local, signed.action())).unwrap();
    let event: Event = p
        .home
        .store
        .read(Duration::from_secs(1), |db| {
            db.query_row(
                "SELECT event FROM hrc_events WHERE id=?1",
                [event.as_hex()],
                |r| decode(&r.get::<_, Vec<u8>>(0)?),
            )
        })
        .unwrap();
    let encrypted: crypto::EncryptedEvent = event.body.deserialized().unwrap();
    let incoming = crypto::IncomingMessage {
        context: &encrypted.context,
        ciphertext: &encrypted.ciphertext.0,
        action_digest: event.action_digest,
    };
    let order = crypto::HomeDelivery {
        previous_sequence: state.sequence,
        sequence: event.sequence,
        event: event.event,
        event_digest: digest(&encode(&event).unwrap()),
    };
    // Resolve the sender's exact committed candidate before preparing another effect.
    assert_eq!(
        a.receive(&mut ast, &incoming, &order, &roster).unwrap(),
        crypto::DeliveryOutcome::Message(crypto::ApplicationMessage::from(text))
    );
    let delivery = b.receive(&mut bst, &incoming, &order, &roster).unwrap();
    assert_eq!(
        delivery,
        crypto::DeliveryOutcome::Message(crypto::ApplicationMessage::from(text))
    );
    if !recovery {
        context.operation_id.operation = Id::random().unwrap();
        let candidate = a
            .prepare_message(
                &mut ast,
                &context,
                &roster,
                "same ciphertext after freshness resumes",
                |_, action| sign_action(&action, &p.local.key).map_err(|_| crypto::Error::Invalid),
            )
            .unwrap();
        let action = verify_action(&candidate.signed_action, &p.local.key.verifying_key()).unwrap();
        p.home
            .store
            .write(|db| {
                db.execute("UPDATE federation_freshness SET deadline=0", [])?;
                Ok(Commit::new(
                    (),
                    b"expire original identity observation deadline".to_vec(),
                ))
            })
            .unwrap();
        let unavailable = inspect(&mut p);
        assert!(unavailable.send_barrier && unavailable.required_removals.is_empty());
        assert!(matches!(
            run(&mut p.home, &p.local, action.action()),
            Outcome::Refused {
                code: ErrorCode::Unavailable,
                ..
            }
        ));
        let recorded: bool = p
            .home
            .store
            .read(Duration::from_secs(1), |db| {
                db.query_row(
                    "SELECT EXISTS(SELECT 1 FROM hrc_operations WHERE window=?1 AND operation=?2)",
                    params![
                        context.operation_id.window.as_hex(),
                        context.operation_id.operation.as_hex()
                    ],
                    |r| r.get(0),
                )
            })
            .unwrap();
        assert!(!recorded);
        p.renew_freshness();
        assert!(!inspect(&mut p).send_barrier);
        let received = run(&mut p.home, &p.local, action.action());
        let extra = committed(received.clone()).unwrap();
        assert_eq!(
            encode(&received).unwrap(),
            encode(&run(&mut p.home, &p.local, action.action())).unwrap()
        );
        let extra: Event = p
            .home
            .store
            .read(Duration::from_secs(1), |db| {
                db.query_row(
                    "SELECT event FROM hrc_events WHERE id=?1",
                    [extra.as_hex()],
                    |r| decode(&r.get::<_, Vec<u8>>(0)?),
                )
            })
            .unwrap();
        let encrypted: crypto::EncryptedEvent = extra.body.deserialized().unwrap();
        a.receive(
            &mut ast,
            &crypto::IncomingMessage {
                context: &encrypted.context,
                ciphertext: &encrypted.ciphertext.0,
                action_digest: extra.action_digest,
            },
            &crypto::HomeDelivery {
                previous_sequence: event.sequence,
                sequence: extra.sequence,
                event: extra.event,
                event_digest: digest(&encode(&extra).unwrap()),
            },
            &roster,
        )
        .unwrap();
    }
    if recovery {
        let queued = p.action(
            &remote,
            Operation::CryptoInspect,
            Target::Room(p.room),
            &Empty {},
        );
        let queued = p.envelope(&remote, admitted.reference, &queued);
        recover_origin(&mut p, &remote);
        assert!(
            p.home
                .federation_verify(
                    &p.gateway,
                    &queued,
                    &privacy(),
                    TimeBounds::test_now(),
                    &|| true
                )
                .is_err()
        );
        assert!(
            p.origin
                .federation_origin_subject(
                    &remote.session,
                    fed::SourceSubject::Action(queued.action),
                    p.agreement.reference,
                    TimeBounds::test_now()
                )
                .is_err()
        );
    } else {
        p.home
            .federation_withdraw_endpoint(admitted.reference, TimeBounds::test_now())
            .unwrap();
    }
    let blocked = inspect(&mut p);
    assert!(blocked.send_barrier);
    assert!(
        blocked
            .required_removals
            .contains(&remote.record.acting.endpoint)
    );
    context.operation_id.operation = Id::random().unwrap();
    let pending = a
        .prepare_message(
            &mut ast,
            &context,
            &roster,
            "must remain unpublished",
            |_, action| sign_action(&action, &p.local.key).map_err(|_| crypto::Error::Invalid),
        )
        .unwrap();
    let signed = verify_action(&pending.signed_action, &p.local.key.verifying_key()).unwrap();
    assert!(matches!(
        run(&mut p.home, &p.local, signed.action()),
        Outcome::Rejected { .. }
    ));
}
