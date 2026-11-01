// SPDX-License-Identifier: Apache-2.0
//! Real guarded identity transactions exercise proof, recovery and original-outcome boundaries.
use super::*;
use crate::{home::DeviceTransport, identity::continuity};
fn snapshot(home: &mut Home, account: AccountId) -> IdentitySnapshot {
    home.store
        .read(Duration::from_secs(1), |db| {
            continuity::snapshot(db, service(), account)
        })
        .unwrap()
}
fn device_request(
    account: AccountId,
    n: u8,
    purpose: DevicePurpose,
    replacement: Option<&SigningKey>,
) -> (SigningKey, Verified<DeviceRequest>, DeviceTransport) {
    let key = SigningKey::from_bytes(&[n; 32]);
    let request_id = Id::random().unwrap();
    let now = TimeBounds::test_now();
    let replacement = replacement.map(|key| {
        Blob(
            sign_replacement_key(
                &ReplacementKeyProof {
                    home: service(),
                    account,
                    request: request_id,
                    key: Id::from_bytes(key.verifying_key().to_bytes()),
                },
                key,
            )
            .unwrap(),
        )
    });
    let value = DeviceRequest {
        home: service(),
        account,
        request: request_id,
        endpoint: id(n + 1),
        endpoint_key: Id::from_bytes(key.verifying_key().to_bytes()),
        principal: id(n + 2),
        purpose,
        created_ms: now.lower_ms.saturating_sub(1000),
        expires_ms: now.upper_ms + 120000,
        replacement,
    };
    let verified = verify_new_device(&sign_device_request(&value, &key).unwrap()).unwrap();
    (
        key,
        verified,
        DeviceTransport {
            principal: id(n + 2),
            session: id(n + 3),
            generation: 1,
            service_boot: id(240),
        },
    )
}
fn proofs(
    request: &Verified<DeviceRequest>,
    challenge: &Verified<DeviceChallenge>,
    key: &SigningKey,
    recovery: Option<&SigningKey>,
) -> DeviceProofs {
    let proof = DeviceProof {
        home: service(),
        account: request.value().account,
        request: request.value().request,
        request_digest: request.digest(),
        challenge_digest: challenge.digest(),
    };
    DeviceProofs {
        endpoint: Blob(sign_device_proof(&proof, key).unwrap()),
        recovery: recovery.map(|key| Blob(sign_device_proof(&proof, key).unwrap())),
    }
}
fn admit(home: &mut Home, controller: &Party, request: &Verified<DeviceRequest>) -> Action {
    let state = snapshot(home, request.value().account);
    let action = action(
        controller,
        Operation::AccountEnrolEndpoint,
        Target::Account(state.account),
        &identity::ApproveEndpoint {
            request: Blob(request.signed_bytes().to_vec()),
            revision: state.revision,
            head: state.head.unwrap(),
        },
    );
    assert!(matches!(
        run(home, controller, &action),
        Outcome::Committed { .. }
    ));
    action
}
fn party(home: &mut Home, request: &Verified<DeviceRequest>, key: SigningKey) -> Party {
    let r = request.value();
    let record = home.endpoint(r.account, r.endpoint).unwrap().unwrap();
    let session = AuthenticatedSession::new(&record, r.principal, id(235), 1).unwrap();
    let window = home
        .open_window(&record, TimeBounds::test_now(), &|| true)
        .unwrap();
    Party {
        key,
        record,
        session,
        window,
    }
}

#[test]
fn endpoint_ticket_requires_fresh_new_key_proof_and_survives_lost_receipt() {
    let fixture = Fixture::new();
    let mut home = fixture.create();
    let owner = enrol(&mut home, 10, AccountClass::Human);
    let account = owner.record.acting.account;
    let (key, request, transport) = device_request(account, 40, DevicePurpose::Enrol, None);
    assert!(
        home.device_challenge(&request, transport, TimeBounds::test_now())
            .is_err()
    );
    admit(&mut home, &owner, &request);
    assert!(
        home.endpoint(account, request.value().endpoint)
            .unwrap()
            .is_none()
    );
    assert!(
        home.device_challenge(
            &request,
            DeviceTransport {
                principal: id(199),
                ..transport
            },
            TimeBounds::test_now()
        )
        .is_err()
    );
    let challenge = home
        .device_challenge(&request, transport, TimeBounds::test_now())
        .unwrap();
    let wrong = proofs(
        &request,
        &challenge,
        &SigningKey::from_bytes(&[99; 32]),
        None,
    );
    let before = home.usage().unwrap().commit_counter;
    let denied = home
        .activate_device(
            &request,
            &challenge,
            &wrong,
            transport,
            TimeBounds::test_now(),
            &|| true,
        )
        .unwrap();
    assert!(matches!(
        denied.outcome,
        Outcome::Refused {
            code: ErrorCode::Denied,
            ..
        }
    ));
    assert_eq!(home.usage().unwrap().commit_counter, before);
    let valid = proofs(&request, &challenge, &key, None);
    let checks = Cell::new(0);
    let denied = home
        .activate_device(
            &request,
            &challenge,
            &valid,
            transport,
            TimeBounds::test_now(),
            &|| {
                checks.set(checks.get() + 1);
                checks.get() == 1
            },
        )
        .unwrap();
    assert!(matches!(
        denied.outcome,
        Outcome::Refused {
            code: ErrorCode::Unavailable,
            ..
        }
    ));
    assert!(
        home.endpoint(account, request.value().endpoint)
            .unwrap()
            .is_none()
    );
    let challenge = home
        .device_challenge(&request, transport, TimeBounds::test_now())
        .unwrap();
    let valid = proofs(&request, &challenge, &key, None);
    let first = home
        .activate_device(
            &request,
            &challenge,
            &valid,
            transport,
            TimeBounds::test_now(),
            &|| true,
        )
        .unwrap();
    assert!(matches!(first.outcome, Outcome::Committed { .. }));
    assert!(matches!(
        home.activate_device(
            &request,
            &challenge,
            &valid,
            transport,
            TimeBounds::test_now(),
            &|| true
        )
        .unwrap()
        .outcome,
        Outcome::Refused { .. }
    ));
    let head = snapshot(&mut home, account).head;
    drop(home);
    let mut home = fixture.open();
    let challenge = home
        .device_challenge(&request, transport, TimeBounds::test_now())
        .unwrap();
    assert!(challenge.value().recorded);
    let repeated = home
        .activate_device(
            &request,
            &challenge,
            &proofs(&request, &challenge, &key, None),
            transport,
            TimeBounds::test_now(),
            &|| true,
        )
        .unwrap();
    assert_eq!(encode(&first).unwrap(), encode(&repeated).unwrap());
    assert_eq!(snapshot(&mut home, account).head, head);
    let second = party(&mut home, &request, key);
    let state = snapshot(&mut home, account);
    let disable = action(
        &owner,
        Operation::AccountDisableEndpoint,
        Target::Account(account),
        &identity::DisableEndpoint {
            endpoint: owner.record.acting.endpoint,
            revision: state.revision,
            head: state.head.unwrap(),
        },
    );
    let outcome = run(&mut home, &owner, &disable);
    assert!(matches!(outcome, Outcome::Committed { .. }));
    assert!(matches!(
        run(
            &mut home,
            &owner,
            &action(
                &owner,
                Operation::AccountInspect,
                Target::Account(account),
                &Empty {}
            )
        ),
        Outcome::Refused {
            code: ErrorCode::Denied,
            ..
        }
    ));
    let resolve = action(
        &second,
        Operation::AccountLifecycleOutcome,
        Target::Account(account),
        &Resolve {
            operation_id: disable.operation_id,
            action_digest: action_digest(&disable).unwrap(),
        },
    );
    let Outcome::Result { body } = run(&mut home, &second, &resolve) else {
        panic!("resolution")
    };
    let saved: ResolveResult = body.deserialized().unwrap();
    assert_eq!(encode(&saved.outcome).unwrap(), encode(&outcome).unwrap());
    let state = snapshot(&mut home, account);
    assert!(!state.legacy_anchor);
    assert_eq!(state.endpoints.len(), 1);
    let records: Vec<ContinuityRecord> = home
        .store
        .read(Duration::from_secs(1), |db| {
            db.prepare("SELECT record FROM identity_records WHERE account=?1 ORDER BY number")?
                .query_map([account.to_string()], |r| decode(&r.get::<_, Vec<u8>>(0)?))?
                .collect()
        })
        .unwrap();
    assert_eq!(records.len(), 3);
    assert_eq!(records[0].change, IdentityChange::Registered);
    assert!(verify_registration_request(&records[0].authorizations[0].0).is_ok());
    for pair in records.windows(2) {
        assert_eq!(pair[1].previous, Some(digest(&encode(&pair[0]).unwrap())))
    }
}

#[test]
fn owner_recovery_atomically_fences_devices_grants_approvals_and_encrypted_roster() {
    let fixture = Fixture::new();
    let mut home = fixture.create();
    let owner = enrol(&mut home, 10, AccountClass::Human);
    let account = owner.record.acting.account;
    let agent = enrol(&mut home, 30, AccountClass::Agent { operator: account });
    let room = room(&mut home, &owner, "recovery");
    let grant = grant(&mut home, &owner, &agent, room, delegation::Mode::Approve);
    let mut queued = delegated(
        send(&agent, room, "old-generation candidate"),
        &owner,
        grant,
    );
    queued.approval = Some(id(180));
    let prepare = action(
        &agent,
        Operation::ApprovalPrepare,
        Target::Delegation(grant),
        &delegation::Prepare {
            candidate: Blob(sign_action(&queued, &agent.key).unwrap()),
            expires_ms: TimeBounds::test_now().upper_ms + 30000,
        },
    );
    assert!(matches!(
        run(&mut home, &agent, &prepare),
        Outcome::Committed { .. }
    ));
    home.store.write(|db|{db.execute("INSERT INTO hrc_encrypted_rooms(room,barrier) VALUES(?1,0)",[room.to_string()])?;db.execute("INSERT INTO hrc_encrypted_roster(room,endpoint,account,represented,actor,credential) VALUES(?1,?2,?3,?3,?4,?4)",params![room.to_string(),owner.record.acting.endpoint.as_hex(),account.to_string(),encode(&owner.record.acting)?])?;Ok(Commit::new((),b"identity barrier fixture".to_vec()))}).unwrap();
    let old_security = snapshot(&mut home, account).security_generation;
    let (key, request, transport) = device_request(account, 60, DevicePurpose::Recover, None);
    let challenge = home
        .device_challenge(&request, transport, TimeBounds::test_now())
        .unwrap();
    let admin = proofs(&request, &challenge, &key, Some(home.signing_key()));
    let denied = home
        .activate_device(
            &request,
            &challenge,
            &admin,
            transport,
            TimeBounds::test_now(),
            &|| true,
        )
        .unwrap();
    assert!(matches!(
        denied.outcome,
        Outcome::Refused {
            code: ErrorCode::Denied,
            ..
        }
    ));
    assert_eq!(
        snapshot(&mut home, account).security_generation,
        old_security
    );
    let recovery = SigningKey::from_bytes(&[110; 32]);
    let proof = proofs(&request, &challenge, &key, Some(&recovery));
    let checks = Cell::new(0);
    let refused = home
        .activate_device(
            &request,
            &challenge,
            &proof,
            transport,
            TimeBounds::test_now(),
            &|| {
                checks.set(checks.get() + 1);
                checks.get() == 1
            },
        )
        .unwrap();
    assert!(matches!(refused.outcome, Outcome::Refused { .. }));
    assert_eq!(
        snapshot(&mut home, account).security_generation,
        old_security
    );
    let unchanged: (u8, u8, u8) = home
        .store
        .read(Duration::from_secs(1), |db| {
            Ok((
                db.query_row(
                    "SELECT state FROM hrc_grants WHERE id=?1",
                    [grant.id.as_hex()],
                    |r| r.get(0),
                )?,
                db.query_row(
                    "SELECT state FROM hrc_approvals WHERE id=?1",
                    [id(180).as_hex()],
                    |r| r.get(0),
                )?,
                db.query_row(
                    "SELECT barrier FROM hrc_encrypted_rooms WHERE room=?1",
                    [room.to_string()],
                    |r| r.get(0),
                )?,
            ))
        })
        .unwrap();
    assert_eq!(unchanged, (0, 0, 0));
    let challenge = home
        .device_challenge(&request, transport, TimeBounds::test_now())
        .unwrap();
    let receipt = home
        .activate_device(
            &request,
            &challenge,
            &proofs(&request, &challenge, &key, Some(&recovery)),
            transport,
            TimeBounds::test_now(),
            &|| true,
        )
        .unwrap();
    assert!(matches!(receipt.outcome, Outcome::Committed { .. }));
    assert!(
        home.endpoint(account, owner.record.acting.endpoint)
            .unwrap()
            .is_none()
    );
    assert_eq!(
        snapshot(&mut home, account).security_generation,
        old_security + 1
    );
    assert!(matches!(
        run(&mut home, &agent, &queued),
        Outcome::Refused {
            code: ErrorCode::Denied,
            ..
        }
    ));
    drop(home);
    let mut home = fixture.open();
    let changed: (u8, u8, u8) = home
        .store
        .read(Duration::from_secs(1), |db| {
            Ok((
                db.query_row(
                    "SELECT state FROM hrc_grants WHERE id=?1",
                    [grant.id.as_hex()],
                    |r| r.get(0),
                )?,
                db.query_row(
                    "SELECT state FROM hrc_approvals WHERE id=?1",
                    [id(180).as_hex()],
                    |r| r.get(0),
                )?,
                db.query_row(
                    "SELECT barrier FROM hrc_encrypted_rooms WHERE room=?1",
                    [room.to_string()],
                    |r| r.get(0),
                )?,
            ))
        })
        .unwrap();
    assert_eq!(changed, (1, 2, 1));
    let replacement = party(&mut home, &request, key);
    assert_eq!(replacement.record.acting.account, account);
    assert_eq!(
        replacement.record.acting.security_generation,
        old_security + 1
    );
}

#[test]
fn owner_key_rotation_requires_both_keys_and_preserves_surviving_devices() {
    let fixture = Fixture::new();
    let mut home = fixture.create();
    let owner = enrol(&mut home, 10, AccountClass::Human);
    let account = owner.record.acting.account;
    let controller_key = SigningKey::from_bytes(&[140; 32]);
    let state = snapshot(&mut home, account);
    let replacement = ReplacementKeyProof {
        home: service(),
        account,
        request: id(210),
        key: Id::from_bytes(controller_key.verifying_key().to_bytes()),
    };
    let wrong = action(
        &owner,
        Operation::AccountRotateRecovery,
        Target::Account(account),
        &identity::RotateRecovery {
            replacement: Blob(sign_replacement_key(&replacement, &owner.key).unwrap()),
            revision: state.revision,
            head: state.head.unwrap(),
        },
    );
    assert!(matches!(
        run(&mut home, &owner, &wrong),
        Outcome::Rejected { .. }
    ));
    assert_eq!(snapshot(&mut home, account).recovery_generation, 1);
    let rotate = action(
        &owner,
        Operation::AccountRotateRecovery,
        Target::Account(account),
        &identity::RotateRecovery {
            replacement: Blob(sign_replacement_key(&replacement, &controller_key).unwrap()),
            revision: state.revision,
            head: state.head.unwrap(),
        },
    );
    assert!(matches!(
        run(&mut home, &owner, &rotate),
        Outcome::Committed { .. }
    ));
    let new = SigningKey::from_bytes(&[150; 32]);
    let (key, request, transport) =
        device_request(account, 70, DevicePurpose::RotateRecovery, Some(&new));
    let mut misbound = request.value().clone();
    misbound.request = id(222);
    assert!(sign_device_request(&misbound, &key).is_err());
    misbound = request.value().clone();
    misbound.account.local = id(223);
    assert!(sign_device_request(&misbound, &key).is_err());
    let challenge = home
        .device_challenge(&request, transport, TimeBounds::test_now())
        .unwrap();
    let old = controller_key;
    let receipt = home
        .activate_device(
            &request,
            &challenge,
            &proofs(&request, &challenge, &key, Some(&old)),
            transport,
            TimeBounds::test_now(),
            &|| true,
        )
        .unwrap();
    assert!(matches!(receipt.outcome, Outcome::Committed { .. }));
    let current = snapshot(&mut home, account);
    assert_eq!(
        current.recovery_key,
        Id::from_bytes(new.verifying_key().to_bytes())
    );
    assert_eq!(current.recovery_generation, 3);
    assert_eq!(current.security_generation, 1);
    assert_eq!(current.endpoints.len(), 1);
    assert!(
        home.endpoint(account, owner.record.acting.endpoint)
            .unwrap()
            .is_some()
    );
    let (next_key, next, transport) = device_request(account, 80, DevicePurpose::Recover, None);
    let challenge = home
        .device_challenge(&next, transport, TimeBounds::test_now())
        .unwrap();
    assert!(matches!(
        home.activate_device(
            &next,
            &challenge,
            &proofs(&next, &challenge, &next_key, Some(&old)),
            transport,
            TimeBounds::test_now(),
            &|| true
        )
        .unwrap()
        .outcome,
        Outcome::Refused {
            code: ErrorCode::Denied,
            ..
        }
    ));
    let wrong_boot = DeviceTransport {
        service_boot: id(239),
        ..transport
    };
    assert!(matches!(
        home.activate_device(
            &next,
            &challenge,
            &proofs(&next, &challenge, &next_key, Some(&new)),
            wrong_boot,
            TimeBounds::test_now(),
            &|| true
        )
        .unwrap()
        .outcome,
        Outcome::Refused {
            code: ErrorCode::Denied,
            ..
        }
    ));
    assert!(matches!(
        home.activate_device(
            &next,
            &challenge,
            &proofs(&next, &challenge, &next_key, Some(&new)),
            transport,
            TimeBounds::test_now(),
            &|| true
        )
        .unwrap()
        .outcome,
        Outcome::Committed { .. }
    ));
}

#[test]
fn old_stores_receive_only_an_explicit_legacy_anchor_and_unknown_schema_is_refused() {
    let fixture = Fixture::new();
    let mut home = fixture.create();
    let owner = enrol(&mut home, 10, AccountClass::Human);
    let account = owner.record.acting.account;
    home.store.write(|db|{db.execute_batch("DROP TABLE identity_receipts;DROP TABLE identity_tickets;DROP TABLE identity_records;DROP TABLE identity_accounts;DROP TABLE identity_schema;")?;Ok(Commit::new((),b"prior identity schema fixture".to_vec()))}).unwrap();
    drop(home);
    let mut home = fixture.open();
    let state = snapshot(&mut home, account);
    assert!(state.legacy_anchor);
    let record: ContinuityRecord = home
        .store
        .read(Duration::from_secs(1), |db| {
            db.query_row(
                "SELECT record FROM identity_records WHERE account=?1 AND number=1",
                [account.to_string()],
                |r| decode(&r.get::<_, Vec<u8>>(0)?),
            )
        })
        .unwrap();
    assert_eq!(record.change, IdentityChange::LegacyServiceAnchor);
    assert!(record.authorizations.is_empty());
    home.store
        .write(|db| {
            db.execute("UPDATE identity_schema SET version=99", [])?;
            Ok(Commit::new((), b"unknown identity schema fixture".to_vec()))
        })
        .unwrap();
    drop(home);
    let store = Store::open(
        fixture.root.join("Data"),
        fixture.root.join("Guard"),
        &fixture.key,
        *service().service.as_bytes(),
        storage::Limits::default(),
    )
    .unwrap();
    assert!(Home::open(store, service(), SigningKey::from_bytes(&[4; 32])).is_err());
}
