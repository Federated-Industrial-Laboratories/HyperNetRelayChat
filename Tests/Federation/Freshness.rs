// SPDX-License-Identifier: Apache-2.0
use super::*;

#[test]
fn cached_checkpoint_is_read_only_and_renamed_identity_stays_dirty_until_acknowledged() {
    let mut p = Pair::new();
    let remote = p.remote.clone();
    let admission = p.admit(&remote);
    let before = p.origin.usage().unwrap().commit_counter;
    for _ in 0..3 {
        let bytes = p
            .origin
            .federation_checkpoint(
                remote.record.acting.account,
                p.agreement.reference,
                TimeBounds::test_now(),
            )
            .unwrap();
        assert_eq!(
            verify_origin_identity_checkpoint(&bytes.0, &p.origin.signing_key().verifying_key())
                .unwrap()
                .digest(),
            admission.checkpoint
        );
    }
    assert_eq!(p.origin.usage().unwrap().commit_counter, before);
    let window = p
        .origin
        .open_window(&remote.record, TimeBounds::test_now(), &|| true)
        .unwrap();
    let action = Action {
        home: p.origin.service_id(),
        operation_id: OperationId {
            window: window.id,
            operation: Id::random().unwrap(),
        },
        actor: Actor::Direct {
            acting: remote.record.acting.clone(),
        },
        target: Target::Account(remote.record.acting.account),
        operation: Operation::AccountSetNickname,
        body: Value::serialized(&identity::Nickname {
            nickname: "RenamedOrigin".into(),
        })
        .unwrap(),
        expected: BTreeMap::new(),
        approval: None,
        agreement: None,
    };
    let signed = verify_action(
        &sign_action(&action, &remote.key).unwrap(),
        &remote.key.verifying_key(),
    )
    .unwrap();
    assert!(matches!(
        p.origin
            .execute(&signed, &remote.session, TimeBounds::test_now(), &|| true)
            .unwrap()
            .outcome,
        Outcome::Committed { .. }
    ));
    let stale = [CheckpointRef {
        account: remote.record.acting.account,
        checkpoint_digest: admission.checkpoint,
    }];
    assert!(
        p.origin
            .federation_freshness(p.agreement.reference, &stale, TimeBounds::test_now())
            .is_err()
    );
    let checkpoint = p
        .origin
        .federation_checkpoint(
            remote.record.acting.account,
            p.agreement.reference,
            TimeBounds::test_now(),
        )
        .unwrap();
    let current =
        verify_origin_identity_checkpoint(&checkpoint.0, &p.origin.signing_key().verifying_key())
            .unwrap();
    assert_eq!(current.value().nickname, "RenamedOrigin");
    assert_ne!(current.digest(), admission.checkpoint);
    assert!(
        p.origin
            .federation_watched(
                p.agreement.reference,
                true,
                None,
                32,
                TimeBounds::test_now()
            )
            .unwrap()
            .items[0]
            .dirty
    );
    let before = p.origin.usage().unwrap().commit_counter;
    p.origin
        .federation_checkpoint(
            remote.record.acting.account,
            p.agreement.reference,
            TimeBounds::test_now(),
        )
        .unwrap();
    assert_eq!(p.origin.usage().unwrap().commit_counter, before);
    let page = p
        .origin
        .federation_identity_page(
            p.agreement.reference,
            current.digest(),
            0,
            4,
            TimeBounds::test_now(),
        )
        .unwrap();
    assert!(
        p.home
            .federation_update_identity(
                &p.gateway,
                &fed::IdentityImport {
                    checkpoint,
                    page,
                    trust_anchor: None
                },
                TimeBounds::test_now(),
                &|| true
            )
            .unwrap()
    );
    p.origin
        .federation_acknowledge_identity(
            p.agreement.reference,
            remote.record.acting.account,
            current.digest(),
            TimeBounds::test_now(),
        )
        .unwrap();
    assert!(
        p.origin
            .federation_watched(
                p.agreement.reference,
                true,
                None,
                32,
                TimeBounds::test_now()
            )
            .unwrap()
            .items
            .is_empty()
    );
    p.renew_freshness();
}

#[test]
fn freshness_has_original_deadline_current_head_final_permit_and_restart_fence() {
    let mut p = Pair::new();
    let remote = p.remote.clone();
    let admission = p.admit(&remote);
    let refs = [CheckpointRef {
        account: remote.record.acting.account,
        checkpoint_digest: admission.checkpoint,
    }];
    let lease = p
        .origin
        .federation_freshness(p.agreement.reference, &refs, TimeBounds::test_now())
        .unwrap();
    let value =
        verify_identity_freshness(&lease.0, &p.origin.signing_key().verifying_key()).unwrap();
    assert!(value.value().expires_ms - value.value().issued_ms <= 5000);
    let mut overlong = value.value().clone();
    overlong.expires_ms = overlong.issued_ms + 5001;
    assert!(sign_identity_freshness(&overlong, p.origin.signing_key()).is_err());
    let wrong = sign_identity_freshness(value.value(), &p.attestor).unwrap();
    assert!(
        p.home
            .federation_accept_freshness(&p.gateway, &wrong, TimeBounds::test_now(), &|| true)
            .is_err()
    );
    p.home
        .federation_accept_freshness(&p.gateway, &lease.0, TimeBounds::test_now(), &|| true)
        .unwrap();
    let read = |home: &mut Home| {
        home.store
            .read(Duration::from_secs(1), |db| {
                db.query_row(
                    "SELECT expires,deadline FROM federation_freshness WHERE account=?1",
                    [remote.record.acting.account.to_string()],
                    |r| Ok((r.get::<_, u64>(0)?, r.get::<_, u64>(1)?)),
                )
            })
            .unwrap()
    };
    let before = read(&mut p.home);
    p.home
        .federation_accept_freshness(&p.gateway, &lease.0, TimeBounds::test_now(), &|| true)
        .unwrap();
    assert_eq!(read(&mut p.home), before);
    let mut changed = value.value().clone();
    changed.checkpoints[0].checkpoint_digest = id(220);
    let changed = sign_identity_freshness(&changed, p.origin.signing_key()).unwrap();
    assert!(
        p.home
            .federation_accept_freshness(&p.gateway, &changed, TimeBounds::test_now(), &|| true)
            .is_err()
    );
    std::thread::sleep(Duration::from_millis(2));
    let newer = p
        .origin
        .federation_freshness(p.agreement.reference, &refs, TimeBounds::test_now())
        .unwrap();
    let calls = Cell::new(0);
    assert!(
        p.home
            .federation_accept_freshness(&p.gateway, &newer.0, TimeBounds::test_now(), &|| {
                let n = calls.get();
                calls.set(n + 1);
                n == 0
            })
            .is_err()
    );
    assert_eq!(read(&mut p.home), before);
    let actor = Actor::Direct {
        acting: remote.record.acting.clone(),
    };
    assert!(
        p.home
            .store
            .read(Duration::from_secs(1), |db| Ok(fed::recipient_fresh(
                db,
                p.room,
                &actor,
                TimeBounds::test_now()
            )
            .unwrap()))
            .unwrap()
    );
    drop(p.home);
    p.home = p._home_fixture.open();
    assert!(
        !p.home
            .store
            .read(Duration::from_secs(1), |db| Ok(fed::recipient_fresh(
                db,
                p.room,
                &actor,
                TimeBounds::test_now()
            )
            .unwrap()))
            .unwrap()
    );
    p.renew_freshness();
    assert!(
        p.home
            .store
            .read(Duration::from_secs(1), |db| Ok(fed::recipient_fresh(
                db,
                p.room,
                &actor,
                TimeBounds::test_now()
            )
            .unwrap()))
            .unwrap()
    );
}
