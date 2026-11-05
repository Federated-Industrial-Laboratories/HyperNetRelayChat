// SPDX-License-Identifier: Apache-2.0
use super::*;

#[test]
fn checkpoint_replay_is_no_write_and_service_only_key_substitution_fails() {
    let mut p = Pair::new();
    let remote = p.remote.clone();
    p.admit(&remote);
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
    let page = p
        .origin
        .federation_identity_page(
            p.agreement.reference,
            cp.digest(),
            0,
            4,
            TimeBounds::test_now(),
        )
        .unwrap();
    let before = p.home.usage().unwrap().commit_counter;
    assert!(
        p.home
            .federation_update_identity(
                &p.gateway,
                &fed::IdentityImport {
                    checkpoint: checkpoint.clone(),
                    page: page.clone(),
                    trust_anchor: None
                },
                TimeBounds::test_now(),
                &|| true
            )
            .unwrap()
    );
    assert_eq!(p.home.usage().unwrap().commit_counter, before);
    let mut changed = cp.value().clone();
    changed.state.endpoints[0].key = Id::from_bytes(
        SigningKey::from_bytes(&[113; 32])
            .verifying_key()
            .to_bytes(),
    );
    let forged = Blob(sign_origin_identity_checkpoint(&changed, p.origin.signing_key()).unwrap());
    let signed =
        verify_origin_identity_checkpoint(&forged.0, &p.origin.signing_key().verifying_key())
            .unwrap();
    let mut altered_page =
        verify_origin_identity_page(&page.0, &p.origin.signing_key().verifying_key())
            .unwrap()
            .value()
            .clone();
    altered_page.checkpoint = signed.digest();
    let altered_page =
        Blob(sign_origin_identity_page(&altered_page, p.origin.signing_key()).unwrap());
    assert!(
        p.home
            .federation_update_identity(
                &p.gateway,
                &fed::IdentityImport {
                    checkpoint: forged,
                    page: altered_page,
                    trust_anchor: None
                },
                TimeBounds::test_now(),
                &|| true
            )
            .is_err()
    );
    assert_eq!(
        p.home
            .endpoint(remote.record.acting.account, remote.record.acting.endpoint)
            .unwrap()
            .unwrap()
            .key,
        remote.key.verifying_key()
    );
}

#[test]
fn origin_disable_changes_projection_and_refuses_prepared_old_generation() {
    let mut p = Pair::new();
    let mut remote = p.remote.clone();
    let admitted = p.admit(&remote);
    p.bootstrap(&mut remote, admitted.reference);
    let queued = p.action(
        &remote,
        Operation::RoomJoin,
        Target::Room(p.room),
        &Empty {},
    );
    let envelope = p.envelope(&remote, admitted.reference, &queued);
    let signed = Blob(sign_action(&queued, &remote.key).unwrap());
    let source = p
        .origin
        .federation_origin_subject(
            &remote.session,
            fed::SourceSubject::Action(signed),
            p.agreement.reference,
            TimeBounds::test_now(),
        )
        .unwrap();
    let origin = p.origin.service_id();
    let account = remote.record.acting.account;
    let state = p
        .origin
        .store
        .read(Duration::from_secs(1), |db| {
            crate::identity::continuity::snapshot(db, origin, account)
        })
        .unwrap();
    let window = p
        .origin
        .open_window(&remote.record, TimeBounds::test_now(), &|| true)
        .unwrap();
    let disable = Action {
        home: origin,
        operation_id: OperationId {
            window: window.id,
            operation: Id::random().unwrap(),
        },
        actor: Actor::Direct {
            acting: remote.record.acting.clone(),
        },
        target: Target::Account(account),
        operation: Operation::AccountDisableEndpoint,
        body: Value::serialized(&identity::DisableEndpoint {
            endpoint: remote.record.acting.endpoint,
            revision: state.revision,
            head: state.head.unwrap(),
        })
        .unwrap(),
        expected: BTreeMap::new(),
        approval: None,
        agreement: None,
    };
    let signed = verify_action(
        &sign_action(&disable, &remote.key).unwrap(),
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
    assert!(
        p.origin
            .federation_origin_current(&source, &remote.session, TimeBounds::test_now())
            .is_err()
    );
    let dirty = p
        .origin
        .federation_watched(
            p.agreement.reference,
            true,
            None,
            32,
            TimeBounds::test_now(),
        )
        .unwrap();
    assert_eq!(dirty.items.len(), 1);
    assert_eq!(dirty.items[0].account, account);
    let stale = [CheckpointRef {
        account,
        checkpoint_digest: admitted.checkpoint,
    }];
    assert!(
        p.origin
            .federation_freshness(p.agreement.reference, &stale, TimeBounds::test_now())
            .is_err()
    );
    drop(p.origin);
    let store = Store::open(
        p._origin_fixture.root.join("Data"),
        p._origin_fixture.root.join("Guard"),
        &p._origin_fixture.key,
        *origin.service.as_bytes(),
        storage::Limits::default(),
    )
    .unwrap();
    p.origin = Home::open(store, origin, SigningKey::from_bytes(&[43; 32])).unwrap();
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
    let checkpoint = p
        .origin
        .federation_checkpoint(account, p.agreement.reference, TimeBounds::test_now())
        .unwrap();
    let cp =
        verify_origin_identity_checkpoint(&checkpoint.0, &p.origin.signing_key().verifying_key())
            .unwrap();
    let page = p
        .origin
        .federation_identity_page(
            p.agreement.reference,
            cp.digest(),
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
    assert!(
        p.home
            .endpoint(account, remote.record.acting.endpoint)
            .unwrap()
            .is_none()
    );
    p.origin
        .federation_acknowledge_identity(
            p.agreement.reference,
            account,
            cp.digest(),
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
    assert!(
        p.home
            .federation_verify(
                &p.gateway,
                &envelope,
                &privacy(),
                TimeBounds::test_now(),
                &|| true
            )
            .is_err()
    );
}
