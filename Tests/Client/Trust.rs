// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::client::{cache, trust};
fn anchor() -> (ContinuityRecord, SigningKey, SigningKey) {
    let action = action();
    let endpoint = SigningKey::from_bytes(&[20; 32]);
    let recovery = SigningKey::from_bytes(&[21; 32]);
    let registration = AccountRegistration {
        home: action.home,
        account: action.actor.represented(),
        endpoint: action.actor.acting().endpoint,
        endpoint_key: Id::from_bytes(endpoint.verifying_key().to_bytes()),
        transport_principal: id(30),
        recovery_key: Id::from_bytes(recovery.verifying_key().to_bytes()),
        classification: AccountClass::Human,
        invitation: id(31),
    };
    let state = IdentitySnapshot {
        home: registration.home,
        account: registration.account,
        classification: registration.classification.clone(),
        security_generation: 1,
        revision: 1,
        recovery_key: registration.recovery_key,
        recovery_generation: 1,
        head: None,
        legacy_anchor: false,
        endpoints: vec![EndpointView {
            actor: action.actor.acting().clone(),
            key: registration.endpoint_key,
            principal: registration.transport_principal,
        }],
    };
    (
        ContinuityRecord {
            index: 1,
            previous: None,
            position: 1,
            change: IdentityChange::Registered,
            authorizations: vec![Blob(sign_registration(&registration, &endpoint).unwrap())],
            state,
        },
        endpoint,
        recovery,
    )
}
#[test]
fn owner_signed_anchor_and_disable_reject_home_only_substitution() {
    let (first, key, _) = anchor();
    let homekey = SigningKey::from_bytes(&[22; 32]);
    let checked =
        trust::check_chain(&homekey.verifying_key(), vec![first.clone()], |_, _| None).unwrap();
    assert_eq!(
        checked.view(trust::TrustState::UntrustedRegistration).state,
        trust::TrustState::UntrustedRegistration
    );
    let head = checked.hashes[0];
    let mut action = action();
    action.operation = Operation::AccountDisableEndpoint;
    action.target = Target::Account(first.state.account);
    action.body = Value::serialized(&crate::identity::DisableEndpoint {
        endpoint: first.state.endpoints[0].actor.endpoint,
        head,
        revision: 1,
    })
    .unwrap();
    let mut second = first.clone();
    second.index = 2;
    second.previous = Some(head);
    second.position = 2;
    second.change = IdentityChange::EndpointDisabled;
    second.state.head = Some(head);
    second.state.revision = 2;
    second.state.endpoints.clear();
    second.authorizations = vec![Blob(sign_action(&action, &key).unwrap())];
    let chain = trust::check_chain(
        &homekey.verifying_key(),
        vec![first.clone(), second.clone()],
        |_, _| None,
    )
    .unwrap();
    assert!(chain.latest().endpoints.is_empty());
    second.state.endpoints = first.state.endpoints.clone();
    second.state.endpoints[0].key = Id::from_bytes(homekey.verifying_key().to_bytes());
    assert!(
        trust::check_chain(
            &homekey.verifying_key(),
            vec![first.clone(), second],
            |_, _| None
        )
        .is_err()
    );
    let mut substituted = first.clone();
    substituted.state.recovery_key = Id::from_bytes(homekey.verifying_key().to_bytes());
    assert!(trust::check_chain(&homekey.verifying_key(), vec![substituted], |_, _| None).is_err());
    let mut legacy = first;
    legacy.change = IdentityChange::LegacyServiceAnchor;
    legacy.state.legacy_anchor = true;
    legacy.authorizations.clear();
    assert_eq!(
        trust::check_chain(&homekey.verifying_key(), vec![legacy], |_, _| None)
            .unwrap()
            .view(trust::TrustState::LegacyAnchor)
            .state,
        trust::TrustState::LegacyAnchor
    );
}
#[test]
fn recovery_requires_owner_proof_and_exact_new_endpoint_binding() {
    let (first, _, recovery) = anchor();
    let home = SigningKey::from_bytes(&[22; 32]);
    let endpoint = SigningKey::from_bytes(&[23; 32]);
    let head = digest(&cache::encode(&first).unwrap());
    let request = DeviceRequest {
        home: first.state.home,
        account: first.state.account,
        request: id(40),
        endpoint: id(41),
        endpoint_key: Id::from_bytes(endpoint.verifying_key().to_bytes()),
        principal: id(42),
        purpose: DevicePurpose::Recover,
        created_ms: 1000,
        expires_ms: 10_000,
        replacement: None,
    };
    let requestbytes = sign_device_request(&request, &endpoint).unwrap();
    let challenge = DeviceChallenge {
        home: request.home,
        account: request.account,
        request: request.request,
        request_digest: verify_new_device(&requestbytes).unwrap().digest(),
        nonce: id(43),
        service_boot: id(44),
        principal: request.principal,
        session: id(45),
        transport_generation: 1,
        security_generation: 1,
        account_revision: 1,
        recovery_generation: 1,
        recovery_key: first.state.recovery_key,
        continuity_head: head,
        recorded: false,
        issued_ms: 1100,
        expires_ms: 6100,
    };
    let challengebytes = sign_device_challenge(&challenge, &home).unwrap();
    let proof = DeviceProof {
        home: request.home,
        account: request.account,
        request: request.request,
        request_digest: verify_new_device(&requestbytes).unwrap().digest(),
        challenge_digest: verify_device_challenge(&challengebytes, &home.verifying_key())
            .unwrap()
            .digest(),
    };
    let proofs = DeviceProofs {
        endpoint: Blob(sign_device_proof(&proof, &endpoint).unwrap()),
        recovery: Some(Blob(sign_device_proof(&proof, &recovery).unwrap())),
    };
    let mut state = first.state.clone();
    state.head = Some(head);
    state.revision = 2;
    state.security_generation = 2;
    state.endpoints = vec![EndpointView {
        actor: EndpointActor {
            account: request.account,
            endpoint: request.endpoint,
            security_generation: 2,
            enrolment_generation: 1,
            binding_digest: id(46),
        },
        key: request.endpoint_key,
        principal: request.principal,
    }];
    let second = ContinuityRecord {
        index: 2,
        previous: Some(head),
        position: 2,
        change: IdentityChange::Recovered,
        authorizations: vec![
            Blob(requestbytes),
            Blob(challengebytes),
            Blob(cache::encode(&proofs).unwrap()),
        ],
        state,
    };
    assert!(
        trust::check_chain(
            &home.verifying_key(),
            vec![first.clone(), second.clone()],
            |_, _| None
        )
        .is_ok()
    );
    let mut forged = second.clone();
    let mut noowner = proofs;
    noowner.recovery = Some(Blob(sign_device_proof(&proof, &home).unwrap()));
    forged.authorizations[2] = Blob(cache::encode(&noowner).unwrap());
    assert!(
        trust::check_chain(
            &home.verifying_key(),
            vec![first.clone(), forged],
            |_, _| None
        )
        .is_err()
    );
    let mut changed = second;
    changed.state.endpoints[0].principal = id(47);
    assert!(trust::check_chain(&home.verifying_key(), vec![first, changed], |_, _| None).is_err());
}
