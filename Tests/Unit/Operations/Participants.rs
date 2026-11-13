// SPDX-License-Identifier: Apache-2.0
//! The managed identity stays stoppable after revocation without accepting another operator.
use super::*;
use hrc::{
    clock,
    service::{Descriptor, files},
};
#[test]
fn revoked_api_remains_stoppable_but_wrong_operator_or_endpoint_is_refused() {
    let root = std::env::temp_dir().join(format!("hrc-managed-api-{}", Id::random().unwrap()));
    files::directory(&root, true).unwrap();
    let endpoint = files::create_key(&root.join("Endpoint.key")).unwrap();
    let service = files::create_key(&root.join("Service.key")).unwrap();
    let network = NetworkId {
        network: Id::random().unwrap(),
        incarnation: Id::random().unwrap(),
    };
    let home = ServiceId {
        network,
        service: Id::random().unwrap(),
    };
    let operator = AccountId {
        origin: network,
        local: Id::random().unwrap(),
    };
    let profile = Profile {
        server: Descriptor {
            version: 1,
            home,
            signing_key: Id::from_bytes(service.verifying_key().to_bytes()),
            protocol: PROTOCOL.into(),
            text_profile: hrc::text::PROFILE.into(),
        },
        registration: AccountRegistration {
            home,
            account: AccountId {
                origin: network,
                local: Id::random().unwrap(),
            },
            endpoint: Id::random().unwrap(),
            endpoint_key: Id::from_bytes(endpoint.verifying_key().to_bytes()),
            transport_principal: Id::random().unwrap(),
            recovery_key: Id::random().unwrap(),
            classification: AccountClass::Agent { operator },
            invitation: Id::random().unwrap(),
        },
        companion: root.join("Companion"),
        clock: clock::Config {
            observation: root.join("Clock"),
            monitor_key: Id::random().unwrap().as_hex(),
        },
        federation: None,
        agreements: vec![],
    };
    files::create_json(&root.join("Profile.json"), &profile).unwrap();
    let api = integration::initialise(&root, &root.join("Integration")).unwrap();
    let credential = root.join("Client.json");
    let credential_id = integration::issue(
        &api,
        integration::Scope {
            rooms: vec![RoomId {
                home,
                local: Id::random().unwrap(),
            }],
            initiate: false,
            history: false,
            agent_replies: false,
        },
        &credential,
    )
    .unwrap();
    let mut configuration = Configuration {
        version: 1,
        operator,
        profile: root.clone(),
        api,
        credential,
        credential_id,
        limits: Default::default(),
    };
    let unit = configuration.unit().unwrap();
    assert!(configuration.scope().is_ok());
    integration::revoke(&configuration.api, credential_id).unwrap();
    assert!(configuration.scope().is_err());
    assert_eq!(configuration.unit().unwrap(), unit); // Stop remains available after credential revocation.
    configuration.operator.local = Id::random().unwrap();
    assert!(configuration.unit().is_err());
    configuration.operator = operator;
    let mut mismatched = integration::Configuration::load(&configuration.api).unwrap();
    mismatched.endpoint = Id::random().unwrap();
    std::fs::write(&configuration.api, serde_json::to_vec(&mismatched).unwrap()).unwrap();
    assert!(configuration.unit().is_err());
    std::fs::remove_dir_all(root).unwrap();
}
