// SPDX-License-Identifier: Apache-2.0
//! Admission bindings, native uncertainty and independent reader identities have explicit failure contracts.
use super::*;
use std::{fs, os::unix::fs::PermissionsExt, time::Duration};

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!("hrc-admission-{}", id().unwrap()));
        fs::create_dir(&path).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
        Self(path)
    }
    fn config(&self) -> Config {
        let route = |value: u8| RouteConfig {
            service: hex::encode([value; 32]),
            profile: self.0.join(format!("Profile{value}")),
        };
        Config {
            core: self.0.join("Core"),
            suite: self.0.join("Suite"),
            publisher_key: self.0.join("Publisher"),
            bootstrap: self.0.join("Bootstrap"),
            operator_directory: self.0.join("Operator"),
            operator_key: self.0.join("Key"),
            operator_lock: self.0.join("Operator.lock"),
            authority_control_directory: self.0.join("Control"),
            clock_directory: self.0.join("Clock"),
            clock_metadata: self.0.join("Clock.json"),
            image: format!("sha256:{}", hex::encode([1; 32])),
            home_config: self.0.join("Home.json"),
            relay: route(2),
            authority: route(3),
            application: route(4),
            reader: None,
            access_expires_ms: now_ms().unwrap() + 120_000,
        }
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn candidate(device: u8, relay: u8, reader: bool) -> Candidate {
    Candidate::new(&[device, relay], &json!({"devicePublicKey":hex::encode([device;32]),"relayPublicKey":hex::encode([relay;32])}), reader).unwrap()
}
#[test]
fn readers_require_independent_device_and_possession_keys() {
    let chat = candidate(11, 12, false);
    assert!(super::super::workflow::distinct(&chat, &candidate(13, 14, true)).is_ok());
    for reader in [
        candidate(11, 14, true),
        candidate(13, 12, true),
        candidate(12, 11, true),
    ] {
        assert!(super::super::workflow::distinct(&chat, &reader).is_err());
    }
}
#[test]
fn uncertain_native_effect_is_retained_without_selecting_new_parameters() {
    let fixture = Fixture::new();
    let config = fixture.config();
    let cancel = AtomicBool::new(false);
    let native = native::Native::new(&config, &cancel, Instant::now() + Duration::from_secs(1));
    let effects = fixture.0.join("Effects");
    directory(&effects).unwrap();
    let folder = effects.join("Grant");
    directory(&folder).unwrap();
    let intent = Intent {
        arguments: args(&["authority-inspection", "delegate-grant", "--id", "retained"]),
        output: None,
    };
    save(&folder.join("Intent.json"), &intent).unwrap();
    assert!(matches!(
        effect(&native, &fixture.0, "Grant", intent.arguments.clone(), None),
        Err(Error::Native)
    ));
    assert!(folder.join("Blocked.json").exists());
    assert!(!folder.join("Result.json").exists());
    assert!(matches!(
        effect(&native, &fixture.0, "Grant", args(&["different"]), None),
        Err(Error::Bound)
    ));
    assert!(read::<Intent>(&folder.join("Intent.json")).unwrap() == intent);
}
#[test]
fn one_operator_lock_serializes_distinct_recipients() {
    let fixture = Fixture::new();
    let config = fixture.config();
    let first = Lock::acquire(&config).unwrap();
    assert!(matches!(Lock::acquire(&config), Err(Error::Busy)));
    drop(first);
    assert!(Lock::acquire(&config).is_ok());
}
#[test]
fn retained_grant_must_match_exact_candidate_actions_and_scope() {
    let fixture = Fixture::new();
    let config = fixture.config();
    let chat = candidate(11, 12, false);
    let admission = Admission {
        config_digest: String::new(),
        bootstrap_sha256: String::new(),
        network: hex::encode([20; 32]),
        incarnation: hex::encode([21; 32]),
        access_expires_ms: 600_000,
        route_seconds: 120,
        not_before_ms: 1,
        initial_expires_ms: 120_000,
        join_expires_ms: 600_000,
        invitation_id: hex::encode([22; 32]),
        invitation_expires_ms: 600_000,
        chat: chat.clone(),
        reader: None,
    };
    let fields = json!([102,1,{"hex":admission.network},{"hex":admission.incarnation},1,null,
        {"hex":chat.reader_grant},{"hex":hex::encode([23;32])},{"hex":chat.principal},null,[0,6],[[0,{"hex":admission.network}]],
        [admission.not_before_ms,admission.access_expires_ms],null,0,[268435456_u64,1024,8,16],null]);
    let mut result = json!({"status":"GrantDelegated","grant":chat.reader_grant,"recordDigest":routes::record_digest(&fields).unwrap(),"record":fields});
    assert!(routes::check_grant(&config, &admission, &chat, false, &result).is_ok());
    result["record"][10] = json!([0, 2, 6]);
    result["recordDigest"] = json!(routes::record_digest(&result["record"]).unwrap());
    assert!(routes::check_grant(&config, &admission, &chat, false, &result).is_err());
}
#[test]
fn route_expiry_binds_logical_identity_instead_of_service_signing_key() {
    use ciborium::Value as Cbor;
    let fixture = Fixture::new();
    let mut route = fixture.config().authority;
    let network = hex::encode([20; 32]);
    let incarnation = hex::encode([21; 32]);
    // Native AuthorityRoutes::RegisteredProfile has a 22-field signed payload.
    // This metadata preflight reads context, identity and validity; native template
    // authoring subsequently verifies the complete profile, manifest and signature.
    let mut fields = vec![Cbor::Null; 22];
    fields[0] = Cbor::Integer(200.into());
    fields[1] = Cbor::Integer(1.into());
    fields[2] = Cbor::Text("AuthorityRouteProfile".into());
    fields[3] = Cbor::Bytes(vec![20; 32]);
    fields[4] = Cbor::Bytes(vec![21; 32]);
    fields[6] = Cbor::Bytes(vec![22; 32]);
    fields[11] = Cbor::Array(vec![
        Cbor::Bytes(hex::decode(&route.service).unwrap()),
        Cbor::Text("authority.example".into()),
        Cbor::Bytes(vec![23; 32]),
        Cbor::Bytes(vec![]),
        Cbor::Text(String::new()),
    ]);
    fields[20] = Cbor::Array(vec![Cbor::Integer(1.into()), Cbor::Integer(600_000.into())]);
    let payload = hrc::protocol::canonical_encode(&Cbor::Array(fields), 32768).unwrap();
    let envelope = Cbor::Array(vec![
        Cbor::Integer(0.into()),
        Cbor::Integer(1.into()),
        Cbor::Bytes(payload),
        Cbor::Array(vec![]),
    ]);
    exact(
        &route.profile,
        &hrc::protocol::canonical_encode(&envelope, 32768).unwrap(),
    )
    .unwrap();
    assert_eq!(
        routes::profile_expiry(&route, &network, &incarnation).unwrap(),
        600_000
    );
    assert!(routes::profile_expiry(&route, &incarnation, &network).is_err());
    route.service = hex::encode([22; 32]);
    assert!(routes::profile_expiry(&route, &network, &incarnation).is_err());
}

#[test]
fn completed_expired_routes_recover_and_replace_large_delivery_without_native_issuance() {
    use super::super::workflow::{Current, completed_round, current, store_current};
    use ciborium::Value as C;
    let fixture = Fixture::new();
    let config = fixture.config();
    let cancel = AtomicBool::new(false);
    let native = native::Native::new(&config, &cancel, Instant::now() + Duration::from_secs(5));
    let chat = candidate(11, 12, false);
    let admission = Admission {
        config_digest: String::new(),
        bootstrap_sha256: String::new(),
        network: hex::encode([20; 32]),
        incarnation: hex::encode([21; 32]),
        access_expires_ms: 600_000,
        route_seconds: 120,
        not_before_ms: 1,
        initial_expires_ms: 2,
        join_expires_ms: 600_000,
        invitation_id: hex::encode([22; 32]),
        invitation_expires_ms: 600_000,
        chat: chat.clone(),
        reader: None,
    };
    exact(&fixture.0.join("Setup.json"), &vec![b'x'; 40_000]).unwrap();
    let round = fixture.0.join("Round1");
    directory(&round).unwrap();
    let folder = round.join("Chat");
    directory(&folder).unwrap();
    directory(&folder.join("Effects")).unwrap();
    let bytes = |s: &str| C::Bytes(hex::decode(s).unwrap());
    let reference = |s: &str| {
        C::Array(vec![
            C::Integer(200.into()),
            bytes(s),
            C::Integer(1.into()),
            C::Bytes(vec![25; 32]),
        ])
    };
    for (role, id, destination) in [
        ("Authority", &chat.authority, &config.authority.service),
        (
            "Application",
            &chat.destination,
            &config.application.service,
        ),
    ] {
        let payload = C::Array(vec![
            reference(&config.relay.service),
            reference(destination),
            C::Null,
            C::Null,
            bytes(&chat.relay),
            C::Integer(0.into()),
            C::Null,
            C::Null,
            C::Null,
            C::Integer(2.into()),
            C::Null,
        ]);
        let record = C::Array(vec![
            C::Integer(166.into()),
            C::Integer(1.into()),
            bytes(&admission.network),
            bytes(&admission.incarnation),
            C::Integer(2.into()),
            C::Null,
            bytes(id),
            payload,
        ]);
        let output = folder.join(format!("{role}Route.json"));
        save(
            &output,
            &json!({"voucher":hrc::protocol::canonical_encode(&record, 65536).unwrap()}),
        )
        .unwrap();
        let effect = folder.join("Effects").join(format!("{role}Route"));
        directory(&effect).unwrap();
        save(
            &effect.join("Intent.json"),
            &Intent {
                arguments: args(&["must-not-execute"]),
                output: Some(output),
            },
        )
        .unwrap();
    }
    // Both routes expired long ago, but their exact outputs are durable. Missing
    // Result/Delivery/Current markers must be reconstructed without native commands.
    let recovered = completed_round(&native, &admission, &fixture.0, &round)
        .unwrap()
        .unwrap();
    assert_eq!(recovered.route_expires_ms, 2);
    assert_eq!(recovered.chat_routes[0].generation, 2);
    assert!(folder.join("Effects/AuthorityRoute/Result.json").exists());
    assert!(folder.join("Effects/ApplicationRoute/Result.json").exists());
    let value = Current {
        round: 1,
        delivery: recovered.clone(),
    };
    store_current(&fixture.0, &value).unwrap();
    assert!(fs::metadata(fixture.0.join("Current.json")).unwrap().len() > 65_536);
    store_current(
        &fixture.0,
        &Current {
            round: 2,
            delivery: recovered.clone(),
        },
    )
    .unwrap();
    assert_eq!(current(&fixture.0).unwrap().round, 2);
    assert_eq!(
        current(&fixture.0).unwrap().delivery.setup_bundle,
        recovered.setup_bundle
    );
    assert_eq!(
        completed_round(&native, &admission, &fixture.0, &round).unwrap(),
        Some(recovered)
    );
    fs::remove_file(round.join("Delivery.json")).unwrap();
    fs::remove_file(folder.join("Effects/ApplicationRoute/Intent.json")).unwrap();
    assert!(
        completed_round(&native, &admission, &fixture.0, &round)
            .unwrap()
            .is_none()
    );
}
