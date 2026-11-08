// SPDX-License-Identifier: Apache-2.0
use super::*;

fn artifact(value: u8) -> Artifact {
    Artifact::from_bytes(&[value]).unwrap()
}
fn delivery() -> Delivery {
    let route = |role: &str, seed| RouteDelivery {
        role: role.into(),
        subject: format!("{seed:02x}").repeat(32),
        artifact: artifact(seed),
        voucher_id: format!("{:02x}", seed + 10).repeat(32),
        generation: 1,
        expires_ms: 1000,
    };
    Delivery {
        setup_bundle: artifact(1),
        chat_request_sha256: "11".repeat(32),
        chat_routes: vec![route("Authority", 2), route("Application", 3)],
        reader: Some(admission::ReaderDelivery {
            network_invitation: artifact(4),
            request_sha256: "22".repeat(32),
            routes: vec![route("Authority", 5), route("Page", 6)],
        }),
        access_expires_ms: 10_000,
        join_expires_ms: 9000,
        route_expires_ms: 1000,
        renewal_after_ms: 3000,
    }
}
fn renewed() -> Delivery {
    let mut next = delivery();
    for route in next
        .chat_routes
        .iter_mut()
        .chain(next.reader.as_mut().unwrap().routes.iter_mut())
    {
        route.generation += 1;
        route.expires_ms += 1000;
        route.artifact = artifact(9);
    }
    next.route_expires_ms += 1000;
    next.renewal_after_ms += 1000;
    next
}

#[test]
fn renewal_accepts_same_identity_and_retries_but_rejects_rebinding_and_rollback() {
    let old = delivery();
    let next = renewed();
    assert!(validate_successor(&old, &old).is_ok());
    assert!(validate_successor(&old, &next).is_ok());
    assert!(validate_successor(&next, &old).is_err());
    let mut altered = next.clone();
    altered.setup_bundle = artifact(8);
    assert!(validate_successor(&old, &altered).is_err());
    altered = next.clone();
    altered.chat_routes[0].voucher_id = "ff".repeat(32);
    assert!(validate_successor(&old, &altered).is_err());
    altered = old.clone();
    altered.chat_routes[0].artifact = artifact(8);
    assert!(validate_successor(&old, &altered).is_err());
    altered = next.clone();
    altered.reader.as_mut().unwrap().request_sha256 = "ff".repeat(32);
    assert!(validate_successor(&old, &altered).is_err());
    altered = next;
    altered.access_expires_ms += 1;
    assert!(validate_successor(&old, &altered).is_err());
}

struct Temporary(PathBuf);
impl Temporary {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "hrc-admission-{}",
            hrc::protocol::Id::random().unwrap().as_hex()
        ));
        native::directory(&path).unwrap();
        Self(path)
    }
}
impl Drop for Temporary {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn invitation() -> Invitation {
    Invitation {
        format: admission::INVITATION_FORMAT.into(),
        name: "Test host".into(),
        address: "127.0.0.1:18443".parse().unwrap(),
        certificate_authority_pem: "test certificate".into(),
        server_certificate_sha256: "01".repeat(32),
        network: "02".repeat(32),
        incarnation: "03".repeat(32),
        bootstrap_sha256: artifact(1).sha256,
        bootstrap_fingerprint: "04".repeat(32),
        id: "05".repeat(32),
        secret: "06".repeat(32),
        expires_ms: u64::MAX - 1,
        access_expires_ms: u64::MAX,
    }
}

#[test]
fn private_workflow_serializes_resume_and_keeps_authentication_keys() {
    let temp = Temporary::new();
    let mut config = RuntimeConfig::at(temp.0.clone());
    config.self_service = Some(temp.0.join("Admission"));
    native::directory(config.self_service.as_ref().unwrap()).unwrap();
    replace(
        &config
            .self_service
            .as_ref()
            .unwrap()
            .join("Invitation.json"),
        &invitation(),
    )
    .unwrap();
    let first = Workflow::open(&config).unwrap();
    let key = files::read(&first.root.join("Authentication/Authentication.key"), 32).unwrap();
    assert!(matches!(Workflow::open(&config), Err(Error::Busy)));
    drop(first);
    let reopened = Workflow::open(&config).unwrap();
    assert_eq!(
        files::read(&reopened.root.join("Authentication/Authentication.key"), 32).unwrap(),
        key
    );
    let cancel = AtomicBool::new(true);
    assert!(matches!(
        reopened.client.exchange(
            Action::Status,
            &cancel,
            Instant::now() + Duration::from_secs(1)
        ),
        Err(admission::Error::Cancelled)
    ));
    drop(reopened);
    config.network_profile = temp.0.join("Other/Profile.json");
    assert!(Workflow::open(&config).is_err());
}

#[test]
fn reader_applied_checkpoint_is_independent_of_chat_and_persists() {
    let temp = Temporary::new();
    let original = delivery();
    mark(&temp.0, "ChatApplied.json", &original).unwrap();
    mark(&temp.0, "ReaderApplied.json", &original).unwrap();
    let next = renewed();
    mark(&temp.0, "ChatApplied.json", &next).unwrap();
    assert!(current(&temp.0, "ChatApplied.json", &next));
    assert!(!current(&temp.0, "ReaderApplied.json", &next));
    assert!(current(&temp.0, "ReaderApplied.json", &original));
    assert!(!current(&temp.0, "ChatApplied.json", &original));
}

#[test]
fn metadata_cannot_replace_invitation_network_pin_or_expand_access() {
    let mut invitation = invitation();
    invitation.access_expires_ms = 10_000;
    let metadata = NetworkMetadata {
        bootstrap: artifact(1),
        bootstrap_fingerprint: invitation.bootstrap_fingerprint.clone(),
        network: invitation.network.clone(),
        incarnation: invitation.incarnation.clone(),
        application_service: "07".repeat(32),
        reader_available: true,
        access_expires_ms: invitation.access_expires_ms,
    };
    assert!(validate_metadata(&invitation, &metadata).is_ok());
    let mut replaced = metadata.clone();
    replaced.network = "08".repeat(32);
    assert!(validate_metadata(&invitation, &replaced).is_err());
    replaced = metadata;
    replaced.bootstrap = artifact(2);
    assert!(validate_metadata(&invitation, &replaced).is_err());
    replaced.bootstrap = artifact(1);
    replaced.access_expires_ms += 1;
    assert!(validate_metadata(&invitation, &replaced).is_err());
}

#[test]
fn manual_runtime_remains_optional_and_reader_uses_independent_paths() {
    let c = RuntimeConfig::at(PathBuf::from("/private/chat"));
    let value = serde_json::to_value(&c).unwrap();
    assert!(value.get("selfService").is_none());
    assert!(
        serde_json::from_value::<RuntimeConfig>(value)
            .unwrap()
            .self_service
            .is_none()
    );
    let reader = reader_config(&c);
    assert_ne!(reader.network_profile, c.network_profile);
    assert_ne!(reader.joined_directory, c.joined_directory);
    assert_eq!(reader.clock_observation, c.clock_observation);
    assert!(reader.self_service.is_none());
}

#[test]
fn companion_path_limit_counts_bytes_and_reserves_the_unix_terminator() {
    assert!(native::socket_path_valid(Path::new(&format!(
        "/{}",
        "a".repeat(106)
    ))));
    assert!(!native::socket_path_valid(Path::new(&format!(
        "/{}",
        "a".repeat(107)
    ))));
    assert!(!native::socket_path_valid(Path::new(&format!(
        "/{}",
        "é".repeat(54)
    ))));
    assert!(!native::socket_path_valid(Path::new(
        "/private/invalid\0socket"
    )));
}

#[test]
fn long_companion_path_refuses_before_invitation_or_native_effects_and_preserves_manual_runtime() {
    let temp = Temporary::new();
    let mut config = RuntimeConfig::at(temp.0.clone());
    config.companion_directory = temp.0.join("a".repeat(108));
    // Existing manual configurations remain loadable; the new check belongs to invitation entry.
    config.save().unwrap();
    let path = temp.0.join("OnboardingRuntime.json");
    let before = files::read(&path, 65536).unwrap();
    assert!(RuntimeConfig::load(&path).unwrap().self_service.is_none());
    assert_eq!(
        join(
            &mut config,
            "not an invitation",
            None,
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(1)
        ),
        Err(Error::CompanionSocketPath)
    );
    assert!(config.self_service.is_none());
    assert_eq!(files::read(&path, 65536).unwrap(), before);
    for name in ["Admission", "Network", "Clock", "Profile", "Recovery"] {
        assert!(!temp.0.join(name).exists());
    }
}

#[test]
fn invitation_refuses_existing_manual_keys_without_changing_runtime_and_resumes_owned_state() {
    let temp = Temporary::new();
    let mut config = RuntimeConfig::at(temp.0.clone());
    config.save().unwrap();
    let runtime_path = temp.0.join("OnboardingRuntime.json");
    let original = files::read(&runtime_path, 65536).unwrap();
    native::directory(config.network_profile.parent().unwrap()).unwrap();
    files::create(&config.network_profile, b"existing native profile").unwrap();
    assert_eq!(invitation_folder(&mut config), Err(Error::AdmissionFolder));
    assert_eq!(files::read(&runtime_path, 65536).unwrap(), original);
    assert_eq!(
        files::read(&config.network_profile, 1024).unwrap(),
        b"existing native profile"
    );
    assert!(config.self_service.is_none());
    assert!(!temp.0.join("Admission").exists());

    // A retained opt-in survives a cancelled worker whose in-memory snapshot is older.
    let mut retained = config.clone();
    retained.self_service = Some(temp.0.join("Admission"));
    retained.page_browser_profile = Some(temp.0.join("Reader/Network/Profile.json"));
    retained.save().unwrap();
    invitation_folder(&mut config).unwrap();
    assert_eq!(config.self_service, retained.self_service);
    assert_eq!(config.page_browser_profile, retained.page_browser_profile);
}

#[test]
fn delivered_route_metadata_must_match_native_voucher_and_prepared_recipient() {
    use ciborium::Value as Cbor;
    let temp = Temporary::new();
    let config = RuntimeConfig::at(temp.0.clone());
    replace(
        &temp.0.join("PreparedNetwork.json"),
        &runtime::Prepared {
            bootstrap_sha256: "01".repeat(32),
            device_key: "04".repeat(32),
            relay_key: "05".repeat(32),
            network: "01".repeat(32),
            incarnation: "02".repeat(32),
        },
    )
    .unwrap();
    let n = |number: u64| Cbor::Integer(number.into());
    let payload = Cbor::Array(vec![
        Cbor::Null,
        Cbor::Null,
        Cbor::Bytes(vec![4; 32]),
        Cbor::Null,
        Cbor::Bytes(vec![5; 32]),
        n(0),
        Cbor::Null,
        n(1),
        n(16384),
        n(500_000),
        Cbor::Null,
    ]);
    let voucher = hrc::protocol::canonical_encode(
        &Cbor::Array(vec![
            n(166),
            n(1),
            Cbor::Bytes(vec![1; 32]),
            Cbor::Bytes(vec![2; 32]),
            n(1),
            Cbor::Null,
            Cbor::Bytes(vec![6; 32]),
            payload,
        ]),
        65536,
    )
    .unwrap();
    let bytes = serde_json::to_vec(
        &json!({"version":1,"protocol":7,"network":vec![1u8;32],"incarnation":vec![2u8;32],
        "destination":{"service":vec![3u8;32]},"limits":{"bytes":16384},"voucher":voucher}),
    )
    .unwrap();
    let route = RouteDelivery {
        role: "Application".into(),
        subject: "03".repeat(32),
        artifact: Artifact::from_bytes(&bytes).unwrap(),
        voucher_id: "06".repeat(32),
        generation: 1,
        expires_ms: 500_000,
    };
    let metadata = NetworkMetadata {
        bootstrap: artifact(1),
        bootstrap_fingerprint: "01".repeat(32),
        network: "01".repeat(32),
        incarnation: "02".repeat(32),
        application_service: "03".repeat(32),
        reader_available: false,
        access_expires_ms: 600_000,
    };
    assert!(
        validate_routes(
            &config,
            &metadata,
            std::slice::from_ref(&route),
            &["Application"]
        )
        .is_ok()
    );
    let mut changed = route.clone();
    changed.generation = 2;
    assert!(validate_routes(&config, &metadata, &[changed], &["Application"]).is_err());
    changed = route.clone();
    changed.subject = "07".repeat(32);
    assert!(validate_routes(&config, &metadata, &[changed], &["Application"]).is_err());
    changed = route.clone();
    changed.expires_ms += 1;
    assert!(validate_routes(&config, &metadata, &[changed], &["Application"]).is_err());
    replace(
        &temp.0.join("PreparedNetwork.json"),
        &runtime::Prepared {
            bootstrap_sha256: "01".repeat(32),
            device_key: "04".repeat(32),
            relay_key: "07".repeat(32),
            network: "01".repeat(32),
            incarnation: "02".repeat(32),
        },
    )
    .unwrap();
    assert!(validate_routes(&config, &metadata, &[route], &["Application"]).is_err());
}

#[test]
fn pending_before_acceptance_retries_the_exact_operation_until_ready() {
    let actions = [
        Action::Inspect {
            secret: "01".repeat(32),
        },
        Action::Redeem {
            secret: "01".repeat(32),
            chat_request: artifact(1),
            reader_request: Some(artifact(2)),
        },
        Action::Enrol {
            registration: artifact(3),
        },
        Action::Renew,
    ];
    for action in actions {
        let expected = serde_json::to_value(&action).unwrap();
        let mut calls = 0;
        let result = exchange_repeated(
            action,
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(5),
            |retried| {
                assert_eq!(serde_json::to_value(&retried).unwrap(), expected);
                calls += 1;
                if calls < 3 {
                    Ok(Response::Pending {
                        phase: "Admission service is unavailable or busy".into(),
                        retry_after_ms: 0,
                    })
                } else {
                    Ok(Response::Ready {
                        delivery: delivery(),
                        enrolled: true,
                    })
                }
            },
        )
        .unwrap();
        assert!(matches!(result, Response::Ready { enrolled: true, .. }));
        assert_eq!(calls, 3);
    }
}
