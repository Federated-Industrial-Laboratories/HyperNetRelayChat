// SPDX-License-Identifier: Apache-2.0
//! The real private socket serves the running encrypted Home without releasing its lease.
use super::*;
use crate::{
    home::admission as a,
    service::{self, live_admission::Binding},
    storage,
};
use ed25519_dalek::Signer;
use std::time::{SystemTime, UNIX_EPOCH};
#[path = "Host.rs"]
mod host;
fn id(n: u8) -> Id {
    Id::from_bytes([n; 32])
}
fn witness(directory: &Path, key: &SigningKey) -> clock::Config {
    let wall = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_millis() as u64;
    let boot = clock::boot_ms().unwrap();
    let host = fs::read_to_string("/proc/sys/kernel/random/boot_id")
        .unwrap()
        .trim()
        .to_owned();
    let payload = canonical_encode(
        &ciborium::Value::Array(vec![
            44u64.into(),
            1u64.into(),
            ciborium::Value::Text(host),
            wall.into(),
            boot.into(),
            (boot + 1000).into(),
            0u64.into(),
            ciborium::Value::Text("192.0.2.1".into()),
        ]),
        4096,
    )
    .unwrap();
    let public = key.verifying_key().to_bytes();
    let mut input = b"HyperNet/RecordSignature/1\0".to_vec();
    input.extend((payload.len() as u32).to_be_bytes());
    input.extend(&payload);
    input.extend(public);
    let bytes = canonical_encode(
        &ciborium::Value::Array(vec![
            0u64.into(),
            1u64.into(),
            ciborium::Value::Bytes(payload),
            ciborium::Value::Array(vec![ciborium::Value::Array(vec![
                ciborium::Value::Bytes(public.to_vec()),
                ciborium::Value::Bytes(key.sign(&input).to_bytes().to_vec()),
            ])]),
        ]),
        4096,
    )
    .unwrap();
    let path = directory.join("Clock.cbor");
    let next = directory.join("Clock.next");
    fs::write(&next, bytes).unwrap();
    fs::rename(next, &path).unwrap();
    clock::Config {
        observation: path,
        monitor_key: hex::encode(public),
    }
}
#[test]
fn live_private_socket_enrolment_preserves_home_ownership_and_exact_retry() {
    let root = std::env::temp_dir().join(format!("hrc-live-{}", Id::random().unwrap()));
    files::directory(&root, true).unwrap();
    let directory=root.join("a-long-private-service-directory-used-to-test-unix-path-addressing-without-an-extra-socket-folder");
    files::directory(&directory, true).unwrap();
    for name in ["Data", "Guard"] {
        files::directory(&directory.join(name), true).unwrap();
    }
    let service = ServiceId {
        network: NetworkId {
            network: id(1),
            incarnation: id(2),
        },
        service: id(3),
    };
    let room = RoomId {
        home: service,
        local: id(4),
    };
    let signer = files::create_key(&directory.join("Signing.key")).unwrap();
    let database = storage::Key::create(directory.join("Database.key")).unwrap();
    let store = storage::Store::create(
        directory.join("Data"),
        directory.join("Guard"),
        &database,
        *service.service.as_bytes(),
        service::storage_limits(),
    )
    .unwrap();
    let mut home = Home::create(store, service, signer.clone()).unwrap();
    home.store.write(|db|{db.execute("INSERT INTO hrc_rooms(id,room,name,topic,owner,revision,sequence,created,mode) VALUES(?1,?2,'Welcome','','owner',1,0,0,0)",rusqlite::params![room.to_string(),crate::home::types::encode(&room)?])?;Ok(storage::Commit::new((),b"fixture room".to_vec()))}).unwrap();
    let clock_key = SigningKey::from_bytes(&[8; 32]);
    let clock = witness(&directory, &clock_key);
    let config = Config {
        descriptor: service::Descriptor {
            version: 1,
            home: service,
            signing_key: Id::from_bytes(signer.verifying_key().to_bytes()),
            protocol: PROTOCOL.into(),
            text_profile: crate::text::PROFILE.into(),
        },
        companion: directory.clone(),
        clock,
        motd: String::new(),
        room_creation: crate::home::RoomCreationPolicy::AllowList { accounts: vec![] },
    };
    files::create_json(&directory.join("Service.json"), &config).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let shared = Arc::new(Shared {
        config: config.clone(),
        signer,
        home: home_access::HomeAccess::new(home, Arc::clone(&stop)),
        companion: Companion::new(&directory).unwrap(),
        boot: id(9),
        handshakes: AtomicUsize::new(0),
        ingress: Mutex::new(Budget::new(64, 16)),
        diagnostics: None,
        diagnostic_lines: AtomicUsize::new(0),
        authority_admission: admission::Admission::default(),
        federation_routes: vec![],
        stop,
    });
    let server = Server::start(&directory, Arc::clone(&shared)).unwrap();
    let registrar = files::create_key(&root.join("Registrar.key")).unwrap();
    let binding = Binding {
        directory: directory.clone(),
        home: service,
        service_key: config.descriptor.signing_key,
        registrar_key_file: root.join("Registrar.key"),
    };
    let binding_path = root.join("Binding.json");
    files::create_json(&binding_path, &binding).unwrap();
    let p = a::Policy {
        enabled: true,
        registrar_key: Id::from_bytes(registrar.verifying_key().to_bytes()),
        rooms: vec![room],
        agents_enabled: true,
        max_agents_per_operator: 2,
    };
    control::configure(&directory, p).unwrap();
    assert!(config.store(&directory).is_err());
    let describe = control::request(&binding_path, &a::Request::new(a::Action::Describe)).unwrap();
    assert!(matches!(describe.result, a::Status::Described { .. }));
    let key = SigningKey::from_bytes(&[10; 32]);
    let recovery = SigningKey::from_bytes(&[11; 32]);
    let candidate = a::Prepare {
        claim_id: id(20),
        native_principal: id(21),
        identity: a::Identity {
            account: AccountId {
                origin: service.network,
                local: id(22),
            },
            endpoint: id(23),
            endpoint_key: Id::from_bytes(key.verifying_key().to_bytes()),
            recovery_key: Id::from_bytes(recovery.verifying_key().to_bytes()),
        },
        classification: a::Classification::Person,
        rooms: vec![room],
        allow_initiate: true,
        allow_agent_replies: false,
        successor: false,
        operator_consent: None,
    };
    witness(&directory, &clock_key);
    let response = control::request(
        &binding_path,
        &a::Request::new(a::Action::Prepare(candidate.clone().into())),
    )
    .unwrap();
    let a::Status::Prepared { invitation, .. } = response.result else {
        panic!()
    };
    let bytes = sign_registration(&candidate.registration(service, invitation.id), &key).unwrap();
    let enrol = a::Request::new(a::Action::Enrol {
        claim_id: candidate.claim_id,
        registration: a::Artifact::new(&bytes),
    });
    witness(&directory, &clock_key);
    let first = control::request(&binding_path, &enrol).unwrap();
    assert!(matches!(first.result, a::Status::Complete { .. }));
    witness(&directory, &clock_key);
    let again = control::request(&binding_path, &enrol).unwrap();
    assert_eq!(
        serde_json::to_value(&first).unwrap(),
        serde_json::to_value(&again).unwrap()
    );
    assert!(config.store(&directory).is_err());
    assert!(
        shared
            .home
            .lock()
            .unwrap()
            .endpoint(candidate.identity.account, candidate.identity.endpoint)
            .unwrap()
            .is_some()
    );
    let wrong = SigningKey::from_bytes(&[99; 32]);
    let reply = control::call(
        &binding,
        &wrong,
        Control::Request {
            request: a::Request::new(a::Action::Describe),
        },
    )
    .unwrap();
    assert_eq!(reply["code"], "RegistrarBinding");

    // A repeated signed control frame is rejected before another Home transaction.
    witness(&directory, &clock_key);
    let nonce = id(240);
    let payload = control::Payload {
        home: service,
        boot: shared.boot,
        nonce,
        expires_boot_ms: clock::boot_ms().unwrap() + 5000,
        control: Control::Request {
            request: a::Request::new(a::Action::Describe),
        },
    };
    let before = shared.home.lock().unwrap().usage().unwrap().commit_counter;
    for replay in [false, true] {
        let (_held, path) = control::socket_directory(&directory).unwrap();
        let mut socket = UnixStream::connect(path).unwrap();
        let end = Instant::now() + Duration::from_secs(2);
        control::send(&mut socket, &payload, &registrar, end).unwrap();
        assert_eq!(control::receive(&mut socket, end).is_err(), replay);
    }
    assert_eq!(
        shared.home.lock().unwrap().usage().unwrap().commit_counter,
        before + 1
    );
    // The public participant helper generates all HRC keys locally and survives a lost profile write.
    let child = root.join("Participant");
    let options = crate::client::admission::Options {
        server: config.descriptor.clone(),
        claim_id: id(30),
        native_principal: id(31),
        classification: a::Classification::Person,
        rooms: vec![room],
        allow_initiate: true,
        allow_agent_replies: false,
        successor: false,
        companion: directory.clone(),
        clock: config.clock.clone(),
    };
    let local = crate::client::admission::prepare(&child, options.clone()).unwrap();
    let retry = crate::client::admission::prepare(&child, options.clone()).unwrap();
    assert_eq!(local.request, retry.request);
    let incomplete = root.join("InterruptedParticipant");
    files::directory(&incomplete, true).unwrap();
    files::create_json(&incomplete.join("Intent.json"), &options).unwrap();
    files::directory(&incomplete.join("Profile"), true).unwrap();
    let retained_key = files::create_key(&incomplete.join("Profile/Endpoint.key")).unwrap();
    let recovered = crate::client::admission::prepare(&incomplete, options.clone()).unwrap();
    assert_eq!(
        recovered.request.identity.endpoint_key,
        Id::from_bytes(retained_key.verifying_key().to_bytes())
    );
    fs::remove_file(incomplete.join("Participant.ready")).unwrap();
    assert_eq!(
        recovered.request,
        crate::client::admission::prepare(&incomplete, options.clone())
            .unwrap()
            .request
    );
    let mut changed = options;
    changed.claim_id = id(32);
    assert!(crate::client::admission::prepare(&child, changed).is_err());
    witness(&directory, &clock_key);
    let prepared = control::request(
        &binding_path,
        &a::Request::new(a::Action::Prepare(local.request.clone().into())),
    )
    .unwrap();
    let a::Status::Prepared { invitation, .. } = prepared.result else {
        panic!()
    };
    let signed = crate::client::admission::registration(&child, &invitation).unwrap();
    assert!(child.join("Recovery.key").exists());
    assert!(!child.join("Profile/Recovery.key").exists());
    // An interrupted join can outlive the invitation and retention pruning. The
    // private registrar refreshes only expiry, so the local signed bytes stay exact.
    let mut expired = invitation.clone();
    expired.expires_ms = 0;
    shared
        .home
        .lock()
        .unwrap()
        .store
        .write(|db| {
            db.execute(
                "UPDATE hrc_admission_claims SET invitation=?1,expires=0 WHERE id=?2",
                rusqlite::params![
                    crate::home::types::encode(&expired)?,
                    local.request.claim_id.as_hex()
                ],
            )?;
            db.execute(
                "DELETE FROM hrc_invitations WHERE id=?1",
                [expired.id.as_hex()],
            )?;
            Ok(storage::Commit::new(
                (),
                b"test expired pending claim".to_vec(),
            ))
        })
        .unwrap();
    witness(&directory, &clock_key);
    let refreshed = control::request(
        &binding_path,
        &a::Request::new(a::Action::Prepare(local.request.clone().into())),
    )
    .unwrap();
    let a::Status::Prepared {
        invitation: refreshed,
        ..
    } = refreshed.result
    else {
        panic!()
    };
    assert_eq!(refreshed.id, invitation.id);
    assert!(refreshed.expires_ms > expired.expires_ms);
    assert_eq!(
        signed,
        crate::client::admission::registration(&child, &refreshed).unwrap()
    );
    fs::remove_file(child.join("Profile/Profile.json")).unwrap();
    assert_eq!(
        signed,
        crate::client::admission::registration(&child, &invitation).unwrap()
    );
    witness(&directory, &clock_key);
    let enrolled = control::request(
        &binding_path,
        &a::Request::new(a::Action::Enrol {
            claim_id: local.request.claim_id,
            registration: signed,
        }),
    )
    .unwrap();
    assert!(matches!(enrolled.result, a::Status::Complete { .. }));
    witness(&directory, &clock_key);
    let retired = control::request(
        &binding_path,
        &a::Request::new(a::Action::Revoke {
            claim_id: local.request.claim_id,
        }),
    )
    .unwrap();
    assert!(
        matches!(retired.result,a::Status::Revoked{account:Some(account),more_affected:false,..}if account==local.request.identity.account)
    );
    witness(&directory, &clock_key);
    let retry = control::request(
        &binding_path,
        &a::Request::new(a::Action::Status {
            claim_id: local.request.claim_id,
        }),
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(&retired).unwrap(),
        serde_json::to_value(retry).unwrap()
    );
    assert!(
        shared
            .home
            .lock()
            .unwrap()
            .endpoint(
                local.request.identity.account,
                local.request.identity.endpoint
            )
            .unwrap()
            .is_none()
    );
    drop(server);
    assert!(!directory.join("Admission.sock").exists());
    drop(shared);
    let mut reopened = Home::open(
        config.store(&directory).unwrap(),
        service,
        files::key(&directory.join("Signing.key")).unwrap(),
    )
    .unwrap();
    let response = reopened
        .admission_request(
            &a::Request::new(a::Action::Status {
                claim_id: candidate.claim_id,
            }),
            Id::from_bytes(registrar.verifying_key().to_bytes()),
            witness(&directory, &clock_key).sample().unwrap(),
        )
        .unwrap();
    assert_eq!(
        serde_json::to_value(response).unwrap(),
        serde_json::to_value(first).unwrap()
    );
    drop(reopened);
    fs::remove_dir_all(root).unwrap();
}
