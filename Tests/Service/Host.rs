// SPDX-License-Identifier: Apache-2.0
//! The shared host adapter completes through the actual running Home control socket.
use super::*;
use crate::{conversations, home::AuthenticatedSession, service::host as adapter};
struct Fixture {
    root: PathBuf,
    stop: std::sync::mpsc::Sender<()>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = self.stop.send(());
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
        let _ = fs::remove_dir_all(&self.root);
    }
}
#[test]
fn shared_host_finish_configures_running_home_and_never_restores_disabled_policy() {
    let root = std::env::temp_dir().join(format!("hrc-host-boundary-{}", Id::random().unwrap()));
    files::directory(&root, true).unwrap();
    let clock_key = SigningKey::from_bytes(&[33; 32]);
    let clock = witness(&root, &clock_key);
    let (stop, receive) = std::sync::mpsc::channel();
    let clock_root = root.clone();
    let worker = thread::spawn(move || {
        while matches!(
            receive.recv_timeout(Duration::from_millis(100)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout)
        ) {
            witness(&clock_root, &clock_key);
        }
    });
    let fixture = Fixture {
        root,
        stop,
        worker: Some(worker),
    };
    let directory = fixture.root.join("HRC");
    let options = adapter::Options {
        home: ServiceId {
            network: NetworkId {
                network: id(1),
                incarnation: id(2),
            },
            service: id(3),
        },
        receiver_companion: fixture.root.join("Receiver"),
        clock: clock.clone(),
        owner_principal: id(20),
        owner_companion: fixture.root.join("OwnerCompanion"),
        nickname: "Owner".into(),
        motd: "Welcome".into(),
        agents_enabled: true,
        max_agents_per_operator: 2,
    };
    let prepared = adapter::request(
        &directory,
        adapter::Request {
            format: adapter::FORMAT.into(),
            action: adapter::Action::Prepare(Box::new(options.clone())),
        },
    )
    .unwrap();
    let config = Config::load(&prepared.service_directory).unwrap();
    let signer = files::key(&prepared.service_directory.join("Signing.key")).unwrap();
    let mut home = Home::open(
        config.store(&prepared.service_directory).unwrap(),
        options.home,
        signer.clone(),
    )
    .unwrap()
    .with_room_creation(config.room_creation.clone())
    .unwrap();
    let owner = crate::client::Profile::load(&prepared.owner_profile).unwrap();
    let endpoint = home
        .endpoint(owner.registration.account, owner.registration.endpoint)
        .unwrap()
        .unwrap();
    let key = files::key(&prepared.owner_profile.join("Endpoint.key")).unwrap();
    let session = AuthenticatedSession::new(&endpoint, options.owner_principal, id(21), 1).unwrap();
    let window = home
        .open_window(&endpoint, clock.sample().unwrap(), &|| true)
        .unwrap();
    let action = crate::protocol::Action {
        home: options.home,
        operation_id: OperationId {
            window: window.id,
            operation: id(22),
        },
        actor: Actor::Direct {
            acting: endpoint.acting,
        },
        target: Target::Service,
        operation: Operation::RoomCreate,
        body: Value::serialized(&conversations::Create {
            name: "general".into(),
            confidentiality: RoomConfidentiality::Community,
        })
        .unwrap(),
        expected: Default::default(),
        approval: None,
        agreement: None,
    };
    let bytes = sign_action(&action, &key).unwrap();
    let response = home
        .execute(
            &verify_action(&bytes, &key.verifying_key()).unwrap(),
            &session,
            clock.sample().unwrap(),
            &|| true,
        )
        .unwrap();
    let Outcome::Committed { body, .. } = &response.outcome else {
        panic!("owner room creation refused: {:?}", response.outcome)
    };
    let room = body
        .deserialized::<crate::messaging::Committed>()
        .unwrap()
        .room
        .unwrap();
    // Model an interruption after the signed owner effect was retained, before
    // live policy configuration. The other fixture exercises actual client I/O.
    files::create(&directory.join("General.Action.cbor"), &bytes).unwrap();
    files::create(
        &directory.join("General.Outcome.cbor"),
        &canonical_encode(
            &Value::serialized(&response.outcome).unwrap(),
            ORDINARY_FRAME_BYTES,
        )
        .unwrap(),
    )
    .unwrap();
    files::create_json(&directory.join("Nickname.done"), &true).unwrap();
    let stopped = Arc::new(AtomicBool::new(false));
    let shared = Arc::new(Shared {
        config: config.clone(),
        signer,
        home: home_access::HomeAccess::new(home, Arc::clone(&stopped)),
        companion: Companion::new(&prepared.service_directory).unwrap(),
        boot: id(23),
        handshakes: AtomicUsize::new(0),
        ingress: Mutex::new(Budget::new(64, 16)),
        diagnostics: None,
        diagnostic_lines: AtomicUsize::new(0),
        authority_admission: admission::Admission::default(),
        federation_routes: vec![],
        stop: stopped,
    });
    let server = Server::start(&prepared.service_directory, Arc::clone(&shared)).unwrap();
    let ready = adapter::request(
        &directory,
        adapter::Request {
            format: adapter::FORMAT.into(),
            action: adapter::Action::Finish,
        },
    )
    .unwrap();
    assert_eq!(ready.status, "Ready");
    assert_eq!(ready.rooms, vec![room]);
    assert!(config.store(&prepared.service_directory).is_err());
    let described = control::request(
        &ready.admission_binding,
        &a::Request::new(a::Action::Describe),
    )
    .unwrap();
    let a::Status::Described { mut policy, .. } = described.result else {
        panic!()
    };
    assert!(policy.enabled);
    assert!(policy.agents_enabled);
    assert_eq!(policy.max_agents_per_operator, 2);
    assert_eq!(policy.rooms, vec![room]);
    policy.enabled = false;
    control::configure(&prepared.service_directory, policy).unwrap();
    fs::remove_file(directory.join("Ready.json")).unwrap(); // Lost local result after Home committed; host disabled it later.
    let again = adapter::request(
        &directory,
        adapter::Request {
            format: adapter::FORMAT.into(),
            action: adapter::Action::Finish,
        },
    )
    .unwrap();
    assert_eq!(
        serde_json::to_value(&ready).unwrap(),
        serde_json::to_value(&again).unwrap()
    );
    let described = control::request(
        &ready.admission_binding,
        &a::Request::new(a::Action::Describe),
    )
    .unwrap();
    assert!(matches!(
        described.result,
        a::Status::Described {
            policy: a::Policy { enabled: false, .. },
            ..
        }
    ));
    let changed = a::Policy {
        enabled: true,
        registrar_key: id(24),
        rooms: vec![room],
        agents_enabled: true,
        max_agents_per_operator: 2,
    };
    assert!(control::configure_host(&prepared.service_directory, changed).is_err());
    let again = adapter::request(
        &directory,
        adapter::Request {
            format: adapter::FORMAT.into(),
            action: adapter::Action::Prepare(Box::new(options)),
        },
    )
    .unwrap();
    assert_eq!(again.rooms, vec![room]);
    drop(server);
    drop(shared);
    assert!(config.store(&prepared.service_directory).is_ok());
}
