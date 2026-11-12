// SPDX-License-Identifier: Apache-2.0
//! Exercise the real request-only socket, credentials, signed challenge and unchanged owner control.
use super::*;

pub(super) fn check_boundary(
    root: &Path,
    directory: &Path,
    shared: &Arc<Shared>,
    registrar: &SigningKey,
    policy: &a::Policy,
    clock_key: &SigningKey,
) {
    let uid = unsafe { libc::geteuid() };
    let path = root.join("Bridge");
    let binding = Binding {
        directory: path.clone(),
        peer_uid: Some(uid),
        home: shared.config.descriptor.home,
        service_key: shared.config.descriptor.signing_key,
        registrar_key_file: root.join("Registrar.key"),
    };
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o7777, 0o711);
    assert_eq!(
        fs::metadata(path.join("Admission.sock")).unwrap().mode() & 0o7777,
        0o666
    );
    let entries: Vec<_> = fs::read_dir(&path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect();
    assert_eq!(entries, vec![std::ffi::OsString::from("Admission.sock")]);
    assert_eq!(fs::metadata(directory).unwrap().mode() & 0o7777, 0o700);
    assert_eq!(
        fs::metadata(directory.join("Admission.sock"))
            .unwrap()
            .mode()
            & 0o7777,
        0o600
    );
    let describe = || Control::Request {
        request: a::Request::new(a::Action::Describe),
    };
    witness(directory, clock_key);
    let result = control::call(&binding, registrar, describe()).unwrap();
    assert_eq!(result["status"], "described");
    let mut wrong = binding.clone();
    wrong.peer_uid = Some(uid + 1);
    assert!(control::call(&wrong, registrar, describe()).is_err());
    wrong = binding.clone();
    wrong.service_key = id(99);
    assert!(control::call(&wrong, registrar, describe()).is_err());
    // A real owner-signed administrative request must fail at the bridge even
    // when it bypasses the client helper's request-only restriction.
    for mismatch in [false, true] {
        let (_held, socket) = control::bridge::directory(&path, uid, false).unwrap();
        let mut socket = UnixStream::connect(socket).unwrap();
        let end = Instant::now() + Duration::from_secs(2);
        let hello = control::receive(&mut socket, end).unwrap();
        assert_eq!(hello.signer, binding.service_key);
        let challenge: control::bridge::Challenge = control::verify(&hello).unwrap();
        let mut disabled = policy.clone();
        disabled.enabled = false;
        let before = shared.home.lock().unwrap().usage().unwrap().commit_counter;
        let payload = Payload {
            home: binding.home,
            boot: challenge.boot,
            nonce: if mismatch { id(98) } else { challenge.nonce },
            expires_boot_ms: challenge.expires_boot_ms,
            control: if mismatch {
                describe()
            } else {
                Control::Configure { policy: disabled }
            },
        };
        control::send(
            &mut socket,
            &payload,
            if mismatch { registrar } else { &shared.signer },
            end,
        )
        .unwrap();
        assert!(control::receive(&mut socket, end).is_err());
        assert_eq!(
            shared.home.lock().unwrap().usage().unwrap().commit_counter,
            before
        );
    }
    // Check SO_PEERCRED independently of a valid signature: this listener is
    // configured for a different real UID and sends no challenge to this peer.
    let denied_path = root.join("DeniedBridge");
    let denied = Server::start_socket(&denied_path, Arc::clone(shared), Some(uid + 1)).unwrap();
    let wrong_peer = Binding {
        directory: denied_path.clone(),
        ..binding.clone()
    };
    assert!(control::call(&wrong_peer, registrar, describe()).is_err());
    drop(denied);
    assert!(!denied_path.join("Admission.sock").exists());
    // An outsider-writable bridge directory is refused before any connection.
    fs::set_permissions(&path, fs::Permissions::from_mode(0o777)).unwrap();
    assert!(control::call(&binding, registrar, describe()).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o711)).unwrap();
    witness(directory, clock_key);
    let result = control::call(&binding, registrar, describe()).unwrap();
    assert_eq!(result["policy"]["enabled"], true);
    assert!(shared.config.store(directory).is_err());
    let queue = root.join("Queue");
    files::directory(&queue, true).unwrap();
    let (_held, socket) = control::socket_directory(&queue).unwrap();
    let listener = UnixListener::bind(&socket).unwrap();
    assert_eq!(
        unsafe { libc::listen(std::os::fd::AsRawFd::as_raw_fd(&listener), 1) },
        0
    );
    let first = control::bridge::connect(&socket).unwrap();
    let second = control::bridge::connect(&socket).unwrap();
    let started = Instant::now();
    assert!(control::bridge::connect(&socket).is_err());
    assert!(started.elapsed() < Duration::from_secs(1));
    drop((first, second, listener));
}
