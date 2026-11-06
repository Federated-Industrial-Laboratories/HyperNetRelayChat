// SPDX-License-Identifier: Apache-2.0
use super::{Error, bundle, native};
use ciborium::Value as Cbor;
use serde_json::json;
use std::{
    path::Path,
    sync::atomic::AtomicBool,
    time::{Duration, Instant},
};

#[test]
fn stale_companion_socket_can_reach_native_restart() {
    let directory =
        std::env::temp_dir().join(format!("hrc-ipc-{}", hrc::protocol::Id::random().unwrap()));
    std::fs::create_dir(&directory).unwrap();
    let socket = directory.join("Control.sock");
    assert!(!native::socket_live(&socket).unwrap());
    let listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    assert!(native::socket_live(&socket).unwrap());
    drop(listener);
    assert!(socket.exists());
    assert!(!native::socket_live(&socket).unwrap());
    std::fs::remove_dir_all(directory).unwrap();
}

fn n(value: u64) -> Cbor {
    Cbor::Integer(value.into())
}
fn route(connections: u64, allowance: u64, per_connection: u64) -> Vec<u8> {
    let payload = Cbor::Array(vec![
        Cbor::Null,
        Cbor::Null,
        Cbor::Bytes(vec![4; 32]),
        Cbor::Null,
        Cbor::Bytes(vec![5; 32]),
        n(0),
        Cbor::Null,
        n(connections),
        n(allowance),
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
    serde_json::to_vec(
        &json!({"version":1,"protocol":7,"network":vec![1u8;32],"incarnation":vec![2u8;32],
        "destination":{"service":vec![3u8;32]},"limits":{"bytes":per_connection},"voucher":voucher}),
    )
    .unwrap()
}

#[test]
fn reconnect_allowance_covers_each_full_connection_reservation() {
    assert!(matches!(
        bundle::route(&route(16, 268_435_456, 268_435_456), 7),
        Err(Error::RouteBudget)
    ));
    let accepted = bundle::route(&route(128, 34_359_738_368, 268_435_456), 7).unwrap();
    assert_eq!(accepted.connections, 128);
    assert_eq!(accepted.expires_ms, 500_000);
    assert!(bundle::route(&route(128, 34_359_738_368, 268_435_456), 1).is_err());
}

#[test]
fn fresh_profile_requires_complete_exact_grant_reference() {
    let id = "11".repeat(32);
    let digest = "22".repeat(32);
    assert!(!bundle::grant_reference(&id));
    assert!(bundle::grant_reference(&format!("{id}:1:{digest}")));
    for middle in ["0", "01", "-1", "18446744073709551616"] {
        assert!(!bundle::grant_reference(&format!("{id}:{middle}:{digest}")));
    }
    assert!(!bundle::grant_reference(&format!(
        "{id}:1:{}",
        "AA".repeat(32)
    )));
}

#[test]
fn artifact_hash_and_canonical_hex_cannot_be_substituted() {
    let bytes = b"public invitation";
    let value = json!({"sha256":bundle::fingerprint(bytes),"hex":hex::encode(bytes)});
    let artifact: bundle::Artifact = serde_json::from_value(value.clone()).unwrap();
    assert_eq!(artifact.bytes().unwrap(), bytes);
    let mut replaced = value.clone();
    replaced["hex"] = json!(hex::encode(b"different invitation"));
    let artifact: bundle::Artifact = serde_json::from_value(replaced).unwrap();
    assert_eq!(artifact.bytes(), Err(Error::BundleBinding));
    let mut noncanonical = value;
    noncanonical["hex"] = json!(hex::encode(bytes).to_uppercase());
    let artifact: bundle::Artifact = serde_json::from_value(noncanonical).unwrap();
    assert_eq!(artifact.bytes(), Err(Error::BundleBinding));
}

#[test]
fn cancellation_and_original_deadline_precede_process_creation() {
    let missing = Path::new("/a-command-that-must-not-run");
    assert_eq!(
        native::run(
            missing,
            &[],
            &AtomicBool::new(true),
            Instant::now() + Duration::from_secs(1)
        ),
        Err(Error::Cancelled)
    );
    assert_eq!(
        native::run(missing, &[], &AtomicBool::new(false), Instant::now()),
        Err(Error::Deadline)
    );
}

#[test]
fn failed_native_command_never_displays_its_private_stderr() {
    let shell = Path::new("/bin/sh").canonicalize().unwrap();
    let result = native::run(
        &shell,
        &native::strings(&["-c", "printf private-native-detail >&2; exit 7"]),
        &AtomicBool::new(false),
        Instant::now() + Duration::from_secs(5),
    );
    assert_eq!(result, Err(Error::NativeRefused));
    assert!(
        !result
            .unwrap_err()
            .to_string()
            .contains("private-native-detail")
    );
}

#[test]
fn operator_native_diagnostics_strip_controls_and_private_material() {
    let shell = Path::new("/bin/sh").canonicalize().unwrap();
    let args = native::strings(&[
        "-c",
        r#"printf private-success-output; printf '\033[31mError: subnet overlaps\033[0m; missing slirp4netns\n\033]8;;https://hidden.invalid\007helper\033]8;;\007\n\342\200\256direction\nargument %s\n-----BEGIN PRIVATE KEY-----\nprivate-key-material\n-----END PRIVATE KEY-----\ntoken=private-token-material\nabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcdefabcd\n' "$1" >&2; exit 7"#,
        "--key-file",
        "private-argument-value",
    ]);
    let failure = native::run_diagnostic(
        &shell,
        &args,
        &AtomicBool::new(false),
        Instant::now() + Duration::from_secs(5),
    )
    .unwrap_err();
    assert_eq!(failure.category, Error::NativeRefused);
    let detail = failure.detail.unwrap();
    assert!(detail.contains("Error: subnet overlaps") && detail.contains("missing slirp4netns"));
    assert!(detail.contains("helper") && detail.contains("direction"));
    for private in [
        "private-success-output",
        "private-argument-value",
        "private-key-material",
        "private-token-material",
        "abcdef",
        "hidden.invalid",
        "[31m",
    ] {
        assert!(!detail.contains(private), "leaked {private}");
    }
    assert!(
        !detail
            .chars()
            .any(|c| c.is_control() || hrc::text::sensitive(c))
    );
}

#[test]
fn operator_native_reports_are_bounded_and_only_returned_for_failed_exits() {
    let shell = Path::new("/bin/sh").canonicalize().unwrap();
    let cancel = AtomicBool::new(false);
    let end = Instant::now() + Duration::from_secs(5);
    let failure = native::run_diagnostic(
        &shell,
        &native::strings(&["-c", "i=0; while [ $i -lt 800 ]; do printf 'bounded diagnostic ' >&2; i=$((i+1)); done; exit 1"]),
        &cancel,
        end,
    ).unwrap_err();
    let detail = failure.detail.unwrap();
    assert!(detail.len() <= 2048 && detail.ends_with("[truncated]"));
    assert_eq!(
        native::run_diagnostic(
            &shell,
            &native::strings(&["-c", "printf success; printf private-stderr >&2"]),
            &cancel,
            end,
        )
        .unwrap(),
        b"success"
    );
    let stopped = native::run_diagnostic(&shell, &[], &AtomicBool::new(true), end).unwrap_err();
    assert_eq!(stopped.category, Error::Cancelled);
    assert!(stopped.detail.is_none());
    let limited = native::run_diagnostic(
        &shell,
        &native::strings(&["-c", "exec /usr/bin/yes 1>&2"]),
        &cancel,
        end,
    )
    .unwrap_err();
    assert_eq!(limited.category, Error::OutputLimit);
    assert!(limited.detail.is_none());
}

#[test]
fn unbounded_native_stdout_is_stopped_and_reaped() {
    let program = Path::new("/usr/bin/yes").canonicalize().unwrap();
    assert_eq!(
        native::run(
            &program,
            &[],
            &AtomicBool::new(false),
            Instant::now() + Duration::from_secs(5)
        ),
        Err(Error::OutputLimit)
    );
}

#[test]
fn timed_out_native_command_is_not_accepted_as_success() {
    let program = Path::new("/usr/bin/sleep").canonicalize().unwrap();
    assert_eq!(
        native::run(
            &program,
            &native::strings(&["30"]),
            &AtomicBool::new(false),
            Instant::now() + Duration::from_millis(50)
        ),
        Err(Error::Deadline)
    );
}

#[test]
fn external_profile_needs_no_setup_configuration_or_clock_to_open_offline() {
    use hrc::{
        client::Profile,
        clock,
        protocol::*,
        service::{Descriptor, files},
    };
    struct Directory(std::path::PathBuf);
    impl Drop for Directory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    let directory = Directory(
        std::env::temp_dir().join(format!("hrc-onboarding-{}", Id::random().unwrap().as_hex())),
    );
    files::directory(&directory.0, true).unwrap();
    let profile_path = directory.0.join("Profile");
    files::directory(&profile_path, true).unwrap();
    let key = files::create_key(&profile_path.join("Endpoint.key")).unwrap();
    let public = Id::from_bytes(key.verifying_key().to_bytes());
    let network = NetworkId {
        network: Id::random().unwrap(),
        incarnation: Id::random().unwrap(),
    };
    let home = ServiceId {
        network,
        service: Id::random().unwrap(),
    };
    let profile = Profile {
        server: Descriptor {
            version: 1,
            home,
            signing_key: public,
            protocol: "hrc/1".into(),
            text_profile: hrc::text::PROFILE.into(),
        },
        registration: AccountRegistration {
            home,
            account: AccountId {
                origin: network,
                local: Id::random().unwrap(),
            },
            endpoint: Id::random().unwrap(),
            endpoint_key: public,
            transport_principal: public,
            recovery_key: public,
            classification: AccountClass::Human,
            invitation: Id::random().unwrap(),
        },
        companion: directory.0.join("ExternalCompanion"),
        clock: clock::Config {
            observation: directory.0.join("NoObservation"),
            monitor_key: public.as_hex(),
        },
        federation: None,
        agreements: vec![],
    };
    files::create_json(&profile_path.join("Profile.json"), &profile).unwrap();
    assert!(super::prepare_existing(&profile_path, true, &AtomicBool::new(false)).is_ok());
    // Runtime ownership remains external when no explicit local configuration exists.
    assert!(super::prepare_existing(&profile_path, false, &AtomicBool::new(false)).is_ok());
    assert!(!directory.0.join("OnboardingRuntime.json").exists());
    assert!(!profile.companion.exists());
}

struct SetupDirectory(std::path::PathBuf);
impl SetupDirectory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "hrc-setup-{}",
            hrc::protocol::Id::random().unwrap()
        ));
        hrc::service::files::directory(&path, true).unwrap();
        Self(path)
    }
}
impl Drop for SetupDirectory {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

#[test]
fn socket_picker_includes_local_chrony_socket_without_accepting_symlink() {
    let directory = SetupDirectory::new();
    let socket = directory.0.join("chronyd.sock");
    let _listener = std::os::unix::net::UnixDatagram::bind(&socket).unwrap();
    let alias = directory.0.join("alias.sock");
    std::os::unix::fs::symlink(&socket, &alias).unwrap();
    let result = super::runtime::perform(
        super::runtime::Task::Browse(directory.0.clone()),
        super::RuntimeConfig::at(directory.0.clone()),
        &AtomicBool::new(false),
    )
    .unwrap();
    let (_, entries) = result.listing.unwrap();
    assert!(entries.contains(&(socket.clone(), false)));
    assert!(!entries.iter().any(|(path, _)| path == &alias));
    assert!(native::private_socket(&socket).is_ok());
    assert_eq!(
        native::private_socket(&alias),
        Err(Error::ClockPrerequisite)
    );
}

#[test]
fn interrupted_clock_initialisation_recovers_same_validated_signer_and_pin() {
    use hrc::service::files;
    let directory = SetupDirectory::new();
    let mut config = super::RuntimeConfig::at(directory.0.clone());
    config.chronyc = "/usr/bin/chronyc".into();
    files::directory(&config.clock_directory, true).unwrap();
    files::create_json(
        &config.clock_directory.join("ClockConfig.json"),
        &json!({
            "chronyc":config.chronyc,"socket":config.chrony_socket,
            "exportDirectory":config.clock_directory.join("Public"),
        }),
    )
    .unwrap();
    let key = ed25519_dalek::SigningKey::from_bytes(&[9; 32]);
    let public = hex::encode(key.verifying_key().to_bytes());
    let signer = config.clock_directory.join("ClockSigner.json");
    files::create_json(
        &signer,
        &json!({"secretKey":hex::encode(key.to_bytes()),"publicKey":public}),
    )
    .unwrap();
    let original = files::read(&signer, 4096).unwrap();
    // Simulates initialise-export completing before cancellation prevented saving its returned pin.
    assert!(config.clock_monitor_key.is_empty());
    super::runtime::recover_clock_identity(&mut config).unwrap();
    assert_eq!(config.clock_monitor_key, public);
    let persisted =
        super::RuntimeConfig::load(&directory.0.join("OnboardingRuntime.json")).unwrap();
    assert_eq!(persisted.clock_monitor_key, public);
    assert_eq!(files::read(&signer, 4096).unwrap(), original);
    // Neither a caller-supplied different pin nor inconsistent private identity can be adopted.
    config.clock_monitor_key = "01".repeat(32);
    assert_eq!(
        super::runtime::recover_clock_identity(&mut config),
        Err(Error::ClockUnavailable)
    );
    assert_eq!(
        super::RuntimeConfig::load(&directory.0.join("OnboardingRuntime.json"))
            .unwrap()
            .clock_monitor_key,
        public
    );
    config.clock_monitor_key.clear();
    native::replace_file(
        &signer,
        &serde_json::to_vec(&json!({"secretKey":"02".repeat(32),"publicKey":public})).unwrap(),
    )
    .unwrap();
    assert_eq!(
        super::runtime::recover_clock_identity(&mut config),
        Err(Error::ClockUnavailable)
    );
}

#[test]
fn private_observer_is_explicit_local_configuration_and_remains_optional() {
    let directory = SetupDirectory::new();
    let mut config = super::RuntimeConfig::at(directory.0.clone());
    config.save().unwrap();
    let path = directory.0.join("OnboardingRuntime.json");
    assert!(
        super::RuntimeConfig::load(&path)
            .unwrap()
            .private_chrony
            .is_none()
    );
    config.private_chrony = Some(super::PrivateChrony {
        executable: "/usr/sbin/chronyd".into(),
        configuration: directory.0.join("chrony.conf"),
    });
    config.save().unwrap();
    let observer = super::RuntimeConfig::load(&path)
        .unwrap()
        .private_chrony
        .unwrap();
    assert_eq!(observer.configuration, directory.0.join("chrony.conf"));
    config.private_chrony.as_mut().unwrap().configuration = "relative.conf".into();
    assert_eq!(config.save(), Err(Error::LocalConfiguration));
}
