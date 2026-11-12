use super::*;

#[test]
fn room_creation_policy_has_explicit_compatible_operator_commands() {
    let account = format!(
        "{}:{}:{}",
        "01".repeat(32),
        "02".repeat(32),
        "03".repeat(32)
    );
    for prefix in [
        vec![
            "hrc",
            "service",
            "room-creation",
            "--directory",
            "/private/service",
        ],
        vec![
            "hrc",
            "manage",
            "service",
            "room-creation",
            "--config",
            "/private/Service.json",
        ],
    ] {
        assert!(Cli::try_parse_from(prefix.clone()).is_ok());
        for option in ["--allow-all", "--deny-all"] {
            let mut args = prefix.clone();
            args.push(option);
            assert!(Cli::try_parse_from(args).is_ok());
        }
        let mut args = prefix.clone();
        args.extend(["--account", &account]);
        assert!(Cli::try_parse_from(args.clone()).is_ok());
        args.push("--allow-all");
        assert!(Cli::try_parse_from(args).is_err());
        let mut args = prefix;
        args.extend(["--allow-all", "--deny-all"]);
        assert!(Cli::try_parse_from(args).is_err());
    }
}

#[test]
fn desktop_entry_opens_without_command_line_profile_assembly() {
    assert!(Cli::try_parse_from(["hrc"]).unwrap().command.is_none());
    let cli = Cli::try_parse_from(["hrc", "gui", "--setup"]).unwrap();
    assert!(matches!(
        cli.command,
        Some(Command::Gui(desktop::Options {
            profile: None,
            setup: true,
            offline: false
        }))
    ));
    let cli = Cli::try_parse_from(["hrc", "gui", "--offline"]).unwrap();
    assert!(matches!(
        cli.command,
        Some(Command::Gui(desktop::Options {
            profile: None,
            offline: true,
            ..
        }))
    ));
    assert!(Cli::try_parse_from(["hrc", "tui"]).is_err());
}

#[test]
fn old_preferences_default_to_unboxed_classic_history() {
    let old = serde_json::json!({"theme":"Dark", "density":"Comfortable", "textScale":1.0, "quiet":false, "sound":false, "ambiguousWide":false});
    let preferences: hrc::client::Preferences = serde_json::from_value(old).unwrap();
    assert_eq!(preferences.chat_layout, hrc::client::ChatLayout::Classic);
}

#[test]
fn encrypted_history_recovery_requires_an_explicit_sync_flag() {
    let id = |n| hrc::protocol::Id::from_bytes([n; 32]);
    let room = hrc::protocol::RoomId {
        home: hrc::protocol::ServiceId {
            network: hrc::protocol::NetworkId {
                network: id(1),
                incarnation: id(2),
            },
            service: id(3),
        },
        local: id(4),
    }
    .to_string();
    let args = [
        "hrc",
        "crypto",
        "sync",
        "--profile",
        "/private/agent",
        "--room",
        room.as_str(),
    ];
    for requested in [false, true] {
        let mut args = args.to_vec();
        if requested {
            args.push("--resynchronise");
        }
        let cli = Cli::try_parse_from(args).unwrap();
        assert!(
            matches!(cli.command,Some(Command::Crypto {command: conversation::encryption_cli::Command::Sync {resynchronise,..}}) if resynchronise==requested)
        );
    }
}

#[test]
fn endpoint_lifecycle_requires_explicit_purpose_and_secret_files() {
    assert!(
        Cli::try_parse_from([
            "hrc",
            "profile",
            "identity",
            "activate",
            "--directory",
            "/private/new",
            "--recovery-key-file",
            "/private/owner/Recovery.key"
        ])
        .is_ok()
    );
    assert!(
        Cli::try_parse_from([
            "hrc",
            "profile",
            "identity",
            "activate",
            "--directory",
            "/private/new",
            "--recovery-key",
            "secret"
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from([
            "hrc",
            "profile",
            "identity",
            "prepare",
            "--directory",
            "/private/new"
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from([
            "hrc",
            "profile",
            "identity",
            "continuity",
            "--profile",
            "/private/device",
            "--limit",
            "17"
        ])
        .is_err()
    );
    assert!(
        Cli::try_parse_from([
            "hrc",
            "profile",
            "identity",
            "key-create",
            "--output",
            "/private/owner/New.key"
        ])
        .is_ok()
    );
}

#[test]
fn diagnostic_admission_requires_exact_principal_and_bounded_waits() {
    let base = [
        "hrc",
        "transport",
        "probe-serve",
        "--companion",
        "/private/agent",
    ];
    assert!(Cli::try_parse_from(base).is_err());
    for invalid in [
        "0".repeat(64),
        "A".repeat(64),
        "f".repeat(63),
        "\u{1b}".repeat(64),
    ] {
        let mut args = base.to_vec();
        args.extend(["--allow-principal", &invalid]);
        assert!(Cli::try_parse_from(args).is_err());
    }
    let principal = "ab".repeat(32);
    for bound in ["99", "60001"] {
        let mut args = base.to_vec();
        args.extend(["--allow-principal", &principal, "--timeout-ms", bound]);
        assert!(Cli::try_parse_from(args).is_err());
    }
    let mut args = base.to_vec();
    args.extend(["--allow-principal", &principal]);
    assert!(Cli::try_parse_from(args).is_ok());
}

#[test]
fn committed_membership_output_keeps_readiness_failure_and_pending_identity_separate() {
    use hrc::{client, protocol::*};
    let id = |n| Id::from_bytes([n; 32]);
    let home = ServiceId {
        network: NetworkId {
            network: id(1),
            incarnation: id(2),
        },
        service: id(3),
    };
    let response = Response {
        home,
        operation_id: OperationId {
            window: id(4),
            operation: id(5),
        },
        action_digest: id(6),
        outcome: Outcome::Committed {
            event: Some(id(7)),
            position: 1,
            body: hrc::protocol::Value::Null,
        },
    };
    let key = SigningKey::from_bytes(&[10; 32]);
    let action = Action {
        home,
        operation_id: OperationId {
            window: id(4),
            operation: id(8),
        },
        actor: Actor::Direct {
            acting: EndpointActor {
                account: AccountId {
                    origin: home.network,
                    local: id(9),
                },
                endpoint: id(10),
                security_generation: 1,
                enrolment_generation: 1,
                binding_digest: id(11),
            },
        },
        target: Target::Room(RoomId {
            home,
            local: id(12),
        }),
        operation: Operation::CryptoEpochReady,
        body: hrc::protocol::Value::serialized(&hrc::confidential::Ready {
            group: id(13),
            epoch: 1,
            commit_digest: id(14),
            sequence: 1,
            welcome: None,
        })
        .unwrap(),
        expected: Default::default(),
        approval: None,
        agreement: None,
    };
    let signed = verify_action(&sign_action(&action, &key).unwrap(), &key.verifying_key()).unwrap();
    let pending = client::outbox::Pending {
        action: signed.clone(),
        last_response: None,
        abandoned: false,
        held: false,
    };
    let expected = client::json::value(&response).unwrap();
    let output = conversation::encryption_cli::membership_report(
        response,
        Err(client::Error::Refused {
            code: ErrorCode::Unavailable,
            detail: "TransportAuthorityExpired".into(),
            retry_after_ms: Some(1000),
        }),
        Ok(vec![pending]),
    )
    .unwrap();
    assert_eq!(output["response"], expected);
    assert_eq!(output["readiness"]["status"], "Incomplete");
    assert_eq!(
        output["readiness"]["error"]["detail"],
        "TransportAuthorityExpired"
    );
    assert_eq!(output["readiness"]["error"]["retryAfterMs"], 1000);
    assert_eq!(
        output["pendingReadiness"][0]["operationId"],
        client::json::value(&action.operation_id).unwrap()
    );
    assert_eq!(
        output["pendingReadiness"][0]["actionDigest"],
        signed.digest().as_hex()
    );
}

#[test]
fn bot_diagnostic_output_refuses_full_pipe_without_blocking_or_changing_flags() {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    let mut fds = [-1; 2];
    assert_eq!(
        unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_NONBLOCK | libc::O_CLOEXEC) },
        0
    );
    let _read = unsafe { OwnedFd::from_raw_fd(fds[0]) };
    let write = unsafe { OwnedFd::from_raw_fd(fds[1]) };
    let bytes = [b'x'; 4096];
    loop {
        let count = unsafe { libc::write(write.as_raw_fd(), bytes.as_ptr().cast(), bytes.len()) };
        if count < 0 {
            assert_eq!(
                std::io::Error::last_os_error().kind(),
                std::io::ErrorKind::WouldBlock
            );
            break;
        }
    }
    let flags = unsafe { libc::fcntl(write.as_raw_fd(), libc::F_GETFL) };
    assert_eq!(
        unsafe { libc::fcntl(write.as_raw_fd(), libc::F_SETFL, flags & !libc::O_NONBLOCK) },
        0
    );
    let started = std::time::Instant::now();
    assert!(bot_output_to(write.as_raw_fd(), &json!({"status":"BotStatus"})).is_err());
    assert!(started.elapsed() < Duration::from_secs(1));
    assert_eq!(
        unsafe { libc::fcntl(write.as_raw_fd(), libc::F_GETFL) },
        flags & !libc::O_NONBLOCK
    );
    assert!(
        model_request_seconds("241")
            .unwrap_err()
            .contains("5-minute history certificate")
    );
}
