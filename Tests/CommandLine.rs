use super::*;

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
