// SPDX-License-Identifier: Apache-2.0
//! Origin diagnostic categories cannot change or disclose detail in signed public refusals.
use super::*;

fn observed_time() -> clock::TimeBounds {
    let mut now = clock::TimeBounds::test_now();
    now.lower_ms = 1000;
    now.upper_ms = 1500;
    now.boot_ms = 100;
    now
}

#[test]
fn assertion_sampling_delay_consumes_lifetime_without_double_counting_clock_uncertainty() {
    let now = observed_time();
    for delay in [0, 1, 25, 100] {
        let (uncertainty, end) = assertion_time(now, 99, 100 + delay, 1100, 5000, 5000).unwrap();
        assert_eq!(uncertainty, 250);
        assert_eq!(end, 2000 - delay);
    }
}

#[test]
fn assertion_time_keeps_original_clock_and_permission_boundaries() {
    let now = observed_time();
    assert!(matches!(
        assertion_time(now, 101, 102, 1100, 5000, 5000),
        Err(OriginAuthorityFailure::AssertionClockOrBinding)
    ));
    assert!(matches!(
        assertion_time(now, 98, 99, 1100, 5000, 5000),
        Err(OriginAuthorityFailure::AssertionClockOrBinding)
    ));
    let mut wide = now;
    wide.upper_ms += 1;
    assert!(matches!(
        assertion_time(wide, 99, 100, 1100, 5000, 5000),
        Err(OriginAuthorityFailure::AssertionClockOrBinding)
    ));
    let mut reversed = now;
    reversed.upper_ms = 999;
    assert!(assertion_time(reversed, 99, 100, 1100, 5000, 5000).is_err());
    for (after, receipt, authority, challenge) in [
        (600, 1100, 5000, 5000),
        (1100, 1100, 5000, 5000),
        (100, 1100, 1500, 5000),
        (100, 1100, 5000, 1500),
        (100, 6101, 10000, 10000),
    ] {
        assert!(matches!(
            assertion_time(now, 99, after, receipt, authority, challenge),
            Err(OriginAuthorityFailure::AssertionLifetime)
        ));
    }
    assert_eq!(
        assertion_time(now, 99, 100, 1100, 1700, 1800).unwrap().1,
        1700
    );
    assert_eq!(
        assertion_time(now, 99, 100, 1100, 1800, 1700).unwrap().1,
        1700
    );
}

#[test]
fn origin_authority_reasons_are_fixed_bounded_and_distinguishable() {
    use OriginAuthorityFailure::*;
    let reasons = [
        IdentityCheckpointChanged,
        IdentityAuthorityRead,
        IdentityAuthorityBeforePage,
        IdentityPageUnavailable,
        IdentityAuthorityAfterPage,
        ChallengeNotCurrent,
        OriginAuthorityRead,
        AssertionEvidenceUnavailable,
        AssertionClockOrBinding,
        AssertionLifetime,
        AssertionPrivacy,
        AssertionNoLongerPermitted,
    ];
    let codes: std::collections::BTreeSet<_> = reasons.iter().map(|reason| reason.code()).collect();
    assert_eq!(codes.len(), reasons.len());
    assert!(
        codes.iter().all(|code| {
            code.len() <= 40 && code.bytes().all(|byte| byte.is_ascii_alphabetic())
        })
    );
    // The diagnostic enum accepts no principal, payload, nonce or error-detail input.
    let public = serde_json::to_string(&refusal_outcome(Error::Authority)).unwrap();
    assert!(codes.iter().all(|code| !public.contains(*code)));
}

#[test]
fn origin_authority_failure_retains_the_exact_signed_public_refusal() {
    let id = |n| Id::from_bytes([n; 32]);
    let key = SigningKey::from_bytes(&[81; 32]);
    let response = FederationControl::Result {
        profile: FEDERATION_PROFILE,
        home: ServiceId {
            network: NetworkId {
                network: id(1),
                incarnation: id(2),
            },
            service: id(3),
        },
        origin: ServiceId {
            network: NetworkId {
                network: id(4),
                incarnation: id(5),
            },
            service: id(6),
        },
        agreement: AgreementRef {
            id: id(7),
            revision: 1,
            digest: id(10),
        },
        request: id(8),
        operation: Operation::FederationSession,
        request_digest: id(9),
        outcome: refusal_outcome(Error::Authority),
        created_ms: 1000,
        expires_ms: 6000,
    };
    let bytes = sign_federation_control(&response, &key).unwrap();
    let verified = verify_federation_control(&bytes, &key.verifying_key()).unwrap();
    let FederationControl::Result { outcome, .. } = verified.value() else {
        panic!("signed refusal changed kind");
    };
    assert!(matches!(outcome, Outcome::Refused {
        code: ErrorCode::Unavailable, detail, retry_after_ms: Some(1000)
    } if detail == "CurrentAuthorityUnavailable"));
}

#[test]
fn other_origin_refusals_keep_their_existing_classification_and_detail() {
    assert!(
        matches!(refusal_outcome(Error::AuthorityAdmissionBusy), Outcome::Refused {
        code: ErrorCode::Overloaded, detail, retry_after_ms: Some(1000)
    } if detail == "AuthorityAdmissionBusy")
    );
    assert!(matches!(refusal_outcome(Error::ForwardRefused {
        code: ErrorCode::Denied, detail: "CurrentDestinationPolicy".into(), retry_after_ms: None,
    }), Outcome::Refused {
        code: ErrorCode::Denied, detail, retry_after_ms: None,
    } if detail == "CurrentDestinationPolicy"));
}

fn read_action() -> VerifiedAction {
    let id = |n| Id::from_bytes([n; 32]);
    let network = NetworkId {
        network: id(1),
        incarnation: id(2),
    };
    let home = ServiceId {
        network,
        service: id(3),
    };
    let action = Action {
        home,
        operation_id: OperationId {
            window: id(4),
            operation: id(5),
        },
        actor: Actor::Direct {
            acting: EndpointActor {
                account: AccountId {
                    origin: network,
                    local: id(6),
                },
                endpoint: id(7),
                security_generation: 1,
                enrolment_generation: 1,
                binding_digest: id(8),
            },
        },
        target: Target::Room(RoomId { home, local: id(9) }),
        operation: Operation::RoomInspect,
        body: Value::serialized(&crate::home::Empty {}).unwrap(),
        expected: Default::default(),
        approval: None,
        agreement: None,
    };
    let key = SigningKey::from_bytes(&[81; 32]);
    verify_action(&sign_action(&action, &key).unwrap(), &key.verifying_key()).unwrap()
}
fn expiry_outcome(retry: Option<u64>) -> Outcome {
    Outcome::Refused {
        code: ErrorCode::Unavailable,
        detail: "SourceAuthorityExpired".into(),
        retry_after_ms: retry,
    }
}
fn signed_reply(action: &VerifiedAction, outcome: Outcome, key: &SigningKey) -> Frame {
    Frame::new(
        FrameKind::Response,
        sign_response(
            &Response {
                home: action.action().home,
                operation_id: action.action().operation_id,
                action_digest: action.digest(),
                outcome,
            },
            key,
        )
        .unwrap(),
    )
    .unwrap()
}

#[test]
fn exact_source_expiry_recertifies_once_under_the_original_end() {
    let action = read_action();
    let key = SigningKey::from_bytes(&[82; 32]);
    let end = clock::boot_ms().unwrap() + 10_000;
    let mut calls = 0;
    let result = recertify_source(
        end,
        || false,
        |received_end| {
            calls += 1;
            assert_eq!(received_end, end);
            let outcome = if calls == 1 {
                expiry_outcome(Some(0))
            } else {
                Outcome::Result { body: Value::Null }
            };
            forwarded_action_attempt(
                signed_reply(&action, outcome, &key),
                &action,
                &key.verifying_key(),
            )
        },
    )
    .unwrap();
    assert_eq!(calls, 2);
    assert!(matches!(
        verify_response(&result.payload, &key.verifying_key())
            .unwrap()
            .value()
            .outcome,
        Outcome::Result { .. }
    ));

    for local_first in [false, true] {
        let mut calls = 0;
        let result = recertify_source(
            end,
            || false,
            |_| {
                calls += 1;
                if local_first && calls == 1 {
                    return Ok(SourceAttempt::LocalLifetime);
                }
                forwarded_action_attempt(
                    signed_reply(&action, expiry_outcome(None), &key),
                    &action,
                    &key.verifying_key(),
                )
            },
        )
        .unwrap();
        assert_eq!(
            calls, 2,
            "local and remote expiry share one retry allowance"
        );
        assert!(matches!(
            verify_response(&result.payload, &key.verifying_key())
                .unwrap()
                .value()
                .outcome,
            Outcome::Refused {
                code: ErrorCode::Unavailable,
                ..
            }
        ));
    }
}

#[test]
fn other_outcomes_and_ambiguous_effects_never_request_new_source_authority() {
    let action = read_action();
    let key = SigningKey::from_bytes(&[82; 32]);
    for outcome in [
        Outcome::Unknown,
        Outcome::Absent,
        Outcome::Committed {
            event: Some(Id::from_bytes([84; 32])),
            position: 1,
            body: Value::Null,
        },
        Outcome::Result { body: Value::Null },
        Outcome::Refused {
            code: ErrorCode::Denied,
            detail: "SourceAuthorityExpired".into(),
            retry_after_ms: None,
        },
        Outcome::Rejected {
            code: ErrorCode::Unavailable,
            detail: "SourceAuthorityExpired".into(),
        },
        Outcome::Refused {
            code: ErrorCode::Unavailable,
            detail: "FederationAuthorityUnavailable".into(),
            retry_after_ms: Some(0),
        },
    ] {
        let expected = outcome_bytes(&outcome);
        let mut calls = 0;
        let result = recertify_source(
            clock::boot_ms().unwrap() + 10_000,
            || false,
            |_| {
                calls += 1;
                forwarded_action_attempt(
                    signed_reply(&action, outcome.clone(), &key),
                    &action,
                    &key.verifying_key(),
                )
            },
        )
        .unwrap();
        assert_eq!(calls, 1);
        assert_eq!(
            outcome_bytes(
                &verify_response(&result.payload, &key.verifying_key())
                    .unwrap()
                    .value()
                    .outcome
            ),
            expected
        );
    }
    for failure in [Error::Transport, Error::Authentication, Error::Authority] {
        let mut failure = Some(failure);
        let mut calls = 0;
        assert!(
            recertify_source(
                clock::boot_ms().unwrap() + 10_000,
                || false,
                |_| {
                    calls += 1;
                    Err(failure
                        .take()
                        .expect("uncertain or invalid check was repeated"))
                }
            )
            .is_err()
        );
        assert_eq!(calls, 1);
    }
}
fn outcome_bytes(outcome: &Outcome) -> Vec<u8> {
    canonical_encode(&Value::serialized(outcome).unwrap(), ORDINARY_FRAME_BYTES).unwrap()
}

#[test]
fn expiry_refusal_must_have_the_exact_home_signature_and_action_binding() {
    let action = read_action();
    let key = SigningKey::from_bytes(&[82; 32]);
    for fault in 0..5 {
        let mut response = Response {
            home: action.action().home,
            operation_id: action.action().operation_id,
            action_digest: action.digest(),
            outcome: expiry_outcome(None),
        };
        match fault {
            0 => response.home.service = Id::from_bytes([90; 32]),
            1 => response.operation_id.operation = Id::from_bytes([91; 32]),
            2 => response.action_digest = Id::from_bytes([92; 32]),
            _ => {}
        }
        let signer = if fault == 3 {
            SigningKey::from_bytes(&[93; 32])
        } else {
            key.clone()
        };
        let frame = Frame::new(
            if fault == 4 {
                FrameKind::FederationControl
            } else {
                FrameKind::Response
            },
            sign_response(&response, &signer).unwrap(),
        )
        .unwrap();
        assert!(forwarded_action_attempt(frame, &action, &key.verifying_key()).is_err());
    }
}

#[test]
fn recertification_honours_cancellation_expiry_and_retry_guidance_without_new_budget() {
    use std::cell::Cell;
    let end = clock::boot_ms().unwrap() + 10_000;
    let cancelled = Cell::new(false);
    let mut calls = 0;
    assert!(matches!(
        recertify_source(
            end,
            || cancelled.get(),
            |_| {
                calls += 1;
                cancelled.set(true);
                Ok(SourceAttempt::LocalLifetime)
            }
        ),
        Err(Error::AuthorityAdmissionStopped)
    ));
    assert_eq!(calls, 1);
    assert!(recertify_source(0, || false, |_| panic!("expired original end")).is_err());
    let mut calls = 0;
    assert!(matches!(
        recertify_source(
            end,
            || false,
            |_| {
                calls += 1;
                Ok(SourceAttempt::LocalLifetime)
            }
        ),
        Err(Error::Authority)
    ));
    assert_eq!(calls, 2);
    let action = read_action();
    let key = SigningKey::from_bytes(&[82; 32]);
    let mut calls = 0;
    let result = recertify_source(
        end,
        || false,
        |_| {
            calls += 1;
            forwarded_action_attempt(
                signed_reply(&action, expiry_outcome(Some(60_000)), &key),
                &action,
                &key.verifying_key(),
            )
        },
    )
    .unwrap();
    assert_eq!(
        calls, 1,
        "guidance cannot fit, so no new authority call starts"
    );
    assert!(matches!(
        verify_response(&result.payload, &key.verifying_key())
            .unwrap()
            .value()
            .outcome,
        Outcome::Refused {
            retry_after_ms: Some(60_000),
            ..
        }
    ));
}

#[test]
fn known_expiry_refusal_survives_delay_before_retry_but_not_a_new_uncertain_attempt() {
    use std::cell::Cell;
    let action = read_action();
    let key = SigningKey::from_bytes(&[82; 32]);
    let refused = signed_reply(&action, expiry_outcome(Some(0)), &key);
    let pause = Cell::new(false);
    let end = clock::boot_ms().unwrap() + 500;
    let mut calls = 0;
    let result = recertify_source(
        end,
        || {
            if pause.replace(false) {
                // Model scheduling delay after the known refusal, bounded by
                // the same end. No second authority attempt has started yet.
                let left = end.saturating_sub(clock::boot_ms().unwrap());
                std::thread::sleep(Duration::from_millis(left + 1));
            }
            false
        },
        |_| {
            calls += 1;
            assert_eq!(calls, 1, "expired original end cannot start a retry");
            pause.set(true);
            forwarded_action_attempt(refused.clone(), &action, &key.verifying_key())
        },
    )
    .unwrap();
    assert_eq!(calls, 1);
    assert_eq!(result, refused);

    let mut calls = 0;
    let result = recertify_source(
        clock::boot_ms().unwrap() + 10_000,
        || false,
        |_| {
            calls += 1;
            if calls == 1 {
                forwarded_action_attempt(refused.clone(), &action, &key.verifying_key())
            } else {
                Err(Error::Transport)
            }
        },
    );
    assert_eq!(calls, 2);
    assert!(
        matches!(result, Err(Error::Transport)),
        "a prior refusal cannot hide a new uncertain outcome"
    );
}
