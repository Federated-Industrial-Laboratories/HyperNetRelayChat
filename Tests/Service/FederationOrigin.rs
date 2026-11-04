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
