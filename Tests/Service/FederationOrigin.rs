// SPDX-License-Identifier: Apache-2.0
//! Origin diagnostic categories cannot change or disclose detail in signed public refusals.
use super::*;

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
