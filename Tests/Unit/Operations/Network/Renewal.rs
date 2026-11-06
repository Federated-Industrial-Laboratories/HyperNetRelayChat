// SPDX-License-Identifier: Apache-2.0
use super::*;

#[test]
fn deadline_requires_current_whole_seconds_and_both_consent_ceilings() {
    assert!(validate_deadline(1_000, 2_000, 3_000).is_ok());
    for until in [999, 1_000, 2_001, 4_000, 604_802_000] {
        assert!(validate_deadline(1_000, until, 3_000).is_err());
    }
    assert!(validate_deadline(1_000, 604_802_000, u64::MAX).is_err());
}

#[test]
fn review_binds_current_artifacts_expiry_and_exact_granted_operations() {
    let review = RenewalPreview {
        digest: String::new(),
        valid_until_ms: 2_000,
        domain_expires_ms: 2_000,
        host_boot: "boot".into(),
        preserves_network_identity: true,
        proposals: vec![],
        governance_expires_ms: 10_000,
        client_voucher_maximum_ms: 86_390_000,
        client_principal: "principal".into(),
        renewed_permissions: vec![json!({"actions":[30],"service":"one"})],
        artifacts: BTreeMap::from([("route".into(), "digest".into())]),
    };
    let expected = review_digest(&review).unwrap();
    for case in 0..4 {
        let mut changed = review.clone();
        match case {
            0 => changed.valid_until_ms += 1_000,
            1 => changed
                .artifacts
                .insert("route".into(), "changed".into())
                .map(|_| ())
                .unwrap(),
            2 => changed.renewed_permissions[0]["actions"] = json!([29, 30]),
            _ => changed.client_principal = "different".into(),
        }
        assert_ne!(review_digest(&changed).unwrap(), expected);
    }
    let mut displayed = review;
    displayed.digest = expected.clone();
    assert_eq!(review_digest(&displayed).unwrap(), expected);
}
