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

fn review() -> RenewalPreview {
    RenewalPreview {
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
    }
}
#[test]
fn review_binds_current_artifacts_expiry_and_exact_granted_operations() {
    let review = review();
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

#[test]
fn reopened_host_recovers_only_its_exact_unfinished_renewal_review() {
    let root = std::env::temp_dir().join(format!(
        "hrc-renew-{}",
        &hrc::protocol::Id::random().unwrap().as_hex()[..16]
    ));
    native::directory(&root).unwrap();
    let mut c = Configuration::at(root.clone());
    c.core = PathBuf::from("/tmp/Core/Bin/HyperNet");
    c.suite = PathBuf::from("/tmp/Suite/Bin/HyperNetSuite");
    c.publisher_key = PathBuf::from("/tmp/Publisher.pub");
    c.bind_address = "192.0.2.1".parse().unwrap();
    c.advertised_address = c.bind_address;
    c.same_organisation = true;
    let mut review = review();
    review.digest = review_digest(&review).unwrap();
    let mut journal = Journal {
        format: "HrcHosting/1".into(),
        configuration_digest: config_digest(&c).unwrap(),
        image: String::new(),
        created_ms: 1,
        expires_ms: 2_000,
        phase: "Renewing".into(),
        ids: BTreeMap::new(),
        artifacts: BTreeMap::new(),
        results: BTreeMap::from([(
            "renewal/2000".into(),
            json!({"digest":review.digest,"completed":false}),
        )]),
        completed: true,
    };
    native::directory(&root.join("Successor")).unwrap();
    native::directory(&root.join("Successor/2000")).unwrap();
    let path = root.join("Successor/2000/Review.json");
    write(&path, &review).unwrap();
    write(&root.join("Hosting.json"), &journal).unwrap();
    let cancel = AtomicBool::new(false);
    assert_eq!(pending_renewal(&c, &cancel).unwrap().digest, review.digest);
    let original = review.clone();
    review.renewed_permissions[0]["actions"] = json!([29, 30]);
    write(&path, &review).unwrap();
    assert!(matches!(pending_renewal(&c, &cancel), Err(Error::State)));
    review.digest = review_digest(&review).unwrap();
    write(&path, &review).unwrap();
    assert!(matches!(pending_renewal(&c, &cancel), Err(Error::State)));
    write(&path, &original).unwrap();
    journal.results.get_mut("renewal/2000").unwrap()["completed"] = json!(true);
    write(&root.join("Hosting.json"), &journal).unwrap();
    assert!(pending_renewal(&c, &cancel).is_err());
    std::fs::remove_dir_all(root).unwrap();
}
