// SPDX-License-Identifier: Apache-2.0
use super::*;
use std::{path::PathBuf, time::Duration};
fn configuration() -> Configuration {
    Configuration::at(PathBuf::from("/tmp/HrcSubnetContract"))
}
fn inventory(subnets: &[&str]) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({"version":1,"complete":true,"ipv4Subnets":subnets}))
        .unwrap()
}

#[test]
fn fresh_allocation_detects_containing_contained_and_boundary_overlaps() {
    let c = configuration();
    assert!(conflicts(&c, &inventory(&[])).unwrap().is_empty());
    assert_eq!(
        conflicts(&c, &inventory(&["10.89.0.0/16"])).unwrap().len(),
        4
    );
    assert_eq!(
        conflicts(&c, &inventory(&["10.89.220.42/32"])).unwrap(),
        ["10.89.220.0/24"]
    );
    assert_eq!(
        conflicts(&c, &inventory(&["10.89.223.0/24"])).unwrap(),
        ["10.89.223.0/24"]
    );
    assert!(
        conflicts(&c, &inventory(&["10.89.219.0/24", "10.89.224.0/24"]))
            .unwrap()
            .is_empty()
    );
    assert_eq!(conflicts(&c, &inventory(&["0.0.0.0/0"])).unwrap().len(), 4);
}

#[test]
fn malformed_or_incomplete_inventory_never_proves_free_subnets() {
    let c = configuration();
    for bytes in [
        br#"{"version":1,"complete":false,"ipv4Subnets":[]}"#.to_vec(),
        br#"{"version":2,"complete":true,"ipv4Subnets":[]}"#.to_vec(),
        br#"{"version":1,"complete":true,"ipv4Subnets":[],"ignored":true}"#.to_vec(),
        inventory(&["10.89.220.1/24"]),
        inventory(&["10.89.220.0/33"]),
        inventory(&["10.89.220.0/024"]),
        inventory(&["::/0"]),
        inventory(&["invalid"]),
        inventory(&vec!["10.89.220.0/24"; 1025]),
        vec![b' '; 65537],
    ] {
        assert!(conflicts(&c, &bytes).is_err());
    }
}

#[test]
fn resume_requires_exact_private_journal_and_does_not_claim_free_subnets() {
    let root = std::env::temp_dir().join(format!(
        "hrc-subnets-{}",
        &hrc::protocol::Id::random().unwrap().as_hex()[..16]
    ));
    files::directory(&root, true).unwrap();
    let mut c = Configuration::at(root.clone());
    c.core = PathBuf::from("/usr/bin/false");
    assert!(!resuming(&c).unwrap());
    let cancel = AtomicBool::new(false);
    let end = Instant::now() + Duration::from_secs(5);
    assert!(!requirement(&c, &cancel, end).unwrap().ready);
    let journal = engine::Journal {
        format: "HrcHosting/1".into(),
        configuration_digest: engine::config_digest(&c).unwrap(),
        image: String::new(),
        created_ms: 1,
        expires_ms: 2,
        phase: "Preparing".into(),
        ids: Default::default(),
        results: Default::default(),
        artifacts: Default::default(),
        completed: false,
    };
    let path = root.join("Hosting.json");
    files::create_json(&path, &journal).unwrap();
    let observed = requirement(&c, &cancel, end).unwrap();
    assert!(observed.ready);
    assert_eq!(observed.component, "Existing hosting configuration");
    assert!(observed.action.contains("free subnets are not inferred"));
    let mut changed = c.clone();
    changed.subnet_octet -= 1;
    assert!(resuming(&changed).is_err());
    fs::remove_file(&path).unwrap();
    std::os::unix::fs::symlink(root.join("missing"), &path).unwrap();
    assert!(resuming(&c).is_err());
    fs::remove_file(&path).unwrap();
    files::create(&path, b"{}").unwrap();
    assert!(resuming(&c).is_err());
    fs::remove_dir_all(root).unwrap();
}
