// SPDX-License-Identifier: Apache-2.0
//! Hosting review binds the native topology, finite consent and trusted package helpers.
use super::*;
use std::{net::Ipv4Addr, path::PathBuf};

fn configuration() -> Configuration {
    let mut c = Configuration::at(PathBuf::from("/tmp/HrcHostContract"));
    c.core = PathBuf::from("/tmp/Core/Bin/HyperNet");
    c.suite = PathBuf::from("/tmp/Suite/Bin/HyperNetSuite");
    c.publisher_key = PathBuf::from("/tmp/Publisher.pub");
    c.same_organisation = true;
    c
}
#[test]
fn explicit_host_consent_does_not_claim_independent_relay_privacy() {
    let mut c = configuration();
    assert!(c.validate().is_ok());
    c.same_organisation = false;
    assert!(matches!(c.validate(), Err(Error::Configuration(_))));
}
#[test]
fn recovery_material_and_runtime_state_cannot_overlap() {
    let mut c = configuration();
    c.recovery_directory = c.root.join("Recovery");
    assert!(c.validate().is_err());
    c.recovery_directory = PathBuf::from("/tmp");
    assert!(c.validate().is_err());
}
#[test]
fn review_changes_when_exposure_consent_or_identity_location_changes() {
    let original = configuration();
    let pin = engine::config_digest(&original).unwrap();
    for change in 0..5 {
        let mut c = original.clone();
        match change {
            0 => c.lifetime_hours = 2,
            1 => c.relay_port += 1,
            2 => c.recovery_directory = PathBuf::from("/tmp/AnotherRecovery"),
            3 => c.advertised_address = Ipv4Addr::new(192, 0, 2, 1),
            _ => c.resources.connection_bytes *= 2,
        }
        assert_ne!(engine::config_digest(&c).unwrap(), pin);
    }
}
#[test]
fn native_port_subnet_and_domain_limits_are_checked_before_effects() {
    let original = configuration();
    for change in 0..6 {
        let mut c = original.clone();
        match change {
            0 => c.authority_first_port = 65534,
            1 => c.relay_port = c.authority_first_port,
            2 => c.subnet_octet = 253,
            3 => c.lifetime_hours = 169,
            4 => c.resources.relay_connections = 1,
            _ => c.resources.connection_bytes = 1,
        }
        assert!(c.validate().is_err());
    }
    let mut c = original;
    c.bind_address = Ipv4Addr::UNSPECIFIED;
    assert!(c.validate().is_err());
}
#[test]
fn shell_and_mount_metacharacters_do_not_become_host_configuration() {
    let mut c = configuration();
    c.root = PathBuf::from("/tmp/host:/other");
    assert!(c.validate().is_err());
    let mut value = serde_json::to_value(configuration()).unwrap();
    value["shell"] = serde_json::json!("anything");
    assert!(serde_json::from_value::<Configuration>(value).is_err());
}
#[test]
fn embedded_verifiers_match_the_supported_released_sources() {
    for (data, expected) in [
        (
            include_bytes!("../../../../Source/Operations/Network/Package/Core/Bundle.py")
                .as_slice(),
            "47f636c1d35df1396ee878c30d3872504f5ee31cf54c6768eaf90b9e62a549e4",
        ),
        (
            include_bytes!("../../../../Source/Operations/Network/Package/Core/PackageTrust.py")
                .as_slice(),
            "5f58c67ea68ceca21ed33aa5229d62c17ea647d028dc74a9a637f5aaeb3e8e2d",
        ),
        (
            include_bytes!("../../../../Source/Operations/Network/Package/Suite/Bundle.py")
                .as_slice(),
            "9c738affdd1843a9969eaa6b0254cd39b685e68998c5ece6462d0a9c61b66dde",
        ),
        (
            include_bytes!("../../../../Source/Operations/Network/Package/Suite/PackageTrust.py")
                .as_slice(),
            "84600aa9eec08d549d19a04534ae2ecf1644945687174e6d79a3bb17c1106833",
        ),
    ] {
        assert_eq!(engine::digest(data), expected);
    }
}
