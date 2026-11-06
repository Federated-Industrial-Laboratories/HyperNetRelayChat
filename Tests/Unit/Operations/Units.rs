// SPDX-License-Identifier: Apache-2.0
use super::*;
#[test]
fn distinct_definition_ids_cannot_control_the_same_unit() {
    let first = hrc::protocol::Id::from_bytes([1; 32]);
    let mut bytes = [1; 32];
    bytes[31] = 2;
    let second = hrc::protocol::Id::from_bytes(bytes);
    let a = name("bot", first);
    let b = name("bot", second);
    assert_ne!(a, b);
    assert!(unit(&a).is_ok());
    assert!(unit(&b).is_ok());
    assert_ne!(name("model", first), a);
}
#[test]
fn unrelated_units_and_option_injection_are_refused() {
    for value in [
        "ssh.service",
        "--all",
        "hrc-managed-bot-*",
        "hrc-managed-bot-x\nssh.service",
        "hrc-managed-bot-x.service",
    ] {
        assert!(unit(value).is_err());
    }
}
