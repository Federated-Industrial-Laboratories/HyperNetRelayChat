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

#[test]
fn latest_observation_does_not_present_an_old_failure_as_current() {
    let failed = serde_json::json!({"status":"BotStatus","observation":{"phase":"retrying","observedMs":1,"lastSuccessMs":null,"lastModelSuccessMs":null,"initialConnectionVerified":false,"modelFailure":null,"currentFailure":{"code":"ClockUnavailable","operation":null,"observedMs":1},"lastFailure":{"code":"ClockUnavailable","operation":null,"observedMs":1},"retryInMs":2000}});
    let mut ready = failed.clone();
    ready["observation"]["phase"] = serde_json::json!("ready");
    ready["observation"]["observedMs"] = serde_json::json!(2);
    ready["observation"]["currentFailure"] = serde_json::Value::Null;
    ready["observation"]["retryInMs"] = serde_json::Value::Null;
    let log = format!("{failed}\n{{\"status\":\"BotReady\"}}\n{ready}\n");
    let report = observation(log.as_bytes()).unwrap();
    assert_eq!(report.phase, hrc::bot::Phase::Ready);
    assert!(report.current_failure.is_none());
    assert!(report.last_failure.is_some());
}
