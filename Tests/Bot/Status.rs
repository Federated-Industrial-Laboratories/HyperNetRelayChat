use super::*;
#[test]
fn recovered_dependency_clears_current_failure_but_retains_history_and_model_state() {
    let mut emitted = Vec::new();
    {
        let mut callback = |value: &Observation| emitted.push(value.clone());
        let mut reporter = Reporter::new(&mut callback);
        reporter.failure(
            &Error::Client(crate::client::Error::Clock),
            Phase::Retrying,
            Some(2000),
        );
        reporter.success(true);
        assert!(reporter.observation.current_failure.is_none());
        assert!(reporter.observation.last_failure.is_some());
        assert!(reporter.observation.last_success_ms.is_some());
        reporter.model(&Err(Error::ModelIncomplete));
        reporter.success(true);
        assert!(reporter.observation.model_failure.is_some());
        reporter.model(&Ok(Some("Ready".into())));
        assert!(reporter.observation.model_failure.is_none());
        assert!(reporter.observation.last_model_success_ms.is_some());
        assert_eq!(
            reporter.observation.last_failure.as_ref().unwrap().code,
            "BotModelReplyTokensExhausted"
        );
    }
    assert!(emitted.iter().any(|v| v.phase == Phase::Retrying));
    assert!(
        emitted
            .iter()
            .any(|v| v.phase == Phase::Ready && v.current_failure.is_none())
    );
}
#[test]
fn storage_diagnosis_keeps_operation_and_retries_only_transient_categories() {
    for (source, retries) in [
        (crate::storage::Error::Busy, true),
        (crate::storage::Error::Deadline, true),
        (crate::storage::Error::Quota, false),
        (crate::storage::Error::Fenced, false),
        (crate::storage::Error::Continuity, false),
    ] {
        let error = Error::Storage {
            operation: "State.advance",
            source,
        };
        assert_eq!(
            super::super::runtime::retry_delay(&error).is_some(),
            retries
        );
        let detail = Failure::new(&error, 1);
        assert_eq!(detail.operation.as_deref(), Some("State.advance"));
        assert_ne!(detail.code, "BotStateUnavailable");
    }
}
