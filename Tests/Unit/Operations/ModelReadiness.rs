use super::*;
#[test]
fn readiness_recovers_refusal_and_clears_current_failure() {
    let mut attempts = 0;
    let mut events = Vec::new();
    poll(
        &AtomicBool::new(false),
        Duration::from_secs(5),
        |_| {
            attempts += 1;
            if attempts == 1 {
                Err(hrc::bot::Error::ModelUnavailable)
            } else {
                Ok(true)
            }
        },
        |phase, _, _, error| {
            events.push((phase.to_owned(), error.map(str::to_owned)));
            Ok(())
        },
    )
    .unwrap();
    assert_eq!(events.last(), Some(&("ready".into(), None)));
    assert!(events.iter().any(|(phase, _)| phase == "waiting"));
}
#[test]
fn cancellation_interrupts_backoff_and_invalid_response_is_not_retried() {
    let cancel = AtomicBool::new(false);
    let mut calls = 0;
    assert!(
        poll(
            &cancel,
            Duration::from_secs(60),
            |_| {
                calls += 1;
                Err(hrc::bot::Error::ModelUnavailable)
            },
            |phase, _, _, _| {
                if phase == "waiting" {
                    cancel.store(true, Ordering::Release);
                }
                Ok(())
            }
        )
        .is_err()
    );
    assert_eq!(calls, 1);
    let mut calls = 0;
    assert!(
        poll(
            &AtomicBool::new(false),
            Duration::from_secs(60),
            |_| {
                calls += 1;
                Err(hrc::bot::Error::ModelResponse)
            },
            |_, _, _, _| Ok(())
        )
        .is_err()
    );
    assert_eq!(calls, 1);
}
