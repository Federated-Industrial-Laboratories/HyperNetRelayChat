use super::*;

#[test]
fn discarded_handoff_reconnects_with_one_unchanged_overall_deadline() {
    let deadline = clock::boot_ms().unwrap() + 30_000;
    let mut calls = 0;
    let value = establish(deadline, |end| {
        assert_eq!(end, deadline);
        calls += 1;
        if calls == 1 {
            Err(Error::Handshake)
        } else {
            Ok(7)
        }
    })
    .unwrap();
    assert_eq!(value, 7);
    assert_eq!(calls, 2);
}

#[test]
fn session_retries_are_bounded_and_do_not_repeat_invalid_identity_or_frames() {
    let deadline = clock::boot_ms().unwrap() + 30_000;
    let mut calls = 0;
    assert!(
        establish::<()>(deadline, |_| {
            calls += 1;
            Err(Error::Handshake)
        })
        .is_err()
    );
    assert_eq!(calls, 3);
    for error in [Error::Authentication, Error::Frame, Error::Connect] {
        let mut error = Some(error);
        assert!(
            establish::<()>(deadline, |_| Err(error
                .take()
                .expect("permanent failure retried")))
            .is_err()
        );
    }
    calls = 0;
    assert!(
        establish(clock::boot_ms().unwrap().saturating_sub(1), |_| {
            calls += 1;
            Ok(())
        })
        .is_err()
    );
    assert_eq!(calls, 0);
}
