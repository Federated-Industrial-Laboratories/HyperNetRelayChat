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

#[test]
fn malformed_frame_header_keeps_its_permanent_classification() {
    let mut attempts = 0;
    let result = establish::<()>(clock::boot_ms().unwrap() + 30000, |_| {
        attempts += 1;
        FrameHeader::decode([0, 0, 0, 2, 255])
            .map(|_| ())
            .map_err(|_| io::Error::Frame)
            .map_err(handshake_failure)
    });
    assert!(matches!(result, Err(Error::Frame)));
    assert_eq!(attempts, 1);
    assert!(matches!(
        handshake_failure(io::Error::Transport),
        Error::Handshake
    ));
    assert!(matches!(
        handshake_failure(io::Error::Deadline),
        Error::Handshake
    ));
    assert!(matches!(transport_failure(io::Error::Frame), Error::Frame));
    assert!(matches!(
        transport_failure(io::Error::Deadline),
        Error::Transport
    ));
}
