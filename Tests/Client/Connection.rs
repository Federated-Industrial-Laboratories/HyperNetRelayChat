// SPDX-License-Identifier: Apache-2.0
//! Session setup retains typed failures, original deadlines and a finite retry count.
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
    for error in [Error::Authentication, Error::Frame] {
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
fn transient_preparation_retains_its_type_and_original_setup_budget() {
    use crate::hypernet::Error as HyperNet;
    for source in [
        HyperNet::Timeout,
        HyperNet::Unavailable,
        HyperNet::Closed,
        HyperNet::Capacity,
        HyperNet::Busy,
        HyperNet::NotActive,
    ] {
        let error = Error::Connect(source);
        assert!(error.retryable_session());
        let deadline = clock::boot_ms().unwrap() + 30_000;
        let mut calls = 0;
        let mut error = Some(error);
        let value = establish(deadline, |end| {
            assert_eq!(end, deadline);
            calls += 1;
            error.take().map_or(Ok(7), Err)
        })
        .unwrap();
        assert_eq!((value, calls), (7, 2));
    }
    let mut calls = 0;
    let result = establish::<()>(clock::boot_ms().unwrap() + 30_000, |_| {
        calls += 1;
        Err(Error::Connect(HyperNet::Timeout))
    });
    assert!(matches!(result, Err(Error::Connect(HyperNet::Timeout))));
    assert_eq!(calls, 3);

    let deadline = clock::boot_ms().unwrap() + 200;
    calls = 0;
    let result = establish::<()>(deadline, |end| {
        assert_eq!(end, deadline);
        calls += 1;
        std::thread::sleep(Duration::from_millis(210));
        Err(Error::Connect(HyperNet::Timeout))
    });
    assert!(matches!(result, Err(Error::Connect(HyperNet::Timeout))));
    assert_eq!(calls, 1, "expired original setup budget was renewed");
}

#[test]
fn explicit_preparation_refusal_and_invalid_context_are_terminal() {
    use crate::hypernet::Error as HyperNet;
    for wrap in [Error::Companion, Error::Connect] {
        for source in [
            HyperNet::Refused,
            HyperNet::InvalidInput,
            HyperNet::Path,
            HyperNet::Ownership,
            HyperNet::Changed,
            HyperNet::Frame,
            HyperNet::Protocol,
            HyperNet::UnsupportedVersion,
            HyperNet::Clock,
        ] {
            let expected = source.code();
            let error = wrap(source);
            assert!(!error.retryable_session());
            let mut error = Some(error);
            let result = establish::<()>(clock::boot_ms().unwrap() + 30_000, |_| {
                Err(error
                    .take()
                    .expect("permanent preparation failure was retried"))
            });
            let failure = result.unwrap_err();
            match &failure {
                Error::Companion(source) | Error::Connect(source) => {
                    assert_eq!(source.code(), expected)
                }
                _ => panic!("typed preparation category was lost"),
            }
            assert_eq!(super::super::Error::Network(failure).retry_delay_ms(), None);
        }
    }
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
