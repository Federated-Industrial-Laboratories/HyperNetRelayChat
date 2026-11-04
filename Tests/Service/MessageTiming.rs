// SPDX-License-Identifier: Apache-2.0
//! Bound optional message observations without changing service outcomes.
use super::*;
use crate::protocol::{ErrorCode, Value};

#[test]
fn disabled_rate_limited_and_exhausted_observations_never_sample() {
    assert!(begin(false, Instant::now()).is_none());
    let mut sampler = Sampler::new();
    for expected in 1..=4 {
        assert_eq!(sampler.admit(1000), Some(expected));
    }
    assert_eq!(sampler.admit(1000), None);
    assert_eq!(sampler.admit(1499), None);
    assert_eq!(sampler.admit(1500), Some(5));
    for expected in 6..=MAXIMUM_SAMPLES {
        assert_eq!(sampler.admit(u64::from(expected) * 500), Some(expected));
    }
    for _ in 0..16 {
        assert_eq!(sampler.admit(u64::MAX), None);
    }
    assert_eq!(sampler.issued, MAXIMUM_SAMPLES);
}

#[test]
fn sampler_contention_drops_observation_without_waiting_or_consuming_a_number() {
    let sampler = Mutex::new(Sampler::new());
    let (send, receive) = std::sync::mpsc::channel();
    std::thread::scope(|scope| {
        let guard = sampler.lock().unwrap();
        let worker = scope.spawn(|| {
            let now = Instant::now();
            send.send(sample_at(&sampler, now, now, 1000).is_none())
                .unwrap();
        });
        let completed = receive.recv_timeout(Duration::from_secs(1));
        // Release on failure too, so a mistakenly blocking sampler can finish.
        drop(guard);
        worker.join().unwrap();
        assert!(completed.unwrap());
    });
    assert_eq!(sampler.lock().unwrap().issued, 0);
}

#[test]
fn service_spans_partition_received_frame_through_write_without_post_write_work() {
    let received = Instant::now();
    let at = |ns| received + Duration::from_nanos(ns);
    let sampler = Mutex::new(Sampler::new());
    let mut sample = sample_at(&sampler, received, at(7), 1000).unwrap();
    sample.authority_start = at(11);
    sample.authority_end = at(31);
    sample.execute_end = at(50);
    sample.encoded = at(61);
    sample.outcome = "Committed";
    let record = sample.record(at(80), true);
    assert_eq!(record.frame_to_dispatch_ns, 7);
    assert_eq!(record.authority_ns, 20);
    assert_eq!(record.execute_ns, 23);
    assert_eq!(record.encode_ns, 11);
    assert_eq!(record.write_ns, 19);
    assert_eq!(record.total_ns, 80);
    assert_eq!(
        record.frame_to_dispatch_ns
            + record.authority_ns
            + record.execute_ns
            + record.encode_ns
            + record.write_ns,
        record.total_ns
    );
    let line = record.line();
    let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(parsed["totalNs"], 80);
    assert_eq!(parsed["outcome"], "Committed");
    assert_eq!(parsed["write"], "Complete");
}

#[test]
fn message_records_are_fixed_bounded_and_do_not_expose_response_contents() {
    let secret = "private message, identity, key, and refusal detail";
    let outcomes = [
        (
            Outcome::Committed {
                event: None,
                position: u64::MAX,
                body: Value::Text(secret.into()),
            },
            "Committed",
        ),
        (
            Outcome::Refused {
                code: ErrorCode::Unavailable,
                detail: secret.into(),
                retry_after_ms: Some(u64::MAX),
            },
            "Refused",
        ),
        (
            Outcome::Rejected {
                code: ErrorCode::Denied,
                detail: secret.into(),
            },
            "Rejected",
        ),
        (
            Outcome::Result {
                body: Value::Text(secret.into()),
            },
            "Result",
        ),
        (Outcome::Absent, "Absent"),
        (Outcome::Unknown, "Unknown"),
    ];
    for (outcome, label) in outcomes {
        let record = Record {
            sample: u16::MAX,
            boot_ms: u64::MAX,
            frame_to_dispatch_ns: u64::MAX,
            authority_ns: u64::MAX,
            execute_ns: u64::MAX,
            encode_ns: u64::MAX,
            write_ns: u64::MAX,
            total_ns: u64::MAX,
            outcome: outcome_label(&outcome),
            written: false,
        };
        let line = record.line();
        assert!(line.len() < 384);
        assert!(!line.contains(secret));
        let parsed: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(parsed["outcome"], label);
        assert_eq!(parsed["write"], "Failed");
        assert_eq!(parsed.as_object().unwrap().len(), 11);
        assert!(parsed.get("operationId").is_none());
        assert!(parsed.get("detail").is_none());
        assert!(parsed.get("body").is_none());
    }
}
