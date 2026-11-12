// SPDX-License-Identifier: Apache-2.0
use super::*;
use crate::onboarding::Error;
use std::time::{Duration, Instant};
#[test]
fn superseded_runtime_result_cannot_reconnect_or_override_new_offline_choice() {
    let ctx = egui::Context::default();
    for outcome in [Ok(()), Err(Error::Deadline)] {
        let mut runtime = Runtime {
            online: true,
            job: Some(simple::Job::start(&ctx, move |_| outcome)),
            ..Default::default()
        };
        // The stale result is already waiting when the user chooses Offline.
        let end = Instant::now() + Duration::from_secs(2);
        while !runtime.job.as_ref().unwrap().finished() {
            assert!(Instant::now() < end);
            std::thread::yield_now();
        }
        assert!(runtime.poll(false, &ctx).is_none());
        assert!(!runtime.online);
    }
}
