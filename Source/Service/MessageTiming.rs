// SPDX-License-Identifier: Apache-2.0
//! Opt-in, bounded service spans for verified local message sends.
use super::{Budget, clock};
use crate::protocol::Outcome;
use std::{
    sync::Mutex,
    time::{Duration, Instant},
};

const MAXIMUM_SAMPLES: u16 = 512;
static SAMPLER: Mutex<Sampler> = Mutex::new(Sampler::new());

struct Sampler {
    budget: Budget,
    issued: u16,
}
impl Sampler {
    const fn new() -> Self {
        Self {
            budget: Budget::new(2, 4),
            issued: 0,
        }
    }
    fn admit(&mut self, now: u64) -> Option<u16> {
        if self.issued >= MAXIMUM_SAMPLES || !self.budget.admit(now) {
            return None;
        }
        self.issued += 1;
        Some(self.issued)
    }
}

pub(super) fn begin(enabled: bool, received: Instant) -> Option<Sample> {
    if !enabled {
        return None;
    }
    let boot_ms = clock::boot_ms().ok()?;
    sample_at(&SAMPLER, received, Instant::now(), boot_ms)
}

fn sample_at(
    sampler: &Mutex<Sampler>,
    received: Instant,
    dispatch: Instant,
    boot_ms: u64,
) -> Option<Sample> {
    let sample = sampler.try_lock().ok()?.admit(boot_ms)?;
    Some(Sample {
        sample,
        boot_ms,
        received,
        dispatch,
        authority_start: dispatch,
        authority_end: dispatch,
        execute_end: dispatch,
        encoded: dispatch,
        outcome: "Unknown",
    })
}

pub(super) struct Sample {
    sample: u16,
    boot_ms: u64,
    received: Instant,
    dispatch: Instant,
    authority_start: Instant,
    authority_end: Instant,
    execute_end: Instant,
    encoded: Instant,
    outcome: &'static str,
}
impl Sample {
    pub(super) fn authority_started(&mut self) {
        self.authority_start = Instant::now();
    }
    pub(super) fn authority_complete(&mut self) {
        self.authority_end = Instant::now();
    }
    pub(super) fn executed(&mut self, outcome: &Outcome) {
        self.execute_end = Instant::now();
        self.outcome = outcome_label(outcome);
    }
    pub(super) fn encoding_complete(&mut self) {
        self.encoded = Instant::now();
    }
    fn record(self, completed: Instant, written: bool) -> Record {
        let ns = |duration: Duration| duration.as_nanos().try_into().unwrap_or(u64::MAX);
        let authority_ns = ns(self
            .authority_end
            .saturating_duration_since(self.authority_start));
        Record {
            sample: self.sample,
            boot_ms: self.boot_ms,
            frame_to_dispatch_ns: ns(self.dispatch.saturating_duration_since(self.received)),
            authority_ns,
            execute_ns: ns(self.execute_end.saturating_duration_since(self.dispatch))
                .saturating_sub(authority_ns),
            encode_ns: ns(self.encoded.saturating_duration_since(self.execute_end)),
            write_ns: ns(completed.saturating_duration_since(self.encoded)),
            total_ns: ns(completed.saturating_duration_since(self.received)),
            outcome: self.outcome,
            written,
        }
    }
    pub(super) fn finish(self, written: bool) {
        let record = self.record(Instant::now(), written);
        crate::diagnostics::emit(&record.line());
    }
}

fn outcome_label(outcome: &Outcome) -> &'static str {
    match outcome {
        Outcome::Committed { .. } => "Committed",
        Outcome::Refused { .. } => "Refused",
        Outcome::Rejected { .. } => "Rejected",
        Outcome::Result { .. } => "Result",
        Outcome::Absent => "Absent",
        Outcome::Unknown => "Unknown",
    }
}

struct Record {
    sample: u16,
    boot_ms: u64,
    frame_to_dispatch_ns: u64,
    authority_ns: u64,
    execute_ns: u64,
    encode_ns: u64,
    write_ns: u64,
    total_ns: u64,
    outcome: &'static str,
    written: bool,
}
impl Record {
    fn line(&self) -> String {
        let write = if self.written { "Complete" } else { "Failed" };
        format!(
            "{{\"event\":\"MessageTiming\",\"sample\":{},\"bootMs\":{},\"frameToDispatchNs\":{},\"authorityNs\":{},\"executeNs\":{},\"encodeNs\":{},\"writeNs\":{},\"totalNs\":{},\"outcome\":\"{}\",\"write\":\"{}\"}}",
            self.sample,
            self.boot_ms,
            self.frame_to_dispatch_ns,
            self.authority_ns,
            self.execute_ns,
            self.encode_ns,
            self.write_ns,
            self.total_ns,
            self.outcome,
            write,
        )
    }
}

#[cfg(test)]
#[path = "../../Tests/Service/MessageTiming.rs"]
mod tests;
