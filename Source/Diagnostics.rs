// SPDX-License-Identifier: Apache-2.0
//! Bounded diagnostic output cannot hold a conversation or shutdown behind its sink.
use std::{
    io::Write,
    sync::{OnceLock, mpsc},
    thread,
};

const QUEUE_RECORDS: usize = 32;
const RECORD_BYTES: usize = 1024;
static OUTPUT: OnceLock<Option<Output>> = OnceLock::new();

struct Record {
    bytes: [u8; RECORD_BYTES],
    length: usize,
}
impl Record {
    fn new(line: &str) -> Option<Self> {
        if line.len() >= RECORD_BYTES {
            return None;
        }
        let mut record = Self {
            bytes: [0; RECORD_BYTES],
            length: line.len() + 1,
        };
        record.bytes[..line.len()].copy_from_slice(line.as_bytes());
        record.bytes[line.len()] = b'\n';
        Some(record)
    }
}
#[derive(Clone)]
struct Output {
    sender: mpsc::SyncSender<Record>,
}
impl Output {
    fn start(mut sink: impl Write + Send + 'static) -> Option<Self> {
        let (sender, receiver) = mpsc::sync_channel::<Record>(QUEUE_RECORDS);
        // One process-lifetime writer is detached: shutdown never joins a blocked sink.
        thread::Builder::new()
            .name("hrc-diagnostics".into())
            .spawn(move || {
                for record in receiver {
                    if sink.write_all(&record.bytes[..record.length]).is_err() {
                        break;
                    }
                }
            })
            .ok()?;
        Some(Self { sender })
    }

    fn try_emit(&self, line: &str) -> bool {
        Record::new(line).is_some_and(|record| self.sender.try_send(record).is_ok())
    }
}

/// Initialise before session deadlines or service workers start. Failure disables output.
pub(crate) fn start() {
    OUTPUT.get_or_init(|| Output::start(std::io::stderr()));
}

/// Callers retain their own content restrictions and rate/total budgets.
pub(crate) fn emit(line: &str) {
    if let Some(Some(output)) = OUTPUT.get() {
        let _ = output.try_emit(line);
    }
}

#[cfg(test)]
#[path = "../Tests/Diagnostics/Output.rs"]
mod tests;
