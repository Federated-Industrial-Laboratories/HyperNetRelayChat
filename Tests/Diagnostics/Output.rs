// SPDX-License-Identifier: Apache-2.0
//! Exercise saturation, sink failure and shutdown without relying on stderr consumption.
use super::*;
use std::{io, time::Duration};

struct Release(Option<mpsc::SyncSender<()>>);
impl Drop for Release {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.try_send(());
        }
    }
}
struct StalledSink {
    entered: mpsc::SyncSender<()>,
    release: mpsc::Receiver<()>,
    finished: mpsc::SyncSender<()>,
}
impl Write for StalledSink {
    fn write(&mut self, _: &[u8]) -> io::Result<usize> {
        let _ = self.entered.try_send(());
        let _ = self.release.recv();
        Err(io::Error::from(io::ErrorKind::BrokenPipe))
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl Drop for StalledSink {
    fn drop(&mut self) {
        let _ = self.finished.try_send(());
    }
}

#[test]
fn saturated_output_and_handle_shutdown_do_not_wait_for_a_stalled_sink() {
    let (entered_tx, entered) = mpsc::sync_channel(1);
    let (release_tx, release) = mpsc::sync_channel(1);
    let release_guard = Release(Some(release_tx));
    let (finished_tx, finished) = mpsc::sync_channel(1);
    let output = Output::start(StalledSink {
        entered: entered_tx,
        release,
        finished: finished_tx,
    })
    .unwrap();
    assert!(output.try_emit("first"));
    entered.recv_timeout(Duration::from_secs(2)).unwrap();

    let (completed_tx, completed) = mpsc::sync_channel(1);
    let producer = thread::spawn(move || {
        let accepted = (0..128).filter(|_| output.try_emit("bounded")).count();
        drop(output);
        completed_tx.send(accepted).unwrap();
    });
    // Receive before releasing the sink, including producer handle destruction.
    let result = completed.recv_timeout(Duration::from_secs(2));
    drop(release_guard); // Also releases the writer if a later assertion fails.
    assert_eq!(result.unwrap(), QUEUE_RECORDS);
    producer.join().unwrap();
    finished.recv_timeout(Duration::from_secs(2)).unwrap();
}

#[test]
fn oversized_output_occupies_no_queue_slot_and_closed_output_is_dropped() {
    let (sender, receiver) = mpsc::sync_channel(1);
    let output = Output { sender };
    assert!(!output.try_emit(&"x".repeat(RECORD_BYTES)));
    assert!(output.try_emit(&"x".repeat(RECORD_BYTES - 1)));
    let record = receiver.try_recv().unwrap();
    assert_eq!(record.length, RECORD_BYTES);
    assert_eq!(record.bytes[RECORD_BYTES - 1], b'\n');
    drop(receiver);
    assert!(!output.try_emit("closed"));
}

#[test]
fn a_sink_error_closes_its_queue_without_poisoning_producers() {
    let (finished_tx, finished) = mpsc::sync_channel(1);
    struct Broken(mpsc::SyncSender<()>);
    impl Write for Broken {
        fn write(&mut self, _: &[u8]) -> io::Result<usize> {
            Err(io::Error::from(io::ErrorKind::BrokenPipe))
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }
    impl Drop for Broken {
        fn drop(&mut self) {
            let _ = self.0.try_send(());
        }
    }
    let output = Output::start(Broken(finished_tx)).unwrap();
    assert!(output.try_emit("first"));
    finished.recv_timeout(Duration::from_secs(2)).unwrap();
    assert!(!output.try_emit("after error"));
}
