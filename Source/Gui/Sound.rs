// SPDX-License-Identifier: Apache-2.0
//! Optional desktop sound has one bounded worker and never receives message content.
use std::{
    process::{Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, SyncSender},
    },
    thread,
    time::{Duration, Instant},
};
pub(super) struct Sound {
    sender: SyncSender<()>,
    stopped: Arc<AtomicBool>,
    unavailable: Arc<AtomicBool>,
    worker: Option<thread::JoinHandle<()>>,
}
impl Sound {
    pub(super) fn new() -> Self {
        let (sender, receiver) = mpsc::sync_channel(1);
        let stopped = Arc::new(AtomicBool::new(false));
        let unavailable = Arc::new(AtomicBool::new(false));
        let stop = Arc::clone(&stopped);
        let failed = Arc::clone(&unavailable);
        let worker = thread::Builder::new()
            .name("hrc-notification-sound".into())
            .spawn(move || {
                let mut last = None;
                while !stop.load(Ordering::Acquire) {
                    if receiver.recv_timeout(Duration::from_millis(100)).is_err() {
                        continue;
                    }
                    if last.is_some_and(|last: Instant| last.elapsed() < Duration::from_secs(5)) {
                        continue;
                    }
                    last = Some(Instant::now());
                    let child = Command::new("canberra-gtk-play")
                        .args(["--id=message-new-instant", "--description=HRC notification"])
                        .stdin(Stdio::null())
                        .stdout(Stdio::null())
                        .stderr(Stdio::null())
                        .spawn();
                    let Ok(mut child) = child else {
                        failed.store(true, Ordering::Release);
                        continue;
                    };
                    let end = Instant::now() + Duration::from_secs(3);
                    loop {
                        match child.try_wait() {
                            Ok(Some(status)) => {
                                failed.store(!status.success(), Ordering::Release);
                                break;
                            }
                            Err(_) => {
                                failed.store(true, Ordering::Release);
                                let _ = child.kill();
                                let _ = child.wait();
                                break;
                            }
                            Ok(None) => {}
                        }
                        if stop.load(Ordering::Acquire) || Instant::now() >= end {
                            let _ = child.kill();
                            let _ = child.wait();
                            break;
                        }
                        thread::sleep(Duration::from_millis(50));
                    }
                }
            })
            .ok();
        if worker.is_none() {
            unavailable.store(true, Ordering::Release);
        }
        Self {
            sender,
            stopped,
            unavailable,
            worker,
        }
    }
    pub(super) fn play(&self) {
        let _ = self.sender.try_send(());
    }
    pub(super) fn unavailable(&self) -> bool {
        self.unavailable.load(Ordering::Acquire)
    }
}
impl Drop for Sound {
    fn drop(&mut self) {
        self.stopped.store(true, Ordering::Release);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}
