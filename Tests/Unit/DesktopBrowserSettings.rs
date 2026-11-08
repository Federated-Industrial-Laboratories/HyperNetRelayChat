// SPDX-License-Identifier: Apache-2.0
// Leaving reader settings settles private persistence before Setup captures its runtime.
use super::*;
use crate::onboarding::RuntimeConfig;
use hrc::{protocol::Id, service::files};
use std::{
    sync::{atomic::Ordering, mpsc},
    time::{Duration, Instant},
};

#[test]
fn closing_reader_settings_settles_save_before_setup_loads_runtime() {
    let directory =
        std::env::temp_dir().join(format!("hrc-reader-settings-{}", Id::random().unwrap()));
    files::directory(&directory, true).unwrap();
    let mut config = RuntimeConfig::at(directory.clone());
    config.save().unwrap();
    let path = directory.join("OnboardingRuntime.json");
    let reader = directory.join("Reader/Profile.json");
    config.page_browser_profile = Some(reader.clone());
    let (started, ready) = mpsc::sync_channel(1);
    let mut settings = Settings {
        visible: true,
        profile: Some(config.hrc_profile.clone()),
        saving: Some(
            browser::Job::start(&egui::Context::default(), move |cancel| {
                started.send(()).unwrap();
                let end = Instant::now() + Duration::from_secs(2);
                while !cancel.load(Ordering::Acquire) {
                    if Instant::now() >= end {
                        return Err("The settings job was not cancelled.");
                    }
                    std::thread::yield_now();
                }
                // A save already past its final cancellation check may finish during close.
                config.save().map_err(|_| "The final save failed.")
            })
            .unwrap(),
        ),
        ..Default::default()
    };
    ready.recv_timeout(Duration::from_secs(2)).unwrap();
    settings.close();
    assert!(!settings.visible);
    assert!(settings.profile.is_none());
    assert!(settings.saving.is_none());
    let setup_snapshot = RuntimeConfig::load(&path).unwrap();
    assert_eq!(setup_snapshot.page_browser_profile, Some(reader.clone()));
    setup_snapshot.save().unwrap();
    assert_eq!(
        RuntimeConfig::load(&path).unwrap().page_browser_profile,
        Some(reader)
    );
    std::fs::remove_dir_all(directory).unwrap();
}
