// SPDX-License-Identifier: Apache-2.0
// Browser handoff keeps addresses in fixed arguments and rejects unsafe theme files.
use super::*;
use std::{
    ffi::OsStr,
    os::unix::fs::{PermissionsExt, symlink},
    path::PathBuf,
};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "hrc-browser-{}",
            hrc::protocol::Id::random().unwrap()
        ));
        files::directory(&path, true).unwrap();
        Self(path)
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
#[test]
fn page_browser_argv_keeps_explicit_paths_and_address_intact() {
    let mut config = RuntimeConfig::at("/Private/Data".into());
    config.suite = "/Pinned Suite/HyperNetSuite".into();
    config.network_profile = "/Private/selected profile;literal.json".into();
    let address = format!(
        "hypernet://{}/{}/News/{}",
        "a".repeat(64),
        "b".repeat(64),
        "c".repeat(32)
    );
    let cmd = command(&config, Path::new("/Private/Browser Theme.json"), &address).unwrap();
    assert_eq!(cmd.get_program(), OsStr::new("/Pinned Suite/HyperNetSuite"));
    assert_eq!(
        cmd.get_args().collect::<Vec<_>>(),
        [
            "network",
            "connect",
            "--profile",
            "/Private/selected profile;literal.json",
            "--",
            "browse",
            "--gui",
            "--theme-file",
            "/Private/Browser Theme.json",
            &address,
        ]
        .map(OsStr::new)
    );
    assert!(command(&config, Path::new("/Private/theme"), "--other-option").is_err());
}
#[test]
fn page_browser_palette_replaces_privately_without_credentials() {
    let directory = Directory::new();
    let path = directory.0.join("BrowserTheme.json");
    let first = include_bytes!("../../Themes/OceanDark.json");
    let second = include_bytes!("../../Themes/ForestLight.json");
    write_palette(&path, first).unwrap();
    write_palette(&path, second).unwrap();
    assert_eq!(files::read(&path, 16384).unwrap(), second);
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    assert_eq!(fs::read_dir(&directory.0).unwrap().count(), 1);
    assert!(write_palette(&path, br#"{"credentials":"secret"}"#).is_err());
    assert_eq!(files::read(&path, 16384).unwrap(), second);
}
#[test]
fn page_browser_palette_refuses_links_and_shared_files() {
    let directory = Directory::new();
    let target = directory.0.join("Original.json");
    let path = directory.0.join("BrowserTheme.json");
    let bytes = include_bytes!("../../Themes/OceanDark.json");
    files::create(&target, bytes).unwrap();
    symlink(&target, &path).unwrap();
    assert!(write_palette(&path, bytes).is_err());
    fs::remove_file(&path).unwrap();
    fs::hard_link(&target, &path).unwrap();
    assert!(write_palette(&path, bytes).is_err());
    fs::remove_file(&path).unwrap();
    files::create(&path, bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(write_palette(&path, bytes).is_err());
    assert_eq!(fs::read(&target).unwrap(), bytes);
}
#[test]
fn page_browser_requires_configuration_bound_to_selected_chat() {
    let directory = Directory::new();
    let profile = directory.0.join("Profile");
    assert!(configuration(&profile).is_err());
    let mut config = RuntimeConfig::at(directory.0.clone());
    config.hrc_profile = directory.0.join("AnotherProfile");
    files::create_json(&directory.0.join("OnboardingRuntime.json"), &config).unwrap();
    assert!(matches!(
        configuration(&profile),
        Err("The browser configuration belongs to another chat profile.")
    ));
}

#[test]
fn page_browser_selection_persists_without_changing_chat_runtime() {
    let directory = Directory::new();
    let mut config = RuntimeConfig::at(directory.0.clone());
    config.save().unwrap();
    let path = directory.0.join("OnboardingRuntime.json");
    let original: Value = serde_json::from_slice(&files::read(&path, 65536).unwrap()).unwrap();
    assert!(original.get("pageBrowserProfile").is_none());
    assert!(
        RuntimeConfig::load(&path)
            .unwrap()
            .page_browser_profile
            .is_none()
    );
    config.page_browser_profile = Some(directory.0.join("Reader/Profile.json"));
    config.save().unwrap();
    let reopened = RuntimeConfig::load(&path).unwrap();
    assert_eq!(reopened.page_browser_profile, config.page_browser_profile);
    let mut retained = serde_json::to_value(&reopened).unwrap();
    retained
        .as_object_mut()
        .unwrap()
        .remove("pageBrowserProfile");
    assert_eq!(retained, original);
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
    );
    let address = format!(
        "hypernet://{}/{}/News/{}",
        "a".repeat(64),
        "b".repeat(64),
        "c".repeat(32)
    );
    let cmd = command(&reopened, Path::new("/Private/theme.json"), &address).unwrap();
    assert_eq!(
        cmd.get_args().nth(3),
        reopened
            .page_browser_profile
            .as_ref()
            .map(|p| p.as_os_str())
    );
    config.page_browser_profile = Some("relative/Profile.json".into());
    assert!(config.save().is_err());
    assert_eq!(
        RuntimeConfig::load(&path).unwrap().page_browser_profile,
        reopened.page_browser_profile
    );
}

fn native_report(seed: u8) -> Value {
    serde_json::json!({"state":"Joined","membership":true,
        "fingerprint":"03".repeat(32),"descriptorDigest":"04".repeat(32),
        "trust":{"network":"01".repeat(32),"incarnation":"02".repeat(32)},
        "client":format!("{seed:02x}").repeat(32),
        "devicePublicKey":format!("{:02x}",seed+1).repeat(32),
        "relayPublicKey":format!("{:02x}",seed+2).repeat(32)})
}
#[test]
fn page_reader_rejects_unjoined_cross_network_and_reused_identities() {
    let chat = Identity::from_report(&native_report(10)).unwrap();
    let reader = Identity::from_report(&native_report(20)).unwrap();
    assert!(check_identity(&chat, &reader, chat.network, chat.device, true).is_ok());
    assert!(check_identity(&chat, &chat, chat.network, chat.device, false).is_ok());
    assert!(check_identity(&chat, &chat, chat.network, chat.device, true).is_err());
    for field in ["client", "devicePublicKey", "relayPublicKey"] {
        let mut report = native_report(20);
        report[field] = native_report(10)[field].clone();
        let duplicate = Identity::from_report(&report).unwrap();
        assert!(check_identity(&chat, &duplicate, chat.network, chat.device, true).is_err());
    }
    for field in ["network", "incarnation"] {
        let mut report = native_report(20);
        report["trust"][field] = serde_json::json!("ff".repeat(32));
        let wrong_network = Identity::from_report(&report).unwrap();
        assert!(check_identity(&chat, &wrong_network, chat.network, chat.device, true).is_err());
    }
    for field in ["fingerprint", "descriptorDigest"] {
        let mut report = native_report(20);
        report[field] = serde_json::json!("ff".repeat(32));
        let different_trust = Identity::from_report(&report).unwrap();
        assert!(check_identity(&chat, &different_trust, chat.network, chat.device, true).is_err());
    }
    assert!(check_identity(&chat, &reader, chat.network, reader.device, true).is_err());
    let mut prepared = native_report(20);
    prepared["state"] = serde_json::json!("OfflinePrepared");
    prepared["membership"] = serde_json::json!(false);
    assert!(Identity::from_report(&prepared).is_err());
    assert!(
        Identity::from_report(&serde_json::json!({"state":"Joined","membership":true})).is_err()
    );
}
#[test]
fn page_reader_profile_path_refuses_shared_or_aliased_private_state() {
    let directory = Directory::new();
    let original = directory.0.join("Profile.json");
    let alias = directory.0.join("Alias.json");
    files::create(&original, b"native inspect owns the private format").unwrap();
    assert!(private_profile(&original).is_ok());
    symlink(&original, &alias).unwrap();
    assert!(private_profile(&alias).is_err());
    fs::remove_file(&alias).unwrap();
    fs::hard_link(&original, &alias).unwrap();
    assert!(private_profile(&original).is_err());
    fs::remove_file(&alias).unwrap();
    fs::set_permissions(&original, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(private_profile(&original).is_err());
    assert!(private_profile(Path::new("relative/Profile.json")).is_err());
}

#[test]
fn page_reader_existing_window_refuses_second_spawn_without_touching_palette() {
    let directory = Directory::new();
    let reader = directory.0.join("Profile.json");
    let palette = directory.0.join("BrowserTheme.json");
    let child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
    let mut browser = Browser::default();
    browser.children.push(Opened {
        child,
        reader: reader.clone(),
    });
    let result = browser.launch(Launch {
        command: Command::new("/nonexistent-must-not-run"),
        reader,
        palette: palette.clone(),
        colours: include_bytes!("../../Themes/OceanDark.json").to_vec(),
    });
    let process = &mut browser.children[0].child;
    process.kill().unwrap();
    process.wait().unwrap();
    assert!(
        result
            .unwrap_err()
            .starts_with("A browser already uses this reader profile.")
    );
    assert_eq!(browser.children.len(), 1);
    assert!(!palette.exists());
}

#[test]
fn leaving_chat_context_discards_pending_launch_and_preserves_open_browser() {
    let directory = Directory::new();
    let palette = directory.0.join("BrowserTheme.json");
    let child = Command::new("/bin/sleep").arg("30").spawn().unwrap();
    let mut browser = Browser::default();
    browser.children.push(Opened {
        child,
        reader: directory.0.join("OpenReader.json"),
    });
    for ready_before_cancel in [false, true] {
        let launch = Launch {
            command: Command::new("/nonexistent-must-not-run"),
            reader: directory.0.join("PendingReader.json"),
            palette: palette.clone(),
            colours: include_bytes!("../../Themes/OceanDark.json").to_vec(),
        };
        let (started, ready) = mpsc::sync_channel(1);
        browser.opening = Some(
            Job::start(&egui::Context::default(), move |cancel| {
                started.send(()).unwrap();
                let end = Instant::now() + Duration::from_secs(2);
                while !ready_before_cancel && !cancel.load(Ordering::Acquire) {
                    if Instant::now() >= end {
                        return Err("The launch was not cancelled.");
                    }
                    thread::yield_now();
                }
                Ok(launch)
            })
            .unwrap(),
        );
        ready.recv_timeout(Duration::from_secs(2)).unwrap();
        if ready_before_cancel {
            browser
                .opening
                .as_mut()
                .unwrap()
                .worker
                .take()
                .unwrap()
                .join()
                .unwrap();
        }
        browser.cancel_pending();
        assert!(browser.poll().is_none());
        assert!(browser.opening.is_none());
        assert_eq!(browser.children.len(), 1);
        assert!(browser.children[0].child.try_wait().unwrap().is_none());
        assert!(!palette.exists());
    }
    browser.children[0].child.kill().unwrap();
    browser.children[0].child.wait().unwrap();
}
