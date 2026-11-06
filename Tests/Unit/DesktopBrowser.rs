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
