// SPDX-License-Identifier: Apache-2.0
//! A retained index can locate only its exact content-addressed signed candidate.
use super::*;

#[test]
fn retained_index_cannot_select_foreign_executables_or_target_path_components() {
    let root = Path::new("/private/Installation");
    let archive = "a".repeat(64);
    let target = "b".repeat(64);
    let expected = prefix(root, Product::Suite, &archive)
        .unwrap()
        .join("Bin/HyperNetSuite");
    let mut value = json!({"suiteExecutable":expected,"packages":{"suite":{"archiveSha256":archive,"targetDigest":target}}});
    assert_eq!(
        selected_executable(root, &value, Product::Suite).unwrap(),
        expected
    );
    assert!(
        publisher(root, &value)
            .unwrap()
            .starts_with(root.join("Products/Suite/Targets"))
    );
    value["suiteExecutable"] = json!("/usr/bin/other-program");
    assert!(selected_executable(root, &value, Product::Suite).is_err());
    value["suiteExecutable"] = json!(expected);
    for invalid in ["../outside".to_owned(), "A".repeat(64), "a".repeat(63)] {
        value["packages"]["suite"]["archiveSha256"] = json!(invalid);
        value["packages"]["suite"]["targetDigest"] = json!(invalid);
        assert!(selected_executable(root, &value, Product::Suite).is_err());
        assert!(publisher(root, &value).is_err());
    }
}

#[test]
fn desktop_registration_retries_without_replacing_native_state() {
    use hrc::{protocol::Id, service::files};
    use std::{fs, os::unix::fs::PermissionsExt};
    struct Fixture(PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }
    // The executable validator intentionally rejects shared temporary ancestors.
    let root = std::env::var_os("HRC_SIMPLE_FIXTURE_ROOT")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("target"))
        .join(format!("bootstrap-links-{}", Id::random().unwrap()));
    files::directory(&root, true).unwrap();
    let fixture = Fixture(root);
    let suite = fixture.0.join("Installed Suite");
    files::create(
        &suite,
        br##"#!/usr/bin/python3
import json, pathlib, sys
root=pathlib.Path(__file__).parent
with (root/'Calls.jsonl').open('a') as log: log.write(json.dumps(sys.argv[1:])+'\n')
assert sys.argv[1:]==['join','install']
status=(root/'RegistrationStatus').read_text()
if status=='Failed': sys.exit(7)
print(json.dumps({'status':status}))
"##,
    )
    .unwrap();
    fs::set_permissions(&suite, fs::Permissions::from_mode(0o700)).unwrap();
    let retained = fixture.0.join("Installation.json");
    files::create(&retained, b"retained admitted packages").unwrap();
    let status = fixture.0.join("RegistrationStatus");
    files::create(&status, b"Failed").unwrap();
    let cancel = AtomicBool::new(false);
    assert!(
        register_desktop(&suite, &cancel)
            .unwrap_err()
            .contains("native tools remain installed")
    );
    fs::write(&status, "Ready").unwrap();
    assert!(register_desktop(&suite, &cancel).is_err());
    fs::write(&status, "DesktopInstalled").unwrap();
    register_desktop(&suite, &cancel).unwrap();
    assert_eq!(fs::read(&retained).unwrap(), b"retained admitted packages");
    assert_eq!(
        fs::read_to_string(fixture.0.join("Calls.jsonl"))
            .unwrap()
            .lines()
            .count(),
        3
    );
    fs::set_permissions(&suite, fs::Permissions::from_mode(0o722)).unwrap();
    assert!(register_desktop(&suite, &cancel).is_err());
    assert_eq!(
        fs::read_to_string(fixture.0.join("Calls.jsonl"))
            .unwrap()
            .lines()
            .count(),
        3
    );
}
