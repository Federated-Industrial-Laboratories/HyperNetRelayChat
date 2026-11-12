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
