use super::*;
use sha2::{Digest, Sha256};
use std::{fs, os::unix::fs::symlink};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        Self(std::env::temp_dir().join(format!(
            "hrc-assistant-{}",
            hrc::protocol::Id::random().unwrap()
        )))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn preview_is_read_only_and_installed_files_are_reusable_without_source() {
    let directory = Directory::new();
    let preview = install_scoped(Provider::Codex, Scope::Workspace, &directory.0, false).unwrap();
    assert_eq!(preview["can_apply"], true);
    assert!(!directory.0.exists());
    install_scoped(Provider::Codex, Scope::Workspace, &directory.0, true).unwrap();
    assert!(
        directory
            .0
            .join(".agents/skills/hrc-setup/references/Contract.md")
            .is_file()
    );
    assert!(
        directory
            .0
            .join(".codex/agents/hrc-local-operator.toml")
            .is_file()
    );
    assert!(!directory.0.join(".codex/config.toml").exists());
    assert!(!directory.0.join(".codex/hooks.json").exists());
    let repeated = install_scoped(Provider::Codex, Scope::Workspace, &directory.0, false).unwrap();
    assert!(
        repeated["files"]
            .as_array()
            .unwrap()
            .iter()
            .all(|f| f["action"] == "unchanged")
    );
}

#[test]
fn unowned_and_user_edited_files_are_never_overwritten() {
    let directory = Directory::new();
    let path = directory.0.join(".agents/skills/hrc-setup/SKILL.md");
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    let same = include_bytes!("../../../Harness/skills/hrc-setup/SKILL.md");
    fs::write(&path, same).unwrap();
    assert_eq!(
        install_scoped(Provider::Codex, Scope::Workspace, &directory.0, false).unwrap()["can_apply"],
        false
    );
    assert_eq!(
        install_scoped(Provider::Codex, Scope::Workspace, &directory.0, true),
        Err("AssistantFileConflict")
    );
    assert_eq!(fs::read(&path).unwrap(), same);
    fs::remove_file(&path).unwrap();
    install_scoped(Provider::Codex, Scope::Workspace, &directory.0, true).unwrap();
    fs::write(&path, "Operator's own instructions").unwrap();
    assert_eq!(
        install_scoped(Provider::Codex, Scope::Workspace, &directory.0, true),
        Err("AssistantFileConflict")
    );
    assert_eq!(
        fs::read_to_string(path).unwrap(),
        "Operator's own instructions"
    );
}

#[test]
fn removal_preserves_edited_files_and_shared_configuration() {
    let directory = Directory::new();
    install_scoped(Provider::Claude, Scope::Workspace, &directory.0, true).unwrap();
    let modified = directory.0.join(".claude/skills/hrc-security/SKILL.md");
    let settings = directory.0.join(".claude/settings.json");
    fs::write(&modified, "My policy").unwrap();
    fs::write(&settings, "{}").unwrap();
    let result = uninstall_scoped(Provider::Claude, Scope::Workspace, &directory.0, true).unwrap();
    assert!(
        result["files"]
            .as_array()
            .unwrap()
            .iter()
            .any(|f| f["action"] == "preserve")
    );
    assert_eq!(fs::read_to_string(modified).unwrap(), "My policy");
    assert_eq!(fs::read_to_string(settings).unwrap(), "{}");
    assert!(
        !directory
            .0
            .join(".claude/skills/hrc-setup/SKILL.md")
            .exists()
    );
}

#[test]
fn linked_destinations_and_traversing_receipts_are_refused() {
    let directory = Directory::new();
    let external = Directory::new();
    fs::create_dir_all(&directory.0).unwrap();
    fs::create_dir_all(&external.0).unwrap();
    symlink(&external.0, directory.0.join(".agents")).unwrap();
    assert!(install_scoped(Provider::Codex, Scope::Workspace, &directory.0, true).is_err());
    assert!(!external.0.join("skills").exists());
    fs::remove_file(directory.0.join(".agents")).unwrap();
    install_scoped(Provider::Codex, Scope::Workspace, &directory.0, true).unwrap();
    let receipt = directory.0.join(".hrc-harness/receipts/codex.json");
    let mut value: Value = serde_json::from_slice(&fs::read(&receipt).unwrap()).unwrap();
    value["files"][".agents/skills/hrc-setup/../../../../outside"] = json!(["0".repeat(64)]);
    fs::write(&receipt, serde_json::to_vec(&value).unwrap()).unwrap();
    assert!(install_scoped(Provider::Codex, Scope::Workspace, &directory.0, false).is_err());
}

#[test]
fn interrupted_owned_update_resumes_but_does_not_claim_other_content() {
    let directory = Directory::new();
    install_scoped(Provider::Codex, Scope::Workspace, &directory.0, true).unwrap();
    let relative = ".agents/skills/hrc-setup/SKILL.md";
    let path = directory.0.join(relative);
    let wanted = fs::read(&path).unwrap();
    let old = b"previously installed version";
    let receipt = directory.0.join(".hrc-harness/receipts/codex.json");
    let mut value: Value = serde_json::from_slice(&fs::read(&receipt).unwrap()).unwrap();
    value["files"][relative] = json!([
        hex::encode(Sha256::digest(old)),
        hex::encode(Sha256::digest(&wanted))
    ]);
    fs::write(&receipt, serde_json::to_vec(&value).unwrap()).unwrap();
    fs::write(&path, old).unwrap();
    install_scoped(Provider::Codex, Scope::Workspace, &directory.0, true).unwrap();
    assert_eq!(fs::read(&path).unwrap(), wanted);
    fs::write(&path, "unrelated replacement").unwrap();
    assert_eq!(
        install_scoped(Provider::Codex, Scope::Workspace, &directory.0, true),
        Err("AssistantFileConflict")
    );
}

#[test]
fn user_scope_and_hardlink_checks_preserve_provider_boundaries() {
    let directory = Directory::new();
    install_scoped(Provider::Copilot, Scope::User, &directory.0, true).unwrap();
    assert!(
        directory
            .0
            .join(".copilot/skills/hrc-setup/SKILL.md")
            .is_file()
    );
    assert!(
        directory
            .0
            .join(".copilot/agents/hrc-observer.agent.md")
            .is_file()
    );
    assert!(!directory.0.join(".github").exists());
    assert_eq!(
        install_scoped(Provider::Copilot, Scope::Workspace, &directory.0, false),
        Err("AssistantInvalidReceipt")
    );
    let path = directory.0.join(".copilot/skills/hrc-setup/SKILL.md");
    fs::hard_link(&path, directory.0.join("second-link")).unwrap();
    assert!(uninstall_scoped(Provider::Copilot, Scope::User, &directory.0, true).is_err());
    assert!(path.exists());
}

#[test]
fn unsupported_destination_encoding_returns_an_error_before_serialization() {
    use std::os::unix::ffi::OsStringExt;
    let path = PathBuf::from(std::ffi::OsString::from_vec(b"/tmp/hrc-\xff".to_vec()));
    assert_eq!(
        install_scoped(Provider::Codex, Scope::Workspace, &path, false),
        Err("AssistantUnsupportedDestination")
    );
    assert_eq!(
        install_scoped(
            Provider::Codex,
            Scope::Workspace,
            Path::new("/tmp/hrc\npath"),
            false
        ),
        Err("AssistantUnsupportedDestination")
    );
}
