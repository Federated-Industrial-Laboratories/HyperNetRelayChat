// SPDX-License-Identifier: Apache-2.0
use super::*;
use hrc::home::RoomCreationPolicy;

struct Directories(PathBuf);
impl Directories {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "hrc-policy-ui-{}",
            hrc::protocol::Id::random().unwrap()
        ));
        for name in ["First", "Second"] {
            std::fs::create_dir_all(root.join(name)).unwrap();
        }
        Self(root)
    }
    fn at(&self, name: &str) -> ops::home::Configuration {
        ops::home::Configuration::at(self.0.join(name).canonicalize().unwrap())
    }
}
impl Drop for Directories {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}
fn apply_enabled(form: &mut Form) -> bool {
    let context = egui::Context::default();
    let mut enabled = None;
    let mut output = context.run_ui(egui::RawInput::default(), |ui| {
        enabled = Some(form.creation_editor(ui).enabled());
    });
    output.textures_delta.clear();
    enabled.unwrap()
}
fn load_restricted(form: &mut Form) {
    form.receive_policy(
        form.selection().unwrap(),
        RoomCreationPolicy::AllowList { accounts: vec![] },
    )
    .unwrap();
    assert!(form.restrict_creation);
    assert!(apply_enabled(form));
}

#[test]
fn creation_controls_require_a_policy_loaded_for_the_current_service_definition() {
    let directories = Directories::new();
    let mut form = Form::default();
    form.select_config(directories.at("First"));
    assert!(!apply_enabled(&mut form));
    assert!(form.take_policy().is_err());
    load_restricted(&mut form);

    form.config.directory = directories.at("Second").directory;
    assert!(!apply_enabled(&mut form));
    assert!(form.policy_selection.is_none());
    load_restricted(&mut form);

    form.file = directories.0.join("AnotherDefinition.json");
    assert!(!apply_enabled(&mut form));
    load_restricted(&mut form);

    form.config.limits.memory_mib *= 2;
    assert!(!apply_enabled(&mut form));
    load_restricted(&mut form);

    // Loading a definition also invalidates a draft when its folder is unchanged.
    form.select_config(form.config.clone());
    assert!(!apply_enabled(&mut form));
    load_restricted(&mut form);
    form.config.directory = directories.0.join("Second/../Second");
    assert!(!apply_enabled(&mut form));
}

#[test]
fn delayed_results_and_completed_updates_cannot_reactivate_an_old_policy_draft() {
    let directories = Directories::new();
    let mut form = Form::default();
    form.select_config(directories.at("First"));
    load_restricted(&mut form);
    let old = form.selection().unwrap();
    // Network-status completion uses the same selection transition.
    form.select_config(directories.at("Second"));
    form.select_config(directories.at("First"));
    assert!(form.receive_policy(old, RoomCreationPolicy::All).is_err());
    assert!(!apply_enabled(&mut form));

    load_restricted(&mut form);
    let old = form.selection().unwrap();
    let (configuration, policy) = form.take_policy().unwrap();
    assert_eq!(configuration.directory, directories.at("First").directory);
    assert_eq!(policy, RoomCreationPolicy::AllowList { accounts: vec![] });
    assert!(!apply_enabled(&mut form));
    assert!(form.receive_policy(old, RoomCreationPolicy::All).is_err());
    assert!(!apply_enabled(&mut form));
    load_restricted(&mut form);
}
