// SPDX-License-Identifier: Apache-2.0
// Theme imports remain bounded data, preserve owned files, and fall back without changing identity.
use super::*;
use std::os::unix::fs::{PermissionsExt, symlink};

struct Directory(PathBuf);
impl Directory {
    fn new() -> Self {
        let path = std::env::temp_dir().join(format!(
            "hrc-themes-{}",
            hrc::protocol::Id::random().unwrap()
        ));
        directory(&path, true).unwrap();
        Self(path)
    }
    fn library(&self) -> Library {
        Library::at(Some(self.0.clone()))
    }
}
impl Drop for Directory {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn palette() -> Palette {
    Palette::parse(include_bytes!("../../../Themes/OceanDark.json")).unwrap()
}

#[test]
fn shipped_themes_are_readable_and_old_preferences_keep_original_defaults() {
    let library = Library::at(None);
    assert_eq!(library.entries.len(), 14);
    for entry in &library.entries {
        assert!(Palette::parse(&entry.palette.bytes().unwrap()).is_ok());
        let c = &entry.palette.colors;
        assert!(c.text.contrast(c.surface) >= 4.5);
        assert!(c.muted.contrast(c.surface) >= 4.5);
        assert!(c.selection_text.contrast(c.selection) >= 4.5);
    }
    let old = br#"{"theme":"Light","density":"Comfortable","textScale":1.0,"quiet":false,"sound":false,"ambiguousWide":false}"#;
    let preferences: hrc::client::Preferences = serde_json::from_slice(old).unwrap();
    assert!(preferences.palette.is_none());
    assert_eq!(library.selected(&preferences).unwrap().id, "hypernet-light");
    let context = eframe::egui::Context::default();
    super::super::configure_selected(&context, &preferences, &library);
    let style = context.style_of(eframe::egui::Theme::Light);
    assert_eq!(
        style.visuals.panel_fill,
        eframe::egui::Color32::from_rgb(235, 240, 242)
    );
    assert_eq!(
        style.visuals.override_text_color,
        Some(eframe::egui::Color32::from_rgb(32, 45, 55))
    );
    assert_eq!(style.spacing.interact_size, eframe::egui::vec2(128.0, 32.0));
}

#[test]
fn themes_reject_executable_fields_bad_colours_controls_and_unreadable_text() {
    let valid = serde_json::to_value(palette()).unwrap();
    for change in 0..11 {
        let mut value = valid.clone();
        match change {
            0 => value["script"] = "echo unsafe".into(),
            1 => value["colors"]["text"] = "#11223300".into(),
            2 => value["colors"]["text"] = "red".into(),
            3 => value["colors"]["text"] = value["colors"]["surface"].clone(),
            4 => value["colors"]["selectionText"] = value["colors"]["selection"].clone(),
            5 => value["display"]["font"] = "/tmp/Font.ttf".into(),
            6 => value["display"]["cornerCut"] = 1000.into(),
            7 => value["display"]["outlineWidth"] = 0.into(),
            8 => value["name"] = "Unsafe\u{202e}name".into(),
            9 => value["version"] = 2.into(),
            _ => value["colors"]["warning"] = "#000000".into(),
        }
        assert!(
            Palette::parse(&serde_json::to_vec(&value).unwrap()).is_err(),
            "accepted case {change}"
        );
    }
    let bytes = String::from_utf8(palette().bytes().unwrap()).unwrap();
    assert!(
        Palette::parse(
            bytes
                .replacen("\"version\": 1", "\"version\": 1, \"version\": 1", 1)
                .as_bytes()
        )
        .is_err()
    );
    assert!(Palette::parse(&vec![b' '; MAX_BYTES + 1]).is_err());
    assert!(Palette::parse(&[0xff]).is_err());
}

#[test]
fn imported_palettes_round_trip_privately_and_reuse_identical_content() {
    let directory = Directory::new();
    let mut library = directory.library();
    let value = palette();
    let id = library.import(&value).unwrap();
    assert_eq!(library.import(&value).unwrap(), id);
    let path = directory.0.join(format!("{id}.json"));
    let metadata = fs::metadata(&path).unwrap();
    assert_eq!(metadata.mode() & 0o777, 0o600);
    assert_eq!(paths(&directory.0).unwrap().len(), 1);
    let preferences = hrc::client::Preferences {
        palette: Some(id.clone()),
        ..Default::default()
    };
    let reloaded = directory.library();
    assert_eq!(
        reloaded.selected(&preferences).unwrap().palette.name,
        value.name
    );
    library.remove(&id).unwrap();
    assert!(!path.exists());
    assert!(library.selected(&preferences).is_none());
}

#[test]
fn edited_linked_and_unrelated_theme_files_are_preserved() {
    let directory = Directory::new();
    let mut library = directory.library();
    let value = palette();
    let id = library.import(&value).unwrap();
    let path = directory.0.join(format!("{id}.json"));
    fs::write(&path, b"user content").unwrap();
    assert!(library.import(&value).is_err());
    assert!(library.remove(&id).is_err());
    assert_eq!(fs::read(&path).unwrap(), b"user content");
    let preferences = hrc::client::Preferences {
        palette: Some(id.clone()),
        ..Default::default()
    };
    let reloaded = directory.library();
    assert!(reloaded.selected(&preferences).is_none());
    assert!(reloaded.problem.is_some());
    let context = eframe::egui::Context::default();
    super::super::configure_selected(&context, &preferences, &reloaded);
    assert_eq!(
        context
            .style_of(eframe::egui::Theme::Dark)
            .visuals
            .panel_fill,
        eframe::egui::Color32::from_rgb(23, 27, 31)
    );
    fs::remove_file(&path).unwrap();
    let unrelated = directory.0.join("Personal.json");
    files::create(&unrelated, b"preserve").unwrap();
    symlink(&unrelated, &path).unwrap();
    assert!(library.import(&value).is_err());
    assert!(library.remove(&id).is_err());
    assert_eq!(fs::read(&unrelated).unwrap(), b"preserve");
    fs::remove_file(&path).unwrap();
    fs::hard_link(&unrelated, &path).unwrap();
    assert!(library.import(&value).is_err());
    assert!(library.remove(&id).is_err());
    assert_eq!(fs::read(&unrelated).unwrap(), b"preserve");
    assert!(library.remove("../../Personal").is_err());
}

#[test]
fn imports_refuse_unsafe_sources_and_do_not_change_source_files() {
    let directory = Directory::new();
    let path = directory.0.join("Source.json");
    let bytes = palette().bytes().unwrap();
    files::create(&path, &bytes).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Library::read_import(&path).is_ok());
    let linked = directory.0.join("Link.json");
    symlink(&path, &linked).unwrap();
    assert!(Library::read_import(&linked).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(Library::read_import(&path).is_err());
    assert_eq!(fs::read(&path).unwrap(), bytes);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&path, vec![b' '; MAX_BYTES + 1]).unwrap();
    assert!(Library::read_import(&path).is_err());
}

#[test]
fn import_count_is_bounded_without_replacing_existing_files() {
    let directory = Directory::new();
    for index in 0..MAX_IMPORTED {
        let mut value = palette();
        value.name = format!("Ocean {index}");
        let bytes = value.bytes().unwrap();
        files::create(
            &directory.0.join(format!("{}.json", identifier(&bytes))),
            &bytes,
        )
        .unwrap();
    }
    let mut library = directory.library();
    assert_eq!(library.entries.len(), 14 + MAX_IMPORTED);
    assert!(library.import(&palette()).is_err());
    assert_eq!(paths(&directory.0).unwrap().len(), MAX_IMPORTED);
}
