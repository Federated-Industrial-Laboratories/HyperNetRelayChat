// SPDX-License-Identifier: Apache-2.0
//! Palette selection and explicit preview/import from a bounded local file browser.
use super::{
    data::{Mode, Palette},
    library::{Entry, Library},
};
use crate::gui::components as c;
use eframe::egui;
use hrc::client::{Preferences, Theme};
use std::path::{Path, PathBuf};

fn select(preferences: &mut Preferences, entry: &Entry) {
    preferences.theme = entry.palette.mode.theme();
    preferences.palette = (!entry.original()).then(|| entry.id.clone());
}
fn preview(ui: &mut egui::Ui, palette: &Palette) {
    let colors = &palette.colors;
    egui::Frame::new()
        .fill(colors.surface.colour())
        .stroke(egui::Stroke::new(1.0, colors.border.colour()))
        .inner_margin(12)
        .show(ui, |ui| {
            ui.set_width(ui.available_width().min(400.0));
            ui.horizontal_wrapped(|ui| {
                ui.colored_label(colors.text.colour(), &palette.name);
                for colour in [
                    colors.panel,
                    colors.surface,
                    colors.accent,
                    colors.selection,
                    colors.text,
                ] {
                    let (rect, _) =
                        ui.allocate_exact_size(egui::vec2(20.0, 20.0), egui::Sense::hover());
                    ui.painter().rect_filled(rect, 0.0, colour.colour());
                }
            });
            ui.horizontal_wrapped(|ui| {
                ui.colored_label(colors.muted.colour(), "12:34");
                ui.colored_label(colors.accent.colour(), "Alex");
                ui.colored_label(colors.text.colour(), "Ready when you are.");
            });
            egui::Frame::new()
                .fill(colors.selection.colour())
                .inner_margin(4)
                .show(ui, |ui| {
                    ui.colored_label(colors.selection_text.colour(), "Selected conversation");
                });
        });
}
pub fn controls(
    ui: &mut egui::Ui,
    preferences: &mut Preferences,
    library: &mut Library,
    chooser: &mut Chooser,
) {
    let selected = library.selected(preferences);
    let selected_name = selected
        .map(|entry| entry.palette.name.clone())
        .unwrap_or_else(|| match preferences.theme {
            Theme::Dark => "HyperNet Dark (fallback)".into(),
            Theme::Light => "HyperNet Light (fallback)".into(),
        });
    let removable = selected
        .filter(|entry| entry.imported)
        .map(|entry| entry.id.clone());
    c::field(ui, "Theme", |ui| {
        egui::ComboBox::from_id_salt("hrc-palette")
            .width(320.0_f32.min(ui.available_width()))
            .selected_text(&selected_name)
            .show_ui(ui, |ui| {
                for mode in [Mode::Dark, Mode::Light] {
                    ui.strong(if mode == Mode::Dark { "Dark" } else { "Light" });
                    for entry in library
                        .entries
                        .iter()
                        .filter(|entry| entry.palette.mode == mode)
                    {
                        let selected = library
                            .selected(preferences)
                            .is_some_and(|chosen| chosen.id == entry.id);
                        let label = if entry.imported {
                            format!("{} · imported", entry.palette.name)
                        } else {
                            entry.palette.name.clone()
                        };
                        if ui.selectable_label(selected, label).clicked() {
                            select(preferences, entry);
                        }
                    }
                }
            });
        ui.horizontal_wrapped(|ui| {
            if c::button(ui, "Import JSON…").clicked() {
                chooser.open();
            }
            if let Some(id) = &removable
                && c::button(ui, "Remove imported").clicked()
            {
                match library.remove(id) {
                    Ok(()) => preferences.palette = None,
                    Err(error) => chooser.message = Some(error),
                }
            }
        });
        if let Some(entry) = library.selected(preferences) {
            preview(ui, &entry.palette);
        }
        if preferences.palette.is_some() && library.selected(preferences).is_none() {
            ui.label("Selected theme unavailable. The original light or dark default is active.");
            if c::button(ui, "Use default").clicked() {
                preferences.palette = None;
            }
        }
        if let Some(problem) = library.problem {
            ui.label(problem);
        }
        if let Some(message) = chooser.message {
            ui.label(message);
        }
    });
    if let Some(id) = chooser.show(ui.ctx(), library)
        && let Some(entry) = library.entries.iter().find(|entry| entry.id == id)
    {
        select(preferences, entry);
    }
}

#[derive(Default)]
pub struct Chooser {
    visible: bool,
    folder: PathBuf,
    location: String,
    entries: Vec<(PathBuf, bool)>,
    limited: bool,
    preview: Option<Palette>,
    message: Option<&'static str>,
}
impl Chooser {
    fn open(&mut self) {
        self.visible = true;
        self.preview = None;
        self.message = None;
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| PathBuf::from("/"));
        self.read(home);
    }
    fn read(&mut self, path: PathBuf) {
        self.folder = path;
        self.location = self.folder.display().to_string();
        self.entries.clear();
        self.limited = false;
        self.preview = None;
        self.message = None;
        match std::fs::read_dir(&self.folder) {
            Ok(entries) => {
                for (index, entry) in entries.take(257).enumerate() {
                    if index == 256 {
                        self.limited = true;
                        break;
                    }
                    let Ok(entry) = entry else {
                        self.message = Some("Some folder entries could not be read.");
                        continue;
                    };
                    let Ok(kind) = entry.file_type() else {
                        continue;
                    };
                    if kind.is_dir()
                        || kind.is_file()
                            && entry
                                .path()
                                .extension()
                                .is_some_and(|v| v.eq_ignore_ascii_case("json"))
                    {
                        self.entries.push((entry.path(), kind.is_dir()));
                    }
                }
                self.entries
                    .sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            }
            Err(_) => self.message = Some("This folder could not be read."),
        }
    }
    fn inspect(&mut self, path: &Path) {
        match Library::read_import(path) {
            Ok(palette) => {
                self.preview = Some(palette);
                self.message = None;
            }
            Err(error) => {
                self.preview = None;
                self.message = Some(error);
            }
        }
    }
    fn show(&mut self, ctx: &egui::Context, library: &mut Library) -> Option<String> {
        if !self.visible {
            return None;
        }
        let mut visible = true;
        let mut navigate = None;
        let mut inspect = None;
        let mut imported = None;
        egui::Window::new("Import theme")
            .id(egui::Id::unique("hrc-theme-import"))
            .open(&mut visible)
            .default_width(640.0)
            .collapsible(false)
            .show(ctx, |ui| {
                ui.horizontal(|ui| {
                    ui.add(
                        egui::TextEdit::singleline(&mut self.location)
                            .desired_width(380.0)
                            .char_limit(4096),
                    );
                    if c::button(ui, "Open folder").clicked() {
                        navigate = Some(PathBuf::from(&self.location));
                    }
                });
                if c::button(ui, "Up").clicked() {
                    navigate = self.folder.parent().map(Path::to_owned);
                }
                egui::ScrollArea::vertical()
                    .id_salt("theme-files")
                    .max_height(240.0)
                    .show(ui, |ui| {
                        for (path, folder) in &self.entries {
                            let name = path.file_name().unwrap_or_default().to_string_lossy();
                            let label = if *folder {
                                format!("[Folder] {name}")
                            } else {
                                name.into_owned()
                            };
                            if c::row(ui, false, &label).clicked() {
                                if *folder {
                                    navigate = Some(path.clone());
                                } else {
                                    inspect = Some(path.clone());
                                }
                            }
                        }
                    });
                if self.limited {
                    ui.label("Showing up to 256 folder entries. Open a narrower folder.");
                }
                if let Some(palette) = &self.preview {
                    ui.separator();
                    preview(ui, palette);
                    if c::primary(ui, "Import and use").clicked() {
                        match library.import(palette) {
                            Ok(id) => imported = Some(id),
                            Err(error) => self.message = Some(error),
                        }
                    }
                }
                if let Some(message) = self.message {
                    ui.colored_label(super::error(ui), message);
                }
                if c::button(ui, "Cancel").clicked() {
                    self.visible = false;
                }
            });
        if !visible || imported.is_some() {
            self.visible = false;
        }
        if let Some(path) = navigate {
            self.read(path);
        }
        if let Some(path) = inspect {
            self.inspect(&path);
        }
        imported
    }
}
