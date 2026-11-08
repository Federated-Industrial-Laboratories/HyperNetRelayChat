// SPDX-License-Identifier: Apache-2.0
//! A bounded local file chooser for configuration and existing runtime assets.
use super::{PathBuf, c, egui};
use std::os::unix::fs::FileTypeExt;
#[derive(Default)]
pub(in crate::desktop) struct Picker {
    target: Option<&'static str>,
    directory: PathBuf,
    entries: Vec<(PathBuf, bool)>,
    folder: bool,
    selected: Option<(&'static str, PathBuf)>,
    error: Option<String>,
}
impl Picker {
    pub fn open(&mut self, target: &'static str, path: &std::path::Path, folder: bool) {
        self.target = Some(target);
        self.folder = folder;
        let directory = if path.is_dir() {
            path.to_owned()
        } else {
            path.parent()
                .filter(|p| p.is_dir())
                .map(std::path::Path::to_owned)
                .unwrap_or_else(|| {
                    std::env::var_os("HOME")
                        .map(PathBuf::from)
                        .unwrap_or_else(|| "/".into())
                })
        };
        self.read(directory);
    }
    fn read(&mut self, path: PathBuf) {
        self.directory = path;
        self.entries.clear();
        self.error = None;
        match std::fs::read_dir(&self.directory) {
            Ok(entries) => {
                for entry in entries.take(256).flatten() {
                    if let Ok(kind) = entry.file_type()
                        && (kind.is_dir()
                            || kind.is_file()
                            || kind.is_symlink()
                            || kind.is_socket())
                    {
                        self.entries.push((entry.path(), entry.path().is_dir()));
                    }
                }
                self.entries
                    .sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
            }
            Err(_) => self.error = Some("This folder could not be read.".into()),
        }
    }
    pub fn take(&mut self, target: &str) -> Option<PathBuf> {
        if self.selected.as_ref().is_some_and(|v| v.0 == target) {
            self.selected.take().map(|v| v.1)
        } else {
            None
        }
    }
    pub fn show(&mut self, ctx: &egui::Context) {
        let Some(target) = self.target else { return };
        let mut open = true;
        let mut navigate = None;
        let mut selected = None;
        egui::Window::new("Choose a local file or folder")
            .id(egui::Id::unique("operations-picker"))
            .open(&mut open)
            .default_width(620.0)
            .show(ctx, |ui| {
                ui.add(egui::Label::new(self.directory.display().to_string()).wrap());
                ui.horizontal(|ui| {
                    if c::button(ui, "Up").clicked() {
                        navigate = self.directory.parent().map(std::path::Path::to_owned);
                    }
                    if self.folder && c::button(ui, "Choose folder").clicked() {
                        selected = Some(self.directory.clone());
                    }
                });
                if let Some(error) = &self.error {
                    ui.label(error);
                }
                egui::ScrollArea::vertical()
                    .max_height(400.0)
                    .show(ui, |ui| {
                        for (path, directory) in &self.entries {
                            if self.folder && !directory {
                                continue;
                            }
                            let label = format!(
                                "{}{}",
                                if *directory { "[Folder] " } else { "" },
                                path.file_name().unwrap_or_default().to_string_lossy()
                            );
                            if c::row(ui, false, &label).clicked() {
                                if *directory {
                                    navigate = Some(path.clone());
                                } else {
                                    selected = Some(path.clone());
                                }
                            }
                        }
                    });
                if self.entries.len() == 256 {
                    ui.small("Showing up to 256 entries. Choose a narrower folder.");
                }
            });
        if let Some(path) = navigate {
            self.read(path);
        }
        if let Some(path) = selected {
            self.selected = Some((target, path));
            open = false;
        }
        if !open {
            self.target = None;
        }
    }
}
