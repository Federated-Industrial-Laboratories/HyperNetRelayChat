// SPDX-License-Identifier: Apache-2.0
//! Signed native-package import with an explicit, digest-bound review.
use super::*;
pub(super) struct Form {
    config: ops::packages::Configuration,
    pub preview: Option<Value>,
}
impl Default for Form {
    fn default() -> Self {
        Self {
            config: ops::packages::Configuration {
                product: ops::packages::Product::Core,
                downloads: std::env::var_os("HOME")
                    .map(PathBuf::from)
                    .unwrap_or_default()
                    .join("Downloads"),
            },
            preview: None,
        }
    }
}
impl Workspace {
    pub(super) fn packages_ui(&mut self, ui: &mut egui::Ui) {
        let ctx = ui.ctx().clone();
        ui.heading("Native packages");
        c::section(ui, "Import a signed release", |ui| {
            let before = (
                self.packages.config.product,
                self.packages.config.downloads.clone(),
            );
            ui.horizontal(|ui| {
                ui.selectable_value(
                    &mut self.packages.config.product,
                    ops::packages::Product::Core,
                    "HyperNet Core",
                );
                ui.selectable_value(
                    &mut self.packages.config.product,
                    ops::packages::Product::Suite,
                    "HyperNetSuite",
                );
            });
            path(
                ui,
                "Download folder",
                &mut self.packages.config.downloads,
                &mut self.picker,
                "native-downloads",
                true,
            );
            if before
                != (
                    self.packages.config.product,
                    self.packages.config.downloads.clone(),
                )
            {
                self.packages.preview = None;
            }
            let product = self.packages.config.product;
            c::readout(ui, "REQUIRED VERSION", product.version());
            ui.label("Select the folder containing the release .tar, .tar.sig, .target.json, .target.json.sig and Publisher.pub files.");
            ui.hyperlink_to(
                "Open release downloads",
                format!(
                    "https://github.com/Federated-Industrial-Laboratories/{}/releases/tag/v{}",
                    product.name(),
                    product.version()
                ),
            );
            ui.horizontal_wrapped(|ui| {
                c::muted_badge(ui, "Pinned publisher");
                c::muted_badge(ui, "Per-user installation");
                c::muted_badge(ui, "No system package changes");
            });
            if c::primary(ui, "Verify package").clicked() {
                let config = self.packages.config.clone();
                self.start(
                    &ctx,
                    "Verify native package",
                    Completion::PackagePreview,
                    move |cancel| ops::packages::preview(&config, cancel),
                );
            }
        });
        if let Some(preview) = self.packages.preview.clone() {
            c::section(ui, "Installation review", |ui| {
                ui.horizontal_wrapped(|ui| {
                    c::readout(ui, "PRODUCT", preview["product"].as_str().unwrap_or(""));
                    c::readout(ui, "VERSION", preview["version"].as_str().unwrap_or(""));
                });
                ui.add(egui::Label::new(preview["destination"].as_str().unwrap_or("")).wrap());
                if let Some(digest) = preview["digest"].as_str().map(str::to_owned)
                    && c::primary(ui, "Install package").clicked()
                {
                    let config = self.packages.config.clone();
                    self.start(
                        &ctx,
                        "Install native package",
                        Completion::PackageInstalled,
                        move |cancel| ops::packages::install(&config, &digest, cancel),
                    );
                }
            });
        }
        if c::button(ui, "Network setup").clicked() {
            self.page = Page::Network;
        }
    }
}
