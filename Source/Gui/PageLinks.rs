// SPDX-License-Identifier: Apache-2.0
//! Canonical HyperNet Page addresses remain complete while their visible labels stay compact.
use super::*;
use std::ops::Range;

const PREFIX: &str = "hypernet://";
const MAX_LINKS: usize = 16;
const MAX_MESSAGE: usize = 8192;

pub(crate) struct Address<'a> {
    pub network: &'a str,
    pub author: &'a str,
    pub namespace: &'a str,
    pub page: &'a str,
}
impl<'a> Address<'a> {
    pub(crate) fn parse(value: &'a str) -> Option<Self> {
        if value.len() > 512 {
            return None;
        }
        let mut fields = value.strip_prefix(PREFIX)?.split('/');
        let address = Self {
            network: fields.next()?,
            author: fields.next()?,
            namespace: fields.next()?,
            page: fields.next()?,
        };
        let hexadecimal = |s: &str, length| {
            s.len() == length
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        };
        let namespace = address.namespace;
        (fields.next().is_none()
            && hexadecimal(address.network, 64)
            && hexadecimal(address.author, 64)
            && hexadecimal(address.page, 32)
            && !namespace.is_empty()
            && namespace.len() <= 32
            && namespace.as_bytes()[0].is_ascii_alphabetic()
            && namespace.bytes().all(|b| b.is_ascii_alphanumeric()))
        .then_some(address)
    }
    fn label(&self) -> String {
        format!("Page: {} / {}…", self.namespace, &self.page[..8])
    }
}

fn delimiter(c: char) -> bool {
    c.is_whitespace() || "<>\"'()[]{}".contains(c)
}
fn ranges(text: &str) -> Vec<Range<usize>> {
    if text.len() > MAX_MESSAGE {
        return Vec::new();
    }
    let mut links = Vec::new();
    for (start, _) in text.match_indices(PREFIX).take(64) {
        if text[..start]
            .chars()
            .next_back()
            .is_some_and(|c| !delimiter(c))
        {
            continue;
        }
        let candidate = text[start..].split(delimiter).next().unwrap_or("");
        let candidate = candidate.trim_end_matches(['.', ',', ';', ':', '!']);
        if Address::parse(candidate).is_some() {
            links.push(start..start + candidate.len());
            if links.len() == MAX_LINKS {
                break;
            }
        }
    }
    links
}

pub(crate) struct Request {
    pub address: String,
    pub palette: Vec<u8>,
}

fn plain(ui: &mut egui::Ui, text: &str, action: bool) -> egui::Response {
    let text = egui::RichText::new(text);
    ui.add(
        egui::Label::new(if action { text.italics() } else { text })
            .wrap()
            .selectable(true),
    )
}
fn details(ui: &mut egui::Ui, uri: &str, address: &Address<'_>) {
    let viewport = ui.ctx().content_rect();
    let width = (viewport.width() - 40.0).clamp(80.0, 460.0);
    ui.set_max_width(width);
    egui::ScrollArea::vertical()
        .max_height((viewport.height() * 0.6).max(80.0))
        .show(ui, |ui| {
            ui.strong("HyperNet Page");
            for text in [
                format!("Namespace: {}", address.namespace),
                format!("Network: {}", address.network),
                format!("Author: {}", address.author),
                format!("Page: {}", address.page),
                uri.to_owned(),
            ] {
                let mut job = egui::text::LayoutJob::simple(
                    text,
                    egui::FontId::monospace(12.0),
                    ui.visuals().text_color(),
                    width,
                );
                job.wrap.break_anywhere = true;
                ui.label(job);
            }
            ui.label("Open in the configured HyperNet browser. Content is verified when opened.");
        });
}
fn link(ui: &mut egui::Ui, uri: &str, address: &Address<'_>) -> egui::Response {
    let response = ui
        .add(
            egui::Label::new(
                egui::RichText::new(address.label())
                    .color(ui.visuals().hyperlink_color)
                    .underline(),
            )
            .truncate()
            .sense(egui::Sense::click()),
        )
        .on_hover_cursor(egui::CursorIcon::PointingHand);
    response.widget_info(|| {
        egui::WidgetInfo::labeled(egui::Role::Link, ui.is_enabled(), address.label())
    });
    response.on_hover_ui(|ui| details(ui, uri, address))
}
impl App {
    pub(super) fn page_text(
        &mut self,
        ui: &mut egui::Ui,
        text: &str,
        action: bool,
    ) -> egui::Response {
        let links = ranges(text);
        if links.is_empty() {
            return plain(ui, text, action);
        }
        ui.horizontal_wrapped(|ui| {
            ui.spacing_mut().item_spacing.x = 0.0;
            let mut offset = 0;
            for range in links {
                if offset != range.start {
                    plain(ui, &text[offset..range.start], action);
                }
                let uri = &text[range.clone()];
                let address = Address::parse(uri).expect("parsed Page address");
                let response = link(ui, uri, &address);
                if response.clicked() {
                    match theme::browser_palette(&self.model.snapshot.preferences, &self.themes) {
                        Ok(palette) => {
                            self.page_request = Some(Request {
                                address: uri.into(),
                                palette,
                            })
                        }
                        Err(error) => self.model.error = Some(error.into()),
                    }
                }
                response.context_menu(|ui| {
                    if ui.button("Copy Page address").clicked() {
                        ui.ctx().copy_text(uri.to_owned());
                        ui.close();
                    }
                    if ui.button("Copy message").clicked() {
                        ui.ctx().copy_text(text.to_owned());
                        ui.close();
                    }
                });
                offset = range.end;
            }
            if offset != text.len() {
                plain(ui, &text[offset..], action);
            }
        })
        .response
    }
}

#[cfg(test)]
#[path = "../../Tests/Unit/Gui/PageLinks.rs"]
mod tests;
