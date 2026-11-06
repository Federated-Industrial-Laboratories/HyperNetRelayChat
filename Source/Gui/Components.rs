// SPDX-License-Identifier: Apache-2.0
//! Shared geometry and surfaces for the native conversation interface.
use eframe::egui::{self, Color32, Response, RichText, Ui};

pub const ACTION_WIDTH: f32 = 128.0;
pub const CONTROL_HEIGHT: f32 = 32.0;

pub fn accent(ui: &Ui) -> Color32 {
    if ui.visuals().dark_mode {
        Color32::from_rgb(139, 194, 201)
    } else {
        Color32::from_rgb(35, 104, 116)
    }
}

pub fn surface(ui: &Ui) -> Color32 {
    if ui.visuals().dark_mode {
        Color32::from_rgb(32, 37, 42)
    } else {
        Color32::from_rgb(248, 250, 251)
    }
}

pub fn frame(ui: &Ui) -> egui::Frame {
    egui::Frame::new()
        .fill(surface(ui))
        .stroke(ui.visuals().widgets.noninteractive.bg_stroke)
        .inner_margin(12)
}

pub fn button(ui: &mut Ui, label: &str) -> Response {
    ui.add_sized(
        [ACTION_WIDTH.min(ui.available_width()), CONTROL_HEIGHT],
        egui::Button::new(label).truncate(),
    )
    .on_hover_text(label)
}

pub fn primary(ui: &mut Ui, label: &str) -> Response {
    ui.add_sized(
        [ACTION_WIDTH.min(ui.available_width()), CONTROL_HEIGHT],
        egui::Button::new(RichText::new(label).strong())
            .fill(ui.visuals().selection.bg_fill)
            .truncate(),
    )
}

pub fn choice(ui: &mut Ui, selected: bool, label: &str) -> Response {
    ui.add_sized(
        [ACTION_WIDTH.min(ui.available_width()), CONTROL_HEIGHT],
        egui::Button::new(label).selected(selected).truncate(),
    )
}

pub fn row(ui: &mut Ui, selected: bool, label: &str) -> Response {
    ui.add_sized(
        [ui.available_width(), CONTROL_HEIGHT + 6.0],
        egui::Button::new((label, egui::Atom::grow()))
            .selected(selected)
            .frame_when_inactive(false)
            .truncate(),
    )
    .on_hover_text(label)
}

pub fn badge(ui: &mut Ui, label: &str, colour: Color32) -> Response {
    egui::Frame::new()
        .fill(colour.gamma_multiply(if ui.visuals().dark_mode { 0.14 } else { 0.08 }))
        .stroke(egui::Stroke::new(1.0, colour.gamma_multiply(0.45)))
        .inner_margin(egui::Margin::symmetric(7, 3))
        .show(ui, |ui| {
            ui.label(RichText::new(label).size(11.0).color(colour))
        })
        .response
}

pub fn accent_badge(ui: &mut Ui, label: &str) -> Response {
    let colour = accent(ui);
    badge(ui, label, colour)
}

pub fn muted_badge(ui: &mut Ui, label: &str) -> Response {
    let colour = ui.visuals().weak_text_color();
    badge(ui, label, colour)
}

pub fn section(ui: &mut Ui, title: &str, add: impl FnOnce(&mut Ui)) {
    frame(ui).show(ui, |ui| {
        ui.set_width(ui.available_width());
        ui.label(RichText::new(title).strong().size(16.0));
        ui.add_space(6.0);
        add(ui);
    });
    ui.add_space(8.0);
}

pub fn field(ui: &mut Ui, label: &str, add: impl FnOnce(&mut Ui)) {
    ui.horizontal(|ui| {
        ui.add_sized(
            [128.0, CONTROL_HEIGHT],
            egui::Label::new(label).halign(egui::Align::Min),
        );
        ui.vertical_centered_justified(add);
    });
}

pub fn readout(ui: &mut Ui, label: &str, value: &str) -> Response {
    egui::Frame::new()
        .fill(surface(ui))
        .stroke(ui.visuals().widgets.noninteractive.bg_stroke)
        .inner_margin(egui::Margin::symmetric(9, 5))
        .show(ui, |ui| {
            ui.spacing_mut().interact_size.y = 16.0;
            ui.horizontal(|ui| {
                ui.label(RichText::new(label).size(10.0).weak());
                ui.label(RichText::new(value).size(11.0).monospace());
            });
        })
        .response
}
