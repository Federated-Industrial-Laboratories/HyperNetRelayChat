// SPDX-License-Identifier: MIT
// Give native boxes one hard-edged outline without changing content or interaction geometry.
use eframe::egui::{
    self, Color32, CornerRadius, Shape, Ui,
    epaint::{PathShape, PathStroke},
};
use std::sync::Arc;

#[path = "ThemeUi.rs"]
mod controls;
#[path = "ThemeData.rs"]
mod data;
#[path = "ThemeLibrary.rs"]
mod library;
pub(super) use controls::{Chooser, controls};
use data::Palette;
pub(super) use library::Library;

const CORNER_CUT: f32 = 5.0;
const MIN_BOX_SIDE: f32 = 3.0;

fn apply(ctx: &egui::Context, style: &mut egui::Style, corner_cut: f32) {
    style.visuals.window_corner_radius = CornerRadius::ZERO;
    style.visuals.menu_corner_radius = CornerRadius::ZERO;
    for widget in [
        &mut style.visuals.widgets.noninteractive,
        &mut style.visuals.widgets.inactive,
        &mut style.visuals.widgets.hovered,
        &mut style.visuals.widgets.active,
        &mut style.visuals.widgets.open,
    ] {
        widget.corner_radius = CornerRadius::ZERO;
    }
    style.visuals.handle_shape = egui::style::HandleShape::Rect { aspect_ratio: 0.75 };
    ctx.on_end_pass(
        "HRC box outlines",
        Arc::new(move |ui| finish(ui, corner_cut)),
    );
}

fn finish(ui: &mut Ui, corner_cut: f32) {
    let ctx = ui.ctx();
    let mut layers = ctx.memory(|memory| memory.layer_ids().collect::<Vec<_>>());
    if !layers.contains(&ui.layer_id()) {
        layers.push(ui.layer_id());
    }
    ctx.graphics_mut(|graphics| {
        for layer in layers {
            if let Some(list) = graphics.get_mut(layer) {
                for index in 0..list.next_idx().0 {
                    list.mutate_shape(egui::layers::ShapeIdx(index), |clipped| {
                        box_outline(&mut clipped.shape, corner_cut);
                    });
                }
            }
        }
    });
}

fn box_outline(shape: &mut Shape, corner_cut: f32) {
    match shape {
        Shape::Vec(shapes) => {
            for shape in shapes {
                box_outline(shape, corner_cut);
            }
        }
        Shape::Rect(rectangle)
            if rectangle.brush.is_none()
                && rectangle.blur_width == 0.0
                && rectangle.angle == 0.0
                && rectangle.rect.is_finite()
                && rectangle.rect.width() >= MIN_BOX_SIDE
                && rectangle.rect.height() >= MIN_BOX_SIDE
                && (rectangle.fill != Color32::TRANSPARENT || !rectangle.stroke.is_empty()) =>
        {
            let rect = rectangle.rect;
            let cut = corner_cut.min(rect.width() * 0.5).min(rect.height() * 0.5);
            let points = vec![
                rect.left_top(),
                egui::pos2(rect.right() - cut, rect.top()),
                egui::pos2(rect.right(), rect.top() + cut),
                rect.right_bottom(),
                rect.left_bottom(),
            ];
            let stroke = PathStroke::from(rectangle.stroke).with_kind(rectangle.stroke_kind);
            *shape = Shape::Path(PathShape::convex_polygon(points, rectangle.fill, stroke));
        }
        _ => {}
    }
}

pub fn configure(ctx: &egui::Context, light: bool, compact: bool, scale: f32) {
    configure_palette(ctx, light, compact, scale, None);
}

#[derive(Clone, Copy)]
struct Extras {
    surface: Color32,
    custom: bool,
}
pub fn surface(ui: &Ui) -> Color32 {
    ui.ctx()
        .data(|data| data.get_temp::<Extras>(egui::Id::unique("hrc-theme-extras")))
        .map_or(ui.visuals().window_fill, |extras| extras.surface)
}
fn custom(ui: &Ui) -> bool {
    ui.ctx()
        .data(|data| data.get_temp::<Extras>(egui::Id::unique("hrc-theme-extras")))
        .is_some_and(|extras| extras.custom)
}
pub fn warning(ui: &Ui) -> Color32 {
    if custom(ui) {
        ui.visuals().warn_fg_color
    } else {
        Color32::from_rgb(211, 170, 91)
    }
}
pub fn error(ui: &Ui) -> Color32 {
    if custom(ui) {
        ui.visuals().error_fg_color
    } else {
        Color32::LIGHT_RED
    }
}
pub fn online(ui: &Ui) -> Color32 {
    if !custom(ui) {
        Color32::from_rgb(117, 201, 153)
    } else if ui.visuals().dark_mode {
        Color32::from_rgb(148, 230, 173)
    } else {
        Color32::from_rgb(22, 83, 44)
    }
}
pub fn configure_selected(
    ctx: &egui::Context,
    preferences: &hrc::client::Preferences,
    library: &Library,
) {
    let palette = library
        .selected(preferences)
        .filter(|entry| !entry.original())
        .map(|entry| &entry.palette);
    configure_palette(
        ctx,
        preferences.theme == hrc::client::Theme::Light,
        preferences.density == hrc::client::Density::Compact,
        preferences.text_scale,
        palette,
    );
}
fn configure_palette(
    ctx: &egui::Context,
    light: bool,
    compact: bool,
    scale: f32,
    palette: Option<&Palette>,
) {
    let light = palette.map_or(light, |p| p.mode == data::Mode::Light);
    let theme = if light {
        egui::Theme::Light
    } else {
        egui::Theme::Dark
    };
    let mut style = egui::Style {
        visuals: if light {
            egui::Visuals::light()
        } else {
            egui::Visuals::dark()
        },
        ..Default::default()
    };
    if !light {
        style.visuals.override_text_color = Some(Color32::from_rgb(219, 227, 232));
        style.visuals.weak_text_color = Some(Color32::from_rgb(151, 165, 175));
        style.visuals.panel_fill = Color32::from_rgb(23, 27, 31);
        style.visuals.window_fill = Color32::from_rgb(30, 35, 40);
        style.visuals.extreme_bg_color = Color32::from_rgb(17, 21, 25);
        style.visuals.faint_bg_color = Color32::from_rgb(31, 36, 41);
        style.visuals.selection.bg_fill = Color32::from_rgb(49, 80, 86);
        style.visuals.selection.stroke = egui::Stroke::new(1.0, Color32::from_rgb(183, 218, 219));
        style.visuals.hyperlink_color = Color32::from_rgb(139, 194, 201);
        style.visuals.widgets.noninteractive.bg_stroke =
            egui::Stroke::new(1.0, Color32::from_rgb(54, 62, 69));
        style.visuals.widgets.inactive.weak_bg_fill = Color32::from_rgb(38, 44, 50);
        style.visuals.widgets.hovered.weak_bg_fill = Color32::from_rgb(47, 61, 68);
        style.visuals.widgets.active.weak_bg_fill = Color32::from_rgb(49, 80, 86);
    } else {
        style.visuals.override_text_color = Some(Color32::from_rgb(32, 45, 55));
        style.visuals.weak_text_color = Some(Color32::from_rgb(83, 100, 110));
        style.visuals.panel_fill = Color32::from_rgb(235, 240, 242);
        style.visuals.window_fill = Color32::from_rgb(248, 250, 251);
        style.visuals.extreme_bg_color = Color32::from_rgb(255, 255, 255);
        style.visuals.faint_bg_color = Color32::from_rgb(244, 247, 248);
        style.visuals.selection.bg_fill = Color32::from_rgb(202, 226, 230);
        style.visuals.selection.stroke = egui::Stroke::new(1.0, Color32::from_rgb(35, 104, 116));
        style.visuals.hyperlink_color = Color32::from_rgb(35, 104, 116);
    }
    let mut surface = if light {
        Color32::from_rgb(248, 250, 251)
    } else {
        Color32::from_rgb(32, 37, 42)
    };
    let mut corner_cut = CORNER_CUT;
    if let Some(palette) = palette {
        let c = &palette.colors;
        surface = c.surface.colour();
        corner_cut = palette.display.corner_cut;
        let width = palette.display.outline_width;
        let visuals = &mut style.visuals;
        visuals.override_text_color = Some(c.text.colour());
        visuals.weak_text_color = Some(c.muted.colour());
        visuals.panel_fill = c.panel.colour();
        visuals.window_fill = c.window.colour();
        visuals.extreme_bg_color = c.input.colour();
        visuals.faint_bg_color = c.faint.colour();
        visuals.selection.bg_fill = c.selection.colour();
        visuals.selection.stroke = egui::Stroke::new(width, c.selection_text.colour());
        visuals.hyperlink_color = c.accent.colour();
        visuals.window_stroke = egui::Stroke::new(width, c.border.colour());
        visuals.warn_fg_color = if light {
            Color32::from_rgb(112, 64, 0)
        } else {
            Color32::from_rgb(246, 203, 125)
        };
        visuals.error_fg_color = if light {
            Color32::from_rgb(144, 18, 31)
        } else {
            Color32::from_rgb(255, 196, 189)
        };
        for (widget, fill) in [
            (&mut visuals.widgets.noninteractive, c.faint),
            (&mut visuals.widgets.inactive, c.button),
            (&mut visuals.widgets.hovered, c.hover),
            (&mut visuals.widgets.active, c.pressed),
            (&mut visuals.widgets.open, c.selection),
        ] {
            widget.bg_fill = fill.colour();
            widget.weak_bg_fill = fill.colour();
            widget.bg_stroke = egui::Stroke::new(width, c.border.colour());
            widget.fg_stroke = egui::Stroke::new(width, c.text.colour());
        }
    }
    style.spacing.item_spacing = egui::vec2(8.0, if compact { 6.0 } else { 9.0 });
    style.spacing.button_padding = egui::vec2(12.0, 7.0);
    style.spacing.interact_size = egui::vec2(128.0, 32.0);
    style.spacing.text_edit_width = 320.0;
    style.spacing.slider_width = 240.0;
    style.spacing.window_margin = egui::Margin::same(16);
    for font in style.text_styles.values_mut() {
        font.size *= scale.clamp(0.75, 2.0);
    }
    apply(ctx, &mut style, corner_cut);
    ctx.data_mut(|data| {
        data.insert_temp(
            egui::Id::unique("hrc-theme-extras"),
            Extras {
                surface,
                custom: palette.is_some(),
            },
        )
    });
    ctx.set_theme(theme);
    ctx.set_style_of(theme, style);
}
