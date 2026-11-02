// SPDX-License-Identifier: MIT
// Give native boxes one hard-edged outline without changing content or interaction geometry.
use eframe::egui::{
    self, Color32, CornerRadius, Shape, Ui,
    epaint::{PathShape, PathStroke},
};
use std::sync::Arc;

const CORNER_CUT: f32 = 5.0;
const MIN_BOX_SIDE: f32 = 3.0;

fn apply(ctx: &egui::Context, style: &mut egui::Style) {
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
    ctx.on_end_pass("HRC box outlines", Arc::new(finish));
}

fn finish(ui: &mut Ui) {
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
                        box_outline(&mut clipped.shape);
                    });
                }
            }
        }
    });
}

fn box_outline(shape: &mut Shape) {
    match shape {
        Shape::Vec(shapes) => {
            for shape in shapes {
                box_outline(shape);
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
            let cut = CORNER_CUT.min(rect.width() * 0.5).min(rect.height() * 0.5);
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
        style.visuals.panel_fill = Color32::from_rgb(27, 30, 34);
        style.visuals.window_fill = Color32::from_rgb(27, 30, 34);
        style.visuals.extreme_bg_color = Color32::from_rgb(17, 20, 23);
        style.visuals.selection.bg_fill = Color32::from_rgb(49, 80, 86);
        style.visuals.selection.stroke = egui::Stroke::new(1.0, Color32::from_rgb(183, 218, 219));
        style.visuals.hyperlink_color = Color32::from_rgb(139, 194, 201);
    }
    style.spacing.item_spacing = egui::vec2(8.0, if compact { 4.0 } else { 8.0 });
    style.spacing.button_padding = egui::vec2(10.0, if compact { 3.0 } else { 6.0 });
    style.spacing.interact_size.y = if compact { 24.0 } else { 32.0 };
    for font in style.text_styles.values_mut() {
        font.size *= scale.clamp(0.75, 2.0);
    }
    apply(ctx, &mut style);
    ctx.set_theme(theme);
    ctx.set_style_of(theme, style);
}
