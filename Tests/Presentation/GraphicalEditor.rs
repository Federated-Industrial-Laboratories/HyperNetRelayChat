use super::*;
fn frame(ctx: &egui::Context, editor: &mut Editor, events: Vec<egui::Event>) -> bool {
    frame_enabled(ctx, editor, events, true)
}
fn frame_enabled(
    ctx: &egui::Context,
    editor: &mut Editor,
    events: Vec<egui::Event>,
    enabled: bool,
) -> bool {
    let id = egui::Id::unique("test-composer");
    ctx.memory_mut(|m| m.request_focus(id));
    let mut rejected = false;
    let mut output = ctx.run_ui(
        egui::RawInput {
            screen_rect: Some(egui::Rect::from_min_size(
                egui::Pos2::ZERO,
                egui::vec2(640.0, 300.0),
            )),
            events,
            ..Default::default()
        },
        |ui| {
            rejected = ui
                .add_enabled_ui(enabled, |ui| show(ui, id, editor))
                .inner
                .rejected;
        },
    );
    output.textures_delta.clear();
    rejected
}

#[test]
fn a_disabled_composer_cannot_accept_paste_or_custom_undo() {
    let ctx = egui::Context::default();
    let mut editor = Editor::new("saved draft").unwrap();
    editor.insert(" latest").unwrap();
    frame(&ctx, &mut editor, vec![]);
    frame_enabled(
        &ctx,
        &mut editor,
        vec![egui::Event::Paste(" blocked".into())],
        false,
    );
    assert_eq!(editor.text(), "saved draft latest");
    frame_enabled(
        &ctx,
        &mut editor,
        vec![key(egui::Key::Z, egui::Modifiers::CTRL)],
        false,
    );
    assert_eq!(editor.text(), "saved draft latest");
}
fn key(key: egui::Key, modifiers: egui::Modifiers) -> egui::Event {
    egui::Event::Key {
        key,
        physical_key: None,
        pressed: true,
        repeat: false,
        modifiers,
    }
}
#[test]
fn graphical_edits_keep_clusters_and_invalid_replacement_paste_keeps_the_draft() {
    let ctx = egui::Context::default();
    let mut editor = Editor::new("e\u{301}👩‍🚀").unwrap();
    frame(&ctx, &mut editor, vec![]);
    frame(
        &ctx,
        &mut editor,
        vec![key(egui::Key::ArrowLeft, egui::Modifiers::NONE)],
    );
    assert_eq!(editor.cursor(), "e\u{301}".len());
    frame(
        &ctx,
        &mut editor,
        vec![key(egui::Key::Backspace, egui::Modifiers::NONE)],
    );
    assert_eq!(editor.text(), "👩‍🚀");
    frame(
        &ctx,
        &mut editor,
        vec![key(egui::Key::Z, egui::Modifiers::CTRL)],
    );
    assert_eq!(editor.text(), "e\u{301}👩‍🚀");
    frame(
        &ctx,
        &mut editor,
        vec![key(egui::Key::A, egui::Modifiers::CTRL)],
    );
    assert!(frame(
        &ctx,
        &mut editor,
        vec![egui::Event::Paste("x".repeat(8193))]
    ));
    assert_eq!(editor.text(), "e\u{301}👩‍🚀");
}
