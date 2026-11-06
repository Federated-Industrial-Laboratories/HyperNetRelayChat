// SPDX-License-Identifier: Apache-2.0
//! Keep egui's accessible text control while enforcing HRC grapheme and size rules.
use eframe::egui::{
    self,
    text::{CCursor, CCursorRange, CharIndex},
};
use hrc::presentation::editor::{self, Editor};
use std::ops::Range;

fn byte(text: &str, character: CharIndex) -> usize {
    text.char_indices()
        .nth(character.0)
        .map_or(text.len(), |(i, _)| i)
}
fn character(text: &str, byte: usize) -> CharIndex {
    CharIndex(text[..byte].chars().count())
}
struct Buffer<'a> {
    editor: &'a mut Editor,
    editable: bool,
    rejected: bool,
}
impl egui::TextBuffer for Buffer<'_> {
    fn is_mutable(&self) -> bool {
        self.editable
    }
    fn as_str(&self) -> &str {
        self.editor.text()
    }
    fn insert_text(&mut self, text: &str, at: CharIndex) -> usize {
        if !self.editable {
            return 0;
        }
        let at = editor::floor(self.editor.text(), byte(self.editor.text(), at));
        if self.editor.replace(at..at, text).is_err() {
            self.rejected = true;
            0
        } else {
            text.chars().count()
        }
    }
    fn delete_char_range(&mut self, range: Range<CharIndex>) {
        if !self.editable {
            return;
        }
        let start = byte(self.editor.text(), range.start);
        let end = byte(self.editor.text(), range.end);
        let _ = self.editor.replace(start..end, "");
    }
    fn delete_selected_ccursor_range(&mut self, [min, max]: [CCursor; 2]) -> CCursor {
        self.delete_char_range(min.index..max.index);
        CCursor::new(character(self.editor.text(), self.editor.cursor()))
    }
    fn char_range(&self, range: Range<CharIndex>) -> &str {
        let text = self.editor.text();
        &text[editor::floor(text, byte(text, range.start))
            ..editor::ceil(text, byte(text, range.end))]
    }
    fn replace_with(&mut self, text: &str) {
        if !self.editable {
            return;
        }
        if self
            .editor
            .replace(0..self.editor.text().len(), text)
            .is_err()
        {
            self.rejected = true;
        }
    }
    fn type_id(&self) -> std::any::TypeId {
        std::any::TypeId::of::<Buffer<'static>>()
    }
}

pub struct Output {
    pub response: egui::WidgetAtomResponse,
    pub rejected: bool,
}
pub fn show(ui: &mut egui::Ui, id: egui::Id, editor: &mut Editor) -> Output {
    let checkpoint = editor.clone();
    let mut state = egui::TextEdit::load_state(ui.ctx(), id).unwrap_or_default();
    if let Some(range) = state.cursor.char_range() {
        editor.select(
            byte(editor.text(), range.secondary.index),
            byte(editor.text(), range.primary.index),
        );
    }
    if ui.is_enabled() && ui.memory(|memory| memory.has_focus(id)) {
        ui.input_mut(|input| {
            input.events.retain(|event| {
                let egui::Event::Key {
                    key,
                    pressed: true,
                    modifiers,
                    ..
                } = event
                else {
                    return true;
                };
                if modifiers.command || modifiers.ctrl {
                    match key {
                        egui::Key::Z if modifiers.shift => editor.redo(),
                        egui::Key::Z => editor.undo(),
                        egui::Key::Y => editor.redo(),
                        _ => return true,
                    }
                    return false;
                }
                if modifiers.alt {
                    return true;
                }
                match key {
                    egui::Key::ArrowLeft => editor.left(modifiers.shift),
                    egui::Key::ArrowRight => editor.right(modifiers.shift),
                    _ => return true,
                }
                false
            })
        });
    }
    state.cursor.set_char_range(Some(CCursorRange::two(
        CCursor::new(character(editor.text(), editor.anchor())),
        CCursor::new(character(editor.text(), editor.cursor())),
    )));
    state.store(ui.ctx(), id);
    let before = editor.cursor();
    let mut buffer = Buffer {
        editor,
        editable: ui.is_enabled(),
        rejected: false,
    };
    let mut output = egui::TextEdit::multiline(&mut buffer)
        .id(id)
        .interactive(ui.is_enabled())
        .hint_text("Message")
        .margin(egui::vec2(10.0, 9.0))
        .desired_rows(3)
        .desired_width(f32::INFINITY)
        .show(ui);
    let rejected = buffer.rejected;
    if rejected {
        *buffer.editor = checkpoint;
        output.state = egui::text_edit::TextEditState::default();
        output.cursor_range = Some(CCursorRange::two(
            CCursor::new(character(buffer.editor.text(), buffer.editor.anchor())),
            CCursor::new(character(buffer.editor.text(), buffer.editor.cursor())),
        ));
    }
    if let Some(mut range) = output.cursor_range {
        let text = buffer.editor.text();
        let primary = byte(text, range.primary.index);
        let secondary = byte(text, range.secondary.index);
        let (primary, secondary) = if primary == secondary {
            let p = if primary > before {
                editor::ceil(text, primary)
            } else {
                editor::floor(text, primary)
            };
            (p, p)
        } else if primary < secondary {
            (editor::floor(text, primary), editor::ceil(text, secondary))
        } else {
            (editor::ceil(text, primary), editor::floor(text, secondary))
        };
        range.primary.index = character(text, primary);
        range.secondary.index = character(text, secondary);
        buffer.editor.select(secondary, primary);
        output.state.cursor.set_char_range(Some(range));
        output.state.store(ui.ctx(), id);
    }
    Output {
        response: output.response,
        rejected,
    }
}

#[cfg(test)]
#[path = "../../Tests/Presentation/GraphicalEditor.rs"]
mod tests;
