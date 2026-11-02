// SPDX-License-Identifier: Apache-2.0
//! An atomic, bounded draft editor whose positions are extended-grapheme boundaries.
use crate::{messaging::Mention, protocol::AccountId};
use std::{collections::VecDeque, ops::Range};
use unicode_segmentation::UnicodeSegmentation;

#[derive(Clone, Debug, Default)]
struct State {
    text: String,
    cursor: usize,
    anchor: usize,
    mentions: Vec<Mention>,
}
#[derive(Clone, Debug, Default)]
pub struct Editor {
    state: State,
    undo: VecDeque<State>,
    redo: VecDeque<State>,
}
#[derive(Clone, Copy, Debug, thiserror::Error)]
#[error("draft exceeds 8192 bytes or 2000 graphemes, or contains unsupported controls")]
pub struct InvalidDraft;

fn valid(text: &str) -> bool {
    text.is_empty() || crate::text::message(text).is_ok()
}
pub fn floor(text: &str, position: usize) -> usize {
    if position >= text.len() {
        return text.len();
    }
    text.grapheme_indices(true)
        .map(|(i, _)| i)
        .take_while(|i| *i <= position)
        .last()
        .unwrap_or(0)
}
pub fn ceil(text: &str, position: usize) -> usize {
    text.grapheme_indices(true)
        .map(|(i, _)| i)
        .find(|i| *i >= position)
        .unwrap_or(text.len())
}
pub fn previous(text: &str, position: usize) -> usize {
    text.grapheme_indices(true)
        .map(|(i, _)| i)
        .take_while(|i| *i < position)
        .last()
        .unwrap_or(0)
}
pub fn next(text: &str, position: usize) -> usize {
    text.grapheme_indices(true)
        .map(|(i, _)| i)
        .find(|i| *i > position)
        .unwrap_or(text.len())
}
impl Editor {
    pub fn new(text: &str) -> Result<Self, InvalidDraft> {
        let mut editor = Self::default();
        editor.reset(text)?;
        Ok(editor)
    }
    /// Restore a different room's draft without carrying its undo history across rooms.
    pub fn reset(&mut self, text: &str) -> Result<(), InvalidDraft> {
        self.reset_draft(text, &[])
    }
    pub fn reset_draft(&mut self, text: &str, mentions: &[Mention]) -> Result<(), InvalidDraft> {
        if !valid(text) {
            return Err(InvalidDraft);
        }
        if mentions.len() > 16 {
            return Err(InvalidDraft);
        }
        let mut previous_end = 0;
        for mention in mentions {
            let start = mention.start as usize;
            let end = mention.end as usize;
            if start < previous_end
                || start >= end
                || end > text.len()
                || floor(text, start) != start
                || ceil(text, end) != end
            {
                return Err(InvalidDraft);
            }
            previous_end = end;
        }
        self.state = State {
            text: text.into(),
            cursor: text.len(),
            anchor: text.len(),
            mentions: mentions.to_vec(),
        };
        self.undo.clear();
        self.redo.clear();
        Ok(())
    }
    pub fn text(&self) -> &str {
        &self.state.text
    }
    pub fn cursor(&self) -> usize {
        self.state.cursor
    }
    /// The token before the cursor, bounded by a complete Unicode whitespace character.
    pub fn completion_range(&self) -> Range<usize> {
        let cursor = self.cursor();
        let start = self.text()[..cursor]
            .char_indices()
            .rev()
            .find(|(_, character)| character.is_whitespace())
            .map_or(0, |(index, character)| index + character.len_utf8());
        start..cursor
    }
    pub fn anchor(&self) -> usize {
        self.state.anchor
    }
    pub fn mentions(&self) -> &[Mention] {
        &self.state.mentions
    }
    pub fn selection(&self) -> Range<usize> {
        self.state.cursor.min(self.state.anchor)..self.state.cursor.max(self.state.anchor)
    }
    pub fn selected(&self) -> &str {
        &self.state.text[self.selection()]
    }
    pub fn select(&mut self, anchor: usize, cursor: usize) {
        self.state.anchor = floor(&self.state.text, anchor);
        self.state.cursor = floor(&self.state.text, cursor);
    }
    pub fn select_all(&mut self) {
        self.select(0, self.state.text.len());
    }
    fn move_to(&mut self, position: usize, extend: bool) {
        self.state.cursor = floor(&self.state.text, position);
        if !extend {
            self.state.anchor = self.state.cursor;
        }
    }
    pub fn left(&mut self, extend: bool) {
        let range = self.selection();
        let position = if !extend && !range.is_empty() {
            range.start
        } else {
            previous(self.text(), self.cursor())
        };
        self.move_to(position, extend);
    }
    pub fn right(&mut self, extend: bool) {
        let range = self.selection();
        let position = if !extend && !range.is_empty() {
            range.end
        } else {
            next(self.text(), self.cursor())
        };
        self.move_to(position, extend);
    }
    pub fn home(&mut self, extend: bool, whole: bool) {
        let position = if whole {
            0
        } else {
            self.text()[..self.cursor()]
                .rfind('\n')
                .map_or(0, |i| i + 1)
        };
        self.move_to(position, extend);
    }
    pub fn end(&mut self, extend: bool, whole: bool) {
        let position = if whole {
            self.text().len()
        } else {
            self.text()[self.cursor()..]
                .find('\n')
                .map_or(self.text().len(), |i| self.cursor() + i)
        };
        self.move_to(position, extend);
    }
    fn remember(&mut self) {
        if self.undo.len() == 32 {
            self.undo.pop_front();
        }
        self.undo.push_back(self.state.clone());
        self.redo.clear();
    }
    pub fn replace(&mut self, range: Range<usize>, text: &str) -> Result<(), InvalidDraft> {
        if range.start > range.end || range.end > self.text().len() || text.len() > 8192 {
            return Err(InvalidDraft);
        }
        let range = floor(self.text(), range.start)..ceil(self.text(), range.end);
        let mut candidate = self.state.text.clone();
        candidate.replace_range(range.clone(), text);
        if !valid(&candidate) {
            return Err(InvalidDraft);
        }
        if candidate == self.state.text {
            return Ok(());
        }
        let mut mentions = self.state.mentions.clone();
        mentions.retain_mut(|mention| {
            let start = mention.start as usize;
            let end = mention.end as usize;
            // Touching the selected spelling removes its binding; edits never retarget it.
            if range.start <= end && range.end >= start {
                return false;
            }
            if range.end < start {
                let removed = range.end - range.start;
                mention.start = (start - removed + text.len()) as u32;
                mention.end = (end - removed + text.len()) as u32;
            }
            true
        });
        self.remember();
        // A combining insertion can merge with a neighbouring cluster.
        let cursor = ceil(&candidate, range.start + text.len());
        self.state = State {
            text: candidate,
            cursor,
            anchor: cursor,
            mentions,
        };
        Ok(())
    }
    pub fn insert(&mut self, text: &str) -> Result<(), InvalidDraft> {
        self.replace(self.selection(), text)
    }
    pub fn complete_mention(
        &mut self,
        range: Range<usize>,
        account: AccountId,
        nickname: &str,
    ) -> Result<(), InvalidDraft> {
        if crate::text::handle(nickname).is_err() {
            return Err(InvalidDraft);
        }
        let before = self.clone();
        let start = floor(self.text(), range.start);
        let replacement = format!("@{nickname} ");
        self.replace(range, &replacement)?;
        if self.state.text == before.state.text {
            self.remember();
        }
        let end = start + replacement.len() - 1;
        self.state
            .mentions
            .retain(|mention| (mention.end as usize) <= start || (mention.start as usize) >= end);
        if self.state.mentions.len() >= 16 {
            *self = before;
            return Err(InvalidDraft);
        }
        self.state.mentions.push(Mention {
            account,
            start: start as u32,
            end: (start + replacement.len() - 1) as u32,
        });
        self.state.mentions.sort_by_key(|mention| mention.start);
        Ok(())
    }
    pub fn backspace(&mut self) {
        let mut range = self.selection();
        if range.is_empty() {
            range.start = previous(self.text(), range.start);
        }
        let _ = self.replace(range, "");
    }
    pub fn delete(&mut self) {
        let mut range = self.selection();
        if range.is_empty() {
            range.end = next(self.text(), range.end);
        }
        let _ = self.replace(range, "");
    }
    pub fn undo(&mut self) {
        if let Some(previous) = self.undo.pop_back() {
            self.redo
                .push_back(std::mem::replace(&mut self.state, previous));
        }
    }
    pub fn redo(&mut self) {
        if let Some(next) = self.redo.pop_back() {
            self.undo
                .push_back(std::mem::replace(&mut self.state, next));
        }
    }
}

#[cfg(test)]
#[path = "../../Tests/Presentation/Editor.rs"]
mod tests;
