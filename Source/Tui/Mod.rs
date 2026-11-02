// SPDX-License-Identifier: Apache-2.0
//! A bounded terminal surface over the same client commands and draft editor.
#[path = "Render.rs"]
mod render;
use crate::{
    commands,
    interaction::{Model, Panel},
};
use crossterm::{
    event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers},
    execute, terminal,
};
use hrc::client::Command;
use std::{
    io::{self, IsTerminal, Write},
    path::Path,
    time::Duration,
};

struct Terminal;
impl Terminal {
    fn open() -> io::Result<Self> {
        if !io::stdin().is_terminal() || !io::stdout().is_terminal() {
            return Err(io::ErrorKind::Unsupported.into());
        }
        terminal::enable_raw_mode()?;
        let guard = Self;
        execute!(
            io::stdout(),
            terminal::EnterAlternateScreen,
            event::EnableBracketedPaste,
            crossterm::cursor::Show
        )?;
        Ok(guard)
    }
}
impl Drop for Terminal {
    fn drop(&mut self) {
        let _ = execute!(
            io::stdout(),
            event::DisableBracketedPaste,
            crossterm::style::ResetColor,
            crossterm::style::SetAttribute(crossterm::style::Attribute::Reset),
            crossterm::cursor::Show,
            terminal::LeaveAlternateScreen
        );
        let _ = terminal::disable_raw_mode();
    }
}
pub fn run(profile: &Path, offline: bool) -> Result<(), &'static str> {
    let mut model = Model::open(profile, offline)?;
    let _terminal = Terminal::open().map_err(|_| "TerminalUnavailable")?;
    let mut scroll = 0;
    let mut dirty = true;
    let mut revision = u64::MAX;
    loop {
        if model.tick() {
            let _ = write!(io::stdout(), "\x07");
        }
        if model.closing && model.draft_saved() {
            break;
        }
        if dirty || revision != model.snapshot.revision {
            render::draw(&model, scroll).map_err(|_| "TerminalOutputFailed")?;
            dirty = false;
            revision = model.snapshot.revision;
        }
        if event::poll(Duration::from_millis(100)).map_err(|_| "TerminalInputFailed")? {
            dirty = true;
            match event::read().map_err(|_| "TerminalInputFailed")? {
                Event::Key(key) if key.kind != KeyEventKind::Release => {
                    key_event(&mut model, key, &mut scroll)
                }
                Event::Paste(text) => model.edit(|editor| editor.insert(&text)),
                Event::Resize(_, _) => {}
                _ => {}
            }
        }
    }
    model.controller.shutdown();
    Ok(())
}
fn key_event(model: &mut Model, key: KeyEvent, scroll: &mut usize) {
    let shift = key.modifiers.contains(KeyModifiers::SHIFT);
    let ctrl = key.modifiers.contains(KeyModifiers::CONTROL);
    let alt = key.modifiers.contains(KeyModifiers::ALT);
    match key.code {
        KeyCode::Char('q' | 'c') if ctrl => model.close(),
        KeyCode::Char('a') if ctrl => model.editor.select_all(),
        KeyCode::Char('z') if ctrl => {
            model.edit(|editor| {
                editor.undo();
                Ok(())
            });
        }
        KeyCode::Char('y') if ctrl => {
            model.edit(|editor| {
                editor.redo();
                Ok(())
            });
        }
        KeyCode::Char('j') if ctrl => model.edit(|e| e.insert("\n")),
        KeyCode::Char('n' | 'p') if ctrl => {
            let rooms = model
                .snapshot
                .rooms
                .iter()
                .filter(|r| r.joined)
                .map(|r| r.room)
                .collect::<Vec<_>>();
            if !rooms.is_empty() {
                let current = model
                    .snapshot
                    .selected
                    .as_ref()
                    .and_then(|selected| rooms.iter().position(|r| *r == selected.summary.room))
                    .unwrap_or(0);
                let next = if key.code == KeyCode::Char('n') {
                    (current + 1) % rooms.len()
                } else {
                    (current + rooms.len() - 1) % rooms.len()
                };
                model.select(rooms[next]);
                *scroll = 0;
            }
        }
        KeyCode::Char('f') if ctrl => {
            model.error = Some("Use /search TEXT; search filters are listed in /help".into());
        }
        KeyCode::Char('r') if ctrl => {
            model.dispatch(Command::Refresh);
        }
        KeyCode::Char('u') if ctrl => model.panel = Panel::Status,
        KeyCode::Esc => {
            model.panel = Panel::Conversation;
            model.error = None;
            model.reply = None;
            model.closing = false;
            model.dispatch(Command::CloseSearch);
        }
        KeyCode::F(1) => {
            model.panel = Panel::Help;
            *scroll = 0;
        }
        KeyCode::PageUp => {
            if model.panel == Panel::Conversation {
                *scroll = scroll.saturating_add(10).min(10000);
            } else {
                *scroll = scroll.saturating_sub(10);
            }
            if model.panel == Panel::Conversation && *scroll > 10 {
                model.dispatch(Command::LoadMore);
            }
        }
        KeyCode::PageDown => {
            if model.panel == Panel::Conversation {
                *scroll = scroll.saturating_sub(10);
            } else {
                *scroll = scroll.saturating_add(10).min(10000);
            }
        }
        KeyCode::Left => model.editor.left(shift),
        KeyCode::Right => model.editor.right(shift),
        KeyCode::Home => model.editor.home(shift, ctrl),
        KeyCode::End => model.editor.end(shift, ctrl),
        KeyCode::Backspace => {
            model.edit(|editor| {
                editor.backspace();
                Ok(())
            });
        }
        KeyCode::Delete => {
            model.edit(|editor| {
                editor.delete();
                Ok(())
            });
        }
        KeyCode::Enter if alt || shift => model.edit(|e| e.insert("\n")),
        KeyCode::Enter => {
            model.submit();
            *scroll = 0;
        }
        KeyCode::Tab => complete(model),
        KeyCode::Char(c) if !ctrl && !alt => model.edit(|e| e.insert(c.encode_utf8(&mut [0; 4]))),
        _ => {}
    }
}
fn complete(model: &mut Model) {
    if !model.composer_enabled() {
        return;
    }
    let range = model.editor.completion_range();
    let (start, cursor) = (range.start, range.end);
    let prefix = &model.editor.text()[start..cursor];
    if let Some(prefix) = prefix.strip_prefix('@') {
        let key = hrc::text::lookup(prefix, 1024).unwrap_or_default();
        let matches = model
            .snapshot
            .selected
            .as_ref()
            .map(|r| {
                r.members
                    .iter()
                    .filter(|m| {
                        hrc::text::lookup(&m.nickname, 1024)
                            .is_ok_and(|name| name.starts_with(&key))
                    })
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if matches.len() == 1 {
            let member = &matches[0];
            if model
                .editor
                .complete_mention(start..cursor, member.account, &member.nickname)
                .is_ok()
            {
                model.edited();
            }
        } else {
            model.error = Some(if matches.is_empty() {
                "No matching member".into()
            } else {
                format!(
                    "Choose an unambiguous nickname: {}",
                    matches
                        .iter()
                        .take(8)
                        .map(|m| m.nickname.clone())
                        .collect::<Vec<_>>()
                        .join(", ")
                )
            });
        }
    } else if start == 0 && prefix.starts_with('/') {
        let matches = commands::HELP
            .iter()
            .map(|(command, _)| command.split_whitespace().next().unwrap_or(command))
            .filter(|command| command.starts_with(prefix))
            .collect::<Vec<_>>();
        if matches.len() == 1 {
            let replacement = format!("{} ", matches[0]);
            model.edit(|e| e.replace(start..cursor, &replacement));
        } else {
            model.error = Some(matches.join("  "));
        }
    }
}
