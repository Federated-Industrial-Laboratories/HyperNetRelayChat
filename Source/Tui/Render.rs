// SPDX-License-Identifier: Apache-2.0
//! Only owned terminal controls execute; all displayed content is neutralised and clipped.
use super::*;
use crate::display;
use crossterm::{
    cursor::MoveTo,
    queue,
    style::{Attribute, Color, Print, SetAttribute, SetBackgroundColor, SetForegroundColor},
    terminal::{Clear, ClearType},
};
use hrc::presentation::terminal_text::{clip, width, wrap};
use unicode_segmentation::UnicodeSegmentation;

pub(super) fn draw(model: &Model, scroll: usize) -> io::Result<()> {
    let (columns, rows) = terminal::size()?;
    let columns = usize::from(columns).clamp(1, 300);
    let rows = usize::from(rows).clamp(1, 120);
    let wide = model.snapshot.preferences.ambiguous_wide;
    let light = model.snapshot.preferences.theme == hrc::client::Theme::Light;
    let foreground = if light { Color::Black } else { Color::Grey };
    let mut output = io::BufWriter::new(io::stdout().lock());
    queue!(
        output,
        MoveTo(0, 0),
        SetBackgroundColor(if light { Color::White } else { Color::Black }),
        Clear(ClearType::All),
        SetForegroundColor(if light { Color::DarkCyan } else { Color::Cyan })
    )?;
    line(
        &mut output,
        0,
        columns,
        wide,
        &format!(
            "HRC · {} · F1 help · Ctrl+Q close",
            display::connection(&model.snapshot)
        ),
    )?;
    queue!(output, SetForegroundColor(foreground))?;
    let rooms = model
        .snapshot
        .rooms
        .iter()
        .filter(|r| r.joined)
        .map(|room| {
            format!(
                "{}{}({})",
                if model
                    .snapshot
                    .selected
                    .as_ref()
                    .is_some_and(|s| s.summary.room == room.room)
                {
                    ">"
                } else {
                    ""
                },
                room.name,
                room.unread
            )
        })
        .collect::<Vec<_>>()
        .join("  ");
    if rows > 1 {
        line(&mut output, 1, columns, wide, &rooms)?;
    }
    let composer_rows = 4.min(rows.saturating_sub(4));
    let history_rows = rows.saturating_sub(composer_rows + 4);
    let lines = content(model, columns, wide);
    let (start, end) = if model.panel == Panel::Conversation {
        let end = lines
            .len()
            .saturating_sub(scroll.min(lines.len().saturating_sub(1)));
        (end.saturating_sub(history_rows), end)
    } else {
        let start = scroll.min(lines.len().saturating_sub(history_rows));
        (start, (start + history_rows).min(lines.len()))
    };
    for (i, text) in lines[start..end].iter().enumerate() {
        line(&mut output, i + 2, columns, wide, text)?;
    }
    let divider = rows.saturating_sub(composer_rows + 2);
    if divider > 1 {
        line(
            &mut output,
            divider,
            columns,
            wide,
            if model.reply.is_some() {
                "Reply · Enter sends · Ctrl+J newline · Tab completes"
            } else {
                "Enter sends · Ctrl+J newline · Tab completes · Ctrl+N/P rooms"
            },
        )?;
    }
    let draft = wrap(model.editor.text(), columns, 120, wide);
    let prefix = wrap(
        &model.editor.text()[..model.editor.cursor()],
        columns,
        120,
        wide,
    );
    let cursor_line = prefix.len().saturating_sub(1);
    let draft_start = cursor_line.saturating_sub(composer_rows.saturating_sub(1));
    let selection = model.editor.selection();
    let selection_position = |position| {
        let lines = wrap(&model.editor.text()[..position], columns, 120, wide);
        (
            lines.len().saturating_sub(1),
            lines.last().map_or(0, |line| width(line, wide)),
        )
    };
    let selection_start = selection_position(selection.start);
    let selection_end = selection_position(selection.end);
    for (i, text) in draft
        .iter()
        .skip(draft_start)
        .take(composer_rows)
        .enumerate()
    {
        let row = draft_start + i;
        let selected = if selection.is_empty() || row < selection_start.0 || row > selection_end.0 {
            0..0
        } else {
            (if row == selection_start.0 {
                selection_start.1
            } else {
                0
            })..(if row == selection_end.0 {
                selection_end.1
            } else {
                columns
            })
        };
        queue!(output, MoveTo(0, (divider + 1 + i) as u16))?;
        let mut column = 0;
        for grapheme in text.graphemes(true) {
            let next = column + width(grapheme, wide).max(1);
            queue!(
                output,
                SetAttribute(if column < selected.end && next > selected.start {
                    Attribute::Reverse
                } else {
                    Attribute::NoReverse
                }),
                Print(grapheme)
            )?;
            column = next;
        }
        queue!(output, SetAttribute(Attribute::NoReverse))?;
    }
    if rows > 2 {
        let status = model
            .error
            .clone()
            .or_else(|| {
                model
                    .snapshot
                    .status
                    .as_ref()
                    .map(|s| format!("{}: {}", s.code, s.detail))
            })
            .unwrap_or_else(|| {
                if model.draft_saved() {
                    "Draft saved locally".into()
                } else {
                    "Saving draft…".into()
                }
            });
        line(&mut output, rows - 1, columns, wide, &status)?;
    }
    let cursor_column = prefix
        .last()
        .map_or(0, |line| width(line, wide))
        .min(columns.saturating_sub(1));
    let cursor_row =
        (divider + 1 + cursor_line.saturating_sub(draft_start)).min(rows.saturating_sub(2));
    queue!(output, MoveTo(cursor_column as u16, cursor_row as u16))?;
    output.flush()
}
fn line(
    output: &mut impl Write,
    row: usize,
    columns: usize,
    wide: bool,
    text: &str,
) -> io::Result<()> {
    queue!(
        output,
        MoveTo(0, row as u16),
        Print(clip(text, columns, wide))
    )
}
fn content(model: &Model, columns: usize, wide: bool) -> Vec<String> {
    let snapshot = &model.snapshot;
    let mut raw = Vec::new();
    match model.panel {
        Panel::Conversation => {
            if let Some(room) = &snapshot.selected {
                raw.push(format!(
                    "# {} · {} · {}{}",
                    room.summary.name,
                    room.summary.topic,
                    display::confidentiality(room.summary.confidentiality),
                    if room.stale { " · retained copy" } else { "" }
                ));
                if let Some(gap) = &room.gap {
                    raw.push(format!("History gap: {gap}; /resync"));
                }
                let events = if let Some(search) = &snapshot.search {
                    raw.push(format!(
                        "Search '{}' · {} · /cancel-search /next /close-search",
                        search.query.terms.join(" "),
                        if search.running { "running" } else { "results" }
                    ));
                    &search.events
                } else {
                    &room.events
                };
                for event in events.iter().rev().take(256).rev() {
                    raw.push(format!(
                        "{} {}: {}",
                        display::time(event.timestamp_ms),
                        display::actor(&event.actor, &room.members),
                        display::event_text_with_content(
                            event,
                            snapshot
                                .search
                                .as_ref()
                                .and_then(|s| s.content.get(&event.event))
                                .or_else(|| room.content.get(&event.event))
                        )
                    ));
                    if snapshot.preferences.density == hrc::client::Density::Comfortable {
                        raw.push(String::new());
                    }
                }
                for delivery in snapshot
                    .deliveries
                    .iter()
                    .rev()
                    .filter(|d| d.room == Some(room.summary.room))
                    .take(3)
                {
                    raw.push(display::delivery(delivery));
                }
            } else {
                raw.push("Select a room with /join ROOM, or /create NAME".into());
            }
        }
        Panel::Help => {
            raw.push("Ctrl+N/P changes rooms; Ctrl+R refreshes; Ctrl+U status; Esc conversation. PageUp/Down scrolls. Ctrl+A selects all; Ctrl+Z/Y undo/redo. Ctrl+J inserts a line break.".into());
            raw.extend(
                commands::HELP
                    .iter()
                    .map(|(command, description)| format!("{command}: {description}")),
            );
        }
        Panel::Motd => raw.push(if snapshot.motd.is_empty() {
            "No message of the day".into()
        } else {
            snapshot.motd.clone()
        }),
        Panel::Settings => {
            raw.push(format!(
                "Theme {:?} · density {:?} · quiet={} · sound={} · ambiguous-width={}",
                snapshot.preferences.theme,
                snapshot.preferences.density,
                snapshot.preferences.quiet,
                snapshot.preferences.sound,
                snapshot.preferences.ambiguous_wide
            ));
            raw.push("/theme dark|light; /density compact|comfortable; /quiet; /sound on|off; /notify all|mentions|off; /room-sound on|off; /width narrow|wide".into());
        }
        Panel::Status => {
            raw.push(format!("Account {}", snapshot.account));
            for choice in &snapshot.services {
                raw.push(format!(
                    "{} service {}: /network {}",
                    if choice.selected {
                        "Selected"
                    } else {
                        "Available"
                    },
                    choice.home,
                    choice
                        .agreement
                        .map(|a| a.id.to_string())
                        .unwrap_or_else(|| "local".into())
                ));
            }
            raw.extend(
                display::federation_privacy(snapshot.federation_privacy.as_ref())
                    .into_iter()
                    .map(|(label, value)| format!("{label}: {value}")),
            );
            raw.extend(
                display::privacy(snapshot.privacy.as_ref())
                    .into_iter()
                    .map(|(label, value)| format!("{label}: {value}")),
            );
            if let Some(room) = &snapshot.selected {
                raw.push(display::confidentiality(room.summary.confidentiality).into());
                if let Some(crypto) = &room.crypto {
                    raw.push(format!(
                        "Encrypted epoch {} · send barrier={} · frozen={} · future-only admission",
                        crypto.remote.epoch, crypto.remote.send_barrier, crypto.remote.frozen
                    ));
                    raw.push("/crypto enrol|inspect|publish|start|sync; /crypto add PACKAGE; /crypto remove ENDPOINT".into());
                    for contact in &crypto.contacts {
                        raw.push(format!(
                            "Contact {} {:?}; fingerprint {}; /trust {} {}{}",
                            contact.account,
                            contact.state,
                            contact.anchor,
                            contact.account,
                            contact.anchor,
                            if contact.state == hrc::client::trust::TrustState::LegacyAnchor {
                                " legacy"
                            } else {
                                ""
                            }
                        ));
                    }
                    for package in &crypto.remote.packages {
                        raw.push(format!(
                            "Requested endpoint {} · package {} · {}",
                            package.member.actor.acting().endpoint,
                            package.digest,
                            display::actor(&package.member.actor, &room.members)
                        ));
                    }
                    for member in &crypto.remote.members {
                        raw.push(format!(
                            "Encrypted endpoint {} · {}{}",
                            member.actor.acting().endpoint,
                            display::actor(&member.actor, &room.members),
                            if crypto
                                .remote
                                .required_removals
                                .contains(&member.actor.acting().endpoint)
                            {
                                " · removal required"
                            } else {
                                ""
                            }
                        ));
                    }
                }
                raw.push("Members (presence does not prove who typed a message):".into());
                raw.extend(room.members.iter().map(|m| {
                    format!(
                        "{} {} {:?} · {}",
                        if m.present {
                            "present"
                        } else {
                            "no current presence"
                        },
                        m.nickname,
                        m.classification,
                        m.account
                    )
                }));
            }
            raw.extend(snapshot.deliveries.iter().map(|d| {
                format!(
                    "{} {} {}",
                    display::operation(d.operation_id),
                    d.action_digest,
                    display::delivery(d)
                )
            }));
        }
        Panel::Agents => {
            raw.push("/inspect GRANT; /pause GRANT; /resume GRANT; /revoke GRANT; /grant AGENT MODE HOURS HISTORY_HOURS RATE OPS PURPOSE".into());
            for agent in &snapshot.inspection.agents {
                raw.push(format!(
                    "Agent {} · {}",
                    agent.nickname, agent.actor.account
                ));
            }
            for grant in &snapshot.inspection.grants {
                raw.push(format!(
                    "{} · {:?} {:?} · agent {} · {:?} · expires {}",
                    grant.reference.id,
                    grant.state,
                    grant.scope.mode,
                    grant.scope.agent.account,
                    grant.scope.operations,
                    grant.scope.expires_ms
                ));
            }
            if let Some(inspection) = &snapshot.inspection.grant {
                raw.push(format!(
                    "Scope: rooms {:?}; history {}..{}; {} operations/minute; purpose {}",
                    inspection.grant.scope.rooms,
                    inspection.grant.scope.history_from_ms,
                    inspection.grant.scope.history_until_ms,
                    inspection.grant.scope.max_operations_per_minute,
                    inspection.grant.scope.purpose
                ));
                for pending in &inspection.pending {
                    raw.push(format!(
                        "Approval {} · digest {} · state {} · expires {}",
                        pending.approval, pending.action_digest, pending.state, pending.expires_ms
                    ));
                    if let Some(action) = snapshot.inspection.proposed.iter().find(|a| {
                        hrc::protocol::action_digest(a).is_ok_and(|d| d == pending.action_digest)
                    }) {
                        raw.push(format!(
                            "Exact {:?} {:?} · {}",
                            action.operation,
                            action.target,
                            if let Some(hrc::client::MessageContent::Decrypted(body)) = snapshot
                                .inspection
                                .proposed_content
                                .get(&pending.action_digest)
                            {
                                body.text.clone()
                            } else if action
                                .body
                                .deserialized::<hrc::crypto::EncryptedBody>()
                                .is_ok()
                            {
                                "Encrypted proposal plaintext is unavailable; approval blocked"
                                    .into()
                            } else {
                                action
                                    .body
                                    .deserialized::<hrc::messaging::Send>()
                                    .map(|s| s.text)
                                    .unwrap_or_else(|_| format!("{:?}", action.body))
                            }
                        ));
                    }
                }
            }
        }
    }
    raw.into_iter()
        .take(512)
        .flat_map(|line| wrap(&line, columns, 120, wide))
        .take(8192)
        .collect()
}
