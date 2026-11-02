// SPDX-License-Identifier: Apache-2.0
//! Discoverable slash commands resolve stable targets before entering the shared client.
use hrc::{
    client::{Command, RestrictionKind, Snapshot},
    messaging, moderation,
    protocol::*,
    text,
};
use std::result::Result;
#[path = "AgentCommands.rs"]
mod agents;

pub const HELP: &[(&str, &str)] = &[
    (
        "/join ROOM",
        "Join a room by its unambiguous name or identifier",
    ),
    ("/part", "Leave the selected room"),
    ("/create NAME", "Create a community room"),
    ("/private NAME", "Create an encrypted private group"),
    (
        "/msg ACCOUNT",
        "Invite an account to a confidential conversation",
    ),
    (
        "/whisper ACCOUNT",
        "Invite an account to a confidential conversation",
    ),
    (
        "/invite ACCOUNT",
        "Invite an account to the selected private group",
    ),
    (
        "/crypto enrol|inspect|publish|start|sync",
        "Manage this endpoint's encrypted room access",
    ),
    (
        "/crypto add PACKAGE",
        "Commit an explicitly published endpoint package",
    ),
    (
        "/crypto remove ENDPOINT",
        "Remove an endpoint from the encrypted epoch",
    ),
    (
        "/crypto recover",
        "Explicitly create a fresh encrypted group; future traffic only",
    ),
    (
        "/trust ACCOUNT ANCHOR [legacy]",
        "Pin the inspected first-contact fingerprint",
    ),
    ("/me TEXT", "Send an action"),
    ("/nick NAME", "Change your displayed nickname"),
    (
        "/presence TEXT",
        "Announce this endpoint's presence for five minutes",
    ),
    ("/topic TEXT", "Set the selected room's topic"),
    (
        "/search TEXT",
        "Search retained room messages; optional --sender, --represented, --from, --until before -- TEXT",
    ),
    (
        "/live",
        "Return from search context to the live conversation",
    ),
    (
        "/ignore NAME",
        "Suppress that account's deliveries and search results",
    ),
    ("/unignore NAME", "Remove the recipient ignore filter"),
    ("/mute NAME", "Silence notifications from that account"),
    ("/unmute NAME", "Restore its notifications"),
    (
        "/silence NAME",
        "Restrict room publication for five minutes",
    ),
    ("/unsilence NAME", "Remove the publication restriction"),
    ("/kick NAME", "Remove a member from this room"),
    ("/ban NAME", "Ban a member for one day"),
    ("/unban NAME", "Remove that room ban"),
    ("/agents", "Inspect agents, grants and exact approvals"),
    ("/quiet", "Toggle quiet mode"),
    ("/motd", "Read the service's message of the day"),
    ("/connect", "Reconnect through HyperNet"),
    ("/disconnect", "Keep drafts and disconnect"),
    ("/settings", "Open appearance and notification preferences"),
    ("/help", "Show commands and shortcuts"),
    ("/quit", "Close this client"),
    ("/reply EVENT TEXT", "Reply to an exact event in this room"),
    (
        "/context EVENT",
        "Open an authorised surrounding conversation page",
    ),
    ("/next", "Read the next search page"),
    ("/cancel-search", "Cancel the running search"),
    ("/close-search", "Return to the conversation"),
    ("/resync", "Resynchronise an explicit history gap"),
    ("/read", "Mark the displayed conversation handled/read"),
    ("/theme dark|light", "Set the interface theme"),
    ("/density compact|comfortable", "Set layout density"),
    (
        "/sound on|off",
        "Enable or disable optional notification sounds",
    ),
    (
        "/room-sound on|off",
        "Enable or disable sounds for this room",
    ),
    (
        "/notify all|mentions|off",
        "Set notifications for this room",
    ),
    (
        "/width narrow|wide",
        "Select ambiguous terminal character width",
    ),
    ("/who", "Inspect members, privacy and delivery state"),
    (
        "/grant AGENT MODE HOURS HISTORY_HOURS RATE OPS PURPOSE",
        "Grant exact scope; OPS is read,reply,send,handled,moderate joined with commas",
    ),
    (
        "/inspect GRANT",
        "Inspect exact grant scope and pending approvals",
    ),
    ("/pause GRANT", "Pause subsequent delegated effects"),
    ("/resume GRANT", "Resume a paused grant"),
    ("/revoke GRANT", "Permanently revoke a grant"),
    (
        "/approve APPROVAL DIGEST",
        "Approve the inspected exact action and content",
    ),
    (
        "/reject APPROVAL DIGEST",
        "Reject the inspected exact action",
    ),
    (
        "/resolve OPERATION DIGEST",
        "Resolve an original uncertain operation",
    ),
    (
        "/abandon OPERATION DIGEST",
        "Stop automatic retries while retaining the unknown outcome",
    ),
];

pub enum Interaction {
    Request(Box<Command>),
    Help,
    Agents,
    Settings,
    Status,
    Motd,
    Quit,
}
fn request(command: Command) -> Interaction {
    Interaction::Request(Box::new(command))
}
fn room(snapshot: &Snapshot) -> Result<RoomId, &'static str> {
    snapshot
        .selected
        .as_ref()
        .map(|r| r.summary.room)
        .ok_or("Select a room first")
}
pub fn account(snapshot: &Snapshot, label: &str) -> Result<AccountId, &'static str> {
    if let Ok(id) = label.parse() {
        return Ok(id);
    }
    let members = &snapshot
        .selected
        .as_ref()
        .ok_or("Select a room first")?
        .members;
    let key = text::lookup(label.trim_start_matches('@'), 1024).map_err(|_| "Invalid nickname")?;
    let mut matching = members
        .iter()
        .filter(|m| text::lookup(&m.nickname, 1024).is_ok_and(|value| value == key));
    let member = matching.next().ok_or("No matching room member")?;
    if matching.next().is_some() {
        return Err("Nickname is ambiguous; select the member by identity");
    }
    Ok(member.account)
}
fn target_room(snapshot: &Snapshot, label: &str) -> Result<RoomId, &'static str> {
    if let Ok(id) = label.parse() {
        return Ok(id);
    }
    let key = text::lookup(label, 1024).map_err(|_| "Invalid room name")?;
    let mut matching = snapshot
        .rooms
        .iter()
        .filter(|r| text::lookup(&r.name, 1024).is_ok_and(|value| value == key));
    let found = matching
        .next()
        .ok_or("No matching room; use its complete identifier to join")?;
    if matching.next().is_some() {
        return Err("Room name is ambiguous; select its complete identifier");
    }
    Ok(found.room)
}
pub fn parse(
    input: &str,
    mentions: &[messaging::Mention],
    snapshot: &Snapshot,
    parent: Option<Id>,
) -> Result<Interaction, &'static str> {
    let send = |body: &str, offset: usize, action: bool| -> Result<Interaction, &'static str> {
        let mentions = mentions
            .iter()
            .filter_map(|mention| {
                if (mention.start as usize) < offset {
                    return None;
                }
                let mut mention = mention.clone();
                mention.start -= offset as u32;
                mention.end -= offset as u32;
                Some(mention)
            })
            .collect();
        Ok(request(Command::Send {
            room: room(snapshot)?,
            text: body.into(),
            mentions,
            parent,
            causation: None,
            action,
            grant: None,
        }))
    };
    if input.starts_with("//") {
        return send(&input[1..], 1, false);
    }
    if !input.starts_with('/') {
        return send(input, 0, false);
    }
    let (command, rest) = input.split_once(char::is_whitespace).unwrap_or((input, ""));
    let rest = rest.trim_start();
    let command = command.to_ascii_lowercase();
    if let Some(result) = agents::parse(&command, rest, snapshot)? {
        return Ok(request(result));
    }
    Ok(match command.as_str() {
        "/help" => Interaction::Help,
        "/agents" => Interaction::Agents,
        "/settings" => Interaction::Settings,
        "/motd" => Interaction::Motd,
        "/quit" => Interaction::Quit,
        "/who" => Interaction::Status,
        "/next" => request(Command::NextSearchPage),
        "/cancel-search" => request(Command::CancelSearch),
        "/close-search" => request(Command::CloseSearch),
        "/resync" => request(Command::Resynchronise),
        "/live" => request(Command::SelectRoom(room(snapshot)?)),
        "/context" => request(Command::OpenEvent {
            room: room(snapshot)?,
            event: rest.parse().map_err(|_| "Invalid event identifier")?,
        }),
        "/read" => {
            let view = snapshot.selected.as_ref().ok_or("Select a room first")?;
            request(Command::MarkRead {
                room: view.summary.room,
                sequence: view
                    .events
                    .last()
                    .map_or(view.read_sequence, |e| e.sequence),
            })
        }
        "/reply" => {
            let (event, body) = rest
                .split_once(char::is_whitespace)
                .ok_or("Use /reply EVENT TEXT")?;
            let offset = input.len() - body.len();
            let Interaction::Request(mut request) = send(body, offset, false)? else {
                unreachable!()
            };
            if let Command::Send { parent, .. } = &mut *request {
                *parent = Some(event.parse().map_err(|_| "Invalid reply identifier")?);
            }
            Interaction::Request(request)
        }
        "/theme" | "/density" | "/sound" | "/width" => {
            let mut preferences = snapshot.preferences.clone();
            match (command.as_str(), rest) {
                ("/theme", "dark") => preferences.theme = hrc::client::Theme::Dark,
                ("/theme", "light") => preferences.theme = hrc::client::Theme::Light,
                ("/density", "compact") => preferences.density = hrc::client::Density::Compact,
                ("/density", "comfortable") => {
                    preferences.density = hrc::client::Density::Comfortable
                }
                ("/sound", "on") => preferences.sound = true,
                ("/sound", "off") => preferences.sound = false,
                ("/width", "narrow") => preferences.ambiguous_wide = false,
                ("/width", "wide") => preferences.ambiguous_wide = true,
                _ => return Err("Invalid preference; use /help"),
            }
            request(Command::SetPreferences(preferences))
        }
        "/notify" | "/room-sound" => {
            let view = snapshot.selected.as_ref().ok_or("Select a room first")?;
            let mut preferences = view.preferences.clone();
            match (command.as_str(), rest) {
                ("/notify", "all") => {
                    preferences.notifications = hrc::client::NotificationMode::All
                }
                ("/notify", "mentions") => {
                    preferences.notifications = hrc::client::NotificationMode::Mentions
                }
                ("/notify", "off") => {
                    preferences.notifications = hrc::client::NotificationMode::Off
                }
                ("/room-sound", "on") => preferences.sound = true,
                ("/room-sound", "off") => preferences.sound = false,
                _ => return Err("Invalid notification setting; use /help"),
            }
            request(Command::SetRoomPreferences {
                room: view.summary.room,
                preferences,
            })
        }
        "/connect" => request(Command::Connect),
        "/disconnect" => request(Command::Disconnect),
        "/quiet" => {
            let mut p = snapshot.preferences.clone();
            p.quiet = !p.quiet;
            request(Command::SetPreferences(p))
        }
        "/join" if !rest.is_empty() => request(Command::Join(target_room(snapshot, rest)?)),
        "/part" | "/leave" => request(Command::Leave(room(snapshot)?)),
        "/create" if !rest.is_empty() => request(Command::CreateRoom { name: rest.into() }),
        "/private" if !rest.is_empty() => {
            request(Command::CreatePrivateGroup { name: rest.into() })
        }
        "/msg" | "/whisper" if !rest.is_empty() => request(Command::CreateDirect {
            recipient: account(snapshot, rest)?,
        }),
        "/invite" if !rest.is_empty() => request(Command::Invite {
            room: room(snapshot)?,
            account: account(snapshot, rest)?,
        }),
        "/crypto" => {
            let (operation, argument) = rest.split_once(' ').unwrap_or((rest, ""));
            request(match operation {
                "enrol" if argument.is_empty() => Command::CryptoEnrol,
                "inspect" if argument.is_empty() => Command::CryptoInspect {
                    room: room(snapshot)?,
                    grant: None,
                },
                "publish" if argument.is_empty() => Command::CryptoPublish {
                    room: room(snapshot)?,
                    grant: None,
                },
                "start" | "recover" if argument.is_empty() => Command::CryptoInitialise {
                    room: room(snapshot)?,
                    recover: operation == "recover",
                },
                "sync" if argument.is_empty() => Command::CryptoSync {
                    room: room(snapshot)?,
                    grant: None,
                },
                "add" => Command::CryptoCommit {
                    room: room(snapshot)?,
                    additions: vec![argument.parse().map_err(|_| "Use a package digest")?],
                    removals: vec![],
                },
                "remove" => Command::CryptoCommit {
                    room: room(snapshot)?,
                    additions: vec![],
                    removals: vec![argument.parse().map_err(|_| "Use an endpoint ID")?],
                },
                _ => {
                    return Err(
                        "Use /crypto enrol, inspect, publish, start, sync, add, remove or recover",
                    );
                }
            })
        }
        "/trust" => {
            let fields = rest.split_whitespace().collect::<Vec<_>>();
            if !(2..=3).contains(&fields.len()) || fields.len() == 3 && fields[2] != "legacy" {
                return Err("Use /trust ACCOUNT ANCHOR [legacy]");
            }
            request(Command::TrustContact {
                account: account(snapshot, fields[0])?,
                anchor_digest: fields[1]
                    .parse()
                    .map_err(|_| "Use the inspected anchor digest")?,
                legacy: fields.len() == 3,
            })
        }
        "/me" if !rest.is_empty() => return send(rest, input.len() - rest.len(), true),
        "/nick" if !rest.is_empty() => request(Command::SetNickname(rest.into())),
        "/presence" if !rest.is_empty() => request(Command::SetPresence(hrc::identity::Presence {
            status: rest.into(),
            duration_ms: 300000,
        })),
        "/topic" => request(Command::SetTopic {
            room: room(snapshot)?,
            topic: rest.into(),
        }),
        "/search" if !rest.is_empty() => request(Command::Search(search(rest)?)),
        "/ignore" | "/unignore" | "/mute" | "/unmute" if !rest.is_empty() => {
            let ignored = match command.as_str() {
                "/ignore" => Some(true),
                "/unignore" => Some(false),
                _ => None,
            };
            let muted = match command.as_str() {
                "/mute" => Some(true),
                "/unmute" => Some(false),
                _ => None,
            };
            request(Command::SetFilter {
                subject: account(snapshot, rest)?,
                ignored,
                muted,
            })
        }
        "/silence" | "/unsilence" | "/kick" | "/ban" | "/unban" if !rest.is_empty() => {
            let kind = match command.as_str() {
                "/kick" => RestrictionKind::Kick,
                "/ban" | "/unban" => RestrictionKind::Ban,
                _ => RestrictionKind::Silence,
            };
            request(Command::SetRestriction {
                room: room(snapshot)?,
                kind,
                restriction: moderation::Restriction {
                    subject: account(snapshot, rest)?,
                    enabled: !matches!(command.as_str(), "/unsilence" | "/unban"),
                    duration_ms: if matches!(kind, RestrictionKind::Ban) {
                        86_400_000
                    } else {
                        300_000
                    },
                    reason: "Room moderation".into(),
                },
            })
        }
        "/msg" | "/whisper" => {
            return Err("Confidential direct conversations are unavailable in this build");
        }
        _ => {
            return Err(
                "Unknown or incomplete command; use /help. Use // for a literal leading slash",
            );
        }
    })
}

fn search(mut input: &str) -> Result<messaging::Search, &'static str> {
    let mut query = messaging::Search {
        terms: vec![],
        sender: None,
        represented: None,
        from_ms: None,
        until_ms: None,
        cursor: None,
        limit: 32,
    };
    while input.starts_with("--") {
        if let Some(text) = input.strip_prefix("-- ") {
            input = text;
            break;
        }
        let (flag, rest) = input
            .split_once(char::is_whitespace)
            .ok_or("A search filter needs a value")?;
        let rest = rest.trim_start();
        let (value, rest) = rest.split_once(char::is_whitespace).unwrap_or((rest, ""));
        match flag {
            "--sender" => {
                query.sender = Some(value.parse().map_err(|_| "Invalid sender identifier")?)
            }
            "--represented" => {
                query.represented = Some(
                    value
                        .parse()
                        .map_err(|_| "Invalid represented account identifier")?,
                )
            }
            "--from" => {
                query.from_ms = Some(value.parse().map_err(|_| "Invalid from UTC milliseconds")?)
            }
            "--until" => {
                query.until_ms = Some(
                    value
                        .parse()
                        .map_err(|_| "Invalid until UTC milliseconds")?,
                )
            }
            _ => return Err("Unknown search filter; use -- before literal text starting with --"),
        }
        input = rest.trim_start();
    }
    if !input.is_empty() {
        query.terms.push(input.into());
    }
    Ok(query)
}

#[cfg(test)]
#[path = "../../Tests/Presentation/Commands.rs"]
mod tests;
