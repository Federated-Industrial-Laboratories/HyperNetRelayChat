// SPDX-License-Identifier: Apache-2.0
//! Terminal delegation commands select inspected stable identities and exact approval digests.
use super::*;
use hrc::{
    client::GrantChange,
    delegation::{self, Mode},
};
use std::time::{SystemTime, UNIX_EPOCH};
pub(super) fn parse(
    command: &str,
    rest: &str,
    snapshot: &Snapshot,
) -> Result<Option<Command>, &'static str> {
    Ok(Some(match command {
        "/inspect" | "/pause" | "/resume" | "/revoke" => {
            let id: Id = rest.parse().map_err(|_| "Invalid grant identifier")?;
            let grant = snapshot
                .inspection
                .grants
                .iter()
                .find(|g| g.reference.id == id)
                .ok_or("Refresh /agents and choose an inspected grant")?;
            match command {
                "/inspect" => Command::InspectGrant(grant.reference),
                _ => Command::ChangeGrant {
                    grant: grant.reference,
                    change: match command {
                        "/pause" => GrantChange::Pause,
                        "/resume" => GrantChange::Resume,
                        _ => GrantChange::Revoke,
                    },
                },
            }
        }
        "/approve" | "/reject" => {
            let (id, digest) = rest
                .split_once(' ')
                .ok_or("Use /approve APPROVAL DIGEST or /reject APPROVAL DIGEST")?;
            let approval: Id = id.parse().map_err(|_| "Invalid approval identifier")?;
            let action_digest: Id = digest.trim().parse().map_err(|_| "Invalid action digest")?;
            let inspection = snapshot
                .inspection
                .grant
                .as_ref()
                .ok_or("Inspect the grant first")?;
            if !inspection
                .pending
                .iter()
                .any(|p| p.approval == approval && p.action_digest == action_digest && p.state == 0)
                || !snapshot
                    .inspection
                    .proposed
                    .iter()
                    .any(|a| hrc::protocol::action_digest(a).is_ok_and(|d| d == action_digest))
            {
                return Err("The exact pending action is not inspected");
            }
            Command::DecideApproval {
                grant: inspection.grant.reference,
                decision: delegation::Decision {
                    approval,
                    action_digest,
                },
                approve: command == "/approve",
            }
        }
        "/abandon" | "/resolve" => {
            let (id, digest) = rest
                .split_once(' ')
                .ok_or("Use /abandon OPERATION DIGEST")?;
            let operation_id = crate::display::parse_operation(id)?;
            let action_digest = digest.trim().parse().map_err(|_| "Invalid action digest")?;
            if command == "/resolve" {
                Command::ResolvePending {
                    operation_id,
                    action_digest,
                }
            } else {
                Command::AbandonPending {
                    operation_id,
                    action_digest,
                }
            }
        }
        "/grant" => create(rest, snapshot)?,
        _ => return Ok(None),
    }))
}
fn create(rest: &str, snapshot: &Snapshot) -> Result<Command, &'static str> {
    let mut fields = rest.splitn(7, ' ');
    let account = account(snapshot, fields.next().ok_or("Missing agent")?)?;
    let agent = snapshot
        .inspection
        .agents
        .iter()
        .find(|a| a.actor.account == account)
        .ok_or("Refresh /agents and select an authorised agent endpoint")?
        .actor
        .clone();
    let mode = match fields.next() {
        Some("draft") => Mode::Draft,
        Some("approve") => Mode::Approve,
        Some("autonomous") => Mode::Autonomous,
        _ => return Err("Mode must be draft, approve or autonomous"),
    };
    let hours: u64 = fields
        .next()
        .and_then(|v| v.parse().ok())
        .filter(|v| (1..=168).contains(v))
        .ok_or("Validity is 1..168 hours")?;
    let history: u64 = fields
        .next()
        .and_then(|v| v.parse().ok())
        .filter(|v| *v <= 720)
        .ok_or("History is 0..720 hours; 0 means future only")?;
    let rate: u16 = fields
        .next()
        .and_then(|v| v.parse().ok())
        .filter(|v| (1..=60).contains(v))
        .ok_or("Rate is 1..60 operations/minute")?;
    let mut operations = Vec::new();
    for operation in fields.next().ok_or("Missing operations")?.split(',') {
        match operation {
            "read" => operations.extend([Operation::HistoryPage, Operation::SearchQuery]),
            "reply" => operations.push(Operation::MessageReply),
            "send" => operations.extend([Operation::MessageSend, Operation::MessageAction]),
            "handled" => operations.push(Operation::UnreadSet),
            "moderate" => operations.extend([
                Operation::ModerationSilence,
                Operation::ModerationKick,
                Operation::ModerationBan,
            ]),
            _ => return Err("Operations are read,reply,send,handled,moderate"),
        }
    }
    let purpose = fields
        .next()
        .filter(|p| !p.is_empty())
        .ok_or("An explicit purpose is required")?
        .to_owned();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "Local time unavailable")?
        .as_millis() as u64;
    let expires_ms = now + hours * 3600000;
    Ok(Command::CreateGrant(delegation::Create {
        agent,
        rooms: vec![room(snapshot)?],
        recipients: vec![],
        operations,
        mode,
        not_before_ms: now.saturating_sub(1000),
        expires_ms,
        history_from_ms: now.saturating_sub(history * 3600000),
        history_until_ms: expires_ms,
        max_operations_per_minute: rate,
        purpose,
    }))
}
