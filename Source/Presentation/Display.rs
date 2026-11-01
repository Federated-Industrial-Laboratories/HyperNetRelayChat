// SPDX-License-Identifier: Apache-2.0
//! Plain presentation of stable attribution and current transport observations.
use hrc::{
    client::{ConnectionState, Snapshot},
    conversations::Member,
    hypernet::{Assurance, Privacy, RelayPath},
    messaging,
    protocol::*,
    text,
};

pub fn short_account(account: AccountId) -> String {
    format!(
        "{}@{}",
        &account.local.as_hex()[..8],
        &account.origin.network.as_hex()[..8]
    )
}
pub fn nickname(account: AccountId, members: &[Member]) -> String {
    members
        .iter()
        .find(|member| member.account == account)
        .map(|member| text::identity_display(&member.nickname))
        .filter(|name| !name.is_empty())
        .unwrap_or_else(|| short_account(account))
}
pub fn actor(actor: &Actor, members: &[Member]) -> String {
    match actor {
        Actor::Direct { acting } => nickname(acting.account, members),
        Actor::IndependentAgent { acting, .. } => {
            format!("{} · Agent", nickname(acting.account, members))
        }
        Actor::Delegated {
            acting,
            represented,
            ..
        } => format!(
            "{} · via {}",
            nickname(*represented, members),
            nickname(acting.account, members)
        ),
    }
}
pub fn event_text(event: &Event) -> String {
    if matches!(
        event.kind,
        Operation::MessageSend | Operation::MessageReply | Operation::MessageAction
    ) {
        event
            .body
            .deserialized::<messaging::Send>()
            .map(|body| body.text)
            .unwrap_or_else(|_| "Unsupported message content".into())
    } else {
        match event.kind {
            Operation::RoomCreate => "created the room",
            Operation::RoomJoin => "joined",
            Operation::RoomLeave => "left",
            Operation::RoomSetTopic => "changed the topic",
            Operation::ModerationSilence => "changed a room silence",
            Operation::ModerationKick => "removed a room member",
            Operation::ModerationBan => "changed a room ban",
            _ => "updated room state",
        }
        .into()
    }
}
pub fn time(ms: u64) -> String {
    let seconds = ms / 1000 % 86_400;
    format!(
        "{:02}:{:02}:{:02}",
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60
    )
}
pub fn connection(snapshot: &Snapshot) -> String {
    match &snapshot.connection {
        ConnectionState::Offline => "Offline".into(),
        ConnectionState::Connecting => "Connecting through HyperNet".into(),
        ConnectionState::Resolving => "Resolving pending operations".into(),
        ConnectionState::Online => "Connected through HyperNet".into(),
        ConnectionState::Backoff { retry_in_ms, .. } => {
            format!("Reconnect in {} s", retry_in_ms.div_ceil(1000))
        }
    }
}
pub fn delivery(delivery: &hrc::client::Delivery) -> String {
    match &delivery.outcome {
        None => "Queued locally; outcome is not yet known".into(),
        Some(Outcome::Committed { .. }) => "Committed by the service".into(),
        Some(Outcome::Rejected { code, detail }) => format!("Rejected: {code:?} · {detail}"),
        Some(Outcome::Refused { code, detail, .. }) => format!(
            "Current request refused: {code:?} · {detail}; prior outcome may remain unknown"
        ),
        Some(Outcome::Result { .. }) => "Query completed".into(),
        Some(Outcome::Absent) => "Not committed at the last resolution".into(),
        Some(Outcome::Unknown) => "Outcome unknown; resolve the original operation".into(),
    }
}
pub fn privacy(privacy: Option<&Privacy>) -> Vec<(&'static str, String)> {
    let Some(p) = privacy else {
        return vec![("Route", "No current observation".into())];
    };
    let assurance = |a| {
        match a {
            Some(Assurance::Organisation) => "Organisation",
            Some(Assurance::Independent) => "Independent operators",
            None => "Not reported",
        }
        .to_string()
    };
    vec![
        (
            "Observation",
            if p.is_historical() {
                "Historical; current properties unavailable"
            } else {
                "Current transport observation"
            }
            .into(),
        ),
        (
            "Transport authentication",
            if p.transport_authenticated() {
                "Authenticated"
            } else {
                "Not currently observed"
            }
            .into(),
        ),
        (
            "Relay path",
            match p.relay_path() {
                RelayPath::ApprovedAttachment => "Approved HyperNet attachment",
                RelayPath::NestedTlsViaRelay => "Nested TLS through HyperNet relay",
                RelayPath::Unknown => "Unknown",
                RelayPath::Unavailable => "Unavailable",
            }
            .into(),
        ),
        ("Transport TLS", p.tls().unwrap_or("Not reported").into()),
        (
            "Endpoint protection",
            match p.transport_protection() {
                Some(hrc::hypernet::TransportProtection::Tls13FinalService) => {
                    "TLS 1.3 to final service"
                }
                None => "Not separately reported",
            }
            .into(),
        ),
        ("Requested assurance", assurance(p.selected_minimum())),
        ("Configured assurance", assurance(p.configured_assurance())),
        (
            "Physical operator independence",
            "Not independently verified by this client".into(),
        ),
    ]
}

pub fn operation(id: OperationId) -> String {
    format!("{}:{}", id.window, id.operation)
}
pub fn parse_operation(text: &str) -> std::result::Result<OperationId, &'static str> {
    let (window, operation) = text
        .split_once(':')
        .ok_or("Operation identity must include window:operation")?;
    Ok(OperationId {
        window: window.parse().map_err(|_| "Invalid retry window")?,
        operation: operation
            .parse()
            .map_err(|_| "Invalid operation identifier")?,
    })
}

pub fn timestamp(ms: u64) -> String {
    ::time::OffsetDateTime::from_unix_timestamp_nanos(i128::from(ms) * 1_000_000)
        .ok()
        .and_then(|date| {
            date.format(&::time::format_description::well_known::Rfc3339)
                .ok()
        })
        .unwrap_or_else(|| "Time outside display range".into())
}
pub fn date_bound(input: &str) -> std::result::Result<Option<u64>, &'static str> {
    let input = input.trim();
    if input.is_empty() {
        return Ok(None);
    }
    if input.len() > 64 {
        return Err("Invalid date");
    }
    let date = if input.len() == 10 {
        ::time::Date::parse(
            input,
            &::time::macros::format_description!("[year]-[month]-[day]"),
        )
        .map(|date| date.midnight().assume_utc())
        .map_err(|_| "Use YYYY-MM-DD or an ISO 8601 timestamp")?
    } else {
        ::time::OffsetDateTime::parse(input, &::time::format_description::well_known::Rfc3339)
            .map_err(|_| "Use YYYY-MM-DD or an ISO 8601 timestamp")?
    };
    u64::try_from(date.unix_timestamp_nanos().div_euclid(1_000_000))
        .map(Some)
        .map_err(|_| "The date must be on or after 1970-01-01")
}

#[cfg(test)]
#[path = "../../Tests/Presentation/Dates.rs"]
mod tests;
