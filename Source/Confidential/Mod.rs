// SPDX-License-Identifier: Apache-2.0
//! Encrypted-room authority, public group state and immediate withdrawal barriers.
#[path = "Admission.rs"]
mod admission;
#[path = "Authority.rs"]
mod authority;
#[path = "Epochs.rs"]
mod epochs;
#[path = "Representation.rs"]
mod representation;
#[path = "Schema.rs"]
mod schema;
#[path = "Types.rs"]
mod types;
use crate::{clock::TimeBounds, home::types::*, protocol::*};
use rusqlite::{Transaction, params};
pub(crate) use schema::initialize;
pub use types::*;

/// Called in the same authoritative transaction as identity or grant withdrawal.
/// Keep the old roster so the next public commit must actually remove its leaves.
pub(crate) fn invalidate_accounts(
    db: &Transaction<'_>,
    accounts: &[AccountId],
) -> rusqlite::Result<()> {
    if accounts.len() > 256 {
        return Err(rusqlite::Error::InvalidQuery);
    }
    let mut rooms = std::collections::BTreeSet::new();
    for account in accounts {
        let mut statement = db.prepare(
            "SELECT DISTINCT room FROM hrc_encrypted_roster WHERE account=?1 OR represented=?1 OR operator=?1 LIMIT 257",
        )?;
        for room in statement.query_map([account.to_string()], |r| r.get::<_, String>(0))? {
            rooms.insert(room?);
        }
        if rooms.len() > 256 {
            return Err(rusqlite::Error::InvalidQuery);
        }
    }
    for room in rooms {
        db.execute(
            "UPDATE hrc_encrypted_rooms SET barrier=1 WHERE room=?1",
            [&room],
        )?;
        db.execute(
            "UPDATE hrc_rooms SET revision=revision+1 WHERE id=?1",
            params![room],
        )?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "../../Tests/Confidential/Authority.rs"]
mod tests;

pub(crate) fn operate(
    db: &Transaction<'_>,
    verified: &VerifiedAction,
    now: TimeBounds,
    permit: crate::delegation::Permit,
) -> Domain<Outcome> {
    let action = verified.action();
    match action.operation {
        Operation::CryptoEnrolEndpoint => admission::enrol(db, verified),
        Operation::CryptoPublishKeyPackage => admission::package(db, action, now),
        Operation::CryptoPropose | Operation::CryptoRecover => epochs::initialise(db, action, now),
        Operation::CryptoCommit => epochs::commit(db, action, now),
        Operation::CryptoEpochReady => epochs::ready(db, action, now),
        Operation::CryptoInspect => epochs::inspect(db, action, now, permit),
        Operation::CryptoWelcome => epochs::welcome(db, action, now),
        Operation::CryptoReport => epochs::report(db, action, now),
        _ => invalid("EncryptionOperation"),
    }
}
/// Every ciphertext send rechecks all recipients, including expired grants without a timer.
pub(crate) fn message(
    db: &Transaction<'_>,
    action: &Action,
    now: TimeBounds,
) -> Domain<(Value, Option<Id>, Option<Id>)> {
    let room = crate::conversations::target(action)?;
    let state = epochs::state(db, room)?;
    let members = authority::members(db, room)?;
    if state.barrier || state.frozen {
        return conflict("EncryptedSendBarrier");
    }
    if !authority::required_removals(db, room, &members, now)?.is_empty() {
        return conflict("EncryptedAuthorityChanged");
    }
    if !authority::fresh(db, room, &members, now)? {
        return Err(Fault::Reject(
            ErrorCode::Unavailable,
            "OriginIdentityFreshnessUnavailable",
        ));
    }
    if !members.iter().any(|m| m.actor == action.actor) {
        return deny("SenderNotInEpoch");
    }
    let (context, body) = crate::crypto::EncryptionContext::from_action(action)
        .map_err(|_| Fault::Reject(ErrorCode::InvalidInput, "EncryptedMessage"))?;
    if state.group != Some(context.group) || state.epoch != context.epoch {
        return conflict("EncryptedEpoch");
    }
    let ready: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM hrc_mls_ready WHERE group_id=?1 AND epoch=?2 AND endpoint=?3)",
        params![
            context.group.as_bytes().as_slice(),
            context.epoch,
            action.actor.acting().endpoint.as_hex()
        ],
        |r| r.get(0),
    )?;
    if !ready {
        return deny("EndpointNotReady");
    }
    let mode: u8 = db.query_row(
        "SELECT mode FROM hrc_rooms WHERE id=?1",
        [room.to_string()],
        |r| r.get(0),
    )?;
    if mode == 1
        && members
            .iter()
            .map(|m| m.actor.represented())
            .collect::<std::collections::BTreeSet<_>>()
            .len()
            != 2
    {
        return conflict("DirectRecipientNotReady");
    }
    let parent = body.parent;
    let cause = body.causation;
    Ok((
        value(&crate::crypto::EncryptedEvent {
            context,
            ciphertext: Blob(body.ciphertext),
        })?,
        parent,
        cause,
    ))
}

pub(crate) fn check_reader(
    db: &rusqlite::Connection,
    action: &Action,
    now: TimeBounds,
) -> Domain<()> {
    let room = crate::conversations::target(action)?;
    if !authority::reader(db, room, &action.actor, now)? {
        return deny("EncryptedReadPermission");
    }
    Ok(())
}

pub(crate) fn final_authority(
    db: &rusqlite::Connection,
    action: &Action,
    now: TimeBounds,
) -> Domain<bool> {
    if !matches!(
        action.operation,
        Operation::MessageSend
            | Operation::MessageReply
            | Operation::MessageAction
            | Operation::CryptoCommit
            | Operation::CryptoEpochReady
            | Operation::CryptoPropose
            | Operation::CryptoRecover
    ) {
        return Ok(true);
    }
    let Target::Room(room) = action.target else {
        return Ok(true);
    };
    let mode: u8 = db.query_row(
        "SELECT mode FROM hrc_rooms WHERE id=?1",
        [room.to_string()],
        |r| r.get(0),
    )?;
    if mode == 0 {
        return Ok(true);
    }
    let members = authority::members(db, room)?;
    Ok(
        authority::required_removals(db, room, &members, now)?.is_empty()
            && authority::fresh(db, room, &members, now)?,
    )
}
