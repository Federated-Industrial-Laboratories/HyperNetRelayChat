// SPDX-License-Identifier: Apache-2.0
//! Delete expired local crypto records under the caller's archive and retry policy.
use super::*;

#[derive(Clone, Copy, Debug, Default, serde::Serialize)]
pub struct PrunedRecords {
    pub deliveries: usize,
    pub transitions: usize,
    pub outbox: usize,
    pub approvals: usize,
}
/// Use in the same transaction as local archive/index expiry. `through_sequence`
/// is an already-consumed history position. Closed operation windows must be
/// authenticated and irreversible; their tombstones prevent re-encryption.
/// Unknown outbox outcomes and unresolved previews are never deleted here.
pub fn prune_in(
    tx: &Transaction<'_>,
    group: Id,
    through_sequence: u64,
    closed_windows: &[Id],
) -> Result<PrunedRecords> {
    if closed_windows.len() > 64 {
        return Err(Error::Limit);
    }
    let (_, cursor, _) = metadata(tx, group)?;
    if through_sequence > cursor {
        return Err(Error::Conflict);
    }
    let mut result = PrunedRecords {
        deliveries: tx.execute(
            "DELETE FROM crypto_deliveries WHERE group_id=?1 AND sequence<=?2",
            rusqlite::params![group.as_bytes().as_slice(), through_sequence],
        )?,
        transitions: tx.execute(
            "DELETE FROM crypto_transitions WHERE group_id=?1 AND sequence<=?2",
            rusqlite::params![group.as_bytes().as_slice(), through_sequence],
        )?,
        ..Default::default()
    };
    for window in closed_windows {
        let pruned = close_window_in(tx, *window)?;
        result.outbox += pruned.outbox;
        result.approvals += pruned.approvals;
    }

    Ok(result)
}
/// Close a previously authenticated retry window after its expiry. Pending and abandoned
/// unknown outcomes remain inspectable; closing never claims rejection or rewinds MLS.
pub fn close_window_in(tx: &Transaction<'_>, window: Id) -> Result<PrunedRecords> {
    let exists: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM crypto_closed_windows WHERE id=?1)",
        [window.as_bytes()],
        |r| r.get(0),
    )?;
    if !exists {
        let count: i64 = tx.query_row("SELECT count(*) FROM crypto_closed_windows", [], |r| {
            r.get(0)
        })?;
        if count >= RECORD_LIMIT {
            return Err(Error::Limit);
        }
        tx.execute(
            "INSERT INTO crypto_closed_windows VALUES(?1)",
            [window.as_bytes()],
        )?;
    }
    Ok(PrunedRecords {
        outbox: tx.execute(
            "DELETE FROM crypto_outbox WHERE window_id=?1 AND state IN ('committed','rejected')",
            [window.as_bytes()],
        )?,
        approvals: tx.execute(
            "DELETE FROM crypto_approvals WHERE window_id=?1 AND state IN ('delivered','rejected')",
            [window.as_bytes()],
        )?,
        ..Default::default()
    })
}
pub(super) fn window_open(tx: &Transaction<'_>, window: Id) -> Result<()> {
    let closed: bool = tx.query_row(
        "SELECT EXISTS(SELECT 1 FROM crypto_closed_windows WHERE id=?1)",
        [window.as_bytes().as_slice()],
        |r| r.get(0),
    )?;
    if closed {
        return Err(Error::Conflict);
    }
    Ok(())
}
