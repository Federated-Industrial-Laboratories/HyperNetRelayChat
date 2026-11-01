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
        let count: i64 = tx.query_row("SELECT count(*) FROM crypto_closed_windows", [], |r| {
            r.get(0)
        })?;
        if count >= RECORD_LIMIT {
            return Err(Error::Limit);
        }
        tx.execute(
            "INSERT OR IGNORE INTO crypto_closed_windows(id) VALUES(?1)",
            [window.as_bytes().as_slice()],
        )?;
        result.outbox+=tx.execute("DELETE FROM crypto_outbox WHERE group_id=?1 AND window_id=?2 AND state IN ('committed','rejected')",rusqlite::params![group.as_bytes().as_slice(),window.as_bytes().as_slice()])?;
        result.approvals+=tx.execute("DELETE FROM crypto_approvals WHERE group_id=?1 AND window_id=?2 AND state IN ('delivered','rejected')",rusqlite::params![group.as_bytes().as_slice(),window.as_bytes().as_slice()])?;
    }
    Ok(result)
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
