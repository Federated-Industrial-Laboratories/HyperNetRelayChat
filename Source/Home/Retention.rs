// SPDX-License-Identifier: Apache-2.0
//! Expiry excludes content immediately and removes bounded batches with their indexes.
use super::types::*;
use rusqlite::{Transaction, params};
pub(super) fn clean(db: &Transaction<'_>, now: u64) -> rusqlite::Result<()> {
    let cutoff = now.saturating_sub(RETENTION);
    let removed:u64=db.query_row("SELECT COALESCE(sum(bytes),0) FROM (SELECT bytes FROM hrc_events WHERE created<?1 ORDER BY created LIMIT 128)",[cutoff],|r|r.get(0))?;
    db.execute("DELETE FROM hrc_agent_effects WHERE cause IN(SELECT id FROM hrc_events WHERE created<?1 ORDER BY created LIMIT 128)",[cutoff])?;
    db.execute("DELETE FROM hrc_events WHERE position IN(SELECT position FROM hrc_events WHERE created<?1 ORDER BY created LIMIT 128)",[cutoff])?;
    db.execute(
        "UPDATE hrc_meta SET history_bytes=MAX(0,history_bytes-?1) WHERE singleton=1",
        [removed],
    )?;
    db.execute("UPDATE hrc_rooms SET earliest=COALESCE((SELECT MIN(sequence) FROM hrc_events WHERE room=hrc_rooms.id),sequence+1)",[])?;
    db.execute("DELETE FROM hrc_operations WHERE rowid IN(SELECT o.rowid FROM hrc_operations o JOIN hrc_windows w ON w.id=o.window WHERE o.created<?1 AND w.expires<?2 LIMIT 128)",params![now.saturating_sub(7*DAY),now])?;
    // Window tombstones remain: a random old window is never reissued or reconstructed from a client.
    db.execute("DELETE FROM hrc_approvals WHERE rowid IN(SELECT rowid FROM hrc_approvals WHERE expires<?1 LIMIT 128)",[now])?;
    db.execute("DELETE FROM hrc_restrictions WHERE rowid IN(SELECT rowid FROM hrc_restrictions WHERE expires<?1 LIMIT 128)", [now])?;
    db.execute("DELETE FROM hrc_presence WHERE rowid IN(SELECT rowid FROM hrc_presence WHERE expires<?1 LIMIT 128)", [now])?;
    db.execute("DELETE FROM hrc_invitations WHERE rowid IN(SELECT rowid FROM hrc_invitations WHERE expires<?1 LIMIT 128)", [now])?;
    db.execute("DELETE FROM hrc_budgets WHERE rowid IN(SELECT rowid FROM hrc_budgets WHERE updated<?1 LIMIT 128)", [now.saturating_sub(7*DAY)])?;
    Ok(())
}
