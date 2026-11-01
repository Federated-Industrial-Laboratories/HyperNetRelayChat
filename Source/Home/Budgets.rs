// SPDX-License-Identifier: Apache-2.0
//! Persisted token budgets survive reconnects and process restarts.
use super::types::*;
use crate::protocol::*;
use rusqlite::{OptionalExtension, Transaction, params};
struct Budget {
    key: String,
    capacity: u64,
    rate: u64,
    cost: u64,
}
pub(super) fn admit(db: &Transaction<'_>, action: &Action, now: u64) -> Domain<bool> {
    let sends = matches!(
        action.operation,
        Operation::MessageSend | Operation::MessageReply | Operation::MessageAction
    );
    let mut budgets = Vec::new();
    let mut account = |id: AccountId| {
        let (capacity, rate, cost) = if sends {
            (8000, 2000, 1000)
        } else {
            (32000, 8000, 1000)
        };
        budgets.push(Budget {
            key: format!("{}:{id}", if sends { "send" } else { "operation" }),
            capacity,
            rate,
            cost,
        });
        if sends {
            budgets.push(Budget {
                key: format!("bytes:{id}"),
                capacity: 65536,
                rate: 32768,
                cost: action_bytes(action)
                    .map(|b| b.len() as u64)
                    .unwrap_or(65536),
            });
        }
        match action.operation {
            Operation::AccountSetNickname | Operation::PresenceSet => budgets.push(Budget {
                key: format!("metadata:{id}"),
                capacity: 60000,
                rate: 1000,
                cost: 10000,
            }),
            Operation::RoomJoin | Operation::RoomLeave => budgets.push(Budget {
                key: format!("membership:{id}"),
                capacity: 60000,
                rate: 1000,
                cost: 6000,
            }),
            Operation::SearchQuery => budgets.push(Budget {
                key: format!("search:{id}"),
                capacity: 2000,
                rate: 1000,
                cost: 1000,
            }),
            _ => {}
        }
    };
    account(action.actor.acting().account);
    if action.actor.represented() != action.actor.acting().account {
        account(action.actor.represented());
    }
    if sends {
        budgets.push(Budget {
            key: "service:send".into(),
            capacity: 40000,
            rate: 20000,
            cost: 1000,
        });
        budgets.push(Budget {
            key: "service:bytes".into(),
            capacity: 524288,
            rate: 262144,
            cost: action_bytes(action)
                .map(|b| b.len() as u64)
                .unwrap_or(65536),
        });
        if let Target::Room(room) = action.target {
            budgets.push(Budget {
                key: format!("room:{room}"),
                capacity: 20000,
                rate: 10000,
                cost: 1000,
            });
        }
    }
    if let Actor::Delegated { grant, .. } = action.actor {
        let current = crate::delegation::load(db, grant.id)?;
        let rate = u64::from(current.scope.max_operations_per_minute);
        budgets.push(Budget {
            key: format!("grant:{}", grant.id),
            capacity: rate * 60_000,
            rate: rate * 1000,
            cost: 60_000,
        });
    }
    let mut updated = Vec::new();
    for budget in budgets {
        let current: Option<(u64, u64)> = db
            .query_row(
                "SELECT credit,updated FROM hrc_budgets WHERE key=?1",
                [&budget.key],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?;
        let credit = current
            .map(|(credit, updated)| {
                credit
                    .saturating_add(now.saturating_sub(updated).saturating_mul(budget.rate) / 1000)
                    .min(budget.capacity)
            })
            .unwrap_or(budget.capacity);
        if credit < budget.cost {
            return Ok(false);
        }
        updated.push((budget.key, credit - budget.cost));
    }
    for (key, credit) in updated {
        db.execute("INSERT INTO hrc_budgets VALUES(?1,?2,?3) ON CONFLICT(key) DO UPDATE SET credit=excluded.credit,updated=excluded.updated",params![key,credit,now])?;
    }
    Ok(true)
}
