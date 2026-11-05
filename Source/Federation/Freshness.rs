// SPDX-License-Identifier: Apache-2.0
//! Durable origin watches and short observations of foreign identity currentness.
use super::*;
use rusqlite::{OptionalExtension, params};
use std::time::Duration;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct WatchedIdentity {
    pub account: AccountId,
    pub acknowledged: Option<Id>,
    pub dirty: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct OriginWatchPage {
    pub items: Vec<WatchedIdentity>,
    pub next: Option<AccountId>,
}

pub(crate) fn mark_identity_changed(
    db: &Transaction<'_>,
    account: AccountId,
) -> rusqlite::Result<()> {
    // The legacy identity migration can run before federation has ever existed.
    let exists: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_master WHERE name='federation_watches')",
        [],
        |r| r.get(0),
    )?;
    if exists {
        db.execute(
            "UPDATE federation_watches SET dirty=1 WHERE account=?1",
            [account.to_string()],
        )?;
    }
    Ok(())
}

pub(super) fn watch_export(
    db: &Transaction<'_>,
    agreement: AgreementRef,
    account: AccountId,
    checkpoint: Id,
) -> Domain<()> {
    let count: u64 = db.query_row(
        "SELECT count(*) FROM federation_watches WHERE agreement=?1",
        [agreement.id.as_hex()],
        |r| r.get(0),
    )?;
    let exists: bool = db.query_row(
        "SELECT EXISTS(SELECT 1 FROM federation_watches WHERE agreement=?1 AND account=?2)",
        params![agreement.id.as_hex(), account.to_string()],
        |r| r.get(0),
    )?;
    if !exists && count >= 256 {
        return Err(Fault::Reject(ErrorCode::Overloaded, "OriginWatchCapacity"));
    }
    db.execute("INSERT INTO federation_watches(agreement,account,dirty) VALUES(?1,?2,1) ON CONFLICT(agreement,account) DO UPDATE SET dirty=CASE WHEN acknowledged=?3 THEN dirty ELSE 1 END",
        params![agreement.id.as_hex(),account.to_string(),checkpoint.as_hex()])?;
    Ok(())
}

/// A process restart invalidates every received lease; a new signed observation is required.
pub(crate) fn reset_freshness(store: &mut storage::Store) -> storage::Result<()> {
    let any: bool = store.read(Duration::from_secs(2), |db| {
        db.query_row(
            "SELECT EXISTS(SELECT 1 FROM federation_freshness)",
            [],
            |r| r.get(0),
        )
    })?;
    if any {
        store.write(|db| {
            db.execute("DELETE FROM federation_freshness", [])?;
            Ok(Commit::new((), b"HRC.Federation.FreshnessRestart".to_vec()))
        })?;
    }
    Ok(())
}

fn current_export(
    db: &Connection,
    home: ServiceId,
    account: AccountId,
    checkpoint: Id,
    signer: &VerifyingKey,
) -> Domain<OriginIdentityCheckpoint> {
    let bytes: Option<Vec<u8>> = db
        .query_row(
            "SELECT signed FROM federation_exports WHERE account=?1 AND digest=?2",
            params![account.to_string(), checkpoint.as_hex()],
            |r| r.get(0),
        )
        .optional()?;
    let bytes = bytes.ok_or(Fault::Reject(
        ErrorCode::Conflict,
        "OriginCheckpointChanged",
    ))?;
    let signed = verify_origin_identity_checkpoint(&bytes, signer)
        .map_err(|_| Fault::Reject(ErrorCode::Denied, "OriginCheckpoint"))?;
    let snapshot = crate::identity::continuity::snapshot(db, home, account)?;
    let nickname: String = db.query_row(
        "SELECT nickname FROM hrc_accounts WHERE id=?1",
        [account.to_string()],
        |r| r.get(0),
    )?;
    if signed.digest() != checkpoint
        || encode(&snapshot)? != encode(&signed.value().state)?
        || signed.value().nickname != nickname
    {
        return conflict("OriginIdentityChanged");
    }
    Ok(signed.value().clone())
}

impl Home {
    pub fn federation_watched(
        &mut self,
        agreement: AgreementRef,
        dirty_only: bool,
        after: Option<AccountId>,
        limit: u16,
        clock: TimeBounds,
    ) -> Result<OriginWatchPage> {
        if limit == 0 || limit > 32 {
            return Err(refused("OriginWatchPage"));
        }
        let t = now(clock)?;
        self.store.read(Duration::from_secs(2),|db| {
            let query=||->Domain<OriginWatchPage>{
                let a=current(db,agreement,t)?;
                if a.agreement.origin!=self.home { return deny("OriginWatchOwner"); }
                let mut statement=db.prepare("SELECT account,acknowledged,dirty FROM federation_watches WHERE agreement=?1 AND (?2=0 OR dirty=1) AND account>?3 ORDER BY account LIMIT ?4")?;
                let mut items=statement.query_map(params![agreement.id.as_hex(),dirty_only,after.map(|a|a.to_string()).unwrap_or_default(),u32::from(limit)+1], |r| {
                    let account=r.get::<_,String>(0)?.parse().map_err(|_|rusqlite::Error::InvalidQuery)?;
                    let acknowledged=r.get::<_,Option<String>>(1)?.map(|s|s.parse().map_err(|_|rusqlite::Error::InvalidQuery)).transpose()?;
                    Ok(WatchedIdentity {account,acknowledged,dirty:r.get(2)?})
                })?.collect::<rusqlite::Result<Vec<_>>>()?;
                let next=if items.len()>usize::from(limit) {items.pop();items.last().map(|v|v.account)}else{None};
                Ok(OriginWatchPage {items,next})
            }; Ok(query())
        })?.map_err(convert)
    }

    pub fn federation_acknowledge_identity(
        &mut self,
        agreement: AgreementRef,
        account: AccountId,
        checkpoint: Id,
        clock: TimeBounds,
    ) -> Result<()> {
        let home = self.home;
        let signer = self.signer.verifying_key();
        write(
            self,
            &(
                "HRC.Federation.IdentityAcknowledged",
                agreement,
                account,
                checkpoint,
            ),
            clock,
            |db, t| {
                let state = current(db, agreement, t)?;
                if state.agreement.origin != home || account.origin != home.network {
                    return deny("OriginWatchOwner");
                }
                current_export(db, home, account, checkpoint, &signer)?;
                if db.execute("UPDATE federation_watches SET acknowledged=?1,dirty=0 WHERE agreement=?2 AND account=?3",
                params![checkpoint.as_hex(),agreement.id.as_hex(),account.to_string()])? != 1 {return deny("OriginWatchUnavailable");}
                Ok(())
            },
        )
    }

    /// Sign only exact heads acknowledged as fully imported, then checked against current origin state.
    pub fn federation_freshness(
        &mut self,
        agreement: AgreementRef,
        checkpoints: &[CheckpointRef],
        clock: TimeBounds,
    ) -> Result<Blob> {
        if checkpoints.is_empty()
            || checkpoints.len() > 32
            || checkpoints.windows(2).any(|w| w[0].account >= w[1].account)
        {
            return Err(refused("OriginFreshnessAccounts"));
        }
        let t = now(clock)?;
        let home = self.home;
        let key = self.signer.verifying_key();
        let value=self.store.read(Duration::from_secs(2),|db| {
            let query=||->Domain<IdentityFreshness>{
                let a=current(db,agreement,t)?;if a.agreement.origin!=home {return deny("OriginFreshnessOwner");}
                let mut expires=t.lower_ms.saturating_add(5000).min(a.agreement.expires_ms);
                for reference in checkpoints {
                    let known:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM federation_watches WHERE agreement=?1 AND account=?2 AND acknowledged=?3 AND dirty=0)",
                        params![agreement.id.as_hex(),reference.account.to_string(),reference.checkpoint_digest.as_hex()],|r|r.get(0))?;
                    if !known {return conflict("OriginIdentityNotAcknowledged");}
                    let cp=current_export(db,home,reference.account,reference.checkpoint_digest,&key)?;
                    expires=expires.min(cp.expires_ms);
                }
                Ok(IdentityFreshness {profile:FEDERATION_PROFILE,home:a.agreement.home,origin:home,agreement,
                    checkpoints:checkpoints.to_vec(),issued_ms:t.lower_ms,expires_ms:expires})
            };Ok(query())
        })?.map_err(convert)?;
        if !now(clock)?.permits(value.issued_ms, value.expires_ms) {
            return Err(refused("OriginFreshnessExpired"));
        }
        Ok(Blob(sign_identity_freshness(&value, &self.signer)?))
    }

    pub fn federation_accept_freshness(
        &mut self,
        gateway: &GatewayContext,
        signed_lease: &[u8],
        clock: TimeBounds,
        permit: &dyn Fn() -> bool,
    ) -> Result<()> {
        if !permit() {
            return Err(Error::Refused {
                code: ErrorCode::Unavailable,
                detail: "GatewayAuthorityUnavailable",
            });
        }
        let state = self.federation_agreement(gateway.agreement, clock)?;
        let lease =
            verify_identity_freshness(signed_lease, &key(state.agreement.origin_service_key)?)?;
        let home = self.home;
        write(
            self,
            &("HRC.Federation.Freshness", lease.digest()),
            clock,
            |db, t| {
                let state = current(db, gateway.agreement, t)?;
                exchange::gateway_binding(&state, gateway, home)?;
                let value = lease.value();
                if state.agreement.home != home
                    || value.home != home
                    || value.origin != state.agreement.origin
                    || value.agreement != state.reference
                    || value.issued_ms > t.upper_ms
                    || t.upper_ms >= value.expires_ms
                {
                    return Err(Fault::Reject(
                        ErrorCode::Unavailable,
                        "OriginFreshnessExpired",
                    ));
                }
                let deadline = t
                    .boot_ms
                    .saturating_add(value.expires_ms.saturating_sub(t.upper_ms));
                for reference in &value.checkpoints {
                    if !identities::referenced(db, state.reference, reference.account)? {
                        return deny("OriginFreshnessScope");
                    }
                    let current: Option<String> = db
                        .query_row(
                            "SELECT checkpoint FROM federation_identities WHERE account=?1",
                            [reference.account.to_string()],
                            |r| r.get(0),
                        )
                        .optional()?;
                    if current.as_deref() != Some(&reference.checkpoint_digest.as_hex()) {
                        return conflict("OriginCheckpointChanged");
                    }
                    let cp = identities::checkpoint(db, reference.checkpoint_digest)?;
                    if cp.origin != value.origin
                        || cp.account != reference.account
                        || !t.permits(cp.issued_ms, cp.expires_ms)
                    {
                        return deny("OriginFreshnessCheckpoint");
                    }
                    db.execute("INSERT INTO federation_freshness VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(agreement,account) DO UPDATE SET revision=excluded.revision,checkpoint=excluded.checkpoint,expires=excluded.expires,deadline=excluded.deadline WHERE federation_freshness.checkpoint<>excluded.checkpoint OR federation_freshness.expires<excluded.expires",
                    params![state.reference.id.as_hex(),state.reference.revision,reference.account.to_string(),reference.checkpoint_digest.as_hex(),value.expires_ms,deadline])?;
                }
                if !permit()
                    || clock
                        .refresh()
                        .map_err(|_| rusqlite::Error::InvalidQuery)?
                        .upper_ms
                        >= value.expires_ms
                {
                    return Err(Fault::Reject(
                        ErrorCode::Unavailable,
                        "OriginFreshnessExpired",
                    ));
                }
                Ok(())
            },
        )
    }
}

/// Missing freshness prevents publication, but does not claim a confirmed identity withdrawal.
pub(crate) fn recipient_fresh(
    db: &Connection,
    room: RoomId,
    actor: &Actor,
    now: TimeBounds,
) -> Domain<bool> {
    for account in crate::conversations::subjects(actor) {
        if account.origin == room.home.network {
            continue;
        }
        let rows=db.prepare("SELECT a.data FROM federation_freshness f JOIN federation_identities i ON i.account=f.account AND i.checkpoint=f.checkpoint JOIN federation_agreements a ON a.id=f.agreement AND a.revision=f.revision WHERE f.account=?1 AND f.expires>?2 AND f.deadline>?3 AND a.withdrawn=0 LIMIT 33")?
            .query_map(params![account.to_string(),now.upper_ms,now.boot_ms],|r|decode::<AgreementState>(&r.get::<_,Vec<u8>>(0)?))?.collect::<rusqlite::Result<Vec<_>>>()?;
        if !rows.iter().any(|a| {
            a.agreement.home == room.home
                && a.agreement.origin.network == account.origin
                && now.permits(a.agreement.not_before_ms, a.agreement.expires_ms)
                && a.agreement.rooms.iter().any(|r| r.room == room)
        }) {
            return Ok(false);
        }
    }
    Ok(true)
}
