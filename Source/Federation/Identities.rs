// SPDX-License-Identifier: Apache-2.0
use super::*;
use rusqlite::{OptionalExtension, params};
use std::time::Duration;

#[derive(Clone, Debug)]
pub struct TrustAnchor {
    pub anchor: Id,
    pub legacy: bool,
}
#[derive(Clone, Debug)]
pub struct IdentityImport {
    pub checkpoint: Blob,
    pub page: Blob,
    pub trust_anchor: Option<TrustAnchor>,
}
#[derive(Clone, Debug)]
pub enum SourceSubject {
    Action(Blob),
    Session(Blob),
}
#[derive(Clone, Debug)]
pub struct OriginSubject {
    pub subject: FederationSubject,
    pub endpoint_binding: Blob,
    pub checkpoints: Vec<CheckpointRef>,
    pub acting: EndpointActor,
    pub agreement: AgreementRef,
    pub(super) source: SourceSubject,
    pub(super) states: Vec<IdentitySnapshot>,
}
pub(crate) fn checkpoint(db: &Connection, digest: Id) -> Domain<OriginIdentityCheckpoint> {
    let bytes: Option<Vec<u8>> = db
        .query_row(
            "SELECT data FROM federation_checkpoints WHERE digest=?1 AND complete=1",
            [digest.as_hex()],
            |r| r.get(0),
        )
        .optional()?;
    bytes
        .map(|b| decode(&b))
        .transpose()?
        .ok_or(Fault::Reject(ErrorCode::Denied, "IdentityProofIncomplete"))
}
fn records(
    db: &Connection,
    account: AccountId,
    maximum: u64,
) -> rusqlite::Result<Vec<ContinuityRecord>> {
    db.prepare("SELECT data FROM federation_records WHERE account=?1 AND number<=?2 ORDER BY number LIMIT 1025")?.query_map(params![account.to_string(),maximum],|r|decode(&r.get::<_,Vec<u8>>(0)?))?.collect()
}
fn operator(db: &Connection, account: AccountId, position: u64) -> Option<IdentitySnapshot> {
    // Both the controlled account and its operator belong to this same origin.
    let bytes: Vec<u8> = db
        .query_row(
            "SELECT data FROM federation_records WHERE account=?1 ORDER BY number DESC LIMIT 1",
            [account.to_string()],
            |r| r.get(0),
        )
        .ok()?;
    let latest: ContinuityRecord = decode(&bytes).ok()?;
    if latest.state.account.origin != account.origin {
        return None;
    }
    records(db, account, 1024)
        .ok()?
        .into_iter()
        .rev()
        .find(|r| r.position < position)
        .map(|r| r.state)
}
pub(super) fn referenced(
    db: &Connection,
    agreement: AgreementRef,
    account: AccountId,
) -> rusqlite::Result<bool> {
    if !is_foreign(db, account)? {
        return Ok(false);
    }
    let rows = db
        .prepare(
            "SELECT data FROM federation_admissions WHERE agreement=?1 AND withdrawn=0 LIMIT 257",
        )?
        .query_map([agreement.id.as_hex()], |r| {
            decode::<RemoteAdmission>(&r.get::<_, Vec<u8>>(0)?)
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    if rows.len() > 256 {
        return Err(rusqlite::Error::InvalidQuery);
    }
    for admission in rows {
        if admission.acting.account == account {
            return Ok(true);
        }
        if let Ok((identity, _)) = foreign_identity(db, admission.acting.account)
            && identity.classification == (AccountClass::Agent { operator: account })
        {
            return Ok(true);
        }
    }
    Ok(false)
}
pub(crate) fn foreign_identity(
    db: &Connection,
    account: AccountId,
) -> Domain<(IdentitySnapshot, Blob)> {
    let signed:Option<Vec<u8>>=db.query_row("SELECT c.signed FROM federation_identities i JOIN federation_checkpoints c ON c.digest=i.checkpoint WHERE i.account=?1 AND c.complete=1",[account.to_string()],|r|r.get(0)).optional()?;
    let Some(signed) = signed else {
        return deny("ForeignIdentityUnavailable");
    };
    let bytes:Vec<u8>=db.query_row("SELECT c.data FROM federation_identities i JOIN federation_checkpoints c ON c.digest=i.checkpoint WHERE i.account=?1",[account.to_string()],|r|r.get(0))?;
    let cp: OriginIdentityCheckpoint = decode(&bytes)?;
    Ok((cp.state, Blob(signed)))
}
pub(crate) fn foreign_page(
    db: &Connection,
    account: AccountId,
    after: u64,
    limit: u16,
) -> Domain<crate::home::InspectionPage<ContinuityRecord>> {
    if limit == 0 || limit > 4 || after > 1024 {
        return invalid("IdentityPage");
    }
    let mut items = Vec::new();
    let mut total = 0;
    let mut stmt=db.prepare("SELECT number,data FROM federation_records WHERE account=?1 AND number>?2 ORDER BY number LIMIT 5")?;
    let mut next = None;
    for row in stmt.query_map(params![account.to_string(), after], |r| {
        Ok((r.get::<_, u64>(0)?, r.get::<_, Vec<u8>>(1)?))
    })? {
        let (number, bytes) = row?;
        if items.len() >= usize::from(limit) || total + bytes.len() > 48 * 1024 {
            next = Some((number - 1).to_string());
            break;
        }
        total += bytes.len();
        items.push(decode(&bytes)?);
    }
    if items.is_empty() && next.is_some() {
        return Err(Fault::Reject(ErrorCode::Overloaded, "IdentityResponseSize"));
    }
    Ok(crate::home::InspectionPage { items, next })
}
fn import(
    db: &Transaction<'_>,
    a: &FederationAgreement,
    cp: &Verified<OriginIdentityCheckpoint>,
    page: &Verified<OriginIdentityPage>,
    trust: Option<&TrustAnchor>,
    now: TimeBounds,
) -> Domain<bool> {
    let c = cp.value();
    let p = page.value();
    current(db, p.agreement, now)?;
    if cp.signer_key() != a.origin_service_key
        || page.signer_key() != a.origin_service_key
        || c.origin != a.origin
        || p.origin != a.origin
        || p.account != c.account
        || p.checkpoint != cp.digest()
        || p.agreement.id != a.id
        || p.agreement.revision != a.revision
        || !now.permits(c.issued_ms, c.expires_ms)
        || c.expires_ms > a.expires_ms
    {
        return deny("OriginIdentityBinding");
    }
    let old: Option<(Vec<u8>, Vec<u8>, u64)> = db
        .query_row(
            "SELECT anchor,head,records FROM federation_identities WHERE account=?1",
            [c.account.to_string()],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    if let Some((anchor, _, count)) = &old {
        if anchor.as_slice() != c.anchor_digest.as_bytes() || u64::from(c.records) < *count {
            return deny("OriginContinuityRollback");
        }
        let (previous, _) = foreign_identity(db, c.account)?;
        if c.state.revision < previous.revision {
            return deny("OriginRevisionRollback");
        }
    } else if !trust
        .is_some_and(|t| t.anchor == c.anchor_digest && t.legacy == c.state.legacy_anchor)
    {
        return deny("OriginTrustRequired");
    }
    if c.state.classification == AccountClass::Human && c.state.account.origin != a.origin.network {
        return deny("OriginIdentity");
    }
    let mut retained = records(db, c.account, p.after)?;
    if retained.len() as u64 != p.after {
        return conflict("IdentityPageCursor");
    }
    let maximum_count: u64 = db.query_row(
        "SELECT coalesce(max(number),0) FROM federation_records WHERE account=?1",
        [c.account.to_string()],
        |r| r.get(0),
    )?;
    if p.after > maximum_count
        || p.next > u64::from(c.records)
        || p.complete != (p.next == u64::from(c.records))
    {
        return invalid("IdentityPageCursor");
    }
    for bytes in &p.records {
        let record: ContinuityRecord = decode(&bytes.0)?;
        if record.state.account != c.account {
            return deny("IdentityPageAccount");
        }
        retained.push(record);
    }
    let checked = crate::identity::proofs::check_chain(
        &VerifyingKey::from_bytes(a.origin_service_key.as_bytes())
            .map_err(|_| Fault::Reject(ErrorCode::Denied, "OriginKey"))?,
        retained,
        |account, position| operator(db, account, position),
    )
    .map_err(|_| Fault::Reject(ErrorCode::Denied, "OriginContinuity"))?;
    if checked.hashes.first() != Some(&c.anchor_digest) {
        return deny("OriginAnchor");
    }
    db.execute("DELETE FROM federation_checkpoints WHERE account=?1 AND digest<>?2 AND digest NOT IN(SELECT checkpoint FROM federation_identities WHERE account=?1)",params![c.account.to_string(),cp.digest().as_hex()])?;
    let current_bytes:u64=db.query_row("SELECT (SELECT coalesce(sum(length(data)),0) FROM federation_records)+(SELECT coalesce(sum(length(data)+length(signed)),0) FROM federation_checkpoints)",[],|r|r.get(0))?;
    let added = p
        .records
        .iter()
        .enumerate()
        .filter(|(i, _)| p.after + *i as u64 + 1 > maximum_count)
        .map(|(_, b)| b.0.len() as u64)
        .sum::<u64>();
    if current_bytes + added + cp.signed_bytes().len() as u64 + encode(c)?.len() as u64
        > 64 * 1024 * 1024
    {
        return Err(Fault::Reject(ErrorCode::Overloaded, "IdentityProofQuota"));
    }
    for record in checked.records.iter().skip(p.after as usize) {
        let data = encode(record)?;
        let hash = digest(&data);
        let existing: Option<Vec<u8>> = db
            .query_row(
                "SELECT digest FROM federation_records WHERE account=?1 AND number=?2",
                params![c.account.to_string(), record.index],
                |r| r.get(0),
            )
            .optional()?;
        if existing
            .as_ref()
            .is_some_and(|b| b.as_slice() != hash.as_bytes())
        {
            return deny("OriginContinuityFork");
        }
        db.execute(
            "INSERT OR IGNORE INTO federation_records VALUES(?1,?2,?3,?4)",
            params![c.account.to_string(), record.index, hash.as_bytes(), data],
        )?;
    }
    db.execute("INSERT OR IGNORE INTO federation_checkpoints(digest,account,agreement,signed,data,complete) VALUES(?1,?2,?3,?4,?5,0)",params![cp.digest().as_hex(),c.account.to_string(),a.id.as_hex(),cp.signed_bytes(),encode(c)?])?;
    if !p.complete {
        return Ok(false);
    }
    let latest = checked.latest();
    if checked.hashes.last() != Some(&c.head)
        || latest.home != c.origin
        || latest.account != c.account
        || latest.security_generation != c.state.security_generation
        || latest.recovery_key != c.state.recovery_key
        || latest.recovery_generation != c.state.recovery_generation
        || latest.classification != c.state.classification
        || latest.legacy_anchor != c.state.legacy_anchor
        || latest.revision > c.state.revision
        || encode(&latest.endpoints)? != encode(&c.state.endpoints)?
    {
        return deny("OriginCheckpointState");
    }
    if let AccountClass::Agent { operator } = c.state.classification {
        let (op, _) = foreign_identity(db, operator)?;
        if op.home != a.origin || op.classification != AccountClass::Human {
            return deny("OriginOperator");
        }
    }
    let count: u64 = db.query_row("SELECT count(*) FROM hrc_accounts", [], |r| r.get(0))?;
    if old.is_none() && count >= 256 {
        return Err(Fault::Reject(ErrorCode::Overloaded, "IdentityCapacity"));
    }
    crate::text::handle(&c.nickname)
        .map_err(|_| Fault::Reject(ErrorCode::InvalidInput, "OriginNickname"))?;
    let lookup = crate::text::lookup(&c.nickname, 256)
        .map_err(|_| Fault::Reject(ErrorCode::InvalidInput, "OriginNickname"))?;
    if old.is_some() {
        let (previous, _) = foreign_identity(db, c.account)?;
        if previous.security_generation != c.state.security_generation
            || previous.endpoints.iter().any(|old| {
                !c.state.endpoints.iter().any(|new| {
                    new.actor == old.actor && new.key == old.key && new.principal == old.principal
                })
            })
        {
            invalidate(db, &[c.account])?;
        }
    }
    db.execute("INSERT INTO hrc_accounts(id,account,class,recovery,security,revision,nickname,lookup) VALUES(?1,?2,?3,?4,?5,?6,?7,?8) ON CONFLICT(id) DO UPDATE SET class=excluded.class,recovery=excluded.recovery,security=excluded.security,revision=excluded.revision,nickname=excluded.nickname,lookup=excluded.lookup",params![c.account.to_string(),encode(&c.account)?,encode(&c.state.classification)?,c.state.recovery_key.as_bytes(),c.state.security_generation,c.state.revision,c.nickname,lookup])?;
    db.execute(
        "UPDATE hrc_endpoints SET disabled=1 WHERE account=?1",
        [c.account.to_string()],
    )?;
    for ep in &c.state.endpoints {
        db.execute("INSERT INTO hrc_endpoints VALUES(?1,?2,?3,?4,?5,0) ON CONFLICT(account,endpoint) DO UPDATE SET actor=excluded.actor,key=excluded.key,principal=excluded.principal,disabled=0",params![c.account.to_string(),ep.actor.endpoint.as_hex(),encode(&ep.actor)?,ep.key.as_bytes(),ep.principal.as_hex()])?;
    }
    db.execute(
        "UPDATE federation_checkpoints SET complete=1 WHERE digest=?1",
        [cp.digest().as_hex()],
    )?;
    db.execute("INSERT INTO federation_identities VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(account) DO UPDATE SET checkpoint=excluded.checkpoint,head=excluded.head,records=excluded.records",params![c.account.to_string(),encode(&a.origin)?,cp.digest().as_hex(),c.anchor_digest.as_bytes(),c.head.as_bytes(),c.records])?;
    // Grant/transition proofs retain their exact signed checkpoint inline. A stale
    // forwarding checkpoint is not current authority and need not occupy this cache.
    db.execute(
        "DELETE FROM federation_checkpoints WHERE account=?1 AND digest<>?2",
        params![c.account.to_string(), cp.digest().as_hex()],
    )?;
    Ok(true)
}
impl Home {
    pub fn federation_import_identity(
        &mut self,
        agreement: AgreementRef,
        importing: &IdentityImport,
        clock: TimeBounds,
    ) -> Result<bool> {
        let a = self.federation_agreement(agreement, clock)?;
        if a.agreement.home != self.home {
            return Err(refused("IdentityReceiver"));
        }
        let cp = verify_origin_identity_checkpoint(
            &importing.checkpoint.0,
            &key(a.agreement.origin_service_key)?,
        )?;
        let page =
            verify_origin_identity_page(&importing.page.0, &key(a.agreement.origin_service_key)?)?;
        if importing.checkpoint.0.len() > 8192 {
            return Err(refused("IdentityCheckpointSize"));
        }
        write(
            self,
            &("HRC.Federation.Identity", cp.digest(), page.digest()),
            clock,
            |db, now| {
                current(db, agreement, now)?;
                import(
                    db,
                    &a.agreement,
                    &cp,
                    &page,
                    importing.trust_anchor.as_ref(),
                    now,
                )
            },
        )
    }
    pub fn federation_update_identity(
        &mut self,
        gateway: &GatewayContext,
        importing: &IdentityImport,
        clock: TimeBounds,
        permit: &dyn Fn() -> bool,
    ) -> Result<bool> {
        if importing.checkpoint.0.len() > 8192 {
            return Err(refused("IdentityCheckpointSize"));
        }
        if importing.trust_anchor.is_some() || !permit() {
            return Err(refused("IdentityImportAuthority"));
        }
        let a = self.federation_agreement(gateway.agreement, clock)?;
        exchange::gateway_binding(&a, gateway, self.home).map_err(convert)?;
        let cp = verify_origin_identity_checkpoint(
            &importing.checkpoint.0,
            &key(a.agreement.origin_service_key)?,
        )?;
        let account = cp.value().account;
        let allowed = self.store.read(Duration::from_secs(2), |db| {
            referenced(db, gateway.agreement, account)
        })?;
        if !allowed {
            return Err(refused("IdentityImportScope"));
        }
        let page =
            verify_origin_identity_page(&importing.page.0, &key(a.agreement.origin_service_key)?)?;
        let t = now(clock)?;
        let unchanged=self.store.read(Duration::from_secs(2),|db|{
            let check=||->Domain<bool>{let c=cp.value();let p=page.value();current(db,gateway.agreement,t)?;
                if p.agreement!=gateway.agreement||p.account!=c.account||p.checkpoint!=cp.digest()||p.origin!=a.agreement.origin||c.origin!=a.agreement.origin||!t.permits(c.issued_ms,c.expires_ms)||p.next>u64::from(c.records)||p.complete!=(p.next==u64::from(c.records)){return deny("IdentityPageBinding")}
                let known:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM federation_identities i JOIN federation_checkpoints c ON c.digest=i.checkpoint WHERE i.account=?1 AND i.checkpoint=?2 AND c.complete=1)",params![account.to_string(),cp.digest().as_hex()],|r|r.get(0))?;
                if !known{return Ok(false)}
                for(index,blob)in p.records.iter().enumerate(){let number=p.after+index as u64+1;let saved:Vec<u8>=db.query_row("SELECT data FROM federation_records WHERE account=?1 AND number=?2",params![account.to_string(),number],|r|r.get(0))?;if saved!=blob.0{return deny("OriginContinuityFork")}}
                Ok(true)};Ok(check())
        })?.map_err(convert)?;
        if unchanged {
            if !permit() {
                return Err(Error::Refused {
                    code: ErrorCode::Unavailable,
                    detail: "GatewayAuthorityUnavailable",
                });
            }
            return Ok(true);
        }
        write(
            self,
            &("HRC.Federation.IdentityUpdate", cp.digest(), page.digest()),
            clock,
            |db, t| {
                let accepted = current(db, gateway.agreement, t)?;
                exchange::gateway_binding(&accepted, gateway, accepted.agreement.home)?;
                if !permit() {
                    return deny("GatewayAuthority");
                };
                let result = import(db, &a.agreement, &cp, &page, None, t)?;
                if !permit() {
                    return Err(Fault::Sql(rusqlite::Error::InvalidQuery));
                }
                Ok(result)
            },
        )
    }
    pub fn federation_checkpoint(
        &mut self,
        account: AccountId,
        agreement: AgreementRef,
        clock: TimeBounds,
    ) -> Result<Blob> {
        let a = self.federation_agreement(agreement, clock)?;
        if self.home != a.agreement.origin || account.origin != self.home.network {
            return Err(refused("OriginCheckpointAccount"));
        }
        let home = self.home;
        let signer = self.signer.clone();
        let observed = now(clock)?;
        let cached=self.store.read(Duration::from_secs(2),|db| {
            let query=||->Domain<Option<Blob>> {
                current(db,agreement,observed)?;
                let floor:u64=db.query_row("SELECT clock_floor FROM hrc_meta WHERE singleton=1",[],|r|r.get(0))?;
                observed.after_floor(floor).map_err(|_|Fault::Reject(ErrorCode::Unavailable,"ClockRollback"))?;
                let exists:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM federation_watches WHERE agreement=?1 AND account=?2)",params![agreement.id.as_hex(),account.to_string()],|r|r.get(0))?;
                if !exists {return Ok(None);}
                let saved:Option<(Vec<u8>,u64)>=db.query_row("SELECT signed,expires FROM federation_exports WHERE account=?1",[account.to_string()],|r|Ok((r.get(0)?,r.get(1)?))).optional()?;
                let Some((bytes,expires))=saved else{return Ok(None)};
                if expires<=observed.upper_ms.saturating_add(60_000)||expires>a.agreement.expires_ms {return Ok(None);}
                let cp=verify_origin_identity_checkpoint(&bytes,&signer.verifying_key()).map_err(|_|Fault::Reject(ErrorCode::Denied,"CheckpointExport"))?;
                let snapshot=crate::identity::continuity::snapshot(db,home,account)?;
                let nickname:String=db.query_row("SELECT nickname FROM hrc_accounts WHERE id=?1",[account.to_string()],|r|r.get(0))?;
                if encode(&cp.value().state)?!=encode(&snapshot)?||cp.value().nickname!=nickname {return Ok(None);}
                if !clock.refresh().map_err(|_|rusqlite::Error::InvalidQuery)?.permits(cp.value().issued_ms,cp.value().expires_ms) {return Err(Fault::Reject(ErrorCode::Unavailable,"CheckpointExpired"));}
                Ok(Some(Blob(bytes)))
            };Ok(query())
        })?.map_err(convert)?;
        if let Some(cached) = cached {
            return Ok(cached);
        }
        write(self, "HRC.Federation.CheckpointExport", clock, |db, now| {
            current(db, agreement, now)?;
            let snapshot = crate::identity::continuity::snapshot(db, home, account)?;
            let nickname: String = db.query_row(
                "SELECT nickname FROM hrc_accounts WHERE id=?1",
                [account.to_string()],
                |r| r.get(0),
            )?;
            let saved: Option<(Vec<u8>, u64)> = db
                .query_row(
                    "SELECT signed,expires FROM federation_exports WHERE account=?1",
                    [account.to_string()],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if let Some((bytes, expires)) = saved
                && expires > now.upper_ms + 60_000
                && expires <= a.agreement.expires_ms
            {
                let old = verify_origin_identity_checkpoint(&bytes, &signer.verifying_key())
                    .map_err(|_| Fault::Reject(ErrorCode::Denied, "CheckpointExport"))?;
                if encode(&old.value().state)? == encode(&snapshot)?
                    && old.value().nickname == nickname
                {
                    super::freshness::watch_export(db, agreement, account, old.digest())?;
                    return Ok(Blob(bytes));
                }
            }
            let (records,anchor):(u16,Vec<u8>)=db.query_row("SELECT a.records,r.digest FROM identity_accounts a JOIN identity_records r ON r.account=a.account AND r.number=1 WHERE a.account=?1",[account.to_string()],|r|Ok((r.get(0)?,r.get(1)?)))?;
            let cp = OriginIdentityCheckpoint {
                profile: 1,
                origin: home,
                account,
                head: snapshot
                    .head
                    .ok_or(Fault::Reject(ErrorCode::Denied, "ContinuityHead"))?,
                state: snapshot,
                anchor_digest: Id::from_bytes(
                    anchor
                        .try_into()
                        .map_err(|_| rusqlite::Error::InvalidQuery)?,
                ),
                records,
                nickname,
                issued_ms: now.lower_ms,
                expires_ms: (now.lower_ms + 7 * DAY).min(a.agreement.expires_ms),
            };
            let signed = sign_origin_identity_checkpoint(&cp, &signer)
                .map_err(|_| Fault::Reject(ErrorCode::InvalidInput, "CheckpointEncoding"))?;
            if signed.len() > 8192 {
                return invalid("CheckpointSize");
            };
            let verified = verify_origin_identity_checkpoint(&signed, &signer.verifying_key())
                .map_err(|_| rusqlite::Error::InvalidQuery)?;
            super::freshness::watch_export(db, agreement, account, verified.digest())?;
            db.execute("INSERT INTO federation_exports VALUES(?1,?2,?3,?4) ON CONFLICT(account) DO UPDATE SET digest=excluded.digest,signed=excluded.signed,expires=excluded.expires",params![account.to_string(),verified.digest().as_hex(),signed,cp.expires_ms])?;
            Ok(Blob(signed))
        })
    }
    /// Caller must authorize the exact account through local administration or a validated proof authorization.
    pub fn federation_identity_page(
        &mut self,
        agreement: AgreementRef,
        checkpoint_digest: Id,
        after: u64,
        limit: u16,
        clock: TimeBounds,
    ) -> Result<Blob> {
        let a = self.federation_agreement(agreement, clock)?;
        if self.home != a.agreement.origin || limit == 0 || limit > 4 || after > 1024 {
            return Err(refused("IdentityPageScope"));
        }
        let data=self.store.read(Duration::from_secs(2),|db|{
            let signed:Vec<u8>=db.query_row("SELECT signed FROM federation_exports WHERE digest=?1",[checkpoint_digest.as_hex()],|r|r.get(0))?;
            let cp=verify_origin_identity_checkpoint(&signed,&self.signer.verifying_key()).map_err(|_|rusqlite::Error::InvalidQuery)?;
            let c=cp.value();let mut records=Vec::new();let mut total=0;
            let mut statement=db.prepare("SELECT record FROM identity_records WHERE account=?1 AND number>?2 AND number<=?3 ORDER BY number LIMIT 4")?;
            for bytes in statement.query_map(params![c.account.to_string(),after,c.records],|r|r.get::<_,Vec<u8>>(0))?{let bytes=bytes?;if records.len()>=usize::from(limit)||total+bytes.len()>56*1024{break}total+=bytes.len();records.push(Blob(bytes));}
            let next=after+records.len() as u64;Ok(OriginIdentityPage{profile:1,origin:self.home,agreement,account:c.account,checkpoint:checkpoint_digest,after,records,next,complete:next==u64::from(c.records)})
        })?;
        Ok(Blob(sign_origin_identity_page(&data, &self.signer)?))
    }
}
